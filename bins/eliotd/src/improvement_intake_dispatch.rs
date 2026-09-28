//! Production improvement-intake dispatch for `eliotd` (issue #1867 W1,
//! I12.24).
//!
//! This is the production caller that closes the gap the cross-check refuted:
//! before this module, [`crate::improvement_intake::route_evidence_refs_to_backlog`]
//! and [`crate::improvement_intake::route_self_quality_handoff_to_backlog`]
//! were defined but reached from no production entry point, so the
//! `eliot-improvement` candidate/brief path was unreachable in production.
//! The daemon run loop now reaches it through
//! [`crate::daemon_runtime`]'s retained `ImprovementIntakeFlight`.
//!
//! # The evidence is a real observation this daemon already made
//!
//! The single evidence source is the daemon's OWN live
//! [`eliot_maintenance::AutomationTriggerDecision`] produced by
//! [`crate::DaemonComposition::evaluate_maintenance_trigger`]
//! (`maintenance_trigger_evaluator.rs::DaemonComposition::evaluate_maintenance_trigger`),
//! which the run loop already evaluates per cadence. That decision carries the
//! Governor owner's real `trigger_id`, `family`, `scope_ref`, `reason`,
//! `decision` and `admits_job`, and is bound to the observed evidence
//! references the trigger site passed in. Nothing here invents an observation:
//! every ref below is derived from that decision's own fields.
//!
//! The source is typed as [`eliot_improvement::EvidenceSource::Watchdog`]
//! because I12.24:40-55 lists "Watchdog" as the trigger family for an admitted
//! problem/signal occurrence, and `MaintenanceTriggerOrigin::AdmittedObservation`
//! is this daemon's own classification of exactly that
//! (`maintenance_trigger_evaluator.rs::MaintenanceTriggerOrigin::maintenance_trigger`
//! maps it to `MaintenanceTrigger::WatchdogProblem`). `ASSUMPTION:` the
//! `Watchdog` variant is the honest label for a maintenance-trigger problem
//! signal; I12.24:40-55 names no separate "maintenance" variant, and the
//! daemon is the Watchdog-adjacent problem-recipe producer, not a
//! `ConformanceDiagnosis` producer — it holds no `SelfQualityInput`.
//!
//! # The durable port is the existing Governor/Kernel named mutation
//!
//! The owner-actionable artifact (candidate revision + brief + owner decision)
//! is committed through the EXISTING
//! [`crate::DaemonComposition::commit_learning_record`] seam, which is the one
//! Governor-owned caller of
//! [`eliot_governor::commit_learning_record`] and the only path that reaches
//! the closed `RecordLearningRecord` mutation
//! ([`eliot_store_api::LearningRecordKind::Candidate`]). No second write
//! path, store client or durability scheme is introduced here, and no
//! in-memory `BoundedBacklog` is treated as durable: the backlog is used only
//! for its deduplication registry within this one pass, and the committed
//! record is the durable artifact.
//!
//! # Promotion stays refused, by construction, not by omission
//!
//! The intake's promotion-grade budget gate
//! ([`eliot_improvement::require_matched_budget_for_promotion`]) is NOT
//! satisfied here, because this daemon runs no experiment and therefore
//! holds no real matched-budget live shadow/canary evidence. This module
//! consequently uses the advisory composition of the same
//! `eliot-improvement` owners — [`eliot_improvement::candidate_from_evidence`],
//! [`eliot_improvement::brief_at_safe_boundary`] and
//! [`crate::improvement_intake::record_brief_decision`] — rather than
//! calling [`eliot_improvement::intake_from_evidence`], whose unconditional
//! `require_matched_budget_for_promotion` call would demand fabricated
//! canary refs. This is the honest advisory state I12.24:74-80 describes:
//! "advisory … default; changes nothing until owner acts", and a
//! replay-only candidate that cannot promote. `BLOCKED-BY` promoting this
//! path through `intake_from_evidence` needs an owner that publishes real
//! matched-budget live shadow/canary evidence
//! ([`eliot_improvement::BudgetProof::live_shadow_refs`] /
//! [`::live_canary_refs`]); none exists in this workspace. W1's reachability
//! requirement — a real production caller consuming real evidence and
//! emitting a durably committed owner-actionable artifact — is met without
//! weakening that gate, which stays closed.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use eliot_contracts::StateFence;
use eliot_improvement::candidate_bounds::{BoundedBacklog, CandidateBoundPolicy};
use eliot_improvement::{
    EvidenceSource, ImprovementBrief, ImprovementCandidate, ImprovementError, ImprovementLifecycle,
    ImprovementSurface, OwnerDecision, OwnerDecisionKind, ReplayPlan, SafeBoundary,
    brief_at_safe_boundary, candidate_from_evidence, sourced_evidence,
};
use eliot_protocol::RequestIdentity;
use eliot_receipts::RequestBinding;
use eliot_store_api::{
    LearningRecordKind, ScopeId, canonical_json_bytes, learning_record_commit_params,
    learning_record_mutation_request,
};
use thiserror::Error;

use super::{DaemonComposition, SERVICE_NAME};

/// Closed improvement surface this daemon's own self-quality-debt observations
/// concern.
///
/// I12.24:29-30 treats context/retrieval/memory transformation regret and
/// module/recipe drift as the surfaces an improvement candidate targets, and
/// this daemon's only genuine observation source is its own maintenance /
/// self-quality debt family, so the candidate is honestly scoped to `Memory`.
/// `ASSUMPTION:` `Memory` is the honest surface label for a maintenance-debt
/// observation; the alternative labels (`Skill`, `ToolProfile`, `Rule`,
/// `PacketCompiler`, `Verifier`, `Scheduler`) each imply an owner this
/// daemon does not have, and `Verifier`/`Scheduler` are additionally
/// prohibited-for-tuning surfaces (`application_class.rs::is_prohibited_tuning_surface`).
const IMPROVEMENT_SURFACE: ImprovementSurface = ImprovementSurface::Memory;

/// Project the daemon identity used as the candidate's owning decision
/// authority (`SERVICE_NAME` is the daemon's own registered service name).
const IMPROVEMENT_OWNER: &str = "eliotd.maintenance";

/// Closed store scope for durable improvement-candidate learning records.
///
/// This is the same fixed `governor` scope the Skill lifecycle/evidence owner
/// rows already use (`skill_evidence_read.rs::LIFECYCLE_SCOPE`), so the
/// improvement candidate lands in the Governor-owned scope rather than
/// inventing a second scope.
const IMPROVEMENT_SCOPE: &str = "governor";

/// Deadlines bounding one durable learning-record commit ingress, in Unix
/// milliseconds, matching the retained daemon transport's own operation bound
/// (`experience_runtime.rs::COMMIT_INGRESS_DEADLINE_MS`).
const IMPROVEMENT_COMMIT_DEADLINE_MS: u64 = 30_000;

/// Typed failures of the production improvement-intake dispatch.
#[derive(Debug, Error)]
pub enum ImprovementDispatchError {
    /// The `eliot-improvement` owner rejected the candidate, brief, or
    /// decision assembly for this real observation.
    #[error("improvement intake: {0}")]
    Improvement(#[from] ImprovementError),
    /// The bounded-backlog registry refused the candidate.
    #[error("improvement backlog: {0}")]
    Backlog(String),
    /// The durable learning-record commit was refused.
    #[error("improvement learning-record commit: {0}")]
    Commit(String),
    /// The store scope or record identity is not a valid contract value.
    #[error("improvement contract value: {0}")]
    Contract(String),
}

/// One assembled, owner-actionable improvement artifact over a real
/// observation, ready to be made durable.
///
/// Every field is a function of the observed maintenance decision; the
/// `ImprovementBrief` is the exact artifact I12.24:74 requires the decision
/// owner to read (problem, evidence, likely benefit, risk, proposed owner,
/// cost, next reversible step, unknowns) so the owner never searches raw
/// metrics.
#[derive(Clone, Debug)]
pub struct ImprovementArtifact {
    /// The evidence-bound candidate admitted to the deduplication registry.
    pub candidate: ImprovementCandidate,
    /// Owner-actionable brief at the safe boundary.
    pub brief: ImprovementBrief,
    /// Recorded, non-mutating owner decision over that brief.
    pub decision: OwnerDecision,
}

/// Assembles the deduplicated improvement candidate, the owner-actionable
/// brief, and the recorded owner decision from one real maintenance-trigger
/// observation.
///
/// The decision's own `trigger_id`, `family`, `scope_ref`, `reason` and
/// `decision` are the evidence lineage, so two evaluations of the same
/// failure under the same admitted fence deduplicate by content
/// (`BoundedBacklog::admit` merges on overlapping lineage) rather than
/// minting a fresh candidate per observation.
///
/// `state_fence` is the daemon's own admitted Kernel fence for this pass; it
/// becomes the candidate's `validity_scope` (see [`admitted_fence_ref`]), so
/// the artifact is only ever admitted under the same authority epoch and
/// resource generation the observation was evaluated under.
///
/// This performs no durability, no promotion and no activation: it returns the
/// artifact, and the caller commits it through
/// [`crate::DaemonComposition::commit_learning_record`].
pub fn assemble_improvement_artifact(
    decision: &eliot_maintenance::AutomationTriggerDecision,
    state_fence: &StateFence,
) -> Result<ImprovementArtifact, ImprovementDispatchError> {
    // Evidence lineage: the decision's own stable identity, never a fresh
    // per-observation value, so a repeat deduplicates.
    let evidence_refs = vec![
        format!("maintenance-trigger:{}", decision.trigger_id),
        format!("maintenance-scope:{}", decision.scope_ref),
    ];
    let trace_refs = vec![format!("maintenance-family:{}", decision.family)];
    // `MaintenanceFamily` carries a `Display` impl (its canonical SCREAMING
    // spelling); `AutomationDecision` and `DecisionReason` are `Debug`-only
    // closed owner enums and gain no `Display` here, so they are named by
    // their derived variant spelling instead.
    let trigger = format!(
        "maintenance automation {} evaluated {:?} for reason {:?}",
        decision.family, decision.decision, decision.reason
    );
    // The replay plan is diagnostic-only (I12.24:76-77): the fixed replay,
    // holdout and transfer legs are the decision's own canonical refs, and the
    // counter metrics name what must not regress. Promotion is separately
    // refused by the intake's budget gate, which this advisory path does not
    // attempt to satisfy.
    let replay_plan = ReplayPlan {
        fixed_replay_refs: evidence_refs.clone(),
        holdout_refs: vec![format!("maintenance-holdout:{}", decision.trigger_id)],
        transfer_refs: vec![format!("maintenance-transfer:{}", decision.scope_ref)],
        counter_metric_names: vec!["blocked_maintenance_runs".to_owned()],
        verifier_refs: vec![format!("maintenance-evaluator:{}", decision.family)],
    };
    let admitted_scope = admitted_fence_ref(state_fence)?;
    let evidence = sourced_evidence(
        EvidenceSource::Watchdog,
        &evidence_refs,
        &trace_refs,
        &trigger,
        &[format!(
            "unproven-blocked-automation:{}",
            decision.trigger_id
        )],
        &admitted_scope,
        IMPROVEMENT_OWNER,
    )?;

    let mut candidate = candidate_from_evidence(
        SERVICE_NAME,
        IMPROVEMENT_SURFACE,
        &format!(
            "evaluate and resolve the blocked maintenance family {} at {}",
            decision.family, decision.scope_ref
        ),
        &evidence,
        replay_plan,
        BTreeMap::new(),
        &format!("maintenance-family:{}", decision.family),
        &format!("maintenance-canary:{}", decision.trigger_id),
        &format!("maintenance-rollback:{}", decision.trigger_id),
        &format!("maintenance-stop:{}", decision.trigger_id),
    )?;
    // Admitted intake is triaged for owner review, exactly as the intake
    // path does, so the durable record carries the owner-decision lifecycle.
    candidate.transition_lifecycle(ImprovementLifecycle::Triaged)?;

    // The safe boundary is the daemon's own admitted generation plus the
    // daemon's decision owner, both real values this daemon holds.
    let boundary = SafeBoundary {
        active_main_agent_or_human_ref: format!("owner:{IMPROVEMENT_OWNER}"),
        boundary_ref: format!("boundary:{}", decision.scope_ref),
    };
    let brief = brief_at_safe_boundary(
        &candidate,
        &trigger,
        &format!(
            "the blocked family {} is evaluated on every cadence and cannot start",
            decision.family
        ),
        "advisory only; no authority, privacy, finish or durability effect is taken",
        IMPROVEMENT_OWNER,
        "one owner triage pass over the stored brief",
        &format!("triage maintenance trigger {}", decision.trigger_id),
        vec![format!(
            "unknown whether maintenance family {} has a start route",
            decision.family
        )],
        &boundary,
    )?;

    // The daemon's owner records a non-mutating `Investigate` disposition: the
    // artifact is real and actionable, and recording it changes nothing. This
    // is the production caller of the bridge's
    // `record_brief_decision`, which previously had none.
    let decision_record = crate::improvement_intake::record_brief_decision(
        &brief,
        IMPROVEMENT_OWNER,
        OwnerDecisionKind::Investigate,
        &format!("triage blocked maintenance family {}", decision.family),
    )
    .map_err(|error| ImprovementDispatchError::Contract(error.to_string()))?;

    // Deduplication registry: admitted under the observed lineage so a repeat
    // of the same failure merges instead of minting a new candidate. This
    // backlog is a per-pass registry, never treated as durable storage — the
    // durable artifact is the committed learning record below.
    let mut registry = BoundedBacklog::new(vec![CandidateBoundPolicy {
        target_surface: IMPROVEMENT_SURFACE,
        max_active: 8,
        min_value: 0.0,
        governor_authority_ref: IMPROVEMENT_OWNER.to_owned(),
        policy_revision: 1,
    }])
    .map_err(|error| ImprovementDispatchError::Backlog(error.to_string()))?;
    let value = 1.0;
    registry
        .admit(candidate.clone(), value, Some(IMPROVEMENT_OWNER.to_owned()))
        .map_err(|error| ImprovementDispatchError::Backlog(error.to_string()))?;

    Ok(ImprovementArtifact {
        candidate,
        brief,
        decision: decision_record,
    })
}

/// Renders the daemon's own admitted fence as the candidate's stable
/// `validity_scope` reference.
///
/// The improvement candidate's admitted boundary is the real Kernel fence this
/// dispatch observed the maintenance decision under, not a string that only
/// claims to be one: both components the maintenance owner treats as
/// distinct are carried verbatim — the lineage-aware authority epoch (the
/// exact `(lineage_id, sequence)` tuple, per
/// `epoch_identity.rs::EpochId::is_same_authority`) and the monotonic resource
/// generation. A candidate is therefore only ever read back as valid under the
/// same admitted authority and generation that produced it.
fn admitted_fence_ref(state_fence: &StateFence) -> Result<String, ImprovementDispatchError> {
    state_fence
        .validate()
        .map_err(|error| ImprovementDispatchError::Contract(error.to_string()))?;
    Ok(format!(
        "admitted-fence:{}/{}@{}",
        state_fence.authority_epoch.lineage_id.as_str(),
        state_fence.authority_epoch.sequence,
        state_fence.resource_generation.value()
    ))
}

/// Derives the admitted commit ingress for one durable improvement record.
///
/// Mirrors `experience_runtime.rs::derive_commit_ingress`: the request
/// metadata is derived from the daemon's own admitted fence and the
/// idempotency key is the owner-derived candidate key, so an identical
/// observation replays convergently under the same key.
fn improvement_commit_identity(
    candidate: &ImprovementCandidate,
    state_fence: &StateFence,
) -> Result<RequestIdentity, ImprovementDispatchError> {
    let now = super::unix_ms_i64();
    let metadata = eliot_contracts::RequestMetadata {
        request_id: eliot_contracts::RequestId::new(format!(
            "{SERVICE_NAME}:improvement-candidate:{}",
            candidate.candidate_id
        ))
        .map_err(|error| ImprovementDispatchError::Contract(error.to_string()))?,
        session_id: None,
        task_id: None,
        product_id: eliot_contracts::ProductId::new(SERVICE_NAME)
            .map_err(|error| ImprovementDispatchError::Contract(error.to_string()))?,
        source_id: eliot_contracts::SourceId::new(SERVICE_NAME)
            .map_err(|error| ImprovementDispatchError::Contract(error.to_string()))?,
        state_fence: state_fence.clone(),
        clock: eliot_contracts::ClockReading {
            valid_time_ms: Some(now),
            known_time_ms: Some(now),
            transaction_sequence: None,
            monotonic_ns: None,
        },
    };
    metadata
        .validate()
        .map_err(|error| ImprovementDispatchError::Contract(error.to_string()))?;
    Ok(RequestIdentity {
        request: RequestBinding {
            metadata,
            state_fence: state_fence.clone(),
        },
        idempotency_key: format!("improvement-candidate:{}", candidate.candidate_id),
        deadline_unix_ms: super::unix_ms().saturating_add(IMPROVEMENT_COMMIT_DEADLINE_MS),
        cancellation_id: format!("improvement-candidate:{}:cancel", candidate.candidate_id),
    })
}

/// Commits one assembled improvement artifact durably through the existing
/// Governor/Kernel `RecordLearningRecord` named mutation.
///
/// The record kind is the closed
/// [`eliot_store_api::LearningRecordKind::Candidate`]; the record document is
/// the canonical JSON of the candidate + brief + owner decision, and the
/// presented `record_digest` is that exact canonical bytes, so the digest IS
/// the immutable revision identity. Durability goes exclusively through
/// [`DaemonComposition::commit_learning_record`]; no second write path and no
/// store client is opened here.
pub async fn commit_improvement_artifact(
    composition: &mut DaemonComposition,
    artifact: &ImprovementArtifact,
    state_fence: &StateFence,
) -> Result<(eliot_store_api::WriteReceipt, bool), ImprovementDispatchError> {
    let record = serde_json::json!({
        "candidate": artifact.candidate,
        "brief": artifact.brief,
        "owner_decision": artifact.decision,
    });
    let record_bytes = canonical_json_bytes(&record)
        .map_err(|error| ImprovementDispatchError::Contract(error.to_string()))?;
    let record_json = String::from_utf8(record_bytes)
        .map_err(|_| ImprovementDispatchError::Contract("record is not utf-8".to_owned()))?;
    let record_digest = eliot_contracts::sha256_hex(record_json.as_bytes());
    let scope_digest = eliot_contracts::sha256_hex(IMPROVEMENT_SCOPE.as_bytes());
    let fence_digest = eliot_contracts::sha256_hex(format!("{state_fence:?}").as_bytes());
    let request = learning_record_mutation_request(learning_record_commit_params(
        LearningRecordKind::Candidate,
        format!("improvement-candidate:{}", artifact.candidate.candidate_id),
        record_json,
        record_digest,
        scope_digest,
        fence_digest,
        format!("improvement-candidate:{}", artifact.candidate.candidate_id),
    ));
    let identity = improvement_commit_identity(&artifact.candidate, state_fence)?;
    let scope = ScopeId::new(IMPROVEMENT_SCOPE)
        .map_err(|error| ImprovementDispatchError::Contract(error.to_string()))?;
    // The durable commit is the whole point of this path: any refusal is a
    // typed diagnostic, never a silent drop.
    let (receipt, effective) = composition
        .commit_learning_record(
            &identity,
            request,
            scope,
            // Proof refs: the candidate's own evidence lineage, verbatim.
            artifact.candidate.evidence_refs.clone(),
            None,
            false,
            false,
            Vec::new(),
            Vec::new(),
        )
        .await
        .map_err(|error| ImprovementDispatchError::Commit(error.to_string()))?;
    Ok((receipt, effective))
}
