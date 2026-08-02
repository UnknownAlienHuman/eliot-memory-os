use crate::EngineError;
use eliot_types::{
    CanonicalMemoryUtilityLedger, ForgettingOperator, MemoryCompressionArtifact,
    MemoryDistillationAction, MemoryDistillationApplyReceipt, MemoryDistillationApplySelection,
    MemoryDistillationCandidate, MemoryDistillationCheckpoint, MemoryDistillationCorpusItem,
    MemoryDistillationCorpusProfile, MemoryDistillationFinding, MemoryDistillationInput,
    MemoryDistillationPlan, MemoryDistillationScheduleRequest, MemoryEcologyDecision,
    MemoryLifecycleState, MemoryRevision, MemoryTier, MemoryUtilityLedgerEntry,
    MemoryUtilitySignalKind, MemoryUtilitySourceRecord, MemoryVitalityScore, ProjectId,
};
use serde::Serialize;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use time::OffsetDateTime;

pub const MEMORY_DISTILLATION_RULESET_VERSION: &str = "eliot-c4-distillation-v1";
const MEMORY_DISTILLATION_NORMALIZATION_TOKEN_LIMIT: usize = 12;

#[derive(Clone, Debug, Default)]
pub struct MemoryDistillationService;

impl MemoryDistillationService {
    pub fn derive_utility_ledger(
        project_id: ProjectId,
        snapshot_revision: MemoryRevision,
        source_records: &[MemoryUtilitySourceRecord],
        complete: bool,
    ) -> CanonicalMemoryUtilityLedger {
        let mut entries = BTreeMap::<String, MemoryUtilityLedgerEntry>::new();
        for record in source_records {
            let targets = if record.target_refs.is_empty() {
                vec![record.record_ref.clone()]
            } else {
                record.target_refs.clone()
            };
            let signals = utility_signals(record);
            for target_ref in targets {
                let entry =
                    entries
                        .entry(target_ref.clone())
                        .or_insert_with(|| MemoryUtilityLedgerEntry {
                            target_ref,
                            ..MemoryUtilityLedgerEntry::default()
                        });
                entry.maintenance_cost_units = entry
                    .maintenance_cost_units
                    .saturating_add(record.serialized_bytes.div_ceil(1024).max(1));
                for signal in &signals {
                    apply_utility_signal(entry, *signal, &record.payload);
                }
                if !record.evidence_ref.trim().is_empty() {
                    entry.evidence_refs.push(record.evidence_ref.clone());
                }
            }
        }
        let mut entries = entries.into_values().collect::<Vec<_>>();
        for entry in &mut entries {
            entry.evidence_refs.sort();
            entry.evidence_refs.dedup();
        }
        CanonicalMemoryUtilityLedger {
            project_id,
            snapshot_revision,
            complete,
            source_record_count: source_records.len(),
            entries,
        }
    }

    #[allow(clippy::too_many_lines)]
    pub fn plan(input: MemoryDistillationInput) -> Result<MemoryDistillationPlan, EngineError> {
        if input.ruleset_version != MEMORY_DISTILLATION_RULESET_VERSION {
            return Err(EngineError::WriteRejected(
                "unsupported memory distillation ruleset".to_owned(),
            ));
        }
        if input.utility_ledger.project_id != input.project_id
            || input.utility_ledger.snapshot_revision != input.snapshot_revision
        {
            return Err(EngineError::WriteRejected(
                "utility ledger is not bound to the distillation snapshot".to_owned(),
            ));
        }
        let profile = corpus_profile(&input.items, &input.utility_ledger);
        let ledger = input
            .utility_ledger
            .entries
            .iter()
            .map(|entry| (entry.target_ref.as_str(), entry))
            .collect::<BTreeMap<_, _>>();
        let mut candidates = Vec::new();
        let mut protected_refs = Vec::new();
        let mut unresolved_items = Vec::new();
        let mut already_classified = BTreeSet::new();

        let mut exact_groups =
            BTreeMap::<(String, String), Vec<&MemoryDistillationCorpusItem>>::new();
        for item in &input.items {
            if !item.content_hash.trim().is_empty() {
                exact_groups
                    .entry((normalize(&item.scope), item.content_hash.clone()))
                    .or_default()
                    .push(item);
            }
        }
        for mut group in exact_groups.into_values().filter(|group| group.len() > 1) {
            group.sort_by(|left, right| {
                right
                    .protected
                    .cmp(&left.protected)
                    .then_with(|| right.current_truth.cmp(&left.current_truth))
                    .then_with(|| left.target_ref.cmp(&right.target_ref))
            });
            let authoritative = group[0];
            for duplicate in group.into_iter().skip(1) {
                if duplicate.protected || duplicate.current_truth {
                    protected_refs.push(duplicate.target_ref.clone());
                    continue;
                }
                already_classified.insert(duplicate.target_ref.clone());
                candidates.push(candidate(
                    std::slice::from_ref(&duplicate.target_ref),
                    MemoryDistillationFinding::ExactDuplicate,
                    MemoryDistillationAction::Archive,
                    100,
                    true,
                    duplicate
                        .evidence_refs
                        .iter()
                        .chain(authoritative.evidence_refs.iter())
                        .cloned()
                        .collect(),
                    Vec::new(),
                )?);
            }
        }

        for item in &input.items {
            if item.protected || item.current_truth {
                protected_refs.push(item.target_ref.clone());
                continue;
            }
            if already_classified.contains(&item.target_ref) {
                continue;
            }
            let utility = ledger.get(item.target_ref.as_str()).copied();
            let finding = deterministic_item_finding(item, utility);
            let Some((finding, action, confidence, automatic)) = finding else {
                continue;
            };
            let evidence_refs = item
                .evidence_refs
                .iter()
                .chain(
                    utility
                        .into_iter()
                        .flat_map(|entry| entry.evidence_refs.iter()),
                )
                .cloned()
                .collect();
            already_classified.insert(item.target_ref.clone());
            candidates.push(candidate(
                std::slice::from_ref(&item.target_ref),
                finding,
                action,
                confidence,
                automatic,
                evidence_refs,
                item.counterexamples.clone(),
            )?);
        }

        classify_semantic_groups(
            &input.items,
            &already_classified,
            &mut candidates,
            &mut unresolved_items,
        )?;
        classify_episode_groups(&input.items, &mut candidates)?;

        if !input.complete || !input.utility_ledger.complete {
            unresolved_items.push(
                "source projection or canonical utility ledger is incomplete; no automatic apply is allowed"
                    .to_owned(),
            );
            for candidate in &mut candidates {
                candidate.automatic_apply_allowed = false;
            }
        }
        protected_refs.sort();
        protected_refs.dedup();
        candidates.sort_by(|left, right| left.candidate_id.cmp(&right.candidate_id));
        candidates.dedup_by(|left, right| left.candidate_id == right.candidate_id);
        unresolved_items.sort();
        unresolved_items.dedup();
        let expected_active_bytes_delta = candidates
            .iter()
            .filter(|candidate| candidate.automatic_apply_allowed)
            .filter_map(|candidate| candidate.target_refs.first())
            .filter_map(|target| input.items.iter().find(|item| item.target_ref == *target))
            .map(|item| -i64::try_from(item.token_units.saturating_mul(4)).unwrap_or(i64::MAX))
            .sum();
        let plan_material = (
            input.project_id,
            input.snapshot_revision,
            &input.ruleset_version,
            input.complete,
            &profile,
            &candidates,
            &protected_refs,
            &unresolved_items,
        );
        Ok(MemoryDistillationPlan {
            plan_id: stable_id("memory-distillation-plan", &plan_material)?,
            project_id: input.project_id,
            snapshot_revision: input.snapshot_revision,
            ruleset_version: input.ruleset_version,
            complete: input.complete && input.utility_ledger.complete,
            corpus_profile_before: profile,
            candidates,
            protected_refs,
            expected_active_bytes_delta,
            expected_reconstruction_delta: 0,
            unresolved_items,
        })
    }

    pub fn select_reversible_actions(
        plan: &MemoryDistillationPlan,
        selected_candidate_ids: &[String],
    ) -> Result<MemoryDistillationApplyReceipt, EngineError> {
        let mut selected = Vec::new();
        let mut rejected_candidate_ids = Vec::new();
        for candidate_id in selected_candidate_ids {
            let Some(candidate) = plan
                .candidates
                .iter()
                .find(|candidate| candidate.candidate_id == *candidate_id)
            else {
                rejected_candidate_ids.push(candidate_id.clone());
                continue;
            };
            let Some(operator) = distillation_operator(candidate.proposed_action) else {
                rejected_candidate_ids.push(candidate_id.clone());
                continue;
            };
            if !plan.complete
                || !candidate.automatic_apply_allowed
                || !candidate.reversible
                || candidate.evidence_refs.is_empty()
                || candidate.target_refs.is_empty()
            {
                rejected_candidate_ids.push(candidate_id.clone());
                continue;
            }
            selected.push(MemoryDistillationApplySelection {
                candidate_id: candidate.candidate_id.clone(),
                target_ref: candidate.target_refs[0].clone(),
                operator,
                evidence_refs: candidate.evidence_refs.clone(),
                restore_conditions: candidate.restore_conditions.clone(),
            });
        }
        selected.sort_by(|left, right| left.candidate_id.cmp(&right.candidate_id));
        selected.dedup_by(|left, right| left.candidate_id == right.candidate_id);
        rejected_candidate_ids.sort();
        rejected_candidate_ids.dedup();
        Ok(MemoryDistillationApplyReceipt {
            apply_id: stable_id(
                "memory-distillation-apply",
                &(plan.plan_id.as_str(), &selected, &rejected_candidate_ids),
            )?,
            plan_id: plan.plan_id.clone(),
            project_id: plan.project_id,
            snapshot_revision: plan.snapshot_revision,
            selected,
            rejected_candidate_ids,
            write_receipts: Vec::new(),
        })
    }

    pub fn validate_compression(
        artifact: &MemoryCompressionArtifact,
        protected_constraints: &[String],
    ) -> Result<(), EngineError> {
        let preserved = artifact
            .invariant_core
            .iter()
            .chain(artifact.preserved_exact_atoms.iter())
            .chain(artifact.applicability_boundary.iter())
            .chain(artifact.counterexamples.iter())
            .chain(artifact.verifier_refs.iter())
            .map(|value| normalize(value))
            .collect::<BTreeSet<_>>();
        let missing = protected_constraints
            .iter()
            .filter(|constraint| !preserved.contains(&normalize(constraint)))
            .cloned()
            .collect::<Vec<_>>();
        if artifact.source_refs.is_empty()
            || artifact.output_ref.trim().is_empty()
            || artifact.required_probe.trim().is_empty()
            || artifact.verifier_refs.is_empty()
            || artifact.replay_requirement.trim().is_empty()
            || !artifact.candidate_only
            || artifact.output_token_units >= artifact.input_token_units
            || !missing.is_empty()
        {
            return Err(EngineError::WriteRejected(format!(
                "compression loses protected structure or is not replay-bound: missing={missing:?}"
            )));
        }
        Ok(())
    }

    pub fn schedule(request: &MemoryDistillationScheduleRequest) -> MemoryDistillationCheckpoint {
        let invalid_batch = request.batch_size == 0 || request.batch_size > 500;
        let insufficient_evidence = request.new_evidence_count < request.minimum_evidence_count;
        let paused = request.interactive_load_active || invalid_batch || insufficient_evidence;
        let reason = if request.interactive_load_active {
            "paused_under_interactive_load"
        } else if invalid_batch {
            "batch_size_out_of_bounds"
        } else if insufficient_evidence {
            "insufficient_new_verified_evidence"
        } else {
            "bounded_distillation_ready"
        };
        MemoryDistillationCheckpoint {
            project_id: request.project_id,
            trigger: request.trigger,
            cursor: request.cursor.clone(),
            batch_size: request.batch_size.clamp(1, 500),
            paused,
            reason: reason.to_owned(),
        }
    }

    pub fn tier(
        item: &MemoryDistillationCorpusItem,
        utility: Option<&MemoryUtilityLedgerEntry>,
    ) -> MemoryTier {
        if matches!(
            item.lifecycle,
            MemoryLifecycleState::Suppressed
                | MemoryLifecycleState::Quarantined
                | MemoryLifecycleState::Poisoned
        ) {
            return MemoryTier::SuppressedQuarantined;
        }
        if matches!(
            item.lifecycle,
            MemoryLifecycleState::Archived
                | MemoryLifecycleState::Forgotten
                | MemoryLifecycleState::HardDeleted
                | MemoryLifecycleState::RetainedForAudit
        ) {
            return MemoryTier::ArchivedAudit;
        }
        let useful = utility.is_some_and(|entry| {
            entry.beneficial_use_count > 0
                || entry.prevented_failure_count > 0
                || entry.verification_success_count > entry.verification_failure_count
        });
        if item.current_truth
            || item.negative_memory
            || item.status.eq_ignore_ascii_case("verified")
            || item.record_kind.contains("procedure")
            || useful
        {
            MemoryTier::Hot
        } else if item.record_kind.contains("experience")
            || item.record_kind.contains("pattern")
            || item.status.eq_ignore_ascii_case("supported")
        {
            MemoryTier::Warm
        } else {
            MemoryTier::Cold
        }
    }

    pub fn vitality_from_ledger(
        project_id: ProjectId,
        target_ref: &str,
        ledger: &CanonicalMemoryUtilityLedger,
    ) -> MemoryVitalityScore {
        let entry = ledger
            .entries
            .iter()
            .find(|entry| entry.target_ref == target_ref)
            .cloned()
            .unwrap_or_else(|| MemoryUtilityLedgerEntry {
                target_ref: target_ref.to_owned(),
                ..MemoryUtilityLedgerEntry::default()
            });
        let utility_raw = entry.beneficial_use_count.saturating_mul(140)
            + entry.prevented_failure_count.saturating_mul(190)
            + entry.correct_verifier_selection_count.saturating_mul(120)
            + entry.verification_success_count.saturating_mul(50);
        let harm_raw = entry.negative_transfer_count.saturating_mul(300)
            + entry.false_activation_count.saturating_mul(220)
            + entry.stale_hits.saturating_mul(120)
            + entry.verification_failure_count.saturating_mul(100)
            + entry.contradiction_count.saturating_mul(160);
        let utility_millis = i64::try_from(utility_raw.min(1000)).unwrap_or(1000);
        let harm_millis = i64::try_from(harm_raw.min(1000)).unwrap_or(1000);
        let decision = if entry.negative_transfer_count > 0 || entry.false_activation_count >= 2 {
            MemoryEcologyDecision::Suppress
        } else if entry.contradiction_count > 0 {
            MemoryEcologyDecision::SplitPattern
        } else if entry.stale_hits > 0 {
            MemoryEcologyDecision::RequireRevalidation
        } else if entry.context_cost_tokens > 512 && entry.beneficial_use_count == 0 {
            MemoryEcologyDecision::KeepHandleOnly
        } else if harm_millis > utility_millis {
            MemoryEcologyDecision::Demote
        } else {
            MemoryEcologyDecision::KeepHot
        };
        MemoryVitalityScore {
            memory_ref: target_ref.to_owned(),
            project_id,
            reuse_count: signal_count(&entry, MemoryUtilitySignalKind::PacketInclusion),
            decision_delta_history: Vec::new(),
            verification_success_count: entry.verification_success_count,
            verification_failure_count: entry.verification_failure_count,
            stale_hits: entry.stale_hits,
            false_activation_count: entry.false_activation_count,
            beneficial_use_count: entry.beneficial_use_count,
            prevented_failure_count: entry.prevented_failure_count,
            correct_verifier_selection_count: entry.correct_verifier_selection_count,
            negative_transfer_count: entry.negative_transfer_count,
            contradiction_count: entry.contradiction_count,
            context_cost_tokens: entry.context_cost_tokens,
            maintenance_cost_units: entry.maintenance_cost_units,
            minority_importance_millis: 0,
            freshness_millis: 0,
            scope_fit_millis: if entry.scope_suppressions == 0 {
                1000
            } else {
                0
            },
            utility_millis,
            harm_millis,
            decision,
            recency_score: 0.0,
            scope_fit_score: if entry.scope_suppressions == 0 {
                1.0
            } else {
                0.0
            },
            utility_score: f64::from(i32::try_from(utility_millis).unwrap_or(1000)) / 1000.0,
            harm_score: f64::from(i32::try_from(harm_millis).unwrap_or(1000)) / 1000.0,
            computed_at: OffsetDateTime::now_utc(),
        }
    }
}

fn utility_signals(record: &MemoryUtilitySourceRecord) -> Vec<MemoryUtilitySignalKind> {
    let kind = record.record_kind.to_ascii_lowercase();
    let mut signals = Vec::new();
    if kind.contains("injection_receipt") {
        signals.push(MemoryUtilitySignalKind::InjectionReceipt);
        signals.push(MemoryUtilitySignalKind::PacketInclusion);
    }
    if kind.contains("fetch_atoms_l2") || kind.contains("exact_l2") {
        signals.push(MemoryUtilitySignalKind::ExactL2Expansion);
    }
    if kind.contains("context_packet") {
        signals.push(MemoryUtilitySignalKind::PacketInclusion);
        signals.push(MemoryUtilitySignalKind::ContextTokenCost);
    }
    if kind.contains("understanding") {
        signals.push(MemoryUtilitySignalKind::UnderstandingProofCitation);
    }
    if kind.contains("action_contract") {
        signals.push(MemoryUtilitySignalKind::ActionContractCitation);
    }
    if kind.contains("verification") {
        signals.push(MemoryUtilitySignalKind::VerificationCitation);
    }
    if kind.contains("completion_proof") {
        signals.push(MemoryUtilitySignalKind::CompletionProofCitation);
    }
    if kind.contains("memory_influence") {
        signals.push(MemoryUtilitySignalKind::Influence);
    }
    for (key, signal) in [
        (
            "prevented_repeated_failure",
            MemoryUtilitySignalKind::PreventedRepeatedFailure,
        ),
        (
            "correct_verifier_selection",
            MemoryUtilitySignalKind::CorrectVerifierSelection,
        ),
        (
            "prediction_resolution",
            MemoryUtilitySignalKind::PredictionResolution,
        ),
        (
            "negative_transfer",
            MemoryUtilitySignalKind::NegativeTransfer,
        ),
        (
            "stale_suppression",
            MemoryUtilitySignalKind::StaleSuppression,
        ),
        (
            "scope_suppression",
            MemoryUtilitySignalKind::ScopeSuppression,
        ),
        ("false_activation", MemoryUtilitySignalKind::FalseActivation),
        ("contradiction", MemoryUtilitySignalKind::Contradiction),
        (
            "repeated_low_delta",
            MemoryUtilitySignalKind::RepeatedLowDeltaLoad,
        ),
        ("restore_regret", MemoryUtilitySignalKind::RestoreRegret),
        (
            "missing_context_regret",
            MemoryUtilitySignalKind::MissingContextRegret,
        ),
    ] {
        if payload_signal(&record.payload, key) {
            signals.push(signal);
        }
    }
    signals.push(MemoryUtilitySignalKind::MaintenanceCost);
    signals.sort();
    signals.dedup();
    signals
}

fn apply_utility_signal(
    entry: &mut MemoryUtilityLedgerEntry,
    signal: MemoryUtilitySignalKind,
    payload: &Value,
) {
    *entry.signal_counts.entry(signal).or_insert(0) += 1;
    match signal {
        MemoryUtilitySignalKind::InjectionReceipt
        | MemoryUtilitySignalKind::ExactL2Expansion
        | MemoryUtilitySignalKind::PacketInclusion
        | MemoryUtilitySignalKind::UnderstandingProofCitation
        | MemoryUtilitySignalKind::ActionContractCitation
        | MemoryUtilitySignalKind::CompletionProofCitation
        | MemoryUtilitySignalKind::Influence
        | MemoryUtilitySignalKind::PredictionResolution => {
            entry.beneficial_use_count = entry.beneficial_use_count.saturating_add(1);
        }
        MemoryUtilitySignalKind::VerificationCitation => {
            if payload_string(payload, "result").as_deref() == Some("failed") {
                entry.verification_failure_count =
                    entry.verification_failure_count.saturating_add(1);
            } else {
                entry.verification_success_count =
                    entry.verification_success_count.saturating_add(1);
            }
        }
        MemoryUtilitySignalKind::PreventedRepeatedFailure => {
            entry.prevented_failure_count = entry.prevented_failure_count.saturating_add(1);
        }
        MemoryUtilitySignalKind::CorrectVerifierSelection => {
            entry.correct_verifier_selection_count =
                entry.correct_verifier_selection_count.saturating_add(1);
        }
        MemoryUtilitySignalKind::NegativeTransfer => {
            entry.negative_transfer_count = entry.negative_transfer_count.saturating_add(1);
        }
        MemoryUtilitySignalKind::StaleSuppression => {
            entry.stale_hits = entry.stale_hits.saturating_add(1);
        }
        MemoryUtilitySignalKind::ScopeSuppression => {
            entry.scope_suppressions = entry.scope_suppressions.saturating_add(1);
        }
        MemoryUtilitySignalKind::FalseActivation => {
            entry.false_activation_count = entry.false_activation_count.saturating_add(1);
        }
        MemoryUtilitySignalKind::Contradiction => {
            entry.contradiction_count = entry.contradiction_count.saturating_add(1);
        }
        MemoryUtilitySignalKind::RepeatedLowDeltaLoad => {
            entry.repeated_low_delta_loads = entry.repeated_low_delta_loads.saturating_add(1);
        }
        MemoryUtilitySignalKind::ContextTokenCost => {
            entry.context_cost_tokens = entry
                .context_cost_tokens
                .saturating_add(payload_u64(payload, "estimated_tokens").unwrap_or(1));
        }
        MemoryUtilitySignalKind::MaintenanceCost => {}
        MemoryUtilitySignalKind::RestoreRegret => {
            entry.restore_regret_count = entry.restore_regret_count.saturating_add(1);
        }
        MemoryUtilitySignalKind::MissingContextRegret => {
            entry.missing_context_regret_count =
                entry.missing_context_regret_count.saturating_add(1);
        }
    }
}

fn deterministic_item_finding(
    item: &MemoryDistillationCorpusItem,
    utility: Option<&MemoryUtilityLedgerEntry>,
) -> Option<(
    MemoryDistillationFinding,
    MemoryDistillationAction,
    u16,
    bool,
)> {
    if item.certification_noise {
        return Some((
            MemoryDistillationFinding::ObsoleteArtifact,
            MemoryDistillationAction::Archive,
            100,
            true,
        ));
    }
    if item.obsolete_replacement.is_some() {
        return Some((
            MemoryDistillationFinding::ObsoleteArtifact,
            MemoryDistillationAction::Archive,
            100,
            true,
        ));
    }
    if item.superseded_by.is_some() && !item.evidence_refs.is_empty() {
        return Some((
            MemoryDistillationFinding::StaleSuperseded,
            MemoryDistillationAction::Archive,
            100,
            true,
        ));
    }
    if item.exact_scope_contradiction.is_some() && !item.evidence_refs.is_empty() {
        return Some((
            MemoryDistillationFinding::WrongScope,
            MemoryDistillationAction::Suppress,
            100,
            true,
        ));
    }
    if matches!(item.lifecycle, MemoryLifecycleState::Poisoned) {
        return Some((
            MemoryDistillationFinding::Poisoned,
            MemoryDistillationAction::Quarantine,
            100,
            false,
        ));
    }
    if utility.is_some_and(|entry| entry.negative_transfer_count > 0) {
        return Some((
            MemoryDistillationFinding::HarmfulTransfer,
            MemoryDistillationAction::Quarantine,
            95,
            false,
        ));
    }
    if utility.is_some_and(|entry| {
        entry.repeated_low_delta_loads >= 2
            && entry.beneficial_use_count == 0
            && !entry.evidence_refs.is_empty()
    }) {
        return Some((
            MemoryDistillationFinding::RepeatedLowDelta,
            MemoryDistillationAction::KeepHandleOnly,
            100,
            true,
        ));
    }
    if utility
        .is_some_and(|entry| entry.context_cost_tokens > 512 && entry.beneficial_use_count == 0)
    {
        return Some((
            MemoryDistillationFinding::HighCostLowValue,
            MemoryDistillationAction::Demote,
            90,
            false,
        ));
    }
    None
}

fn classify_semantic_groups(
    items: &[MemoryDistillationCorpusItem],
    already_classified: &BTreeSet<String>,
    candidates: &mut Vec<MemoryDistillationCandidate>,
    unresolved: &mut Vec<String>,
) -> Result<(), EngineError> {
    let mut groups = BTreeMap::<(String, String), Vec<&MemoryDistillationCorpusItem>>::new();
    for item in items {
        if already_classified.contains(&item.target_ref)
            || item.normalized_proposition.trim().is_empty()
            || item.mechanism.trim().is_empty()
        {
            continue;
        }
        groups
            .entry((
                normalize(&item.normalized_proposition),
                normalize(&item.mechanism),
            ))
            .or_default()
            .push(item);
    }
    for group in groups.into_values().filter(|group| group.len() > 1) {
        let first = group[0];
        let equivalent = group.iter().skip(1).all(|item| {
            normalized_set(&item.applies_when) == normalized_set(&first.applies_when)
                && normalized_set(&item.does_not_apply_when)
                    == normalized_set(&first.does_not_apply_when)
                && normalized_set(&item.counterexamples) == normalized_set(&first.counterexamples)
                && normalize(&item.scope) == normalize(&first.scope)
        });
        let targets = group
            .iter()
            .map(|item| item.target_ref.clone())
            .collect::<Vec<_>>();
        let evidence = group
            .iter()
            .flat_map(|item| item.evidence_refs.clone())
            .collect::<Vec<_>>();
        if equivalent && group.iter().all(|item| item.counterexamples.is_empty()) {
            candidates.push(candidate(
                &targets,
                MemoryDistillationFinding::SemanticDuplicate,
                MemoryDistillationAction::Supersede,
                90,
                false,
                evidence,
                Vec::new(),
            )?);
        } else {
            unresolved.push(format!(
                "near_miss_requires_bounded_reasoning:{}",
                targets.join(",")
            ));
            candidates.push(candidate(
                &targets,
                MemoryDistillationFinding::NearMiss,
                MemoryDistillationAction::KeepHot,
                50,
                false,
                evidence,
                group
                    .iter()
                    .flat_map(|item| item.counterexamples.clone())
                    .collect(),
            )?);
        }
    }
    Ok(())
}

fn classify_episode_groups(
    items: &[MemoryDistillationCorpusItem],
    candidates: &mut Vec<MemoryDistillationCandidate>,
) -> Result<(), EngineError> {
    let mut groups = BTreeMap::<String, Vec<&MemoryDistillationCorpusItem>>::new();
    for item in items.iter().filter(|item| {
        item.record_kind.contains("episode") || item.record_kind.contains("experience_case")
    }) {
        if !item.mechanism.trim().is_empty() {
            groups
                .entry(normalize(&item.mechanism))
                .or_default()
                .push(item);
        }
    }
    for group in groups.into_values().filter(|group| group.len() > 1) {
        let targets = group
            .iter()
            .map(|item| item.target_ref.clone())
            .collect::<Vec<_>>();
        candidates.push(candidate(
            &targets,
            MemoryDistillationFinding::CompressibleEpisodeGroup,
            MemoryDistillationAction::ProposePattern,
            80,
            false,
            group
                .iter()
                .flat_map(|item| item.evidence_refs.clone())
                .collect(),
            group
                .iter()
                .flat_map(|item| item.counterexamples.clone())
                .collect(),
        )?);
    }
    Ok(())
}

fn candidate(
    targets: &[String],
    finding: MemoryDistillationFinding,
    action: MemoryDistillationAction,
    confidence: u16,
    automatic_apply_allowed: bool,
    mut evidence_refs: Vec<String>,
    mut counterevidence_refs: Vec<String>,
) -> Result<MemoryDistillationCandidate, EngineError> {
    let mut target_refs = targets.to_vec();
    target_refs.sort();
    target_refs.dedup();
    evidence_refs.sort();
    evidence_refs.dedup();
    counterevidence_refs.sort();
    counterevidence_refs.dedup();
    Ok(MemoryDistillationCandidate {
        candidate_id: stable_id(
            "memory-distillation-candidate",
            &(
                &target_refs,
                finding,
                action,
                &evidence_refs,
                &counterevidence_refs,
            ),
        )?,
        target_refs,
        finding,
        evidence_refs,
        counterevidence_refs,
        confidence,
        proposed_action: action,
        automatic_apply_allowed,
        reversible: !matches!(action, MemoryDistillationAction::Compress),
        restore_conditions: vec![
            "exact transition receipt remains available".to_owned(),
            "fresh evidence justifies reactivation".to_owned(),
        ],
    })
}

fn corpus_profile(
    items: &[MemoryDistillationCorpusItem],
    ledger: &CanonicalMemoryUtilityLedger,
) -> MemoryDistillationCorpusProfile {
    let utility = ledger
        .entries
        .iter()
        .map(|entry| (entry.target_ref.as_str(), entry))
        .collect::<BTreeMap<_, _>>();
    let mut tier_counts = BTreeMap::new();
    let mut active_bytes = 0_u64;
    for item in items {
        let tier =
            MemoryDistillationService::tier(item, utility.get(item.target_ref.as_str()).copied());
        *tier_counts.entry(tier).or_insert(0) += 1;
        if matches!(tier, MemoryTier::Hot | MemoryTier::Warm) {
            active_bytes = active_bytes.saturating_add(item.token_units.saturating_mul(4));
        }
    }
    MemoryDistillationCorpusProfile {
        physical_records: items.len(),
        logical_items: items
            .iter()
            .map(|item| item.target_ref.as_str())
            .collect::<BTreeSet<_>>()
            .len(),
        total_bytes: items
            .iter()
            .map(|item| item.token_units.saturating_mul(4))
            .sum(),
        active_bytes,
        tier_counts,
    }
}

fn distillation_operator(action: MemoryDistillationAction) -> Option<ForgettingOperator> {
    match action {
        MemoryDistillationAction::KeepHandleOnly | MemoryDistillationAction::Demote => {
            Some(ForgettingOperator::Demote)
        }
        MemoryDistillationAction::Suppress => Some(ForgettingOperator::Suppress),
        MemoryDistillationAction::Supersede => Some(ForgettingOperator::Supersede),
        MemoryDistillationAction::Archive => Some(ForgettingOperator::Archive),
        MemoryDistillationAction::Quarantine => Some(ForgettingOperator::MarkPoisoned),
        MemoryDistillationAction::Restore => Some(ForgettingOperator::Restore),
        MemoryDistillationAction::KeepHot
        | MemoryDistillationAction::Compress
        | MemoryDistillationAction::ProposePattern
        | MemoryDistillationAction::ProposeProcedure => None,
    }
}

fn signal_count(entry: &MemoryUtilityLedgerEntry, signal: MemoryUtilitySignalKind) -> u64 {
    entry.signal_counts.get(&signal).copied().unwrap_or(0)
}

fn payload_signal(value: &Value, key: &str) -> bool {
    match value.get(key) {
        Some(Value::Bool(value)) => *value,
        Some(Value::Number(value)) => value.as_u64().unwrap_or(0) > 0,
        Some(Value::String(value)) => !value.trim().is_empty() && value != "false" && value != "0",
        Some(Value::Array(value)) => !value.is_empty(),
        Some(Value::Object(value)) => !value.is_empty(),
        _ => value
            .as_object()
            .into_iter()
            .flat_map(|object| object.values())
            .any(|nested| payload_signal(nested, key)),
    }
}

fn payload_string(value: &Value, key: &str) -> Option<String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .map(str::to_ascii_lowercase)
        .or_else(|| {
            value
                .as_object()
                .into_iter()
                .flat_map(|object| object.values())
                .find_map(|nested| payload_string(nested, key))
        })
}

fn payload_u64(value: &Value, key: &str) -> Option<u64> {
    value.get(key).and_then(Value::as_u64).or_else(|| {
        value
            .as_object()
            .into_iter()
            .flat_map(|object| object.values())
            .find_map(|nested| payload_u64(nested, key))
    })
}

fn normalize(value: &str) -> String {
    eliot_types::normalize_query_tokens(value)
        .into_iter()
        .take(MEMORY_DISTILLATION_NORMALIZATION_TOKEN_LIMIT)
        .collect::<Vec<_>>()
        .join(" ")
}

fn normalized_set(values: &[String]) -> BTreeSet<String> {
    values.iter().map(|value| normalize(value)).collect()
}

fn stable_id(prefix: &str, value: &impl Serialize) -> Result<String, EngineError> {
    let encoded = serde_json::to_vec(value)?;
    Ok(format!("{prefix}:{}", blake3::hash(&encoded).to_hex()))
}

#[cfg(test)]
mod tests {
    use super::normalize;

    #[test]
    fn semantic_normalization_keeps_its_twelve_token_identity_boundary() {
        let twelve = "zulu alpha beta gamma delta epsilon zeta eta theta iota kappa lambda";
        assert_eq!(normalize(&format!("{twelve} memory")), twelve);
    }
}
