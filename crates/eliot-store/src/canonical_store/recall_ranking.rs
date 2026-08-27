//! Architecture P.6 canonical Store
//! Implementation I2.19 — canonical recall ranking boundary (read/filter/rank/dedup only)

use std::collections::BTreeMap;

use eliot_types::{
    CognitiveProjectionReadState, L0CollapsedDuplicateTrace, L0FeatureScore, L0RankTrace,
    L0SuppressionTrace, MemoryConfidence, MemoryHandlePreview, MemoryRevision, ProjectSequence,
    RecallL0Request, RecallL0Response, TruncationInfo,
};

use super::{MAX_RECALL_RESULTS, RecallCandidateLoad, RecallCandidateRow};

#[derive(Clone)]
struct RankedRecallCandidate {
    row: RecallCandidateRow,
    score: L0FeatureScore,
    retrieval_admitted: bool,
}

#[allow(clippy::too_many_lines)]
pub(super) fn rank_recall_candidates(
    request: &RecallL0Request,
    load: RecallCandidateLoad,
) -> RecallL0Response {
    let query_tokens = eliot_types::normalize_query_tokens(&request.query);
    let normalized_query = query_tokens.join(" ");
    let exact_query = request.query.trim().to_lowercase();
    let candidates_considered = load.candidates.len();
    let mut lifecycle_suppressions = Vec::new();
    let mut scope_suppressions = Vec::new();
    let mut filtered = Vec::with_capacity(load.candidates.len());
    for row in load.candidates {
        if !request.lifecycle_audit && !is_default_visible_lifecycle(row.lifecycle_state) {
            lifecycle_suppressions.push(L0SuppressionTrace {
                handle: row.handle,
                reason: format!(
                    "lifecycle_{}",
                    row.lifecycle_state
                        .map_or_else(|| "unknown".to_owned(), |state| format!("{state:?}"))
                        .to_ascii_lowercase()
                ),
            });
            continue;
        }
        let Some(scope_fit) = recall_scope_fit(&row.scope_text, &request.scope_refs) else {
            scope_suppressions.push(L0SuppressionTrace {
                handle: row.handle,
                reason: "scope_mismatch".to_owned(),
            });
            continue;
        };
        filtered.push((row, scope_fit));
    }
    let (capacity_segments, ordinary): (Vec<_>, Vec<_>) = filtered
        .into_iter()
        .partition(|(row, _)| row.record_type == "memory_blob_segment");
    let (collapsed, mut collapsed_duplicates) = collapse_recall_candidates(ordinary);
    let mut admitted = collapsed
        .into_iter()
        .map(|(row, scope_fit)| {
            rank_recall_candidate(
                row,
                scope_fit,
                request,
                load.at_revision,
                &query_tokens,
                &normalized_query,
                &exact_query,
            )
        })
        .filter(|candidate| candidate.retrieval_admitted)
        .collect::<Vec<_>>();
    admitted.extend(capacity_segments.into_iter().map(|(row, scope_fit)| {
        rank_recall_candidate(
            row,
            scope_fit,
            request,
            load.at_revision,
            &query_tokens,
            &normalized_query,
            &exact_query,
        )
    }));
    let (deduplicated_segments, segment_traces) = collapse_ranked_capacity_segments(admitted);
    admitted = deduplicated_segments
        .into_iter()
        .filter(|candidate| candidate.retrieval_admitted)
        .collect();
    collapsed_duplicates.extend(segment_traces);
    admitted.sort_by(|left, right| {
        right
            .score
            .total
            .cmp(&left.score.total)
            .then_with(|| right.row.authority_rank.cmp(&left.row.authority_rank))
            .then_with(|| left.row.handle.cmp(&right.row.handle))
    });
    let admitted_count = admitted.len();
    admitted.truncate(MAX_RECALL_RESULTS);
    let top_score = admitted.first().map(|candidate| candidate.score.total);
    let memory_confidence = MemoryConfidence::from_top_score(top_score);
    let handles = admitted
        .iter()
        .map(|candidate| MemoryHandlePreview {
            handle: candidate.row.handle.clone(),
            record_type: candidate.row.record_type.clone(),
            preview: candidate.row.preview.clone(),
            lifecycle_state: candidate.row.lifecycle_state,
            lifecycle_badge: None,
        })
        .collect::<Vec<_>>();
    let feature_scores = admitted
        .into_iter()
        .map(|candidate| candidate.score)
        .collect::<Vec<_>>();
    let candidates_returned = handles.len();
    let query_mode = "unicode_multi_kind_lifecycle_aware_v4".to_owned();

    RecallL0Response {
        project_id: request.project_id,
        at_revision: load.at_revision,
        projection_revision: Some(load.at_revision),
        projection_state: CognitiveProjectionReadState::Published,
        handles,
        memory_confidence,
        query_mode: query_mode.clone(),
        rank_trace: L0RankTrace {
            query: request.query.clone(),
            normalized_query,
            candidates_considered,
            candidates_returned,
            feature_scores,
            lifecycle_suppressions,
            scope_suppressions,
            collapsed_duplicates,
            no_useful_memory: candidates_returned == 0,
            query_mode,
        },
        truncation: TruncationInfo {
            truncated: load.truncated || admitted_count > MAX_RECALL_RESULTS,
            limit: MAX_RECALL_RESULTS,
            returned: candidates_returned,
        },
    }
}

fn collapse_ranked_capacity_segments(
    candidates: Vec<RankedRecallCandidate>,
) -> (Vec<RankedRecallCandidate>, Vec<L0CollapsedDuplicateTrace>) {
    let mut ordinary = Vec::new();
    let mut by_parent = BTreeMap::<String, Vec<RankedRecallCandidate>>::new();
    for candidate in candidates {
        if candidate.row.record_type == "memory_blob_segment" {
            by_parent
                .entry(candidate.row.handle.clone())
                .or_default()
                .push(candidate);
        } else {
            ordinary.push(candidate);
        }
    }
    let mut traces = Vec::new();
    for (parent_handle, mut segments) in by_parent {
        segments.sort_by(|left, right| {
            right
                .score
                .total
                .cmp(&left.score.total)
                .then_with(|| right.row.authority_rank.cmp(&left.row.authority_rank))
                .then_with(|| {
                    left.row
                        .source_segment_ordinal
                        .unwrap_or_default()
                        .cmp(&right.row.source_segment_ordinal.unwrap_or_default())
                })
                .then_with(|| left.row.record_ref.cmp(&right.row.record_ref))
        });
        let authoritative = segments.remove(0);
        if !segments.is_empty() {
            traces.push(L0CollapsedDuplicateTrace {
                authoritative_handle: parent_handle,
                collapsed_record_refs: segments
                    .iter()
                    .map(|segment| segment.row.record_ref.clone())
                    .collect(),
                reason: "parent_segment_dedup_after_scoring".to_owned(),
            });
        }
        ordinary.push(authoritative);
    }
    (ordinary, traces)
}

#[allow(clippy::too_many_lines)]
fn rank_recall_candidate(
    row: RecallCandidateRow,
    scope_fit: i32,
    request: &RecallL0Request,
    at_revision: MemoryRevision,
    query_tokens: &[String],
    normalized_query: &str,
    exact_query: &str,
) -> RankedRecallCandidate {
    let candidate_tokens = eliot_types::normalize_query_tokens(&row.search_text);
    let preview_tokens = eliot_types::normalize_query_tokens(&row.preview);
    let cue_tokens = eliot_types::normalize_query_tokens(&row.cue_text);
    let concept_tokens = eliot_types::normalize_query_tokens(&row.concept_text);
    let normalized_preview = preview_tokens.join(" ");
    let overlap = query_tokens
        .iter()
        .filter(|token| candidate_tokens.contains(token))
        .count();
    let overlap_score = i32::try_from(overlap).unwrap_or(i32::MAX);
    let exact_identifier = i32::from(row.handle.to_lowercase() == exact_query) * 1_000;
    let subject_identity =
        i32::from(!query_tokens.is_empty() && overlap == query_tokens.len()) * 200;
    let exact_preview =
        i32::from(!normalized_query.is_empty() && normalized_preview == normalized_query) * 250;
    let preview_contains =
        i32::from(!normalized_query.is_empty() && normalized_preview.contains(normalized_query))
            * 140;
    let lexical_overlap = overlap_score * 40 + exact_preview + preview_contains;
    let normalized_cues = cue_tokens.join(" ");
    let query_exact_cue = i32::from(
        !normalized_query.is_empty()
            && (normalized_cues == normalized_query || normalized_cues.contains(normalized_query)),
    ) * 180;
    let requested_cue_hits = request
        .task_class_cues
        .iter()
        .flat_map(|cue| eliot_types::normalize_query_tokens(cue))
        .filter(|cue| cue_tokens.contains(cue))
        .count();
    let exact_cue = query_exact_cue + i32::try_from(requested_cue_hits.min(4)).unwrap_or(4) * 40;
    let task_relation = i32::from(
        request.task_id.is_some() && row.task_id.is_some() && request.task_id == row.task_id,
    ) * 120;
    let concept_query_overlap = query_tokens
        .iter()
        .filter(|token| concept_tokens.contains(token))
        .count();
    let requested_concept_hits = request
        .concept_refs
        .iter()
        .flat_map(|concept| eliot_types::normalize_query_tokens(concept))
        .filter(|token| concept_tokens.contains(token))
        .count();
    let concept_relation = i32::try_from(concept_query_overlap.min(4)).unwrap_or(4) * 25
        + i32::try_from(requested_concept_hits.min(4)).unwrap_or(4) * 40;
    let lifecycle_fit = match row.lifecycle_state {
        Some(
            eliot_types::MemoryLifecycleState::Active | eliot_types::MemoryLifecycleState::Restored,
        )
        | None => 20,
        Some(eliot_types::MemoryLifecycleState::Dormant) => -20,
        _ => 0,
    };
    let evidence_authority = row.authority_rank.clamp(0, 100);
    let revision_distance = row.memory_revision.map_or(u64::MAX, |revision| {
        at_revision.value().saturating_sub(revision.value())
    });
    let freshness_fit = match revision_distance {
        0 => 40,
        1..=5 => 20,
        6..=50 => 5,
        _ => 0,
    };
    let negative_memory_value = i32::from(row.negative_memory && overlap > 0) * 80;
    let known_decision_delta = i32::from(row.known_decision_delta > 0 && overlap > 0) * 60;
    let prior_beneficial_use = row.prior_beneficial_use.clamp(0, 10) * 5;
    let verification_value = if overlap > 0 {
        row.verification_value.clamp(0, 100)
    } else {
        0
    };
    let context_cost = -i32::try_from(row.preview.len().div_ceil(64).min(40)).unwrap_or(40);
    let stale_penalty = if matches!(
        row.lifecycle_state,
        Some(eliot_types::MemoryLifecycleState::Stale)
    ) || row.status.eq_ignore_ascii_case("stale")
    {
        -300
    } else {
        0
    };
    let contradiction_penalty = i32::from(row.contradiction_signal) * -120;
    let harm_penalty = i32::from(row.harm_signal) * -250;
    let repetition_penalty = i32::from(row.repetition_signal) * -40;
    let weak_single_token = query_tokens.len() > 2 && overlap == 1;
    let distraction_penalty = i32::from(row.distraction_signal || weak_single_token) * -60;
    let total = exact_identifier
        + subject_identity
        + lexical_overlap
        + exact_cue
        + task_relation
        + scope_fit
        + concept_relation
        + lifecycle_fit
        + freshness_fit
        + evidence_authority
        + negative_memory_value
        + known_decision_delta
        + prior_beneficial_use
        + verification_value
        + context_cost
        + stale_penalty
        + contradiction_penalty
        + harm_penalty
        + repetition_penalty
        + distraction_penalty;
    let retrieval_signal = overlap > 0
        || exact_preview > 0
        || preview_contains > 0
        || exact_cue > 0
        || concept_relation > 0;
    let retrieval_admitted = exact_identifier != 0 || (retrieval_signal && total >= 80);
    let mut reasons = Vec::new();
    if exact_identifier > 0 {
        reasons.push("exact_handle".to_owned());
    }
    if subject_identity > 0 {
        reasons.push("all_query_tokens".to_owned());
    }
    if overlap > 0 {
        reasons.push(format!("token_overlap:{overlap}"));
    }
    if exact_preview > 0 {
        reasons.push("exact_preview".to_owned());
    }
    if preview_contains > 0 {
        reasons.push("preview_contains_query".to_owned());
    }
    if exact_cue > 0 {
        reasons.push("exact_normalized_cue".to_owned());
    }
    if task_relation > 0 {
        reasons.push("current_task_relation".to_owned());
    }
    if scope_fit > 0 {
        reasons.push("scope_fit".to_owned());
    }
    if concept_relation > 0 {
        reasons.push("concept_relation".to_owned());
    }
    if negative_memory_value > 0 {
        reasons.push("negative_memory_overlap".to_owned());
    }
    if known_decision_delta > 0 {
        reasons.push("known_decision_delta".to_owned());
    }
    if prior_beneficial_use > 0 {
        reasons.push("prior_beneficial_use".to_owned());
    }
    if verification_value > 0 {
        reasons.push("verification_value".to_owned());
    }
    if stale_penalty < 0 {
        reasons.push("stale_penalty".to_owned());
    }
    if contradiction_penalty < 0 {
        reasons.push("contradiction_penalty".to_owned());
    }
    if harm_penalty < 0 {
        reasons.push("harm_penalty".to_owned());
    }
    if repetition_penalty < 0 {
        reasons.push("repetition_penalty".to_owned());
    }
    if distraction_penalty < 0 {
        reasons.push("distraction_penalty".to_owned());
    }
    RankedRecallCandidate {
        score: L0FeatureScore {
            handle: row.handle.clone(),
            exact_identifier,
            subject_identity,
            lexical_overlap,
            task_relation,
            scope_fit,
            lifecycle_fit,
            evidence_authority,
            prior_decision_delta: negative_memory_value,
            exact_cue,
            concept_relation,
            freshness_fit,
            negative_memory_value,
            known_decision_delta,
            prior_beneficial_use,
            verification_value,
            context_cost,
            stale_penalty,
            contradiction_penalty,
            harm_penalty,
            repetition_penalty,
            distraction_penalty,
            total,
            reasons,
        },
        row,
        retrieval_admitted,
    }
}

pub(super) fn is_default_visible_lifecycle(
    state: Option<eliot_types::MemoryLifecycleState>,
) -> bool {
    !matches!(
        state,
        Some(
            eliot_types::MemoryLifecycleState::Suppressed
                | eliot_types::MemoryLifecycleState::Archived
                | eliot_types::MemoryLifecycleState::Quarantined
                | eliot_types::MemoryLifecycleState::Forgotten
                | eliot_types::MemoryLifecycleState::HardDeleted
        )
    )
}

fn normalize_scope(value: &str) -> String {
    value
        .trim()
        .replace('\\', "/")
        .trim_matches('/')
        .to_lowercase()
}

fn recall_scope_fit(candidate_scope: &str, requested_scopes: &[String]) -> Option<i32> {
    if requested_scopes.is_empty() || candidate_scope.trim().is_empty() {
        return Some(0);
    }
    let candidate = normalize_scope(candidate_scope);
    requested_scopes
        .iter()
        .map(|scope| normalize_scope(scope))
        .any(|scope| {
            !scope.is_empty()
                && (candidate == scope
                    || candidate.starts_with(&format!("{scope}/"))
                    || scope.starts_with(&format!("{candidate}/")))
        })
        .then_some(90)
}

fn recall_candidate_preference(row: &RecallCandidateRow) -> (u64, u64, i32) {
    (
        row.memory_revision.map_or(0, MemoryRevision::value),
        row.project_sequence.map_or(0, ProjectSequence::value),
        row.authority_rank,
    )
}

fn choose_authoritative_candidate(
    mut rows: Vec<(RecallCandidateRow, i32)>,
    reason: &str,
    traces: &mut Vec<L0CollapsedDuplicateTrace>,
) -> (RecallCandidateRow, i32) {
    rows.sort_by(|(left, _), (right, _)| {
        recall_candidate_preference(right)
            .cmp(&recall_candidate_preference(left))
            .then_with(|| left.handle.cmp(&right.handle))
            .then_with(|| left.record_ref.cmp(&right.record_ref))
    });
    let authoritative = rows.remove(0);
    if !rows.is_empty() {
        traces.push(L0CollapsedDuplicateTrace {
            authoritative_handle: authoritative.0.handle.clone(),
            collapsed_record_refs: rows
                .into_iter()
                .map(|(row, _)| {
                    if row.record_ref.is_empty() {
                        row.handle
                    } else {
                        row.record_ref
                    }
                })
                .collect(),
            reason: reason.to_owned(),
        });
    }
    authoritative
}

fn collapse_recall_candidates(
    candidates: Vec<(RecallCandidateRow, i32)>,
) -> (
    Vec<(RecallCandidateRow, i32)>,
    Vec<L0CollapsedDuplicateTrace>,
) {
    let mut traces = Vec::new();
    let mut by_handle = BTreeMap::<String, Vec<(RecallCandidateRow, i32)>>::new();
    for candidate in candidates {
        by_handle
            .entry(candidate.0.handle.clone())
            .or_default()
            .push(candidate);
    }
    let current = by_handle
        .into_values()
        .map(|rows| choose_authoritative_candidate(rows, "superseded_revision", &mut traces))
        .collect::<Vec<_>>();

    let mut by_semantics = BTreeMap::<String, Vec<(RecallCandidateRow, i32)>>::new();
    for candidate in current {
        let preview = eliot_types::normalize_query_tokens(&candidate.0.preview).join(" ");
        let semantics = if preview.is_empty() {
            candidate.0.handle.clone()
        } else {
            format!(
                "{}|{}|{}|{}|{}|{}",
                candidate.0.record_type,
                preview,
                normalize_scope(&candidate.0.scope_text),
                eliot_types::normalize_query_tokens(&candidate.0.concept_text).join(" "),
                candidate.0.status.to_ascii_lowercase(),
                candidate.0.negative_memory
            )
        };
        by_semantics.entry(semantics).or_default().push(candidate);
    }
    let deduplicated = by_semantics
        .into_values()
        .map(|rows| choose_authoritative_candidate(rows, "semantic_duplicate", &mut traces))
        .collect();
    (deduplicated, traces)
}
