//! Memory curation and the memory lifecycle surface.
//!
//! Curation decides what the corpus should keep, forget or protect; the
//! lifecycle tools report and propose against that decision. They share the
//! record shape and the protection rules, so they belong in one module rather
//! than split across the dispatch table by tool name.

use super::*;

pub(super) async fn dispatch_memory_corpus_profile(
    state: &McpState,
    arguments: Value,
) -> Result<Value> {
    let input: ProjectSemanticToolInput = serde_json::from_value(arguments)?;
    let project_id = parse_project_id(&input.project_id)?;
    let physical_cases =
        semantic_records::<ExperienceCase>(state, project_id, "experience_case").await?;
    let physical_patterns =
        semantic_records::<ExperiencePattern>(state, project_id, "experience_pattern").await?;
    let physical_case_record_count = u64::try_from(physical_cases.len()).unwrap_or(u64::MAX);
    let physical_pattern_record_count = u64::try_from(physical_patterns.len()).unwrap_or(u64::MAX);
    let cases = deduplicate_experience_cases(physical_cases);
    let patterns = deduplicate_experience_patterns(physical_patterns);
    let verified_episode_count = cases
        .iter()
        .flat_map(|case| case.source_episode_refs.iter())
        .collect::<std::collections::BTreeSet<_>>()
        .len()
        .try_into()
        .unwrap_or(u64::MAX);
    let active_procedure_count = patterns
        .iter()
        .filter(|pattern| {
            pattern.maturity.state == eliot_types::ExperienceMaturityState::ActiveProcedure
        })
        .count()
        .try_into()
        .unwrap_or(u64::MAX);
    let profile = CorpusProfileService::profile(&CorpusProfileInput {
        graph_health: Some(state.store.graph_health().await?),
        verified_episode_count,
        physical_case_record_count,
        physical_pattern_record_count,
        cases,
        patterns,
        active_procedure_count,
    });
    serde_json::to_value(profile).map_err(Into::into)
}

const CURATION_RULESET_VERSION: &str = "eliot-l13-curation-v1";
const MAX_CURATION_SCAN_RECORDS_PER_SOURCE: usize = 1_000;
const CURATION_SCAN_PAGE_SIZE: u16 = 100;

#[allow(clippy::too_many_lines)]
pub(super) async fn dispatch_memory_curation_preview(
    state: &McpState,
    arguments: Value,
) -> Result<Value> {
    let request: MemoryCurationPreviewRequest = serde_json::from_value(arguments)?;
    if request.page_size == 0 || request.page_size > 100 {
        anyhow::bail!("curation preview page_size must be between 1 and 100");
    }
    if request.ruleset_version != CURATION_RULESET_VERSION {
        anyhow::bail!("unsupported curation ruleset_version");
    }
    let cursor_scope = canonical_struct_hash(&json!({
        "tool": "eliot_memory_curation_preview",
        "project_id": request.project_id,
        "task_id": request.task_id,
        "at_revision": request.at_revision,
        "ruleset_version": request.ruleset_version,
    }))?;
    let cursor_state = operator_cursor_state(
        request.cursor.as_deref(),
        &cursor_scope,
        &state.cursor_signing_key,
    )?;
    if cursor_state.canonical_start != 0 || cursor_state.matched_seen != 0 {
        anyhow::bail!("curation preview cursor has invalid state");
    }

    let mut records = Vec::new();
    let mut scan_start = 0_u64;
    let mut scan_is_exact = false;
    while records.len() < MAX_CURATION_SCAN_RECORDS_PER_SOURCE {
        let remaining = MAX_CURATION_SCAN_RECORDS_PER_SOURCE - records.len();
        let limit = u16::try_from(remaining.min(usize::from(CURATION_SCAN_PAGE_SIZE)))?;
        let page = state
            .store
            .curation_record_page(
                request.project_id,
                request.task_id,
                request.at_revision,
                scan_start,
                limit,
            )
            .await?;
        let returned = page.len();
        records.extend(page);
        scan_start = scan_start.saturating_add(u64::try_from(returned)?);
        if returned < usize::from(limit) {
            scan_is_exact = true;
            break;
        }
    }
    if !scan_is_exact && records.len() == MAX_CURATION_SCAN_RECORDS_PER_SOURCE {
        scan_is_exact = state
            .store
            .curation_record_page(
                request.project_id,
                request.task_id,
                request.at_revision,
                scan_start,
                1,
            )
            .await?
            .is_empty();
    }

    let mut protection_start = 0_u64;
    let mut protection_records = Vec::new();
    let mut protection_scan_is_exact = false;
    while protection_start < u64::try_from(MAX_CURATION_SCAN_RECORDS_PER_SOURCE)? {
        let remaining =
            MAX_CURATION_SCAN_RECORDS_PER_SOURCE.saturating_sub(usize::try_from(protection_start)?);
        let limit = u16::try_from(remaining.min(usize::from(CURATION_SCAN_PAGE_SIZE)))?;
        let page = state
            .store
            .canonical_record_page(
                request.project_id,
                Some(request.task_id),
                &[CanonicalReceiptKind::MinorityPressureRecord.as_str()],
                protection_start,
                limit,
            )
            .await?;
        let returned = page.len();
        protection_records.extend(page.into_iter().filter(|record| {
            record
                .memory_revision
                .is_some_and(|revision| revision.value() <= request.at_revision.value())
        }));
        protection_start = protection_start.saturating_add(u64::try_from(returned)?);
        if returned < usize::from(limit) {
            protection_scan_is_exact = true;
            break;
        }
    }
    if !protection_scan_is_exact
        && protection_start == u64::try_from(MAX_CURATION_SCAN_RECORDS_PER_SOURCE)?
    {
        protection_scan_is_exact = state
            .store
            .canonical_record_page(
                request.project_id,
                Some(request.task_id),
                &[CanonicalReceiptKind::MinorityPressureRecord.as_str()],
                protection_start,
                1,
            )
            .await?
            .is_empty();
    }
    records.extend(protection_records);
    scan_is_exact = scan_is_exact && protection_scan_is_exact;

    let (mut candidates, mut protected_refs, corpus_profile) =
        analyze_curation_records(&records, scan_is_exact);
    candidates.sort_by(|left, right| {
        left.handle
            .cmp(&right.handle)
            .then_with(|| left.kind.cmp(&right.kind))
    });
    protected_refs.sort();
    protected_refs.dedup();
    remove_protected_curation_candidates(&mut candidates, &protected_refs);
    let total_matching = candidates.len();
    let offset = usize::try_from(cursor_state.base_offset)
        .context("curation preview cursor offset exceeds this platform")?;
    if offset > total_matching {
        anyhow::bail!("curation preview cursor offset exceeds the stable result set");
    }
    let end = offset
        .saturating_add(usize::from(request.page_size))
        .min(total_matching);
    let page = candidates[offset..end].to_vec();
    let next_cursor = (end < total_matching).then(|| {
        operator_cursor(
            OperatorCursorState {
                base_offset: u64::try_from(end).unwrap_or(u64::MAX),
                canonical_start: 0,
                matched_seen: 0,
            },
            &cursor_scope,
            &state.cursor_signing_key,
        )
    });
    serde_json::to_value(MemoryCurationPreviewResponse {
        project_id: request.project_id,
        task_id: request.task_id,
        snapshot_revision: request.at_revision,
        ruleset_version: request.ruleset_version,
        read_only: true,
        corpus_profile,
        candidates: page,
        protected_refs,
        cursor: request.cursor,
        next_cursor,
        total_matching,
        total_is_exact: scan_is_exact,
    })
    .map_err(Into::into)
}

#[allow(clippy::too_many_lines)]
pub(super) fn analyze_curation_records(
    records: &[CanonicalRecord<Value>],
    scan_is_exact: bool,
) -> (
    Vec<MemoryCurationCandidate>,
    Vec<String>,
    MemoryCurationCorpusProfile,
) {
    let mut candidates = Vec::new();
    let mut protected_refs = Vec::new();
    let mut receipt_kind_counts = BTreeMap::new();
    let mut lifecycle_counts = BTreeMap::new();
    for record in records {
        *receipt_kind_counts
            .entry(record.receipt_kind.clone())
            .or_insert(0) += 1;
        let metadata = explicit_curation_metadata(&record.receipt_body);
        let lifecycle = curation_first_string(&record.receipt_body, "lifecycle_transitions")
            .or_else(|| curation_string(&record.receipt_body, "lifecycle_status"))
            .or_else(|| curation_string(&record.receipt_body, "to_state"))
            .or_else(|| metadata.and_then(|value| curation_string(value, "lifecycle")))
            .unwrap_or_else(|| "active".to_owned());
        *lifecycle_counts.entry(lifecycle.clone()).or_insert(0) += 1;
        // Lifecycle actions must target the canonical record identity. A writer-provided
        // logical label remains evidence only and must never alias two physical records.
        let handle = record.subject_ref.clone();
        let explicitly_protected = curation_record_is_protected(record, metadata);
        if explicitly_protected {
            protected_refs.push(handle);
            continue;
        }
        if !matches!(lifecycle.as_str(), "active" | "restored") {
            continue;
        }
        let Some(metadata) = metadata else {
            continue;
        };
        let finding = if let Some(duplicate_of) = curation_string(metadata, "duplicate_of") {
            Some((
                MemoryCurationFindingKind::Duplicate,
                "archive",
                99,
                vec![duplicate_of],
                vec![
                    "exact canonical duplicate must remain active".to_owned(),
                    "restore receipt with operator reason".to_owned(),
                ],
            ))
        } else if let Some(duplicate_of) = curation_string(metadata, "semantic_duplicate_of") {
            let equivalence_verified = metadata
                .get("semantic_equivalence_verified")
                .and_then(Value::as_bool)
                == Some(true);
            Some((
                MemoryCurationFindingKind::SemanticDuplicate,
                if equivalence_verified {
                    "archive"
                } else {
                    "propose_archive"
                },
                if equivalence_verified { 92 } else { 70 },
                vec![duplicate_of],
                vec![
                    "semantic equivalence must remain verified".to_owned(),
                    "restore receipt with counterexample evidence".to_owned(),
                ],
            ))
        } else if metadata.get("scope_match").and_then(Value::as_bool) == Some(false) {
            Some((
                MemoryCurationFindingKind::WrongScope,
                "suppress",
                95,
                curation_strings(metadata, "wrong_scope_for"),
                vec![
                    "fresh scope applicability evidence".to_owned(),
                    "restore receipt with revised scope".to_owned(),
                ],
            ))
        } else if curation_numeric(metadata, "utility_score").is_some_and(|score| score <= 25.0)
            && metadata.get("evidence_sufficient").and_then(Value::as_bool) == Some(true)
        {
            Some((
                MemoryCurationFindingKind::LowUtility,
                "archive",
                92,
                Vec::new(),
                vec![
                    "new evidence of positive retrieval utility".to_owned(),
                    "restore receipt after utility re-evaluation".to_owned(),
                ],
            ))
        } else if curation_numeric(metadata, "utility_score").is_some_and(|score| score <= 25.0)
            && metadata.get("evidence_sufficient").and_then(Value::as_bool) == Some(false)
        {
            Some((
                MemoryCurationFindingKind::LowUtilityInsufficientEvidence,
                "propose_archive",
                60,
                Vec::new(),
                vec![
                    "new supporting evidence".to_owned(),
                    "restore receipt after utility re-evaluation".to_owned(),
                ],
            ))
        } else if curation_numeric(metadata, "utility_delta").is_some_and(|score| score <= 0.0)
            && curation_numeric(metadata, "repeat_count").is_some_and(|count| count >= 2.0)
        {
            Some((
                MemoryCurationFindingKind::RepeatedLowDelta,
                "archive",
                95,
                curation_strings(metadata, "repeated_with"),
                vec![
                    "positive utility delta at a later revision".to_owned(),
                    "restore receipt after cargo re-evaluation".to_owned(),
                ],
            ))
        } else if metadata.get("unsafe_instruction").and_then(Value::as_bool) == Some(true)
            && metadata.get("evidence_sufficient").and_then(Value::as_bool) == Some(true)
        {
            Some((
                MemoryCurationFindingKind::UnsafeInstruction,
                "suppress",
                99,
                curation_strings(metadata, "unsafe_evidence_refs"),
                vec![
                    "explicit safety revalidation".to_owned(),
                    "restore receipt with operator evidence".to_owned(),
                ],
            ))
        } else if let Some(superseded_by) = curation_string(metadata, "superseded_by") {
            let has_exact_reason = curation_string(metadata, "stale_reason_ref").is_some();
            Some((
                MemoryCurationFindingKind::StaleSuperseded,
                if has_exact_reason {
                    "archive"
                } else {
                    "propose_archive"
                },
                if has_exact_reason { 95 } else { 80 },
                vec![superseded_by],
                vec![
                    "superseding record must remain current".to_owned(),
                    "restore receipt after freshness revalidation".to_owned(),
                ],
            ))
        } else {
            None
        };
        let Some((finding_kind, action, confidence, mut signal_refs, restore_requirements)) =
            finding
        else {
            continue;
        };
        let mut evidence_refs = curation_strings(metadata, "evidence_refs");
        evidence_refs.push(format!("receipt:{}", record.canonical_receipt.receipt_id));
        evidence_refs.append(&mut signal_refs);
        evidence_refs.sort();
        evidence_refs.dedup();
        let mut counterevidence_refs = curation_strings(metadata, "counterevidence_refs");
        counterevidence_refs.sort();
        counterevidence_refs.dedup();
        candidates.push(MemoryCurationCandidate {
            handle,
            kind: record.receipt_kind.clone(),
            lifecycle,
            authority: curation_string(metadata, "authority")
                .unwrap_or_else(|| "writer_actor_canonical_store".to_owned()),
            finding_kind,
            evidence_refs,
            counterevidence_refs,
            confidence,
            proposed_reversible_action: action.to_owned(),
            restore_requirements,
        });
    }
    (
        candidates,
        protected_refs,
        MemoryCurationCorpusProfile {
            scanned_records: records.len(),
            scan_limit: MAX_CURATION_SCAN_RECORDS_PER_SOURCE.saturating_mul(2),
            scan_truncated: !scan_is_exact,
            receipt_kind_counts,
            lifecycle_counts,
        },
    )
}

pub(super) fn curation_record_is_protected(
    record: &CanonicalRecord<Value>,
    metadata: Option<&Value>,
) -> bool {
    if record.receipt_kind == "minority_pressure_record"
        || curation_string(&record.receipt_body, "status").as_deref() == Some("verified")
    {
        return true;
    }
    metadata.is_some_and(|value| {
        value
            .get("protected")
            .and_then(Value::as_bool)
            .unwrap_or(false)
            || value
                .get("current_truth")
                .and_then(Value::as_bool)
                .unwrap_or(false)
            || value
                .get("audit_required")
                .and_then(Value::as_bool)
                .unwrap_or(false)
            || curation_string(value, "role").is_some_and(|role| {
                matches!(
                    role.as_str(),
                    "counterexample" | "minority" | "protected" | "current_truth" | "audit_history"
                )
            })
            || (curation_string(value, "role").as_deref() == Some("failure_fingerprint")
                && value.get("reopen_condition_met").and_then(Value::as_bool) != Some(true))
    })
}

pub(super) fn explicit_curation_metadata(value: &Value) -> Option<&Value> {
    value
        .get("curation")
        .filter(|candidate| candidate.is_object())
        .or_else(|| {
            ["payload", "receipt_body", "body"]
                .iter()
                .filter_map(|key| value.get(key))
                .find_map(explicit_curation_metadata)
        })
}

pub(super) fn curation_string(value: &Value, name: &str) -> Option<String> {
    value
        .get(name)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

pub(super) fn curation_first_string(value: &Value, name: &str) -> Option<String> {
    value
        .get(name)
        .and_then(Value::as_array)
        .and_then(|values| values.first())
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

pub(super) fn curation_strings(value: &Value, name: &str) -> Vec<String> {
    match value.get(name) {
        Some(Value::String(value)) if !value.trim().is_empty() => vec![value.trim().to_owned()],
        Some(Value::Array(values)) => values
            .iter()
            .filter_map(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_owned)
            .take(64)
            .collect(),
        _ => Vec::new(),
    }
}

pub(super) fn curation_numeric(value: &Value, name: &str) -> Option<f64> {
    value.get(name).and_then(|value| {
        value
            .as_f64()
            .or_else(|| value.as_str().and_then(|text| text.parse().ok()))
    })
}

pub(super) fn dispatch_memory_lifecycle_status(arguments: Value) -> Result<Value> {
    let input: MemoryLifecycleStatusToolInput = serde_json::from_value(arguments)?;
    let project_id = project_id_from_label(&input.project);
    let report = MemoryLifecycleService::new().status(project_id, &input.memory_ref);
    serde_json::to_value(report).map_err(Into::into)
}

pub(super) fn dispatch_memory_lifecycle_propose(arguments: Value) -> Result<Value> {
    let input: MemoryLifecycleProposeToolInput = serde_json::from_value(arguments)?;
    let operator = parse_forgetting_operator(&input.operator)?;
    let reason = parse_forgetting_reason(&input.reason)?;
    let superseding_ref = (operator == ForgettingOperator::Supersede)
        .then(|| format!("{}:superseding", input.memory_ref));
    let policy = ForgettingPolicyService::propose(
        project_id_from_label(&input.project),
        &input.memory_ref,
        operator,
        reason,
        vec!["mcp:memory-lifecycle:proposal".to_owned()],
        superseding_ref,
        None,
    );
    let decision = MemoryLifecycleGate::decide(&policy, &[]);
    serde_json::to_value(json!({
        "component": "memory_lifecycle_proposal",
        "policy": policy,
        "decision": decision
    }))
    .map_err(Into::into)
}

pub(super) fn dispatch_memory_lifecycle_vitality(arguments: Value) -> Result<Value> {
    let input: MemoryLifecycleProjectToolInput = serde_json::from_value(arguments)?;
    let score = MemoryVitalityService::score(
        project_id_from_label(&input.project),
        input
            .memory_ref
            .as_deref()
            .unwrap_or("memory-lifecycle:baseline"),
    );
    serde_json::to_value(score).map_err(Into::into)
}

pub(super) fn dispatch_memory_lifecycle_gravity(arguments: Value) -> Result<Value> {
    let input: MemoryLifecycleProjectToolInput = serde_json::from_value(arguments)?;
    let score = MemoryVitalityService::score(
        project_id_from_label(&input.project),
        input
            .memory_ref
            .as_deref()
            .unwrap_or("memory-lifecycle:baseline"),
    );
    let gravity = MemoryGravityService::gravity(&score);
    serde_json::to_value(gravity).map_err(Into::into)
}

pub(super) async fn dispatch_memory_lifecycle_influence(
    state: &McpState,
    arguments: Value,
) -> Result<Value> {
    let input: MemoryLifecycleInfluenceToolInput = serde_json::from_value(arguments)?;
    let lifecycle = MemoryLifecyclePacketView::default();
    let mut report = MemoryInfluenceService::report(
        project_id_from_label(&input.project),
        input.task.as_deref().map(task_id_from_label),
        input.task.clone(),
        input
            .included_refs
            .unwrap_or_else(|| vec!["memory-lifecycle:baseline".to_owned()]),
        &lifecycle,
    );
    if let Some(outcome) = input.outcome {
        MemoryInfluenceService::attach_outcome(&mut report, outcome)?;
    }
    write_memory_influence_to_memory(state, &mut report).await?;
    write_json_report(
        &state
            .root
            .join("reports")
            .join("memory-influence")
            .join("latest.json"),
        &report,
    )?;
    serde_json::to_value(report).map_err(Into::into)
}
