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

pub(super) async fn dispatch_memory_distillation_preview(
    state: &McpState,
    arguments: Value,
) -> Result<Value> {
    let request: MemoryDistillationPreviewToolInput = serde_json::from_value(arguments)?;
    if request.page_size == 0 || request.page_size > 100 {
        anyhow::bail!("distillation preview page_size must be between 1 and 100");
    }
    if request.ruleset_version != eliot_engine::MEMORY_DISTILLATION_RULESET_VERSION {
        anyhow::bail!("unsupported memory distillation ruleset_version");
    }
    if request.cursor.is_some() && request.at_revision.is_none() {
        anyhow::bail!("continued distillation preview requires the returned at_revision");
    }
    let project_id = parse_project_id(&request.project_id)?;
    let requested_revision = request.at_revision.map(MemoryRevision::new);
    let (snapshot_revision, records, scan_complete) =
        canonical_memory_snapshot(state, project_id, &[], requested_revision).await?;
    let utility_ledger = MemoryDistillationService::derive_utility_ledger(
        project_id,
        snapshot_revision,
        &canonical_utility_sources(&records)?,
        scan_complete,
    );
    let items = canonical_distillation_items(&records)?;
    let mut plan = MemoryDistillationService::plan(MemoryDistillationInput {
        project_id,
        snapshot_revision,
        ruleset_version: request.ruleset_version.clone(),
        complete: scan_complete,
        items,
        utility_ledger,
    })?;
    let total_matching = plan.candidates.len();
    let cursor_scope = canonical_struct_hash(&json!({
        "tool": "eliot_memory_distillation_preview",
        "project_id": project_id,
        "at_revision": snapshot_revision,
        "ruleset_version": request.ruleset_version,
        "plan_id": plan.plan_id,
    }))?;
    let cursor_state = operator_cursor_state(
        request.cursor.as_deref(),
        &cursor_scope,
        &state.cursor_signing_key,
    )?;
    if cursor_state.canonical_start != 0 || cursor_state.matched_seen != 0 {
        anyhow::bail!("distillation preview cursor has invalid state");
    }
    let offset = usize::try_from(cursor_state.base_offset)
        .context("distillation preview cursor offset exceeds this platform")?;
    if offset > total_matching {
        anyhow::bail!("distillation preview cursor exceeds the stable result set");
    }
    let end = offset
        .saturating_add(usize::from(request.page_size))
        .min(total_matching);
    plan.candidates = plan.candidates[offset..end].to_vec();
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
    Ok(json!({
        "project_id": project_id,
        "at_revision": snapshot_revision,
        "read_only": true,
        "plan": plan,
        "cursor": request.cursor,
        "next_cursor": next_cursor,
        "total_matching": total_matching,
        "total_is_exact": scan_complete,
    }))
}

pub(super) fn dispatch_memory_distillation_schedule(arguments: Value) -> Result<Value> {
    let request: MemoryDistillationScheduleRequest = serde_json::from_value(arguments)?;
    serde_json::to_value(MemoryDistillationService::schedule(&request)).map_err(Into::into)
}

pub(super) async fn dispatch_memory_distillation_apply(
    state: &McpState,
    context: AuthenticatedRequestContext,
    arguments: Value,
) -> Result<Value> {
    require_canonical_controller_authority(state)?;
    let input: MemoryDistillationApplyToolInput = serde_json::from_value(arguments)?;
    if input.selected_candidate_ids.is_empty() || input.selected_candidate_ids.len() > 100 {
        anyhow::bail!("distillation apply requires between 1 and 100 selected candidate ids");
    }
    validate_broker_text("idempotency_key", &input.idempotency_key, 256)?;
    if input.ruleset_version != eliot_engine::MEMORY_DISTILLATION_RULESET_VERSION {
        anyhow::bail!("unsupported memory distillation ruleset_version");
    }
    let project_id = parse_project_id(&input.project_id)?;
    let task_id = TaskId::from_str(&input.task_id).context("parse distillation task_id")?;
    let task = state
        .store
        .task_contract_by_id(task_id)
        .await?
        .context("distillation apply task does not exist")?;
    if task.project_id != project_id {
        anyhow::bail!("distillation apply task belongs to a different project");
    }
    let expected_revision = MemoryRevision::new(input.at_revision);
    let current_revision = state
        .store
        .current_state(&CurrentStateRequest {
            project_id,
            consistency: ReadConsistencyMode::Latest,
            at_least_revision: None,
        })
        .await?
        .memory_revision;
    if current_revision != expected_revision {
        anyhow::bail!(
            "distillation apply snapshot is stale: expected={} current={}",
            expected_revision.value(),
            current_revision.value()
        );
    }
    let (snapshot_revision, records, complete) =
        canonical_memory_snapshot(state, project_id, &[], Some(expected_revision)).await?;
    let utility_ledger = MemoryDistillationService::derive_utility_ledger(
        project_id,
        snapshot_revision,
        &canonical_utility_sources(&records)?,
        complete,
    );
    let plan = MemoryDistillationService::plan(MemoryDistillationInput {
        project_id,
        snapshot_revision,
        ruleset_version: input.ruleset_version,
        complete,
        items: canonical_distillation_items(&records)?,
        utility_ledger,
    })?;
    let mut receipt =
        MemoryDistillationService::select_reversible_actions(&plan, &input.selected_candidate_ids)?;
    if !receipt.rejected_candidate_ids.is_empty() {
        anyhow::bail!(
            "distillation apply rejected unsafe, incomplete, missing, or non-reversible candidates: {:?}",
            receipt.rejected_candidate_ids
        );
    }
    for selection in &receipt.selected {
        let candidate = plan
            .candidates
            .iter()
            .find(|candidate| candidate.candidate_id == selection.candidate_id)
            .context("selected distillation candidate disappeared from the exact plan")?;
        let reason = distillation_forgetting_reason(candidate.finding)?;
        let stable_key = format!(
            "distillation:{}",
            blake3::hash(
                format!("{}:{}", input.idempotency_key, selection.candidate_id).as_bytes()
            )
            .to_hex()
        );
        let write_receipt = persist_operator_lifecycle_transition(
            state,
            context,
            project_id,
            task_id,
            &selection.target_ref,
            selection.operator,
            reason,
            OperatorLifecycleBinding::unbound(selection.evidence_refs.clone()),
            &stable_key,
        )
        .await?;
        receipt.write_receipts.push(write_receipt);
    }
    serde_json::to_value(receipt).map_err(Into::into)
}

fn distillation_forgetting_reason(finding: MemoryDistillationFinding) -> Result<ForgettingReason> {
    match finding {
        MemoryDistillationFinding::ExactDuplicate => Ok(ForgettingReason::Duplicate),
        MemoryDistillationFinding::StaleSuperseded
        | MemoryDistillationFinding::ObsoleteArtifact => Ok(ForgettingReason::Superseded),
        MemoryDistillationFinding::WrongScope => Ok(ForgettingReason::WrongScope),
        MemoryDistillationFinding::RepeatedLowDelta => Ok(ForgettingReason::LowUtility),
        other => {
            anyhow::bail!("distillation finding is not eligible for automatic apply: {other:?}")
        }
    }
}

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
        } else if curation_numeric(metadata, "utility_score").is_some_and(|score| score <= 25.0) {
            Some((
                MemoryCurationFindingKind::LowUtilityInsufficientEvidence,
                "propose_archive",
                40,
                vec!["writer_utility_score_is_not_canonical_evidence".to_owned()],
                vec![
                    "derive utility from canonical inclusion, influence, verification, cost, and regret records"
                        .to_owned(),
                    "re-run memory distillation against a complete revision-fenced utility ledger"
                        .to_owned(),
                ],
            ))
        } else if curation_numeric(metadata, "utility_delta").is_some_and(|score| score <= 0.0)
            && curation_numeric(metadata, "repeat_count").is_some_and(|count| count >= 2.0)
        {
            Some((
                MemoryCurationFindingKind::LowUtilityInsufficientEvidence,
                "propose_archive",
                40,
                vec!["writer_utility_delta_is_not_canonical_evidence".to_owned()],
                vec![
                    "derive repeated low delta from complete canonical use and outcome records"
                        .to_owned(),
                    "preserve the active handle until the governed distillation plan is complete"
                        .to_owned(),
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

const MEMORY_DISTILLATION_SCAN_PAGE_SIZE: u16 = 100;
const MAX_MEMORY_DISTILLATION_SCAN_RECORDS: usize = 1_000_000;

pub(super) async fn canonical_memory_snapshot(
    state: &McpState,
    project_id: ProjectId,
    receipt_kinds: &[&str],
    requested_revision: Option<MemoryRevision>,
) -> Result<(MemoryRevision, Vec<CanonicalRecord<Value>>, bool)> {
    let snapshot_revision = if let Some(revision) = requested_revision {
        revision
    } else {
        state
            .store
            .current_state(&CurrentStateRequest {
                project_id,
                consistency: ReadConsistencyMode::Latest,
                at_least_revision: None,
            })
            .await?
            .memory_revision
    };
    let mut records = Vec::new();
    let mut start = 0_u64;
    let mut complete = false;
    while records.len() < MAX_MEMORY_DISTILLATION_SCAN_RECORDS {
        let remaining = MAX_MEMORY_DISTILLATION_SCAN_RECORDS.saturating_sub(records.len());
        let limit = u16::try_from(remaining.min(usize::from(MEMORY_DISTILLATION_SCAN_PAGE_SIZE)))?;
        let page = state
            .store
            .canonical_record_page_at_revision(
                project_id,
                None,
                receipt_kinds,
                Some(snapshot_revision),
                start,
                limit,
            )
            .await?;
        let returned = page.len();
        records.extend(page);
        start = start.saturating_add(u64::try_from(returned)?);
        if returned < usize::from(limit) {
            complete = true;
            break;
        }
    }
    if !complete && records.len() == MAX_MEMORY_DISTILLATION_SCAN_RECORDS {
        complete = state
            .store
            .canonical_record_page_at_revision(
                project_id,
                None,
                receipt_kinds,
                Some(snapshot_revision),
                start,
                1,
            )
            .await?
            .is_empty();
    }
    Ok((snapshot_revision, records, complete))
}

pub(crate) fn canonical_utility_sources(
    records: &[CanonicalRecord<Value>],
) -> Result<Vec<MemoryUtilitySourceRecord>> {
    records
        .iter()
        .map(|record| {
            let mut target_refs = BTreeSet::new();
            target_refs.insert(record.subject_ref.clone());
            collect_memory_target_refs(&record.receipt_body, None, &mut target_refs);
            Ok(MemoryUtilitySourceRecord {
                record_ref: format!("canonical:{}", record.record_id),
                record_kind: record.receipt_kind.clone(),
                target_refs: target_refs.into_iter().collect(),
                evidence_ref: format!("receipt:{}", record.canonical_receipt.receipt_id),
                payload: record.receipt_body.clone(),
                memory_revision: record.memory_revision,
                project_sequence: record.project_sequence,
                serialized_bytes: u64::try_from(serde_json::to_vec(&record.receipt_body)?.len())?,
            })
        })
        .collect()
}

fn collect_memory_target_refs(
    value: &Value,
    field_name: Option<&str>,
    output: &mut BTreeSet<String>,
) {
    let is_memory_reference_field = field_name.is_some_and(|name| {
        matches!(
            name,
            "target_ref"
                | "memory_ref"
                | "memory_handle"
                | "handle"
                | "included_refs"
                | "memory_handles_received"
                | "memory_handles_expanded"
                | "memory_handles_used"
                | "suppressed_refs"
                | "collapsed_duplicate_refs"
        )
    });
    match value {
        Value::String(text) if is_memory_reference_field && !text.trim().is_empty() => {
            output.insert(text.trim().to_owned());
        }
        Value::Array(values) => {
            for item in values {
                collect_memory_target_refs(item, field_name, output);
            }
        }
        Value::Object(object) => {
            for (name, nested) in object {
                collect_memory_target_refs(nested, Some(name), output);
            }
        }
        _ => {}
    }
}

#[allow(clippy::too_many_lines)]
pub(crate) fn canonical_distillation_items(
    records: &[CanonicalRecord<Value>],
) -> Result<Vec<MemoryDistillationCorpusItem>> {
    let mut lifecycle = BTreeMap::new();
    let mut minority_protected = BTreeSet::new();
    for record in records {
        if record.receipt_kind == CanonicalReceiptKind::StateTransition.as_str() {
            let transition =
                serde_json::from_value::<MemoryStateTransition>(record.receipt_body.clone())?;
            lifecycle.insert(record.subject_ref.clone(), transition.to_state);
        } else if record.receipt_kind == CanonicalReceiptKind::MinorityPressureRecord.as_str() {
            minority_protected.insert(record.subject_ref.clone());
        }
    }
    records
        .iter()
        .filter(|record| is_distillable_record_kind(&record.receipt_kind))
        .map(|record| {
            let metadata = explicit_curation_metadata(&record.receipt_body);
            let scope = distillation_string(metadata, &record.receipt_body, &["scope"])
                .unwrap_or_else(|| format!("project:{}", record.project_id));
            let normalized_proposition = distillation_string(
                metadata,
                &record.receipt_body,
                &[
                    "normalized_proposition",
                    "statement",
                    "summary",
                    "description",
                ],
            )
            .unwrap_or_default();
            let mechanism = distillation_string(
                metadata,
                &record.receipt_body,
                &["mechanism", "causal_mechanism"],
            )
            .unwrap_or_default();
            let content_hash =
                distillation_string(metadata, &record.receipt_body, &["content_hash"])
                    .unwrap_or_else(|| {
                        blake3::hash(
                            serde_json::to_vec(&record.receipt_body)
                                .unwrap_or_else(|_| record.record_id.as_bytes().to_vec())
                                .as_slice(),
                        )
                        .to_hex()
                        .to_string()
                    });
            let status = distillation_string(
                metadata,
                &record.receipt_body,
                &["status", "epistemic_status"],
            )
            .unwrap_or_else(|| "candidate".to_owned());
            let role =
                distillation_string(metadata, &record.receipt_body, &["role"]).unwrap_or_default();
            let current_truth = distillation_bool(metadata, &record.receipt_body, "current_truth")
                || status.eq_ignore_ascii_case("verified");
            let negative_memory = record.receipt_kind.contains("failure")
                || matches!(role.as_str(), "failure_fingerprint" | "negative_memory");
            let protected = current_truth
                || negative_memory
                || minority_protected.contains(&record.subject_ref)
                || distillation_bool(metadata, &record.receipt_body, "protected")
                || matches!(
                    role.as_str(),
                    "counterexample" | "minority" | "audit_history" | "current_truth"
                );
            let serialized_bytes = u64::try_from(serde_json::to_vec(&record.receipt_body)?.len())?;
            let mut evidence_refs =
                distillation_strings(metadata, &record.receipt_body, "evidence_refs");
            evidence_refs.push(format!("receipt:{}", record.canonical_receipt.receipt_id));
            evidence_refs.sort();
            evidence_refs.dedup();
            Ok(MemoryDistillationCorpusItem {
                record_ref: format!("canonical:{}", record.record_id),
                target_ref: record.subject_ref.clone(),
                record_kind: record.receipt_kind.clone(),
                task_id: record.task_id,
                scope,
                content_hash,
                normalized_proposition,
                mechanism,
                applies_when: distillation_strings(metadata, &record.receipt_body, "applies_when"),
                does_not_apply_when: distillation_strings(
                    metadata,
                    &record.receipt_body,
                    "does_not_apply_when",
                ),
                counterexamples: distillation_strings(
                    metadata,
                    &record.receipt_body,
                    "counterexamples",
                ),
                evidence_refs,
                verifier_refs: distillation_strings(
                    metadata,
                    &record.receipt_body,
                    "verifier_refs",
                ),
                lifecycle: lifecycle
                    .get(&record.subject_ref)
                    .copied()
                    .unwrap_or(MemoryLifecycleState::Active),
                status,
                token_units: serialized_bytes.div_ceil(4).max(1),
                current_truth,
                negative_memory,
                protected,
                superseded_by: distillation_string(
                    metadata,
                    &record.receipt_body,
                    &["superseded_by"],
                ),
                exact_scope_contradiction: distillation_string(
                    metadata,
                    &record.receipt_body,
                    &["exact_scope_contradiction", "wrong_scope_for"],
                ),
                obsolete_replacement: distillation_string(
                    metadata,
                    &record.receipt_body,
                    &["obsolete_replacement", "current_replacement"],
                ),
                certification_noise: distillation_bool(
                    metadata,
                    &record.receipt_body,
                    "certification_noise",
                ),
            })
        })
        .collect()
}

fn is_distillable_record_kind(kind: &str) -> bool {
    [
        "claim",
        "evidence",
        "failure",
        "invariant",
        "decision",
        "capsule",
        "card",
        "experience",
        "pattern",
        "procedure",
        "episode",
        "snapshot",
        "artifact",
    ]
    .iter()
    .any(|candidate| kind.contains(candidate))
        && ![
            "receipt",
            "transition",
            "trajectory",
            "observation",
            "injection",
        ]
        .iter()
        .any(|candidate| kind.contains(candidate))
}

fn distillation_string(metadata: Option<&Value>, body: &Value, names: &[&str]) -> Option<String> {
    names
        .iter()
        .find_map(|name| metadata.and_then(|value| curation_string(value, name)))
        .or_else(|| names.iter().find_map(|name| recursive_string(body, name)))
}

fn recursive_string(value: &Value, name: &str) -> Option<String> {
    curation_string(value, name).or_else(|| match value {
        Value::Array(values) => values
            .iter()
            .find_map(|value| recursive_string(value, name)),
        Value::Object(object) => object
            .values()
            .find_map(|value| recursive_string(value, name)),
        _ => None,
    })
}

fn distillation_strings(metadata: Option<&Value>, body: &Value, name: &str) -> Vec<String> {
    let direct = metadata.map_or_else(Vec::new, |value| curation_strings(value, name));
    if direct.is_empty() {
        recursive_strings(body, name)
    } else {
        direct
    }
}

fn recursive_strings(value: &Value, name: &str) -> Vec<String> {
    let direct = curation_strings(value, name);
    if !direct.is_empty() {
        return direct;
    }
    match value {
        Value::Array(values) => values
            .iter()
            .flat_map(|value| recursive_strings(value, name))
            .take(64)
            .collect(),
        Value::Object(object) => object
            .values()
            .flat_map(|value| recursive_strings(value, name))
            .take(64)
            .collect(),
        _ => Vec::new(),
    }
}

fn distillation_bool(metadata: Option<&Value>, body: &Value, name: &str) -> bool {
    metadata
        .and_then(|value| value.get(name))
        .and_then(Value::as_bool)
        .or_else(|| recursive_bool(body, name))
        .unwrap_or(false)
}

fn recursive_bool(value: &Value, name: &str) -> Option<bool> {
    value
        .get(name)
        .and_then(Value::as_bool)
        .or_else(|| match value {
            Value::Array(values) => values.iter().find_map(|value| recursive_bool(value, name)),
            Value::Object(object) => object
                .values()
                .find_map(|value| recursive_bool(value, name)),
            _ => None,
        })
}

pub(super) async fn dispatch_memory_lifecycle_status(
    state: &McpState,
    arguments: Value,
) -> Result<Value> {
    let input: MemoryLifecycleStatusToolInput = serde_json::from_value(arguments)?;
    let project_id = project_id_from_label(&input.project);
    let (_, records, complete) = canonical_memory_snapshot(
        state,
        project_id,
        &[CanonicalReceiptKind::StateTransition.as_str()],
        None,
    )
    .await?;
    if !complete {
        anyhow::bail!("canonical lifecycle projection is incomplete");
    }
    let mut matching = records
        .into_iter()
        .filter(|record| record.subject_ref == input.memory_ref)
        .map(|record| {
            let transition = serde_json::from_value::<MemoryStateTransition>(record.receipt_body)?;
            Ok((transition, record.canonical_receipt))
        })
        .collect::<Result<Vec<_>>>()?;
    matching.sort_by_key(|item| item.0.created_at);
    let lifecycle = matching
        .last()
        .map_or_else(MemoryLifecycleService::new, |latest| {
            MemoryLifecycleService::new().with_state(&input.memory_ref, latest.0.to_state)
        });
    let mut report = lifecycle.status(project_id, &input.memory_ref);
    report.related_receipts = matching
        .into_iter()
        .map(|(_, receipt)| format!("receipt:{}", receipt.receipt_id))
        .collect();
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

pub(super) async fn dispatch_memory_lifecycle_vitality(
    state: &McpState,
    arguments: Value,
) -> Result<Value> {
    let input: MemoryLifecycleProjectToolInput = serde_json::from_value(arguments)?;
    let project_id = project_id_from_label(&input.project);
    let (snapshot_revision, records, complete) =
        canonical_memory_snapshot(state, project_id, &[], None).await?;
    let ledger = MemoryDistillationService::derive_utility_ledger(
        project_id,
        snapshot_revision,
        &canonical_utility_sources(&records)?,
        complete,
    );
    let target_ref = input
        .memory_ref
        .or_else(|| ledger.entries.first().map(|entry| entry.target_ref.clone()))
        .unwrap_or_else(|| "memory-lifecycle:empty-corpus".to_owned());
    let score = MemoryDistillationService::vitality_from_ledger(project_id, &target_ref, &ledger);
    serde_json::to_value(score).map_err(Into::into)
}

pub(super) async fn dispatch_memory_lifecycle_gravity(
    state: &McpState,
    arguments: Value,
) -> Result<Value> {
    let input: MemoryLifecycleProjectToolInput = serde_json::from_value(arguments)?;
    let project_id = project_id_from_label(&input.project);
    let (snapshot_revision, records, complete) =
        canonical_memory_snapshot(state, project_id, &[], None).await?;
    let ledger = MemoryDistillationService::derive_utility_ledger(
        project_id,
        snapshot_revision,
        &canonical_utility_sources(&records)?,
        complete,
    );
    let target_ref = input
        .memory_ref
        .or_else(|| ledger.entries.first().map(|entry| entry.target_ref.clone()))
        .unwrap_or_else(|| "memory-lifecycle:empty-corpus".to_owned());
    let score = MemoryDistillationService::vitality_from_ledger(project_id, &target_ref, &ledger);
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
