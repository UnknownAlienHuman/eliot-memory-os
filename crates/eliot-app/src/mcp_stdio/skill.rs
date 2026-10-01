//! The skill registry and curator surface.
//!
//! Listing, inspecting and filtering skills, and the curator that proposes
//! what to keep. Activation and curation read the same skill cards, so the
//! registry and the curator belong together.

use super::*;

pub(super) fn dispatch_skill_list(arguments: Value) -> Result<Value> {
    let input: SkillProjectToolInput = serde_json::from_value(arguments)?;
    let project_id = project_id_from_label(&input.project);
    let skills = vec![
        mcp_active_skill(SkillId::new_v7(), SkillLifecycleState::Active),
        SkillRegistryService::create_candidate("MCP skill candidate", "mcp"),
    ];
    let filter = SkillDistractorFilterService::filter(
        project_id,
        TaskId::new_v7(),
        &skills,
        &mcp_skill_context("skill lifecycle"),
    );
    serde_json::to_value(json!({
        "component": "skill_list",
        "skills": skills,
        "normal_recall_included": filter.skills_included,
        "normal_recall_removed": filter.distractors_removed
    }))
    .map_err(Into::into)
}

pub(super) fn dispatch_skill_inspect(arguments: Value) -> Result<Value> {
    let input: SkillInspectToolInput = serde_json::from_value(arguments)?;
    let skill_id = parse_skill_id_or_new(&input.skill);
    let skill = mcp_active_skill(skill_id, SkillLifecycleState::Active);
    serde_json::to_value(skill).map_err(Into::into)
}

pub(super) fn dispatch_skill_estimate(arguments: Value) -> Result<Value> {
    let input: SkillTaskToolInput = serde_json::from_value(arguments)?;
    let skill = mcp_active_skill(SkillId::new_v7(), SkillLifecycleState::Active);
    let estimate = SkillNeedEstimator::estimate(
        project_id_from_label(&input.project),
        task_id_from_label(&input.task),
        &skill,
        &mcp_skill_context(&input.task),
    );
    serde_json::to_value(estimate).map_err(Into::into)
}

pub(super) fn dispatch_skill_filter(arguments: Value) -> Result<Value> {
    let input: SkillTaskToolInput = serde_json::from_value(arguments)?;
    let skills = vec![
        mcp_active_skill(SkillId::new_v7(), SkillLifecycleState::Active),
        SkillRegistryService::create_candidate("MCP skill candidate", "mcp"),
    ];
    let filter = SkillDistractorFilterService::filter(
        project_id_from_label(&input.project),
        task_id_from_label(&input.task),
        &skills,
        &mcp_skill_context(&input.task),
    );
    serde_json::to_value(filter).map_err(Into::into)
}

pub(super) fn dispatch_skill_influence(arguments: Value) -> Result<Value> {
    let input: SkillTaskToolInput = serde_json::from_value(arguments)?;
    let skill = mcp_active_skill(SkillId::new_v7(), SkillLifecycleState::Active);
    // The measured Skill bytes travel with the request, so the report carries a
    // canonical #704 serialized-byte measurement instead of a caller-declared
    // constant. (Issue #880, migration of this seam.)
    let report = SkillInfluenceService::report(SkillInfluenceReportInput {
        project_id: project_id_from_label(&input.project),
        task_id: task_id_from_label(&input.task),
        packet_id: Some(input.task),
        considered: vec![skill.skill_id],
        included: vec![skill.skill_id],
        executed: Vec::new(),
        execution_proofs: Vec::new(),
        measured_skills: Some(vec![skill]),
    });
    // 783/22: `SkillInfluenceReport::context_measurement` is owned by
    // `eliot-types` and now carries the unit, status and evidence binding
    // itself (#880 AUD2), so the engine's figure is republished verbatim from
    // that projection rather than beside a hand-built qualifier. The value is
    // the engine's own checked aggregate over the exact Skill bytes supplied
    // above; the app never re-derives it and never supplies a literal. An
    // unavailable measurement is republished with a null value and its own
    // status, and there is no `u64::MAX` sentinel left that a consumer could
    // compare against a budget as though it were an enormous cost.
    report
        .context_measurement
        .validate()
        .context("engine context measurement projection is not closed")?;
    let mut response = serde_json::to_value(&report)?
        .as_object()
        .cloned()
        .unwrap_or_default();
    response.insert(
        "context_measurement_wire".to_owned(),
        recorded_context_measurement_wire(&report.context_measurement),
    );
    Ok(Value::Object(response))
}

/// 783/22: the engine's typed context measurement, republished with its own
/// unit, status and seal so the wire form cannot disagree with the record.
fn recorded_context_measurement_wire(
    measurement: &SkillContextMeasurementProjection,
) -> Value {
    json!({
        "schema_version": measurement.schema_version,
        "unit": measurement.unit,
        "status": measurement.status,
        "empirical": measurement.empirical,
        "value": measurement.value,
        "rendered_utf8_bytes": measurement.rendered_utf8_bytes,
        "content_digest": measurement.content_digest,
        "value_digest": measurement.value_digest,
    })
}

pub(super) async fn dispatch_skill_execution_proof(
    state: &McpState,
    arguments: Value,
) -> Result<Value> {
    let input: SkillExecutionProofToolInput = serde_json::from_value(arguments)?;
    let mut proof = SkillExecutionProofService::proof(
        parse_skill_id_or_new(&input.skill),
        ProjectId::new_v7(),
        task_id_from_label(&input.task),
        vec!["inspect-scope".to_owned()],
        vec!["MCP skill proof output".to_owned()],
        vec!["just verify".to_owned()],
        SkillExecutionOutcome::Succeeded,
    );
    write_skill_execution_proof_to_memory(state, &mut proof).await?;
    write_json_report(
        &state
            .root
            .join("reports")
            .join("skill-lifecycle")
            .join("latest.json"),
        &proof,
    )?;
    serde_json::to_value(proof).map_err(Into::into)
}

pub(super) async fn dispatch_skill_curator_run(
    state: &McpState,
    arguments: Value,
) -> Result<Value> {
    let input: SkillCuratorRunToolInput = serde_json::from_value(arguments)?;
    let mut run = mcp_skill_curator_run(&input.project, input.dry_run.unwrap_or(true));
    write_skill_curator_run_to_memory(state, &mut run).await?;
    let report = SkillCurationReportService::report(run.clone());
    write_skill_curator_reports(state, &report)?;
    serde_json::to_value(report).map_err(Into::into)
}

pub(super) async fn dispatch_skill_curator_proposals(
    state: &McpState,
    arguments: Value,
) -> Result<Value> {
    let input: SkillProjectToolInput = serde_json::from_value(arguments)?;
    let run = if let Some(run) = latest_skill_curator_run(&state.root)? {
        run
    } else {
        let mut run = mcp_skill_curator_run(&input.project, true);
        write_skill_curator_run_to_memory(state, &mut run).await?;
        run
    };
    let report = SkillCurationReportService::report(run.clone());
    write_skill_curator_reports(state, &report)?;
    serde_json::to_value(json!({
        "component": "skill_curation_proposals",
        "run_id": run.run_id,
        "open_proposals": run.proposals
    }))
    .map_err(Into::into)
}

pub(super) fn dispatch_skill_curator_inspect(state: &McpState, arguments: Value) -> Result<Value> {
    let input: SkillCuratorInspectToolInput = serde_json::from_value(arguments)?;
    let run = latest_skill_curator_run(&state.root)?
        .context("no latest skill-curator run found; call eliot_skill_curator_run first")?;
    if input.run != "latest" && input.run != run.run_id {
        anyhow::bail!("requested run id does not match latest skill-curator run");
    }
    serde_json::to_value(run).map_err(Into::into)
}

pub(super) fn dispatch_skill_curator_report(state: &McpState) -> Result<Value> {
    let report = latest_json_report(
        &state
            .root
            .join("reports")
            .join("skill-curator")
            .join("latest.json"),
    )?
    .context("no latest skill-curator report found; call eliot_skill_curator_run first")?;
    Ok(report)
}

pub(super) fn dispatch_skill_curator_gate(state: &McpState, arguments: Value) -> Result<Value> {
    let input: SkillCuratorGateToolInput = serde_json::from_value(arguments)?;
    let proposal = find_skill_curation_proposal(&state.root, &input.proposal)?;
    let decision = SkillCurationGate::decide(
        &proposal,
        IncidentService::new(&state.root).lockdown_active()?,
    );
    write_skill_curator_gate_report(state, std::slice::from_ref(&decision))?;
    serde_json::to_value(decision).map_err(Into::into)
}
