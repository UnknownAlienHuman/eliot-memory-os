fn canonical_struct_hash<T: serde::Serialize>(value: &T) -> Result<String> {
    Ok(blake3::hash(&serde_json::to_vec(value)?)
        .to_hex()
        .to_string())
}

#[allow(clippy::too_many_lines)]
async fn dispatch_compile_packet_l3(
    state: &McpState,
    context: AuthenticatedRequestContext,
    arguments: Value,
) -> Result<Value> {
    let input = input_validation::decode_compile_packet_input(arguments)?;
    let requested_memory_free_control =
        input.memory_mode == Some(MemoryExposureMode::MemoryFreeControl);
    if input
        .material_frame
        .as_ref()
        .is_some_and(|frame| frame.expected_observable.trim().is_empty())
    {
        return Err(eliot_types::ToolInputError {
            data: eliot_types::ToolInputErrorData {
                code: "INVALID_TOOL_INPUT".to_owned(),
                missing: Vec::new(),
                invalid: vec![eliot_types::InvalidField {
                    field: "material_frame.expected_observable".to_owned(),
                    reason: "material work requires a machine-checkable expected observable"
                        .to_owned(),
                }],
                minimal_valid_example: eliot_types::compile_packet_minimal_example(),
            },
        }
        .into());
    }
    let request = input.request;
    let parsed_task_id = TaskId::from_str(&request.task_id).ok();
    let packet_task = if let Some(packet_task_id) = parsed_task_id {
        state.store.task_contract_by_id(packet_task_id).await?
    } else {
        None
    };
    let codecortex_reports = latest_codecortex_report(&state.root)?
        .into_iter()
        .collect::<Vec<_>>();
    let current_git_scope =
        resolve_governed_packet_git_scope(&request, packet_task.as_ref(), &codecortex_reports)
            .await?;
    let compiler = ContextCompiler::new(ReadService::new(state.store.clone()));
    let mut packet = match (current_git_scope.as_ref(), input.material_frame.as_ref()) {
        (Some(scope), Some(frame)) => {
            Box::pin(compiler.compile_material_with_governed_git_scope(
                &request,
                &codecortex_reports,
                scope,
                frame,
            ))
            .await?
        }
        (Some(scope), None) => {
            Box::pin(compiler.compile_with_governed_git_scope(&request, &codecortex_reports, scope))
                .await?
        }
        (None, Some(frame)) => {
            Box::pin(compiler.compile_material(&request, &codecortex_reports, frame)).await?
        }
        (None, None) => {
            Box::pin(compiler.compile_with_codecortex(&request, &codecortex_reports)).await?
        }
    };
    let touched_paths = packet_scope_paths(&packet, input.material_frame.as_ref(), &request);
    let resolved_concept_ids = if packet_task.is_some() {
        state
            .ul
            .resolve_concept_ids(request.project_id, &touched_paths)
            .await?
    } else {
        Vec::new()
    };
    let assignment = if let (Some(task_id), Some(task)) = (parsed_task_id, packet_task.as_ref()) {
        let task_class = eliot_engine::UlTokenPolicyService::classify(
            Some(task),
            input.material_frame.as_ref(),
            &resolved_concept_ids,
            &touched_paths,
        );
        let config_hash = blake3::hash(b"ul-token-policy-v1").to_hex();
        Some(
            state
                .ul
                .token_policy
                .assignment(
                    request.project_id,
                    task_id,
                    &task_class,
                    config_hash.as_ref(),
                )
                .await?,
        )
    } else {
        None
    };
    let experiment_control = assignment
        .as_ref()
        .is_some_and(|assignment| assignment.arm == eliot_types::UlExperimentArm::Control);
    let memory_free_control = requested_memory_free_control || experiment_control;
    let effective_memory_mode = if memory_free_control {
        MemoryExposureMode::MemoryFreeControl
    } else {
        input.memory_mode.unwrap_or_default()
    };
    if memory_free_control {
        enforce_memory_free_control(&mut packet, input.material_frame.as_ref());
        eliot_engine::PacketQualityService::finalize(&mut packet, input.material_frame.as_ref())?;
    }
    let task_frame = TaskMeaningFrame {
        task_id: request.task_id.clone(),
        user_goal: request.goal.clone(),
        normalized_goal: request.goal.to_ascii_lowercase(),
        task_or_action_type: "governed_task".to_owned(),
        desired_state_transition: request.goal.clone(),
        problem_or_failure_signature: packet.open_questions.join(" "),
        project_module_boundary: packet
            .codecortex
            .as_ref()
            .map_or_else(Vec::new, |view| view.report_refs.clone()),
        files_symbols_config: packet.codecortex.as_ref().map_or_else(Vec::new, |view| {
            view.file_evidence
                .iter()
                .map(|evidence| evidence.path.clone())
                .collect()
        }),
        control_data_state_path: packet
            .causal_bridge
            .iter()
            .map(|hop| format!("{} -> {} -> {}", hop.from, hop.relation, hop.to))
            .collect(),
        constraints: input
            .material_frame
            .as_ref()
            .map_or_else(Vec::new, |frame| frame.killed_paths.clone()),
        invariants: input
            .material_frame
            .as_ref()
            .map_or_else(Vec::new, |frame| frame.acceptance_items.clone()),
        current_evidence: packet.exact_handles.clone(),
        material_unknowns: packet.open_questions.clone(),
        expected_artifact: input
            .material_frame
            .as_ref()
            .map_or_else(String::new, |frame| frame.next_allowed_action.clone()),
        predicted_observable: input
            .material_frame
            .as_ref()
            .map_or_else(String::new, |frame| frame.expected_observable.clone()),
        verifier_need: input
            .material_frame
            .as_ref()
            .map_or_else(String::new, |frame| frame.verifier.clone()),
        abstraction_level_needed: "auto".to_owned(),
        codecortex_report_ref: codecortex_reports
            .first()
            .map(|report| format!("codecortex:{}:{}", report.project, report.task)),
        ..TaskMeaningFrame::default()
    };
    let memory_need = MemoryNeedService::decide(&task_frame, None);
    let cases = deduplicate_experience_cases(
        semantic_records::<ExperienceCase>(state, request.project_id, "experience_case").await?,
    );
    let exposure_policy = MemoryExposurePolicy {
        mode: effective_memory_mode,
        packet_cache_partition: format!(
            "{:?}:{}",
            effective_memory_mode,
            request.task_id
        )
        .to_ascii_lowercase(),
        ..MemoryExposurePolicy::default()
    };
    let experience = ExperienceRetrievalService::recall(
        &ExperienceRecallRequest {
            project_id: request.project_id,
            task_frame,
            need: memory_need.clone(),
            exposure_policy,
        },
        &cases,
    );
    packet.memory_need_decision = Some(memory_need);
    packet.experience_priors = experience.experience_priors;
    if let Some(task) = &packet_task {
        packet.memory_applicability.inclusion_reasons.push(format!(
            "eliot/task/{}@{}:canonical_task_state",
            task.task_id,
            task.memory_revision.value()
        ));
        packet.memory_applicability.inclusion_reasons.sort();
        packet.memory_applicability.inclusion_reasons.dedup();
    }
    let fallback_text = format!(
        "{} {} {}",
        request.goal,
        request.candidate_handles.join(" "),
        packet.exact_handles.join(" ")
    );
    let pyramid = if memory_free_control {
        None
    } else {
        Some(
            state
                .ul
                .packet_enrichment(
                    request.project_id,
                    &request.task_id,
                    &touched_paths,
                    &fallback_text,
                )
                .await?,
        )
    };
    write_json_report(
        &state
            .root
            .join("reports")
            .join("context-packets")
            .join("latest.json"),
        &packet,
    )?;
    let required_invariant_refs = pyramid
        .as_ref()
        .map_or_else(Vec::new, |pyramid| pyramid.required_invariant_refs.clone());
    let mut frame_stub =
        material_frame_stub(&packet, packet_task.as_ref(), &required_invariant_refs);
    if frame_stub.causal_bridge.is_empty()
        && let Some(pyramid) = &pyramid
    {
        frame_stub.causal_bridge = pyramid.bridge.clone();
    }
    let packet_id = packet.packet_id.clone();
    let mut value = serde_json::to_value(packet)?;
    if let Some(pyramid) = &pyramid {
        value["ul_understanding"] = pyramid.understanding.clone();
        let coverage = serde_json::to_value(pyramid.coverage)?
            .as_str()
            .unwrap_or("blind")
            .to_owned();
        value["ul_meta"] = json!({
            "coverage": coverage,
            "novelty_percent": pyramid.meta.novelty_percent,
            "danger": pyramid.meta.danger_paths,
            "recommended_probe": pyramid.recommended_probe,
        });
        let material_risk = input.material_frame.is_some();
        if let Some(frame) = input.material_frame.as_ref() {
            let missing_invariant_refs =
                missing_invariant_refs(&pyramid.required_invariant_refs, frame);
            if !missing_invariant_refs.is_empty() {
                value["ul_gate"] = json!({
                    "status": "require_packet_refresh",
                    "reason": "missing_capsule_invariants",
                    "missing_invariant_refs": missing_invariant_refs,
                });
            }
        }
        if material_risk
            && pyramid.coverage == eliot_types::CoverageClass::Blind
            && value.get("ul_gate").is_none()
        {
            let suggested_probe = pyramid
                .recommended_probe
                .clone()
                .or_else(|| {
                    input
                        .material_frame
                        .as_ref()
                        .map(|frame| frame.verifier.clone())
                })
                .unwrap_or_else(|| frame_stub.verifier.clone());
            value["ul_gate"] = json!({
                "status": "require_probe",
                "reason": "blind_subsystem",
                "concept_or_path": pyramid
                    .blind_target
                    .clone()
                    .or_else(|| touched_paths.first().cloned())
                    .unwrap_or_else(|| "unknown".to_owned()),
                "suggested_probe": suggested_probe,
            });
        }
    }
    if let Some(frame) = input.material_frame.as_ref() {
        let source_frame_hash = canonical_struct_hash(frame)?;
        if let Ok(task_id) = TaskId::from_str(&request.task_id) {
            let diagnostic_prediction = frame
                .cheapest_discriminative_probes
                .first()
                .map(|probe| {
                    (
                        probe.clone(),
                        eliot_types::DiagnosticExpectation::Appears,
                    )
                });
            let captures = state
                .ul
                .prediction
                .capture_frame(eliot_engine::PredictionFrameCaptureInput {
                    base: eliot_engine::PredictionCaptureInput {
                        project_id: request.project_id,
                        task_id,
                        session_id: context.session_id,
                        subsystem_concept_id: pyramid
                            .as_ref()
                            .and_then(|value| value.subsystem_concept_id.clone()),
                        packet_id: packet_id.clone(),
                        expected_observable: frame.expected_observable.clone(),
                        source_frame_hash,
                    },
                    confidence: frame.prediction_confidence,
                    predicted_changed_paths: frame.predicted_changed_paths.clone(),
                    predicted_failing_verifiers: frame.predicted_failing_verifiers.clone(),
                    diagnostic_prediction,
                })
                .await?;
            if !captures.is_empty() {
                value["prediction_refs"] = serde_json::to_value(
                    captures
                        .iter()
                        .map(|capture| capture.prediction_ref.clone())
                        .collect::<Vec<_>>(),
                )?;
                value["prediction_ref"] = Value::String(captures[0].prediction_ref.clone());
            }
        }
        if eliot_engine::parse_expected_observable(&frame.expected_observable).is_none()
            && frame.predicted_changed_paths.is_empty()
            && frame.predicted_failing_verifiers.is_empty()
        {
            value["ul_prediction"] = json!({"status": "not_machine_checkable"});
        }
    }
    value["frame_stub"] = serde_json::to_value(frame_stub)?;
    value["frame_stub_required_edits"] = json!([]);
    value["frame_stub_ready"] = Value::Bool(true);
    if let Some(task) = packet_task.as_ref() {
        enrich_packet_with_task(state, &mut value, task).await?;
    }
    if let Some(assignment) = assignment {
        let effective_injection_mode = if assignment.arm == eliot_types::UlExperimentArm::Control {
            None
        } else {
            state.ul.token_policy.effective_mode(&assignment).await?
        };
        value["ul_experiment"] = json!({
            "project_id": assignment.project_id,
            "task_id": assignment.task_id,
            "task_class": assignment.task_class,
            "ordinal": assignment.ordinal,
            "arm": assignment.arm,
            "assignment_injection_mode": assignment.injection_mode,
            "effective_injection_mode": effective_injection_mode,
            "effective_memory_mode": if memory_free_control {
                "memory_free_control"
            } else {
                "configured"
            },
            "config_hash": assignment.config_hash,
        });
    }
    state.ul.record_packet_gate(
        request.project_id,
        context.session_id,
        parsed_task_id,
        value.get("ul_gate"),
    )?;
    Ok(value)
}

fn enforce_memory_free_control(
    packet: &mut ContextPacketL3,
    frame: Option<&MaterialPacketFrame>,
) {
    packet.current_truth.clear();
    packet.relevant_verified_claims.clear();
    packet.relevant_supported_claims.clear();
    packet.weak_claims_warning.clear();
    packet.negative_memory.clear();
    packet.recent_failures.clear();
    packet.known_decisions.clear();
    packet.open_questions.clear();
    packet.exact_handles.clear();
    packet.source_receipts.clear();
    packet.epistemic_state = eliot_types::EpistemicPacketState::default();
    packet.memory_decisions.clear();
    packet.experience_priors.clear();
    packet.memory_need_decision = None;
    packet.memory_confidence = eliot_types::MemoryConfidence::None;
    packet.memory_applicability.decisions.clear();
    packet.memory_applicability.inclusion_reasons.clear();
    packet.memory_applicability.suppression_reasons =
        vec!["memory_free_control".to_owned()];
    packet.memory_applicability.revalidation_reasons.clear();
    packet.historical_memory.clear();
    packet.memory_lifecycle.suppressed_refs.clear();
    packet.memory_lifecycle.demoted_refs.clear();
    packet.memory_lifecycle.superseded_refs.clear();
    packet.memory_lifecycle.archived_refs.clear();
    packet.memory_lifecycle.minority_preserved_refs.clear();
    packet.memory_lifecycle.lifecycle_warnings =
        vec!["memory_free_control".to_owned()];
    packet.decision_locality_suffix.exact_load_bearing_atoms =
        frame.map_or_else(Vec::new, |frame| frame.exact_load_bearing_atoms.clone());
    packet.decision_locality_suffix.open_unknowns.clear();
    packet.truncation.truncated = false;
    packet.truncation.returned = 0;
}

fn packet_scope_paths(
    packet: &ContextPacketL3,
    frame: Option<&MaterialPacketFrame>,
    request: &CompilePacketL3Request,
) -> Vec<String> {
    let mut values = BTreeSet::new();
    if let Some(codecortex) = &packet.codecortex {
        for evidence in &codecortex.file_evidence {
            insert_path_tokens(&mut values, &evidence.path);
        }
    }
    for hop in &packet.causal_bridge {
        insert_path_tokens(&mut values, &hop.from);
        insert_path_tokens(&mut values, &hop.to);
        if let Some(reference) = &hop.evidence_ref {
            insert_path_tokens(&mut values, reference);
        }
    }
    if let Some(frame) = frame {
        for atom in &frame.exact_load_bearing_atoms {
            insert_path_tokens(&mut values, atom);
        }
        for hop in &frame.causal_bridge {
            insert_path_tokens(&mut values, &hop.from);
            insert_path_tokens(&mut values, &hop.to);
            if let Some(reference) = &hop.evidence_ref {
                insert_path_tokens(&mut values, reference);
            }
        }
    }
    for handle in &request.candidate_handles {
        insert_path_tokens(&mut values, handle);
    }
    insert_path_tokens(&mut values, &request.goal);
    values.into_iter().collect()
}

fn insert_path_tokens(paths: &mut BTreeSet<String>, value: &str) {
    for token in eliot_types::path_cue_tokens(value) {
        paths.insert(token);
    }
}

fn material_frame_stub(
    packet: &ContextPacketL3,
    task: Option<&TaskContract>,
    required_invariant_refs: &[String],
) -> MaterialPacketFrame {
    let next_action = if packet
        .decision_locality_suffix
        .next_allowed_action
        .trim()
        .is_empty()
    {
        "inspect responsible boundary".to_owned()
    } else {
        packet.decision_locality_suffix.next_allowed_action.clone()
    };
    let verifier = if packet.decision_locality_suffix.verifier.trim().is_empty() {
        "cargo test --workspace".to_owned()
    } else {
        packet.decision_locality_suffix.verifier.clone()
    };
    let stop_condition = if packet
        .decision_locality_suffix
        .stop_condition
        .trim()
        .is_empty()
    {
        "stop on verifier failure".to_owned()
    } else {
        packet.decision_locality_suffix.stop_condition.clone()
    };
    MaterialPacketFrame {
        acceptance_items: task.map_or_else(Vec::new, |task| {
            task.acceptance_items
                .iter()
                .map(|item| item.description.clone())
                .collect()
        }),
        environment: packet
            .current_truth_snapshot
            .as_ref()
            .map_or_else(Vec::new, |snapshot| snapshot.environment.clone()),
        active_plan: vec![next_action.clone()],
        completed_work: task.map_or_else(Vec::new, |task| {
            task.acceptance_items
                .iter()
                .filter(|item| item.satisfied)
                .map(|item| item.description.clone())
                .collect()
        }),
        killed_paths: packet.killed_paths.clone(),
        causal_bridge: packet.causal_bridge.clone(),
        negative_memory_checked: !packet.negative_memory.is_empty()
            || packet
                .memory_decisions
                .iter()
                .any(|decision| decision.memory_handle.contains("failure")),
        exact_load_bearing_atoms: packet.exact_handles.clone(),
        cheapest_discriminative_probes: packet
            .decision_locality_suffix
            .cheapest_discriminative_probes
            .clone(),
        responsibility_contour_route_refs: packet
            .decision_locality_suffix
            .responsibility_contour_route_refs
            .clone(),
        next_allowed_action: next_action,
        expected_observable: format!("verifier:{verifier}=pass"),
        verifier: verifier.clone(),
        stop_condition,
        tool_schema_bytes_visible: packet
            .packet_quality
            .as_ref()
            .map_or(0, |quality| quality.tool_schema_bytes_visible),
        instruction_hotset_size: packet
            .packet_quality
            .as_ref()
            .map_or(0, |quality| quality.instruction_hotset_size),
        invariant_refs: required_invariant_refs.to_vec(),
        waived_invariants: Vec::new(),
        prediction_confidence: None,
        predicted_changed_paths: packet
            .exact_handles
            .iter()
            .flat_map(|handle| eliot_types::path_cue_tokens(handle))
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect(),
        predicted_failing_verifiers: vec![verifier],
    }
}

fn missing_invariant_refs(
    required_invariant_refs: &[String],
    frame: &MaterialPacketFrame,
) -> Vec<String> {
    let mut covered = frame.invariant_refs.iter().cloned().collect::<BTreeSet<_>>();
    covered.extend(frame.waived_invariants.iter().filter_map(|waiver| {
        let reason = waiver.reason.trim();
        (!reason.is_empty() && reason.len() <= 240).then(|| waiver.invariant_ref.clone())
    }));
    let mut missing = required_invariant_refs
        .iter()
        .filter(|invariant| !covered.contains(*invariant))
        .cloned()
        .collect::<Vec<_>>();
    missing.sort();
    missing.dedup();
    missing
}

async fn dispatch_understanding_outcome_record(
    state: &McpState,
    arguments: Value,
) -> Result<Value> {
    let mut input: UnderstandingOutcomeToolInput = serde_json::from_value(arguments)?;
    CognitiveMemoryWriter::write_understanding_outcome(
        &state.writer,
        &WriteAdmissionService,
        parse_project_id(&input.project_id)?,
        &mut input.record,
    )
    .await?;
    write_json_report(
        &state
            .root
            .join("reports")
            .join("cognition")
            .join("understanding-outcome-latest.json"),
        &input.record,
    )?;
    serde_json::to_value(input.record).map_err(Into::into)
}

#[allow(clippy::too_many_lines)] // One validated observability command is kept contiguous.
async fn dispatch_memory_influence_trace(
    state: &McpState,
    context: AuthenticatedRequestContext,
    arguments: Value,
) -> Result<Value> {
    let input: MemoryInfluenceToolInput = serde_json::from_value(arguments)?;
    let (project_id, write_id, mut trace) = match input {
        MemoryInfluenceToolInput::Full(input) => (
            parse_project_id(&input.project_id)?,
            WriteId::from_str(&input.write_id)?,
            input.trace,
        ),
        MemoryInfluenceToolInput::Ack(ack) => {
            let project_id = context
                .bound_project_id
                .or_else(|| {
                    ack.project_id
                        .as_deref()
                        .and_then(|project_id| ProjectId::from_str(project_id).ok())
                })
                .context("minimal influence acknowledgement requires project_id when unbound")?;
            let task_id = context
                .bound_task_id
                .or_else(|| {
                    state
                        .ul
                        .touched
                        .last_task_id(project_id, context.session_id)
                })
                .context(
                    "MISSING_PROJECT_PACKET_CONTEXT: minimal influence acknowledgement requires a prior packet for this project or an explicit bound task",
                )?;
            let (packet_id, packet_handles) = state
                .ul
                .touched
                .packet_context(project_id, context.session_id);
            let packet_id = packet_id.context(
                "MISSING_PROJECT_PACKET_CONTEXT: minimal influence acknowledgement requires a prior packet for this project or an explicit bound task",
            )?;
            let epistemic_status =
                influence_epistemic_status(state, project_id, &ack.memory_handle).await?;
            let admission_decision = match epistemic_status.as_str() {
                "verified" => MemoryAdmissionDecision::IncludeVerified,
                "supported" => MemoryAdmissionDecision::IncludeSupported,
                _ => MemoryAdmissionDecision::RequireRevalidation,
            };
            let class_name = serde_json::to_value(ack.influence_class)?
                .as_str()
                .unwrap_or("unknown")
                .to_owned();
            let used_and_changed_action =
                ack.influence_class == MemoryInfluenceClass::UsedAndChangedAction;
            let used_for_verification =
                ack.influence_class == MemoryInfluenceClass::UsedForVerification;
            let prevented_repeated_failure =
                ack.influence_class == MemoryInfluenceClass::PreventedRepeatedFailure;
            let suppressed = matches!(
                ack.influence_class,
                MemoryInfluenceClass::SuppressedAsStale
                    | MemoryInfluenceClass::SuppressedAsWrongScope
            );
            let cited_in_understanding_proof = packet_handles.contains(&ack.memory_handle);
            let trace = MemoryInfluenceTrace {
                task_id,
                session_id: AgentSessionId::from_uuid(context.session_id.as_uuid()),
                memory_handle: ack.memory_handle,
                packet_id,
                admission_decision,
                inclusion_or_suppression_reason: format!("ack:{class_name}"),
                epistemic_status_at_use: epistemic_status,
                cited_in_understanding_proof,
                action_or_probe_changed: used_and_changed_action,
                write_set_changed: false,
                verifier_changed: used_for_verification,
                repeated_failure_prevented: prevented_repeated_failure,
                suppressed_as_stale_or_wrong_scope: suppressed,
                downstream_outcome_ref: ack.downstream_outcome_ref,
                influence_class: ack.influence_class,
                canonical_receipt: None,
            };
            let write_id = ack.write_id.map_or_else(
                || deterministic_influence_write_id(project_id, &trace),
                |write_id| WriteId::from_str(&write_id).context("parse influence write id"),
            )?;
            (project_id, write_id, trace)
        }
    };
    trace.canonical_receipt = None;
    let observability_receipt = CognitiveMemoryWriter::write_memory_influence_trace(
        &state.writer,
        project_id,
        write_id,
        &trace,
    )
    .await?;
    write_json_report(
        &state
            .root
            .join("reports")
            .join("cognition")
            .join("memory-influence-latest.json"),
        &trace,
    )?;
    serde_json::to_value(MemoryInfluenceTraceWriteResult {
        trace,
        observability_receipt,
    })
    .map_err(Into::into)
}

async fn influence_epistemic_status(
    state: &McpState,
    project_id: ProjectId,
    memory_handle: &str,
) -> Result<String> {
    let response = state
        .store
        .fetch_atoms_l2(&FetchAtomsL2Request {
            project_id,
            handles: vec![memory_handle.to_owned()],
            continuation: None,
            consistency: ReadConsistencyMode::Latest,
            at_least_revision: None,
        })
        .await?;
    let status = response
        .claims
        .iter()
        .find(|claim| {
            memory_handle == claim.claim_id.to_string()
                || memory_handle == format!("claim:{}", claim.claim_id)
        })
        .map_or(EpistemicStatus::Unknown, |claim| claim.status);
    Ok(serde_json::to_value(status)?
        .as_str()
        .unwrap_or("unknown")
        .to_owned())
}

fn deterministic_influence_write_id(
    project_id: ProjectId,
    trace: &MemoryInfluenceTrace,
) -> Result<WriteId> {
    let canonical = serde_json::to_vec(&(project_id, trace))?;
    let digest = blake3::hash(&canonical);
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest.as_bytes()[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x50;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Ok(WriteId::from_uuid(uuid::Uuid::from_bytes(bytes)))
}

async fn dispatch_context_cargo_receipt(state: &McpState, arguments: Value) -> Result<Value> {
    let mut input: ContextCargoReceiptToolInput = serde_json::from_value(arguments)?;
    CognitiveMemoryWriter::write_context_cargo_receipt(
        &state.writer,
        &WriteAdmissionService,
        parse_project_id(&input.project_id)?,
        &mut input.receipt,
    )
    .await?;
    write_json_report(
        &state
            .root
            .join("reports")
            .join("cognition")
            .join("context-cargo-latest.json"),
        &input.receipt,
    )?;
    serde_json::to_value(input.receipt).map_err(Into::into)
}

fn dispatch_task_meaning(arguments: Value) -> Result<Value> {
    let input: TaskMeaningToolInput = serde_json::from_value(arguments)?;
    let bridge_quality = TaskMeaningService::bridge_quality(&input.frame);
    let memory_need = MemoryNeedService::decide(&input.frame, input.requested_need);
    Ok(json!({
        "task_meaning_frame": input.frame,
        "causal_bridge_quality": bridge_quality,
        "memory_need_decision": memory_need,
        "authority": "current-task model only; no memory grants current truth or action authority"
    }))
}

async fn semantic_records<T>(
    state: &McpState,
    project_id: ProjectId,
    receipt_kind: &str,
) -> Result<Vec<T>>
where
    T: serde::de::DeserializeOwned,
{
    state
        .store
        .semantic_records_by_kind(project_id, receipt_kind)
        .await?
        .into_iter()
        .map(|observation| {
            serde_json::from_value(
                observation
                    .payload
                    .get("receipt_body")
                    .cloned()
                    .context("canonical semantic observation has no receipt_body")?,
            )
            .map_err(Into::into)
        })
        .collect()
}

async fn dispatch_experience_recall(state: &McpState, arguments: Value) -> Result<Value> {
    let input: ExperienceRecallToolInput = serde_json::from_value(arguments)?;
    let project_id = parse_project_id(&input.project_id)?;
    let cases = deduplicate_experience_cases(
        semantic_records::<ExperienceCase>(state, project_id, "experience_case").await?,
    );
    let need = MemoryNeedService::decide(&input.frame, input.requested_need);
    let request = ExperienceRecallRequest {
        project_id,
        task_frame: input.frame,
        need,
        exposure_policy: input.exposure_policy.unwrap_or_default(),
    };
    serde_json::to_value(ExperienceRetrievalService::recall(&request, &cases)).map_err(Into::into)
}

async fn dispatch_experience_reinstate(state: &McpState, arguments: Value) -> Result<Value> {
    let input: ExperienceReinstateToolInput = serde_json::from_value(arguments)?;
    let project_id = parse_project_id(&input.project_id)?;
    let cases = deduplicate_experience_cases(
        semantic_records::<ExperienceCase>(state, project_id, "experience_case").await?,
    );
    let experience_case = cases
        .iter()
        .find(|case| case.case_id == input.case_id)
        .context("experience case does not exist")?;
    serde_json::to_value(ContextReinstatementService::bundle(experience_case)).map_err(Into::into)
}

async fn dispatch_experience_form(
    state: &McpState,
    context: AuthenticatedRequestContext,
    arguments: Value,
) -> Result<Value> {
    let input: ExperienceFormToolInput = serde_json::from_value(arguments)?;
    let project_id = parse_project_id(&input.project_id)?;
    if input.episode.project_id != project_id {
        anyhow::bail!("experience episode belongs to a different project");
    }
    let task_id = TaskId::from_str(&input.task_id).context("parse experience task_id")?;
    let result = ExperienceFormationService::reconstruct(input.episode)?;
    match result {
        ExperienceFormationResult::Formed {
            mut experience_case,
        } => {
            if let Some(existing) =
                semantic_records::<ExperienceCase>(state, project_id, "experience_case")
                    .await?
                    .into_iter()
                    .find(|existing| existing.case_id == experience_case.case_id)
            {
                let mut value = serde_json::to_value(ExperienceFormationResult::Formed {
                    experience_case: Box::new(existing),
                })?;
                value["idempotent_replay"] = Value::Bool(true);
                return Ok(value);
            }
            let receipt = CognitiveMemoryWriter::write_semantic_record(
                &state.writer,
                &WriteAdmissionService,
                project_id,
                task_id,
                AgentSessionId::from_uuid(context.session_id.as_uuid()),
                "experience_case",
                &experience_case,
            )
            .await?;
            experience_case.authority.canonical_receipt = Some(receipt);
            let mut value =
                serde_json::to_value(ExperienceFormationResult::Formed { experience_case })?;
            value["idempotent_replay"] = Value::Bool(false);
            Ok(value)
        }
        nothing @ ExperienceFormationResult::NothingToLearn { .. } => {
            serde_json::to_value(nothing).map_err(Into::into)
        }
    }
}

async fn dispatch_experience_abstract(
    state: &McpState,
    context: AuthenticatedRequestContext,
    arguments: Value,
) -> Result<Value> {
    let input: ExperienceAbstractToolInput = serde_json::from_value(arguments)?;
    let project_id = parse_project_id(&input.project_id)?;
    let task_id = TaskId::from_str(&input.task_id).context("parse abstraction task_id")?;
    let all_cases = deduplicate_experience_cases(
        semantic_records::<ExperienceCase>(state, project_id, "experience_case").await?,
    );
    let cases = input
        .case_refs
        .iter()
        .map(|case_ref| {
            all_cases
                .iter()
                .find(|case| case.case_id == *case_ref)
                .cloned()
                .with_context(|| format!("experience case {case_ref} does not exist"))
        })
        .collect::<Result<Vec<_>>>()?;
    let result = ContrastiveAbstractionService::abstract_cases(project_id, &cases)?;
    match result {
        ContrastiveAbstractionResult::Formed { mut pattern } => {
            if let Some(existing) =
                semantic_records::<ExperiencePattern>(state, project_id, "experience_pattern")
                    .await?
                    .into_iter()
                    .find(|existing| existing.pattern_id == pattern.pattern_id)
            {
                let mut value = serde_json::to_value(ContrastiveAbstractionResult::Formed {
                    pattern: Box::new(existing),
                })?;
                value["idempotent_replay"] = Value::Bool(true);
                return Ok(value);
            }
            let receipt = CognitiveMemoryWriter::write_semantic_record(
                &state.writer,
                &WriteAdmissionService,
                project_id,
                task_id,
                AgentSessionId::from_uuid(context.session_id.as_uuid()),
                "experience_pattern",
                &pattern,
            )
            .await?;
            pattern.authority.canonical_receipt = Some(receipt);
            let mut value = serde_json::to_value(ContrastiveAbstractionResult::Formed { pattern })?;
            value["idempotent_replay"] = Value::Bool(false);
            Ok(value)
        }
        none @ ContrastiveAbstractionResult::NoLearnablePattern { .. } => {
            serde_json::to_value(none).map_err(Into::into)
        }
    }
}

async fn dispatch_experience_maturity_transition(
    state: &McpState,
    context: AuthenticatedRequestContext,
    arguments: Value,
) -> Result<Value> {
    let input: ExperienceMaturityTransitionToolInput = serde_json::from_value(arguments)?;
    let project_id = parse_project_id(&input.project_id)?;
    let task_id = TaskId::from_str(&input.task_id).context("parse maturity task_id")?;
    let physical_patterns =
        semantic_records::<ExperiencePattern>(state, project_id, "experience_pattern").await?;
    let mut transfer_evidence = input.evidence.independent_host_refs.clone();
    transfer_evidence.extend(input.evidence.verified_decision_delta_refs.clone());
    transfer_evidence.sort();
    transfer_evidence.dedup();
    if let Some(existing) = physical_patterns.iter().find(|existing| {
        existing.pattern_id == input.pattern_id
            && existing.maturity.state == input.target_state
            && existing.transfer_evidence == transfer_evidence
    }) {
        let mut value = serde_json::to_value(existing)?;
        value["idempotent_replay"] = Value::Bool(true);
        return Ok(value);
    }
    let mut pattern = deduplicate_experience_patterns(physical_patterns.clone())
        .into_iter()
        .find(|pattern| pattern.pattern_id == input.pattern_id)
        .context("experience pattern does not exist in the active logical projection")?;
    let next_maturity =
        MaturityGateService::transition(&pattern.maturity, input.target_state, &input.evidence)?;
    pattern.maturity = next_maturity;
    pattern.transfer_evidence = transfer_evidence.clone();
    pattern.authority.review_refs.extend(transfer_evidence);
    pattern.authority.review_refs.sort();
    pattern.authority.review_refs.dedup();
    let receipt = CognitiveMemoryWriter::write_semantic_record(
        &state.writer,
        &WriteAdmissionService,
        project_id,
        task_id,
        AgentSessionId::from_uuid(context.session_id.as_uuid()),
        "experience_pattern",
        &pattern,
    )
    .await?;
    pattern.authority.canonical_receipt = Some(receipt);
    let mut value = serde_json::to_value(pattern)?;
    value["idempotent_replay"] = Value::Bool(false);
    Ok(value)
}

async fn dispatch_negative_transfer_record(
    state: &McpState,
    context: AuthenticatedRequestContext,
    arguments: Value,
) -> Result<Value> {
    let input: NegativeTransferToolInput = serde_json::from_value(arguments)?;
    let project_id = parse_project_id(&input.project_id)?;
    let task_id = TaskId::from_str(&input.task_id).context("parse negative-transfer task_id")?;
    let mut record = NegativeTransferService::record(
        input.experiment_ref,
        input.memory_handles,
        input.task_id,
        input.harm,
        input.root_cause_stage,
        input.source_has_reconstructable_episode,
    );
    if let Some(existing) = semantic_records::<eliot_types::NegativeTransferRecord>(
        state,
        project_id,
        "negative_transfer_record",
    )
    .await?
    .into_iter()
    .find(|existing| existing.record_id == record.record_id)
    {
        let mut value = serde_json::to_value(existing)?;
        value["idempotent_replay"] = Value::Bool(true);
        return Ok(value);
    }
    let receipt = CognitiveMemoryWriter::write_semantic_record(
        &state.writer,
        &WriteAdmissionService,
        project_id,
        task_id,
        AgentSessionId::from_uuid(context.session_id.as_uuid()),
        "negative_transfer_record",
        &record,
    )
    .await?;
    record.receipt = Some(receipt);
    let mut value = serde_json::to_value(record)?;
    value["idempotent_replay"] = Value::Bool(false);
    Ok(value)
}

fn latest_task_packet(state: &McpState, task_id: TaskId) -> Result<Option<ContextPacketL3>> {
    let path = state
        .root
        .join("reports")
        .join("context-packets")
        .join("latest.json");
    if !path.is_file() {
        return Ok(None);
    }
    let packet: ContextPacketL3 = serde_json::from_reader(std::fs::File::open(path)?)?;
    Ok((packet.task_id == task_id.to_string()).then_some(packet))
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
struct AutonomyHostBinding {
    work_item_id: WorkItemId,
    host_id: String,
    lease_ref: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
enum AutonomyApprovalDecisionKind {
    Granted,
    Denied,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
struct AutonomyApprovalRequestRecord {
    approval_id: String,
    request_write_id: WriteId,
    autonomy_run_id: String,
    project_id: ProjectId,
    task_id: TaskId,
    expected_state_revision: u64,
    expected_runtime_revision: u64,
    requested_by_session_id: SessionId,
    exact_action_hash: String,
    approval_revision: u64,
    #[serde(with = "time::serde::rfc3339")]
    expires_at: time::OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    requested_at: time::OffsetDateTime,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
struct AutonomyApprovalDecisionRecord {
    approval_id: String,
    request_write_id: WriteId,
    decision_write_id: WriteId,
    autonomy_run_id: String,
    project_id: ProjectId,
    task_id: TaskId,
    exact_action_hash: String,
    decision: AutonomyApprovalDecisionKind,
    reason: String,
    approval_revision: u64,
    decided_by_session_id: SessionId,
    #[serde(with = "time::serde::rfc3339")]
    expires_at: time::OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    decided_at: time::OffsetDateTime,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
struct AutonomyApprovalConsumptionRecord {
    approval_id: String,
    decision_write_id: WriteId,
    consumption_write_id: WriteId,
    autonomy_run_id: String,
    project_id: ProjectId,
    task_id: TaskId,
    exact_action_hash: String,
    approval_revision: u64,
    consumed_by_session_id: SessionId,
    aggregate_write_id: String,
    #[serde(with = "time::serde::rfc3339")]
    consumed_at: time::OffsetDateTime,
}

#[derive(serde::Serialize)]
struct AutonomyCompletionApprovalScope<'a> {
    action: &'static str,
    project_id: ProjectId,
    task_id: TaskId,
    autonomy_run_id: &'a str,
    expected_state_revision: u64,
    expected_runtime_revision: u64,
    completion_proof_hash: String,
    reason: &'a str,
    risk_tier: &'static str,
    verifier_refs: &'a [String],
}

struct AutonomyCompletionApprovalInput<'a> {
    project_id: ProjectId,
    task_id: TaskId,
    autonomy_run_id: &'a str,
    expected_state_revision: u64,
    expected_runtime_revision: u64,
    completion_proof: &'a CompletionProof,
    reason: &'a str,
    verifier_refs: &'a [String],
}

struct CanonicalR3ApprovalResolution<'a> {
    loaded: &'a LoadedAutonomyRuntime,
    project_id: ProjectId,
    task_id: TaskId,
    approval_id: &'a str,
    exact_action_hash: &'a str,
    aggregate_write_id: WriteId,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
struct AutonomyWorkGraphRecord {
    #[serde(default)]
    aggregate_schema_version: Option<String>,
    #[serde(default)]
    authoritative_commit: Option<AutonomyActionCommit>,
    #[serde(default)]
    runtime_snapshot: Option<Value>,
    #[serde(default)]
    transition_snapshots: Vec<eliot_types::AutonomyRunTransitionReceipt>,
    #[serde(default)]
    recovery_snapshots: Vec<AutonomyRecoveryReceipt>,
    #[serde(default)]
    secondary_transition_snapshots: Vec<eliot_types::AutonomyRunTransitionReceipt>,
    #[serde(default)]
    secondary_recovery_snapshots: Vec<AutonomyRecoveryReceipt>,
    #[serde(default)]
    tripwire_snapshots: Vec<AutonomyTripwireEnvelope>,
    #[serde(default)]
    budget_snapshot: Option<AutonomyBudgetRecord>,
    #[serde(default)]
    action_result: Value,
    #[serde(default)]
    host_result_chains: Vec<AutonomyHostResultChain>,
    #[serde(default)]
    approval_consumption: Option<AutonomyApprovalConsumptionRecord>,
    autonomy_run_id: String,
    runtime_revision: u64,
    action: String,
    action_fingerprint: String,
    tripwire_policy: AutonomyTripwirePolicy,
    work_items: Vec<AutonomyWorkItem>,
    host_bindings: Vec<AutonomyHostBinding>,
    transition_refs: Vec<String>,
    recovery_refs: Vec<String>,
    completion_proof: Option<CompletionProof>,
}

const AUTONOMY_ACTION_AGGREGATE_SCHEMA: &str = "eliot-autonomy-action-aggregate-v1";

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
struct AutonomyActionCommit {
    aggregate_write_id: String,
    idempotency_key: String,
    action: String,
    action_fingerprint: String,
    committed_state: AutonomyRunState,
    committed_state_revision: u64,
    committed_runtime_revision: u64,
    completion_proof_hash: Option<String>,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
struct AutonomyHostResultChain {
    work_item_id: WorkItemId,
    host_id: AgentHostId,
    agent_session_id: AgentSessionId,
    role_lease_id: String,
    work_lease_id: WorkLeaseId,
    invocation_id: String,
    result_id: String,
    disposition_id: String,
    candidate_diff_ref: String,
    candidate_review_ref: String,
    commit_ref: String,
    changed_files: Vec<String>,
    verifier_refs: Vec<String>,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
struct AutonomyBudgetRecord {
    autonomy_run_id: String,
    runtime_revision: u64,
    ledger: AutonomyBudgetLedger,
    usage_evidence_refs: Vec<String>,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
struct AutonomyTripwireEnvelope {
    autonomy_run_id: String,
    runtime_revision: u64,
    work_item_id: WorkItemId,
    evidence_ref: String,
    tripwire: AutonomyTripwireRecord,
}

struct LoadedAutonomyRuntime {
    runtime: BoundedAutonomyRuntime,
    graph: AutonomyWorkGraphRecord,
    canonical: eliot_store::CanonicalAutonomyRunView,
    integrity_status: String,
}

// The daemon is the sole autonomy writer for one runtime instance. A process-wide
// async mutex deliberately serializes every autonomy contract/transition/action
// compare-and-commit section across named-pipe profiles. The guard is never acquired
// by WriterActor or re-entered from an action path, so awaiting the canonical write
// while holding it cannot form an ordering cycle.
static AUTONOMY_COMMIT_SERIALIZER: std::sync::OnceLock<tokio::sync::Mutex<()>> =
    std::sync::OnceLock::new();

struct PreparedOperatorQuery {
    projection: OperatorProjectionKind,
    exact_evidence_target: Option<String>,
    records: Vec<OperatorRecordView>,
}

struct OperatorQueryPageData {
    records: Vec<OperatorRecordView>,
    next_cursor: Option<String>,
    total_matching: usize,
    total_is_exact: bool,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct OperatorCursorState {
    base_offset: u64,
    canonical_start: u64,
    matched_seen: u64,
}

fn dispatch_contour_route_preview(arguments: Value) -> Result<Value> {
    let input: ContourRoutePreviewToolInput = serde_json::from_value(arguments)?;
    let decision = ContourRoutingService::resolve(&ContourRouteRequest {
        project_id: parse_project_id(&input.project_id)?,
        task_id: TaskId::from_str(&input.task_id).context("parse contour task_id")?,
        work_item_id: WorkItemId::from_str(&input.work_item_id)
            .context("parse contour work_item_id")?,
        contour: input.contour,
        policies: &input.policies,
        live_routes: &input.live_routes,
        now: time::OffsetDateTime::now_utc(),
    })?;
    serde_json::to_value(decision).map_err(Into::into)
}

// Every variant is intentionally closed and allowlisted even where the current typed
// execution caller lives outside this MCP module. This prevents a generic raw kind tool.
#[allow(dead_code)]
#[derive(Clone, Copy)]
enum CanonicalReceiptKind {
    StateTransition,
    MemoryTrajectoryCorrectness,
    MinorityPressureRecord,
    TraceCompletenessContract,
    ReplaySet,
    ReplayCase,
    ReplayInputSnapshot,
    SealedReplayRun,
    ReplayRun,
    ReplayAudit,
    HarnessExperiment,
    HarnessDisposition,
    MetaMetricEvidence,
    MetaIsolationRejection,
    ExperimentalPolicyCandidate,
    MetaPolicyPromotion,
    MetaPolicyRollback,
    SleepConsolidationBundle,
    SleepConsolidationRun,
    ProcedureCandidate,
    ProcedureSkillCandidate,
    ProcedurePromotionDisposition,
    ForgettingCandidate,
    TestCandidate,
    ReplayCaseCandidate,
    DreamCandidate,
    AutonomyRunContract,
    AutonomyRunTransition,
    AutonomyBudgetLedger,
    AutonomyWorkGraph,
    AutonomyTripwire,
    AutonomyRecovery,
    AutonomyApprovalRequest,
    AutonomyApprovalDecision,
    AutonomyApprovalConsumption,
    CandidateDiff,
    CandidateReview,
    AgentResult,
    AgentResultDisposition,
    WorktreeLease,
    WorkLease,
    ControllerLease,
    OperationJob,
    AgentInvocationRequest,
    ManagedFinalizationIntent,
    ManagedFinalizationAggregate,
    OperatorControlRequest,
    CognitiveRunContract,
    CognitiveRunAttempt,
    CognitiveToolObservation,
    CognitiveRawVerifier,
    CognitiveRunTerminal,
}

impl CanonicalReceiptKind {
    const fn as_str(self) -> &'static str {
        match self {
            Self::StateTransition => "state_transition",
            Self::MemoryTrajectoryCorrectness => "memory_trajectory_correctness",
            Self::MinorityPressureRecord => "minority_pressure_record",
            Self::TraceCompletenessContract => "trace_completeness_contract",
            Self::ReplaySet => "replay_set",
            Self::ReplayCase => "replay_case",
            Self::ReplayInputSnapshot => "replay_input_snapshot",
            Self::SealedReplayRun => "sealed_replay_run",
            Self::ReplayRun => "replay_run",
            Self::ReplayAudit => "replay_audit",
            Self::HarnessExperiment => "harness_experiment",
            Self::HarnessDisposition => "harness_disposition",
            Self::MetaMetricEvidence => "meta_metric_evidence",
            Self::MetaIsolationRejection => "meta_isolation_rejection",
            Self::ExperimentalPolicyCandidate => "experimental_policy_candidate",
            Self::MetaPolicyPromotion => "meta_policy_promotion",
            Self::MetaPolicyRollback => "meta_policy_rollback",
            Self::SleepConsolidationBundle => "sleep_consolidation_bundle",
            Self::SleepConsolidationRun => "sleep_consolidation_run",
            Self::ProcedureCandidate => "procedure_candidate",
            Self::ProcedureSkillCandidate => "procedure_skill_candidate",
            Self::ProcedurePromotionDisposition => "procedure_promotion_disposition",
            Self::ForgettingCandidate => "forgetting_candidate",
            Self::TestCandidate => "test_candidate",
            Self::ReplayCaseCandidate => "replay_case_candidate",
            Self::DreamCandidate => "dream_candidate",
            Self::AutonomyRunContract => "autonomy_run_contract",
            Self::AutonomyRunTransition => "autonomy_run_transition",
            Self::AutonomyBudgetLedger => "autonomy_budget_ledger",
            Self::AutonomyWorkGraph => "autonomy_work_graph",
            Self::AutonomyTripwire => "autonomy_tripwire",
            Self::AutonomyRecovery => "autonomy_recovery",
            Self::AutonomyApprovalRequest => "autonomy_approval_request",
            Self::AutonomyApprovalDecision => "autonomy_approval_decision",
            Self::AutonomyApprovalConsumption => "autonomy_approval_consumption",
            Self::CandidateDiff => "candidate_diff",
            Self::CandidateReview => "candidate_review",
            Self::AgentResult => "agent_result",
            Self::AgentResultDisposition => "agent_result_disposition",
            Self::WorktreeLease => "worktree_lease",
            Self::WorkLease => "work_lease",
            Self::ControllerLease => "controller_lease",
            Self::OperationJob => "operation_job",
            Self::AgentInvocationRequest => "agent_invocation_request",
            Self::ManagedFinalizationIntent => "managed_finalization_intent",
            Self::ManagedFinalizationAggregate => "managed_finalization_aggregate",
            Self::OperatorControlRequest => "operator_control_request",
            Self::CognitiveRunContract => "cognitive_run_contract",
            Self::CognitiveRunAttempt => "cognitive_run_attempt",
            Self::CognitiveToolObservation => "cognitive_tool_observation",
            Self::CognitiveRawVerifier => "cognitive_raw_verifier",
            Self::CognitiveRunTerminal => "cognitive_run_terminal",
        }
    }
}

fn deterministic_canonical_write_id(
    project_id: ProjectId,
    task_id: Option<TaskId>,
    _kind: CanonicalReceiptKind,
    idempotency_key: &str,
) -> WriteId {
    let digest = blake3::hash(
        format!(
            "canonical-mcp:{project_id}:{}:{idempotency_key}",
            task_id.map_or_else(|| "project".to_owned(), |task_id| task_id.to_string()),
        )
        .as_bytes(),
    );
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest.as_bytes()[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x50;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    WriteId::from_uuid(uuid::Uuid::from_bytes(bytes))
}

async fn dispatch_write_cognitive_observation(
    state: &McpState,
    context: AuthenticatedRequestContext,
    arguments: Value,
) -> Result<Value> {
    let input: CognitiveObservationToolInput = serde_json::from_value(arguments)?;
    if input.payload.is_null() {
        anyhow::bail!("payload must contain a normalized error, diagnostic, or tool observation");
    }
    let project_id = parse_project_id(&input.project_id)?;
    let task_id = TaskId::from_str(&input.task_id).context("parse task id")?;
    let payload_hash = blake3::hash(&serde_json::to_vec(&input.payload)?)
        .to_hex()
        .to_string();
    let write_id = input.write_id.as_deref().map_or_else(
        || {
            Ok(deterministic_canonical_write_id(
                project_id,
                Some(task_id),
                CanonicalReceiptKind::CognitiveToolObservation,
                &format!("part-e-observation:{payload_hash}"),
            ))
        },
        |value| WriteId::from_str(value).context("parse write id"),
    )?;
    let tool_name = input
        .payload
        .get("tool_name")
        .and_then(Value::as_str)
        .unwrap_or("eliot-worker")
        .to_owned();
    let observation = input
        .payload
        .get("error")
        .or_else(|| input.payload.get("diagnostic"))
        .or_else(|| input.payload.get("message"))
        .and_then(Value::as_str)
        .map_or_else(
            || format!("cognitive observation {}", &payload_hash[..16]),
            str::to_owned,
        );
    let command = SemanticCommand::ToolObservationRecord(ToolObservationRecordCommand {
        context: CommandContext {
            write_id,
            agent_id: AgentId::from_uuid(context.session_id.as_uuid()),
            session_id: Some(context.session_id),
            project_id,
            task_id: Some(task_id),
            scope: format!("eliot/task/{task_id}/cognitive-observation"),
            authority: "model-owned Part-E cognitive observation".to_owned(),
            visibility: Visibility::Internal,
            taint: TaintClass::LocalVerified,
            lifecycle_status: LifecycleStatus::Active,
        },
        tool_name,
        observation,
        payload: input.payload,
    });
    let envelope = WriteAdmissionService.admit(&command)?;
    let receipt = state.writer.submit(envelope).await?;
    Ok(json!({
        "receipt": {
            "receipt_id": receipt.receipt_id,
            "write_id": receipt.write_id,
            "status": receipt.status,
        }
    }))
}

async fn write_canonical_observation<T: serde::Serialize>(
    state: &McpState,
    context: AuthenticatedRequestContext,
    project_id: ProjectId,
    task_id: Option<TaskId>,
    kind: CanonicalReceiptKind,
    idempotency_key: &str,
    body: &T,
) -> Result<(WriteReceiptRef, WriteStatus)> {
    let envelope =
        canonical_observation_envelope(context, project_id, task_id, kind, idempotency_key, body)?;
    let receipt = state.writer.submit(envelope).await?;
    Ok((
        WriteReceiptRef {
            receipt_id: receipt.receipt_id,
            write_id: receipt.write_id,
        },
        receipt.status,
    ))
}

fn canonical_observation_envelope<T: serde::Serialize>(
    context: AuthenticatedRequestContext,
    project_id: ProjectId,
    task_id: Option<TaskId>,
    kind: CanonicalReceiptKind,
    idempotency_key: &str,
    body: &T,
) -> Result<MemoryWriteEnvelope> {
    if idempotency_key.trim().is_empty() {
        anyhow::bail!("canonical MCP idempotency key must not be empty");
    }
    let write_id = deterministic_canonical_write_id(project_id, task_id, kind, idempotency_key);
    let command = SemanticCommand::ToolObservationRecord(ToolObservationRecordCommand {
        context: CommandContext {
            write_id,
            agent_id: AgentId::from_uuid(context.session_id.as_uuid()),
            session_id: Some(context.session_id),
            project_id,
            task_id,
            scope: "canonical product record".to_owned(),
            authority: "authenticated governor MCP typed action".to_owned(),
            visibility: Visibility::Internal,
            taint: TaintClass::LocalVerified,
            lifecycle_status: LifecycleStatus::Active,
        },
        tool_name: "eliot-governor-mcp".to_owned(),
        observation: format!("canonical {} record", kind.as_str()),
        payload: json!({
            "receipt_kind": kind.as_str(),
            "receipt_body": body,
            "writer_path": "mcp_stdio::write_canonical_observation"
        }),
    });
    WriteAdmissionService.admit(&command).map_err(Into::into)
}

#[derive(Clone, Debug, serde::Serialize)]
struct CanonicalAutonomyVerifierEvidence {
    verification_id: VerificationId,
    canonical_ref: String,
    registered_name: String,
    profile_ref: String,
    command: String,
    version: String,
    artifact_scope_hash: String,
    artifact_refs: Vec<String>,
    acceptance_item_ids: Vec<String>,
    commit_ref: String,
    verifier_ref: String,
}

fn require_two_real_host_chains(
    contract: &AutonomyRunContract,
    chains: &[AutonomyHostResultChain],
) -> Result<()> {
    if !autonomy_contract_requires_two_hosts(contract) {
        return Ok(());
    }
    let distinct_results = chains
        .iter()
        .map(|chain| chain.result_id.as_str())
        .collect::<std::collections::BTreeSet<_>>();
    let distinct_hosts = chains
        .iter()
        .map(|chain| chain.host_id)
        .collect::<std::collections::BTreeSet<_>>();
    if distinct_results.len() < 2
        || !distinct_hosts.contains(&AgentHostId::OpenCode)
        || !distinct_hosts.contains(&AgentHostId::Antigravity)
    {
        anyhow::bail!(
            "two-host autonomy completion requires distinct real OpenCode and Antigravity result chains"
        );
    }
    Ok(())
}

fn approval_request_write_id(approval_id: &str) -> Result<WriteId> {
    let raw = approval_id
        .strip_prefix("autonomy-approval:")
        .context("approval_id is not a canonical autonomy approval id")?;
    WriteId::from_str(raw).context("approval_id does not contain a valid canonical write id")
}

fn approval_decision_write_id(
    project_id: ProjectId,
    task_id: TaskId,
    approval_id: &str,
) -> WriteId {
    deterministic_canonical_write_id(
        project_id,
        Some(task_id),
        CanonicalReceiptKind::AutonomyApprovalDecision,
        &format!("approval-decision:{approval_id}"),
    )
}

fn approval_consumption_write_id(
    project_id: ProjectId,
    task_id: TaskId,
    approval_id: &str,
) -> WriteId {
    deterministic_canonical_write_id(
        project_id,
        Some(task_id),
        CanonicalReceiptKind::AutonomyApprovalConsumption,
        &format!("approval-consumption:{approval_id}"),
    )
}

async fn canonical_approval_was_consumed(
    state: &McpState,
    loaded: &LoadedAutonomyRuntime,
    project_id: ProjectId,
    task_id: TaskId,
    approval_id: &str,
) -> Result<bool> {
    let write_id = approval_consumption_write_id(project_id, task_id, approval_id);
    let exact_record_exists = state
        .store
        .canonical_record_by_write_id::<AutonomyApprovalConsumptionRecord>(
            project_id,
            Some(task_id),
            &[CanonicalReceiptKind::AutonomyApprovalConsumption.as_str()],
            write_id,
        )
        .await?
        .is_some();
    let aggregate_contains_consumption = loaded.canonical.work_graphs.iter().any(|record| {
        serde_json::from_value::<AutonomyWorkGraphRecord>(record.receipt_body.clone()).is_ok_and(
            |graph| {
                graph
                    .approval_consumption
                    .as_ref()
                    .is_some_and(|consumption| consumption.approval_id == approval_id)
            },
        )
    });
    Ok(exact_record_exists || aggregate_contains_consumption)
}

async fn resolve_canonical_r3_approval(
    state: &McpState,
    context: AuthenticatedRequestContext,
    resolution: CanonicalR3ApprovalResolution<'_>,
) -> Result<(
    CanonicalR3ApprovalAuthorization,
    AutonomyApprovalConsumptionRecord,
)> {
    let CanonicalR3ApprovalResolution {
        loaded,
        project_id,
        task_id,
        approval_id,
        exact_action_hash,
        aggregate_write_id,
    } = resolution;
    let request_write_id = approval_request_write_id(approval_id)?;
    let consumption_write_id = approval_consumption_write_id(project_id, task_id, approval_id);
    if canonical_approval_was_consumed(state, loaded, project_id, task_id, approval_id).await? {
        anyhow::bail!("R3 approval was already consumed");
    }
    let request_record = exact_autonomy_approval_request(
        state,
        project_id,
        task_id,
        &loaded.runtime.contract.autonomy_run_id,
        approval_id,
    )
    .await?
    .context("R3 approval request is missing")?;
    let request = &request_record.receipt_body;
    if request.project_id != project_id
        || request.task_id != task_id
        || request.autonomy_run_id != loaded.runtime.contract.autonomy_run_id
        || request.expected_state_revision != loaded.runtime.contract.state_revision
        || request.expected_runtime_revision != loaded.runtime.runtime_revision
        || request.requested_by_session_id != context.session_id
        || request.exact_action_hash != exact_action_hash
        || request.approval_revision != 0
        || request.expires_at <= time::OffsetDateTime::now_utc()
    {
        anyhow::bail!("R3 approval is stale, principal-mismatched, or action-mismatched");
    }
    let decision_write_id = approval_decision_write_id(project_id, task_id, approval_id);
    let decision = state
        .store
        .canonical_record_by_write_id::<AutonomyApprovalDecisionRecord>(
            project_id,
            Some(task_id),
            &[CanonicalReceiptKind::AutonomyApprovalDecision.as_str()],
            decision_write_id,
        )
        .await?
        .context("R3 approval has no canonical HumanOperator decision")?;
    if decision.receipt_body.decision != AutonomyApprovalDecisionKind::Granted
        || decision.receipt_body.approval_revision != 1
        || decision.receipt_body.exact_action_hash != request.exact_action_hash
        || decision.receipt_body.project_id != project_id
        || decision.receipt_body.task_id != task_id
        || decision.receipt_body.expires_at != request.expires_at
        || decision.receipt_body.approval_id != approval_id
        || decision.receipt_body.request_write_id != request_write_id
        || decision.receipt_body.decision_write_id != decision_write_id
        || decision.canonical_receipt.write_id != decision_write_id
        || decision.receipt_body.expires_at <= time::OffsetDateTime::now_utc()
    {
        anyhow::bail!("R3 approval was denied, expired, or does not bind the exact request");
    }
    let authorization = CanonicalR3ApprovalAuthorization {
        approval_id: approval_id.to_owned(),
        exact_action_hash: exact_action_hash.to_owned(),
        decision_receipt: decision.canonical_receipt.clone(),
        approved_by: decision.receipt_body.decided_by_session_id,
        expires_at: decision.receipt_body.expires_at,
    };
    let consumption = AutonomyApprovalConsumptionRecord {
        approval_id: approval_id.to_owned(),
        decision_write_id,
        consumption_write_id,
        autonomy_run_id: loaded.runtime.contract.autonomy_run_id.clone(),
        project_id,
        task_id,
        exact_action_hash: exact_action_hash.to_owned(),
        approval_revision: decision.receipt_body.approval_revision.saturating_add(1),
        consumed_by_session_id: context.session_id,
        aggregate_write_id: aggregate_write_id.to_string(),
        consumed_at: time::OffsetDateTime::now_utc(),
    };
    Ok((authorization, consumption))
}

#[derive(Debug, Eq, PartialEq, serde::Serialize)]
struct OperatorLifecycleBinding {
    evidence_refs: Vec<String>,
    precondition_refs: Vec<String>,
    approval_ref: Option<String>,
}

impl OperatorLifecycleBinding {
    fn unbound(evidence_refs: Vec<String>) -> Self {
        Self {
            evidence_refs,
            precondition_refs: Vec::new(),
            approval_ref: None,
        }
    }
}

struct OperatorControlRequestDraft<'a> {
    project_id: ProjectId,
    task_id: TaskId,
    operation: &'a str,
    target_ref: &'a str,
    disposition: &'a str,
    exact_action_hash: Option<String>,
    reason_or_evidence_refs: Vec<String>,
    idempotency_key: &'a str,
}

struct OperatorAutonomyApprovalDecision<'a> {
    project_id: ProjectId,
    task_id: TaskId,
    approval_id: &'a str,
    exact_action_hash: &'a str,
    decision: AutonomyApprovalDecisionKind,
    reason: &'a str,
    idempotency_key: &'a str,
}

struct CandidateDispositionActor {
    role_lease_id: String,
    controller_lease_id: Option<String>,
}

struct CandidatePromotion<'a> {
    task: &'a TaskContract,
    candidate: &'a CanonicalClaimCard,
    evidence_refs: &'a [String],
    source_provenance_refs: Vec<String>,
    idempotency_key: &'a str,
    actor: &'a CandidateDispositionActor,
}

async fn resolve_exact_procedure_pattern(
    state: &McpState,
    project_id: ProjectId,
    task_id: TaskId,
    pattern_ref: &str,
) -> Result<(ExperiencePattern, String, String, WriteReceiptRef)> {
    let pattern_id = pattern_ref
        .strip_prefix("experience-pattern:")
        .filter(|value| !value.trim().is_empty())
        .context("pattern_ref must be experience-pattern:<exact-pattern-id>")?;
    let observations = state
        .store
        .experience_pattern_revisions_by_id(project_id, task_id, pattern_id)
        .await?;
    // ExperiencePattern history is immutable: maturity transitions append a
    // new physical observation for the same logical pattern. This exact,
    // bounded store query orders matching revisions newest-first.
    let observation = observations
        .into_iter()
        .max_by_key(|observation| (observation.memory_revision, observation.project_sequence))
        .context("pattern_ref does not resolve to a canonical ExperiencePattern")?;
    let pattern = serde_json::from_value::<ExperiencePattern>(
        observation
            .payload
            .get("receipt_body")
            .cloned()
            .context("canonical ExperiencePattern observation has no receipt_body")?,
    )
    .context("parse canonical ExperiencePattern observation")?;
    if pattern.pattern_id != pattern_id {
        anyhow::bail!("canonical ExperiencePattern id differs from pattern_ref");
    }
    if pattern.project_id != project_id
        || observation.project_id != project_id
        || observation.task_id != Some(task_id)
    {
        anyhow::bail!("ExperiencePattern project differs from requested project");
    }
    let write_id = observation.write_id;
    let receipt = state
        .store
        .write_receipt_by_id(&write_id)
        .await?
        .context("canonical ExperiencePattern observation has no WriterActor receipt")?;
    if receipt.project_id != project_id
        || receipt.task_id != Some(task_id)
        || receipt.command_kind != eliot_types::SemanticCommandKind::ToolObservationRecord
        || receipt.memory_revision != Some(observation.memory_revision)
        || receipt.project_sequence != Some(observation.project_sequence)
        || !receipt
            .created_records
            .contains(&observation.observation_id)
        || !matches!(
            receipt.status,
            WriteStatus::Committed | WriteStatus::IdempotentReplay
        )
    {
        anyhow::bail!("canonical ExperiencePattern receipt scope or status differs");
    }
    Ok((
        pattern.clone(),
        sha256_json(&pattern)?,
        observation.observation_id,
        WriteReceiptRef {
            receipt_id: receipt.receipt_id,
            write_id: receipt.write_id,
        },
    ))
}

fn task_evidence_refs(task: &TaskContract) -> BTreeSet<String> {
    let mut refs = BTreeSet::new();
    for observation_id in &task.observation_ids {
        refs.insert(observation_id.clone());
        refs.insert(format!("observation:{observation_id}"));
    }
    for verification_id in &task.verification_ids {
        refs.insert(verification_id.to_string());
        refs.insert(format!("verification:{verification_id}"));
    }
    for scope in &task.verification_scopes {
        refs.insert(scope.verification_id.to_string());
        refs.insert(format!("verification:{}", scope.verification_id));
        refs.insert(scope.verifier_id.clone());
        refs.insert(format!("verifier:{}", scope.verifier_id));
        refs.insert(scope.worktree_ref.clone());
        refs.insert(scope.path_or_resource_scope.clone());
        for artifact in &scope.artifact_refs {
            refs.insert(artifact.resource_ref.clone());
        }
    }
    refs.retain(|value| !value.trim().is_empty());
    refs
}

async fn validated_negative_transfer_refs(
    state: &McpState,
    project_id: ProjectId,
    task_id: TaskId,
    requested: &[String],
) -> Result<(Vec<String>, Vec<String>)> {
    let records = semantic_records::<eliot_types::NegativeTransferRecord>(
        state,
        project_id,
        "negative_transfer_record",
    )
    .await?;
    let task_refs = [task_id.to_string(), format!("task:{task_id}")];
    let mut validated = Vec::new();
    let mut unresolved = Vec::new();
    for reference in requested {
        let record_id = reference
            .strip_prefix("negative-transfer:")
            .unwrap_or(reference);
        if records
            .iter()
            .any(|record| record.record_id == record_id && task_refs.contains(&record.task_ref))
        {
            validated.push(reference.clone());
        } else {
            unresolved.push(reference.clone());
        }
    }
    Ok((validated, unresolved))
}

async fn validate_procedure_disposition_evidence(
    state: &McpState,
    task: &TaskContract,
    input: &ProcedureCandidateDispositionToolInput,
) -> Result<(Vec<String>, Vec<String>)> {
    let task_artifacts = task_verifier_artifacts(task);
    if input
        .holdout_evidence
        .iter()
        .any(|requested| !task_artifacts.iter().any(|artifact| artifact == requested))
    {
        anyhow::bail!(
            "every holdout_evidence item must resolve to an exact canonical current-task verifier artifact"
        );
    }
    let holdout_refs = input
        .holdout_evidence
        .iter()
        .map(|artifact| artifact.resource_ref.clone())
        .collect::<Vec<_>>();
    let (negative_refs, unresolved) = validated_negative_transfer_refs(
        state,
        task.project_id,
        task.task_id,
        &input.negative_transfer_refs,
    )
    .await?;
    if !unresolved.is_empty() {
        anyhow::bail!(
            "every negative_transfer_ref must resolve to an exact canonical current-task negative-transfer record"
        );
    }
    Ok((holdout_refs, negative_refs))
}

fn procedure_disposition_fingerprint(
    input: &ProcedureCandidateDispositionToolInput,
    task: &TaskContract,
    pattern_sha256: &str,
    pattern_observation_ref: &str,
    pattern_receipt: &WriteReceiptRef,
    candidate: &CanonicalRecord<CanonicalProcedureSkillCandidate>,
) -> Result<String> {
    sha256_json(&json!({
        "project_id": task.project_id,
        "task_id": task.task_id,
        "task_revision": input.expected_revision,
        "pattern_ref": input.pattern_ref,
        "pattern_observation_ref": pattern_observation_ref,
        "pattern_receipt": pattern_receipt,
        "pattern_sha256": pattern_sha256,
        "candidate_ref": input.candidate_ref,
        "candidate_receipt": candidate.canonical_receipt,
        "candidate_sha256": candidate.receipt_body.candidate_sha256,
        "holdout_evidence": input.holdout_evidence,
        "negative_transfer_refs": input.negative_transfer_refs,
    }))
}

fn evaluate_procedure_disposition(
    pattern: &ExperiencePattern,
    candidate: &SkillCardV2,
    holdout_refs: &[String],
    negative_refs: &[String],
    has_generic_holdout: bool,
) -> Result<(
    SkillLifecycleRecord,
    ProcedurePromotionOutcome,
    String,
    Vec<String>,
)> {
    let mut lifecycle = SkillLifecycleService::procedure_promotion_disposition(
        pattern,
        candidate,
        holdout_refs,
        negative_refs,
    );
    lifecycle.write_receipt = None;
    let engine_outcome = lifecycle
        .promotion_outcome
        .context("procedure promotion engine returned no disposition")?;
    let mut reasons = vec![if has_generic_holdout {
        "generic_task_verifier_artifact_is_not_procedure_holdout_authority".to_owned()
    } else {
        "missing_independent_procedure_holdout".to_owned()
    }];
    let outcome = if engine_outcome == ProcedurePromotionOutcome::Promoted {
        lifecycle.state = SkillLifecycleState::Candidate;
        lifecycle.promotion_outcome = Some(ProcedurePromotionOutcome::NotReadyForProcedure);
        reasons.push("procedure_holdout_semantic_kind_is_unavailable_in_v1".to_owned());
        ProcedurePromotionOutcome::NotReadyForProcedure
    } else {
        engine_outcome
    };
    let pattern_disposition = if outcome == ProcedurePromotionOutcome::Demoted {
        "candidate_quarantined_pattern_retained"
    } else {
        "kept_transfer_validated"
    };
    Ok((lifecycle, outcome, pattern_disposition.to_owned(), reasons))
}

fn procedure_disposition_response(
    record: &CanonicalProcedurePromotionDisposition,
    canonical_receipt: &WriteReceiptRef,
    write_status: Option<WriteStatus>,
    idempotent_replay: bool,
) -> Value {
    json!({
        "component": "procedure_promotion_disposition",
        "disposition": record,
        "canonical_receipt": canonical_receipt,
        "write_status": write_status,
        "idempotent_replay": idempotent_replay,
    })
}

async fn persist_procedure_disposition(
    state: &McpState,
    context: AuthenticatedRequestContext,
    idempotency_key: &str,
    record: CanonicalProcedurePromotionDisposition,
) -> Result<Value> {
    let (receipt, status) = write_canonical_observation(
        state,
        context,
        record.project_id,
        Some(record.task_id),
        CanonicalReceiptKind::ProcedurePromotionDisposition,
        idempotency_key,
        &record,
    )
    .await?;
    Ok(procedure_disposition_response(
        &record,
        &receipt,
        Some(status),
        matches!(status, WriteStatus::IdempotentReplay),
    ))
}

async fn resolve_governed_packet_git_scope(
    input: &CompilePacketL3Request,
    task: Option<&TaskContract>,
    codecortex_reports: &[CodeCortexReport],
) -> Result<Option<eliot_types::memory::GovernedGitScope>> {
    let Some(provenance) = task
        .and_then(|task| task.action_provenance.as_ref())
        .filter(|provenance| provenance.source_scope.kind == "git_worktree")
    else {
        return Ok(None);
    };
    let report = codecortex_reports
        .iter()
        .rev()
        .find(|report| report.task == input.task_id)
        .context("governed Git-scoped packet requires a task-matched CodeCortex report")?;
    let expected_worktree = provenance
        .source_scope
        .worktree_ref
        .as_deref()
        .context("governed Git-scoped task has no worktree identity")?;
    let report_root = tokio::fs::canonicalize(&report.repo_root).await?;
    let expected_root = tokio::fs::canonicalize(expected_worktree).await?;
    if report_root != expected_root {
        anyhow::bail!("CodeCortex report worktree differs from canonical action provenance");
    }
    let scope = resolve_packet_git_scope(&report_root, input.project_id).await?;
    if report.git_head.as_deref() != Some(scope.commit.as_str()) || report.dirty == scope.clean {
        anyhow::bail!("task-matched CodeCortex report is stale for the resolved Git scope");
    }
    Ok(Some(scope))
}

async fn enrich_packet_with_task(
    state: &McpState,
    value: &mut Value,
    task: &TaskContract,
) -> Result<()> {
    let Value::Object(object) = value else {
        return Ok(());
    };
    let refs = canonical_packet_refs(state, task).await?;
    let current_receipt = state
        .store
        .write_receipt_by_id(&task.write_id)
        .await?
        .context("current TaskContract WriteReceipt does not resolve")?;
    object.insert("task_contract".to_owned(), serde_json::to_value(task)?);
    object.insert(
        "task_truth_status".to_owned(),
        Value::String("current_canonical".to_owned()),
    );
    object.insert(
        "task_revision_fence".to_owned(),
        serde_json::to_value(task.memory_revision)?,
    );
    object.insert(
        "packet_revision_fence".to_owned(),
        serde_json::to_value(refs.packet_revision_fence)?,
    );
    object.insert("packet_id".to_owned(), Value::String(refs.packet_id));
    object.insert(
        "task_contract_ref".to_owned(),
        Value::String(refs.task_contract_ref.clone()),
    );
    object.insert(
        "current_truth_refs".to_owned(),
        json!([refs.task_contract_ref]),
    );
    object.insert(
        "exact_evidence_refs".to_owned(),
        json!([current_receipt.receipt_id]),
    );
    object.insert(
        "negative_memory_check_ref".to_owned(),
        Value::String(refs.negative_memory_check_ref),
    );
    object.insert(
        "negative_stale_exclusions".to_owned(),
        json!(["candidate observations are not verifier authority"]),
    );
    object.insert(
        "registered_verifiers".to_owned(),
        Value::Array(
            RegisteredTaskVerifier::ALL
                .into_iter()
                .map(RegisteredTaskVerifier::descriptor)
                .collect(),
        ),
    );
    Ok(())
}
