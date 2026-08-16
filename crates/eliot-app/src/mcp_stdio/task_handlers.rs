fn canonical_struct_hash<T: serde::Serialize>(value: &T) -> Result<String> {
    Ok(blake3::hash(&serde_json::to_vec(value)?)
        .to_hex()
        .to_string())
}

const PACKET_POST_COMMIT_OPERATION_KIND: &str = "eliot.packet.post_commit";
const PACKET_POST_COMMIT_SCHEMA_VERSION: &str = "eliot-packet-post-commit-v3";
const PACKET_ACTIVE_AUTHORITY_SCHEMA_VERSION: &str = "eliot-packet-active-authority-v2";
const PACKET_OUTBOX_REPLAY_LIMIT: usize = 32;
const PACKET_OUTBOX_RECOVERY_ERROR_SAMPLE_LIMIT: usize = 16;

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case")]
enum PacketPostCommitStatus {
    Prepared,
    CommittedPending,
    Complete,
    PendingRetry,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case")]
enum PacketPostCommitEffect {
    CodecortexProjection,
    PredictionCapture,
    ExperimentMeasurement,
    GateProjection,
}

/// Immutable packet-commit/effect authority. Response bytes remain separate
/// inspection data. `CodeCortex` `generated_at`, `repo_root`, and
/// `memory_receipt` are the only current projection ephemera excluded here.
#[derive(Clone, Debug, PartialEq, serde::Deserialize, serde::Serialize)]
struct PacketCommitMaterial {
    operation_kind: String,
    schema_version: String,
    project_id: ProjectId,
    task_id: String,
    effect_session_id: SessionId,
    packet_id: String,
    at_revision: MemoryRevision,
    codecortex_projection_hash: Option<String>,
    prediction_intents: Vec<eliot_engine::PacketPredictionIntent>,
    measurement: Option<eliot_types::UlTaskExperimentAssignment>,
    gate_projection: Option<Value>,
    effects: Vec<PacketPostCommitEffect>,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
struct PacketCommitProvenance {
    request_session_id: SessionId,
    #[serde(with = "time::serde::rfc3339")]
    prepared_at: time::OffsetDateTime,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
struct PacketPostCommitIntent {
    operation_id: String,
    material: PacketCommitMaterial,
    provenance: PacketCommitProvenance,
    response_hash_blake3: String,
    response: Value,
    codecortex_projection: Option<CodeCortexReport>,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
struct PacketPostCommitEvent {
    schema_version: String,
    event_id: WriteId,
    operation_id: String,
    request_session_id: SessionId,
    sequence: u64,
    status: PacketPostCommitStatus,
    errors: Vec<String>,
    #[serde(with = "time::serde::rfc3339")]
    recorded_at: time::OffsetDateTime,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
struct ActivePacketAuthority {
    schema_version: String,
    operation_id: String,
    material: PacketCommitMaterial,
    packet: ContextPacketL3,
    response_hash_blake3: String,
    response: Value,
}

#[derive(Clone, Debug)]
struct TaskPacketCommitFence {
    task_contract_hash: String,
    previous_active_fingerprint: Option<String>,
}

static PACKET_TASK_SERIALIZERS: StdOnceLock<
    StdMutex<HashMap<String, std::sync::Weak<tokio::sync::Mutex<()>>>>,
> = StdOnceLock::new();

fn packet_task_serializer(task_id: &str) -> Arc<tokio::sync::Mutex<()>> {
    let serializers = PACKET_TASK_SERIALIZERS.get_or_init(|| StdMutex::new(HashMap::new()));
    let mut serializers = serializers
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let key = task_packet_key(task_id);
    if let Some(serializer) = serializers.get(&key).and_then(std::sync::Weak::upgrade) {
        return serializer;
    }
    let serializer = Arc::new(tokio::sync::Mutex::new(()));
    serializers.insert(key, Arc::downgrade(&serializer));
    serializer
}

#[derive(Clone, Debug)]
struct PreparedPacketMeasurement {
    assignment: eliot_types::UlTaskExperimentAssignment,
    effective_injection_mode: Option<eliot_types::UlInjectionMode>,
}

async fn prepare_packet_measurement(
    state: &McpState,
    project_id: ProjectId,
    task_id: TaskId,
    task_class: eliot_types::UlTaskClass,
    memory_free_control: bool,
) -> Result<PreparedPacketMeasurement> {
    let config_hash = blake3::hash(b"ul-token-policy-v1").to_hex().to_string();
    let arm = if memory_free_control {
        eliot_types::UlExperimentArm::Control
    } else {
        eliot_types::UlExperimentArm::Treatment
    };
    let assignment = eliot_types::UlTaskExperimentAssignment {
        project_id,
        task_id,
        task_class: task_class.clone(),
        // Live odd/even allocation is a post-admission measurement write and
        // is deliberately absent from packet semantics.
        ordinal: 0,
        arm,
        injection_mode: eliot_types::UlInjectionMode::Payload,
        config_hash: config_hash.clone(),
    };
    let effective_injection_mode = if memory_free_control {
        None
    } else {
        state.ul.production_injection_mode(&assignment).await?
    };
    Ok(PreparedPacketMeasurement {
        assignment,
        effective_injection_mode,
    })
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
    let effective_memory_mode = input.memory_mode.unwrap_or_default();
    if let Some(frame) = input.material_frame.as_ref() {
        let invalid = material_frame_required_edits(frame)
            .into_iter()
            .map(|field| eliot_types::InvalidField {
                field: field.to_owned(),
                reason: material_frame_required_edit_reason(field).to_owned(),
            })
            .collect::<Vec<_>>();
        if !invalid.is_empty() {
            return Err(eliot_types::ToolInputError {
                data: eliot_types::ToolInputErrorData {
                    code: "INVALID_TOOL_INPUT".to_owned(),
                    missing: Vec::new(),
                    invalid,
                    minimal_valid_example: eliot_types::compile_packet_minimal_example(),
                },
            }
            .into());
        }
    }
    let request = input.request;
    let material_frame = input.material_frame;
    let packet_serializer = packet_task_serializer(&request.task_id);
    let _packet_guard = packet_serializer.lock().await;
    let parsed_task_id = TaskId::from_str(&request.task_id).ok();
    replay_packet_post_commit_outbox_with_transition_lock(
        state,
        &request.task_id,
        parsed_task_id,
        true,
    )
    .await?;
    let packet_task = if let Some(packet_task_id) = parsed_task_id {
        state.store.task_contract_by_id(packet_task_id).await?
    } else {
        None
    };
    let commit_fence = TaskPacketCommitFence {
        task_contract_hash: canonical_struct_hash(&packet_task)?,
        previous_active_fingerprint: active_packet_fingerprint(state, &request.task_id)?,
    };
    // Certification control is explicit. Hidden experiment assignment must never
    // decide production memory exposure or cause a memory read before this point.
    let previous_packet = if requested_memory_free_control {
        None
    } else {
        parsed_task_id
            .map(|task_id| latest_task_packet(state, task_id))
            .transpose()?
            .flatten()
    };
    let codecortex_batch =
        fresh_codecortex_reports(state, &request, material_frame.as_ref(), packet_task.as_ref())?;
    let codecortex_reports = &codecortex_batch.reports;
    let current_git_scope =
        resolve_governed_packet_git_scope(&request, packet_task.as_ref(), codecortex_reports)
            .await?;
    let touched_paths =
        resolve_packet_scope_paths(&request, material_frame.as_ref(), codecortex_reports);
    let fallback_text = format!("{} {}", request.goal, request.candidate_handles.join(" "));
    let (pyramid_source, resolved_concept_ids, experience_source) = if requested_memory_free_control
    {
        (
            PacketPyramidSource::Forbidden,
            Vec::new(),
            PacketExperienceSource::Forbidden,
        )
    } else {
        match revision_bound_packet_enrichment(
            state,
            request.project_id,
            &request.task_id,
            &touched_paths,
            &fallback_text,
        )
        .await
        {
            Ok((at_revision, pyramid)) => {
                let resolved_concept_ids = pyramid.resolved_concept_ids.clone();
                let snapshot = PacketPyramidSnapshot {
                    at_revision,
                    understanding: pyramid.understanding,
                    bridge: pyramid.bridge,
                    metacognition: pyramid.meta,
                    coverage: pyramid.coverage,
                    blind_target: pyramid.blind_target,
                    recommended_probe: pyramid.recommended_probe,
                    subsystem_concept_id: pyramid.subsystem_concept_id,
                    required_invariant_refs: pyramid.required_invariant_refs,
                    project_evidence: pyramid.project_evidence,
                };
                let cases = semantic_records::<ExperienceCase>(
                    state,
                    request.project_id,
                    "experience_case",
                )
                .await?;
                (
                    PacketPyramidSource::Resolved(Box::new(snapshot)),
                    resolved_concept_ids,
                    PacketExperienceSource::Cases(cases),
                )
            }
            Err(error) => {
                let Some(unavailable) = error.downcast_ref::<PacketEnrichmentUnavailable>() else {
                    return Err(error);
                };
                (
                    PacketPyramidSource::Unavailable {
                        reason: unavailable.0.clone(),
                    },
                    Vec::new(),
                    PacketExperienceSource::Cases(Vec::new()),
                )
            }
        }
    };
    let task_class = eliot_engine::UlTokenPolicyService::classify(
        packet_task.as_ref(),
        material_frame.as_ref(),
        &resolved_concept_ids,
        &touched_paths,
    );
    let resolved_cues = if requested_memory_free_control {
        PacketResolvedCues::default()
    } else {
        PacketResolvedCues {
            task_class_cues: vec![task_class.key()],
            scope_refs: touched_paths.clone(),
            concept_refs: resolved_concept_ids,
        }
    };
    let task_receipt_metadata = if let Some(task) = packet_task.as_ref() {
        let receipt = state
            .store
            .write_receipt_by_id(&task.write_id)
            .await?
            .context("current TaskContract WriteReceipt does not resolve")?;
        Some(PacketTaskReceiptMetadata {
            exact_evidence_refs: vec![receipt.receipt_id.to_string()],
            registered_verifiers: RegisteredTaskVerifier::ALL
                .into_iter()
                .map(RegisteredTaskVerifier::descriptor)
                .collect(),
        })
    } else {
        None
    };
    let compile_mode = match effective_memory_mode {
        MemoryExposureMode::MemoryFreeControl => PacketCompileMode::CertificationControl,
        MemoryExposureMode::IncludeCaseCandidates => PacketCompileMode::CertificationTreatment,
        MemoryExposureMode::FullAudit => PacketCompileMode::ShadowEvaluation,
        MemoryExposureMode::CurrentTruthOnly | MemoryExposureMode::MatureExperienceOnly => {
            PacketCompileMode::Production
        }
    };
    let prepared_measurement = if matches!(
        compile_mode,
        PacketCompileMode::CertificationControl | PacketCompileMode::CertificationTreatment
    ) {
        if let Some(task_id) = parsed_task_id {
            Some(
                prepare_packet_measurement(
                    state,
                    request.project_id,
                    task_id,
                    task_class.clone(),
                    requested_memory_free_control,
                )
                .await?,
            )
        } else {
            None
        }
    } else {
        None
    };
    let plan = PacketCompilePlan {
        request: request.clone(),
        session_id: context.session_id,
        compile_mode,
        memory_exposure: effective_memory_mode,
        task_contract: packet_task.clone(),
        task_receipt_metadata,
        previous_packet,
        material_frame: material_frame.clone(),
        codecortex_reports: codecortex_batch.reports.clone(),
        current_git_scope,
        touched_paths,
        resolved_cues,
        pyramid_source,
        experience_source,
        budget_policy: PacketBudgetPolicy::governor_default(request.max_tokens),
        measurement_view: prepared_measurement
            .as_ref()
            .map(|measurement| PacketMeasurementView {
                task_class: measurement.assignment.task_class.clone(),
                assignment_injection_mode: measurement.assignment.injection_mode,
                effective_injection_mode: measurement.effective_injection_mode,
                config_hash: measurement.assignment.config_hash.clone(),
            }),
    };
    let compiled = Box::pin(
        ContextCompiler::new(ReadService::new(state.store.clone())).compile_plan(plan),
    )
    .await?;
    let packet = compiled.packet;
    let packet_id = packet.packet_id.clone();
    let mut value = serde_json::to_value(&packet)?;
    let Value::Object(supplement) = compiled.response_supplement else {
        unreachable!("semantic packet supplement is always an object")
    };
    let Value::Object(value_object) = &mut value else {
        unreachable!("serialized context packet is always an object")
    };
    value_object.extend(supplement);
    value["packet_budget_decision"] = serde_json::to_value(&compiled.budget)?;
    value["compile_audit"] = serde_json::to_value(&compiled.compile_audit)?;
    if !compiled.admission.active_allowed {
        persist_rejected_context_attempt(state, &packet, &value)?;
        return Ok(value);
    }
    let response_hash_blake3 = canonical_struct_hash(&value)?;
    let codecortex_projection = codecortex_batch.pending_persistence;
    let mut material = PacketCommitMaterial {
        operation_kind: PACKET_POST_COMMIT_OPERATION_KIND.to_owned(),
        schema_version: PACKET_POST_COMMIT_SCHEMA_VERSION.to_owned(),
        project_id: request.project_id,
        task_id: request.task_id.clone(),
        effect_session_id: context.session_id,
        packet_id,
        at_revision: packet.at_revision,
        codecortex_projection_hash: codecortex_projection
            .as_ref()
            .map(codecortex_projection_hash)
            .transpose()?,
        prediction_intents: compiled.prediction_intents,
        measurement: prepared_measurement.map(|measurement| measurement.assignment),
        gate_projection: value.get("ul_gate").cloned(),
        effects: Vec::new(),
    };
    material.effects = packet_post_commit_effect_plan(&material);
    let operation_id = packet_post_commit_operation_id(&material)?;
    let outbox_intent = PacketPostCommitIntent {
        operation_id,
        material,
        provenance: PacketCommitProvenance {
            request_session_id: context.session_id,
            prepared_at: time::OffsetDateTime::now_utc(),
        },
        response_hash_blake3,
        response: value.clone(),
        codecortex_projection,
    };
    let task_commit_guard = task_commit_serializer().lock().await;
    let _task_process_guard = if let Some(task_id) = parsed_task_id {
        Some(acquire_task_transition_process_lock(&state.root, task_id).await?)
    } else {
        None
    };
    ensure_packet_commit_fence(state, parsed_task_id, &request.task_id, &commit_fence).await?;
    let (outbox_root, stored_intent, staged_event) =
        stage_packet_post_commit_outbox(state, &outbox_intent)?;
    if staged_event.status == PacketPostCommitStatus::Complete
        && completed_packet_post_commit_replay_is_idempotent(
            staged_event.status,
            packet_post_commit_intent_is_active(state, &stored_intent)?,
            &stored_intent.operation_id,
        )?
    {
        drop(task_commit_guard);
        return Ok(stored_intent.response);
    }
    let mut post_commit_errors = commit_active_context_packet(state, &stored_intent)?;
    transition_packet_post_commit_outbox(
        &outbox_root,
        &stored_intent,
        PacketPostCommitStatus::CommittedPending,
        &post_commit_errors,
    )?;
    drop(task_commit_guard);
    ensure_packet_post_commit_intent_is_active(state, &stored_intent)?;
    post_commit_errors.extend(apply_packet_post_commit_intent(state, &stored_intent).await);
    finish_packet_post_commit_outbox(&outbox_root, &stored_intent, &post_commit_errors)?;
    Ok(stored_intent.response)
}

async fn revision_bound_packet_enrichment(
    state: &McpState,
    project_id: ProjectId,
    task_id: &str,
    touched_paths: &[String],
    fallback_text: &str,
) -> Result<(MemoryRevision, ul::PyramidPacketEnrichment)> {
    let request = CurrentStateRequest {
        project_id,
        consistency: ReadConsistencyMode::Latest,
        at_least_revision: None,
    };
    let mut last_mismatch = "projection fence was not evaluated".to_owned();
    for attempt in 0..3 {
        let before = state.store.current_state(&request).await?;
        let family_before = packet_enrichment_family_fence(
            state
                .store
                .cognitive_projection_family_states(project_id)
                .await?,
            before.memory_revision,
        );
        let family_before = match family_before {
            Ok(family_before) => family_before,
            Err(error) => {
                last_mismatch = error.to_string();
                if attempt < 2 {
                    tokio::time::sleep(std::time::Duration::from_millis(25_u64 << (attempt * 2)))
                        .await;
                }
                continue;
            }
        };
        let enrichment = state
            .ul
            .packet_enrichment(project_id, task_id, touched_paths, fallback_text)
            .await?;
        let family_after = packet_enrichment_family_fence(
            state
                .store
                .cognitive_projection_family_states(project_id)
                .await?,
            before.memory_revision,
        );
        let after = state.store.current_state(&request).await?;
        match family_after {
            Ok(family_after)
                if after.memory_revision == before.memory_revision
                    && family_after == family_before =>
            {
                return Ok((before.memory_revision, enrichment));
            }
            Ok(_) => {
                last_mismatch = format!(
                    "canonical or derived family state changed: before={}, after={}",
                    before.memory_revision.value(),
                    after.memory_revision.value(),
                );
            }
            Err(error) => last_mismatch = error.to_string(),
        }
        if attempt < 2 {
            tokio::time::sleep(std::time::Duration::from_millis(25_u64 << (attempt * 2))).await;
        }
    }
    Err(PacketEnrichmentUnavailable(format!(
        "Cue/DependencyDirty projection fence did not stabilize after 3 attempts: {last_mismatch}"
    ))
    .into())
}

#[derive(Debug)]
struct PacketEnrichmentUnavailable(String);

impl std::fmt::Display for PacketEnrichmentUnavailable {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for PacketEnrichmentUnavailable {}

fn packet_enrichment_family_fence(
    states: Vec<eliot_store::CognitiveProjectionFamilyState>,
    revision: MemoryRevision,
) -> Result<Vec<eliot_store::CognitiveProjectionFamilyState>> {
    use eliot_store::{CognitiveProjectionFamily, CognitiveProjectionPublicationStatus};

    let mut relevant = states
        .into_iter()
        .filter(|state| {
            matches!(
                state.family,
                CognitiveProjectionFamily::Cue | CognitiveProjectionFamily::DependencyDirty
            )
        })
        .collect::<Vec<_>>();
    relevant.sort_by_key(|state| state.family);
    for family in [
        CognitiveProjectionFamily::Cue,
        CognitiveProjectionFamily::DependencyDirty,
    ] {
        let state = relevant
            .iter()
            .find(|state| state.family == family)
            .with_context(|| format!("{family:?} projection family has no publication state"))?;
        anyhow::ensure!(
            state.status == CognitiveProjectionPublicationStatus::Published
                && state.target_revision >= revision
                && state
                    .applied_revision
                    .is_some_and(|applied| applied >= revision),
            "{family:?} projection is not published through revision {}: status={}, target={}, applied={:?}",
            revision.value(),
            state.status.as_str(),
            state.target_revision.value(),
            state.applied_revision.map(MemoryRevision::value),
        );
    }
    Ok(relevant)
}

fn material_frame_required_edits(frame: &MaterialPacketFrame) -> Vec<&'static str> {
    let mut fields = Vec::new();
    if frame.next_allowed_action.trim().is_empty() {
        fields.push("material_frame.next_allowed_action");
    }
    if frame.expected_observable.trim().is_empty() {
        fields.push("material_frame.expected_observable");
    }
    if frame.verifier.trim().is_empty() {
        fields.push("material_frame.verifier");
    }
    if frame.stop_condition.trim().is_empty() {
        fields.push("material_frame.stop_condition");
    }
    fields
}

fn material_frame_required_edit_reason(field: &str) -> &'static str {
    match field {
        "material_frame.next_allowed_action" => {
            "material work requires an explicit next allowed action"
        }
        "material_frame.expected_observable" => {
            "material work requires a machine-checkable expected observable"
        }
        "material_frame.verifier" => "material work requires a registered verifier",
        "material_frame.stop_condition" => "material work requires an explicit stop condition",
        _ => "material work requires this load-bearing field",
    }
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
                    "MISSING_PROJECT_PACKET_CONTEXT: minimal influence acknowledgement requires an explicit bound task and a same-session L3 packet or exact fetch context",
                )?;
            let (packet_id, packet_handles) = state
                .ul
                .touched
                .packet_context(project_id, context.session_id);
            let packet_id = packet_id.context(
                "MISSING_PROJECT_PACKET_CONTEXT: minimal influence acknowledgement requires an explicit bound task and a same-session L3 packet or exact fetch context",
            )?;
            if packet_id.starts_with("retrieval:") && !packet_handles.contains(&ack.memory_handle) {
                anyhow::bail!(
                    "EXACT_FETCH_CONTEXT_MISMATCH: minimal influence acknowledgement must name a handle returned by the same-session exact fetch"
                );
            }
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

struct CodeCortexCompileBatch {
    reports: Vec<CodeCortexReport>,
    pending_persistence: Option<CodeCortexReport>,
}

fn fresh_codecortex_reports(
    state: &McpState,
    request: &CompilePacketL3Request,
    frame: Option<&MaterialPacketFrame>,
    task: Option<&TaskContract>,
) -> Result<CodeCortexCompileBatch> {
    let class = TaskExecutionClassifier::classify(request, frame, &[], &request.candidate_handles);
    if !TaskExecutionClassifier::should_attach_codecortex(request, frame, &[], &class) {
        return Ok(CodeCortexCompileBatch {
            reports: Vec::new(),
            pending_persistence: None,
        });
    }
    let mut exact_patterns = request.candidate_handles.clone();
    if let Some(frame) = frame {
        exact_patterns.extend(frame.predicted_changed_paths.iter().cloned());
        exact_patterns.extend(frame.exact_load_bearing_atoms.iter().cloned());
    }
    exact_patterns.sort();
    exact_patterns.dedup();
    exact_patterns.truncate(32);
    let codecortex_request = CodeCortexRequest {
        project: request.project_id.to_string(),
        task: request.task_id.clone(),
        goal: request.goal.clone(),
        exact_patterns,
        max_files: 160,
        max_matches_per_pattern: 24,
        include_diagnostics: false,
    };
    let project_root = resolve_codecortex_repo_root(
        &state.root,
        task,
    )?;
    let service = CodeCortexService::new(project_root);
    if let Some(report) = latest_codecortex_report(&state.root)?
        && service.report_is_fresh(&report, &codecortex_request)?
    {
        return Ok(CodeCortexCompileBatch {
            reports: vec![report],
            pending_persistence: None,
        });
    }
    let report = service.scan(&codecortex_request)?;
    Ok(CodeCortexCompileBatch {
        reports: vec![report.clone()],
        pending_persistence: Some(report),
    })
}

fn persist_pending_codecortex_projection(
    state: &McpState,
    pending: &mut Option<CodeCortexReport>,
) -> Result<()> {
    let Some(report) = pending.as_ref() else {
        return Ok(());
    };
    if latest_codecortex_report(&state.root)?
        .is_some_and(|current| current.generated_at >= report.generated_at)
    {
        *pending = None;
        return Ok(());
    }
    atomic_write_json(&codecortex_latest_path(&state.root), &report)?;
    *pending = None;
    Ok(())
}

fn packet_task_root(state: &McpState, task_id: &str) -> PathBuf {
    state
        .root
        .join("reports")
        .join("context-packets")
        .join("tasks")
        .join(task_packet_key(task_id))
}

fn active_packet_authority_path(state: &McpState, task_id: &str) -> PathBuf {
    packet_task_root(state, task_id)
        .join("active")
        .join("authority.json")
}

fn active_packet_latest_path(state: &McpState, task_id: &str) -> PathBuf {
    packet_task_root(state, task_id)
        .join("active")
        .join("latest.json")
}

fn read_active_packet_authority(
    state: &McpState,
    task_id: &str,
) -> Result<Option<ActivePacketAuthority>> {
    let path = active_packet_authority_path(state, task_id);
    let file = match std::fs::File::open(&path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error)
                .with_context(|| format!("open active packet authority at {}", path.display()));
        }
    };
    let authority: ActivePacketAuthority = serde_json::from_reader(file)?;
    anyhow::ensure!(
        authority.schema_version == PACKET_ACTIVE_AUTHORITY_SCHEMA_VERSION,
        "unsupported active packet authority schema at {}",
        path.display()
    );
    anyhow::ensure!(
        canonical_struct_hash(&authority.response)? == authority.response_hash_blake3,
        "active packet authority response hash mismatch at {}",
        path.display()
    );
    let response_packet: ContextPacketL3 = serde_json::from_value(authority.response.clone())
        .with_context(|| {
            format!(
                "active packet authority response does not contain a ContextPacketL3 at {}",
                path.display()
            )
        })?;
    anyhow::ensure!(
        canonical_struct_hash(&response_packet)? == canonical_struct_hash(&authority.packet)?,
        "active packet authority packet/response mismatch at {}",
        path.display()
    );
    validate_packet_commit_material(&authority.material)?;
    anyhow::ensure!(
        task_id == authority.material.task_id
            && task_id == authority.packet.task_id
            && authority.packet.project_id == authority.material.project_id
            && authority.packet.task_id == authority.material.task_id
            && authority.packet.packet_id == authority.material.packet_id
            && authority.packet.at_revision == authority.material.at_revision,
        "active packet authority packet binding mismatch at {}",
        path.display()
    );
    anyhow::ensure!(
        packet_post_commit_operation_id(&authority.material)? == authority.operation_id,
        "active packet authority operation identity mismatch at {}",
        path.display()
    );
    Ok(Some(authority))
}

fn active_packet_fingerprint(state: &McpState, task_id: &str) -> Result<Option<String>> {
    if let Some(authority) = read_active_packet_authority(state, task_id)? {
        return Ok(Some(format!("authority:{}", authority.operation_id)));
    }
    let latest = active_packet_latest_path(state, task_id);
    if !latest.is_file() {
        return Ok(None);
    }
    // A legacy response projection has no canonical operation authority. Its
    // existence remains a fence, but its inspection bytes never become one.
    Ok(Some("legacy-latest:present".to_owned()))
}

async fn ensure_packet_commit_fence(
    state: &McpState,
    parsed_task_id: Option<TaskId>,
    task_id: &str,
    expected: &TaskPacketCommitFence,
) -> Result<()> {
    let current_task = if let Some(task_id) = parsed_task_id {
        state.store.task_contract_by_id(task_id).await?
    } else {
        None
    };
    let current_task_hash = canonical_struct_hash(&current_task)?;
    anyhow::ensure!(
        current_task_hash == expected.task_contract_hash,
        "PACKET_COMMIT_CONFLICT: TaskContract changed while the packet was compiled"
    );
    anyhow::ensure!(
        active_packet_fingerprint(state, task_id)? == expected.previous_active_fingerprint,
        "PACKET_COMMIT_CONFLICT: previous active packet changed while the packet was compiled"
    );
    Ok(())
}

fn codecortex_projection_hash(report: &CodeCortexReport) -> Result<String> {
    let mut value = serde_json::to_value(report)?;
    let object = value
        .as_object_mut()
        .context("CodeCortex projection must serialize as an object")?;
    for ephemeral_field in ["generated_at", "repo_root", "memory_receipt"] {
        object.remove(ephemeral_field);
    }
    canonical_struct_hash(&value)
}

fn packet_post_commit_effect_plan(material: &PacketCommitMaterial) -> Vec<PacketPostCommitEffect> {
    let mut effects = Vec::with_capacity(4);
    if material.codecortex_projection_hash.is_some() {
        effects.push(PacketPostCommitEffect::CodecortexProjection);
    }
    if !material.prediction_intents.is_empty() {
        effects.push(PacketPostCommitEffect::PredictionCapture);
    }
    if material.measurement.is_some() {
        effects.push(PacketPostCommitEffect::ExperimentMeasurement);
    }
    // The gate effect also deletes stale per-session state when the payload is
    // absent, so it is always part of the ordered effect plan.
    effects.push(PacketPostCommitEffect::GateProjection);
    effects
}

fn validate_packet_commit_material(material: &PacketCommitMaterial) -> Result<()> {
    anyhow::ensure!(
        material.operation_kind == PACKET_POST_COMMIT_OPERATION_KIND,
        "unsupported packet post-commit operation kind"
    );
    anyhow::ensure!(
        material.schema_version == PACKET_POST_COMMIT_SCHEMA_VERSION,
        "unsupported packet post-commit schema"
    );
    anyhow::ensure!(
        material.effects == packet_post_commit_effect_plan(material),
        "packet post-commit ordered effect plan mismatch"
    );
    Ok(())
}

fn packet_post_commit_operation_id(material: &PacketCommitMaterial) -> Result<String> {
    validate_packet_commit_material(material)?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(PACKET_POST_COMMIT_OPERATION_KIND.as_bytes());
    hasher.update(&[0]);
    hasher.update(PACKET_POST_COMMIT_SCHEMA_VERSION.as_bytes());
    hasher.update(&[0]);
    hasher.update(&serde_json::to_vec(material)?);
    Ok(hasher.finalize().to_hex().to_string())
}

fn packet_revision_archive_path(
    state: &McpState,
    task_id: &str,
    at_revision: MemoryRevision,
    operation_id: &str,
) -> PathBuf {
    packet_task_root(state, task_id)
        .join("active")
        .join("revisions")
        .join(format!("{}-{operation_id}.json", at_revision.value()))
}

/// Atomically advances the active authority pointer. `latest.json` and the
/// immutable revision archive are projections of that authority and can be
/// repaired by the bounded outbox replayer.
fn commit_active_context_packet(
    state: &McpState,
    intent: &PacketPostCommitIntent,
) -> Result<Vec<String>> {
    let packet = validate_packet_post_commit_intent(intent)?;
    let authority = ActivePacketAuthority {
        schema_version: PACKET_ACTIVE_AUTHORITY_SCHEMA_VERSION.to_owned(),
        operation_id: intent.operation_id.clone(),
        material: intent.material.clone(),
        packet: packet.clone(),
        response_hash_blake3: intent.response_hash_blake3.clone(),
        response: intent.response.clone(),
    };
    atomic_write_json_create_or_replace(
        &active_packet_authority_path(state, &packet.task_id),
        &authority,
    )?;
    let mut errors = Vec::new();
    if let Err(error) = atomic_write_json_create_or_replace(
        &active_packet_latest_path(state, &packet.task_id),
        &intent.response,
    ) {
        errors.push(format!("active_latest_projection: {error:#}"));
    }
    if let Err(error) = persist_immutable_json_path(
        &packet_revision_archive_path(
            state,
            &packet.task_id,
            packet.at_revision,
            &intent.operation_id,
        ),
        &intent.response,
    ) {
        errors.push(format!("active_revision_archive: {error:#}"));
    }
    Ok(errors)
}

fn packet_post_commit_outbox_path(state: &McpState, task_id: &str, operation_id: &str) -> PathBuf {
    packet_task_root(state, task_id)
        .join("outbox")
        .join(operation_id)
}

fn packet_post_commit_intent_path(outbox_root: &Path) -> PathBuf {
    outbox_root.join("intent.json")
}

fn packet_post_commit_events_root(outbox_root: &Path) -> PathBuf {
    outbox_root.join("events")
}

fn stage_packet_post_commit_outbox(
    state: &McpState,
    intent: &PacketPostCommitIntent,
) -> Result<(PathBuf, PacketPostCommitIntent, PacketPostCommitEvent)> {
    let outbox_root =
        packet_post_commit_outbox_path(state, &intent.material.task_id, &intent.operation_id);
    let (stored, current) = stage_packet_post_commit_outbox_at_root(&outbox_root, intent)?;
    Ok((outbox_root, stored, current))
}

fn stage_packet_post_commit_outbox_at_root(
    outbox_root: &Path,
    intent: &PacketPostCommitIntent,
) -> Result<(PacketPostCommitIntent, PacketPostCommitEvent)> {
    validate_packet_post_commit_intent(intent)?;
    let intent_path = packet_post_commit_intent_path(outbox_root);
    if !intent_path.is_file() {
        // A concurrent equivalent request may win immutable publication with
        // different provenance. Once a file exists, its validated canonical
        // material is authoritative and every caller drives that stored intent.
        if let Err(error) = persist_immutable_json_path(&intent_path, intent)
            && !intent_path.is_file()
        {
            return Err(error);
        }
    }
    let stored: PacketPostCommitIntent =
        serde_json::from_reader(std::fs::File::open(&intent_path)?)?;
    validate_packet_post_commit_intent(&stored)?;
    anyhow::ensure!(
        stored.operation_id == intent.operation_id
            && serde_json::to_vec(&stored.material)? == serde_json::to_vec(&intent.material)?,
        "PACKET_COMMIT_IDEMPOTENCY_MISMATCH: immutable packet intent differs at {}",
        intent_path.display()
    );
    let current = if let Some(current) = latest_packet_post_commit_event(outbox_root, &stored)? {
        current
    } else {
        append_packet_post_commit_event(
            outbox_root,
            &stored,
            PacketPostCommitStatus::Prepared,
            &[],
        )?
    };
    Ok((stored, current))
}

fn validate_packet_post_commit_intent(intent: &PacketPostCommitIntent) -> Result<ContextPacketL3> {
    validate_packet_commit_material(&intent.material)?;
    anyhow::ensure!(
        canonical_struct_hash(&intent.response)? == intent.response_hash_blake3,
        "packet post-commit response hash mismatch"
    );
    let packet: ContextPacketL3 = serde_json::from_value(intent.response.clone())
        .context("packet post-commit response does not contain a ContextPacketL3")?;
    anyhow::ensure!(
        packet.project_id == intent.material.project_id
            && packet.task_id == intent.material.task_id
            && packet.packet_id == intent.material.packet_id
            && packet.at_revision == intent.material.at_revision,
        "packet post-commit response does not match canonical packet material"
    );
    let codecortex_projection_hash = intent
        .codecortex_projection
        .as_ref()
        .map(codecortex_projection_hash)
        .transpose()?;
    anyhow::ensure!(
        codecortex_projection_hash == intent.material.codecortex_projection_hash,
        "packet post-commit CodeCortex projection hash mismatch"
    );
    anyhow::ensure!(
        packet_post_commit_operation_id(&intent.material)? == intent.operation_id,
        "packet post-commit operation identity mismatch"
    );
    Ok(packet)
}

fn latest_packet_post_commit_event(
    outbox_root: &Path,
    intent: &PacketPostCommitIntent,
) -> Result<Option<PacketPostCommitEvent>> {
    let events_root = packet_post_commit_events_root(outbox_root);
    if !events_root.is_dir() {
        return Ok(None);
    }
    let mut latest = None::<PacketPostCommitEvent>;
    for entry in std::fs::read_dir(events_root)? {
        let entry = entry?;
        if !entry.path().is_file()
            || entry.path().extension().and_then(|value| value.to_str()) != Some("json")
        {
            continue;
        }
        let event: PacketPostCommitEvent =
            serde_json::from_reader(std::fs::File::open(entry.path())?)?;
        anyhow::ensure!(
            event.schema_version == PACKET_POST_COMMIT_SCHEMA_VERSION
                && event.operation_id == intent.operation_id,
            "packet outbox event identity mismatch"
        );
        let replace = latest.as_ref().is_none_or(|current| {
            (
                event.sequence,
                event.recorded_at,
                event.event_id.to_string(),
            ) > (
                current.sequence,
                current.recorded_at,
                current.event_id.to_string(),
            )
        });
        if replace {
            latest = Some(event);
        }
    }
    Ok(latest)
}

fn append_packet_post_commit_event(
    outbox_root: &Path,
    intent: &PacketPostCommitIntent,
    status: PacketPostCommitStatus,
    errors: &[String],
) -> Result<PacketPostCommitEvent> {
    let sequence = latest_packet_post_commit_event(outbox_root, intent)?
        .map_or(0, |event| event.sequence.saturating_add(1));
    let event = PacketPostCommitEvent {
        schema_version: PACKET_POST_COMMIT_SCHEMA_VERSION.to_owned(),
        event_id: WriteId::new_v7(),
        operation_id: intent.operation_id.clone(),
        request_session_id: intent.provenance.request_session_id,
        sequence,
        status,
        errors: errors.to_vec(),
        recorded_at: time::OffsetDateTime::now_utc(),
    };
    persist_immutable_json_path(
        &packet_post_commit_events_root(outbox_root).join(format!("{}.json", event.event_id)),
        &event,
    )?;
    Ok(event)
}

fn transition_packet_post_commit_outbox(
    outbox_root: &Path,
    expected: &PacketPostCommitIntent,
    next_status: PacketPostCommitStatus,
    errors: &[String],
) -> Result<()> {
    let current_intent: PacketPostCommitIntent = serde_json::from_reader(std::fs::File::open(
        packet_post_commit_intent_path(outbox_root),
    )?)?;
    let current = latest_packet_post_commit_event(outbox_root, &current_intent)?
        .context("packet outbox has no prepared event")?;
    validate_packet_post_commit_intent(&current_intent)?;
    anyhow::ensure!(
        current_intent.operation_id == expected.operation_id
            && serde_json::to_vec(&current_intent.material)?
                == serde_json::to_vec(&expected.material)?,
        "PACKET_COMMIT_IDEMPOTENCY_MISMATCH: packet outbox transition differs at {}",
        outbox_root.display()
    );
    if current.status == PacketPostCommitStatus::Complete {
        return Ok(());
    }
    let allowed = matches!(
        (current.status, next_status),
        (
            PacketPostCommitStatus::Prepared | PacketPostCommitStatus::PendingRetry,
            PacketPostCommitStatus::CommittedPending
        ) | (
            PacketPostCommitStatus::CommittedPending,
            PacketPostCommitStatus::Complete | PacketPostCommitStatus::PendingRetry
        ) | (
            PacketPostCommitStatus::PendingRetry,
            PacketPostCommitStatus::PendingRetry
        )
    ) || current.status == next_status;
    anyhow::ensure!(allowed, "invalid packet outbox status transition");
    append_packet_post_commit_event(outbox_root, &current_intent, next_status, errors)?;
    Ok(())
}

fn finish_packet_post_commit_outbox(
    outbox_root: &Path,
    staged: &PacketPostCommitIntent,
    errors: &[String],
) -> Result<()> {
    transition_packet_post_commit_outbox(
        outbox_root,
        staged,
        if errors.is_empty() {
            PacketPostCommitStatus::Complete
        } else {
            PacketPostCommitStatus::PendingRetry
        },
        errors,
    )
}

fn packet_post_commit_intent_is_active(
    state: &McpState,
    intent: &PacketPostCommitIntent,
) -> Result<bool> {
    let Some(authority) = read_active_packet_authority(state, &intent.material.task_id)? else {
        return Ok(false);
    };
    Ok(packet_post_commit_authority_identity_matches(
        &authority.operation_id,
        authority.material.effect_session_id,
        &authority.packet.packet_id,
        intent,
    ))
}

fn packet_post_commit_authority_identity_matches(
    operation_id: &str,
    session_id: SessionId,
    packet_id: &str,
    intent: &PacketPostCommitIntent,
) -> bool {
    operation_id == intent.operation_id
        && session_id == intent.material.effect_session_id
        && packet_id == intent.material.packet_id
}

fn completed_packet_post_commit_replay_is_idempotent(
    status: PacketPostCommitStatus,
    active_authority_matches: bool,
    operation_id: &str,
) -> Result<bool> {
    if status != PacketPostCommitStatus::Complete {
        return Ok(false);
    }
    anyhow::ensure!(
        active_authority_matches,
        "PACKET_POST_COMMIT_SUPERSEDED: completed operation {operation_id} is no longer the active packet authority"
    );
    Ok(true)
}

fn ensure_packet_post_commit_intent_is_active(
    state: &McpState,
    intent: &PacketPostCommitIntent,
) -> Result<()> {
    anyhow::ensure!(
        packet_post_commit_intent_is_active(state, intent)?,
        "PACKET_POST_COMMIT_SUPERSEDED: operation {} is no longer the active packet authority",
        intent.operation_id
    );
    Ok(())
}

async fn apply_packet_post_commit_intent(
    state: &McpState,
    intent: &PacketPostCommitIntent,
) -> Vec<String> {
    let mut errors = Vec::new();
    let parsed_task_id = TaskId::from_str(&intent.material.task_id).ok();
    for effect in &intent.material.effects {
        match effect {
            PacketPostCommitEffect::CodecortexProjection => {
                if let Some(report) = intent.codecortex_projection.as_ref() {
                    let mut pending = Some(report.clone());
                    if let Err(error) = persist_pending_codecortex_projection(state, &mut pending) {
                        errors.push(format!("codecortex_projection: {error:#}"));
                    }
                } else {
                    errors.push("codecortex_projection: canonical payload is absent".to_owned());
                }
            }
            PacketPostCommitEffect::PredictionCapture => {
                if let Some(task_id) = parsed_task_id {
                    for prediction in &intent.material.prediction_intents {
                        if let Err(error) = state
                            .ul
                            .prediction
                            .capture_packet_intent(
                                intent.material.project_id,
                                task_id,
                                intent.material.effect_session_id,
                                &intent.material.packet_id,
                                prediction,
                            )
                            .await
                        {
                            errors.push(format!(
                                "prediction_projection {}: {error}",
                                prediction.prediction_ref
                            ));
                        }
                    }
                } else {
                    errors.push("prediction_projection: task_id is not canonical".to_owned());
                }
            }
            PacketPostCommitEffect::ExperimentMeasurement => {
                if let Some(assignment) = intent.material.measurement.as_ref() {
                    match state
                        .store
                        .upsert_ul_experiment_assignment_explicit(
                            assignment.project_id,
                            assignment.task_id,
                            &assignment.task_class,
                            assignment.arm,
                            assignment.injection_mode,
                            &assignment.config_hash,
                        )
                        .await
                    {
                        Ok(persisted) if persisted == *assignment => {}
                        Ok(persisted) => errors.push(format!(
                            "experiment_measurement: explicit assignment mismatch: expected={assignment:?}, persisted={persisted:?}"
                        )),
                        Err(error) => {
                            errors.push(format!("experiment_measurement: {error}"));
                        }
                    }
                } else {
                    errors.push("experiment_measurement: canonical payload is absent".to_owned());
                }
            }
            PacketPostCommitEffect::GateProjection => {
                if let Err(error) = state.ul.record_packet_gate(
                    intent.material.project_id,
                    intent.material.effect_session_id,
                    parsed_task_id,
                    intent.material.gate_projection.as_ref(),
                ) {
                    errors.push(format!("gate_projection: {error:#}"));
                }
            }
        }
    }
    errors
}

fn repair_active_packet_projections(
    state: &McpState,
    intent: &PacketPostCommitIntent,
) -> Vec<String> {
    let mut errors = Vec::new();
    if let Err(error) = atomic_write_json_create_or_replace(
        &active_packet_latest_path(state, &intent.material.task_id),
        &intent.response,
    ) {
        errors.push(format!("active_latest_projection: {error:#}"));
    }
    if let Err(error) = persist_immutable_json_path(
        &packet_revision_archive_path(
            state,
            &intent.material.task_id,
            intent.material.at_revision,
            &intent.operation_id,
        ),
        &intent.response,
    ) {
        errors.push(format!("active_revision_archive: {error:#}"));
    }
    errors
}

struct PendingPacketPostCommitOutbox {
    outbox_root: PathBuf,
    intent: PacketPostCommitIntent,
    status: PacketPostCommitStatus,
    errors: Vec<String>,
}

fn pending_packet_post_commit_outbox(
    state: &McpState,
    task_id: &str,
) -> Result<Option<PendingPacketPostCommitOutbox>> {
    let Some(authority) = read_active_packet_authority(state, task_id)? else {
        return Ok(None);
    };
    let outbox_root = packet_post_commit_outbox_path(state, task_id, &authority.operation_id);
    let intent_path = packet_post_commit_intent_path(&outbox_root);
    let intent: PacketPostCommitIntent = serde_json::from_reader(
        std::fs::File::open(&intent_path).with_context(|| {
            format!(
                "open active packet outbox intent for {task_id} at {}",
                intent_path.display()
            )
        })?,
    )?;
    validate_packet_post_commit_intent(&intent)?;
    let current = latest_packet_post_commit_event(&outbox_root, &intent)?.with_context(|| {
        format!(
            "active packet outbox for {task_id} has no durable state event at {}",
            outbox_root.display()
        )
    })?;
    anyhow::ensure!(
        packet_post_commit_authority_identity_matches(
            &authority.operation_id,
            authority.material.effect_session_id,
            &authority.material.packet_id,
            &intent,
        ),
        "active packet authority/outbox identity mismatch for {task_id} at {}",
        outbox_root.display()
    );
    if current.status == PacketPostCommitStatus::Complete {
        return Ok(None);
    }
    Ok(Some(PendingPacketPostCommitOutbox {
        outbox_root,
        intent,
        status: current.status,
        errors: current.errors,
    }))
}

async fn replay_packet_post_commit_outbox_for_task(
    state: &McpState,
    task_id: &str,
    require_completion: bool,
) -> Result<bool> {
    let Some(PendingPacketPostCommitOutbox {
        outbox_root,
        intent,
        status,
        errors: _,
    }) = pending_packet_post_commit_outbox(state, task_id)?
    else {
        return Ok(false);
    };
    if status != PacketPostCommitStatus::CommittedPending {
        transition_packet_post_commit_outbox(
            &outbox_root,
            &intent,
            PacketPostCommitStatus::CommittedPending,
            &[],
        )?;
    }
    ensure_packet_post_commit_intent_is_active(state, &intent)?;
    let mut errors = repair_active_packet_projections(state, &intent);
    errors.extend(apply_packet_post_commit_intent(state, &intent).await);
    finish_packet_post_commit_outbox(&outbox_root, &intent, &errors)?;
    if require_completion && !errors.is_empty() {
        anyhow::bail!(
            "PACKET_POST_COMMIT_REPLAY_PENDING: active operation {} remains incomplete: {}",
            intent.operation_id,
            errors.join("; ")
        );
    }
    Ok(true)
}

async fn replay_packet_post_commit_outbox_with_transition_lock(
    state: &McpState,
    task_handle: &str,
    parsed_task_id: Option<TaskId>,
    require_completion: bool,
) -> Result<bool> {
    if let Some(task_id) = parsed_task_id {
        let task_commit_guard = task_commit_serializer().lock().await;
        let task_process_guard = acquire_task_transition_process_lock(&state.root, task_id).await?;
        drop(task_commit_guard);
        let replay_result =
            replay_packet_post_commit_outbox_for_task(state, task_handle, require_completion).await;
        drop(task_process_guard);
        replay_result
    } else {
        // Legacy non-canonical task handles remain local-only. Do not invent a
        // TaskId merely to participate in the canonical process-lock domain.
        replay_packet_post_commit_outbox_for_task(state, task_handle, require_completion).await
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PacketPostCommitRecoveryEntry {
    directory_name: String,
    authority_path: PathBuf,
}

#[derive(Debug, Default, Eq, PartialEq)]
struct PacketPostCommitRecoveryReport {
    inspected: usize,
    attempted: usize,
    replayed: usize,
    residual_pending: usize,
    error_count: usize,
    error_samples: Vec<String>,
    residual_samples: Vec<String>,
}

impl PacketPostCommitRecoveryReport {
    fn claim_replay_slot(&mut self) -> bool {
        if self.attempted >= PACKET_OUTBOX_REPLAY_LIMIT {
            return false;
        }
        self.attempted = self.attempted.saturating_add(1);
        true
    }

    fn record_error(&mut self, error: impl Into<String>) {
        self.error_count = self.error_count.saturating_add(1);
        if self.error_samples.len() < PACKET_OUTBOX_RECOVERY_ERROR_SAMPLE_LIMIT {
            self.error_samples.push(error.into());
        }
    }

    fn record_residual(
        &mut self,
        task_handle: &str,
        pending: &PendingPacketPostCommitOutbox,
    ) {
        self.residual_pending = self.residual_pending.saturating_add(1);
        if self.residual_samples.len() < PACKET_OUTBOX_RECOVERY_ERROR_SAMPLE_LIMIT {
            self.residual_samples.push(format!(
                "{task_handle}: status={:?}, errors={:?}",
                pending.status, pending.errors
            ));
        }
    }

    fn requires_attention(&self) -> bool {
        self.residual_pending > 0 || self.error_count > 0
    }
}

fn packet_post_commit_recovery_inventory(
    tasks_root: &Path,
    report: &mut PacketPostCommitRecoveryReport,
) -> Vec<PacketPostCommitRecoveryEntry> {
    match std::fs::metadata(tasks_root) {
        Ok(metadata) if metadata.is_dir() => {}
        Ok(_) => {
            report.record_error(format!(
                "packet recovery inventory root is not a directory: {}",
                tasks_root.display()
            ));
            return Vec::new();
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Vec::new(),
        Err(error) => {
            report.record_error(format!(
                "inspect packet recovery inventory root at {}: {error}",
                tasks_root.display()
            ));
            return Vec::new();
        }
    }
    let entries = match std::fs::read_dir(tasks_root) {
        Ok(entries) => entries,
        Err(error) => {
            report.record_error(format!(
                "read packet recovery inventory at {}: {error}",
                tasks_root.display()
            ));
            return Vec::new();
        }
    };
    let mut inventory = Vec::new();
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => {
                report.record_error(format!(
                    "read packet recovery inventory entry at {}: {error}",
                    tasks_root.display()
                ));
                continue;
            }
        };
        let file_type = match entry.file_type() {
            Ok(file_type) => file_type,
            Err(error) => {
                report.record_error(format!(
                    "read packet recovery entry type at {}: {error}",
                    entry.path().display()
                ));
                continue;
            }
        };
        if !file_type.is_dir() {
            continue;
        }
        let directory_name = match entry.file_name().into_string() {
            Ok(directory_name) => directory_name,
            Err(name) => {
                report.record_error(format!(
                    "packet recovery directory name is not Unicode: {}",
                    name.to_string_lossy()
                ));
                continue;
            }
        };
        let authority_path = entry.path().join("active").join("authority.json");
        match std::fs::metadata(&authority_path) {
            Ok(metadata) if metadata.is_file() => {
                inventory.push(PacketPostCommitRecoveryEntry {
                    directory_name,
                    authority_path,
                });
            }
            Ok(_) => report.record_error(format!(
                "packet recovery authority is not a file: {}",
                authority_path.display()
            )),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => report.record_error(format!(
                "inspect packet recovery authority at {}: {error}",
                authority_path.display()
            )),
        }
    }
    inventory.sort_by(|left, right| left.directory_name.cmp(&right.directory_name));
    inventory
}

fn validate_packet_recovery_directory_key(
    directory_name: &str,
    task_handle: &str,
) -> Result<()> {
    let expected = task_packet_key(task_handle);
    anyhow::ensure!(
        directory_name == expected,
        "packet recovery authority directory mismatch: expected {expected}, observed {directory_name}"
    );
    Ok(())
}

fn packet_recovery_task_handle(entry: &PacketPostCommitRecoveryEntry) -> Result<String> {
    let authority: ActivePacketAuthority =
        serde_json::from_reader(std::fs::File::open(&entry.authority_path)?)?;
    let task_handle = authority.material.task_id;
    validate_packet_recovery_directory_key(&entry.directory_name, &task_handle)?;
    Ok(task_handle)
}

async fn recover_packet_post_commit_outboxes(
    state: &McpState,
) -> PacketPostCommitRecoveryReport {
    let tasks_root = state
        .root
        .join("reports")
        .join("context-packets")
        .join("tasks");
    let mut report = PacketPostCommitRecoveryReport::default();
    let inventory = packet_post_commit_recovery_inventory(&tasks_root, &mut report);
    for entry in inventory {
        report.inspected = report.inspected.saturating_add(1);
        let task_handle = match packet_recovery_task_handle(&entry) {
            Ok(task_handle) => task_handle,
            Err(error) => {
                report.record_error(format!(
                    "inspect packet recovery authority at {}: {error:#}",
                    entry.authority_path.display()
                ));
                continue;
            }
        };
        let packet_serializer = packet_task_serializer(&task_handle);
        let _packet_guard = packet_serializer.lock().await;
        let pending = match pending_packet_post_commit_outbox(state, &task_handle) {
            Ok(Some(pending)) => pending,
            Ok(None) => continue,
            Err(error) => {
                report.residual_pending = report.residual_pending.saturating_add(1);
                report.record_error(format!(
                    "inspect active packet outbox for {task_handle}: {error:#}"
                ));
                continue;
            }
        };
        if !report.claim_replay_slot() {
            report.record_residual(&task_handle, &pending);
            continue;
        }
        match replay_packet_post_commit_outbox_with_transition_lock(
            state,
            &task_handle,
            TaskId::from_str(&task_handle).ok(),
            false,
        )
        .await
        {
            Ok(true) => {
                report.replayed = report.replayed.saturating_add(1);
                match pending_packet_post_commit_outbox(state, &task_handle) {
                    Ok(Some(pending)) => report.record_residual(&task_handle, &pending),
                    Ok(None) => {}
                    Err(error) => {
                        report.residual_pending = report.residual_pending.saturating_add(1);
                        report.record_error(format!(
                            "inspect replayed packet outbox for {task_handle}: {error:#}"
                        ));
                    }
                }
            }
            Ok(false) => {}
            Err(error) => {
                report.record_residual(&task_handle, &pending);
                report.record_error(format!(
                    "replay packet outbox for {task_handle}: {error:#}"
                ));
            }
        }
    }
    report
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod packet_commit_unit_tests {
    use super::*;

    #[test]
    fn codecortex_root_resolution_fails_closed_for_non_git_launch_root() {
        let launch_root = std::env::temp_dir().join(format!(
            "eliot-codecortex-non-git-{}",
            WriteId::new_v7()
        ));
        std::fs::create_dir_all(&launch_root).expect("create non-git launch root");
        let result = resolve_codecortex_repo_root_from_sources(Some(&launch_root), None);
        std::fs::remove_dir_all(&launch_root).expect("remove non-git launch root");
        let error = result.expect_err("non-git launch root must not be CodeCortex source truth");
        assert!(error.to_string().contains("Cargo checkout"));
    }

    #[test]
    fn codecortex_root_resolution_ignores_stale_report_projections() {
        let runtime_root = std::env::temp_dir().join(format!(
            "eliot-codecortex-report-projection-{}",
            WriteId::new_v7()
        ));
        let redirect_root = runtime_root.join("forged-repo-root");
        std::fs::create_dir_all(runtime_root.join("reports/action-lease"))
            .expect("create action lease report directory");
        std::fs::create_dir_all(runtime_root.join("reports/work"))
            .expect("create work report directory");
        std::fs::write(
            runtime_root.join("reports/action-lease/latest.json"),
            serde_json::json!({
                "record": {"lease": {"allowed_scope": {"repo_root": redirect_root}}
                }
            })
            .to_string(),
        )
        .expect("write forged action lease report");
        std::fs::write(
            runtime_root.join("reports/work/state.json"),
            serde_json::json!({"leases": [{"scope": {"repo_root": redirect_root}}]}).to_string(),
        )
        .expect("write forged work report");

        let result = resolve_codecortex_repo_root(&runtime_root, None);
        std::fs::remove_dir_all(&runtime_root).expect("remove forged report projection");
        let error = result.expect_err("report projections must not supply CodeCortex root");
        assert!(error
            .to_string()
            .contains("governed scope or ELIOT_GOVERNOR_REPO_ROOT"));
    }

    #[test]
    fn codecortex_root_resolution_uses_configured_governor_root_fallback() {
        let repo_root = std::fs::canonicalize(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../.."),
        )
        .expect("canonical project root");
        let resolved = resolve_codecortex_repo_root_from_sources(None, Some(&repo_root))
            .expect("configured Governor root must resolve");
        assert_eq!(resolved, repo_root);
    }

    #[test]
    fn codecortex_root_resolution_fails_closed_without_trusted_source() {
        let error = resolve_codecortex_repo_root_from_sources(None, None)
            .expect_err("missing governed root must fail closed");
        assert!(error
            .to_string()
            .contains("governed scope or ELIOT_GOVERNOR_REPO_ROOT"));
    }

    fn packet_response(
        project_id: ProjectId,
        task_id: TaskId,
        packet_id: &str,
        at_revision: MemoryRevision,
        additions: Value,
    ) -> Value {
        let mut response = json!({
            "packet_id": packet_id,
            "project_id": project_id,
            "task_id": task_id,
            "goal": "unit packet commit",
            "at_revision": at_revision,
            "current_truth": [],
            "relevant_verified_claims": [],
            "relevant_supported_claims": [],
            "weak_claims_warning": [],
            "negative_memory": [],
            "recent_failures": [],
            "known_decisions": [],
            "open_questions": [],
            "exact_handles": [],
            "source_receipts": [],
            "token_budget_report": {
                "max_tokens": 512,
                "estimated_tokens": 64,
                "truncated": false,
                "sections_truncated": []
            },
            "truncation": {
                "truncated": false,
                "limit": 512,
                "returned": 1
            }
        });
        if let (Value::Object(response), Value::Object(additions)) = (&mut response, additions) {
            response.extend(additions);
        }
        response["packet_id"] = json!(packet_id);
        response["project_id"] = json!(project_id);
        response["task_id"] = json!(task_id);
        response["at_revision"] = json!(at_revision);
        response
    }

    fn outbox_intent(session_id: SessionId, additions: Value) -> PacketPostCommitIntent {
        let project_id = ProjectId::new_v7();
        let task_id = TaskId::new_v7();
        let packet_id = "eliot/packet/unit";
        let at_revision = MemoryRevision::new(7);
        let response = packet_response(project_id, task_id, packet_id, at_revision, additions);
        let response_hash_blake3 = canonical_struct_hash(&response).expect("hash response");
        let mut material = PacketCommitMaterial {
            operation_kind: PACKET_POST_COMMIT_OPERATION_KIND.to_owned(),
            schema_version: PACKET_POST_COMMIT_SCHEMA_VERSION.to_owned(),
            project_id,
            task_id: task_id.to_string(),
            effect_session_id: session_id,
            packet_id: packet_id.to_owned(),
            at_revision,
            codecortex_projection_hash: None,
            prediction_intents: Vec::new(),
            measurement: None,
            gate_projection: None,
            effects: Vec::new(),
        };
        material.effects = packet_post_commit_effect_plan(&material);
        PacketPostCommitIntent {
            operation_id: packet_post_commit_operation_id(&material).expect("hash material"),
            material,
            provenance: PacketCommitProvenance {
                request_session_id: session_id,
                prepared_at: time::OffsetDateTime::UNIX_EPOCH,
            },
            response_hash_blake3,
            response,
            codecortex_projection: None,
        }
    }

    fn refresh_operation_id(intent: &mut PacketPostCommitIntent) {
        intent.material.effects = packet_post_commit_effect_plan(&intent.material);
        intent.operation_id =
            packet_post_commit_operation_id(&intent.material).expect("hash material");
    }

    fn prediction_intent() -> eliot_engine::PacketPredictionIntent {
        eliot_engine::PacketPredictionIntent {
            prediction_ref: "prediction/unit".to_owned(),
            prediction: eliot_types::UlPrediction::VerifierVerdict {
                verifier: "cargo test -p eliot-app packet_commit_unit_tests".to_owned(),
                expected: eliot_types::PredictionExpectation::Pass,
            },
            confidence: Some(eliot_types::PredictionConfidence::High),
            subsystem_concept_id: Some("concept/packet-commit".to_owned()),
            source_frame_hash: "frame-hash".to_owned(),
        }
    }

    fn measurement(material: &PacketCommitMaterial) -> eliot_types::UlTaskExperimentAssignment {
        eliot_types::UlTaskExperimentAssignment {
            project_id: material.project_id,
            task_id: TaskId::from_str(&material.task_id).expect("canonical task id"),
            task_class: eliot_types::UlTaskClass {
                action_class: "compile".to_owned(),
                subsystem: "packet-commit".to_owned(),
                artifact_class: "context-packet".to_owned(),
            },
            ordinal: 0,
            arm: eliot_types::UlExperimentArm::Treatment,
            injection_mode: eliot_types::UlInjectionMode::Payload,
            config_hash: "config-hash".to_owned(),
        }
    }

    fn codecortex_report(generated_at: time::OffsetDateTime) -> CodeCortexReport {
        CodeCortexReport {
            project: "eliot-memory-os".to_owned(),
            task: "packet-commit".to_owned(),
            goal: "bind the post-commit intent".to_owned(),
            generated_at,
            repo_root: "C:/repo".to_owned(),
            git_head: Some("deadbeef".to_owned()),
            dirty: false,
            scope_binding: eliot_types::CodeCortexScopeBinding::default(),
            tracked_files: Vec::new(),
            workspace_members: Vec::new(),
            crates: vec!["eliot-app".to_owned()],
            targets: Vec::new(),
            file_evidence: Vec::new(),
            symbol_evidence: Vec::new(),
            diagnostic_evidence: Vec::new(),
            verifier_evidence: Vec::new(),
            blast_radius: eliot_types::BlastRadiusView {
                files: Vec::new(),
                crates: vec!["eliot-app".to_owned()],
                reasons: vec!["unit fixture".to_owned()],
            },
            invariant_cards: Vec::new(),
            evidence_sources: Vec::new(),
            adapter_notes: Vec::new(),
            memory_receipt: None,
            operation_status: OperationStatus::OperationCompleted,
        }
    }

    #[test]
    fn packet_operation_identity_binds_effect_session_but_not_provenance() {
        let original = outbox_intent(SessionId::new_v7(), json!({"packet": "same"}));
        let mut effect_session_changed = original.clone();
        effect_session_changed.material.effect_session_id = SessionId::new_v7();
        refresh_operation_id(&mut effect_session_changed);
        assert_ne!(original.operation_id, effect_session_changed.operation_id);

        let mut provenance_changed = original.clone();
        provenance_changed.provenance.request_session_id = SessionId::new_v7();
        provenance_changed.provenance.prepared_at =
            time::OffsetDateTime::UNIX_EPOCH + time::Duration::seconds(1);
        assert_eq!(original.operation_id, provenance_changed.operation_id);
        validate_packet_post_commit_intent(&provenance_changed)
            .expect("provenance is outside canonical identity");

        let mut response_changed = original.clone();
        response_changed.response["inspection_only"] = json!("different bytes");
        response_changed.response_hash_blake3 =
            canonical_struct_hash(&response_changed.response).expect("hash changed response");
        assert_ne!(
            original.response_hash_blake3,
            response_changed.response_hash_blake3
        );
        assert_eq!(original.operation_id, response_changed.operation_id);
        validate_packet_post_commit_intent(&response_changed)
            .expect("response inspection bytes are outside canonical identity");
    }

    #[test]
    fn codecortex_identity_excludes_ephemera_but_binds_semantics() {
        let report = codecortex_report(time::OffsetDateTime::UNIX_EPOCH);
        let report_hash = codecortex_projection_hash(&report).expect("hash CodeCortex report");
        let mut original = outbox_intent(SessionId::new_v7(), json!({}));
        original.material.codecortex_projection_hash = Some(report_hash.clone());
        original.codecortex_projection = Some(report.clone());
        refresh_operation_id(&mut original);

        let mut ephemeral = report.clone();
        ephemeral.generated_at = time::OffsetDateTime::UNIX_EPOCH + time::Duration::seconds(30);
        ephemeral.repo_root = "D:/different-checkout".to_owned();
        ephemeral.memory_receipt = Some(WriteReceiptRef {
            receipt_id: ReceiptId::new_v7(),
            write_id: WriteId::new_v7(),
        });
        assert_eq!(
            codecortex_projection_hash(&ephemeral).expect("hash ephemeral variant"),
            report_hash
        );
        let mut ephemeral_intent = original.clone();
        ephemeral_intent.codecortex_projection = Some(ephemeral);
        assert_eq!(ephemeral_intent.operation_id, original.operation_id);
        validate_packet_post_commit_intent(&ephemeral_intent)
            .expect("all prohibited CodeCortex ephemera are outside identity");

        let mut semantic = report;
        semantic.scope_binding.dirty_state_hash = "semantic-change".to_owned();
        let semantic_hash = codecortex_projection_hash(&semantic).expect("hash semantic variant");
        assert_ne!(semantic_hash, report_hash);
        let mut semantic_intent = original.clone();
        semantic_intent.material.codecortex_projection_hash = Some(semantic_hash);
        semantic_intent.codecortex_projection = Some(semantic);
        refresh_operation_id(&mut semantic_intent);
        assert_ne!(semantic_intent.operation_id, original.operation_id);
        validate_packet_post_commit_intent(&semantic_intent)
            .expect("semantic CodeCortex content remains bound");
    }

    #[test]
    fn packet_operation_identity_binds_every_effect_material_class() {
        let original = outbox_intent(SessionId::new_v7(), json!({"packet": "same"}));

        let mut codecortex = original.clone();
        codecortex.material.codecortex_projection_hash = Some("codecortex-hash".to_owned());
        refresh_operation_id(&mut codecortex);

        let mut prediction = original.clone();
        prediction
            .material
            .prediction_intents
            .push(prediction_intent());
        refresh_operation_id(&mut prediction);

        let mut experiment = original.clone();
        experiment.material.measurement = Some(measurement(&experiment.material));
        refresh_operation_id(&mut experiment);

        let mut gate = original.clone();
        gate.material.gate_projection = Some(json!({"status": "allowed"}));
        refresh_operation_id(&mut gate);

        for changed in [&codecortex, &prediction, &experiment, &gate] {
            assert_ne!(original.operation_id, changed.operation_id);
        }
    }

    #[test]
    fn packet_material_contains_no_provenance_ephemera() {
        let intent = outbox_intent(SessionId::new_v7(), json!({"packet": "same"}));
        let keys = serde_json::to_value(&intent.material)
            .expect("serialize material")
            .as_object()
            .expect("material object")
            .keys()
            .cloned()
            .collect::<BTreeSet<_>>();
        assert_eq!(
            keys,
            BTreeSet::from([
                "at_revision".to_owned(),
                "codecortex_projection_hash".to_owned(),
                "effect_session_id".to_owned(),
                "effects".to_owned(),
                "gate_projection".to_owned(),
                "measurement".to_owned(),
                "operation_kind".to_owned(),
                "packet_id".to_owned(),
                "prediction_intents".to_owned(),
                "project_id".to_owned(),
                "schema_version".to_owned(),
                "task_id".to_owned(),
            ])
        );
        assert!(!keys.contains("response_hash_blake3"));
        assert!(!keys.contains("request_session_id"));
        assert!(!keys.contains("prepared_at"));
        assert!(!keys.contains("generated_at"));
    }

    #[test]
    fn packet_effect_plan_is_ordered_and_validated() {
        let mut intent = outbox_intent(SessionId::new_v7(), json!({"packet": "same"}));
        intent.material.codecortex_projection_hash = Some("codecortex-hash".to_owned());
        intent.material.prediction_intents.push(prediction_intent());
        intent.material.measurement = Some(measurement(&intent.material));
        refresh_operation_id(&mut intent);
        assert_eq!(
            intent.material.effects,
            vec![
                PacketPostCommitEffect::CodecortexProjection,
                PacketPostCommitEffect::PredictionCapture,
                PacketPostCommitEffect::ExperimentMeasurement,
                PacketPostCommitEffect::GateProjection,
            ]
        );
        intent.material.effects.swap(0, 1);
        assert!(validate_packet_commit_material(&intent.material).is_err());
        assert!(packet_post_commit_operation_id(&intent.material).is_err());
    }

    #[test]
    fn packet_active_identity_guard_rejects_superseded_intent() {
        let stale = outbox_intent(SessionId::new_v7(), json!({"packet": "stale"}));
        let replacement = outbox_intent(SessionId::new_v7(), json!({"packet": "replacement"}));
        assert!(packet_post_commit_authority_identity_matches(
            &stale.operation_id,
            stale.material.effect_session_id,
            &stale.material.packet_id,
            &stale,
        ));
        assert!(!packet_post_commit_authority_identity_matches(
            &replacement.operation_id,
            replacement.material.effect_session_id,
            &replacement.material.packet_id,
            &stale,
        ));
    }

    #[test]
    fn completed_packet_cannot_reactivate_after_a_new_authority_supersedes_it() {
        assert!(
            completed_packet_post_commit_replay_is_idempotent(
                PacketPostCommitStatus::Complete,
                true,
                "operation-a",
            )
            .expect("the still-active terminal operation is an exact no-op")
        );
        let superseded = completed_packet_post_commit_replay_is_idempotent(
            PacketPostCommitStatus::Complete,
            false,
            "operation-a",
        )
        .expect_err("completed A must not reactivate after B becomes active");
        assert!(
            format!("{superseded:#}").contains("PACKET_POST_COMMIT_SUPERSEDED"),
            "unexpected terminal replay error: {superseded:#}"
        );
        assert!(
            !completed_packet_post_commit_replay_is_idempotent(
                PacketPostCommitStatus::PendingRetry,
                false,
                "operation-a",
            )
            .expect("nonterminal operations continue through commit")
        );
    }

    #[test]
    fn immutable_packet_publication_never_clobbers_concurrent_winner() {
        let fixture_root =
            std::env::temp_dir().join(format!("eliot-packet-immutable-race-{}", WriteId::new_v7()));
        let destination = fixture_root.join("winner.json");
        let barrier = Arc::new(std::sync::Barrier::new(3));
        let handles = [b"first-writer".to_vec(), b"second-writer".to_vec()].map(|bytes| {
            let destination = destination.clone();
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                barrier.wait();
                let result = persist_immutable_bytes(&destination, &bytes);
                (bytes, result)
            })
        });
        barrier.wait();
        let outcomes = handles.map(|handle| handle.join().expect("immutable writer joined"));
        let winner = outcomes
            .iter()
            .find_map(|(bytes, result)| result.is_ok().then_some(bytes.clone()))
            .expect("one immutable writer must publish");
        let loser = outcomes
            .iter()
            .find_map(|(bytes, result)| result.is_err().then_some(bytes.clone()))
            .expect("distinct concurrent bytes must collide");
        assert_eq!(
            outcomes.iter().filter(|(_, result)| result.is_ok()).count(),
            1
        );
        assert_eq!(std::fs::read(&destination).expect("read winner"), winner);
        assert!(persist_immutable_bytes(&destination, &loser).is_err());
        assert_eq!(
            std::fs::read(&destination).expect("reread immutable winner"),
            winner
        );
        assert!(
            std::fs::read_dir(&fixture_root)
                .expect("read immutable fixture")
                .all(|entry| !entry
                    .expect("read fixture entry")
                    .file_name()
                    .to_string_lossy()
                    .ends_with(".tmp")),
            "immutable publication must remove every temporary file"
        );
        std::fs::remove_dir_all(fixture_root).expect("remove immutable fixture");
    }

    #[test]
    fn packet_outbox_replay_drives_the_original_stored_intent() {
        let mut original = outbox_intent(SessionId::new_v7(), json!({"packet": "unit"}));
        let original_report = codecortex_report(time::OffsetDateTime::UNIX_EPOCH);
        original.material.codecortex_projection_hash =
            Some(codecortex_projection_hash(&original_report).expect("hash CodeCortex projection"));
        original.codecortex_projection = Some(original_report);
        refresh_operation_id(&mut original);

        let mut replay = original.clone();
        replay.provenance.request_session_id = SessionId::new_v7();
        replay.provenance.prepared_at =
            time::OffsetDateTime::UNIX_EPOCH + time::Duration::seconds(1);
        replay
            .codecortex_projection
            .as_mut()
            .expect("CodeCortex projection")
            .generated_at = time::OffsetDateTime::UNIX_EPOCH + time::Duration::seconds(2);
        replay.response["inspection_only"] = json!({"request": "later"});
        replay.response_hash_blake3 =
            canonical_struct_hash(&replay.response).expect("hash replay response");
        assert_ne!(original.response_hash_blake3, replay.response_hash_blake3);
        assert_eq!(original.operation_id, replay.operation_id);
        validate_packet_post_commit_intent(&replay)
            .expect("response inspection bytes and CodeCortex ephemera are outside identity");

        let outbox_root =
            std::env::temp_dir().join(format!("eliot-packet-stored-{}", WriteId::new_v7()));
        let (first_stored, first_event) =
            stage_packet_post_commit_outbox_at_root(&outbox_root, &original)
                .expect("stage original intent");
        let (replay_stored, replay_event) =
            stage_packet_post_commit_outbox_at_root(&outbox_root, &replay)
                .expect("stage equivalent replay");

        assert_eq!(first_event.sequence, 0);
        assert_eq!(replay_event.sequence, 0);
        assert_eq!(
            serde_json::to_value(&first_stored).expect("serialize first stored intent"),
            serde_json::to_value(&original).expect("serialize original intent")
        );
        assert_eq!(
            serde_json::to_value(&replay_stored).expect("serialize replay stored intent"),
            serde_json::to_value(&original).expect("serialize original intent")
        );
        assert_eq!(
            replay_event.request_session_id,
            original.provenance.request_session_id
        );
        assert_eq!(
            std::fs::read_dir(packet_post_commit_events_root(&outbox_root))
                .expect("read outbox events")
                .count(),
            1,
            "exact replay must not append a second prepared event"
        );
        std::fs::remove_dir_all(outbox_root).expect("remove stored-intent fixture");
    }

    #[test]
    fn packet_response_integrity_corruption_is_rejected() {
        let mut intent = outbox_intent(SessionId::new_v7(), json!({}));
        intent.response["goal"] = json!("corrupted after hashing");
        let error = validate_packet_post_commit_intent(&intent)
            .expect_err("response bytes must match the stored inspection hash");
        assert!(
            format!("{error:#}").contains("packet post-commit response hash mismatch"),
            "unexpected response integrity error: {error:#}"
        );

        let mut rebound = outbox_intent(SessionId::new_v7(), json!({}));
        rebound.response["packet_id"] = json!("eliot/packet/different");
        rebound.response_hash_blake3 =
            canonical_struct_hash(&rebound.response).expect("rehash rebound response");
        let error = validate_packet_post_commit_intent(&rebound)
            .expect_err("a hash-valid response must still bind canonical packet material");
        assert!(
            format!("{error:#}")
                .contains("packet post-commit response does not match canonical packet material"),
            "unexpected packet binding error: {error:#}"
        );
    }

    #[test]
    fn packet_outbox_enforces_ordered_terminal_transition() {
        let intent = outbox_intent(SessionId::new_v7(), json!({"packet": "unit"}));
        let outbox_root =
            std::env::temp_dir().join(format!("eliot-packet-outbox-{}", WriteId::new_v7()));
        persist_immutable_json_path(&packet_post_commit_intent_path(&outbox_root), &intent)
            .expect("stage intent");
        append_packet_post_commit_event(
            &outbox_root,
            &intent,
            PacketPostCommitStatus::Prepared,
            &[],
        )
        .expect("stage prepared event");
        transition_packet_post_commit_outbox(
            &outbox_root,
            &intent,
            PacketPostCommitStatus::CommittedPending,
            &[],
        )
        .expect("mark committed pending");
        finish_packet_post_commit_outbox(&outbox_root, &intent, &[]).expect("finish outbox");
        transition_packet_post_commit_outbox(
            &outbox_root,
            &intent,
            PacketPostCommitStatus::CommittedPending,
            &["must not downgrade".to_owned()],
        )
        .expect("terminal replay is idempotent");
        let stored = latest_packet_post_commit_event(&outbox_root, &intent)
            .expect("read event log")
            .expect("terminal event");
        assert_eq!(stored.status, PacketPostCommitStatus::Complete);
        assert_eq!(stored.sequence, 2);
        assert!(stored.errors.is_empty());
        assert_eq!(
            std::fs::read_dir(packet_post_commit_events_root(&outbox_root))
                .expect("read terminal events")
                .count(),
            3,
            "terminal replay must not schedule post-commit effects again"
        );
        std::fs::remove_dir_all(outbox_root).expect("remove outbox fixture");
    }

    #[test]
    fn packet_post_commit_intent_pretty_roundtrip_preserves_response_hash() {
        let project_id = ProjectId::new_v7();
        let task_id = TaskId::new_v7();
        let packet_id = "eliot/packet/float-roundtrip";
        let packet_quality = eliot_types::PacketQualityReport {
            packet_id: packet_id.to_owned(),
            task_id: task_id.to_string(),
            revision_fence: MemoryRevision::new(7),
            structured_bytes: 1_723,
            estimated_tokens: 431,
            task_frame_present: true,
            current_truth_coverage: 1.0_f32 / 3.0_f32,
            causal_bridge_hops: 2,
            causal_bridge_missing_hops: Vec::new(),
            negative_memory_checked: true,
            exact_atoms_count: 3,
            material_unknowns: 0,
            verifier_present: true,
            stale_items_suppressed: 0,
            wrong_scope_items_suppressed: 0,
            tool_schema_bytes_visible: 512,
            instruction_hotset_size: 4,
            signal_density: (3.0_f32 * 128.0_f32 / 1_723.0_f32).min(1.0_f32),
            result: eliot_types::PacketQualityResult::Sufficient,
        };
        // This is an upstream serde_json f64 regression value. Packet responses
        // are heterogeneous Values, so their integrity hash must also survive
        // non-packet-quality numeric supplements without a one-ULP drift.
        let response = json!({
            "packet_id": packet_id,
            "project_id": project_id,
            "task_id": task_id,
            "packet_quality": packet_quality,
            "compile_audit": {
                "response_integrity_probe": 51.248_178_375_505_404_f64
            },
            "packet_admission": { "status": "admitted" }
        });
        let intent = outbox_intent(SessionId::new_v7(), response);
        let outbox_root = std::env::temp_dir().join(format!(
            "eliot-packet-intent-float-roundtrip-{}",
            WriteId::new_v7()
        ));
        let intent_path = packet_post_commit_intent_path(&outbox_root);
        persist_immutable_json_path(&intent_path, &intent).expect("persist pretty intent");
        let reread: PacketPostCommitIntent =
            serde_json::from_reader(std::fs::File::open(&intent_path).expect("open intent"))
                .expect("read pretty intent");
        let before_bytes = serde_json::to_vec(&intent.response).expect("serialize before response");
        let after_bytes = serde_json::to_vec(&reread.response).expect("serialize after response");
        let before_number = intent.response["compile_audit"]["response_integrity_probe"]
            .as_f64()
            .expect("before numeric probe");
        let after_number = reread.response["compile_audit"]["response_integrity_probe"]
            .as_f64()
            .expect("after numeric probe");
        let validation = validate_packet_post_commit_intent(&reread);
        std::fs::remove_dir_all(&outbox_root).expect("remove float roundtrip fixture");

        assert_eq!(
            before_bytes,
            after_bytes,
            "packet response changed across pretty persistence: before={} ({:#018x}), after={} ({:#018x}), delta={}",
            String::from_utf8_lossy(&before_bytes),
            before_number.to_bits(),
            String::from_utf8_lossy(&after_bytes),
            after_number.to_bits(),
            after_number - before_number,
        );
        validation.expect("reread packet post-commit intent must retain its response hash");
    }

    #[test]
    fn packet_family_fence_requires_cue_and_dependency_dirty_at_revision() {
        use eliot_store::{CognitiveProjectionFamily, CognitiveProjectionPublicationStatus};

        let project_id = ProjectId::new_v7();
        let revision = MemoryRevision::new(9);
        let state = |family| eliot_store::CognitiveProjectionFamilyState {
            project_id,
            family,
            target_revision: revision,
            applied_revision: Some(revision),
            status: CognitiveProjectionPublicationStatus::Published,
            last_error: None,
            updated_at: time::OffsetDateTime::now_utc(),
        };
        let fence = packet_enrichment_family_fence(
            vec![
                state(CognitiveProjectionFamily::DependencyDirty),
                state(CognitiveProjectionFamily::Cue),
            ],
            revision,
        )
        .expect("complete family fence");
        assert_eq!(fence.len(), 2);
        assert!(
            packet_enrichment_family_fence(vec![state(CognitiveProjectionFamily::Cue)], revision)
                .is_err()
        );
    }

    #[test]
    fn packet_startup_inventory_is_name_ordered_and_complete_beyond_the_old_window() {
        let fixture_root = std::env::temp_dir().join(format!(
            "eliot-packet-recovery-inventory-{}",
            WriteId::new_v7()
        ));
        for index in (0..300).rev() {
            let active = fixture_root
                .join(format!("task-{index:04}"))
                .join("active");
            std::fs::create_dir_all(&active).expect("create recovery inventory entry");
            std::fs::write(active.join("authority.json"), b"{}")
                .expect("write authority marker");
        }

        let mut report = PacketPostCommitRecoveryReport::default();
        let inventory = packet_post_commit_recovery_inventory(&fixture_root, &mut report);

        assert_eq!(inventory.len(), 300);
        assert_eq!(inventory[0].directory_name, "task-0000");
        assert_eq!(inventory[299].directory_name, "task-0299");
        assert_eq!(report.error_count, 0);
        std::fs::remove_dir_all(fixture_root).expect("remove recovery inventory fixture");
    }

    #[test]
    fn packet_startup_inventory_binds_canonical_and_legacy_handles_to_their_directory() {
        let canonical = TaskId::new_v7().to_string();
        let legacy = "legacy-packet-task";

        validate_packet_recovery_directory_key(&canonical, &canonical)
            .expect("canonical task directory");
        validate_packet_recovery_directory_key(&task_packet_key(legacy), legacy)
            .expect("legacy task directory");
        assert!(validate_packet_recovery_directory_key("misplaced", legacy).is_err());
    }

    #[test]
    fn packet_startup_recovery_error_samples_are_bounded_but_counts_are_exact() {
        let mut report = PacketPostCommitRecoveryReport::default();
        for index in 0..(PACKET_OUTBOX_RECOVERY_ERROR_SAMPLE_LIMIT + 5) {
            report.record_error(format!("error-{index}"));
        }

        assert_eq!(
            report.error_count,
            PACKET_OUTBOX_RECOVERY_ERROR_SAMPLE_LIMIT + 5
        );
        assert_eq!(
            report.error_samples.len(),
            PACKET_OUTBOX_RECOVERY_ERROR_SAMPLE_LIMIT
        );
        assert!(report.requires_attention());
    }

    #[test]
    fn packet_startup_recovery_caps_slots_before_failing_replay_attempts() {
        let mut report = PacketPostCommitRecoveryReport::default();
        let mut admitted = 0;
        for index in 0..(PACKET_OUTBOX_REPLAY_LIMIT + 5) {
            if report.claim_replay_slot() {
                admitted += 1;
                report.record_error(format!("forced-replay-failure-{index}"));
            } else {
                report.residual_pending = report.residual_pending.saturating_add(1);
            }
        }

        assert_eq!(admitted, PACKET_OUTBOX_REPLAY_LIMIT);
        assert_eq!(report.attempted, PACKET_OUTBOX_REPLAY_LIMIT);
        assert_eq!(report.error_count, PACKET_OUTBOX_REPLAY_LIMIT);
        assert_eq!(report.residual_pending, 5);
        assert!(!report.claim_replay_slot());
    }
}

fn persist_rejected_context_attempt(
    state: &McpState,
    packet: &ContextPacketL3,
    response: &Value,
) -> Result<()> {
    let task_root = state
        .root
        .join("reports")
        .join("context-packets")
        .join("tasks")
        .join(task_packet_key(&packet.task_id));
    let bytes = serde_json::to_vec_pretty(response)?;
    let attempt_hash = blake3::hash(&bytes).to_hex();
    let path = task_root
        .join("attempts")
        .join(format!("{attempt_hash}.json"));
    persist_immutable_bytes(&path, &bytes)
}

fn persist_immutable_json_path<T: serde::Serialize>(path: &Path, value: &T) -> Result<()> {
    persist_immutable_bytes(path, &serde_json::to_vec_pretty(value)?)
}

fn persist_immutable_bytes(path: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    if path.is_file() {
        let existing = std::fs::read(path)?;
        anyhow::ensure!(
            existing == bytes,
            "immutable context packet collision at {}",
            path.display()
        );
        return Ok(());
    }
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("packet");
    let temporary = path.with_file_name(format!(".{file_name}.{}.tmp", WriteId::new_v7()));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)?;
    let write_result = (|| -> Result<()> {
        file.write_all(bytes)?;
        file.flush()?;
        file.sync_all()?;
        Ok(())
    })();
    drop(file);
    if let Err(error) = write_result {
        let _ = std::fs::remove_file(&temporary);
        return Err(error);
    }

    // A hard link publishes the fully-fsynced inode without ever replacing an
    // existing destination. `rename` on Windows is not a no-clobber primitive.
    let publication = std::fs::hard_link(&temporary, path);
    let cleanup = std::fs::remove_file(&temporary);
    if let Err(error) = cleanup
        && error.kind() != std::io::ErrorKind::NotFound
    {
        return Err(error).with_context(|| {
            format!(
                "remove immutable context packet temporary {}",
                temporary.display()
            )
        });
    }
    match publication {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let existing = std::fs::read(path)?;
            anyhow::ensure!(
                existing == bytes,
                "immutable context packet collision at {}",
                path.display()
            );
            Ok(())
        }
        Err(error) => Err(error.into()),
    }
}

fn atomic_write_json_create_or_replace<T: serde::Serialize>(path: &Path, value: &T) -> Result<()> {
    if path.is_file() {
        return atomic_write_json(path, value);
    }
    let bytes = serde_json::to_vec_pretty(value)?;
    match persist_immutable_bytes(path, &bytes) {
        Ok(()) => Ok(()),
        Err(error) if path.is_file() => atomic_write_json(path, value).context(error),
        Err(error) => Err(error),
    }
}

fn task_packet_key(task_id: &str) -> String {
    TaskId::from_str(task_id).map_or_else(
        |_| blake3::hash(task_id.as_bytes()).to_hex().to_string(),
        |task_id| task_id.to_string(),
    )
}

fn latest_task_packet(state: &McpState, task_id: TaskId) -> Result<Option<ContextPacketL3>> {
    if let Some(authority) = read_active_packet_authority(state, &task_id.to_string())? {
        return Ok((authority.packet.task_id == task_id.to_string()).then_some(authority.packet));
    }
    let task_path = active_packet_latest_path(state, &task_id.to_string());
    if !task_path.is_file() {
        return Ok(None);
    }
    let packet: ContextPacketL3 = serde_json::from_reader(std::fs::File::open(task_path)?)?;
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
