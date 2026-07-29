//! The MCP request path: message in, tool call out.
//!
//! `handle_message` decodes one protocol message, `enforce_bound_tool_scope`
//! decides whether this session may ask for it, and `dispatch_tool` routes the
//! call to the handler module that owns it. The routing table is long by
//! nature -- one arm per tool -- but it is the only place that knows the whole
//! catalog, and keeping it beside the scope check is what makes "no tool
//! reaches a handler unscoped" readable as a single fact.

use super::*;

pub(super) async fn dispatch_host_governor_method(
    state: &McpState,
    method: &str,
    params: Value,
) -> Option<Result<Value>> {
    match method {
        "host/role-grant" => Some(
            crate::host_runtime::grant_role_from_daemon(
                &state.root,
                &state.store,
                &state.writer,
                params,
            )
            .await,
        ),
        "host/observation-record" => Some(
            crate::host_runtime::record_host_observation_from_daemon(
                &state.root,
                &state.store,
                &state.writer,
                params,
            )
            .await,
        ),
        "ul/onboard" => Some(
            crate::commands::run_ul_onboard_from_daemon(
                &state.root,
                &state.store,
                &state.writer,
                params,
            )
            .await,
        ),
        "ul/mine-git" => Some(
            crate::commands::run_ul_mine_git_from_daemon(&state.store, &state.writer, params).await,
        ),
        "ul/report" => Some(
            crate::commands::run_ul_report_from_daemon(
                &state.root,
                &state.store,
                &state.ul.ledger,
                params,
            )
            .await,
        ),
        "ul/maintain" => Some(
            crate::commands::run_ul_maintain_from_daemon(
                &state.config_path,
                &state.store,
                &state.writer,
                params,
            )
            .await,
        ),
        "ul/dirty-report" => {
            Some(crate::commands::run_ul_dirty_report_from_daemon(&state.store, params).await)
        }
        "ul/injection-policy-set" => Some(
            crate::commands::run_ul_injection_policy_set_from_daemon(
                &state.root,
                &state.store,
                params,
            )
            .await,
        ),
        "ul/exam-run" => Some(
            crate::commands::run_ul_exam_run_from_daemon(
                &state.config_path,
                &state.root,
                &state.store,
                &state.writer,
                params,
            )
            .await,
        ),
        "ul/exam-report" => {
            Some(crate::commands::run_ul_exam_report_from_daemon(&state.store, params).await)
        }
        "ul/prediction-sweep" => Some(
            crate::commands::run_ul_prediction_sweep_from_daemon(
                &state.store,
                &state.writer,
                params,
            )
            .await,
        ),
        "ping" => Some(Ok(json!({}))),
        _ => None,
    }
}

pub(super) async fn handle_message(
    state: &McpState,
    context: AuthenticatedRequestContext,
    request: Value,
) -> Option<Value> {
    let id = request.get("id").cloned()?;
    let method = request.get("method").and_then(Value::as_str)?;
    let result = if state.profile == McpAccessProfile::HostGovernor {
        let Some(result) = dispatch_host_governor_method(
            state,
            method,
            request.get("params").cloned().unwrap_or(Value::Null),
        )
        .await
        else {
            return Some(error_response(
                &id,
                -32601,
                &format!("method not found: {method}"),
            ));
        };
        result
    } else if state.profile == McpAccessProfile::CognitiveGovernor {
        match method {
            "cognitive/seal" => {
                Box::pin(cognitive_run_seal(
                    state,
                    context,
                    request.get("params").cloned().unwrap_or(Value::Null),
                ))
                .await
            }
            "cognitive/begin" => {
                Box::pin(cognitive_run_begin(
                    state,
                    context,
                    request.get("params").cloned().unwrap_or(Value::Null),
                ))
                .await
            }
            "cognitive/terminal" => {
                Box::pin(cognitive_run_terminal(
                    state,
                    context,
                    request.get("params").cloned().unwrap_or(Value::Null),
                ))
                .await
            }
            "cognitive/status" => {
                Box::pin(cognitive_run_status(
                    state,
                    request.get("params").cloned().unwrap_or(Value::Null),
                ))
                .await
            }
            "ping" => Ok(json!({})),
            _ => {
                return Some(error_response(
                    &id,
                    -32601,
                    &format!("method not found: {method}"),
                ));
            }
        }
    } else {
        match method {
            "initialize" => record_agent_session(state, context, &request)
                .map(|session| initialize_result(state.profile, &session)),
            "ping" => Ok(json!({})),
            "prompts/list" => Ok(json!({ "prompts": prompt_definitions() })),
            "prompts/get" => prompt_get(request.get("params").unwrap_or(&Value::Null)),
            "tools/list" => {
                if state.profile == McpAccessProfile::CognitiveChild {
                    cognitive_tool_definitions(state, context.session_id)
                        .await
                        .map(|tools| json!({ "tools": tools }))
                } else {
                    Ok(json!({ "tools": tool_definitions_for_profile(state.profile) }))
                }
            }
            "tools/call" => {
                Box::pin(call_tool(
                    state,
                    context,
                    request.get("params").cloned().unwrap_or(Value::Null),
                ))
                .await
            }
            _ => {
                return Some(error_response(
                    &id,
                    -32601,
                    &format!("method not found: {method}"),
                ));
            }
        }
    };
    Some(match result {
        Ok(result) => json!({ "jsonrpc": "2.0", "id": id, "result": result }),
        Err(error) => dispatch_error_response(&id, &error),
    })
}

fn dispatch_error_response(id: &Value, error: &anyhow::Error) -> Value {
    if let Some(input) = error.downcast_ref::<eliot_types::ToolInputError>() {
        error_response_with_data(id, -32602, "invalid tool input", &input.data)
    } else if let Some(eliot_engine::EngineError::EncodingRejected { violations }) =
        error.downcast_ref::<eliot_engine::EngineError>()
    {
        let data = eliot_types::ToolInputErrorData {
            code: "ENCODING_REJECTED".to_owned(),
            missing: Vec::new(),
            invalid: violations
                .iter()
                .filter(|violation| {
                    violation.path != "$.claim.payload.statement"
                        || !violations.iter().any(|canonical| {
                            canonical.path == "$.claim.statement"
                                && canonical.reason == violation.reason
                        })
                })
                .map(|violation| eliot_types::InvalidField {
                    field: violation.path.clone(),
                    reason: violation.reason.clone(),
                })
                .collect(),
            minimal_valid_example: Value::Null,
        };
        error_response_with_data(id, -32602, "encoding rejected", &data)
    } else if matches!(
        error.downcast_ref::<eliot_engine::EngineError>(),
        Some(eliot_engine::EngineError::ObservabilityConflict)
    ) {
        let data = eliot_types::ToolInputErrorData {
            code: "OBSERVABILITY_WRITE_ID_CONFLICT".to_owned(),
            missing: Vec::new(),
            invalid: Vec::new(),
            minimal_valid_example: Value::Null,
        };
        error_response_with_data(id, -32602, "observability write_id conflict", &data)
    } else if let Some(eliot_engine::EngineError::PacketFloorExceedsBudget {
        max_tokens,
        estimated_tokens,
        section_tokens,
    }) = error.downcast_ref::<eliot_engine::EngineError>()
    {
        error_response_with_data(
            id,
            -32602,
            "context packet floor exceeds budget",
            &serde_json::json!({
                "code": "PACKET_FLOOR_EXCEEDS_BUDGET",
                "max_tokens": max_tokens,
                "estimated_tokens": estimated_tokens,
                "section_tokens": section_tokens,
            }),
        )
    } else {
        error_response(id, -32603, &error.to_string())
    }
}

pub(super) fn enforce_bound_tool_scope(
    context: AuthenticatedRequestContext,
    name: &str,
    mut arguments: Value,
) -> Result<Value> {
    let (Some(bound_project_id), Some(bound_task_id)) =
        (context.bound_project_id, context.bound_task_id)
    else {
        return Ok(arguments);
    };
    let object = arguments
        .as_object_mut()
        .context("bound host tool arguments must be a JSON object")?;
    if let Some(explicit) = object.get("project_id") {
        let explicit = explicit
            .as_str()
            .context("bound host project_id must be a string")?;
        if parse_project_id(explicit)? != bound_project_id {
            anyhow::bail!(
                "PROJECT_SCOPE_MISMATCH: explicit project_id differs from the Governor-bound host session"
            );
        }
    } else if BOUND_PROJECT_DEFAULT_TOOLS.contains(&name) {
        object.insert("project_id".to_owned(), json!(bound_project_id));
    }
    if let Some(explicit) = object.get("task_id") {
        let explicit = explicit
            .as_str()
            .context("bound host task_id must be a string")?;
        if TaskId::from_str(explicit).context("parse task id")? != bound_task_id {
            anyhow::bail!(
                "TASK_SCOPE_MISMATCH: explicit task_id differs from the Governor-bound host session"
            );
        }
    } else if BOUND_TASK_DEFAULT_TOOLS.contains(&name) {
        object.insert("task_id".to_owned(), json!(bound_task_id));
    }
    if BOUND_PROJECT_ALIAS_DEFAULT_TOOLS.contains(&name) {
        if let Some(explicit) = object.get("project") {
            let explicit = explicit
                .as_str()
                .context("bound host project must be a string")?;
            if parse_project_id(explicit)? != bound_project_id {
                anyhow::bail!(
                    "PROJECT_SCOPE_MISMATCH: explicit project differs from the Governor-bound host session"
                );
            }
        } else {
            object.insert("project".to_owned(), json!(bound_project_id));
        }
    }
    Ok(arguments)
}

#[allow(clippy::too_many_lines)]
pub(super) async fn call_tool(
    state: &McpState,
    context: AuthenticatedRequestContext,
    params: Value,
) -> Result<Value> {
    let name = params
        .get("name")
        .and_then(Value::as_str)
        .context("tools/call params.name is required")?;
    let arguments = params
        .get("arguments")
        .cloned()
        .unwrap_or_else(|| json!({}));
    let arguments = enforce_bound_tool_scope(context, name, arguments)?;
    let ul_input_bytes = u64::try_from(serde_json::to_vec(&arguments)?.len()).unwrap_or(u64::MAX);
    let (ul_project_id, ul_task_id) = ul_scope(context, &arguments);
    let observed_arguments = ul_project_id.map_or_else(Vec::new, |project_id| {
        state
            .ul
            .touched
            .observe_arguments(project_id, context.session_id, name, &arguments)
    });
    let argument_memory_free_control = name == "eliot_compile_packet_l3"
        && arguments.get("memory_mode").and_then(Value::as_str) == Some("memory_free_control");
    let cognitive_claims = if state.profile == McpAccessProfile::CognitiveChild {
        let claims = cognitive_principal(state, context.session_id).await?;
        ensure_cognitive_tool_observation_capacity(state, &claims.capability).await?;
        if !cognitive_role_allows(claims.capability.invocation_role, name) {
            let denied = json!({
                "error": "cognitive_role_denied",
                "tool_name": name,
                "invocation_role": claims.capability.invocation_role,
            });
            write_cognitive_tool_observation(
                state, context, &claims, name, "denied", &arguments, &denied,
            )
            .await?;
            return Ok(tool_error(&format!(
                "tool is not admitted by cognitive {:?} authority: {name}",
                claims.capability.invocation_role
            )));
        }
        if !cognitive_memory_request_allowed(&claims.capability, name, &arguments) {
            let denied = json!({
                "error": "cognitive_memory_scope_denied",
                "tool_name": name,
                "project_id": claims.capability.project_id,
                "expected_handles": claims.capability.expected_exposure_handles,
            });
            write_cognitive_tool_observation(
                state, context, &claims, name, "denied", &arguments, &denied,
            )
            .await?;
            return Ok(tool_error(
                "tool request exceeds the sealed cognitive memory scope",
            ));
        }
        Some(claims)
    } else {
        None
    };
    if !state.profile.allows(name) {
        return Ok(tool_error(&format!(
            "tool is not available in MCP profile {}: {name}",
            state.profile.as_str()
        )));
    }

    state.ensure_schema().await?;

    let observation_arguments = arguments.clone();
    let mut dispatch_arguments = arguments;
    if cognitive_claims.as_ref().is_some_and(|claims| {
        claims.capability.invocation_role == CognitiveInvocationRole::Target
            && name == "eliot_recall_l0"
    }) {
        dispatch_arguments["limit"] = json!(50);
    }
    let dispatched = Box::pin(dispatch_tool(state, context, name, dispatch_arguments)).await;
    let structured = match dispatched {
        Ok(mut structured) => {
            if let Some(claims) = cognitive_claims.as_ref()
                && claims.capability.invocation_role == CognitiveInvocationRole::Target
                && name == "eliot_recall_l0"
            {
                restrict_cognitive_recall(
                    &mut structured,
                    &claims.capability.expected_exposure_handles,
                )?;
            }
            if let Some(claims) = cognitive_claims.as_ref()
                && claims.capability.invocation_role == CognitiveInvocationRole::Target
                && name == "eliot_fetch_l2"
            {
                let mut response: FetchAtomsL2Response = serde_json::from_value(structured)?;
                filter_required_exact_l2_response(
                    &mut response,
                    &claims.capability.expected_exposure_handles,
                );
                structured = serde_json::to_value(response)?;
            }
            let ul_output_bytes =
                u64::try_from(serde_json::to_vec(&structured)?.len()).unwrap_or(u64::MAX);
            let mut newly_observed = observed_arguments;
            if let Some(project_id) = ul_project_id {
                newly_observed.extend(state.ul.touched.observe_result(
                    project_id,
                    context.session_id,
                    name,
                    &structured,
                ));
            }
            newly_observed.sort_by(|left, right| {
                left.kind
                    .cmp(&right.kind)
                    .then_with(|| left.value.cmp(&right.value))
            });
            newly_observed.dedup();
            let response_memory_free_control = structured
                .get("memory_view")
                .and_then(|memory_view| memory_view.get("mode"))
                .and_then(Value::as_str)
                == Some("memory_free_control");
            let memory_free_control = argument_memory_free_control || response_memory_free_control;
            let mut injection_receipts = Vec::new();
            let mut ul_assignment = None;
            if let Some(project_id) = ul_project_id {
                let (effective_injection_mode, assignment) = state
                    .ul
                    .effective_injection_mode(project_id, ul_task_id, memory_free_control)
                    .await?;
                ul_assignment = assignment;
                if let (Some(assignment), Some(mode)) =
                    (ul_assignment.as_mut(), effective_injection_mode)
                {
                    assignment.injection_mode = mode;
                }
                state
                    .ul
                    .observe_successful_tool(
                        project_id,
                        context.session_id,
                        name,
                        &observation_arguments,
                        &newly_observed,
                    )
                    .await?;
                if effective_injection_mode.is_some() {
                    state
                        .ul
                        .planner
                        .plan_after_tool(project_id, context.session_id, &newly_observed)
                        .await?;
                }
                injection_receipts = state
                    .ul
                    .planner
                    .attach(
                        project_id,
                        ul_task_id,
                        context.session_id,
                        &mut structured,
                        effective_injection_mode,
                    )
                    .await?;
            }
            if let (Some(project_id), Some(task_id)) = (ul_project_id, ul_task_id) {
                let _ = state
                    .ul
                    .ledger
                    .record_call(
                        eliot_engine::UlToolMeasurement {
                            project_id,
                            task_id,
                            session_id: context.session_id,
                            tool_name: name.to_owned(),
                            arguments: observation_arguments.clone(),
                            input_bytes: ul_input_bytes,
                            output_bytes: ul_output_bytes,
                            injection_receipts,
                        },
                        ul_assignment.as_ref(),
                    )
                    .await;
            }
            if let Some(claims) = cognitive_claims.as_ref() {
                write_cognitive_tool_observation(
                    state,
                    context,
                    claims,
                    name,
                    "succeeded",
                    &observation_arguments,
                    &structured,
                )
                .await?;
            }
            structured
        }
        Err(error) => {
            if let Some(claims) = cognitive_claims.as_ref() {
                let observed_error = json!({
                    "error": "dispatch_failed",
                    "message": error.to_string(),
                });
                write_cognitive_tool_observation(
                    state,
                    context,
                    claims,
                    name,
                    "failed",
                    &observation_arguments,
                    &observed_error,
                )
                .await?;
            }
            return Err(error);
        }
    };
    if state.profile == McpAccessProfile::ExternalAuditor {
        write_antigravity_mcp_invocation_receipt(state, name)?;
    }
    tool_success(&structured)
}

fn ul_scope(
    context: AuthenticatedRequestContext,
    arguments: &Value,
) -> (Option<ProjectId>, Option<TaskId>) {
    let project_id = context.bound_project_id.or_else(|| {
        arguments
            .get("project_id")
            .or_else(|| arguments.get("project"))
            .and_then(Value::as_str)
            .and_then(|value| ProjectId::from_str(value).ok())
    });
    let task_id = context.bound_task_id.or_else(|| {
        arguments
            .get("task_id")
            .or_else(|| arguments.get("task"))
            .and_then(Value::as_str)
            .and_then(|value| TaskId::from_str(value).ok())
    });
    (project_id, task_id)
}

pub(super) fn string_array_field(value: &Value, field: &str) -> Vec<String> {
    value
        .get(field)
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect()
}

#[allow(clippy::too_many_lines)]
pub(super) async fn dispatch_tool(
    state: &McpState,
    context: AuthenticatedRequestContext,
    name: &str,
    arguments: Value,
) -> Result<Value> {
    let structured = match name {
        "eliot_cognitive_job_fetch" => {
            Box::pin(dispatch_cognitive_job_fetch(state, context, arguments)).await?
        }
        "eliot_task_contract_create" => {
            Box::pin(dispatch_task_contract_create(state, context, arguments)).await?
        }
        "eliot_task_state" => Box::pin(dispatch_task_state(state, arguments)).await?,
        "eliot_task_action_request" => {
            Box::pin(dispatch_task_action_request(state, context, arguments)).await?
        }
        "eliot_task_observation_record" => {
            Box::pin(dispatch_task_observation_record(state, context, arguments)).await?
        }
        "eliot_write_cognitive_observation" => {
            Box::pin(dispatch_write_cognitive_observation(
                state, context, arguments,
            ))
            .await?
        }
        "eliot_agent_candidate_submit" => {
            Box::pin(dispatch_agent_candidate_submit(state, context, arguments)).await?
        }
        "eliot_task_verification_run" => {
            Box::pin(dispatch_task_verification_run(state, context, arguments)).await?
        }
        "eliot_host_session_status" => dispatch_host_session_status(state, context)?,
        "eliot_project_identity" => {
            let input: ProjectIdentityToolInput = serde_json::from_value(arguments)?;
            let canonical_project_key = input
                .project_key
                .as_deref()
                .map(canonical_project_key)
                .transpose()?;
            let resolved_project_id = canonical_project_key
                .as_deref()
                .map(project_id_from_canonical_key);
            if let (Some(bound), Some(resolved)) = (context.bound_project_id, resolved_project_id)
                && bound != resolved
            {
                anyhow::bail!(
                    "PROJECT_SCOPE_MISMATCH: project_key differs from the Governor-bound host session"
                );
            }
            let project_id = context
                .bound_project_id
                .or(resolved_project_id)
                .context("eliot_project_identity requires project_key for an unbound session")?;
            json!({
                "schema_version": "eliot-project-identity-v2",
                "input_project_key": input.project_key,
                "canonical_project_key": canonical_project_key,
                "project_id": project_id,
                "accepted_by_project_id_fields": true,
                "identity_scope": if context.bound_project_id.is_some() {
                    "governor_bound_host_session"
                } else {
                    "stable across clients using the same canonical project key"
                },
                "bound_task_id": context.bound_task_id,
                "scope_authority": if context.bound_project_id.is_some() {
                    "canonical_host_binding"
                } else {
                    "canonical_project_key"
                }
            })
        }
        "eliot_current_state" => {
            let input: CurrentStateToolInput = serde_json::from_value(arguments)?;
            let mut response = ReadService::new(state.store.clone())
                .current_state(&CurrentStateRequest {
                    project_id: parse_project_id(&input.project_id)?,
                    consistency: consistency(input.at_least_revision),
                    at_least_revision: revision(input.at_least_revision),
                })
                .await?;
            let response = match input.scope.as_deref() {
                None | Some("" | "all_memory") => serde_json::to_value(response)?,
                Some("memory_free_control") => {
                    let excluded_item_count = response.verified_now.len()
                        + response.supported_now.len()
                        + response.weak_or_candidate.len()
                        + response.contested_now.len()
                        + response.do_not_use.len()
                        + response.recent_failures.len();
                    response.verified_now.clear();
                    response.supported_now.clear();
                    response.weak_or_candidate.clear();
                    response.contested_now.clear();
                    response.do_not_use.clear();
                    response.recent_failures.clear();
                    response.truncation.returned = 0;
                    response.truncation.truncated = false;
                    let mut value = serde_json::to_value(response)?;
                    value["memory_view"] = json!({
                        "mode": "memory_free_control",
                        "memory_content_included": false,
                        "excluded_item_count": excluded_item_count,
                        "reason": "pre-registered control condition; revision fence retained while reusable and historical memory content is excluded"
                    });
                    value
                }
                Some(scope) => anyhow::bail!(
                    "unsupported current-state scope {scope}; expected all_memory or memory_free_control"
                ),
            };
            current_state_with_bound_task(response, context.bound_task_id)
        }
        "eliot_recall_l0" => {
            let input: RecallL0ToolInput = serde_json::from_value(arguments)?;
            if input.query.trim().is_empty() || input.query.len() > 512 {
                anyhow::bail!("eliot_recall_l0 query must be non-empty and at most 512 bytes");
            }
            let mut response = ReadService::new(state.store.clone())
                .recall_l0(&RecallL0Request {
                    project_id: parse_project_id(&input.project_id)?,
                    query: input.query,
                    consistency: ReadConsistencyMode::Latest,
                    at_least_revision: None,
                    lifecycle_audit: false,
                })
                .await?;
            let limit = input
                .limit
                .unwrap_or(response.truncation.limit)
                .clamp(1, 50);
            if response.handles.len() > limit {
                response.handles.truncate(limit);
                response.truncation.truncated = true;
            }
            response.truncation.limit = limit;
            response.truncation.returned = response.handles.len();
            let returned = response
                .handles
                .iter()
                .map(|handle| handle.handle.as_str())
                .collect::<HashSet<_>>();
            response
                .rank_trace
                .feature_scores
                .retain(|score| returned.contains(score.handle.as_str()));
            response.rank_trace.candidates_returned = response.handles.len();
            response.rank_trace.no_useful_memory = response.handles.is_empty();
            response.memory_confidence = eliot_types::MemoryConfidence::from_top_score(
                response
                    .rank_trace
                    .feature_scores
                    .iter()
                    .map(|score| score.total)
                    .max(),
            );
            serde_json::to_value(response)?
        }
        "eliot_fetch_l2" => {
            let input: FetchL2ToolInput = serde_json::from_value(arguments)?;
            let handles = input.handles;
            let response = ReadService::new(state.store.clone())
                .fetch_atoms_l2(&FetchAtomsL2Request {
                    project_id: parse_project_id(&input.project_id)?,
                    handles: handles.clone(),
                    continuation: input.continuation,
                    consistency: consistency(input.at_least_revision),
                    at_least_revision: revision(input.at_least_revision),
                })
                .await?;
            serde_json::to_value(response)?
        }
        "eliot_compile_packet_l3" => {
            Box::pin(dispatch_compile_packet_l3(state, context, arguments)).await?
        }
        "eliot_understanding_outcome_record" => {
            Box::pin(dispatch_understanding_outcome_record(state, arguments)).await?
        }
        "eliot_memory_influence_trace" => {
            Box::pin(dispatch_memory_influence_trace(state, context, arguments)).await?
        }
        "eliot_context_cargo_receipt" => {
            Box::pin(dispatch_context_cargo_receipt(state, arguments)).await?
        }
        "eliot_task_meaning" => dispatch_task_meaning(arguments)?,
        "eliot_memory_corpus_profile" => {
            Box::pin(dispatch_memory_corpus_profile(state, arguments)).await?
        }
        "eliot_memory_curation_preview" => {
            Box::pin(dispatch_memory_curation_preview(state, arguments)).await?
        }
        "eliot_experience_recall" => Box::pin(dispatch_experience_recall(state, arguments)).await?,
        "eliot_experience_reinstate" => {
            Box::pin(dispatch_experience_reinstate(state, arguments)).await?
        }
        "eliot_experience_form" => {
            Box::pin(dispatch_experience_form(state, context, arguments)).await?
        }
        "eliot_experience_abstract" => {
            Box::pin(dispatch_experience_abstract(state, context, arguments)).await?
        }
        "eliot_experience_maturity_transition" => {
            Box::pin(dispatch_experience_maturity_transition(
                state, context, arguments,
            ))
            .await?
        }
        "eliot_negative_transfer_record" => {
            Box::pin(dispatch_negative_transfer_record(state, context, arguments)).await?
        }
        "eliot_cognitive_lab_evaluate" => {
            Box::pin(dispatch_cognitive_lab_evaluate(state, context, arguments)).await?
        }
        "eliot_cognitive_failure_localization_record" => {
            Box::pin(dispatch_cognitive_failure_localization_record(
                state, context, arguments,
            ))
            .await?
        }
        "eliot_operator_contract" => dispatch_operator_contract()?,
        "eliot_operator_snapshot" => Box::pin(dispatch_operator_snapshot(state, arguments)).await?,
        "eliot_operator_query" => Box::pin(dispatch_operator_query(state, arguments)).await?,
        "eliot_autonomy_run_status" => {
            Box::pin(dispatch_autonomy_run_status(state, arguments)).await?
        }
        "eliot_operator_command" => {
            Box::pin(dispatch_operator_command(state, context, arguments)).await?
        }
        "eliot_procedure_candidate_create" => {
            Box::pin(dispatch_procedure_candidate_create(
                state, context, arguments,
            ))
            .await?
        }
        "eliot_procedure_candidate_disposition" => {
            Box::pin(dispatch_procedure_candidate_disposition(
                state, context, arguments,
            ))
            .await?
        }
        "eliot_contour_route_preview" => dispatch_contour_route_preview(arguments)?,
        "eliot_autonomy_contract_write" => {
            Box::pin(dispatch_autonomy_contract_write(state, context, arguments)).await?
        }
        "eliot_autonomy_approval_request" => {
            Box::pin(dispatch_autonomy_approval_request(
                state, context, arguments,
            ))
            .await?
        }
        "eliot_autonomy_approval_decide" => {
            Box::pin(dispatch_autonomy_approval_decide(state, context, arguments)).await?
        }
        "eliot_autonomy_transition" => {
            Box::pin(dispatch_autonomy_transition(state, context, arguments)).await?
        }
        "eliot_autonomy_runtime_action" => {
            Box::pin(dispatch_autonomy_runtime_action(state, context, arguments)).await?
        }
        "eliot_submit_understanding_proof" => {
            Box::pin(dispatch_understanding_proof(state, arguments)).await?
        }
        "eliot_cognitive_gate" => {
            let request: CognitiveGateRequest = serde_json::from_value(arguments)?;
            let decision = CognitiveGate::decide(&request);
            write_json_report(
                &state
                    .root
                    .join("reports")
                    .join("cognitive-gate")
                    .join("latest.json"),
                &decision,
            )?;
            serde_json::to_value(decision)?
        }
        "eliot_submit_completion_proof" => {
            if arguments.get("write_id").is_some() && arguments.get("expected_revision").is_some() {
                Box::pin(dispatch_task_completion(state, context, arguments)).await?
            } else {
                let proof: CompletionProof = serde_json::from_value(arguments)?;
                let decision = CompletionGate::decide_with_incident_context(
                    &proof,
                    IncidentService::new(&state.root).lockdown_active()?,
                );
                write_json_report(
                    &state
                        .root
                        .join("reports")
                        .join("completion-gate")
                        .join("latest.json"),
                    &decision,
                )?;
                serde_json::to_value(decision)?
            }
        }
        "eliot_codecortex_scan" => Box::pin(dispatch_codecortex_scan(state, arguments)).await?,
        "eliot_codecortex_latest" => dispatch_codecortex_latest(state)?,
        "eliot_external_review_providers" => dispatch_external_review_providers(state)?,
        "eliot_external_review_request" => {
            Box::pin(dispatch_external_review_request(state, arguments)).await?
        }
        "eliot_external_review_job_status" => {
            dispatch_external_review_job_status(state, arguments)?
        }
        "eliot_external_review_result" => dispatch_external_review_result(state, arguments)?,
        "eliot_external_review_report" => dispatch_external_review_report(state)?,
        "eliot_external_review_run_mock" => {
            Box::pin(dispatch_external_review_run_mock(state, arguments)).await?
        }
        "eliot_delegate_review" => {
            let input: delegation_runtime::DelegationReviewInput =
                serde_json::from_value(arguments)?;
            authorize_dynamic_delegation(state, context, &input)?;
            delegation_runtime::review(&state.root, input).await?
        }
        "eliot_delegate_status" => {
            let input: DelegationRefToolInput = serde_json::from_value(arguments)?;
            delegation_runtime::status(&state.root, &input.delegation_id)?
        }
        "eliot_delegate_result" => {
            let input: DelegationRefToolInput = serde_json::from_value(arguments)?;
            delegation_runtime::result(&state.root, &input.delegation_id)?
        }
        "eliot_delegate_report" => delegation_runtime::report(&state.root)?,
        "eliot_agent_delegate" => {
            Box::pin(dispatch_agent_delegate(state, context, arguments)).await?
        }
        "eliot_agent_job_claim" => dispatch_agent_job_claim(state, context, arguments)?,
        "eliot_agent_job_status" => dispatch_agent_job_status(state, context, arguments)?,
        "eliot_agent_result_submit" => {
            dispatch_agent_result_submit(state, context, arguments).await?
        }
        "eliot_agent_result_finalize" => {
            Box::pin(dispatch_agent_result_finalize(state, context, arguments)).await?
        }
        "eliot_agent_result" => dispatch_agent_result(state, context, arguments)?,
        "eliot_agent_result_disposition" => {
            dispatch_agent_result_disposition(state, context, arguments).await?
        }
        "eliot_delegation_calibration_status" => calibration_runtime::status(&state.root)?,
        "eliot_delegation_calibration_report" => calibration_runtime::report(&state.root)?,
        "eliot_delegation_policy_candidate" => calibration_runtime::candidate_status(&state.root)?,
        "eliot_delegation_promotion_status" => calibration_runtime::promotion_status(&state.root)?,
        "eliot_antigravity_status" => dispatch_antigravity_status(state)?,
        "eliot_antigravity_doctor" => dispatch_antigravity_doctor(state)?,
        "eliot_antigravity_request" => dispatch_antigravity_request(arguments)?,
        "eliot_antigravity_job_status" => dispatch_antigravity_job_status(state, arguments)?,
        "eliot_antigravity_result" => dispatch_antigravity_result(state, arguments)?,
        "eliot_antigravity_report" => dispatch_antigravity_report(state)?,
        "eliot_antigravity_skills" => dispatch_antigravity_skills(state)?,
        "eliot_antigravity_plugin" => dispatch_antigravity_plugin(state)?,
        "eliot_antigravity_auth_status" => dispatch_antigravity_auth_status(state)?,
        "eliot_antigravity_enablement_status" => dispatch_antigravity_enablement_status(state)?,
        "eliot_antigravity_visibility" => dispatch_antigravity_visibility(state)?,
        "eliot_antigravity_mcp_status" => dispatch_antigravity_mcp_status(state)?,
        "eliot_antigravity_plugin_status" => dispatch_antigravity_plugin_status(state)?,
        "eliot_antigravity_live_smoke_status" => dispatch_antigravity_live_smoke_status(state)?,
        "eliot_antigravity_real_report" => dispatch_antigravity_real_report(state)?,
        "eliot_eval_case_list" => dispatch_eval_case_list(arguments)?,
        "eliot_eval_suite_list" => dispatch_eval_suite_list(state, arguments)?,
        "eliot_eval_run" => dispatch_eval_run(state, arguments)?,
        "eliot_eval_verdict" => dispatch_eval_verdict(state, arguments)?,
        "eliot_eval_report" => dispatch_eval_report(state)?,
        "eliot_eval_smoke" => dispatch_eval_smoke(state, arguments)?,
        "eliot_eval_coverage" => dispatch_eval_coverage(state, arguments)?,
        "eliot_eval_baseline_list" => dispatch_eval_baseline_list(state, arguments)?,
        "eliot_eval_compare" => dispatch_eval_compare(state, arguments)?,
        "eliot_eval_gate" => dispatch_eval_gate(state, arguments)?,
        "eliot_eval_profiles" => dispatch_eval_profiles(state)?,
        "eliot_eval_trend" => dispatch_eval_trend(state, arguments)?,
        "eliot_verify_profiles" => dispatch_verify_profiles(state)?,
        "eliot_verify_inventory" => dispatch_verify_inventory(state)?,
        "eliot_verify_plan" => dispatch_verify_plan(state, arguments)?,
        "eliot_verify_report" => dispatch_verify_report(state)?,
        "eliot_verify_cost_report" => dispatch_verify_cost_report(state)?,
        "eliot_verify_last_verdict" => dispatch_verify_last_verdict(state)?,
        "eliot_metrics_registry" => dispatch_metrics_registry(state)?,
        "eliot_metrics_dashboard" => dispatch_metrics_dashboard(state)?,
        "eliot_metrics_slo" => dispatch_metrics_slo(state)?,
        "eliot_metrics_latency" => dispatch_metrics_latency(state)?,
        "eliot_metrics_cost" => dispatch_metrics_cost(state)?,
        "eliot_metrics_quality" => dispatch_metrics_quality(state)?,
        "eliot_metrics_report" => dispatch_metrics_report(state)?,
        "eliot_trace_completeness" => {
            Box::pin(dispatch_trace_completeness(state, context, arguments)).await?
        }
        "eliot_replay_case_create" | "eliot_replay_set_create" => anyhow::bail!(
            "legacy report-only replay fixture path is disabled; register a trace and call eliot_replay_run"
        ),
        "eliot_replay_run" => dispatch_replay_run(state, context, arguments).await?,
        "eliot_replay_report" => dispatch_replay_report(state),
        "eliot_sleep_run" => dispatch_sleep_run(state, context, arguments).await?,
        "eliot_sleep_report" => dispatch_latest_report(state, "sleep")?,
        "eliot_dream_candidate_create" => anyhow::bail!(
            "direct dream fixture creation is disabled; call eliot_sleep_run with canonical trace refs"
        ),
        "eliot_dream_report" => dispatch_latest_report(state, "dream")?,
        "eliot_meta_experiment_run" => {
            Box::pin(dispatch_meta_experiment_run(state, context, arguments)).await?
        }
        "eliot_meta_experiment_disposition" => {
            Box::pin(dispatch_meta_experiment_disposition(
                state, context, arguments,
            ))
            .await?
        }
        "eliot_canonical_status" => Box::pin(dispatch_canonical_status(state, arguments)).await?,
        "eliot_memory_lifecycle_status" => dispatch_memory_lifecycle_status(arguments)?,
        "eliot_memory_lifecycle_propose" => dispatch_memory_lifecycle_propose(arguments)?,
        "eliot_memory_lifecycle_vitality" => dispatch_memory_lifecycle_vitality(arguments)?,
        "eliot_memory_lifecycle_gravity" => dispatch_memory_lifecycle_gravity(arguments)?,
        "eliot_memory_lifecycle_influence" => {
            Box::pin(dispatch_memory_lifecycle_influence(state, arguments)).await?
        }
        "eliot_skill_list" => dispatch_skill_list(arguments)?,
        "eliot_skill_inspect" => dispatch_skill_inspect(arguments)?,
        "eliot_skill_estimate" => dispatch_skill_estimate(arguments)?,
        "eliot_skill_filter" => dispatch_skill_filter(arguments)?,
        "eliot_skill_influence" => dispatch_skill_influence(arguments)?,
        "eliot_skill_execution_proof" => {
            Box::pin(dispatch_skill_execution_proof(state, arguments)).await?
        }
        "eliot_skill_create_candidate" => {
            Box::pin(dispatch_skill_create_candidate(state, arguments)).await?
        }
        "eliot_skill_curator_run" => Box::pin(dispatch_skill_curator_run(state, arguments)).await?,
        "eliot_skill_curator_proposals" => {
            Box::pin(dispatch_skill_curator_proposals(state, arguments)).await?
        }
        "eliot_skill_curator_inspect" => dispatch_skill_curator_inspect(state, arguments)?,
        "eliot_skill_curator_report" => dispatch_skill_curator_report(state)?,
        "eliot_skill_curator_gate" => dispatch_skill_curator_gate(state, arguments)?,
        "eliot_action_plan" => Box::pin(dispatch_action_plan(state, arguments)).await?,
        "eliot_action_lease_status" => dispatch_action_lease_status(state, arguments)?,
        "eliot_patch_preflight" => Box::pin(dispatch_patch_preflight(state, arguments)).await?,
        "eliot_patch_apply" => Box::pin(dispatch_patch_apply(state, arguments)).await?,
        "eliot_patch_status" => dispatch_patch_status(state, arguments)?,
        "eliot_verifier_status" => dispatch_verifier_status(state, arguments)?,
        "eliot_work_create" => Box::pin(dispatch_work_create(state, arguments)).await?,
        "eliot_work_claim" => Box::pin(dispatch_work_claim(state, arguments)).await?,
        "eliot_work_status" => dispatch_work_status(state, arguments)?,
        "eliot_work_renew" => Box::pin(dispatch_work_renew(state, arguments)).await?,
        "eliot_work_release" => Box::pin(dispatch_work_release(state, arguments)).await?,
        "eliot_work_conflicts" => dispatch_work_conflicts(state, arguments)?,
        "eliot_worktree_create" => Box::pin(dispatch_worktree_create(state, arguments)).await?,
        "eliot_worktree_status" => dispatch_worktree_status(state, arguments)?,
        "eliot_worktree_capture_diff" => {
            Box::pin(dispatch_worktree_capture_diff(state, context, arguments)).await?
        }
        "eliot_worktree_review" => {
            Box::pin(dispatch_worktree_review(state, context, arguments)).await?
        }
        "eliot_worktree_cleanup" => Box::pin(dispatch_worktree_cleanup(state, arguments)).await?,
        "eliot_blackboard_add" => Box::pin(dispatch_blackboard_add(state, arguments)).await?,
        "eliot_blackboard_list" => dispatch_blackboard_list(state, arguments)?,
        "eliot_blackboard_ack" => Box::pin(dispatch_blackboard_ack(state, arguments)).await?,
        "eliot_mailbox_send" => Box::pin(dispatch_mailbox_send(state, arguments)).await?,
        "eliot_mailbox_inbox" => dispatch_mailbox_inbox(state, arguments)?,
        "eliot_mailbox_ack" => Box::pin(dispatch_mailbox_ack(state, arguments)).await?,
        "eliot_recovery_scan" => Box::pin(dispatch_recovery_scan(state, arguments)).await?,
        "eliot_collective_trace" => Box::pin(dispatch_collective_trace(state, arguments)).await?,
        "eliot_runtime_status" => dispatch_runtime_status(state),
        "eliot_runtime_health" => dispatch_runtime_health(state)?,
        "eliot_module_list" => dispatch_module_list()?,
        "eliot_module_health" => dispatch_module_health()?,
        "eliot_logs_query" => dispatch_logs_query(state, arguments)?,
        "eliot_service_status" => dispatch_service_status(state)?,
        "eliot_ipc_status" => dispatch_ipc_status(state)?,
        "eliot_readiness_report" => dispatch_readiness_report(state)?,
        "eliot_startup_recovery_report" => dispatch_startup_recovery_report(state)?,
        "eliot_credentials_report" => dispatch_credentials_report(state)?,
        "eliot_adapter_list" => Box::pin(dispatch_adapter_list()).await?,
        "eliot_adapter_health" => Box::pin(dispatch_adapter_health()).await?,
        "eliot_adapter_inspect" => dispatch_adapter_inspect(arguments)?,
        "eliot_adapter_execute_test" => {
            Box::pin(dispatch_adapter_execute_test(state, arguments)).await?
        }
        "eliot_doctor_report" => dispatch_doctor_report(state)?,
        "eliot_data_root_status" => dispatch_data_root_status(state)?,
        "eliot_backup_report" => dispatch_latest_report_or_value(
            state,
            "backup",
            BackupService::new(&state.root).run(eliot_types::BackupKind::LogicalExport, true)?,
        )?,
        "eliot_restore_report" => dispatch_latest_report_or_value(
            state,
            "restore",
            RestoreService::new(&state.root).verify("latest")?,
        )?,
        "eliot_blob_report" => dispatch_blob_report(state)?,
        "eliot_maintenance_status" => dispatch_latest_report_or_value(
            state,
            "maintenance",
            MaintenanceScheduler::new(&state.root)
                .run_one_shot(MaintenanceJobKind::Doctor, true)?,
        )?,
        "eliot_incident_list" => dispatch_incident_list(state)?,
        _ => unreachable!("tool list pre-check guarantees known tool names"),
    };
    Ok(structured)
}

pub(super) fn current_state_with_bound_task(
    mut response: Value,
    bound_task_id: Option<TaskId>,
) -> Value {
    if let Some(task_id) = bound_task_id {
        response["task_id"] = json!(task_id);
    }
    response
}
