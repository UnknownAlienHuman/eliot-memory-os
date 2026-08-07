//! The evidence lifecycle: candidate in, verifier decides, claim out.
//!
//! Nothing in ELIOT is promoted because it was written. A candidate is
//! submitted as evidence, a registered verifier accepts or rejects it, and only
//! then does it become something later work may rely on. Submission and
//! verification are two halves of that one rule and are kept together, because
//! reading either alone tells you nothing about what is actually guaranteed.

use super::*;

#[allow(clippy::too_many_lines)]
pub(super) async fn dispatch_agent_candidate_submit(
    state: &McpState,
    context: AuthenticatedRequestContext,
    arguments: Value,
) -> Result<Value> {
    let submitted_body_sha256 = sha256_json(&arguments)?;
    let mut input: AgentCandidateSubmitInput = serde_json::from_value(arguments)?;
    validate_candidate_field("topic", &input.topic, 160)?;
    validate_candidate_field("statement", &input.statement, 4_000)?;
    validate_candidate_field("freshness_rule", &input.freshness_rule, 1_000)?;
    validate_candidate_field("expected_reuse_note", &input.expected_reuse_note, 200)?;
    validate_candidate_list("where_applicable", &input.where_applicable, 0, 32, 500)?;
    validate_candidate_list(
        "where_not_applicable",
        &input.where_not_applicable,
        0,
        32,
        500,
    )?;
    validate_candidate_list(
        "negative_constraints",
        &input.negative_constraints,
        0,
        32,
        500,
    )?;
    validate_candidate_list("provenance_refs", &input.provenance_refs, 1, 32, 1_000)?;
    if let Some(curation) = input.curation.as_ref() {
        validate_candidate_curation(curation)?;
    }
    let project_id = parse_project_id(&input.project_id)?;
    let binding_source;
    if input.cue_bindings.is_empty() {
        if input.auto_bind == Some(false) || state.profile == McpAccessProfile::CognitiveChild {
            return Err(invalid_cue_input_message(
                "CUE_BINDING_REQUIRED: provide cue_bindings or permit automatic binding",
            ));
        }
        input.cue_bindings = auto_candidate_bindings(state, context, project_id, &input)?;
        binding_source = "auto";
    } else {
        binding_source = "explicit";
    }
    let submitted_bindings = input.cue_bindings.clone();
    let normalized_bindings =
        eliot_types::normalize_bindings(input.cue_bindings, state.root.to_str())
            .map_err(|error| invalid_cue_input_message(&error.to_string()))?;
    if state.profile == McpAccessProfile::CognitiveChild
        && normalized_bindings != submitted_bindings
    {
        return Err(invalid_cue_input_message(
            "capability-bound cue_bindings must already be in canonical normalized form",
        ));
    }
    input.cue_bindings = normalized_bindings;
    let task_id = TaskId::from_str(&input.task_id).context("parse candidate task_id")?;
    let _task = require_task(state, project_id, task_id).await?;
    let write_id = WriteId::from_str(&input.write_id).context("parse candidate write id")?;
    let cognitive_claims = if state.profile == McpAccessProfile::CognitiveChild {
        let claims = state
            .cognitive_principals
            .lock()
            .await
            .get(&context.session_id)
            .cloned()
            .context("cognitive child session has no capability principal")?;
        let capability = &claims.capability;
        if capability.invocation_role != CognitiveInvocationRole::SourceWrite
            || capability.project_id != project_id
            || capability.task_id != task_id
            || capability.session_id != context.session_id
            || capability.expected_write_id != Some(write_id)
            || capability.expected_body_sha256.as_deref() != Some(submitted_body_sha256.as_str())
            || capability.expires_at <= time::OffsetDateTime::now_utc()
            || claims.capability_file != cognitive_capability_path(state, capability)
        {
            anyhow::bail!("candidate submission differs from its cognitive capability binding");
        }
        let attempt_revision = u64::from(capability.call_number) * 2 - 1;
        let attempt = cognitive_record_by_revision::<CognitiveRunAttempt>(
            state,
            project_id,
            task_id,
            &capability.run_id,
            attempt_revision,
            CanonicalReceiptKind::CognitiveRunAttempt,
        )
        .await?
        .context("cognitive candidate has no canonical attempt")?;
        if attempt.canonical_receipt != claims.attempt_receipt
            || attempt.receipt_body.status != CognitiveRunCallStatus::Attempting
            || attempt.receipt_body.capability.as_ref() != Some(capability)
            || attempt.receipt_body.candidate_write_id != Some(write_id)
        {
            anyhow::bail!("cognitive candidate capability is stale or differs from its attempt");
        }
        if cognitive_record_by_revision::<CognitiveRunTerminal>(
            state,
            project_id,
            task_id,
            &capability.run_id,
            attempt_revision + 1,
            CanonicalReceiptKind::CognitiveRunTerminal,
        )
        .await?
        .is_some()
        {
            anyhow::bail!("cognitive candidate capability was consumed by terminal state");
        }
        Some(claims)
    } else {
        None
    };
    if cognitive_claims.is_none() && state.store.write_receipt_by_id(&write_id).await?.is_none() {
        let existing = ReadService::new(state.store.clone())
            .fetch_atoms_l2(&FetchAtomsL2Request {
                project_id,
                handles: Vec::new(),
                continuation: None,
                consistency: ReadConsistencyMode::Latest,
                at_least_revision: None,
            })
            .await?;
        if let Some(claim) = existing_candidate_with_same_topic_and_statement(
            &existing.claims,
            task_id,
            &input.topic,
            &input.statement,
        ) {
            return Ok(json!({
                "status": "candidate_already_present",
                "candidate_only": true,
                "controller_reconciliation_required": true,
                "existing_claim_id": claim.claim_id,
                "at_revision": existing.at_revision,
                "cue_binding_summary": cue_binding_summary(binding_source, &input.cue_bindings),
                "reason": "an active candidate with the same normalized topic and statement already exists; no duplicate write was committed"
            }));
        }
    }
    let mut payload = json!({
        "candidate_only": true,
        "controller_reconciliation_required": true,
        "profile": state.profile.as_str(),
        "task_id": task_id,
        "topic": input.topic,
        "statement": input.statement,
        "where_applicable": input.where_applicable,
        "where_not_applicable": input.where_not_applicable,
        "negative_constraints": input.negative_constraints,
        "provenance_refs": input.provenance_refs,
        "freshness_rule": input.freshness_rule,
        "cue_bindings": input.cue_bindings.clone(),
        "expected_reuse_note": input.expected_reuse_note,
        "curation": input.curation
    });
    if context.bound_project_id == Some(project_id) && context.bound_task_id == Some(task_id) {
        payload
            .as_object_mut()
            .context("candidate payload must be an object")?
            .insert("agent_session_id".to_owned(), json!(context.session_id));
    }
    let payload = if let Some(claims) = cognitive_claims.as_ref() {
        let mut payload = payload;
        let object = payload
            .as_object_mut()
            .context("candidate payload must be an object")?;
        object.insert(
            "cognitive_run_id".to_owned(),
            json!(claims.capability.run_id),
        );
        object.insert(
            "cognitive_call_id".to_owned(),
            json!(claims.capability.call_id),
        );
        object.insert(
            "cognitive_call_number".to_owned(),
            json!(claims.capability.call_number),
        );
        object.insert("cognitive_host".to_owned(), json!(claims.capability.host));
        object.insert("cognitive_session_id".to_owned(), json!(context.session_id));
        object.insert(
            "cognitive_body_sha256".to_owned(),
            json!(submitted_body_sha256),
        );
        object.insert(
            "cognitive_attempt_receipt".to_owned(),
            json!(claims.attempt_receipt),
        );
        payload
    } else {
        payload
    };
    let statement = payload
        .get("statement")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let claim_id = ClaimId::from_uuid(write_id.as_uuid());
    let governor_bound =
        context.bound_project_id == Some(project_id) && context.bound_task_id == Some(task_id);
    let bound_session =
        (cognitive_claims.is_some() || governor_bound).then_some(context.session_id);
    let command = SemanticCommand::ClaimPropose(eliot_types::ClaimProposeCommand {
        context: CommandContext {
            write_id,
            agent_id: AgentId::from_uuid(
                bound_session.map_or(write_id.as_uuid(), eliot_types::SessionId::as_uuid),
            ),
            session_id: bound_session,
            project_id,
            task_id: Some(task_id),
            scope: format!("task:{task_id}:agent-candidate-memory"),
            authority: format!("mcp-profile:{}", state.profile.as_str()),
            visibility: Visibility::Project,
            taint: TaintClass::ExternalAgent,
            lifecycle_status: LifecycleStatus::Active,
        },
        claim: ClaimCardInput {
            claim_id,
            statement: statement.clone(),
            status: EpistemicStatus::Candidate,
            payload,
        },
    });
    let receipt = state
        .writer
        .submit(WriteAdmissionService.admit(&command)?)
        .await?;
    let cue_projection_status = state
        .store
        .cognitive_projection_family_states(project_id)
        .await?
        .into_iter()
        .find(|family| family.family == eliot_store::CognitiveProjectionFamily::Cue)
        .map_or("unavailable", |family| {
            if family.status == eliot_store::CognitiveProjectionPublicationStatus::Published
                && receipt.memory_revision.is_some_and(|revision| {
                    family
                        .applied_revision
                        .is_none_or(|applied| applied < revision)
                })
            {
                "stale"
            } else {
                family.status.as_str()
            }
        });
    Ok(json!({
        "status": "candidate_committed",
        "candidate_only": true,
        "controller_reconciliation_required": true,
        "write_receipt": receipt,
        "cue_projection_status": cue_projection_status,
        "cue_binding_summary": cue_binding_summary(binding_source, &input.cue_bindings),
        "cognitive_binding": cognitive_claims.map(|claims| json!({
            "run_id": claims.capability.run_id,
            "call_id": claims.capability.call_id,
            "call_number": claims.capability.call_number,
            "host": claims.capability.host,
            "session_id": claims.capability.session_id,
            "write_id": claims.capability.expected_write_id,
            "body_sha256": claims.capability.expected_body_sha256,
            "attempt_receipt": claims.attempt_receipt,
        }))
    }))
}

fn auto_candidate_bindings(
    state: &McpState,
    context: AuthenticatedRequestContext,
    project_id: ProjectId,
    input: &AgentCandidateSubmitInput,
) -> Result<Vec<eliot_types::CueBinding>> {
    let recent = state
        .ul
        .touched
        .recent_cues(project_id, context.session_id, 16);
    let corpus = [
        input.topic.as_str(),
        input.statement.as_str(),
        &input.provenance_refs.join(" "),
    ]
    .join(" ")
    .chars()
    .flat_map(char::to_lowercase)
    .collect::<String>();
    let mut selected = Vec::new();
    for cue in &recent {
        let value = cue
            .value
            .chars()
            .flat_map(char::to_lowercase)
            .collect::<String>();
        if !value.is_empty() && corpus.contains(&value) {
            selected.push((cue.clone(), eliot_types::CueStrength::Primary));
        }
    }
    if selected.is_empty()
        && let Some(cue) = recent.iter().find(|cue| {
            matches!(
                cue.kind,
                eliot_types::CueKind::FilePath | eliot_types::CueKind::Symbol
            )
        })
    {
        selected.push((cue.clone(), eliot_types::CueStrength::Primary));
    }
    for cue in recent {
        if selected.len() >= 5 {
            break;
        }
        if !selected.iter().any(|(selected, _)| selected == &cue) {
            selected.push((cue, eliot_types::CueStrength::Secondary));
        }
    }
    if selected.is_empty() {
        return Err(invalid_cue_input_message(
            "CUE_BINDING_REQUIRED: the session touched set has no reusable cue",
        ));
    }
    selected
        .into_iter()
        .take(5)
        .map(|(cue, strength)| {
            Ok(eliot_types::CueBinding {
                match_mode: match cue.kind {
                    eliot_types::CueKind::DirPath => eliot_types::CueMatchMode::Prefix,
                    eliot_types::CueKind::ErrorSignature => eliot_types::CueMatchMode::Signature,
                    _ => eliot_types::CueMatchMode::Exact,
                },
                cue_kind: cue.kind,
                cue_value: cue.value,
                strength,
                expected_reuse_note: input.expected_reuse_note.clone(),
            })
        })
        .collect()
}

fn cue_binding_summary(source: &str, bindings: &[eliot_types::CueBinding]) -> Value {
    json!({
        "source": source,
        "primary": bindings
            .iter()
            .filter(|binding| binding.strength == eliot_types::CueStrength::Primary)
            .count(),
        "secondary": bindings
            .iter()
            .filter(|binding| binding.strength == eliot_types::CueStrength::Secondary)
            .count()
    })
}

fn invalid_cue_input_message(reason: &str) -> anyhow::Error {
    eliot_types::ToolInputError {
        data: eliot_types::ToolInputErrorData {
            code: "INVALID_TOOL_INPUT".to_owned(),
            missing: Vec::new(),
            invalid: vec![eliot_types::InvalidField {
                field: "cue_bindings".to_owned(),
                reason: reason.to_owned(),
            }],
            minimal_valid_example: json!({
                "cue_bindings": [{
                    "cue_kind": "file_path",
                    "cue_value": "crates/eliot-store/src/lib.rs",
                    "match_mode": "exact",
                    "strength": "primary",
                    "expected_reuse_note": "Reuse when editing the canonical store."
                }],
                "expected_reuse_note": "Reuse when the same project area is active."
            }),
        },
    }
    .into()
}

pub(super) fn existing_candidate_with_same_topic_and_statement<'a>(
    claims: &'a [eliot_types::ClaimCard],
    task_id: TaskId,
    topic: &str,
    statement: &str,
) -> Option<&'a eliot_types::ClaimCard> {
    let topic = normalize_candidate_text(topic);
    let statement = normalize_candidate_text(statement);
    claims.iter().find(|claim| {
        claim.status == EpistemicStatus::Candidate
            && claim.payload.get("candidate_only").and_then(Value::as_bool) == Some(true)
            && claim
                .payload
                .get("task_id")
                .and_then(Value::as_str)
                .is_some_and(|candidate_task_id| candidate_task_id == task_id.to_string())
            && claim
                .payload
                .get("topic")
                .and_then(Value::as_str)
                .is_some_and(|existing| normalize_candidate_text(existing) == topic)
            && normalize_candidate_text(&claim.statement) == statement
    })
}

pub(super) fn normalize_candidate_text(value: &str) -> String {
    value.split_whitespace().collect::<Vec<_>>().join(" ")
}

pub(super) fn validate_candidate_field(name: &str, value: &str, max_bytes: usize) -> Result<()> {
    if value.trim().is_empty() || value.len() > max_bytes {
        anyhow::bail!("candidate {name} must be non-empty and no larger than {max_bytes} bytes");
    }
    Ok(())
}

pub(super) fn validate_candidate_curation(curation: &AgentCandidateCurationInput) -> Result<()> {
    validate_candidate_field("curation.handle", &curation.handle, 256)?;
    for (name, value, max_bytes) in [
        (
            "curation.duplicate_of",
            curation.duplicate_of.as_deref(),
            256,
        ),
        (
            "curation.semantic_duplicate_of",
            curation.semantic_duplicate_of.as_deref(),
            256,
        ),
        (
            "curation.superseded_by",
            curation.superseded_by.as_deref(),
            256,
        ),
        (
            "curation.stale_reason_ref",
            curation.stale_reason_ref.as_deref(),
            256,
        ),
        ("curation.role", curation.role.as_deref(), 64),
        ("curation.lifecycle", curation.lifecycle.as_deref(), 64),
        ("curation.authority", curation.authority.as_deref(), 128),
    ] {
        if let Some(value) = value {
            validate_candidate_field(name, value, max_bytes)?;
        }
    }
    validate_candidate_list(
        "curation.wrong_scope_for",
        &curation.wrong_scope_for,
        0,
        32,
        500,
    )?;
    validate_candidate_list(
        "curation.repeated_with",
        &curation.repeated_with,
        0,
        32,
        500,
    )?;
    validate_candidate_list(
        "curation.unsafe_evidence_refs",
        &curation.unsafe_evidence_refs,
        0,
        32,
        500,
    )?;
    validate_candidate_list(
        "curation.evidence_refs",
        &curation.evidence_refs,
        0,
        32,
        500,
    )?;
    validate_candidate_list(
        "curation.counterevidence_refs",
        &curation.counterevidence_refs,
        0,
        32,
        500,
    )?;
    Ok(())
}

pub(super) fn validate_candidate_list(
    name: &str,
    values: &[String],
    min_items: usize,
    max_items: usize,
    max_item_bytes: usize,
) -> Result<()> {
    if values.len() < min_items || values.len() > max_items {
        anyhow::bail!("candidate {name} must contain {min_items}-{max_items} items");
    }
    for value in values {
        validate_candidate_field(name, value, max_item_bytes)?;
    }
    Ok(())
}

pub(super) fn finalize_verifier_scope_hash(scope: &mut VerifierArtifactScope) -> Result<()> {
    scope.canonical_scope_hash.clear();
    scope.canonical_scope_hash = canonical_struct_hash(scope)?;
    Ok(())
}

pub(super) fn verifier_scope_hash_is_valid(scope: &VerifierArtifactScope) -> Result<bool> {
    let expected = scope.canonical_scope_hash.clone();
    let mut material = scope.clone();
    material.canonical_scope_hash.clear();
    Ok(canonical_struct_hash(&material)? == expected)
}

pub(super) async fn run_registered_cargo_verifier(
    worktree: &Path,
    args: &[&str],
    timeout_seconds: u64,
    verifier_name: &str,
) -> Result<()> {
    let mut command = tokio::process::Command::new("cargo");
    command
        .current_dir(worktree)
        .args(args)
        .env("ELIOT_DISABLE_REAL_PROVIDER", "1")
        .env_remove("SURREAL_USER")
        .env_remove("SURREAL_PASS")
        .env_remove("ELIOT_TEST_SURREAL_ENDPOINT")
        .kill_on_drop(true);
    let output = tokio::time::timeout(
        std::time::Duration::from_secs(timeout_seconds),
        command.output(),
    )
    .await
    .with_context(|| format!("registered {verifier_name} verifier timed out"))??;
    if !output.status.success() {
        anyhow::bail!("registered {verifier_name} verifier failed");
    }
    Ok(())
}

pub(super) async fn run_dogfood_blob_verifier(worktree: &Path) -> Result<()> {
    run_registered_cargo_verifier(
        worktree,
        &[
            "test",
            "--offline",
            "-p",
            "eliot-store",
            DOGFOOD_BLOB_TEST,
            "--",
            "--exact",
            "--test-threads=1",
        ],
        120,
        "dogfood blob integrity",
    )
    .await
}

pub(super) async fn run_cargo_workspace_check_verifier(worktree: &Path) -> Result<()> {
    run_registered_cargo_verifier(
        worktree,
        &[
            "check",
            "--workspace",
            "--all-targets",
            "--all-features",
            "--offline",
        ],
        300,
        "workspace cargo check",
    )
    .await
}

#[allow(clippy::too_many_lines)]
pub(super) async fn resolve_verifier_artifact_scope(
    project_id: ProjectId,
    task: &TaskContract,
    verification_id: VerificationId,
    observation_receipt: &eliot_types::WriteReceipt,
    verifier: RegisteredTaskVerifier,
    input: &TaskVerificationToolInput,
) -> Result<VerifierArtifactScope> {
    let config_hash = verifier.config_hash();
    if input.verifier_ref != verifier.reference()
        || input.verifier_config_hash != config_hash
        || input.acceptance_item_ids != [input.item_id.clone()]
    {
        anyhow::bail!("verifier reference, config hash, or acceptance mapping is stale");
    }
    let observed_at = time::OffsetDateTime::now_utc();
    let mut scope = match verifier {
        RegisteredTaskVerifier::ReceiptResolution => {
            if input.worktree_ref.is_some() || !input.artifact_paths.is_empty() {
                anyhow::bail!(
                    "receipt verifier scope is daemon-resolved and accepts no path labels"
                );
            }
            VerifierArtifactScope {
                verification_id,
                verifier_id: verifier.id().to_owned(),
                verifier_version: VERIFIER_VERSION.to_owned(),
                config_hash,
                project_id,
                task_id: task.task_id,
                branch: "canonical".to_owned(),
                commit: observation_receipt
                    .memory_revision
                    .context("observation receipt lacks memory revision")?
                    .value()
                    .to_string(),
                dirty_state_hash: observation_receipt.input_hash.clone(),
                worktree_ref: format!("canonical://project/{project_id}/task/{}", task.task_id),
                artifact_refs: vec![VerifierArtifactRef {
                    resource_ref: format!("eliot/write-receipt/{}", observation_receipt.write_id),
                    content_hash: observation_receipt.input_hash.clone(),
                }],
                path_or_resource_scope: format!(
                    "eliot/write-receipt/{}",
                    observation_receipt.write_id
                ),
                acceptance_item_ids: input.acceptance_item_ids.clone(),
                observed_at,
                expires_or_invalidates_on: vec![
                    "receipt deletion or replacement".to_owned(),
                    "task or project mismatch".to_owned(),
                    "verifier registry config change".to_owned(),
                ],
                canonical_scope_hash: String::new(),
            }
        }
        RegisteredTaskVerifier::DogfoodBlobIntegrity
        | RegisteredTaskVerifier::CargoWorkspaceCheck => {
            let provenance = task
                .action_provenance
                .as_ref()
                .context("git verifier requires stored action provenance")?;
            let expected_worktree = provenance
                .source_scope
                .worktree_ref
                .as_deref()
                .context("git action provenance lacks worktree")?;
            let expected_branch = provenance
                .source_scope
                .branch
                .as_deref()
                .context("git action provenance lacks branch")?;
            let baseline_commit = provenance
                .source_scope
                .baseline_commit
                .as_deref()
                .context("git action provenance lacks baseline commit")?;
            if input.worktree_ref.as_deref() != Some(expected_worktree)
                || input.artifact_paths != provenance.source_scope.artifact_paths
            {
                anyhow::bail!("verifier worktree or artifact paths differ from the ActionLease");
            }
            let before =
                resolve_git_artifact_snapshot(expected_worktree, &input.artifact_paths).await?;
            if !before.clean || before.branch != expected_branch || before.commit == baseline_commit
            {
                anyhow::bail!(
                    "git verifier requires a clean candidate commit on the leased branch"
                );
            }
            let ancestor = run_git(
                &before.root,
                &[
                    "merge-base",
                    "--is-ancestor",
                    baseline_commit,
                    &before.commit,
                ],
            )
            .await?;
            if !ancestor.status.success() {
                anyhow::bail!("candidate commit is not descended from the leased baseline");
            }
            let changed = checked_command_text(
                run_git(
                    &before.root,
                    &["diff", "--name-only", baseline_commit, &before.commit],
                )
                .await?,
                "resolve candidate changed paths",
            )?;
            let mut changed_paths = changed
                .lines()
                .filter(|line| !line.trim().is_empty())
                .map(str::to_owned)
                .collect::<Vec<_>>();
            changed_paths.sort();
            let mut allowed_paths = input.artifact_paths.clone();
            allowed_paths.sort();
            if changed_paths.is_empty()
                || changed_paths
                    .iter()
                    .any(|path| !allowed_paths.contains(path))
            {
                anyhow::bail!(
                    "candidate commit changed files outside the registered artifact scope"
                );
            }
            match verifier {
                RegisteredTaskVerifier::DogfoodBlobIntegrity => {
                    run_dogfood_blob_verifier(&before.root).await?;
                }
                RegisteredTaskVerifier::CargoWorkspaceCheck => {
                    run_cargo_workspace_check_verifier(&before.root).await?;
                }
                RegisteredTaskVerifier::ReceiptResolution => unreachable!(),
            }
            let after =
                resolve_git_artifact_snapshot(expected_worktree, &input.artifact_paths).await?;
            if !after.clean
                || after.branch != before.branch
                || after.commit != before.commit
                || after.dirty_state_hash != before.dirty_state_hash
                || after.artifact_refs != before.artifact_refs
            {
                anyhow::bail!("registered verifier mutated or changed its artifact scope");
            }
            VerifierArtifactScope {
                verification_id,
                verifier_id: verifier.id().to_owned(),
                verifier_version: VERIFIER_VERSION.to_owned(),
                config_hash,
                project_id,
                task_id: task.task_id,
                branch: before.branch,
                commit: before.commit,
                dirty_state_hash: before.dirty_state_hash,
                worktree_ref: before.root.display().to_string(),
                artifact_refs: before.artifact_refs,
                path_or_resource_scope: allowed_paths.join(","),
                acceptance_item_ids: input.acceptance_item_ids.clone(),
                observed_at,
                expires_or_invalidates_on: vec![
                    "branch or commit change".to_owned(),
                    "dirty-state change".to_owned(),
                    "artifact content change".to_owned(),
                    "worktree identity change".to_owned(),
                    "verifier registry config change".to_owned(),
                ],
                canonical_scope_hash: String::new(),
            }
        }
    };
    finalize_verifier_scope_hash(&mut scope)?;
    Ok(scope)
}

#[allow(clippy::too_many_lines)]
pub(super) async fn dispatch_task_verification_run(
    state: &McpState,
    context: AuthenticatedRequestContext,
    arguments: Value,
) -> Result<Value> {
    let verification_started_at = time::OffsetDateTime::now_utc();
    let input: TaskVerificationToolInput = serde_json::from_value(arguments)?;
    if input.mode == "candidate_assertion" {
        return Ok(json!({
            "status": "denied",
            "reason": "candidate output cannot issue verified authority",
            "write_receipt": Value::Null
        }));
    }
    if input.mode != "registered" {
        return Ok(json!({
            "status": "denied_invalid_verifier_scope",
            "reason": "only a registered verifier with typed daemon-resolved scope is authoritative",
            "write_receipt": Value::Null
        }));
    }
    let project_id = parse_project_id(&input.project_id)?;
    let task_id = TaskId::from_str(&input.task_id).context("parse task id")?;
    let _task_guard = task_commit_serializer().lock().await;
    let _task_process_guard = acquire_task_transition_process_lock(&state.root, task_id).await?;
    let write_id = WriteId::from_str(&input.write_id).context("parse write id")?;
    let observation_write_id =
        WriteId::from_str(&input.observation_id).context("parse observation id")?;
    let mut task = require_task(state, project_id, task_id).await?;
    ensure_expected_revision_or_replay(state, &task, input.expected_revision, write_id).await?;
    let provenance = task
        .action_provenance
        .clone()
        .context("verification requires resolved action provenance")?;
    if input.provenance_set_hash != provenance.hash {
        return Ok(json!({
            "status": "denied_invalid_verifier_scope",
            "reason": "provenance hash changed after ActionLease issuance",
            "write_receipt": Value::Null
        }));
    }
    if input.verifier_ref != provenance.planned_verifier_ref {
        return Ok(json!({
            "status": "denied_invalid_verifier_scope",
            "reason": "verifier reference changed after ActionLease issuance",
            "provided_verifier_ref": input.verifier_ref,
            "leased_verifier_ref": provenance.planned_verifier_ref,
            "write_receipt": Value::Null
        }));
    }
    let Some(verifier) = RegisteredTaskVerifier::from_reference(&input.verifier_ref) else {
        return Ok(json!({
            "status": "denied_invalid_verifier_scope",
            "reason": "verifier reference is unregistered or stale",
            "write_receipt": Value::Null
        }));
    };
    if !task.observation_ids.contains(&input.observation_id) {
        anyhow::bail!("verifier observation is not bound to this TaskContract");
    }
    let observation_receipt = state
        .store
        .write_receipt_by_id(&observation_write_id)
        .await?
        .context("observation WriteReceipt does not resolve")?;
    if observation_receipt.project_id != project_id || observation_receipt.task_id != Some(task_id)
    {
        anyhow::bail!("observation WriteReceipt scope does not match task");
    }
    let verification_id = VerificationId::from_uuid(write_id.as_uuid());
    let observation_item_is_satisfied = task.acceptance_items.iter().any(|item| {
        item.required_evidence == TaskAcceptanceEvidenceKind::Observation
            && item.satisfied
            && item.observation_id.as_deref() == Some(input.observation_id.as_str())
    });
    if !observation_item_is_satisfied {
        anyhow::bail!("verifier requires a satisfied candidate observation in this task");
    }
    let scope = match resolve_verifier_artifact_scope(
        project_id,
        &task,
        verification_id,
        &observation_receipt,
        verifier,
        &input,
    )
    .await
    {
        Ok(scope) => scope,
        Err(error) => {
            return Ok(json!({
                "status": "denied_invalid_verifier_scope",
                "reason": error.to_string(),
                "write_receipt": Value::Null
            }));
        }
    };
    let item = task
        .acceptance_items
        .iter_mut()
        .find(|item| item.item_id == input.item_id)
        .context("verification acceptance item not found")?;
    if item.required_evidence != TaskAcceptanceEvidenceKind::Verification {
        anyhow::bail!("acceptance item requires observation evidence");
    }
    item.satisfied = true;
    item.observation_id = Some(input.observation_id.clone());
    item.verification_id = Some(verification_id);
    item.verification_scope_hash = Some(scope.canonical_scope_hash.clone());
    if !task.verification_ids.contains(&verification_id) {
        task.verification_ids.push(verification_id);
    }
    task.verification_scopes
        .retain(|existing| existing.verification_id != verification_id);
    task.verification_scopes.push(scope.clone());
    let verification = VerificationRunInput {
        verification_id,
        claim_id: None,
        verifier: verifier.id().to_owned(),
        result: VerificationResult::Passed,
        summary: "registered verifier passed in daemon-resolved canonical artifact scope"
            .to_owned(),
        payload: json!({
            "task_id": task_id,
            "verifier": verifier.id(),
            "artifact_scope": scope.clone(),
            "observation_id": input.observation_id,
            "observation_receipt_id": observation_receipt.receipt_id,
            "task_revision": input.expected_revision,
            "authority": "daemon_local_verifier"
        }),
    };
    let contract = task_input(&task, Some(MemoryRevision::new(input.expected_revision)));
    let (receipt, task) = submit_task_transition(
        state,
        context,
        project_id,
        write_id,
        contract,
        "daemon-local-verifier",
        TaintClass::LocalVerified,
        TaskTransitionEvidence {
            observation: None,
            verification: Some(verification),
        },
    )
    .await?;
    let verification_ref = format!("verification:{verification_id}");
    let mut prediction_resolution = match state
        .ul
        .prediction
        .resolve(
            project_id,
            task_id,
            verifier.id(),
            VerificationResult::Passed,
            &verification_ref,
            verification_started_at,
        )
        .await
    {
        Ok(records) => json!({
            "status": "resolved",
            "count": records.len(),
            "prediction_refs": records
                .iter()
                .map(|record| format!("prediction:{}", record.prediction_id))
                .collect::<Vec<_>>(),
        }),
        Err(error) => json!({
            "status": "measurement_error",
            "message": error.to_string(),
        }),
    };
    let changed_paths = scope
        .artifact_refs
        .iter()
        .map(|artifact| artifact.resource_ref.clone())
        .collect::<Vec<_>>();
    let blast_resolution = match state
        .ul
        .prediction
        .resolve_blast(
            project_id,
            task_id,
            &changed_paths,
            &[],
            &verification_ref,
            verification_started_at,
        )
        .await
    {
        Ok(records) => json!({
            "status": "resolved",
            "count": records.len(),
            "prediction_refs": records
                .iter()
                .map(|record| format!("prediction:{}", record.prediction_id))
                .collect::<Vec<_>>(),
        }),
        Err(error) => json!({
            "status": "measurement_error",
            "message": error.to_string(),
        }),
    };
    prediction_resolution["blast_radius"] = blast_resolution;
    Ok(json!({
        "status": "passed",
        "verification_id": verification_id,
        "verifier": verifier.id(),
        "artifact_scope": scope,
        "task_contract": task,
        "write_receipt": receipt,
        "ul_prediction_resolution": prediction_resolution
    }))
}

pub(super) fn registered_verifier_for_scope(
    scope: &VerifierArtifactScope,
) -> Option<RegisteredTaskVerifier> {
    RegisteredTaskVerifier::ALL.into_iter().find(|verifier| {
        scope.verifier_id == verifier.id()
            && scope.verifier_version == VERIFIER_VERSION
            && scope.config_hash == verifier.config_hash()
    })
}

pub(super) async fn revalidate_verifier_scope(
    state: &McpState,
    task: &TaskContract,
    scope: &VerifierArtifactScope,
) -> Result<()> {
    if !verifier_scope_hash_is_valid(scope)?
        || scope.project_id != task.project_id
        || scope.task_id != task.task_id
    {
        anyhow::bail!("stored verifier scope hash or task identity is invalid");
    }
    let verifier = registered_verifier_for_scope(scope)
        .context("stored verifier registry entry is stale or unavailable")?;
    match verifier {
        RegisteredTaskVerifier::ReceiptResolution => {
            let artifact = scope
                .artifact_refs
                .as_slice()
                .first()
                .filter(|_| scope.artifact_refs.len() == 1)
                .context("receipt verifier scope must contain exactly one artifact")?;
            let write_id = artifact
                .resource_ref
                .strip_prefix("eliot/write-receipt/")
                .context("receipt verifier artifact reference is malformed")?;
            let write_id = WriteId::from_str(write_id)?;
            let receipt = state
                .store
                .write_receipt_by_id(&write_id)
                .await?
                .context("verified observation receipt no longer resolves")?;
            if receipt.project_id != task.project_id
                || receipt.task_id != Some(task.task_id)
                || receipt.input_hash != artifact.content_hash
                || scope.dirty_state_hash != receipt.input_hash
                || scope.commit
                    != receipt
                        .memory_revision
                        .context("verified receipt lost its memory revision")?
                        .value()
                        .to_string()
                || scope.path_or_resource_scope != artifact.resource_ref
                || scope.worktree_ref
                    != format!(
                        "canonical://project/{}/task/{}",
                        task.project_id, task.task_id
                    )
            {
                anyhow::bail!("canonical receipt artifact scope changed after verification");
            }
        }
        RegisteredTaskVerifier::DogfoodBlobIntegrity
        | RegisteredTaskVerifier::CargoWorkspaceCheck => {
            let provenance = task
                .action_provenance
                .as_ref()
                .context("git verifier scope lost its action provenance")?;
            if provenance.planned_verifier_ref != verifier.reference()
                || provenance.source_scope.worktree_ref.as_deref()
                    != Some(scope.worktree_ref.as_str())
                || provenance.source_scope.branch.as_deref() != Some(scope.branch.as_str())
            {
                anyhow::bail!("git verifier scope no longer matches its ActionLease");
            }
            let artifact_paths = scope
                .artifact_refs
                .iter()
                .map(|artifact| artifact.resource_ref.clone())
                .collect::<Vec<_>>();
            let current =
                resolve_git_artifact_snapshot(&scope.worktree_ref, &artifact_paths).await?;
            if !current.clean
                || current.branch != scope.branch
                || current.commit != scope.commit
                || current.dirty_state_hash != scope.dirty_state_hash
                || current.artifact_refs != scope.artifact_refs
            {
                anyhow::bail!("git artifact state changed after the registered verifier ran");
            }
        }
    }
    Ok(())
}

pub(super) fn remove_protected_curation_candidates(
    candidates: &mut Vec<MemoryCurationCandidate>,
    sorted_protected_refs: &[String],
) {
    candidates.retain(|candidate| {
        sorted_protected_refs
            .binary_search(&candidate.handle)
            .is_err()
    });
}

pub(super) fn verification_id_from_ref(reference: &str) -> Result<VerificationId> {
    let value = reference
        .trim()
        .strip_prefix("verification:")
        .unwrap_or(reference.trim());
    VerificationId::from_str(value).context("parse canonical verification reference")
}

pub(super) fn canonical_verifier_matches_required(
    required: &str,
    verifier: &CanonicalAutonomyVerifierEvidence,
) -> bool {
    [
        verifier.registered_name.as_str(),
        verifier.profile_ref.as_str(),
        verifier.command.as_str(),
        verifier.verifier_ref.as_str(),
    ]
    .iter()
    .any(|candidate| candidate.eq_ignore_ascii_case(required.trim()))
}

pub(super) fn require_exact_canonical_verifier_set(
    required_verifiers: &[String],
    resolved: &[CanonicalAutonomyVerifierEvidence],
) -> Result<()> {
    if required_verifiers.iter().any(|required| {
        !resolved
            .iter()
            .any(|verifier| canonical_verifier_matches_required(required, verifier))
    }) || resolved.iter().any(|verifier| {
        !required_verifiers
            .iter()
            .any(|required| canonical_verifier_matches_required(required, verifier))
    }) {
        anyhow::bail!("canonical verifier refs do not exactly bind the required verifier set");
    }
    Ok(())
}

pub(super) fn require_completion_proof_verifier_binding(
    proof: &CompletionProof,
    verifiers: &[CanonicalAutonomyVerifierEvidence],
) -> Result<()> {
    for verifier in verifiers {
        if !proof.checks_run.contains(&verifier.command)
            || !proof.evidence.contains(&verifier.canonical_ref)
            || !proof.evidence.contains(&verifier.artifact_scope_hash)
        {
            anyhow::bail!(
                "CompletionProof omits exact verifier command, run ref, or artifact scope hash"
            );
        }
        let acceptance_bound = proof.acceptance_items.iter().any(|item| {
            item.status == "verified"
                && [
                    verifier.registered_name.as_str(),
                    verifier.profile_ref.as_str(),
                    verifier.command.as_str(),
                    verifier.verifier_ref.as_str(),
                ]
                .iter()
                .any(|name| name.eq_ignore_ascii_case(item.verifier.trim()))
                && (item.evidence.contains(&verifier.canonical_ref)
                    || item.evidence.contains(&verifier.artifact_scope_hash))
        });
        if !acceptance_bound {
            anyhow::bail!("CompletionProof acceptance does not bind the exact verifier evidence");
        }
    }
    Ok(())
}

pub(super) fn candidate_promotion_replay_matches(
    candidate: &CanonicalClaimCard,
    task_id: TaskId,
    idempotency_key: &str,
    evidence_refs: &[String],
) -> bool {
    let disposition = candidate.payload.get("operator_candidate_disposition");
    candidate.status == EpistemicStatus::Verified
        && candidate.task_id == Some(task_id)
        && disposition
            .and_then(|value| value.get("disposition"))
            .and_then(Value::as_str)
            == Some("promote")
        && disposition.and_then(|value| value.get("task_id")) == Some(&json!(task_id))
        && disposition
            .and_then(|value| value.get("idempotency_key"))
            .and_then(Value::as_str)
            == Some(idempotency_key)
        && disposition.and_then(|value| value.get("evidence_refs")) == Some(&json!(evidence_refs))
}

pub(super) async fn require_candidate_disposition_actor(
    state: &McpState,
    context: AuthenticatedRequestContext,
    task: &TaskContract,
) -> Result<CandidateDispositionActor> {
    let actor = AgentSessionId::from_uuid(context.session_id.as_uuid());
    let broker = delegation_runtime::load_state(&state.root)?;
    let now = time::OffsetDateTime::now_utc();
    let eligible_roles = broker
        .task_role_leases
        .iter()
        .filter(|role| {
            role.task_id == task.task_id
                && role.agent_session_id == actor
                && role.expires_at > now
                && role
                    .capability_scope
                    .iter()
                    .any(|capability| matches!(capability.as_str(), "review" | "review_candidate"))
                && match state.profile {
                    McpAccessProfile::HumanOperator => role.role == AgentRole::Reviewer,
                    McpAccessProfile::CodexController => role.role == AgentRole::Controller,
                    _ => false,
                }
        })
        .collect::<Vec<_>>();
    let [role] = eligible_roles.as_slice() else {
        anyhow::bail!(
            "candidate disposition requires one active canonical reviewer/controller role lease"
        );
    };
    require_exact_current_projection(
        state,
        task.project_id,
        Some(task.task_id),
        "task_role_lease",
        &role.role_lease_id,
        "receipt_body",
        Some("host_role_lease_authority"),
        *role,
    )
    .await?;
    let controller_lease_id = if role.role == AgentRole::Controller {
        let controllers = broker
            .controller_leases
            .iter()
            .filter(|lease| {
                lease.task_id == task.task_id
                    && lease.agent_session_id == actor
                    && lease.expires_at > now
            })
            .collect::<Vec<_>>();
        let [controller] = controllers.as_slice() else {
            anyhow::bail!(
                "controller candidate disposition requires one active canonical ControllerLease"
            );
        };
        require_exact_current_projection(
            state,
            task.project_id,
            Some(task.task_id),
            "controller_lease",
            &controller.controller_lease_id,
            "receipt_body",
            Some("controller_lease"),
            *controller,
        )
        .await?;
        Some(controller.controller_lease_id.clone())
    } else {
        None
    };
    Ok(CandidateDispositionActor {
        role_lease_id: role.role_lease_id.clone(),
        controller_lease_id,
    })
}

pub(super) async fn existing_candidate_promotion(
    state: &McpState,
    promotion: &CandidatePromotion<'_>,
    write_id: WriteId,
) -> Result<Option<WriteReceiptRef>> {
    if let Some(receipt) = state.store.write_receipt_by_id(&write_id).await? {
        if receipt.project_id == promotion.task.project_id
            && receipt.task_id == Some(promotion.task.task_id)
            && receipt.command_kind == SemanticCommandKind::ClaimVerify
            && candidate_promotion_replay_matches(
                promotion.candidate,
                promotion.task.task_id,
                promotion.idempotency_key,
                promotion.evidence_refs,
            )
        {
            return Ok(Some(WriteReceiptRef {
                receipt_id: receipt.receipt_id,
                write_id: receipt.write_id,
            }));
        }
        anyhow::bail!("operator idempotency_key was already used for a different candidate review");
    }
    Ok(None)
}

pub(super) fn task_verifier_artifacts(task: &TaskContract) -> Vec<VerifierArtifactRef> {
    task.verification_scopes
        .iter()
        .flat_map(|scope| &scope.artifact_refs)
        .filter(|artifact| is_canonical_hash(&artifact.content_hash))
        .filter(|artifact| !artifact.resource_ref.trim().is_empty())
        .cloned()
        .collect()
}

pub(super) fn validate_procedure_candidate_source_refs(
    task: &TaskContract,
    pattern: &ExperiencePattern,
    candidate: &SkillCardV2,
) -> Result<()> {
    let mut allowed = task_evidence_refs(task);
    allowed.extend(pattern.member_case_refs.iter().cloned());
    allowed.extend(pattern.authority.exact_source_refs.iter().cloned());
    allowed.extend(pattern.transfer_evidence.iter().cloned());
    if candidate
        .source_trace_refs
        .iter()
        .any(|source_ref| !allowed.contains(source_ref))
    {
        anyhow::bail!(
            "procedure candidate source_trace_refs must resolve through the exact pattern or current task evidence"
        );
    }
    Ok(())
}

pub(super) fn procedure_candidate_identity(
    task: &TaskContract,
    pattern: &ExperiencePattern,
    input: &ProcedureCandidateCreateToolInput,
    pattern_sha256: &str,
    pattern_observation_ref: &str,
    pattern_receipt: &WriteReceiptRef,
) -> Result<(String, String, String)> {
    if input.candidate_skill.lifecycle_state != SkillLifecycleState::Candidate
        || input.candidate_skill.level != eliot_types::SkillLevel::Procedure
    {
        anyhow::bail!("procedure SkillCard must remain candidate-only at Procedure level");
    }
    validate_broker_text("candidate name", &input.candidate_skill.name, 256)?;
    validate_procedure_candidate_source_refs(task, pattern, &input.candidate_skill)?;
    let candidate_ref = format!("skill:{}", input.candidate_skill.skill_id);
    let candidate_sha256 = sha256_json(&input.candidate_skill)?;
    let input_fingerprint = sha256_json(&json!({
        "project_id": task.project_id,
        "task_id": task.task_id,
        "task_revision": input.expected_revision,
        "pattern_ref": input.pattern_ref,
        "pattern_observation_ref": pattern_observation_ref,
        "pattern_receipt": pattern_receipt,
        "pattern_sha256": pattern_sha256,
        "candidate_ref": candidate_ref,
        "candidate_sha256": candidate_sha256,
    }))?;
    Ok((candidate_ref, candidate_sha256, input_fingerprint))
}

pub(super) fn procedure_candidate_response(
    record: &CanonicalProcedureSkillCandidate,
    canonical_receipt: &WriteReceiptRef,
    write_status: Option<WriteStatus>,
    idempotent_replay: bool,
) -> Value {
    json!({
        "component": "procedure_skill_candidate",
        "candidate": record,
        "canonical_receipt": canonical_receipt,
        "write_status": write_status,
        "idempotent_replay": idempotent_replay,
    })
}

pub(super) async fn persist_procedure_candidate(
    state: &McpState,
    context: AuthenticatedRequestContext,
    idempotency_key: &str,
    record: CanonicalProcedureSkillCandidate,
) -> Result<Value> {
    let (receipt, status) = write_canonical_observation(
        state,
        context,
        record.project_id,
        Some(record.task_id),
        CanonicalReceiptKind::ProcedureSkillCandidate,
        idempotency_key,
        &record,
    )
    .await?;
    Ok(procedure_candidate_response(
        &record,
        &receipt,
        Some(status),
        matches!(status, WriteStatus::IdempotentReplay),
    ))
}

pub(super) async fn dispatch_procedure_candidate_create(
    state: &McpState,
    context: AuthenticatedRequestContext,
    arguments: Value,
) -> Result<Value> {
    state.ensure_schema().await?;
    let input: ProcedureCandidateCreateToolInput = serde_json::from_value(arguments)?;
    let project_id = parse_project_id(&input.project_id)?;
    let task_id = TaskId::from_str(&input.task_id).context("parse procedure task_id")?;
    validate_broker_text("idempotency_key", &input.idempotency_key, 256)?;
    let task = require_canonical_task(state, project_id, task_id, input.expected_revision).await?;
    let (pattern, pattern_sha256, pattern_observation_ref, pattern_receipt) =
        resolve_exact_procedure_pattern(state, project_id, task_id, &input.pattern_ref).await?;
    let (candidate_ref, candidate_sha256, input_fingerprint) = procedure_candidate_identity(
        &task,
        &pattern,
        &input,
        &pattern_sha256,
        &pattern_observation_ref,
        &pattern_receipt,
    )?;
    let existing_candidates = state
        .store
        .canonical_records_by_subject_ref::<CanonicalProcedureSkillCandidate>(
            project_id,
            Some(task_id),
            &[CanonicalReceiptKind::ProcedureSkillCandidate.as_str()],
            &candidate_ref,
            2,
        )
        .await?;
    if existing_candidates.len() > 1 {
        anyhow::bail!("candidate_ref resolves to ambiguous canonical SkillCard records");
    }
    if let Some(existing) = existing_candidates.into_iter().next() {
        if existing.receipt_body.input_fingerprint != input_fingerprint {
            anyhow::bail!("candidate_ref is already occupied by a different canonical SkillCard");
        }
        return Ok(procedure_candidate_response(
            &existing.receipt_body,
            &existing.canonical_receipt,
            None,
            true,
        ));
    }
    let write_id = deterministic_canonical_write_id(
        project_id,
        Some(task_id),
        CanonicalReceiptKind::ProcedureSkillCandidate,
        &input.idempotency_key,
    );
    if let Some(existing) = state
        .store
        .canonical_record_by_write_id::<CanonicalProcedureSkillCandidate>(
            project_id,
            Some(task_id),
            &[CanonicalReceiptKind::ProcedureSkillCandidate.as_str()],
            write_id,
        )
        .await?
    {
        if existing.receipt_body.input_fingerprint != input_fingerprint {
            anyhow::bail!("procedure candidate idempotency key conflicts with another candidate");
        }
        return Ok(procedure_candidate_response(
            &existing.receipt_body,
            &existing.canonical_receipt,
            None,
            true,
        ));
    }
    let record = CanonicalProcedureSkillCandidate {
        schema_version: "eliot-procedure-skill-candidate-v1".to_owned(),
        project_id,
        task_id,
        task_revision: input.expected_revision,
        pattern_ref: input.pattern_ref,
        pattern_observation_ref,
        pattern_receipt,
        pattern_sha256,
        candidate_ref,
        candidate_sha256,
        candidate_skill: input.candidate_skill,
        input_fingerprint,
        candidate_only: true,
        activation_applied: false,
        created_at: time::OffsetDateTime::now_utc(),
    };
    persist_procedure_candidate(state, context, &input.idempotency_key, record).await
}

pub(super) async fn resolve_procedure_candidate(
    state: &McpState,
    project_id: ProjectId,
    task_id: TaskId,
    candidate_ref: &str,
) -> Result<CanonicalRecord<CanonicalProcedureSkillCandidate>> {
    if candidate_ref
        .strip_prefix("skill:")
        .is_none_or(|value| value.trim().is_empty())
    {
        anyhow::bail!("candidate_ref must be skill:<exact-skill-id>");
    }
    let mut records = state
        .store
        .canonical_records_by_subject_ref::<CanonicalProcedureSkillCandidate>(
            project_id,
            Some(task_id),
            &[CanonicalReceiptKind::ProcedureSkillCandidate.as_str()],
            candidate_ref,
            2,
        )
        .await?;
    if records.len() != 1 {
        anyhow::bail!("candidate_ref must resolve to exactly one canonical task-scoped SkillCard");
    }
    let record = records
        .pop()
        .context("canonical procedure SkillCard disappeared")?;
    if record.receipt_body.candidate_ref != candidate_ref
        || record.receipt_body.project_id != project_id
        || record.receipt_body.task_id != task_id
        || !record.receipt_body.candidate_only
        || record.receipt_body.activation_applied
        || record.receipt_body.candidate_skill.lifecycle_state != SkillLifecycleState::Candidate
    {
        anyhow::bail!("canonical procedure SkillCard violates candidate-only scope");
    }
    if sha256_json(&record.receipt_body.candidate_skill)? != record.receipt_body.candidate_sha256 {
        anyhow::bail!("canonical procedure SkillCard body hash differs");
    }
    Ok(record)
}

pub(super) async fn dispatch_procedure_candidate_disposition(
    state: &McpState,
    context: AuthenticatedRequestContext,
    arguments: Value,
) -> Result<Value> {
    state.ensure_schema().await?;
    let input: ProcedureCandidateDispositionToolInput = serde_json::from_value(arguments)?;
    let project_id = parse_project_id(&input.project_id)?;
    let task_id = TaskId::from_str(&input.task_id).context("parse procedure task_id")?;
    validate_broker_text("idempotency_key", &input.idempotency_key, 256)?;
    let task = require_canonical_task(state, project_id, task_id, input.expected_revision).await?;
    let (pattern, pattern_sha256, pattern_observation_ref, pattern_receipt) =
        resolve_exact_procedure_pattern(state, project_id, task_id, &input.pattern_ref).await?;
    let candidate_record =
        resolve_procedure_candidate(state, project_id, task_id, &input.candidate_ref).await?;
    let candidate = &candidate_record.receipt_body;
    if candidate.task_revision != input.expected_revision
        || candidate.pattern_ref != input.pattern_ref
        || candidate.pattern_observation_ref != pattern_observation_ref
        || candidate.pattern_receipt != pattern_receipt
        || candidate.pattern_sha256 != pattern_sha256
    {
        anyhow::bail!("procedure candidate does not match current task revision or exact pattern");
    }
    validate_procedure_candidate_source_refs(&task, &pattern, &candidate.candidate_skill)?;

    let (validated_holdout_evidence_refs, validated_negative_transfer_refs) =
        validate_procedure_disposition_evidence(state, &task, &input).await?;
    let input_fingerprint = procedure_disposition_fingerprint(
        &input,
        &task,
        &pattern_sha256,
        &pattern_observation_ref,
        &pattern_receipt,
        &candidate_record,
    )?;
    let write_id = deterministic_canonical_write_id(
        project_id,
        Some(task_id),
        CanonicalReceiptKind::ProcedurePromotionDisposition,
        &input.idempotency_key,
    );
    if let Some(existing) = state
        .store
        .canonical_record_by_write_id::<CanonicalProcedurePromotionDisposition>(
            project_id,
            Some(task_id),
            &[CanonicalReceiptKind::ProcedurePromotionDisposition.as_str()],
            write_id,
        )
        .await?
    {
        if existing.receipt_body.input_fingerprint != input_fingerprint {
            anyhow::bail!(
                "procedure disposition idempotency key conflicts with another exact intent"
            );
        }
        return Ok(procedure_disposition_response(
            &existing.receipt_body,
            &existing.canonical_receipt,
            None,
            true,
        ));
    }

    let (lifecycle_record, promotion_outcome, pattern_disposition, not_ready_reasons) =
        evaluate_procedure_disposition(
            &pattern,
            &candidate.candidate_skill,
            &validated_holdout_evidence_refs,
            &validated_negative_transfer_refs,
            !input.holdout_evidence.is_empty(),
        )?;
    let disposition_hash = blake3::hash(input_fingerprint.as_bytes()).to_hex();
    let record = CanonicalProcedurePromotionDisposition {
        schema_version: "eliot-procedure-promotion-disposition-v1".to_owned(),
        disposition_id: format!("procedure-disposition-{disposition_hash}"),
        project_id,
        task_id,
        task_revision: input.expected_revision,
        pattern_ref: input.pattern_ref,
        pattern_observation_ref,
        pattern_receipt,
        pattern_sha256,
        candidate_ref: input.candidate_ref,
        candidate_receipt: candidate_record.canonical_receipt,
        candidate_sha256: candidate.candidate_sha256.clone(),
        holdout_evidence: input.holdout_evidence,
        validated_holdout_evidence_refs,
        negative_transfer_refs: input.negative_transfer_refs,
        validated_negative_transfer_refs,
        unresolved_evidence_refs: Vec::new(),
        lifecycle_record,
        promotion_outcome,
        pattern_disposition,
        not_ready_reasons,
        input_fingerprint,
        candidate_only: true,
        activation_applied: false,
        created_at: time::OffsetDateTime::now_utc(),
    };
    persist_procedure_disposition(state, context, &input.idempotency_key, record).await
}

pub(super) fn dispatch_verify_profiles(state: &McpState) -> Result<Value> {
    let report = json!({
        "component": "verification_profiles",
        "bounded": true,
        "profiles": VerificationProfileService.profiles(),
        "report_ref": state.root.join("reports").join("verification-profiles").join("latest.json")
    });
    write_verification_report_json_md(
        state,
        "verification-profiles",
        "Verification Profiles",
        &report,
    )?;
    Ok(report)
}

pub(super) fn dispatch_verify_inventory(state: &McpState) -> Result<Value> {
    let inventory = mcp_verification_inventory();
    let report = json!({
        "component": "test_inventory",
        "bounded": true,
        "inventory": inventory,
        "report_ref": state.root.join("reports").join("test-inventory").join("latest.json")
    });
    write_verification_report_json_md(state, "test-inventory", "Test Inventory", &report)?;
    Ok(report)
}

pub(super) fn dispatch_verify_plan(state: &McpState, arguments: Value) -> Result<Value> {
    let input: VerifyPlanToolInput = serde_json::from_value(arguments)?;
    let profile = input.profile.as_deref().unwrap_or("change-gate");
    let inventory = mcp_verification_inventory();
    let plan = VerificationPlannerService.plan(
        &inventory,
        profile,
        vec!["workspace:mcp".to_owned(), "phase:k2".to_owned()],
    )?;
    let report = json!({
        "component": "verification_plans",
        "bounded": true,
        "plan": plan,
        "known_commands_only": VerificationRunnerService.plan_uses_only_known_commands(&plan),
        "report_ref": state.root.join("reports").join("verification-plans").join("latest.json")
    });
    write_verification_report_json_md(state, "verification-plans", "Verification Plans", &report)?;
    Ok(report)
}

pub(super) fn dispatch_verify_report(state: &McpState) -> Result<Value> {
    let inventory = mcp_verification_inventory();
    let profiles = VerificationProfileService.profiles();
    let plan = VerificationPlannerService.plan(
        &inventory,
        "change-gate",
        vec!["workspace:mcp".to_owned(), "phase:k2".to_owned()],
    )?;
    let run = VerificationRunnerService.run_profile_record(&plan)?;
    let verdict = VerificationVerdictService.verdict(&run);
    let cost = TestCostService.report(&inventory, Some(&run));
    let flake = FlakeDetectionService.report("change-gate", 2, &inventory);
    let db_isolation = StatefulDbTestIsolationService.report(&inventory);
    let doctor =
        VerificationDoctorIntegration.status(&inventory, &cost, &flake, &db_isolation, Some(&run));
    write_mcp_verification_artifacts(
        state,
        &inventory,
        &profiles,
        &plan,
        &run,
        &verdict,
        &cost,
        &flake,
        &db_isolation,
    )?;
    let report = json!({
        "component": "verification_report",
        "bounded": true,
        "inventory": inventory,
        "profiles": profiles,
        "latest_plan": plan,
        "latest_run": run,
        "latest_verdict": verdict,
        "cost": cost,
        "flake": flake,
        "db_isolation": db_isolation,
        "doctor_status": doctor,
        "authority": "profile-governance-only; no raw shell, raw db, or DONE override",
        "report_ref": state.root.join("reports").join("verification").join("latest.json")
    });
    write_verification_report_json_md(state, "verification", "Verification", &report)?;
    Ok(report)
}

pub(super) fn dispatch_verify_cost_report(state: &McpState) -> Result<Value> {
    let inventory = mcp_verification_inventory();
    let last_run = mcp_latest_verification_run(&state.root).ok();
    let cost = TestCostService.report(&inventory, last_run.as_ref());
    let report = json!({
        "component": "test_cost",
        "bounded": true,
        "cost": cost,
        "report_ref": state.root.join("reports").join("test-cost").join("latest.json")
    });
    write_verification_report_json_md(state, "test-cost", "Test Cost", &report)?;
    Ok(report)
}

pub(super) fn dispatch_verify_last_verdict(state: &McpState) -> Result<Value> {
    let verdict_path = state
        .root
        .join("reports")
        .join("verification-verdicts")
        .join("latest.json");
    if verdict_path.is_file() {
        return latest_json_report(&verdict_path)?.context("no latest verification verdict found");
    }
    let report = dispatch_verify_report(state)?;
    Ok(json!({
        "component": "verification_last_verdict",
        "verdict": report.get("latest_verdict").cloned(),
        "report_ref": verdict_path
    }))
}

pub(super) fn mcp_verification_inventory() -> TestInventory {
    TestInventoryService.generate(project_id_from_label("eliot-governor"))
}

#[allow(clippy::too_many_arguments)]
pub(super) fn write_mcp_verification_artifacts(
    state: &McpState,
    inventory: &TestInventory,
    profiles: &[eliot_types::TestSuiteProfile],
    plan: &VerificationPlan,
    run: &ProfileVerificationRun,
    verdict: &VerificationVerdict,
    cost: &eliot_types::TestCostReport,
    flake: &eliot_types::FlakeReport,
    db_isolation: &eliot_types::StatefulDbIsolationReport,
) -> Result<()> {
    write_verification_report_json_md(
        state,
        "test-inventory",
        "Test Inventory",
        &json!({ "component": "test_inventory", "inventory": inventory }),
    )?;
    write_verification_report_json_md(
        state,
        "verification-profiles",
        "Verification Profiles",
        &json!({ "component": "verification_profiles", "profiles": profiles }),
    )?;
    write_verification_report_json_md(
        state,
        "verification-plans",
        "Verification Plans",
        &json!({ "component": "verification_plans", "plan": plan }),
    )?;
    write_verification_report_json_md(
        state,
        "verification-runs",
        "Verification Runs",
        &json!({ "component": "verification_runs", "run": run }),
    )?;
    write_verification_report_json_md(
        state,
        "verification-verdicts",
        "Verification Verdicts",
        &json!({ "component": "verification_verdicts", "verdict": verdict }),
    )?;
    write_verification_report_json_md(
        state,
        "test-cost",
        "Test Cost",
        &json!({ "component": "test_cost", "cost": cost }),
    )?;
    write_verification_report_json_md(
        state,
        "flake",
        "Flake",
        &json!({ "component": "flake", "flake": flake }),
    )?;
    write_verification_report_json_md(
        state,
        "db-isolation",
        "DB Isolation",
        &json!({ "component": "db_isolation", "db_isolation": db_isolation }),
    )
}

pub(super) fn mcp_latest_verification_run(root: &Path) -> Result<ProfileVerificationRun> {
    let report = latest_json_report(
        &root
            .join("reports")
            .join("verification-runs")
            .join("latest.json"),
    )?
    .context("no latest verification run found")?;
    serde_json::from_value(
        report
            .get("run")
            .cloned()
            .context("latest verification run report missing run")?,
    )
    .map_err(Into::into)
}

pub(super) fn write_verification_report_json_md<T: serde::Serialize>(
    state: &McpState,
    dir: &str,
    title: &str,
    value: &T,
) -> Result<()> {
    let json_path = state.root.join("reports").join(dir).join("latest.json");
    let markdown_path = state.root.join("reports").join(dir).join("latest.md");
    write_json_report(&json_path, value)?;
    write_markdown_report(
        &markdown_path,
        &format!(
            "# {title}\n\n- authority: `profile-governance-only; no raw command, raw shell, raw db, or DONE override`\n"
        ),
    )
}

pub(super) async fn current_meta_policy_candidate(
    state: &McpState,
    project_id: ProjectId,
    task_id: TaskId,
    experiment: &eliot_types::HarnessExperimentRecord,
) -> Result<Option<CanonicalRecord<eliot_types::ExperimentalMetaPolicyCandidate>>> {
    let Some(authoritative) = experiment.authoritative_policy_candidate.as_ref() else {
        return Ok(None);
    };
    let mut records = state
        .store
        .canonical_records_by_subject_ref::<eliot_types::ExperimentalMetaPolicyCandidate>(
            project_id,
            Some(task_id),
            &[CanonicalReceiptKind::ExperimentalPolicyCandidate.as_str()],
            &authoritative.candidate_id,
            16,
        )
        .await?;
    records.retain(|record| {
        record.receipt_body.candidate_id == authoritative.candidate_id
            && record.receipt_body.source_experiment_ref
                == experiment.harness_experiment_record_id.to_string()
    });
    Ok(records.into_iter().next())
}

pub(super) async fn dispatch_skill_create_candidate(
    state: &McpState,
    arguments: Value,
) -> Result<Value> {
    let input: SkillCreateCandidateToolInput = serde_json::from_value(arguments)?;
    let skill = SkillRegistryService::create_candidate(input.name, "mcp");
    let receipt = write_skill_card_to_memory(state, &skill).await?;
    serde_json::to_value(json!({
        "component": "skill_create_candidate",
        "project": input.project,
        "skill": skill,
        "write_receipt": receipt
    }))
    .map_err(Into::into)
}

pub(super) fn dispatch_verifier_status(state: &McpState, arguments: Value) -> Result<Value> {
    let input: VerifierStatusToolInput = serde_json::from_value(arguments)?;
    let report = latest_json_report(&verifier_latest_path(&state.root))?
        .context("no latest VerifierRun report found")?;
    Ok(json!({
        "component": "verifier_status",
        "requested_task": input.task_id.or(input.task),
        "latest": report
    }))
}

pub(super) async fn require_current_candidate_reviewer(
    state: &McpState,
    context: AuthenticatedRequestContext,
    work_state: &WorkState,
    candidate_diff_id: CandidateDiffId,
) -> Result<AgentSessionId> {
    if !matches!(
        state.profile,
        McpAccessProfile::CodexController | McpAccessProfile::HumanOperator
    ) {
        anyhow::bail!("CandidateReview requires controller or human-operator authority");
    }
    let diff = work_state
        .candidate_diffs
        .iter()
        .find(|diff| diff.candidate_diff_id == candidate_diff_id)
        .context("candidate diff not found")?;
    let worktree = work_state
        .worktree_leases
        .iter()
        .find(|lease| lease.worktree_lease_id == diff.worktree_lease_id)
        .context("candidate diff WorktreeLease not found")?;
    let reviewer = AgentSessionId::from_uuid(context.session_id.as_uuid());
    if reviewer == worktree.holder_session_id {
        anyhow::bail!("CandidateReview requires an independent reviewer");
    }
    let broker = delegation_runtime::load_state(&state.root)?;
    let now = time::OffsetDateTime::now_utc();
    let controller = broker
        .controller_leases
        .iter()
        .find(|lease| {
            lease.task_id == diff.task_id
                && lease.agent_session_id == reviewer
                && lease.expires_at > now
        })
        .context("CandidateReview requires the authenticated active ControllerLease")?;
    let role = broker
        .task_role_leases
        .iter()
        .find(|role| {
            role.task_id == diff.task_id
                && role.agent_session_id == reviewer
                && role.role == AgentRole::Controller
                && role.expires_at > now
                && role
                    .capability_scope
                    .iter()
                    .any(|capability| matches!(capability.as_str(), "review" | "review_candidate"))
        })
        .context("CandidateReview requires the current Controller role review capability")?;
    require_exact_current_projection(
        state,
        diff.project_id,
        Some(diff.task_id),
        "controller_lease",
        &controller.controller_lease_id,
        "receipt_body",
        Some("controller_lease"),
        controller,
    )
    .await?;
    require_exact_current_projection(
        state,
        diff.project_id,
        Some(diff.task_id),
        "task_role_lease",
        &role.role_lease_id,
        "receipt_body",
        Some("host_role_lease_authority"),
        role,
    )
    .await?;
    let worktree_receipt = require_exact_current_projection(
        state,
        diff.project_id,
        Some(diff.task_id),
        "worktree_lease",
        &worktree.worktree_lease_id.to_string(),
        "receipt_body",
        Some("worktree_lease"),
        worktree,
    )
    .await?;
    if worktree.write_receipt.as_ref() != Some(&worktree_receipt) {
        anyhow::bail!("CandidateReview WorktreeLease projection receipt is stale");
    }
    let diff_receipt = require_exact_current_projection(
        state,
        diff.project_id,
        Some(diff.task_id),
        "candidate_diff",
        &diff.candidate_diff_id.to_string(),
        "receipt_body",
        Some("candidate_diff"),
        diff,
    )
    .await?;
    if diff.write_receipt.as_ref() != Some(&diff_receipt) {
        anyhow::bail!("CandidateReview CandidateDiff projection receipt is stale");
    }
    Ok(reviewer)
}

pub(super) fn append_candidate_diff_authority_ref(
    root: &Path,
    artifact_refs: &mut Vec<String>,
) -> Result<()> {
    let work = load_work_state(root)?;
    let candidate = work.candidate_diffs.iter().find(|diff| {
        diff.capture_status == CandidateDiffStatus::AcceptedForPatchRunner
            && artifact_refs.contains(&diff.diff_ref)
    });
    if let Some(diff) = candidate {
        let reference = format!("candidate-diff-id:{}", diff.candidate_diff_id);
        if !artifact_refs.contains(&reference) {
            artifact_refs.push(reference);
        }
    }
    Ok(())
}

pub(super) fn verifier_latest_path(root: &Path) -> PathBuf {
    root.join("reports").join("verifier").join("latest.json")
}

pub(super) fn candidate_diff_report_markdown(report: &Value) -> String {
    format!(
        "# Candidate Diff\n\n- candidate_diff_count: `{}`\n- candidate_review_count: `{}`\n- operation_status: `{}`\n",
        report
            .get("candidate_diff_count")
            .and_then(Value::as_u64)
            .unwrap_or_default(),
        report
            .get("candidate_review_count")
            .and_then(Value::as_u64)
            .unwrap_or_default(),
        report
            .get("operation_status")
            .and_then(Value::as_str)
            .unwrap_or("unknown")
    )
}

pub(super) fn replace_candidate_diff(state: &mut WorkState, replacement: CandidateDiff) {
    if let Some(existing) = state
        .candidate_diffs
        .iter_mut()
        .find(|diff| diff.candidate_diff_id == replacement.candidate_diff_id)
    {
        *existing = replacement;
    } else {
        state.candidate_diffs.push(replacement);
    }
}

pub(super) fn replace_candidate_review(state: &mut WorkState, replacement: CandidateReview) {
    if let Some(existing) = state
        .candidate_reviews
        .iter_mut()
        .find(|review| review.review_id == replacement.review_id)
    {
        *existing = replacement;
    } else {
        state.candidate_reviews.push(replacement);
    }
}

pub(super) fn parse_candidate_review_decision(value: &str) -> Result<CandidateReviewDecision> {
    match value.trim().to_ascii_lowercase().as_str() {
        "accept" | "accept-for-patchrunner" | "accept_for_patchrunner" => {
            Ok(CandidateReviewDecision::AcceptForPatchRunner)
        }
        "reject" => Ok(CandidateReviewDecision::Reject),
        "revise" | "require-revision" | "require_revision" => {
            Ok(CandidateReviewDecision::RequireRevision)
        }
        "human" | "require-human-review" | "require_human_review" => {
            Ok(CandidateReviewDecision::RequireHumanReview)
        }
        other => anyhow::bail!("unknown candidate review decision: {other}"),
    }
}

pub(super) fn validate_managed_verification_run_identity(
    run: &VerificationRun,
    planned: RegisteredTaskVerifier,
    project_id: ProjectId,
    task_id: TaskId,
    write_id: WriteId,
    memory_revision: Option<MemoryRevision>,
) -> Result<()> {
    if run.result != VerificationResult::Passed {
        anyhow::bail!("managed finalization verifier did not pass");
    }
    if run.project_id != Some(project_id)
        || run.task_id != Some(task_id)
        || run.write_id != Some(write_id)
        || run.memory_revision != memory_revision
    {
        anyhow::bail!("managed finalization canonical verifier run receipt binding differs");
    }
    if run.verifier != planned.id()
        || run.payload.get("verifier").and_then(Value::as_str) != Some(planned.id())
    {
        anyhow::bail!("managed finalization canonical verifier run identity differs from planned");
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
pub(super) async fn validate_managed_actual_verifier_refs(
    state: &McpState,
    managed: &crate::host_runtime::ManagedControllerCandidate,
    verifier_refs: &[String],
    require_active_task: bool,
) -> Result<(Vec<String>, TaskContract)> {
    validate_broker_refs("verifier_refs", verifier_refs)?;
    if verifier_refs.len() != 1 {
        anyhow::bail!("managed finalization requires exactly one actual canonical verifier ref");
    }
    let planned = RegisteredTaskVerifier::from_reference(&managed.planned_verifier_ref)
        .context("managed broker planned verifier reference is unregistered or stale")?;
    let task = require_task(state, managed.project_id, managed.task_id).await?;
    if require_active_task && task.status != TaskContractStatus::Active {
        anyhow::bail!("managed finalization requires the active verified TaskContract");
    }
    if !require_active_task
        && !matches!(
            task.status,
            TaskContractStatus::Active | TaskContractStatus::DoneVerified
        )
    {
        anyhow::bail!(
            "managed finalization replay requires an active or done-verified TaskContract"
        );
    }
    let provenance = task
        .action_provenance
        .as_ref()
        .context("managed finalization requires canonical action provenance")?;
    let expected_provenance_hash = provenance.hash.clone();
    let mut provenance_material = provenance.clone();
    provenance_material.hash.clear();
    if provenance.planned_verifier_ref != managed.planned_verifier_ref
        || canonical_struct_hash(&provenance_material)? != expected_provenance_hash
    {
        anyhow::bail!("managed finalization action provenance is stale or verifier-mismatched");
    }

    let verification_id = verification_id_from_ref(&verifier_refs[0])?;
    let canonical_ref = format!("verification:{verification_id}");
    if verifier_refs[0] != canonical_ref {
        anyhow::bail!("managed finalization verifier ref is not canonical");
    }
    if task.verification_ids.as_slice() != [verification_id] || task.verification_scopes.len() != 1
    {
        anyhow::bail!("managed finalization requires the task's exact singleton verification");
    }
    let scope = task
        .verification_scopes
        .iter()
        .find(|scope| scope.verification_id == verification_id)
        .context("managed finalization verifier has no task-bound scope")?;
    let verification_write_id = WriteId::from_uuid(verification_id.as_uuid());
    let verification_receipt = state
        .store
        .write_receipt_by_id(&verification_write_id)
        .await?
        .context("managed finalization verification receipt does not resolve")?;
    if verification_receipt.project_id != managed.project_id
        || verification_receipt.task_id != Some(managed.task_id)
        || verification_receipt.command_kind != SemanticCommandKind::TaskContractWrite
        || !matches!(
            verification_receipt.status,
            WriteStatus::Committed | WriteStatus::IdempotentReplay
        )
        || verification_receipt
            .created_records
            .iter()
            .all(|record| record != &verification_id.to_string())
        || verification_receipt.rejected_reason.is_some()
        || verification_receipt
            .memory_revision
            .is_none_or(|revision| revision > task.memory_revision)
        || (require_active_task
            && (task.write_id != verification_write_id
                || verification_receipt.memory_revision != Some(task.memory_revision)))
    {
        anyhow::bail!("managed finalization verification receipt is stale or scope-mismatched");
    }
    let registry = registered_verifier_for_scope(scope)
        .context("managed finalization verifier registry profile is stale or unknown")?;
    if registry != planned || registry.reference() != managed.planned_verifier_ref {
        anyhow::bail!("actual verification registry reference differs from the planned broker ref");
    }
    let run = state
        .store
        .verification_run_by_id(verification_id)
        .await?
        .context("managed finalization verifier run does not resolve")?;
    validate_managed_verification_run_identity(
        &run,
        planned,
        managed.project_id,
        managed.task_id,
        verification_write_id,
        verification_receipt.memory_revision,
    )?;
    let stored_scope = run
        .payload
        .get("artifact_scope")
        .cloned()
        .and_then(|value| serde_json::from_value::<VerifierArtifactScope>(value).ok());
    if stored_scope.as_ref() != Some(scope) {
        anyhow::bail!("managed finalization verifier run and task scope differ");
    }
    let verification_items = task
        .acceptance_items
        .iter()
        .filter(|item| item.required_evidence == TaskAcceptanceEvidenceKind::Verification)
        .collect::<Vec<_>>();
    if verification_items.len() != 1
        || scope.acceptance_item_ids.as_slice() != [verification_items[0].item_id.as_str()]
        || !verification_items[0].satisfied
        || verification_items[0].verification_id != Some(verification_id)
        || verification_items[0].verification_scope_hash.as_deref()
            != Some(scope.canonical_scope_hash.as_str())
    {
        anyhow::bail!("managed finalization verifier is unrelated to satisfied task acceptance");
    }
    revalidate_verifier_scope(state, &task, scope).await?;
    Ok((vec![canonical_ref], task))
}

pub(super) fn materialize_managed_candidate(
    state: &McpState,
    intent: &ManagedFinalizationIntent,
    authority: &mut ManagedFinalizationAuthority,
) -> Result<FinalizedCandidateArtifacts> {
    let managed = &authority.managed;
    let commit_ref =
        ensure_managed_candidate_commit(&managed.worktree_path, intent, &managed.candidate_diff)?;
    let diff_root = state.root.join("candidate-diffs");
    std::fs::create_dir_all(&diff_root)?;
    let diff_path = diff_root.join(format!("{}.diff", intent.candidate_diff_id));
    std::fs::write(&diff_path, &managed.candidate_diff)?;
    let diff = CandidateDiff {
        candidate_diff_id: intent.candidate_diff_id,
        worktree_lease_id: intent.worktree_lease_id,
        project_id: intent.project_id,
        task_id: intent.task_id,
        work_item_id: intent.work_item_id,
        base_commit: intent.baseline_commit.clone(),
        worktree_head: Some(commit_ref.clone()),
        diff_hash: managed
            .candidate_diff_hash
            .strip_prefix("blake3:")
            .unwrap_or(&managed.candidate_diff_hash)
            .to_owned(),
        diff_ref: diff_path.to_string_lossy().into_owned(),
        changed_files: intent.changed_files.clone(),
        added_files: intent.added_files.clone(),
        modified_files: intent.modified_files.clone(),
        deleted_files: intent.deleted_files.clone(),
        byte_len: managed.candidate_diff.len(),
        file_count: intent.changed_files.len(),
        capture_status: CandidateDiffStatus::AcceptedForPatchRunner,
        created_at: intent.created_at,
        write_receipt: None,
    };
    let review = CandidateReview {
        review_id: intent.review_id.clone(),
        candidate_diff_id: intent.candidate_diff_id,
        reviewer_session_id: intent.controller_session_id,
        decision: CandidateReviewDecision::AcceptForPatchRunner,
        reasons: vec![format!(
            "controller accepted exact managed provider output {}",
            managed.provider_output_hash
        )],
        created_at: intent.created_at,
        patch_request_id: None,
        write_receipt: None,
    };
    replace_candidate_diff(&mut authority.work, diff.clone());
    replace_candidate_review(&mut authority.work, review.clone());
    Ok(FinalizedCandidateArtifacts {
        diff,
        review,
        commit_ref,
    })
}

pub(super) async fn canonicalize_candidate_artifacts(
    state: &McpState,
    context: AuthenticatedRequestContext,
    intent: &ManagedFinalizationIntent,
    authority: &ManagedFinalizationAuthority,
    artifacts: &mut FinalizedCandidateArtifacts,
) -> Result<()> {
    let managed = &authority.managed;
    let (diff_receipt, _) = write_canonical_observation(
        state,
        context,
        managed.project_id,
        Some(managed.task_id),
        CanonicalReceiptKind::CandidateDiff,
        &managed_finalization_key(intent, "candidate-diff"),
        &artifacts.diff,
    )
    .await?;
    artifacts.diff.write_receipt = Some(diff_receipt);
    let (review_receipt, _) = write_canonical_observation(
        state,
        context,
        managed.project_id,
        Some(managed.task_id),
        CanonicalReceiptKind::CandidateReview,
        &managed_finalization_key(intent, "candidate-review"),
        &artifacts.review,
    )
    .await?;
    artifacts.review.write_receipt = Some(review_receipt);
    Ok(())
}

pub(super) fn managed_candidate_file_sets(candidate: &[u8]) -> Result<ManagedCandidateFileSets> {
    let text = std::str::from_utf8(candidate).context("managed candidate is not UTF-8")?;
    let lines = text.lines().collect::<Vec<_>>();
    let mut changed = Vec::new();
    let mut added = Vec::new();
    let mut modified = Vec::new();
    let mut deleted = Vec::new();
    let mut index = 0;
    while index < lines.len() {
        let header = lines[index]
            .strip_prefix("diff --git ")
            .context("managed candidate contains a non-diff section")?;
        let mut fields = header.split_ascii_whitespace();
        let _old = fields.next().context("managed diff old path is absent")?;
        let path = fields
            .next()
            .and_then(|path| path.strip_prefix("b/"))
            .context("managed diff new path is malformed")?
            .replace('\\', "/");
        if fields.next().is_some() || changed.contains(&path) {
            anyhow::bail!("managed candidate path set is ambiguous");
        }
        index += 1;
        let mut is_added = false;
        let mut is_deleted = false;
        while index < lines.len() && !lines[index].starts_with("diff --git ") {
            is_added |= lines[index].starts_with("new file mode ");
            is_deleted |= lines[index].starts_with("deleted file mode ");
            index += 1;
        }
        changed.push(path.clone());
        if is_added {
            added.push(path);
        } else if is_deleted {
            deleted.push(path);
        } else {
            modified.push(path);
        }
    }
    if changed.is_empty() {
        anyhow::bail!("managed candidate path set is empty");
    }
    Ok(ManagedCandidateFileSets {
        changed,
        added,
        modified,
        deleted,
    })
}

pub(super) fn apply_candidate_diff(worktree: &Path, candidate: &[u8]) -> Result<()> {
    for check_only in [true, false] {
        let mut command = std::process::Command::new("git");
        command.arg("-C").arg(worktree).arg("apply");
        if check_only {
            command.arg("--check");
        }
        command.arg("--whitespace=error-all").arg("--");
        command.stdin(std::process::Stdio::piped());
        command.stdout(std::process::Stdio::piped());
        command.stderr(std::process::Stdio::piped());
        let mut child = command.spawn().context("spawn git apply")?;
        child
            .stdin
            .take()
            .context("git apply stdin")?
            .write_all(candidate)?;
        let output = child.wait_with_output()?;
        if !output.status.success() {
            anyhow::bail!(
                "git apply rejected managed candidate: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }
    Ok(())
}

pub(super) fn managed_candidate_hash(bytes: &[u8]) -> String {
    format!("blake3:{}", blake3::hash(bytes).to_hex())
}

pub(super) fn ensure_managed_candidate_commit(
    worktree: &Path,
    intent: &ManagedFinalizationIntent,
    candidate: &[u8],
) -> Result<String> {
    let head = git_managed_stdout(worktree, &["rev-parse", "HEAD"])?;
    let commit_ref = if head == intent.baseline_commit {
        let current = git_managed_bytes(
            worktree,
            &[
                "diff",
                "--binary",
                "--no-ext-diff",
                &intent.baseline_commit,
                "--",
            ],
        )?;
        if current.is_empty() {
            apply_candidate_diff(worktree, candidate)?;
            managed_finalization_failure("apply")?;
        } else if managed_candidate_hash(&current) != intent.candidate_diff_hash {
            anyhow::bail!("managed worktree contains changes outside the exact provider candidate");
        }
        let current = git_managed_bytes(
            worktree,
            &[
                "diff",
                "--binary",
                "--no-ext-diff",
                &intent.baseline_commit,
                "--",
            ],
        )?;
        if managed_candidate_hash(&current) != intent.candidate_diff_hash {
            anyhow::bail!("applied managed candidate differs from provider hash");
        }
        let commit = commit_candidate_diff(worktree, intent)?;
        managed_finalization_failure("commit")?;
        commit
    } else {
        validate_managed_finalization_commit(worktree, intent, &head)?;
        head
    };
    validate_managed_finalization_commit(worktree, intent, &commit_ref)?;
    Ok(commit_ref)
}

pub(super) fn commit_candidate_diff(
    worktree: &Path,
    intent: &ManagedFinalizationIntent,
) -> Result<String> {
    let add = std::process::Command::new("git")
        .arg("-C")
        .arg(worktree)
        .arg("add")
        .arg("--")
        .args(&intent.changed_files)
        .output()?;
    if !add.status.success() {
        anyhow::bail!("git add failed: {}", String::from_utf8_lossy(&add.stderr));
    }
    let commit = std::process::Command::new("git")
        .arg("-C")
        .arg(worktree)
        .args([
            "-c",
            "user.name=Eliot Governor",
            "-c",
            "user.email=eliot-governor@localhost",
            "commit",
            "--no-verify",
            "-m",
        ])
        .arg(managed_finalization_commit_message(intent))
        .env("GIT_AUTHOR_NAME", "Eliot Governor")
        .env("GIT_AUTHOR_EMAIL", "eliot-governor@localhost")
        .env("GIT_COMMITTER_NAME", "Eliot Governor")
        .env("GIT_COMMITTER_EMAIL", "eliot-governor@localhost")
        .env("GIT_AUTHOR_DATE", intent.created_at.to_string())
        .env("GIT_COMMITTER_DATE", intent.created_at.to_string())
        .output()?;
    if !commit.status.success() {
        anyhow::bail!(
            "git commit failed: {}",
            String::from_utf8_lossy(&commit.stderr)
        );
    }
    let head = std::process::Command::new("git")
        .arg("-C")
        .arg(worktree)
        .args(["rev-parse", "HEAD"])
        .output()?;
    if !head.status.success() {
        anyhow::bail!("git rev-parse HEAD failed");
    }
    Ok(String::from_utf8(head.stdout)?.trim().to_owned())
}

pub(super) fn default_work_verifier(scope: &[String]) -> Vec<VerifierRequirement> {
    vec![VerifierRequirement {
        name: "cargo-check".to_owned(),
        command_kind: VerifierCommandKind::CargoCheck,
        command_display: "cargo check --workspace --all-targets --all-features".to_owned(),
        scope: scope.to_vec(),
        required_for_done: true,
        expected_signal: "workspace type-checks".to_owned(),
    }]
}
