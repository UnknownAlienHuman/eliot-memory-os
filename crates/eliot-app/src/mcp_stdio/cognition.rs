//! Cognitive runs: sealing a contract, executing it, and reporting the result.
//!
//! A cognitive run is a bounded piece of reasoning the Governor commissions and
//! then has to be able to account for. Sealing, provider execution and the
//! terminal record belong together because the guarantee is the whole chain,
//! not any one link in it.

use super::*;

pub(super) fn cognitive_policy_snapshot_id(input: &CognitiveSealInput) -> Result<String> {
    sha256_json(&(
        &input.harness_version,
        &input.harness_script_sha256,
        &input.cases_sha256,
        &input.exposure_map_sha256,
        &input.output_contract_sha256,
        &input.models_sha256,
        &input.source_commit,
    ))
}

pub(super) fn validate_cognitive_source_binding(input: &CognitiveSealInput) -> Result<()> {
    if input.source_commit != BUILD_SOURCE_COMMIT {
        anyhow::bail!(
            "cognitive source_commit differs from the Governor build: expected={BUILD_SOURCE_COMMIT} actual={}",
            input.source_commit
        );
    }
    require_sha256(&input.policy_snapshot_id, "policy_snapshot_id")?;
    if input.policy_snapshot_id != cognitive_policy_snapshot_id(input)? {
        anyhow::bail!("cognitive policy_snapshot_id differs from the exact sealed policy inputs");
    }
    Ok(())
}

pub(super) fn cognitive_exposure_sha256(call: &CognitiveRunCallPlan) -> Result<String> {
    sha256_json(&CognitiveExposureProjection {
        revision: &call.expected_truth_revision,
        handles: &call.expected_exposure_handles,
    })
}

pub(super) fn validate_cognitive_execution(execution: &CognitiveExecutionSeal) -> Result<()> {
    for (field, value) in [
        ("executable_sha256", &execution.executable_sha256),
        (
            "provider_executable_sha256",
            &execution.provider_executable_sha256,
        ),
        ("argv_sha256", &execution.argv_sha256),
        ("environment_sha256", &execution.environment_sha256),
        ("cwd_sha256", &execution.cwd_sha256),
        ("bundle_sha256", &execution.bundle_sha256),
        ("prompt_sha256", &execution.prompt_sha256),
    ] {
        require_sha256(value, field)?;
    }
    Ok(())
}

#[allow(clippy::too_many_lines, clippy::type_complexity)]
pub(super) fn expected_cognitive_plan() -> [(
    &'static str,
    AgentHostId,
    CognitiveInvocationRole,
    &'static str,
    Option<&'static str>,
    bool,
); COGNITIVE_RUN_EXACT_CALLS] {
    use AgentHostId::{Antigravity, OpenCode};
    use CognitiveInvocationRole::{Control, SourceWrite, Target};
    [
        (
            "PC-01-target-opencode-treatment",
            OpenCode,
            Target,
            "treatment",
            None,
            false,
        ),
        (
            "PC-01-target-opencode-control",
            OpenCode,
            Control,
            "control",
            None,
            false,
        ),
        (
            "PC-02-target-antigravity-treatment",
            Antigravity,
            Target,
            "treatment",
            None,
            false,
        ),
        (
            "PC-02-target-antigravity-control",
            Antigravity,
            Control,
            "control",
            None,
            false,
        ),
        (
            "LC-01-source-opencode",
            OpenCode,
            SourceWrite,
            "source_write",
            Some("opencode-to-antigravity"),
            false,
        ),
        (
            "LC-01-target-antigravity-control",
            Antigravity,
            Control,
            "control",
            None,
            false,
        ),
        (
            "LC-02-source-antigravity",
            Antigravity,
            SourceWrite,
            "source_write",
            Some("antigravity-to-opencode"),
            false,
        ),
        (
            "LC-02-target-opencode-control",
            OpenCode,
            Control,
            "control",
            None,
            false,
        ),
        (
            "PR-01-target-opencode-treatment",
            OpenCode,
            Target,
            "treatment",
            None,
            false,
        ),
        (
            "NM-01-target-antigravity-treatment",
            Antigravity,
            Target,
            "treatment",
            None,
            false,
        ),
        (
            "DM-01-target-opencode-treatment",
            OpenCode,
            Target,
            "treatment",
            None,
            false,
        ),
        (
            "ST-01-target-antigravity-treatment",
            Antigravity,
            Target,
            "treatment",
            None,
            false,
        ),
        (
            "NU-01-target-opencode-treatment",
            OpenCode,
            Target,
            "treatment",
            None,
            false,
        ),
        (
            "SL-01-target-antigravity-treatment",
            Antigravity,
            Target,
            "treatment",
            None,
            false,
        ),
        (
            "FG-01-target-opencode-treatment",
            OpenCode,
            Target,
            "treatment",
            None,
            false,
        ),
        (
            "AR-01-target-antigravity-treatment",
            Antigravity,
            Target,
            "treatment",
            None,
            false,
        ),
        (
            "LC-01-target-antigravity-treatment",
            Antigravity,
            Target,
            "treatment",
            Some("opencode-to-antigravity"),
            true,
        ),
        (
            "LC-02-target-opencode-treatment",
            OpenCode,
            Target,
            "treatment",
            Some("antigravity-to-opencode"),
            true,
        ),
    ]
}

#[allow(clippy::expect_used)]
pub(super) fn validate_cognitive_plan(plan: &[CognitiveRunCallPlan]) -> Result<()> {
    if plan.len() != COGNITIVE_RUN_EXACT_CALLS {
        anyhow::bail!("cognitive contract requires exactly {COGNITIVE_RUN_EXACT_CALLS} calls");
    }
    let expected = expected_cognitive_plan();
    for (index, (actual, expected)) in plan.iter().zip(expected).enumerate() {
        let call_number = u8::try_from(index + 1).expect("18 fits u8");
        let (call_id, host, role, variant, flow, gated) = expected;
        if actual.call_number != call_number
            || actual.call_id != call_id
            || actual.host != host
            || actual.invocation_role != role
            || actual.variant != variant
            || actual.reciprocal_flow_id.as_deref() != flow
            || actual.requires_shared_gate != gated
        {
            anyhow::bail!("cognitive exact plan mismatch at call {call_number}");
        }
        if actual.case_id.trim().is_empty() || actual.model.trim().is_empty() {
            anyhow::bail!("cognitive call {call_number} requires case_id and model");
        }
        if (actual.invocation_role == CognitiveInvocationRole::SourceWrite)
            != (actual.candidate_write_id.is_some() && actual.candidate_body_sha256.is_some())
        {
            anyhow::bail!(
                "only source-write call {call_number} requires candidate write/body bindings"
            );
        }
        if let Some(body_sha256) = actual.candidate_body_sha256.as_deref() {
            require_sha256(body_sha256, "candidate_body_sha256")?;
        }
        if actual.expected_truth_revision.trim().is_empty()
            || actual.expected_truth_revision.contains("REPLACE")
        {
            anyhow::bail!("cognitive call {call_number} has no exact truth revision");
        }
        if matches!(
            actual.invocation_role,
            CognitiveInvocationRole::Control | CognitiveInvocationRole::SourceWrite
        ) && !actual.expected_exposure_handles.is_empty()
        {
            anyhow::bail!("control/source call {call_number} must have empty exposure");
        }
        if actual.invocation_role == CognitiveInvocationRole::Target
            && actual.expected_exposure_handles.is_empty()
        {
            anyhow::bail!("target call {call_number} requires a non-empty exact exposure");
        }
        if actual.requires_shared_gate && actual.expected_exposure_handles.len() != 1 {
            anyhow::bail!("gated call {call_number} must expose exactly one reciprocal handle");
        }
        require_sha256(&actual.prompt_sha256, "prompt_sha256")?;
        require_sha256(
            &actual.expected_provider_bundle_sha256,
            "expected_provider_bundle_sha256",
        )?;
        require_sha256(&actual.exposure_sha256, "exposure_sha256")?;
        if actual.exposure_sha256 != cognitive_exposure_sha256(actual)? {
            anyhow::bail!("cognitive call {call_number} exposure hash differs from exact fields");
        }
        require_sha256(
            &actual.expected_output_schema_sha256,
            "expected_output_schema_sha256",
        )?;
    }
    let opencode = plan
        .iter()
        .filter(|call| call.host == AgentHostId::OpenCode)
        .count();
    let antigravity = plan
        .iter()
        .filter(|call| call.host == AgentHostId::Antigravity)
        .count();
    let controls = plan
        .iter()
        .filter(|call| call.invocation_role == CognitiveInvocationRole::Control)
        .count();
    let sources = plan
        .iter()
        .filter(|call| call.invocation_role == CognitiveInvocationRole::SourceWrite)
        .count();
    if (opencode, antigravity, controls, sources) != (9, 9, 4, 2) {
        anyhow::bail!(
            "cognitive exact plan allocation must be 9/9 hosts, 4 controls, and 2 sources"
        );
    }
    Ok(())
}

pub(super) fn cognitive_revision_key(run_id: &str, revision: u64) -> String {
    format!("cognitive-run:{run_id}:revision:{revision}")
}

pub(super) fn cognitive_tool_observation_subject(run_id: &str, call_number: u8) -> String {
    format!("{run_id}:call:{call_number}")
}

pub(super) async fn cognitive_record_by_revision<T: serde::de::DeserializeOwned>(
    state: &McpState,
    project_id: ProjectId,
    task_id: TaskId,
    run_id: &str,
    revision: u64,
    kind: CanonicalReceiptKind,
) -> Result<Option<CanonicalRecord<T>>> {
    let key = cognitive_revision_key(run_id, revision);
    let write_id = deterministic_canonical_write_id(project_id, Some(task_id), kind, &key);
    state
        .store
        .canonical_record_by_write_id(project_id, Some(task_id), &[kind.as_str()], write_id)
        .await
        .map_err(Into::into)
}

pub(super) async fn cognitive_run_seal(
    state: &McpState,
    context: AuthenticatedRequestContext,
    params: Value,
) -> Result<Value> {
    state.ensure_schema().await?;
    let input: CognitiveSealInput = serde_json::from_value(params)?;
    if input.run_id.trim().is_empty()
        || input.harness_version.trim().is_empty()
        || input.instance_name.trim().is_empty()
        || input.output_root.trim().is_empty()
    {
        anyhow::bail!("run_id, harness_version, instance_name, and output_root must not be empty");
    }
    if input.timeout_seconds == 0 || input.timeout_seconds > 900 {
        anyhow::bail!("cognitive timeout_seconds must be within 1..=900");
    }
    validate_cognitive_source_binding(&input)?;
    if input.instance_name != state.instance_name {
        anyhow::bail!("cognitive seal instance differs from the serving Governor instance");
    }
    for (field, value) in [
        ("harness_script_sha256", &input.harness_script_sha256),
        ("cases_sha256", &input.cases_sha256),
        ("exposure_map_sha256", &input.exposure_map_sha256),
        ("output_contract_sha256", &input.output_contract_sha256),
        ("models_sha256", &input.models_sha256),
    ] {
        require_sha256(value, field)?;
    }
    validate_cognitive_plan(&input.exact_plan)?;
    if let Some(existing) = cognitive_record_by_revision::<CognitiveRunContract>(
        state,
        input.project_id,
        input.task_id,
        &input.run_id,
        0,
        CanonicalReceiptKind::CognitiveRunContract,
    )
    .await?
    {
        if !same_seal_request(&existing.receipt_body, &input) {
            anyhow::bail!("sealed cognitive contract is immutable");
        }
        return Ok(
            json!({ "contract": existing.receipt_body, "canonical_receipt": existing.canonical_receipt, "replay": true }),
        );
    }
    let nonce = uuid::Uuid::new_v4();
    if nonce.get_version() != Some(uuid::Version::Random) {
        anyhow::bail!("Governor nonce generation did not produce UUIDv4");
    }
    let mut contract = CognitiveRunContract {
        schema_version: COGNITIVE_RUN_SCHEMA_VERSION.to_owned(),
        harness_version: input.harness_version,
        instance_name: input.instance_name,
        run_id: input.run_id,
        project_id: input.project_id,
        task_id: input.task_id,
        governor_nonce: nonce,
        harness_script_sha256: input.harness_script_sha256,
        cases_sha256: input.cases_sha256,
        exposure_map_sha256: input.exposure_map_sha256,
        output_contract_sha256: input.output_contract_sha256,
        models_sha256: input.models_sha256,
        source_commit: input.source_commit,
        policy_snapshot_id: input.policy_snapshot_id,
        output_root: input.output_root,
        timeout_seconds: input.timeout_seconds,
        exact_plan: input.exact_plan,
        hard_provider_call_cap: COGNITIVE_RUN_EXACT_CALLS_U8,
        contract_sha256: String::new(),
        sealed_at: time::OffsetDateTime::now_utc(),
    };
    contract.contract_sha256 = sha256_json(&contract)?;
    let key = cognitive_revision_key(&contract.run_id, 0);
    let (receipt, status) = write_canonical_observation(
        state,
        context,
        contract.project_id,
        Some(contract.task_id),
        CanonicalReceiptKind::CognitiveRunContract,
        &key,
        &contract,
    )
    .await?;
    if !matches!(
        status,
        WriteStatus::Committed | WriteStatus::IdempotentReplay
    ) {
        anyhow::bail!("cognitive contract CAS was rejected");
    }
    Ok(
        json!({ "contract": contract, "canonical_receipt": receipt, "replay": status == WriteStatus::IdempotentReplay }),
    )
}

pub(super) fn cognitive_commit_serializer() -> &'static tokio::sync::Mutex<()> {
    COGNITIVE_COMMIT_SERIALIZER.get_or_init(|| tokio::sync::Mutex::new(()))
}

pub(super) fn deterministic_cognitive_uuid(material: &str) -> uuid::Uuid {
    let digest = blake3::hash(material.as_bytes());
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest.as_bytes()[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x50;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    uuid::Uuid::from_bytes(bytes)
}

pub(super) fn cognitive_capability_path(
    state: &McpState,
    capability: &CognitiveCandidateCapability,
) -> PathBuf {
    // The harness must be able to derive this path before sealing the exact
    // provider environment. Keep the path projection on ubiquitous SHA-256;
    // the protected file contents still carry the independent contract-bound
    // capability token and are validated against canonical attempt state.
    let authority_digest = Sha256::digest(
        format!(
            "{}:{}:{}:{}:{}",
            capability.project_id,
            capability.task_id,
            capability.run_id,
            capability.call_number,
            capability.host.as_str(),
        )
        .as_bytes(),
    );
    let mut authority_hash = String::with_capacity(64);
    for byte in authority_digest {
        let _ = write!(&mut authority_hash, "{byte:02x}");
    }
    state
        .cognitive_runtime
        .runtime_dir
        .join("secrets")
        .join("cognitive-runs")
        .join(&authority_hash[..24])
        .join(format!("call-{:02}.json", capability.call_number))
}

pub(super) fn write_cognitive_capability_file(
    path: &Path,
    file: &CognitiveCapabilityFile,
) -> Result<()> {
    let parent = path
        .parent()
        .context("cognitive capability path has no parent")?;
    fs::create_dir_all(parent).context("create cognitive capability directory")?;
    named_pipe_ipc::restrict_owned_directory_to_current_user(parent)?;
    let bytes = serde_json::to_vec(file).context("serialize cognitive capability")?;
    match OpenOptions::new().create_new(true).write(true).open(path) {
        Ok(mut output) => {
            output
                .write_all(&bytes)
                .context("write cognitive capability")?;
            output.flush().context("flush cognitive capability")?;
            output.sync_all().context("sync cognitive capability")?;
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            anyhow::bail!("cognitive capability file already exists")
        }
        Err(error) => Err(error).context("create cognitive capability file"),
    }
}

pub(super) fn read_cognitive_capability_file(path: &Path) -> Result<CognitiveCapabilityFile> {
    let bytes = fs::read(path).context("read cognitive capability file")?;
    serde_json::from_slice(&bytes).context("decode cognitive capability file")
}

pub(super) async fn validate_cognitive_gate(
    state: &McpState,
    contract_record: &CanonicalRecord<CognitiveRunContract>,
    gate: &CognitiveSharedGateBinding,
) -> Result<()> {
    let contract = &contract_record.receipt_body;
    if gate.contract_receipt != contract_record.canonical_receipt
        || gate.pre_gate_terminal_receipts.len() != COGNITIVE_RUN_RAW_VERIFIER_CALLS
        || gate.source_disposition_receipts.len() != 2
        || gate.reciprocal_verification_receipts.len() != 2
        || gate.canonical_case_dispositions.len() != 2
        || gate.gate_revision == 0
    {
        anyhow::bail!("cognitive shared gate has an invalid cardinality or contract binding");
    }
    let canonical_dispositions = resolve_canonical_case_dispositions(
        &state.store,
        contract_record,
        time::OffsetDateTime::now_utc(),
    )
    .await?;
    if gate.canonical_case_dispositions != canonical_dispositions {
        anyhow::bail!("cognitive shared gate differs from canonical case dispositions");
    }
    for call_number in 1..=COGNITIVE_RUN_RAW_VERIFIER_CALLS_U8 {
        let revision = u64::from(call_number) * 2;
        let terminal = cognitive_record_by_revision::<CognitiveRunTerminal>(
            state,
            contract.project_id,
            contract.task_id,
            &contract.run_id,
            revision,
            CanonicalReceiptKind::CognitiveRunTerminal,
        )
        .await?
        .with_context(|| format!("cognitive gate is missing terminal call {call_number}"))?;
        if terminal.receipt_body.status != CognitiveRunCallStatus::Succeeded
            || terminal.canonical_receipt
                != gate.pre_gate_terminal_receipts[usize::from(call_number - 1)]
        {
            anyhow::bail!("cognitive shared gate terminal chain differs at call {call_number}");
        }
    }
    let mut promotions = Vec::with_capacity(2);
    for (index, source_call) in [5_u8, 7_u8].into_iter().enumerate() {
        let source_attempt = cognitive_record_by_revision::<CognitiveRunAttempt>(
            state,
            contract.project_id,
            contract.task_id,
            &contract.run_id,
            u64::from(source_call) * 2 - 1,
            CanonicalReceiptKind::CognitiveRunAttempt,
        )
        .await?
        .context("reciprocal source attempt is absent")?;
        let source_terminal = cognitive_record_by_revision::<CognitiveRunTerminal>(
            state,
            contract.project_id,
            contract.task_id,
            &contract.run_id,
            u64::from(source_call) * 2,
            CanonicalReceiptKind::CognitiveRunTerminal,
        )
        .await?
        .context("reciprocal source terminal is absent")?;
        let candidate_receipt = source_terminal
            .receipt_body
            .candidate_receipt
            .as_ref()
            .context("reciprocal source terminal has no candidate receipt")?;
        if gate.reciprocal_verification_receipts[index] != *candidate_receipt {
            anyhow::bail!(
                "reciprocal verification receipt differs from the exact source candidate"
            );
        }
        let revision = require_exact_reciprocal_promotion(
            state,
            contract.project_id,
            contract.task_id,
            &source_attempt,
            candidate_receipt.write_id,
            &gate.source_disposition_receipts[index],
        )
        .await?;
        promotions.push((revision, gate.source_disposition_receipts[index].clone()));
    }
    promotions.sort_by_key(|(revision, _)| *revision);
    if promotions[0].0 == promotions[1].0
        || gate.gate_receipt != promotions[1].1
        || gate.gate_revision != promotions[1].0
    {
        anyhow::bail!("cognitive shared gate receipt/revision is not the latest exact promotion");
    }
    let mut hash_projection = gate.clone();
    hash_projection.condition_sha256.clear();
    if gate.condition_sha256 != sha256_json(&hash_projection)? {
        anyhow::bail!("cognitive shared gate condition hash differs from its exact receipt set");
    }
    Ok(())
}

pub(super) async fn load_cognitive_contract(
    state: &McpState,
    input: &CognitiveStatusInput,
) -> Result<CanonicalRecord<CognitiveRunContract>> {
    let record = cognitive_record_by_revision::<CognitiveRunContract>(
        state,
        input.project_id,
        input.task_id,
        &input.run_id,
        0,
        CanonicalReceiptKind::CognitiveRunContract,
    )
    .await?
    .context("cognitive run is not sealed")?;
    if record.receipt_body.project_id != input.project_id
        || record.receipt_body.task_id != input.task_id
        || record.receipt_body.run_id != input.run_id
        || record.receipt_body.instance_name != state.instance_name
    {
        anyhow::bail!("cognitive contract scope or Governor instance binding differs");
    }
    let mut hash_projection = record.receipt_body.clone();
    let expected_hash = hash_projection.contract_sha256.clone();
    hash_projection.contract_sha256.clear();
    if expected_hash != sha256_json(&hash_projection)? {
        anyhow::bail!("cognitive contract canonical hash is invalid");
    }
    validate_cognitive_plan(&record.receipt_body.exact_plan)?;
    Ok(record)
}

#[allow(clippy::expect_used, clippy::too_many_lines)]
pub(super) async fn cognitive_run_begin(
    state: &McpState,
    context: AuthenticatedRequestContext,
    params: Value,
) -> Result<Value> {
    state.ensure_schema().await?;
    let input: CognitiveBeginInput = serde_json::from_value(params)?;
    validate_cognitive_execution(&input.execution)?;
    let scope = CognitiveStatusInput {
        run_id: input.run_id.clone(),
        project_id: input.project_id,
        task_id: input.task_id,
    };
    let commit_guard = cognitive_commit_serializer().lock().await;
    let contract_record = load_cognitive_contract(state, &scope).await?;
    let contract = &contract_record.receipt_body;
    let call = contract
        .exact_plan
        .get(usize::from(input.call_number.saturating_sub(1)))
        .filter(|call| call.call_number == input.call_number)
        .context("cognitive call_number is outside the sealed plan")?;
    if input.execution.prompt_sha256 != call.prompt_sha256
        || input.execution.bundle_sha256 != call.expected_provider_bundle_sha256
    {
        anyhow::bail!(
            "cognitive execution prompt/provider bundle differs from the sealed call plan"
        );
    }
    if call.requires_shared_gate {
        validate_cognitive_gate(
            state,
            &contract_record,
            input
                .shared_gate
                .as_ref()
                .context("cognitive reciprocal target requires the shared gate")?,
        )
        .await?;
    } else if input.shared_gate.is_some() {
        anyhow::bail!("cognitive shared gate is valid only for calls 17 and 18");
    }
    let attempt_revision = u64::from(input.call_number) * 2 - 1;
    if let Some(existing) = cognitive_record_by_revision::<CognitiveRunAttempt>(
        state,
        input.project_id,
        input.task_id,
        &input.run_id,
        attempt_revision,
        CanonicalReceiptKind::CognitiveRunAttempt,
    )
    .await?
    {
        if cognitive_record_by_revision::<CognitiveRunTerminal>(
            state,
            input.project_id,
            input.task_id,
            &input.run_id,
            attempt_revision + 1,
            CanonicalReceiptKind::CognitiveRunTerminal,
        )
        .await?
        .is_some()
        {
            anyhow::bail!(
                "cognitive call is already terminal; status reconciliation forbids redispatch"
            );
        }
        if existing.receipt_body.execution != input.execution
            || existing.receipt_body.shared_gate != input.shared_gate
            || existing.receipt_body.status != CognitiveRunCallStatus::Attempting
        {
            anyhow::bail!("cognitive attempt revision is already occupied by a different begin");
        }
        let capability_file = existing
            .receipt_body
            .capability
            .as_ref()
            .map(|capability| cognitive_capability_path(state, capability));
        if let Some(path) = capability_file.as_ref() {
            let file = read_cognitive_capability_file(path)?;
            if Some(&file.capability) != existing.receipt_body.capability.as_ref()
                || sha256_bytes(file.job_packet.as_bytes()) != call.prompt_sha256
            {
                anyhow::bail!("cognitive capability file differs from canonical attempt");
            }
        }
        return Ok(json!({
            "attempt": existing.receipt_body,
            "canonical_receipt": existing.canonical_receipt,
            "capability_file": capability_file,
            "replay": true,
            "dispatch_admitted": false,
            "reconciliation_required": true,
        }));
    }
    let previous_terminal_receipt = if input.call_number > 1 {
        let previous_call = input.call_number - 1;
        let previous = cognitive_record_by_revision::<CognitiveRunTerminal>(
            state,
            input.project_id,
            input.task_id,
            &input.run_id,
            u64::from(previous_call) * 2,
            CanonicalReceiptKind::CognitiveRunTerminal,
        )
        .await?
        .with_context(|| {
            format!(
                "cognitive call {input_call} cannot begin before call {previous_call} is terminal",
                input_call = input.call_number
            )
        })?;
        if previous.receipt_body.status != CognitiveRunCallStatus::Succeeded {
            anyhow::bail!(
                "cognitive run is terminal after a failed or unknown prior call; redispatch is forbidden"
            );
        }
        Some(previous.canonical_receipt)
    } else {
        None
    };
    let authority_material = format!(
        "{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}",
        contract.project_id,
        contract.task_id,
        contract.instance_name,
        contract.governor_nonce,
        contract.contract_sha256,
        contract.run_id,
        call.call_number,
        call.host.as_str(),
        call.model,
        call.prompt_sha256,
        call.expected_provider_bundle_sha256,
    );
    let invocation_id =
        deterministic_cognitive_uuid(&format!("cognitive-invocation:{authority_material}"))
            .to_string();
    let candidate_write_id = call.candidate_write_id;
    let mut capability_file = None;
    if input.job_packet.len() > 256 * 1024 {
        anyhow::bail!("cognitive job packet exceeds the bounded input limit");
    }
    if let Err(violation) = eliot_types::inspect_secret_bytes(input.job_packet.as_bytes()) {
        anyhow::bail!(
            "secret boundary rejected cognitive job packet: {}",
            violation.rule
        );
    }
    if sha256_bytes(input.job_packet.as_bytes()) != call.prompt_sha256 {
        anyhow::bail!("cognitive job packet differs from the sealed prompt hash");
    }
    let (capability, pending_capability_file) = {
        let session_id = SessionId::new_v7();
        let token = format!(
            "{}{}",
            uuid::Uuid::new_v4().simple(),
            uuid::Uuid::new_v4().simple()
        );
        let token_sha256 = {
            let digest = Sha256::digest(token.as_bytes());
            let mut encoded = String::with_capacity(64);
            for byte in digest {
                write!(&mut encoded, "{byte:02x}").expect("String write");
            }
            encoded
        };
        let capability = CognitiveCandidateCapability {
            capability_id: deterministic_cognitive_uuid(&format!(
                "cognitive-capability:{authority_material}"
            ))
            .to_string(),
            contract_sha256: contract.contract_sha256.clone(),
            run_id: input.run_id.clone(),
            call_id: call.call_id.clone(),
            call_number: input.call_number,
            project_id: input.project_id,
            task_id: input.task_id,
            session_id,
            host: call.host,
            invocation_role: call.invocation_role,
            expected_truth_revision: call.expected_truth_revision.clone(),
            expected_exposure_handles: call.expected_exposure_handles.clone(),
            expected_write_id: candidate_write_id,
            expected_body_sha256: call.candidate_body_sha256.clone(),
            token_sha256,
            expires_at: time::OffsetDateTime::now_utc() + time::Duration::hours(2),
        };
        let path = cognitive_capability_path(state, &capability);
        let pending = (
            path,
            CognitiveCapabilityFile {
                schema_version: COGNITIVE_RUN_SCHEMA_VERSION.to_owned(),
                publication_path: state.cognitive_runtime.publication_path.clone(),
                instance_name: state.instance_name.clone(),
                capability_token: token,
                capability: capability.clone(),
                job_packet: input.job_packet.clone(),
            },
        );
        (Some(capability), Some(pending))
    };
    let attempt = CognitiveRunAttempt {
        schema_version: COGNITIVE_RUN_SCHEMA_VERSION.to_owned(),
        run_id: input.run_id,
        call_id: call.call_id.clone(),
        call_number: input.call_number,
        run_revision: attempt_revision,
        expected_previous_revision: attempt_revision - 1,
        contract_receipt: contract_record.canonical_receipt,
        invocation_id,
        candidate_write_id,
        provider_calls_consumed: input.call_number,
        hard_provider_call_cap: contract.hard_provider_call_cap,
        status: CognitiveRunCallStatus::Attempting,
        execution: input.execution,
        capability,
        shared_gate: input.shared_gate,
        created_at: time::OffsetDateTime::now_utc(),
    };
    let key = cognitive_revision_key(&attempt.run_id, attempt_revision);
    let envelope = canonical_observation_envelope(
        context,
        input.project_id,
        Some(input.task_id),
        CanonicalReceiptKind::CognitiveRunAttempt,
        &key,
        &attempt,
    )?;
    let write_receipt = state
        .writer
        .submit_cognitive_begin(
            envelope,
            CognitiveBeginPrecondition {
                project_id: input.project_id,
                task_id: input.task_id,
                run_id: attempt.run_id.clone(),
                call_number: attempt.call_number,
                contract_receipt: attempt.contract_receipt.clone(),
                previous_terminal_receipt,
                shared_gate: attempt.shared_gate.clone(),
            },
        )
        .await?;
    let receipt = WriteReceiptRef {
        receipt_id: write_receipt.receipt_id,
        write_id: write_receipt.write_id,
    };
    let status = write_receipt.status;
    if !matches!(
        status,
        WriteStatus::Committed | WriteStatus::IdempotentReplay
    ) {
        anyhow::bail!("cognitive begin revision CAS was rejected");
    }
    if let Some((path, file)) = pending_capability_file {
        if let Err(file_error) = write_cognitive_capability_file(&path, &file) {
            let reconciliation = json!({
                "reason": "protected capability handoff failed after canonical attempt",
                "call_number": attempt.call_number,
                "capability_id": file.capability.capability_id,
            });
            let raw_verifier =
                (attempt.call_number <= COGNITIVE_RUN_RAW_VERIFIER_CALLS_U8).then(|| {
                    json!({
                        "verifier_version": "eliot-cognitive-capability-handoff-v1",
                        "checks_sha256": sha256_json(&reconciliation).expect("JSON serializes"),
                        "passed": false,
                    })
                });
            let terminal_params = json!({
                "run_id": attempt.run_id,
                "project_id": contract.project_id,
                "task_id": contract.task_id,
                "call_number": attempt.call_number,
                "status": "unknown_outcome",
                "execution": attempt.execution,
                "process_sha256": null,
                "stdout_sha256": null,
                "stderr_sha256": null,
                "provider_output_sha256": null,
                "candidate_receipt": null,
                "raw_verifier": raw_verifier,
                "reason": "capability handoff failed after attempt commit; sealed UnknownOutcome without provider spawn",
            });
            drop(commit_guard);
            cognitive_run_terminal(state, context, terminal_params)
                .await
                .context("seal UnknownOutcome after capability handoff failure")?;
            return Err(file_error)
                .context("create protected cognitive capability after attempt commit");
        }
        capability_file = Some(path);
    }
    Ok(json!({
        "attempt": attempt,
        "canonical_receipt": receipt,
        "capability_file": capability_file,
        "replay": false,
        "dispatch_admitted": true,
        "reconciliation_required": false,
    }))
}

#[allow(clippy::too_many_lines)]
pub(super) async fn validate_cognitive_host_and_tools(
    state: &McpState,
    contract: &CanonicalRecord<CognitiveRunContract>,
    call: &CognitiveRunCallPlan,
    attempt: &CanonicalRecord<CognitiveRunAttempt>,
    terminal: &CognitiveTerminalInput,
) -> Result<Vec<WriteReceiptRef>> {
    let successful = terminal.status == CognitiveRunCallStatus::Succeeded;
    let observation = terminal.host_observation.as_ref();
    if successful && observation.is_none() {
        anyhow::bail!("successful cognitive terminal requires a host-native observation");
    }
    if let Some(observation) = observation {
        if observation.observation_version != "eliot-cognitive-host-observation-v1"
            || observation.host != call.host
            || observation
                .vendor_session_id
                .as_deref()
                .is_some_and(str::is_empty)
        {
            anyhow::bail!("cognitive host observation identity differs from the sealed call");
        }
        require_sha256(
            &observation.outer_protocol_sha256,
            "host observation outer_protocol_sha256",
        )?;
        if observation
            .observed_model
            .as_deref()
            .is_some_and(|model| model != call.model)
            || (call.host == AgentHostId::OpenCode && observation.observed_model.is_none())
        {
            anyhow::bail!("host-native observed model differs from the sealed model");
        }
    }

    let expected_session = attempt
        .receipt_body
        .capability
        .as_ref()
        .map(|capability| capability.session_id);
    if observation.and_then(|item| item.governor_session_id) != expected_session {
        anyhow::bail!("host observation Governor session differs from attempt capability");
    }
    if expected_session.is_none() {
        anyhow::bail!("cognitive call has no one-shot job capability");
    }
    let attempt_memory_revision = state
        .store
        .write_receipt_by_id(&attempt.canonical_receipt.write_id)
        .await?
        .context("cognitive attempt write receipt disappeared")?
        .memory_revision
        .context("cognitive attempt has no canonical memory revision")?
        .value();

    let observation_subject =
        cognitive_tool_observation_subject(&contract.receipt_body.run_id, call.call_number);
    let mut records = state
        .store
        .canonical_records_by_subject_ref::<CognitiveToolObservation>(
            contract.receipt_body.project_id,
            Some(contract.receipt_body.task_id),
            &[CanonicalReceiptKind::CognitiveToolObservation.as_str()],
            &observation_subject,
            COGNITIVE_TOOL_OBSERVATION_QUERY_LIMIT,
        )
        .await?;
    if records.len() >= COGNITIVE_TOOL_OBSERVATION_MAX {
        anyhow::bail!("cognitive call exceeded its canonical tool-observation cap");
    }
    records.sort_by(|left, right| {
        left.receipt_body
            .observed_at
            .cmp(&right.receipt_body.observed_at)
            .then_with(|| {
                left.canonical_receipt
                    .write_id
                    .to_string()
                    .cmp(&right.canonical_receipt.write_id.to_string())
            })
    });
    for record in &records {
        let body = &record.receipt_body;
        if body.run_id != contract.receipt_body.run_id
            || body.call_subject_ref != observation_subject
            || uuid::Uuid::parse_str(&body.observation_id)
                .ok()
                .is_none_or(|id| id.get_version_num() != 7)
            || body.call_number != call.call_number
            || body.call_id != call.call_id
            || body.project_id != contract.receipt_body.project_id
            || body.task_id != contract.receipt_body.task_id
            || body.session_id != expected_session.context("tool event has no expected session")?
            || body.host != call.host
            || body.attempt_receipt != attempt.canonical_receipt
            || body.sealed_truth_revision != call.expected_truth_revision
        {
            anyhow::bail!("canonical cognitive tool observation binding differs");
        }
        require_sha256(&body.arguments_sha256, "tool observation arguments_sha256")?;
        require_sha256(&body.result_sha256, "tool observation result_sha256")?;
    }

    if successful {
        let job_fetches = records
            .iter()
            .filter(|record| record.receipt_body.tool_name == "eliot_cognitive_job_fetch")
            .collect::<Vec<_>>();
        if job_fetches.len() != 1 || job_fetches[0].receipt_body.outcome != "succeeded" {
            anyhow::bail!("cognitive call requires exactly one successful sealed job fetch");
        }
        match call.invocation_role {
            CognitiveInvocationRole::Control => {
                if records.len() != 1 {
                    anyhow::bail!("control call used a tool beyond its sealed job fetch");
                }
            }
            CognitiveInvocationRole::SourceWrite => {
                let submissions = records
                    .iter()
                    .filter(|record| {
                        record.receipt_body.tool_name == "eliot_agent_candidate_submit"
                            && record.receipt_body.outcome == "succeeded"
                    })
                    .count();
                if records.len() != 2 || submissions != 1 {
                    anyhow::bail!(
                        "source call requires exactly one successful daemon-observed candidate submission"
                    );
                }
            }
            CognitiveInvocationRole::Target => {
                let memory_records = records
                    .iter()
                    .filter(|record| record.receipt_body.tool_name != "eliot_cognitive_job_fetch")
                    .collect::<Vec<_>>();
                let minimum_read_revision = attempt
                    .receipt_body
                    .shared_gate
                    .as_ref()
                    .map_or(attempt_memory_revision, |gate| {
                        attempt_memory_revision.max(gate.gate_revision)
                    });
                if memory_records.is_empty()
                    || memory_records.iter().any(|record| {
                        record.receipt_body.outcome != "succeeded"
                            || record
                                .receipt_body
                                .observed_memory_revision
                                .is_none_or(|revision| revision < minimum_read_revision)
                            || !matches!(
                                record.receipt_body.tool_name.as_str(),
                                "eliot_recall_l0" | "eliot_fetch_l2"
                            )
                    })
                {
                    anyhow::bail!("target call has missing, denied, or failed memory-read events");
                }
                let recall = records
                    .iter()
                    .filter(|record| record.receipt_body.tool_name == "eliot_recall_l0")
                    .collect::<Vec<_>>();
                let fetch = records
                    .iter()
                    .filter(|record| record.receipt_body.tool_name == "eliot_fetch_l2")
                    .collect::<Vec<_>>();
                if recall.is_empty()
                    || recall.iter().any(|record| {
                        record.receipt_body.returned_handles != call.expected_exposure_handles
                    })
                    || (!call.expected_exposure_handles.is_empty() && fetch.is_empty())
                    || fetch.iter().any(|record| {
                        record.receipt_body.requested_handles != call.expected_exposure_handles
                    })
                {
                    anyhow::bail!(
                        "daemon-observed memory exposure differs from the exact sealed handles"
                    );
                }
            }
        }
    }
    Ok(records
        .into_iter()
        .map(|record| record.canonical_receipt)
        .collect())
}

pub(super) async fn ensure_cognitive_raw_verifier(
    state: &McpState,
    context: AuthenticatedRequestContext,
    project_id: ProjectId,
    task_id: TaskId,
    attempt: &CanonicalRecord<CognitiveRunAttempt>,
    terminal: &CognitiveTerminalInput,
    tool_observation_receipts: &[WriteReceiptRef],
) -> Result<Vec<WriteReceiptRef>> {
    if terminal.call_number > COGNITIVE_RUN_RAW_VERIFIER_CALLS_U8 {
        if terminal.raw_verifier.is_some() {
            anyhow::bail!("calls 17 and 18 do not accept raw-verifier evidence");
        }
        return Ok(Vec::new());
    }
    let verifier = terminal
        .raw_verifier
        .as_ref()
        .context("calls 1 through 16 require daemon-bound raw-verifier evidence")?;
    if verifier.verifier_version.trim().is_empty() {
        anyhow::bail!("cognitive raw verifier version must not be empty");
    }
    require_sha256(&verifier.checks_sha256, "raw verifier checks_sha256")?;
    let key = format!(
        "cognitive-run:{}:raw-verifier:{}",
        terminal.run_id, terminal.call_number
    );
    let write_id = deterministic_canonical_write_id(
        project_id,
        Some(task_id),
        CanonicalReceiptKind::CognitiveRawVerifier,
        &key,
    );
    let mut evidence = CognitiveRawVerifierEvidence {
        schema_version: COGNITIVE_RUN_SCHEMA_VERSION.to_owned(),
        run_id: terminal.run_id.clone(),
        call_id: attempt.receipt_body.call_id.clone(),
        call_number: terminal.call_number,
        project_id,
        task_id,
        attempt_receipt: attempt.canonical_receipt.clone(),
        execution: terminal.execution.clone(),
        process_sha256: terminal.process_sha256.clone(),
        stdout_sha256: terminal.stdout_sha256.clone(),
        stderr_sha256: terminal.stderr_sha256.clone(),
        provider_output_sha256: terminal.provider_output_sha256.clone(),
        host_observation: terminal.host_observation.clone(),
        tool_observation_receipts: tool_observation_receipts.to_vec(),
        verifier_version: verifier.verifier_version.clone(),
        checks_sha256: verifier.checks_sha256.clone(),
        passed: terminal.status == CognitiveRunCallStatus::Succeeded,
        verified_at: time::OffsetDateTime::now_utc(),
    };
    if let Some(existing) = state
        .store
        .canonical_record_by_write_id::<CognitiveRawVerifierEvidence>(
            project_id,
            Some(task_id),
            &[CanonicalReceiptKind::CognitiveRawVerifier.as_str()],
            write_id,
        )
        .await?
    {
        evidence.verified_at = existing.receipt_body.verified_at;
        if existing.receipt_body != evidence {
            anyhow::bail!("cognitive raw-verifier CAS is occupied by different evidence");
        }
        return Ok(vec![existing.canonical_receipt]);
    }
    let (receipt, status) = write_canonical_observation(
        state,
        context,
        project_id,
        Some(task_id),
        CanonicalReceiptKind::CognitiveRawVerifier,
        &key,
        &evidence,
    )
    .await?;
    if !matches!(
        status,
        WriteStatus::Committed | WriteStatus::IdempotentReplay
    ) {
        anyhow::bail!("cognitive raw-verifier CAS was rejected");
    }
    Ok(vec![receipt])
}

#[allow(clippy::too_many_lines)]
pub(super) async fn cognitive_run_terminal(
    state: &McpState,
    context: AuthenticatedRequestContext,
    params: Value,
) -> Result<Value> {
    state.ensure_schema().await?;
    let input: CognitiveTerminalInput = serde_json::from_value(params)?;
    validate_cognitive_execution(&input.execution)?;
    if input.reason.trim().is_empty() {
        anyhow::bail!("cognitive terminal reason must not be empty");
    }
    if input.status == CognitiveRunCallStatus::Attempting {
        anyhow::bail!("cognitive terminal status cannot be attempting");
    }
    let _guard = cognitive_commit_serializer().lock().await;
    let contract_record = load_cognitive_contract(
        state,
        &CognitiveStatusInput {
            run_id: input.run_id.clone(),
            project_id: input.project_id,
            task_id: input.task_id,
        },
    )
    .await?;
    let call = contract_record
        .receipt_body
        .exact_plan
        .get(usize::from(input.call_number.saturating_sub(1)))
        .filter(|call| call.call_number == input.call_number)
        .context("cognitive call_number is outside the sealed plan")?;
    let attempt_revision = u64::from(input.call_number) * 2 - 1;
    let terminal_revision = attempt_revision + 1;
    let attempt = cognitive_record_by_revision::<CognitiveRunAttempt>(
        state,
        input.project_id,
        input.task_id,
        &input.run_id,
        attempt_revision,
        CanonicalReceiptKind::CognitiveRunAttempt,
    )
    .await?
    .context("cognitive terminal has no canonical attempt")?;
    if attempt.receipt_body.status != CognitiveRunCallStatus::Attempting
        || attempt.receipt_body.execution != input.execution
        || attempt.receipt_body.call_id != call.call_id
        || attempt.receipt_body.contract_receipt != contract_record.canonical_receipt
    {
        anyhow::bail!("cognitive terminal differs from its canonical attempt authority");
    }
    if input.status == CognitiveRunCallStatus::Succeeded
        && (input.process_sha256.is_none()
            || input.stdout_sha256.is_none()
            || input.stderr_sha256.is_none()
            || input.provider_output_sha256.is_none())
    {
        anyhow::bail!(
            "successful cognitive terminal requires process/stdout/stderr/provider hashes"
        );
    }
    for digest in [
        input.process_sha256.as_deref(),
        input.stdout_sha256.as_deref(),
        input.stderr_sha256.as_deref(),
        input.provider_output_sha256.as_deref(),
    ]
    .into_iter()
    .flatten()
    {
        require_sha256(digest, "cognitive terminal digest")?;
    }
    let tool_observation_receipts =
        validate_cognitive_host_and_tools(state, &contract_record, call, &attempt, &input).await?;
    let raw_verifier_receipts = ensure_cognitive_raw_verifier(
        state,
        context,
        input.project_id,
        input.task_id,
        &attempt,
        &input,
        &tool_observation_receipts,
    )
    .await?;
    if let Some(existing) = cognitive_record_by_revision::<CognitiveRunTerminal>(
        state,
        input.project_id,
        input.task_id,
        &input.run_id,
        terminal_revision,
        CanonicalReceiptKind::CognitiveRunTerminal,
    )
    .await?
    {
        let candidate_write_id = attempt.receipt_body.candidate_write_id;
        let expected = CognitiveRunTerminal {
            schema_version: COGNITIVE_RUN_SCHEMA_VERSION.to_owned(),
            run_id: input.run_id,
            call_id: call.call_id.clone(),
            call_number: input.call_number,
            run_revision: terminal_revision,
            expected_previous_revision: attempt_revision,
            attempt_receipt: attempt.canonical_receipt,
            status: input.status,
            execution: input.execution,
            process_sha256: input.process_sha256,
            stdout_sha256: input.stdout_sha256,
            stderr_sha256: input.stderr_sha256,
            provider_output_sha256: input.provider_output_sha256,
            candidate_write_id,
            candidate_receipt: input.candidate_receipt,
            host_observation: input.host_observation,
            tool_observation_receipts: tool_observation_receipts.clone(),
            raw_verifier_receipts: raw_verifier_receipts.clone(),
            reason: input.reason,
            no_redispatch: true,
            finished_at: existing.receipt_body.finished_at,
        };
        if existing.receipt_body != expected {
            anyhow::bail!("cognitive terminal revision is already occupied by a different outcome");
        }
        return Ok(
            json!({ "terminal": existing.receipt_body, "canonical_receipt": existing.canonical_receipt, "replay": true }),
        );
    }
    let candidate_write_id = attempt.receipt_body.candidate_write_id;
    if call.invocation_role == CognitiveInvocationRole::SourceWrite
        && input.status == CognitiveRunCallStatus::Succeeded
    {
        let receipt = input
            .candidate_receipt
            .as_ref()
            .context("successful source-write terminal requires its candidate receipt")?;
        if Some(receipt.write_id) != candidate_write_id {
            anyhow::bail!("source-write candidate receipt differs from the attempt-bound WriteId");
        }
        require_valid_receipt(state, input.project_id, input.task_id, receipt).await?;
    } else if input.candidate_receipt.is_some() {
        anyhow::bail!("candidate receipt is valid only for a successful source-write call");
    }
    let terminal = CognitiveRunTerminal {
        schema_version: COGNITIVE_RUN_SCHEMA_VERSION.to_owned(),
        run_id: input.run_id,
        call_id: call.call_id.clone(),
        call_number: input.call_number,
        run_revision: terminal_revision,
        expected_previous_revision: attempt_revision,
        attempt_receipt: attempt.canonical_receipt,
        status: input.status,
        execution: input.execution,
        process_sha256: input.process_sha256,
        stdout_sha256: input.stdout_sha256,
        stderr_sha256: input.stderr_sha256,
        provider_output_sha256: input.provider_output_sha256,
        candidate_write_id,
        candidate_receipt: input.candidate_receipt,
        host_observation: input.host_observation,
        tool_observation_receipts,
        raw_verifier_receipts,
        reason: input.reason,
        no_redispatch: true,
        finished_at: time::OffsetDateTime::now_utc(),
    };
    let key = cognitive_revision_key(&terminal.run_id, terminal_revision);
    let envelope = canonical_observation_envelope(
        context,
        input.project_id,
        Some(input.task_id),
        CanonicalReceiptKind::CognitiveRunTerminal,
        &key,
        &terminal,
    )?;
    let write_receipt = if call.invocation_role == CognitiveInvocationRole::SourceWrite
        && terminal.status == CognitiveRunCallStatus::Succeeded
    {
        let capability = attempt
            .receipt_body
            .capability
            .as_ref()
            .context("source terminal attempt has no capability")?;
        let candidate_receipt = terminal
            .candidate_receipt
            .clone()
            .context("source terminal has no candidate receipt")?;
        state
            .writer
            .submit_cognitive_terminal(
                envelope,
                CognitiveTerminalPrecondition {
                    project_id: input.project_id,
                    task_id: input.task_id,
                    run_id: terminal.run_id.clone(),
                    call_id: terminal.call_id.clone(),
                    call_number: terminal.call_number,
                    session_id: capability.session_id,
                    attempt_receipt: terminal.attempt_receipt.clone(),
                    candidate_receipt,
                    expected_write_id: capability
                        .expected_write_id
                        .context("source capability has no expected WriteId")?,
                    expected_body_sha256: capability
                        .expected_body_sha256
                        .clone()
                        .context("source capability has no expected body hash")?,
                },
            )
            .await?
    } else {
        state.writer.submit(envelope).await?
    };
    let receipt = WriteReceiptRef {
        receipt_id: write_receipt.receipt_id,
        write_id: write_receipt.write_id,
    };
    let status = write_receipt.status;
    if !matches!(
        status,
        WriteStatus::Committed | WriteStatus::IdempotentReplay
    ) {
        anyhow::bail!("cognitive terminal revision CAS was rejected");
    }
    if let Some(capability) = attempt.receipt_body.capability.as_ref() {
        let _ = fs::remove_file(cognitive_capability_path(state, capability));
    }
    Ok(json!({ "terminal": terminal, "canonical_receipt": receipt, "replay": false }))
}

#[allow(clippy::expect_used, clippy::too_many_lines)]
pub(super) async fn cognitive_run_status(state: &McpState, params: Value) -> Result<Value> {
    state.ensure_schema().await?;
    let input: CognitiveStatusInput = serde_json::from_value(params)?;
    let contract = load_cognitive_contract(state, &input).await?;
    let mut attempts = state
        .store
        .canonical_records_by_subject_ref::<CognitiveRunAttempt>(
            input.project_id,
            Some(input.task_id),
            &[CanonicalReceiptKind::CognitiveRunAttempt.as_str()],
            &input.run_id,
            64,
        )
        .await?
        .into_iter()
        .filter(|record| record.receipt_body.run_id == input.run_id)
        .collect::<Vec<_>>();
    let mut terminals = state
        .store
        .canonical_records_by_subject_ref::<CognitiveRunTerminal>(
            input.project_id,
            Some(input.task_id),
            &[CanonicalReceiptKind::CognitiveRunTerminal.as_str()],
            &input.run_id,
            64,
        )
        .await?
        .into_iter()
        .filter(|record| record.receipt_body.run_id == input.run_id)
        .collect::<Vec<_>>();
    attempts.sort_by_key(|record| record.receipt_body.call_number);
    terminals.sort_by_key(|record| record.receipt_body.call_number);
    for (index, attempt) in attempts.iter().enumerate() {
        let call_number = u8::try_from(index + 1).expect("18 fits u8");
        if attempt.receipt_body.call_number != call_number
            || attempt.receipt_body.run_revision != u64::from(call_number) * 2 - 1
            || attempt.receipt_body.contract_receipt != contract.canonical_receipt
        {
            anyhow::bail!("cognitive status found a non-canonical attempt chain");
        }
    }
    for (index, terminal) in terminals.iter().enumerate() {
        let call_number = u8::try_from(index + 1).expect("18 fits u8");
        if terminal.receipt_body.call_number != call_number
            || terminal.receipt_body.run_revision != u64::from(call_number) * 2
            || attempts
                .get(index)
                .map(|attempt| &attempt.canonical_receipt)
                != Some(&terminal.receipt_body.attempt_receipt)
        {
            anyhow::bail!("cognitive status found a non-canonical terminal chain");
        }
        let replay_input = CognitiveTerminalInput {
            run_id: terminal.receipt_body.run_id.clone(),
            project_id: input.project_id,
            task_id: input.task_id,
            call_number,
            status: terminal.receipt_body.status,
            execution: terminal.receipt_body.execution.clone(),
            process_sha256: terminal.receipt_body.process_sha256.clone(),
            stdout_sha256: terminal.receipt_body.stdout_sha256.clone(),
            stderr_sha256: terminal.receipt_body.stderr_sha256.clone(),
            provider_output_sha256: terminal.receipt_body.provider_output_sha256.clone(),
            candidate_receipt: terminal.receipt_body.candidate_receipt.clone(),
            host_observation: terminal.receipt_body.host_observation.clone(),
            raw_verifier: None,
            reason: terminal.receipt_body.reason.clone(),
        };
        let validated_tool_receipts = validate_cognitive_host_and_tools(
            state,
            &contract,
            &contract.receipt_body.exact_plan[index],
            &attempts[index],
            &replay_input,
        )
        .await?;
        if validated_tool_receipts != terminal.receipt_body.tool_observation_receipts {
            anyhow::bail!("cognitive status tool-observation receipt set differs");
        }
        if call_number <= COGNITIVE_RUN_RAW_VERIFIER_CALLS_U8 {
            let raw_receipt = terminal
                .receipt_body
                .raw_verifier_receipts
                .first()
                .filter(|_| terminal.receipt_body.raw_verifier_receipts.len() == 1)
                .context("cognitive status raw-verifier cardinality differs")?;
            let raw = state
                .store
                .canonical_record_by_write_id::<CognitiveRawVerifierEvidence>(
                    input.project_id,
                    Some(input.task_id),
                    &[CanonicalReceiptKind::CognitiveRawVerifier.as_str()],
                    raw_receipt.write_id,
                )
                .await?
                .context("cognitive status raw-verifier record disappeared")?;
            if raw.canonical_receipt != *raw_receipt
                || raw.receipt_body.run_id != input.run_id
                || raw.receipt_body.call_number != call_number
                || raw.receipt_body.attempt_receipt != terminal.receipt_body.attempt_receipt
                || raw.receipt_body.execution != terminal.receipt_body.execution
                || raw.receipt_body.process_sha256 != terminal.receipt_body.process_sha256
                || raw.receipt_body.stdout_sha256 != terminal.receipt_body.stdout_sha256
                || raw.receipt_body.stderr_sha256 != terminal.receipt_body.stderr_sha256
                || raw.receipt_body.provider_output_sha256
                    != terminal.receipt_body.provider_output_sha256
                || raw.receipt_body.host_observation != terminal.receipt_body.host_observation
                || raw.receipt_body.tool_observation_receipts
                    != terminal.receipt_body.tool_observation_receipts
                || raw.receipt_body.passed
                    != (terminal.receipt_body.status == CognitiveRunCallStatus::Succeeded)
            {
                anyhow::bail!("cognitive status raw-verifier projection differs");
            }
        } else if !terminal.receipt_body.raw_verifier_receipts.is_empty() {
            anyhow::bail!("cognitive status found raw-verifier evidence after call 16");
        }
        if matches!(call_number, 5 | 7)
            && terminal.receipt_body.status == CognitiveRunCallStatus::Succeeded
        {
            let candidate = terminal
                .receipt_body
                .candidate_receipt
                .as_ref()
                .context("cognitive source terminal has no candidate receipt")?;
            if Some(candidate.write_id) != attempts[index].receipt_body.candidate_write_id {
                anyhow::bail!("cognitive source candidate differs from its attempt");
            }
            require_valid_receipt(state, input.project_id, input.task_id, candidate).await?;
        }
        if call_number >= 17 {
            validate_cognitive_gate(
                state,
                &contract,
                attempts[index]
                    .receipt_body
                    .shared_gate
                    .as_ref()
                    .context("reciprocal terminal attempt lost its shared gate")?,
            )
            .await?;
        }
    }
    if attempts.len() >= 18
        && attempts[16].receipt_body.shared_gate != attempts[17].receipt_body.shared_gate
    {
        anyhow::bail!("calls 17 and 18 do not share one exact reciprocal gate");
    }
    let stopped = terminals
        .iter()
        .any(|record| record.receipt_body.status != CognitiveRunCallStatus::Succeeded);
    let next_call = if stopped
        || attempts.len() > terminals.len()
        || terminals.len() == COGNITIVE_RUN_EXACT_CALLS
    {
        None
    } else {
        Some(u8::try_from(terminals.len() + 1).expect("18 fits u8"))
    };
    let current_revision = attempts
        .last()
        .map_or(0, |attempt| attempt.receipt_body.run_revision)
        .max(
            terminals
                .last()
                .map_or(0, |terminal| terminal.receipt_body.run_revision),
        );
    let mut promoted_source_count = 0_usize;
    for candidate in terminals
        .iter()
        .filter(|terminal| matches!(terminal.receipt_body.call_number, 5 | 7))
        .filter_map(|terminal| terminal.receipt_body.candidate_receipt.as_ref())
    {
        let claim = state
            .store
            .claim_card_by_id(
                input.project_id,
                ClaimId::from_uuid(candidate.write_id.as_uuid()),
            )
            .await?;
        if claim.is_some_and(|claim| claim.status == EpistemicStatus::Verified) {
            promoted_source_count += 1;
        }
    }
    let canonical_case_dispositions = if promoted_source_count == 2 {
        resolve_canonical_case_dispositions(
            &state.store,
            &contract,
            time::OffsetDateTime::now_utc(),
        )
        .await?
    } else {
        Vec::new()
    };
    Ok(json!({
        "contract": contract.receipt_body,
        "contract_receipt": contract.canonical_receipt,
        "attempts": attempts,
        "terminals": terminals,
        "current_revision": current_revision,
        "provider_calls_consumed": attempts.len(),
        "hard_provider_call_cap": COGNITIVE_RUN_EXACT_CALLS,
        "next_call": next_call,
        "stopped_no_redispatch": stopped,
        "complete": terminals.len() == COGNITIVE_RUN_EXACT_CALLS && !stopped,
        "canonical_case_dispositions": canonical_case_dispositions,
    }))
}

pub(super) fn cognitive_role_allows(role: CognitiveInvocationRole, tool_name: &str) -> bool {
    if tool_name == "eliot_cognitive_job_fetch" {
        return true;
    }
    match role {
        CognitiveInvocationRole::SourceWrite => tool_name == "eliot_agent_candidate_submit",
        CognitiveInvocationRole::Target => {
            matches!(tool_name, "eliot_recall_l0" | "eliot_fetch_l2")
        }
        CognitiveInvocationRole::Control => false,
    }
}

pub(super) async fn cognitive_principal(
    state: &McpState,
    session_id: SessionId,
) -> Result<CognitivePrincipalClaims> {
    state
        .cognitive_principals
        .lock()
        .await
        .get(&session_id)
        .cloned()
        .context("cognitive child session has no run-scoped principal")
}

pub(super) async fn cognitive_tool_definitions(
    state: &McpState,
    session_id: SessionId,
) -> Result<Vec<Value>> {
    let role = cognitive_principal(state, session_id)
        .await?
        .capability
        .invocation_role;
    Ok(
        tool_definitions_for_profile(McpAccessProfile::CognitiveChild)
            .into_iter()
            .filter(|definition| {
                definition
                    .get("name")
                    .and_then(Value::as_str)
                    .is_some_and(|name| cognitive_role_allows(role, name))
            })
            .collect(),
    )
}

pub(super) fn cognitive_memory_request_allowed(
    capability: &CognitiveCandidateCapability,
    tool_name: &str,
    arguments: &Value,
) -> bool {
    if capability.invocation_role != CognitiveInvocationRole::Target
        || !matches!(tool_name, "eliot_recall_l0" | "eliot_fetch_l2")
    {
        return true;
    }
    let expected_project = capability.project_id.to_string();
    if arguments.get("project_id").and_then(Value::as_str) != Some(expected_project.as_str()) {
        return false;
    }
    tool_name != "eliot_fetch_l2"
        || (!capability.expected_exposure_handles.is_empty()
            && string_array_field(arguments, "handles") == capability.expected_exposure_handles)
}

pub(super) fn restrict_cognitive_recall(
    structured: &mut Value,
    expected_handles: &[String],
) -> Result<()> {
    let returned = {
        let handles = structured
            .get_mut("handles")
            .and_then(Value::as_array_mut)
            .context("cognitive recall response has no handles array")?;
        let mut by_handle = handles
            .drain(..)
            .filter_map(|item| {
                let handle = item
                    .get("handle")
                    .and_then(Value::as_str)
                    .map(str::to_owned)?;
                Some((handle, item))
            })
            .collect::<HashMap<_, _>>();
        *handles = expected_handles
            .iter()
            .filter_map(|handle| by_handle.remove(handle))
            .collect();
        handles.len()
    };
    if let Some(truncation) = structured.get_mut("truncation") {
        truncation["returned"] = json!(returned);
        truncation["limit"] = json!(expected_handles.len().max(1));
        truncation["truncated"] = json!(false);
    }
    Ok(())
}

pub(super) async fn ensure_cognitive_tool_observation_capacity(
    state: &McpState,
    capability: &CognitiveCandidateCapability,
) -> Result<()> {
    let subject = cognitive_tool_observation_subject(&capability.run_id, capability.call_number);
    let visible = state
        .store
        .canonical_records_by_subject_ref::<CognitiveToolObservation>(
            capability.project_id,
            Some(capability.task_id),
            &[CanonicalReceiptKind::CognitiveToolObservation.as_str()],
            &subject,
            COGNITIVE_TOOL_OBSERVATION_QUERY_LIMIT,
        )
        .await?;
    if visible.len() >= COGNITIVE_TOOL_OBSERVATION_MAX {
        anyhow::bail!("cognitive call exhausted its canonical tool-observation cap");
    }
    Ok(())
}

#[allow(clippy::too_many_lines)] // One transaction-shaped audit record is kept contiguous.
pub(super) async fn write_cognitive_tool_observation(
    state: &McpState,
    context: AuthenticatedRequestContext,
    claims: &CognitivePrincipalClaims,
    tool_name: &str,
    outcome: &str,
    arguments: &Value,
    result: &Value,
) -> Result<WriteReceiptRef> {
    let capability = &claims.capability;
    let attempt_revision = u64::from(capability.call_number) * 2 - 1;
    let attempt = cognitive_record_by_revision::<CognitiveRunAttempt>(
        state,
        capability.project_id,
        capability.task_id,
        &capability.run_id,
        attempt_revision,
        CanonicalReceiptKind::CognitiveRunAttempt,
    )
    .await?
    .context("cognitive tool observation has no canonical attempt")?;
    if attempt.canonical_receipt != claims.attempt_receipt
        || attempt.receipt_body.status != CognitiveRunCallStatus::Attempting
        || attempt.receipt_body.capability.as_ref() != Some(capability)
        || cognitive_record_by_revision::<CognitiveRunTerminal>(
            state,
            capability.project_id,
            capability.task_id,
            &capability.run_id,
            attempt_revision + 1,
            CanonicalReceiptKind::CognitiveRunTerminal,
        )
        .await?
        .is_some()
    {
        anyhow::bail!("cognitive tool observation capability is stale or terminal");
    }
    let requested_handles = if tool_name == "eliot_fetch_l2" {
        string_array_field(arguments, "handles")
    } else {
        Vec::new()
    };
    let returned_handles = if tool_name == "eliot_recall_l0" {
        result
            .get("handles")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|handle| handle.get("handle").and_then(Value::as_str))
            .map(str::to_owned)
            .collect()
    } else {
        Vec::new()
    };
    let result_sha256 = if tool_name == "eliot_cognitive_job_fetch" {
        sha256_json(&(
            &capability.run_id,
            capability.call_number,
            &capability.call_id,
            "job_packet_delivered",
        ))?
    } else {
        sha256_json(result)?
    };
    let observation = CognitiveToolObservation {
        schema_version: COGNITIVE_RUN_SCHEMA_VERSION.to_owned(),
        run_id: capability.run_id.clone(),
        call_subject_ref: cognitive_tool_observation_subject(
            &capability.run_id,
            capability.call_number,
        ),
        observation_id: uuid::Uuid::now_v7().to_string(),
        call_id: capability.call_id.clone(),
        call_number: capability.call_number,
        project_id: capability.project_id,
        task_id: capability.task_id,
        session_id: capability.session_id,
        host: capability.host,
        attempt_receipt: claims.attempt_receipt.clone(),
        tool_name: tool_name.to_owned(),
        outcome: outcome.to_owned(),
        sealed_truth_revision: capability.expected_truth_revision.clone(),
        observed_memory_revision: result.get("at_revision").and_then(Value::as_u64),
        arguments_sha256: sha256_json(arguments)?,
        result_sha256,
        requested_handles,
        returned_handles,
        observed_at: time::OffsetDateTime::now_utc(),
    };
    let key = format!(
        "cognitive-tool:{}:{}:{}:{}:{}:{}:{}:{}",
        observation.run_id,
        observation.call_number,
        observation.session_id,
        observation.observation_id,
        observation.tool_name,
        observation.outcome,
        observation.arguments_sha256,
        observation.result_sha256,
    );
    let (receipt, status) = write_canonical_observation(
        state,
        context,
        observation.project_id,
        Some(observation.task_id),
        CanonicalReceiptKind::CognitiveToolObservation,
        &key,
        &observation,
    )
    .await?;
    if !matches!(
        status,
        WriteStatus::Committed | WriteStatus::IdempotentReplay
    ) {
        anyhow::bail!("cognitive tool observation CAS was rejected");
    }
    Ok(receipt)
}

pub(super) async fn dispatch_cognitive_job_fetch(
    state: &McpState,
    context: AuthenticatedRequestContext,
    arguments: Value,
) -> Result<Value> {
    let call_id = arguments
        .get("call_id")
        .and_then(Value::as_str)
        .context("eliot_cognitive_job_fetch requires call_id")?;
    let claims = cognitive_principal(state, context.session_id).await?;
    if call_id != claims.capability.call_id {
        anyhow::bail!("cognitive job call_id differs from authenticated capability");
    }
    let file = read_cognitive_capability_file(&claims.capability_file)?;
    if file.capability != claims.capability {
        anyhow::bail!("cognitive job packet authority changed after authentication");
    }
    let contract = load_cognitive_contract(
        state,
        &CognitiveStatusInput {
            run_id: claims.capability.run_id.clone(),
            project_id: claims.capability.project_id,
            task_id: claims.capability.task_id,
        },
    )
    .await?;
    let call = contract
        .receipt_body
        .exact_plan
        .get(usize::from(claims.capability.call_number - 1))
        .context("cognitive job call is outside the sealed contract")?;
    if call.call_id != call_id || sha256_bytes(file.job_packet.as_bytes()) != call.prompt_sha256 {
        anyhow::bail!("cognitive job packet differs from the sealed call");
    }
    Ok(json!({
        "schema_version": "eliot-cognitive-job-packet-v1",
        "call_id": call.call_id,
        "invocation_role": call.invocation_role,
        "packet": file.job_packet,
    }))
}

pub(super) async fn dispatch_cognitive_lab_evaluate(
    state: &McpState,
    context: AuthenticatedRequestContext,
    arguments: Value,
) -> Result<Value> {
    let input: CognitiveLabToolInput = serde_json::from_value(arguments)?;
    let project_id = parse_project_id(&input.project_id)?;
    let task_id = TaskId::from_str(&input.task_id).context("parse cognitive-lab task_id")?;
    let mut report =
        CognitiveTransferLabService::evaluate(input.run_id, &input.cases, &input.answers);
    if let Some(existing) = semantic_records::<eliot_types::CognitiveTransferLabReport>(
        state,
        project_id,
        "cognitive_transfer_lab_report",
    )
    .await?
    .into_iter()
    .find(|existing| existing.run_id == report.run_id)
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
        "cognitive_transfer_lab_report",
        &report,
    )
    .await?;
    report.receipt = Some(receipt);
    let mut value = serde_json::to_value(report)?;
    value["idempotent_replay"] = Value::Bool(false);
    Ok(value)
}

pub(super) async fn dispatch_cognitive_failure_localization_record(
    state: &McpState,
    context: AuthenticatedRequestContext,
    arguments: Value,
) -> Result<Value> {
    let mut input: CognitiveFailureLocalizationToolInput = serde_json::from_value(arguments)?;
    if input.report.influence_receipt.trim().is_empty()
        || input.report.exact_evidence_refs.is_empty()
        || input.report.required_correction.trim().is_empty()
    {
        anyhow::bail!(
            "cognitive failure localization requires an influence receipt, exact evidence, and correction owner"
        );
    }
    let project_id = parse_project_id(&input.project_id)?;
    let task_id = TaskId::from_str(&input.task_id).context("parse failure localization task_id")?;
    if let Some(existing) = semantic_records::<CognitiveFailureLocalizationReport>(
        state,
        project_id,
        "cognitive_failure_localization_report",
    )
    .await?
    .into_iter()
    .find(|existing| existing.report_id == input.report.report_id)
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
        "cognitive_failure_localization_report",
        &input.report,
    )
    .await?;
    input.report.receipt = Some(receipt);
    let mut value = serde_json::to_value(input.report)?;
    value["idempotent_replay"] = Value::Bool(false);
    Ok(value)
}

pub(super) async fn cognitive_records<T>(
    state: &McpState,
    project_id: ProjectId,
    task_id: TaskId,
    receipt_kind: &str,
) -> Result<Vec<T>>
where
    T: serde::de::DeserializeOwned,
{
    state
        .store
        .tool_observations_by_kind(project_id, task_id, receipt_kind)
        .await?
        .into_iter()
        .map(|observation| {
            serde_json::from_value(
                observation
                    .payload
                    .get("receipt_body")
                    .cloned()
                    .context("canonical observation has no receipt_body")?,
            )
            .map_err(Into::into)
        })
        .collect()
}

pub(super) fn cognitive_record_schema(field: &str) -> Value {
    let mut properties = serde_json::Map::new();
    properties.insert("project_id".to_owned(), json!({"type": "string"}));
    properties.insert(field.to_owned(), json!({"type": "object"}));
    json!({
        "type": "object",
        "additionalProperties": false,
        "properties": properties,
        "required": ["project_id", field]
    })
}
