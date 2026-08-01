#![allow(
    clippy::expect_used,
    clippy::format_collect,
    clippy::needless_pass_by_value,
    clippy::print_stdout,
    clippy::too_many_lines
)]

use crate::{named_pipe_ipc, runtime_bootstrap, runtime_instance::RuntimeInstance};
use anyhow::{Context, Result};
use eliot_types::{
    AgentHostId, CognitiveExecutionSeal, CognitiveHostObservation, CognitiveInvocationRole,
    CognitiveRunCallPlan, CognitiveRunContract, CognitiveSharedGateBinding,
    MAX_SECRET_BOUNDARY_BYTES, ProjectId, SecretBoundaryRule, SessionId, TaskId, WriteReceiptRef,
    inspect_secret_bytes,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::{Duration, Instant};

const COGNITIVE_RUNNER_REQUEST_SCHEMA: &str = "eliot-cognitive-runner-request-v1";
const COGNITIVE_RUNNER_VERIFIER_VERSION: &str = "eliot-cognitive-rust-verifier-v1";

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CognitiveRunnerRequest {
    schema_version: String,
    instance_name: String,
    run_id: String,
    project_id: ProjectId,
    task_id: TaskId,
    call_number: u8,
    host: AgentHostId,
    model: String,
    executable: PathBuf,
    provider_executable: PathBuf,
    argv: Vec<String>,
    #[serde(default)]
    environment: BTreeMap<String, String>,
    cwd: PathBuf,
    bundle_path: PathBuf,
    prompt_path: PathBuf,
    cases_path: PathBuf,
    exposure_map_path: PathBuf,
    output_contract_path: PathBuf,
    models_path: PathBuf,
    expected_truth_revision: String,
    expected_exposure_handles: Vec<String>,
    #[serde(default)]
    expected_candidate_body_sha256: Option<String>,
    #[serde(default)]
    shared_gate: Option<CognitiveSharedGateBinding>,
    output_root: PathBuf,
    timeout_seconds: u64,
}

#[derive(Clone, Debug, Serialize)]
#[allow(clippy::struct_excessive_bools)]
struct CognitiveProcessProjection {
    schema_version: &'static str,
    run_id: String,
    call_id: String,
    call_number: u8,
    host: AgentHostId,
    model: String,
    launcher_executable: String,
    launcher_executable_sha256_before: String,
    launcher_executable_sha256_after: Option<String>,
    launcher_binary_stable: bool,
    launcher_matches_execution_seal: bool,
    launcher_image: String,
    launcher_volume_serial_number: u32,
    launcher_file_index: u64,
    launcher_attested_in_job: bool,
    provider_executable: String,
    provider_executable_sha256_before: String,
    provider_executable_sha256_after: Option<String>,
    provider_binary_stable: bool,
    provider_matches_execution_seal: bool,
    provider_pid: Option<u32>,
    provider_image: Option<String>,
    provider_volume_serial_number: Option<u32>,
    provider_file_index: Option<u64>,
    provider_image_sha256: Option<String>,
    provider_attested_in_job: bool,
    provider_bundle: String,
    provider_bundle_sha256_before: String,
    provider_bundle_sha256_after: Option<String>,
    provider_bundle_stable: bool,
    provider_bundle_matches_execution_seal: bool,
    provider_bundle_mutation_attempted: bool,
    observed_job_processes: Vec<CognitiveJobProcessProjection>,
    job_observation_errors: Vec<String>,
    launcher_pid: u32,
    job_object_containment: &'static str,
    exit_code: Option<i32>,
    timed_out: bool,
    latency_ms: u128,
    stdout_sha256: Option<String>,
    stderr_sha256: Option<String>,
    secret_boundary_rule: Option<SecretBoundaryRule>,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
struct CognitiveJobProcessProjection {
    pid: u32,
    image: String,
    volume_serial_number: u32,
    file_index: u64,
}

struct ManagedOutput {
    projection: CognitiveProcessProjection,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    secret_boundary_rule: Option<SecretBoundaryRule>,
}

struct PinnedInputFile {
    _handle: eliot_windows_ipc::PinnedFile,
    bytes: Vec<u8>,
}

impl PinnedInputFile {
    fn open(path: &Path) -> Result<Self> {
        let mut handle = eliot_windows_ipc::PinnedFile::open(path)
            .with_context(|| format!("pin sealed input {}", path.display()))?;
        let bytes = handle
            .read_all()
            .with_context(|| format!("read pinned sealed input {}", path.display()))?;
        Ok(Self {
            _handle: handle,
            bytes,
        })
    }

    fn sha256(&self) -> String {
        sha256_bytes(&self.bytes)
    }
}

struct PinnedStaticInputs {
    prompt: PinnedInputFile,
    cases: PinnedInputFile,
    exposure_map: PinnedInputFile,
    output_contract: PinnedInputFile,
    models: PinnedInputFile,
}

impl PinnedStaticInputs {
    fn open(request: &CognitiveRunnerRequest) -> Result<Self> {
        Ok(Self {
            prompt: PinnedInputFile::open(&request.prompt_path)?,
            cases: PinnedInputFile::open(&request.cases_path)?,
            exposure_map: PinnedInputFile::open(&request.exposure_map_path)?,
            output_contract: PinnedInputFile::open(&request.output_contract_path)?,
            models: PinnedInputFile::open(&request.models_path)?,
        })
    }
}

struct PinnedBundleFile {
    relative: String,
    handle: eliot_windows_ipc::PinnedFile,
}

struct PinnedBundle {
    directories: Vec<eliot_windows_ipc::DirectoryOplockGuard>,
    files: Vec<PinnedBundleFile>,
    single_file: bool,
}

impl PinnedBundle {
    fn open(path: &Path) -> Result<Self> {
        if path.is_file() {
            return Ok(Self {
                directories: Vec::new(),
                files: vec![PinnedBundleFile {
                    relative: String::new(),
                    handle: eliot_windows_ipc::PinnedFile::open(path)
                        .with_context(|| format!("pin provider bundle {}", path.display()))?,
                }],
                single_file: true,
            });
        }
        let root = path.canonicalize()?;
        let mut bundle = Self {
            directories: Vec::new(),
            files: Vec::new(),
            single_file: false,
        };
        pin_bundle_directory(&root, &root, &mut bundle)?;
        bundle
            .files
            .sort_by(|left, right| left.relative.cmp(&right.relative));
        Ok(bundle)
    }

    fn sha256(&mut self) -> Result<String> {
        if self.single_file {
            let file = self
                .files
                .first_mut()
                .context("pinned single-file bundle is empty")?;
            return Ok(sha256_bytes(&file.handle.read_all()?));
        }
        let mut hasher = Sha256::new();
        for file in &mut self.files {
            hasher.update(file.relative.as_bytes());
            hasher.update([0]);
            hasher.update(file.handle.read_all()?);
            hasher.update([0]);
        }
        Ok(hasher
            .finalize()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect())
    }

    fn mutation_attempted(&self) -> Result<bool> {
        self.directories
            .iter()
            .try_fold(false, |detected, directory| {
                Ok(detected || directory.mutation_attempted()?)
            })
    }
}

fn pin_bundle_directory(root: &Path, directory: &Path, bundle: &mut PinnedBundle) -> Result<()> {
    reject_reparse_path(directory)?;
    bundle
        .directories
        .push(eliot_windows_ipc::DirectoryOplockGuard::acquire(directory)?);
    let mut entries = fs::read_dir(directory)?.collect::<std::io::Result<Vec<_>>>()?;
    entries.sort_by_key(std::fs::DirEntry::file_name);
    for entry in entries {
        let path = entry.path();
        reject_reparse_path(&path)?;
        let file_type = entry.file_type()?;
        if file_type.is_symlink() {
            anyhow::bail!("cognitive bundle cannot contain symlinks");
        }
        if file_type.is_dir() {
            pin_bundle_directory(root, &path, bundle)?;
        } else if file_type.is_file() {
            bundle.files.push(PinnedBundleFile {
                relative: path
                    .strip_prefix(root)?
                    .to_string_lossy()
                    .replace('\\', "/"),
                handle: eliot_windows_ipc::PinnedFile::open(&path)?,
            });
        }
    }
    Ok(())
}

struct PinnedExecutionAuthority {
    launcher_path: String,
    provider_path: String,
    bundle_path: String,
    launcher: eliot_windows_ipc::PinnedFile,
    provider: eliot_windows_ipc::PinnedFile,
    bundle: PinnedBundle,
}

impl PinnedExecutionAuthority {
    fn open(request: &CognitiveRunnerRequest) -> Result<Self> {
        let launcher = eliot_windows_ipc::PinnedFile::open(&request.executable)
            .context("pin cognitive launcher executable")?;
        let provider = eliot_windows_ipc::PinnedFile::open(&request.provider_executable)
            .context("pin cognitive provider executable")?;
        let bundle = PinnedBundle::open(&request.bundle_path)?;
        Ok(Self {
            launcher_path: canonical_path_string(&request.executable)?,
            provider_path: canonical_path_string(&request.provider_executable)?,
            bundle_path: canonical_path_string(&request.bundle_path)?,
            launcher,
            provider,
            bundle,
        })
    }

    fn hashes(&mut self) -> Result<(String, String, String)> {
        Ok((
            sha256_bytes(&self.launcher.read_all()?),
            sha256_bytes(&self.provider.read_all()?),
            self.bundle.sha256()?,
        ))
    }
}

pub(crate) async fn seal(
    config_path: &Path,
    request_path: &Path,
    instance_name: &str,
) -> Result<()> {
    let request: Value = serde_json::from_slice(&fs::read(request_path)?)?;
    if request.get("instance_name").and_then(Value::as_str) != Some(instance_name) {
        anyhow::bail!("cognitive seal request instance differs from --instance");
    }
    let instance = ready_instance(config_path, "cognitive_seal", instance_name).await?;
    let result =
        named_pipe_ipc::cognitive_governor_request(&instance, "cognitive/seal", request).await?;
    println!("{}", serde_json::to_string(&result)?);
    Ok(())
}

pub(crate) async fn status(
    config_path: &Path,
    run_id: &str,
    project_id: &str,
    task_id: &str,
    instance_name: &str,
) -> Result<()> {
    let instance = ready_instance(config_path, "cognitive_status", instance_name).await?;
    let result = named_pipe_ipc::cognitive_governor_request(
        &instance,
        "cognitive/status",
        json!({
            "run_id": run_id,
            "project_id": ProjectId::from_str(project_id)?,
            "task_id": TaskId::from_str(task_id)?,
        }),
    )
    .await?;
    println!("{}", serde_json::to_string(&result)?);
    Ok(())
}

async fn ready_instance(
    config_path: &Path,
    caller: &str,
    instance_name: &str,
) -> Result<RuntimeInstance> {
    let instance = RuntimeInstance::select(config_path, Some(instance_name))?;
    let governor = std::env::current_exe().context("resolve Eliot Governor executable")?;
    runtime_bootstrap::ensure_daemon_ready(
        config_path,
        &governor,
        named_pipe_ipc::IPC_PROTOCOL_VERSION,
        caller,
        instance.name(),
    )
    .await?;
    Ok(instance)
}

pub(crate) async fn run(
    config_path: &Path,
    request_path: &Path,
    instance_name: &str,
) -> Result<()> {
    reject_reparse_path(request_path)?;
    let request_authority = PinnedInputFile::open(request_path)?;
    let request: CognitiveRunnerRequest = serde_json::from_slice(&request_authority.bytes)
        .context("decode cognitive runner request")?;
    validate_original_request_paths(&request)?;
    validate_request(&request)?;
    if request.instance_name != instance_name {
        anyhow::bail!("cognitive runner request instance differs from --instance");
    }
    let static_inputs = PinnedStaticInputs::open(&request)?;
    let sealed_prompt = std::str::from_utf8(&static_inputs.prompt.bytes)
        .context("sealed cognitive prompt is not UTF-8")?;
    let mut execution_authority = PinnedExecutionAuthority::open(&request)?;
    let (launcher_sha256, provider_sha256, bundle_sha256) = execution_authority.hashes()?;
    fs::create_dir_all(&request.output_root).context("create cognitive output root")?;
    reject_reparse_path(&request.output_root)?;
    let output_root_authority = eliot_windows_ipc::PinnedDirectory::open(&request.output_root)
        .context("pin cognitive output root")?;

    let instance = ready_instance(config_path, "cognitive_runner", instance_name).await?;

    // Invocation status is canonical state, not a local artifact. Re-read it immediately
    // before every dispatch; cognitive/begin performs the revision CAS again.
    let scope = json!({
        "run_id": request.run_id,
        "project_id": request.project_id,
        "task_id": request.task_id,
    });
    let status =
        named_pipe_ipc::cognitive_governor_request(&instance, "cognitive/status", scope.clone())
            .await?;
    let contract: CognitiveRunContract = serde_json::from_value(
        status
            .get("contract")
            .cloned()
            .context("cognitive status has no contract")?,
    )?;
    let call = contract
        .exact_plan
        .get(usize::from(request.call_number.saturating_sub(1)))
        .filter(|call| call.call_number == request.call_number)
        .context("runner call is outside the canonical exact plan")?;
    validate_request_against_contract(&request, &contract, call, &static_inputs)?;
    let bootstrap = cognitive_job_bootstrap(&call.call_id);
    validate_host_argv(&request, &bootstrap, config_path)?;
    if status.get("next_call").and_then(Value::as_u64) != Some(u64::from(request.call_number)) {
        let attempts = status.get("attempts").and_then(Value::as_array);
        let terminals = status.get("terminals").and_then(Value::as_array);
        if attempts.is_some_and(|items| items.len() == terminals.map_or(0, Vec::len) + 1)
            && let Some(attempt) = attempts.and_then(|items| items.last())
            && attempt
                .get("receipt_body")
                .and_then(|body| body.get("call_number"))
                .and_then(Value::as_u64)
                == Some(u64::from(request.call_number))
        {
            let body = attempt
                .get("receipt_body")
                .context("attempt body is absent")?;
            let execution = body
                .get("execution")
                .cloned()
                .context("attempt execution is absent")?;
            let reconciliation = json!({
                "reason": "canonical Attempting revision survived without a terminal",
                "action": "seal_unknown_outcome_without_redispatch",
                "call_number": request.call_number,
            });
            let raw_verifier = (request.call_number <= 16).then(|| {
                json!({
                    "verifier_version": COGNITIVE_RUNNER_VERIFIER_VERSION,
                    "checks_sha256": sha256_json(&reconciliation).expect("JSON serializes"),
                })
            });
            let host_observation = rejected_host_observation(&request, body)?;
            let terminal = named_pipe_ipc::cognitive_governor_request(
                &instance,
                "cognitive/terminal",
                json!({
                    "run_id": request.run_id,
                    "project_id": request.project_id,
                    "task_id": request.task_id,
                    "call_number": request.call_number,
                    "status": "unknown_outcome",
                    "execution": execution,
                    "process_sha256": null,
                    "stdout_sha256": null,
                    "stderr_sha256": null,
                    "provider_output_sha256": null,
                    "candidate_receipt": null,
                    "host_observation": host_observation,
                    "raw_verifier": raw_verifier,
                    "reason": "surviving canonical attempt is ambiguous; sealed UnknownOutcome without redispatch",
                }),
            )
            .await?;
            fs::create_dir_all(&request.output_root)?;
            write_output_json(&request.output_root.join("terminal.json"), &terminal)?;
            anyhow::bail!(
                "reconciled an incomplete cognitive attempt as UnknownOutcome; redispatch is forbidden"
            );
        }
        anyhow::bail!("canonical status does not admit this cognitive call; no dispatch occurred");
    }

    let mut environment = current_environment()?;
    environment.extend(request.environment.clone());
    let capability_path = predicted_capability_path(&instance, &contract, call);
    environment.insert(
        "ELIOT_COGNITIVE_CAPABILITY_FILE".to_owned(),
        capability_path.to_string_lossy().into_owned(),
    );
    if call.variant == "control" {
        environment.insert("ELIOT_COGNITIVE_CONTROL".to_owned(), "1".to_owned());
    }
    let execution = CognitiveExecutionSeal {
        executable_sha256: launcher_sha256,
        provider_executable_sha256: provider_sha256,
        argv_sha256: sha256_json(&request.argv)?,
        environment_sha256: sha256_json(&environment)?,
        cwd_sha256: sha256_bytes(canonical_path_string(&request.cwd)?.as_bytes()),
        bundle_sha256,
        prompt_sha256: static_inputs.prompt.sha256(),
    };
    validate_execution_against_models(&request, call, &execution, &static_inputs.models.bytes)?;
    let begin = named_pipe_ipc::cognitive_governor_request(
        &instance,
        "cognitive/begin",
        json!({
            "run_id": request.run_id,
            "project_id": request.project_id,
            "task_id": request.task_id,
            "call_number": request.call_number,
            "execution": execution,
            "job_packet": sealed_prompt,
            "shared_gate": request.shared_gate,
        }),
    )
    .await?;
    let attempt = begin
        .get("attempt")
        .cloned()
        .context("cognitive begin has no canonical attempt")?;
    if begin.get("dispatch_admitted").and_then(Value::as_bool) != Some(true)
        || begin.get("replay").and_then(Value::as_bool) != Some(false)
    {
        anyhow::bail!(
            "cognitive begin was a replay; canonical reconciliation forbids provider spawn"
        );
    }
    let call_id = attempt
        .get("call_id")
        .and_then(Value::as_str)
        .context("canonical attempt has no call_id")?
        .to_owned();
    if call_id != call.call_id {
        anyhow::bail!("canonical attempt call differs from the sealed plan");
    }
    let capability_path = begin
        .get("capability_file")
        .and_then(Value::as_str)
        .context("cognitive attempt has no protected job capability file")?;
    let expected = environment
        .get("ELIOT_COGNITIVE_CAPABILITY_FILE")
        .context("job capability was not included in exact environment")?;
    if capability_path != expected {
        anyhow::bail!("daemon capability path differs from the pre-sealed exact environment");
    }

    write_output_json(&request.output_root.join("attempt.json"), &attempt)?;
    let command_request = request.clone();
    let command_environment = environment.clone();
    let command_call_id = call_id.clone();
    let command_launcher_sha256 = execution.executable_sha256.clone();
    let command_provider_sha256 = execution.provider_executable_sha256.clone();
    let command_bundle_sha256 = execution.bundle_sha256.clone();
    let operation_runtime =
        crate::host_runtime::supervised_process::daemon_operation_runtime_handle(config_path)?;
    let managed = run_managed_process(
        &command_request,
        &command_environment,
        &command_call_id,
        &command_launcher_sha256,
        &command_provider_sha256,
        &command_bundle_sha256,
        execution_authority,
        operation_runtime,
    )
    .await?;

    write_output_json(
        &request.output_root.join("process.json"),
        &managed.projection,
    )?;
    let output_admitted = managed.secret_boundary_rule.is_none();
    if output_admitted {
        eliot_windows_ipc::write_new_pinned_file(
            &request.output_root.join("raw.stdout"),
            &managed.stdout,
        )?;
        eliot_windows_ipc::write_new_pinned_file(
            &request.output_root.join("raw.stderr"),
            &managed.stderr,
        )?;
    } else {
        write_output_json(
            &request.output_root.join("secret-boundary-rejection.json"),
            &json!({
                "schema_version": "eliot-secret-boundary-rejection-v1",
                "rule": managed.secret_boundary_rule,
                "raw_persisted": false,
                "content_digest_persisted": false,
            }),
        )?;
    }
    let parsed = output_admitted
        .then(|| parse_provider_output(&managed.stdout).ok())
        .flatten();
    if let Some(parsed) = parsed.as_ref() {
        write_output_json(&request.output_root.join("parsed.json"), parsed)?;
    }
    let host_observation = if output_admitted {
        host_observation(&request, &attempt, &managed.stdout)?
    } else {
        rejected_host_observation(&request, &attempt)?
    };
    let mut verification = verify_provider_output(
        &request,
        call,
        parsed.as_ref(),
        &static_inputs.output_contract.bytes,
        &static_inputs.cases.bytes,
    );
    let governor_session_attested = host_observation.governor_session_id.is_some();
    let host_observation_attested = output_admitted
        && governor_session_attested
        && outer_host_observation_attested(&request, &host_observation, &managed.stdout);
    if let Some(checks) = verification.get_mut("checks").and_then(Value::as_array_mut) {
        checks.push(json!({
            "name": "launcher_image_attested_in_job",
            "passed": managed.projection.launcher_attested_in_job,
        }));
        checks.push(json!({
            "name": "launcher_binary_hash_stable",
            "passed": managed.projection.launcher_binary_stable,
        }));
        checks.push(json!({
            "name": "launcher_binary_matches_execution_seal",
            "passed": managed.projection.launcher_matches_execution_seal,
        }));
        checks.push(json!({
            "name": "provider_image_attested_in_job",
            "passed": managed.projection.provider_attested_in_job,
        }));
        checks.push(json!({
            "name": "provider_binary_hash_stable",
            "passed": managed.projection.provider_binary_stable,
        }));
        checks.push(json!({
            "name": "provider_binary_matches_execution_seal",
            "passed": managed.projection.provider_matches_execution_seal,
        }));
        checks.push(json!({
            "name": "provider_bundle_hash_stable",
            "passed": managed.projection.provider_bundle_stable,
        }));
        checks.push(json!({
            "name": "provider_bundle_matches_execution_seal",
            "passed": managed.projection.provider_bundle_matches_execution_seal,
        }));
        checks.push(json!({
            "name": "provider_bundle_namespace_immutable",
            "passed": !managed.projection.provider_bundle_mutation_attempted,
        }));
        checks.push(json!({
            "name": "governor_session_attested",
            "passed": governor_session_attested,
        }));
        checks.push(json!({
            "name": "host_outer_protocol_attested",
            "passed": host_observation_attested,
        }));
        checks.push(json!({
            "name": "secret_boundary_admitted",
            "passed": output_admitted,
        }));
    }
    let process_succeeded = output_admitted
        && managed.projection.exit_code == Some(0)
        && !managed.projection.timed_out
        && managed.projection.launcher_attested_in_job
        && managed.projection.launcher_binary_stable
        && managed.projection.launcher_matches_execution_seal
        && managed.projection.provider_attested_in_job
        && managed.projection.provider_binary_stable
        && managed.projection.provider_matches_execution_seal
        && managed.projection.provider_bundle_stable
        && managed.projection.provider_bundle_matches_execution_seal
        && !managed.projection.provider_bundle_mutation_attempted
        && host_observation_attested;
    if !process_succeeded {
        verification["passed"] = Value::Bool(false);
        verification["classification"] = Value::String("RejectedExternalOpinion".to_owned());
    }
    write_output_json(
        &request.output_root.join("verification.json"),
        &verification,
    )?;
    let verifier_passed = verification
        .get("passed")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let provider_output_sha256 = output_admitted.then(|| {
        parsed.as_ref().map_or_else(
            || sha256_bytes(&managed.stdout),
            |value| sha256_json(value).expect("JSON value serializes"),
        )
    });
    let process_sha256 = sha256_json(&managed.projection)?;
    let terminal_status = if managed.projection.timed_out {
        "unknown_outcome"
    } else if process_succeeded && verifier_passed {
        "succeeded"
    } else {
        "failed"
    };
    let candidate_receipt = if call.invocation_role == CognitiveInvocationRole::SourceWrite
        && terminal_status == "succeeded"
    {
        Some(candidate_receipt(
            parsed
                .as_ref()
                .context("successful source output is absent")?,
        )?)
    } else {
        None
    };
    let raw_verifier = (request.call_number <= 16).then(|| {
        json!({
            "verifier_version": COGNITIVE_RUNNER_VERIFIER_VERSION,
            "checks_sha256": sha256_json(&verification).expect("verification JSON serializes"),
        })
    });
    let terminal = named_pipe_ipc::cognitive_governor_request(
        &instance,
        "cognitive/terminal",
        json!({
            "run_id": request.run_id,
            "project_id": request.project_id,
            "task_id": request.task_id,
            "call_number": request.call_number,
            "status": terminal_status,
            "execution": execution,
            "process_sha256": process_sha256,
            "stdout_sha256": managed.projection.stdout_sha256,
            "stderr_sha256": managed.projection.stderr_sha256,
            "provider_output_sha256": provider_output_sha256,
            "candidate_receipt": candidate_receipt,
            "host_observation": host_observation,
            "raw_verifier": raw_verifier,
            "reason": if !output_admitted {
                "provider output was rejected before parse, persistence, or content-derived hashing"
            } else if terminal_status == "succeeded" {
                "managed provider image, stable binary, host protocol, and internal verifier succeeded"
            } else if terminal_status == "unknown_outcome" {
                "managed provider process exceeded its deadline; no redispatch is admissible"
            } else if !managed.projection.provider_attested_in_job
                || !managed.projection.provider_binary_stable
                || !managed.projection.provider_bundle_stable
                || !managed.projection.provider_bundle_matches_execution_seal
            {
                "managed provider process failed kernel-backed image, stable-binary, or authority-bundle attestation"
            } else {
                "managed provider process or internal structured verifier failed"
            },
        }),
    )
    .await?;
    write_output_json(&request.output_root.join("terminal.json"), &terminal)?;

    // Invocation-status projections are returned only after a fresh canonical re-read.
    let final_status =
        named_pipe_ipc::cognitive_governor_request(&instance, "cognitive/status", scope).await?;
    let canonical_terminal = final_status
        .get("terminals")
        .and_then(Value::as_array)
        .and_then(|records| records.last())
        .and_then(|record| record.get("receipt_body"))
        .context("canonical status did not revalidate the terminal")?;
    if canonical_terminal
        .get("call_number")
        .and_then(Value::as_u64)
        != Some(u64::from(request.call_number))
    {
        anyhow::bail!("canonical status re-read resolved a different terminal call");
    }
    println!("{}", serde_json::to_string(&final_status)?);
    if terminal_status != "succeeded" {
        anyhow::bail!(
            "cognitive provider call ended as {terminal_status}; redispatch is forbidden"
        );
    }
    drop(output_root_authority);
    drop(request_authority);
    Ok(())
}

fn validate_original_request_paths(request: &CognitiveRunnerRequest) -> Result<()> {
    for path in [
        request.executable.as_path(),
        request.provider_executable.as_path(),
        request.cwd.as_path(),
        request.bundle_path.as_path(),
        request.prompt_path.as_path(),
        request.cases_path.as_path(),
        request.exposure_map_path.as_path(),
        request.output_contract_path.as_path(),
        request.models_path.as_path(),
        request.output_root.as_path(),
    ] {
        reject_reparse_path(path)?;
    }
    Ok(())
}

fn validate_request(request: &CognitiveRunnerRequest) -> Result<()> {
    if request.schema_version != COGNITIVE_RUNNER_REQUEST_SCHEMA
        || request.run_id.trim().is_empty()
        || request.model.trim().is_empty()
        || request.timeout_seconds == 0
        || request.timeout_seconds > 900
        || !request.executable.is_file()
        || !request.provider_executable.is_file()
        || !request.cwd.is_dir()
        || !request.bundle_path.exists()
        || !request.prompt_path.is_file()
        || !request.cases_path.is_file()
        || !request.exposure_map_path.is_file()
        || !request.output_contract_path.is_file()
        || !request.models_path.is_file()
    {
        anyhow::bail!("cognitive runner request is invalid or references a missing sealed input");
    }
    let local_app_data =
        PathBuf::from(std::env::var_os("LOCALAPPDATA").context("LOCALAPPDATA is not set")?)
            .canonicalize()
            .context("canonicalize LocalAppData root")?;
    let local_eliot = local_app_data
        .join("Eliot")
        .canonicalize()
        .context("canonicalize LocalAppData Eliot root")?;
    let current_executable = std::env::current_exe()?.canonicalize()?;
    if !host_executable_paths_are_approved(
        request.host,
        &request.executable,
        &request.provider_executable,
        &current_executable,
        &local_app_data,
    )? {
        anyhow::bail!(
            "cognitive host executable path is outside the canonical installed authority"
        );
    }
    let output_parent = request
        .output_root
        .parent()
        .context("cognitive output_root has no parent")?
        .canonicalize()
        .context("cognitive output_root parent must already exist")?;
    let cwd = request.cwd.canonicalize()?;
    let bundle = request.bundle_path.canonicalize()?;
    let home = request
        .environment
        .get("HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(PathBuf::from))
        .or_else(|| std::env::var_os("USERPROFILE").map(PathBuf::from));
    let bundle_is_approved =
        provider_bundle_path_is_approved(request.host, &bundle, &output_parent, home.as_deref())?;
    if !output_parent.starts_with(&local_eliot)
        || !cwd.starts_with(&output_parent)
        || !bundle_is_approved
        || [output_parent.as_path(), cwd.as_path(), bundle.as_path()]
            .iter()
            .any(|path| {
                path.to_string_lossy()
                    .to_ascii_lowercase()
                    .contains("onedrive")
            })
    {
        anyhow::bail!(
            "cognitive owned output/cwd/bundle must stay under LocalAppData\\Eliot and outside OneDrive"
        );
    }
    reject_reparse_path(&output_parent)?;
    reject_reparse_path(&cwd)?;
    reject_reparse_path(&bundle)?;
    reject_reparse_path(&request.provider_executable.canonicalize()?)?;
    Ok(())
}

fn provider_bundle_path_is_approved(
    host: AgentHostId,
    bundle: &Path,
    invocations_root: &Path,
    home: Option<&Path>,
) -> Result<bool> {
    match host {
        AgentHostId::OpenCode => {
            let run_root = invocations_root
                .parent()
                .context("cognitive invocations root has no run root")?;
            let sealed_integration = run_root
                .join("cognitive-provider-authority")
                .join("integrations")
                .join("opencode");
            paths_are_identical(bundle, &sealed_integration)
        }
        AgentHostId::Antigravity => {
            let Some(home) = home else {
                return Ok(false);
            };
            let installed_manifest = home
                .join(".gemini")
                .join("config")
                .join("plugins")
                .join("eliot-antigravity")
                .join("agents")
                .join("eliot-agent")
                .join("agent.md");
            paths_are_identical(bundle, &installed_manifest)
        }
        _ => Ok(false),
    }
}

fn host_executable_paths_are_approved(
    host: AgentHostId,
    launcher: &Path,
    provider: &Path,
    current_executable: &Path,
    local_app_data: &Path,
) -> Result<bool> {
    match host {
        AgentHostId::OpenCode => {
            let installed_provider = local_app_data.join("OpenCode").join("opencode-cli.exe");
            Ok(paths_are_identical(launcher, current_executable)?
                && paths_are_identical(provider, &installed_provider)?)
        }
        AgentHostId::Antigravity => {
            let installed_provider = local_app_data.join("agy").join("bin").join("agy.exe");
            Ok(paths_are_identical(launcher, &installed_provider)?
                && paths_are_identical(provider, &installed_provider)?)
        }
        _ => Ok(false),
    }
}

fn paths_are_identical(left: &Path, right: &Path) -> Result<bool> {
    let left = canonical_path_string(left)?;
    let right = canonical_path_string(right)?;
    #[cfg(windows)]
    {
        Ok(left.eq_ignore_ascii_case(&right))
    }
    #[cfg(not(windows))]
    {
        Ok(left == right)
    }
}

fn cognitive_job_bootstrap(call_id: &str) -> String {
    format!(
        "ELIOT_JOB {call_id}. Call eliot_cognitive_job_fetch with call_id={call_id} before doing any task work; its returned packet is the complete task authority."
    )
}

fn validate_host_argv(
    request: &CognitiveRunnerRequest,
    bootstrap_prompt: &str,
    config_path: &Path,
) -> Result<()> {
    let exact_grammar = host_argv_matches_exact_grammar(request, bootstrap_prompt, config_path)?;
    let authority = match request.host {
        AgentHostId::OpenCode => {
            request
                .environment
                .get("ELIOT_OPENCODE_EXE")
                .is_some_and(|path| {
                    Path::new(path)
                        .canonicalize()
                        .ok()
                        .zip(request.provider_executable.canonicalize().ok())
                        .is_some_and(|(configured, sealed)| configured == sealed)
                })
        }
        AgentHostId::Antigravity => request
            .executable
            .canonicalize()
            .ok()
            .zip(request.provider_executable.canonicalize().ok())
            .is_some_and(|(launcher, provider)| launcher == provider),
        _ => false,
    };
    if !exact_grammar || !authority {
        anyhow::bail!("cognitive host argv is not the sealed fresh-session read-only plan surface");
    }
    Ok(())
}

fn host_argv_matches_exact_grammar(
    request: &CognitiveRunnerRequest,
    bootstrap_prompt: &str,
    config_path: &Path,
) -> Result<bool> {
    let cwd = request.cwd.to_string_lossy();
    let timeout = format!("{}s", request.timeout_seconds);
    let expected = match request.host {
        AgentHostId::OpenCode => vec![
            "host",
            "launch",
            "--host",
            "opencode",
            "--mode",
            "supervised",
            "--cwd",
            cwd.as_ref(),
            "--model",
            request.model.as_str(),
            "--prompt",
            bootstrap_prompt,
        ],
        AgentHostId::Antigravity => vec![
            "--new-project",
            "--add-dir",
            cwd.as_ref(),
            "--agent",
            "eliot-agent",
            "--mode",
            "plan",
            "--sandbox",
            "--model",
            request.model.as_str(),
            "--print-timeout",
            timeout.as_str(),
            "--print",
            bootstrap_prompt,
        ],
        _ => return Ok(false),
    };
    let mut actual = request.argv.iter().map(String::as_str).collect::<Vec<_>>();
    if request.host == AgentHostId::OpenCode
        && actual.first() == Some(&"--config")
        && actual.len() >= 2
    {
        if !paths_are_identical(Path::new(actual[1]), config_path)? {
            return Ok(false);
        }
        actual.drain(..2);
    }
    Ok(actual == expected)
}

fn exact_argument_value(args: &[&str], name: &str, expected: &str) -> bool {
    args.iter().filter(|argument| **argument == name).count() == 1
        && args
            .windows(2)
            .filter(|pair| pair[0] == name && pair[1] == expected)
            .count()
            == 1
}

#[cfg(windows)]
fn reject_reparse_path(path: &Path) -> Result<()> {
    use std::os::windows::fs::MetadataExt as _;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component.as_os_str());
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 => {
                anyhow::bail!(
                    "cognitive owned path contains a reparse point: {}",
                    current.display()
                );
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

#[cfg(not(windows))]
fn reject_reparse_path(_path: &Path) -> Result<()> {
    Ok(())
}

fn validate_request_against_contract(
    request: &CognitiveRunnerRequest,
    contract: &CognitiveRunContract,
    call: &CognitiveRunCallPlan,
    inputs: &PinnedStaticInputs,
) -> Result<()> {
    if contract.run_id != request.run_id
        || contract.instance_name != request.instance_name
        || contract.project_id != request.project_id
        || contract.task_id != request.task_id
        || !request_output_root_matches_call(
            &request.output_root,
            &contract.output_root,
            &call.call_id,
        )?
        || contract.timeout_seconds != request.timeout_seconds
        || call.host != request.host
        || call.model != request.model
        || call.expected_truth_revision != request.expected_truth_revision
        || call.expected_exposure_handles != request.expected_exposure_handles
        || inputs.prompt.sha256() != call.prompt_sha256
        || inputs.cases.sha256() != contract.cases_sha256
        || inputs.exposure_map.sha256() != contract.exposure_map_sha256
        || inputs.output_contract.sha256() != contract.output_contract_sha256
        || inputs.models.sha256() != contract.models_sha256
        || request.expected_candidate_body_sha256 != call.candidate_body_sha256
    {
        anyhow::bail!("cognitive runner request differs from the immutable canonical contract");
    }
    let exposure: Value = serde_json::from_slice(&inputs.exposure_map.bytes)?;
    let case_entry = exposure
        .get("cases")
        .and_then(|cases| cases.get(&call.case_id))
        .context("sealed exposure map has no call case")?;
    if case_entry
        .get("current_truth_revision")
        .and_then(Value::as_str)
        != Some(request.expected_truth_revision.as_str())
    {
        anyhow::bail!("runner truth revision differs from the sealed exposure map");
    }
    let expected = request
        .expected_exposure_handles
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    if call.variant == "control" || call.invocation_role == CognitiveInvocationRole::SourceWrite {
        if !expected.is_empty() {
            anyhow::bail!("control and source-write calls require empty exposure");
        }
    } else if !call.requires_shared_gate {
        let sealed = case_entry
            .get("treatment_handles")
            .and_then(Value::as_array)
            .context("sealed treatment handles are absent")?
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_owned)
            .collect::<BTreeSet<_>>();
        if sealed != expected {
            anyhow::bail!("runner exposure differs from sealed treatment handles");
        }
    } else if expected.len() != 1 {
        anyhow::bail!("reciprocal treatment requires exactly one gate-admitted handle");
    }
    Ok(())
}

fn request_output_root_matches_call(
    requested_output_root: &Path,
    contract_output_root: &str,
    call_id: &str,
) -> Result<bool> {
    let call_component = Path::new(call_id);
    if call_component.components().count() != 1
        || !matches!(
            call_component.components().next(),
            Some(std::path::Component::Normal(_))
        )
    {
        anyhow::bail!("sealed cognitive call_id is not a single safe path component");
    }
    let expected = PathBuf::from(contract_output_root)
        .join("invocations")
        .join(call_id);
    paths_are_identical(&expected, requested_output_root)
}

fn current_environment() -> Result<BTreeMap<String, String>> {
    std::env::vars_os()
        .filter(|(name, _)| {
            matches!(
                name.to_string_lossy().to_ascii_uppercase().as_str(),
                "SYSTEMROOT"
                    | "WINDIR"
                    | "PATH"
                    | "PATHEXT"
                    | "COMSPEC"
                    | "TEMP"
                    | "TMP"
                    | "USERPROFILE"
                    | "APPDATA"
                    | "LOCALAPPDATA"
                    | "HOME"
                    | "HOMEDRIVE"
                    | "HOMEPATH"
            )
        })
        .map(|(name, value)| {
            Ok((
                name.into_string()
                    .map_err(|_| anyhow::anyhow!("non-Unicode environment name"))?,
                value
                    .into_string()
                    .map_err(|_| anyhow::anyhow!("non-Unicode environment value"))?,
            ))
        })
        .collect()
}

fn validate_execution_against_models(
    request: &CognitiveRunnerRequest,
    call: &CognitiveRunCallPlan,
    execution: &CognitiveExecutionSeal,
    models_bytes: &[u8],
) -> Result<()> {
    for name in request.environment.keys() {
        let upper = name.to_ascii_uppercase();
        if upper.starts_with("SURREAL_")
            || upper.contains("TOKEN")
            || upper.contains("SECRET")
            || upper.contains("PASSWORD")
            || upper.ends_with("_KEY")
        {
            anyhow::bail!("cognitive provider environment contains a forbidden secret variable");
        }
    }
    let models: Value = serde_json::from_slice(models_bytes)?;
    let sealed = models
        .get("calls")
        .and_then(|calls| calls.get(&call.call_id))
        .context("sealed models contract has no exact call execution")?;
    let expected: CognitiveExecutionSeal = serde_json::from_value(
        sealed
            .get("execution")
            .cloned()
            .context("sealed models call has no execution seal")?,
    )?;
    let provider_path = canonical_path_string(&request.provider_executable)?;
    if sealed.get("host").and_then(Value::as_str) != Some(request.host.as_str())
        || sealed.get("model").and_then(Value::as_str) != Some(request.model.as_str())
        || sealed.get("provider_executable").and_then(Value::as_str) != Some(provider_path.as_str())
        || expected != *execution
    {
        anyhow::bail!("computed provider execution differs from sealed models authority");
    }
    Ok(())
}

fn predicted_capability_path(
    instance: &RuntimeInstance,
    contract: &CognitiveRunContract,
    call: &CognitiveRunCallPlan,
) -> PathBuf {
    let authority_hash = sha256_bytes(
        format!(
            "{}:{}:{}:{}:{}",
            contract.project_id,
            contract.task_id,
            contract.run_id,
            call.call_number,
            call.host.as_str(),
        )
        .as_bytes(),
    );
    instance
        .runtime_dir()
        .join("secrets")
        .join("cognitive-runs")
        .join(&authority_hash[..24])
        .join(format!("call-{:02}.json", call.call_number))
}

fn canonical_path_string(path: &Path) -> Result<String> {
    let normalized = path.canonicalize()?.to_string_lossy().replace('\\', "/");
    if let Some(unc) = normalized.strip_prefix("//?/UNC/") {
        return Ok(format!("//{unc}"));
    }
    Ok(normalized
        .strip_prefix("//?/")
        .unwrap_or(&normalized)
        .to_owned())
}

fn sha256_bytes(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn sha256_json<T: Serialize>(value: &T) -> Result<String> {
    Ok(sha256_bytes(&serde_json::to_vec(value)?))
}

fn write_output_json<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(value)?;
    eliot_windows_ipc::write_new_pinned_file(path, &bytes)
        .with_context(|| format!("write new sealed cognitive output {}", path.display()))
}

#[allow(
    clippy::too_many_arguments,
    reason = "the managed execution boundary receives independently pinned authority and hash inputs"
)]
async fn run_managed_process(
    request: &CognitiveRunnerRequest,
    environment: &BTreeMap<String, String>,
    call_id: &str,
    expected_launcher_sha256: &str,
    expected_provider_sha256: &str,
    expected_bundle_sha256: &str,
    mut authority: PinnedExecutionAuthority,
    operation_runtime: eliot_engine::OperationRuntimeHandle,
) -> Result<ManagedOutput> {
    let launcher_file_identity = authority.launcher.identity();
    let provider_file_identity = authority.provider.identity();
    let (
        launcher_executable_sha256_before,
        provider_executable_sha256_before,
        provider_bundle_sha256_before,
    ) = authority.hashes()?;
    let started = Instant::now();
    let timeout = Duration::from_secs(request.timeout_seconds);
    let operation_id = format!("cognitive-{call_id}");
    let route_policy = eliot_types::ProviderRoutePolicy::for_route(
        request.host,
        "cognitive-field",
        eliot_types::ProviderDeclaredBudget::new(
            u64::try_from(timeout.as_millis()).unwrap_or(u64::MAX),
            u64::try_from(MAX_SECRET_BOUNDARY_BYTES).unwrap_or(u64::MAX),
        )
        .with_first_output_deadline_ms(None),
    );
    let provider_runtime =
        crate::host_runtime::ProviderRuntime::from_runtime_store(operation_runtime);
    let runner = provider_runtime.runner();
    let mut on_spawned = |_| Ok(());
    let output = eliot_engine::ProviderProcessRunner::run(
        runner.as_ref(),
        eliot_engine::ProviderProcessSpec {
            operation_id,
            invocation_id: Some(call_id.to_owned()),
            executable: request.executable.clone(),
            args: request.argv.iter().map(std::ffi::OsString::from).collect(),
            cwd: request.cwd.clone(),
            environment: environment
                .iter()
                .map(|(name, value)| {
                    (
                        std::ffi::OsString::from(name),
                        std::ffi::OsString::from(value),
                    )
                })
                .collect(),
            stdin_payload: None,
            route_policy,
            cancellation: eliot_engine::runtime_supervision::CancellationToken::new(),
            deadline: tokio::time::Instant::now() + timeout,
            runtime_contract_sha256: Some(expected_bundle_sha256.to_owned()),
            role_lease_id: None,
            role_lease_epoch: None,
        },
        &mut on_spawned,
    )
    .await
    .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    anyhow::ensure!(
        output.worker_error.is_none() && output.reap_receipt.proves_complete_reap(),
        "cognitive provider process cleanup failed: {:?}",
        output.worker_error
    );
    let launcher_pid = output
        .reap_receipt
        .root_pid
        .context("supervised cognitive provider lacks a root PID")?;
    let launcher_process = output
        .observed_processes
        .iter()
        .find(|process| process.pid == launcher_pid)
        .cloned()
        .context("query held launcher process identity")?;
    if launcher_process.pid != launcher_pid {
        anyhow::bail!("held launcher process identity has a conflicting PID");
    }
    let launcher_image = canonical_path_string(&launcher_process.image)?;
    let observed_job_processes = output
        .observed_processes
        .iter()
        .map(|process| {
            Ok(CognitiveJobProcessProjection {
                pid: process.pid,
                image: canonical_path_string(&process.image)?,
                volume_serial_number: process.file_identity.volume_serial_number,
                file_index: process.file_identity.file_index,
            })
        })
        .collect::<Result<BTreeSet<_>>>()?;
    let job_observation_errors = BTreeSet::new();
    let exit_code = output.exit_code;
    let timed_out = output.timed_out;
    let launcher_executable_sha256_after = authority
        .launcher
        .read_all()
        .ok()
        .map(|bytes| sha256_bytes(&bytes));
    let (launcher_binary_stable, launcher_matches_execution_seal) = hash_attestation(
        &launcher_executable_sha256_before,
        launcher_executable_sha256_after.as_deref(),
        expected_launcher_sha256,
    );
    let launcher_attested_in_job = launcher_image.eq_ignore_ascii_case(&authority.launcher_path)
        && launcher_process.file_identity == launcher_file_identity
        && launcher_binary_stable
        && launcher_matches_execution_seal;
    let provider_executable_sha256_after = authority
        .provider
        .read_all()
        .ok()
        .map(|bytes| sha256_bytes(&bytes));
    let (provider_binary_stable, provider_matches_execution_seal) = hash_attestation(
        &provider_executable_sha256_before,
        provider_executable_sha256_after.as_deref(),
        expected_provider_sha256,
    );
    let provider_bundle_sha256_after = authority.bundle.sha256().ok();
    let provider_bundle_mutation_attempted = authority.bundle.mutation_attempted().unwrap_or(true);
    let (provider_bundle_stable, provider_bundle_matches_execution_seal) = hash_attestation(
        &provider_bundle_sha256_before,
        provider_bundle_sha256_after.as_deref(),
        expected_bundle_sha256,
    );
    let provider_process = observed_job_processes.iter().find(|process| {
        process.image.eq_ignore_ascii_case(&authority.provider_path)
            && process.volume_serial_number == provider_file_identity.volume_serial_number
            && process.file_index == provider_file_identity.file_index
            && (request.host != AgentHostId::OpenCode || process.pid != launcher_pid)
    });
    let provider_pid = provider_process.map(|process| process.pid);
    let provider_image = provider_process.map(|process| process.image.clone());
    let provider_volume_serial_number =
        provider_process.map(|process| process.volume_serial_number);
    let provider_file_index = provider_process.map(|process| process.file_index);
    let provider_attested_in_job =
        provider_process.is_some() && provider_binary_stable && provider_matches_execution_seal;
    let provider_image_sha256 = provider_process.and(provider_executable_sha256_after.clone());
    let mut stdout = output.stdout;
    let mut stderr = output.stderr;
    let (secret_boundary_rule, stdout_sha256, stderr_sha256) =
        admit_provider_output(&mut stdout, &mut stderr);
    Ok(ManagedOutput {
        projection: CognitiveProcessProjection {
            schema_version: "eliot-cognitive-process-projection-v1",
            run_id: request.run_id.clone(),
            call_id: call_id.to_owned(),
            call_number: request.call_number,
            host: request.host,
            model: request.model.clone(),
            launcher_executable: authority.launcher_path,
            launcher_executable_sha256_before,
            launcher_executable_sha256_after,
            launcher_binary_stable,
            launcher_matches_execution_seal,
            launcher_image,
            launcher_volume_serial_number: launcher_process.file_identity.volume_serial_number,
            launcher_file_index: launcher_process.file_identity.file_index,
            launcher_attested_in_job,
            provider_executable: authority.provider_path,
            provider_executable_sha256_before,
            provider_executable_sha256_after,
            provider_binary_stable,
            provider_matches_execution_seal,
            provider_pid,
            provider_image,
            provider_volume_serial_number,
            provider_file_index,
            provider_image_sha256,
            provider_attested_in_job,
            provider_bundle: authority.bundle_path,
            provider_bundle_sha256_before,
            provider_bundle_sha256_after,
            provider_bundle_stable,
            provider_bundle_matches_execution_seal,
            provider_bundle_mutation_attempted,
            observed_job_processes: observed_job_processes.into_iter().collect(),
            job_observation_errors: job_observation_errors.into_iter().collect(),
            launcher_pid,
            job_object_containment: "windows-suspended-kill-on-job-close-v1",
            exit_code,
            timed_out,
            latency_ms: started.elapsed().as_millis(),
            stdout_sha256,
            stderr_sha256,
            secret_boundary_rule,
        },
        stdout,
        stderr,
        secret_boundary_rule,
    })
}

fn admit_provider_output(
    stdout: &mut Vec<u8>,
    stderr: &mut Vec<u8>,
) -> (Option<SecretBoundaryRule>, Option<String>, Option<String>) {
    let rule = inspect_secret_bytes(stdout)
        .err()
        .or_else(|| inspect_secret_bytes(stderr).err())
        .map(|violation| violation.rule);
    if rule.is_some() {
        stdout.fill(0);
        stdout.clear();
        stderr.fill(0);
        stderr.clear();
        (rule, None, None)
    } else {
        (None, Some(sha256_bytes(stdout)), Some(sha256_bytes(stderr)))
    }
}

fn hash_attestation(before: &str, after: Option<&str>, expected: &str) -> (bool, bool) {
    (after == Some(before), before == expected)
}

fn host_observation(
    request: &CognitiveRunnerRequest,
    attempt: &Value,
    outer_protocol: &[u8],
) -> Result<CognitiveHostObservation> {
    let governor_session_id = attempt
        .get("capability")
        .filter(|capability| !capability.is_null())
        .and_then(|capability| capability.get("session_id"))
        .and_then(Value::as_str)
        .map(SessionId::from_str)
        .transpose()
        .context("attempt capability has an invalid Governor session")?;
    if request.host != AgentHostId::OpenCode && request.host != AgentHostId::Antigravity {
        anyhow::bail!("unsupported cognitive host observation");
    }
    let (vendor_session_id, observed_model) = outer_host_identity(request.host, outer_protocol);
    Ok(CognitiveHostObservation {
        observation_version: "eliot-cognitive-host-observation-v1".to_owned(),
        governor_session_id,
        vendor_session_id,
        host: request.host,
        observed_model,
        outer_protocol_sha256: sha256_bytes(outer_protocol),
    })
}

fn rejected_host_observation(
    request: &CognitiveRunnerRequest,
    attempt: &Value,
) -> Result<CognitiveHostObservation> {
    let mut observation = host_observation(request, attempt, &[])?;
    if request.host == AgentHostId::OpenCode {
        observation.observed_model = Some(request.model.clone());
    }
    Ok(observation)
}

fn outer_host_identity(
    host: AgentHostId,
    outer_protocol: &[u8],
) -> (Option<String>, Option<String>) {
    let events = outer_protocol_events(outer_protocol);
    let session_event = match host {
        AgentHostId::OpenCode => events
            .iter()
            .find(|event| event.get("type").and_then(Value::as_str) == Some("session.start")),
        AgentHostId::Antigravity => events.iter().find(|event| {
            event.get("schema_version").and_then(Value::as_str)
                != Some("eliot-cognitive-host-output-v1")
                && (first_string(event, &["session_id", "sessionId", "conversation_id"]).is_some()
                    || event
                        .get("type")
                        .or_else(|| event.get("event"))
                        .and_then(Value::as_str)
                        .is_some_and(|kind| kind.to_ascii_lowercase().contains("session")))
        }),
        _ => None,
    };
    let vendor_session_id = session_event
        .and_then(|event| first_string(event, &["session_id", "sessionId", "conversation_id"]));
    let observed_model = session_event
        .and_then(|event| first_string(event, &["model", "model_id", "modelId"]))
        .or_else(|| {
            events.iter().find_map(|event| {
                (event.get("schema_version").and_then(Value::as_str)
                    != Some("eliot-cognitive-host-output-v1"))
                .then(|| first_string(event, &["model", "model_id", "modelId"]))
                .flatten()
            })
        });
    (vendor_session_id, observed_model)
}

fn outer_host_observation_attested(
    request: &CognitiveRunnerRequest,
    observation: &CognitiveHostObservation,
    outer_protocol: &[u8],
) -> bool {
    if observation.host != request.host
        || observation.outer_protocol_sha256 != sha256_bytes(outer_protocol)
    {
        return false;
    }
    match request.host {
        AgentHostId::OpenCode => {
            observation
                .vendor_session_id
                .as_deref()
                .is_some_and(|session| !session.trim().is_empty())
                && observation.observed_model.as_deref() == Some(request.model.as_str())
        }
        AgentHostId::Antigravity => {
            let args = request.argv.iter().map(String::as_str).collect::<Vec<_>>();
            !outer_protocol.is_empty()
                && exact_argument_value(&args, "--agent", "eliot-agent")
                && exact_argument_value(&args, "--model", &request.model)
                && observation
                    .observed_model
                    .as_deref()
                    .is_none_or(|model| model == request.model)
                && observation
                    .vendor_session_id
                    .as_deref()
                    .is_none_or(|session| !session.trim().is_empty())
        }
        _ => false,
    }
}

fn outer_protocol_events(bytes: &[u8]) -> Vec<Value> {
    let Ok(text) = std::str::from_utf8(bytes) else {
        return Vec::new();
    };
    let mut events = text
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line.trim()).ok())
        .collect::<Vec<_>>();
    if events.is_empty()
        && let Ok(value) = serde_json::from_str::<Value>(text.trim())
    {
        events.push(value);
    }
    events
}

fn first_string(value: &Value, keys: &[&str]) -> Option<String> {
    match value {
        Value::Object(object) => {
            for key in keys {
                if let Some(value) = object
                    .get(*key)
                    .and_then(Value::as_str)
                    .filter(|value| !value.trim().is_empty())
                {
                    return Some(value.to_owned());
                }
            }
            object.values().find_map(|value| first_string(value, keys))
        }
        Value::Array(values) => values.iter().find_map(|value| first_string(value, keys)),
        _ => None,
    }
}

fn parse_provider_output(stdout: &[u8]) -> Result<Value> {
    let text = std::str::from_utf8(stdout).context("provider stdout is not UTF-8")?;
    if let Ok(value) = serde_json::from_str::<Value>(text.trim()) {
        return embedded_provider_value(value);
    }
    for line in text.lines().rev() {
        if let Ok(value) = serde_json::from_str::<Value>(line.trim())
            && let Ok(value) = embedded_provider_value(value)
        {
            return Ok(value);
        }
    }
    for (start, _) in text.match_indices('{').rev() {
        if let Ok(value) = serde_json::from_str::<Value>(&text[start..]) {
            return embedded_provider_value(value);
        }
    }
    anyhow::bail!("provider stdout contains no structured host output")
}

fn embedded_provider_value(value: Value) -> Result<Value> {
    if value.get("schema_version").and_then(Value::as_str) == Some("eliot-cognitive-host-output-v1")
    {
        return Ok(value);
    }
    if let Some(text) = value
        .get("part")
        .and_then(|part| part.get("text"))
        .and_then(Value::as_str)
    {
        return serde_json::from_str(text).context("decode embedded provider JSON");
    }
    anyhow::bail!("JSON value is not a cognitive host output")
}

fn verify_provider_output(
    request: &CognitiveRunnerRequest,
    call: &CognitiveRunCallPlan,
    output: Option<&Value>,
    output_contract_bytes: &[u8],
    cases_bytes: &[u8],
) -> Value {
    let contract: Value = serde_json::from_slice(output_contract_bytes).unwrap_or(Value::Null);
    let cases: Value = serde_json::from_slice(cases_bytes).unwrap_or(Value::Null);
    let case = cases
        .get("cases")
        .and_then(Value::as_array)
        .and_then(|cases| {
            cases.iter().find(|case| {
                case.get("case_id").and_then(Value::as_str) == Some(call.case_id.as_str())
            })
        });
    let mut checks = Vec::new();
    let mut add = |name: &str, passed: bool| checks.push(json!({ "name": name, "passed": passed }));
    let Some(output) = output else {
        add("structured_output_present", false);
        return verification_report(call, checks);
    };
    for field in contract
        .get("required_fields")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
    {
        add(&format!("required:{field}"), output.get(field).is_some());
    }
    let forbidden = contract
        .get("forbidden_recursive_fields")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect::<BTreeSet<_>>();
    add(
        "no_chain_of_thought_fields",
        !contains_forbidden_field(output, &forbidden),
    );
    add(
        "case_identity",
        output.get("case_id").and_then(Value::as_str) == Some(call.case_id.as_str()),
    );
    add(
        "variant_identity",
        output.get("variant").and_then(Value::as_str) == Some(call.variant.as_str()),
    );
    add(
        "host_identity",
        output.get("host").and_then(Value::as_str) == Some(request.host.as_str()),
    );
    add(
        "host_session_recorded",
        output
            .get("host_session_id")
            .and_then(Value::as_str)
            .is_some_and(|value| !value.trim().is_empty()),
    );
    add(
        "model_identity",
        output.get("model").and_then(Value::as_str) == Some(request.model.as_str()),
    );
    add(
        "current_truth_revision",
        output.get("current_truth_revision").and_then(Value::as_str)
            == Some(request.expected_truth_revision.as_str()),
    );
    add(
        "exposure_set_exact",
        string_set(output.get("memory_exposure_handles"))
            == request.expected_exposure_handles.iter().cloned().collect(),
    );
    add(
        "negative_transfer_false",
        output.get("negative_transfer").and_then(Value::as_bool) == Some(false),
    );
    if call.invocation_role == CognitiveInvocationRole::SourceWrite {
        let receipt = output.get("candidate_write_receipt");
        add(
            "candidate_only_write_receipt",
            receipt
                .and_then(|value| value.get("status"))
                .and_then(Value::as_str)
                == Some("candidate_only")
                && receipt
                    .and_then(|value| value.get("write_id"))
                    .and_then(Value::as_str)
                    .is_some()
                && receipt
                    .and_then(|value| value.get("receipt_id"))
                    .and_then(Value::as_str)
                    .is_some()
                && receipt
                    .and_then(|value| value.get("evidence_refs"))
                    .and_then(Value::as_array)
                    .is_some_and(|items| !items.is_empty()),
        );
    } else if let Some(verifier) = case.and_then(|case| case.get("verifier")) {
        let mechanism = output
            .get("mechanism_claim")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_ascii_lowercase();
        for term in strings(verifier.get("mechanism_terms_all")) {
            add(
                &format!("mechanism_term:{term}"),
                mechanism.contains(&term.to_ascii_lowercase()),
            );
        }
        let any_terms = strings(verifier.get("mechanism_terms_any"));
        if !any_terms.is_empty() {
            add(
                "mechanism_any_term",
                any_terms
                    .iter()
                    .any(|term| mechanism.contains(&term.to_ascii_lowercase())),
            );
        }
        add(
            "applicability",
            strings(verifier.get("allowed_applicability"))
                .iter()
                .any(|item| {
                    Some(item.as_str())
                        == output.get("applicability_verdict").and_then(Value::as_str)
                }),
        );
        add(
            "first_boundary",
            strings(verifier.get("allowed_first_boundaries"))
                .iter()
                .any(|item| {
                    Some(item.as_str()) == output.get("first_boundary_tag").and_then(Value::as_str)
                }),
        );
        let tags = string_set(output.get("verifier_tags"));
        for tag in strings(verifier.get("required_verifier_tags")) {
            add(&format!("verifier_tag:{tag}"), tags.contains(&tag));
        }
        add(
            "memory_action",
            output.get("memory_action").and_then(Value::as_str)
                == verifier
                    .get("expected_memory_action")
                    .and_then(Value::as_str),
        );
        let attempts = string_set(output.get("wrong_path_attempts"));
        add(
            "no_forbidden_attempts",
            strings(verifier.get("forbidden_actions"))
                .iter()
                .all(|action| !attempts.contains(action)),
        );
        if call.variant == "control" {
            let memory_tools = output
                .get("tool_calls")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .any(|tool| {
                    matches!(
                        tool.get("name").and_then(Value::as_str),
                        Some("eliot_recall_l0" | "eliot_fetch_l2")
                    )
                });
            add(
                "memory_free_control",
                !memory_tools && string_set(output.get("memory_used_handles")).is_empty(),
            );
        }
    } else {
        add("sealed_case_verifier_present", false);
    }
    verification_report(call, checks)
}

fn verification_report(call: &CognitiveRunCallPlan, checks: Vec<Value>) -> Value {
    let passed = checks
        .iter()
        .all(|check| check.get("passed").and_then(Value::as_bool) == Some(true));
    json!({
        "schema_version": "eliot-cognitive-local-verification-v1",
        "case_id": call.case_id,
        "invocation_id": call.call_id,
        "passed": passed,
        "classification": if passed { "AuditFindingCandidate" } else { "RejectedExternalOpinion" },
        "disposition": if passed { "accepted_as_candidate_pending_governor_disposition" } else { "rejected_external_opinion" },
        "truth_promoted": false,
        "checks": checks,
    })
}

fn contains_forbidden_field(value: &Value, forbidden: &BTreeSet<&str>) -> bool {
    match value {
        Value::Object(object) => object.iter().any(|(name, value)| {
            forbidden.contains(name.as_str()) || contains_forbidden_field(value, forbidden)
        }),
        Value::Array(items) => items
            .iter()
            .any(|value| contains_forbidden_field(value, forbidden)),
        _ => false,
    }
}

fn strings(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect()
}

fn string_set(value: Option<&Value>) -> BTreeSet<String> {
    strings(value).into_iter().collect()
}

fn candidate_receipt(output: &Value) -> Result<WriteReceiptRef> {
    let value = output
        .get("candidate_write_receipt")
        .context("source output has no candidate_write_receipt")?;
    let receipt_id = value
        .get("receipt_id")
        .and_then(Value::as_str)
        .context("source candidate receipt_id is absent")?;
    let write_id = value
        .get("write_id")
        .and_then(Value::as_str)
        .context("source candidate write_id is absent")?;
    Ok(WriteReceiptRef {
        receipt_id: eliot_types::ReceiptId::from_str(receipt_id)?,
        write_id: eliot_types::WriteId::from_str(write_id)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn antigravity_attestation_request(argv: Vec<String>) -> CognitiveRunnerRequest {
        CognitiveRunnerRequest {
            schema_version: COGNITIVE_RUNNER_REQUEST_SCHEMA.to_owned(),
            instance_name: "test".to_owned(),
            run_id: "run".to_owned(),
            project_id: ProjectId::new_v7(),
            task_id: TaskId::new_v7(),
            call_number: 1,
            host: AgentHostId::Antigravity,
            model: "agy-model".to_owned(),
            executable: PathBuf::from("agy.exe"),
            provider_executable: PathBuf::from("agy.exe"),
            argv,
            environment: BTreeMap::new(),
            cwd: PathBuf::from("."),
            bundle_path: PathBuf::from("agent.md"),
            prompt_path: PathBuf::from("prompt.md"),
            cases_path: PathBuf::from("cases.json"),
            exposure_map_path: PathBuf::from("exposure.json"),
            output_contract_path: PathBuf::from("output-contract.json"),
            models_path: PathBuf::from("models.json"),
            expected_truth_revision: "revision".to_owned(),
            expected_exposure_handles: Vec::new(),
            expected_candidate_body_sha256: None,
            shared_gate: None,
            output_root: PathBuf::from("output"),
            timeout_seconds: 30,
        }
    }

    #[test]
    fn parses_opencode_embedded_output_without_accepting_event_wrapper() -> Result<()> {
        let raw = fs::read(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../..")
                .join("tests/cognitive/cognitive-contract/fixtures/opencode-events.jsonl"),
        )?;
        let parsed = parse_provider_output(&raw)?;
        assert_eq!(parsed.get("case_id").and_then(Value::as_str), Some("PC-01"));
        assert_eq!(
            parsed.get("schema_version").and_then(Value::as_str),
            Some("eliot-cognitive-host-output-v1")
        );
        let (session_id, model) = outer_host_identity(AgentHostId::OpenCode, &raw);
        assert_eq!(session_id.as_deref(), Some("fixture-session-opencode"));
        assert_eq!(model.as_deref(), Some("fixture-model"));
        Ok(())
    }

    #[test]
    fn antigravity_host_observation_does_not_trust_embedded_result_identity() {
        let raw = br#"{"schema_version":"eliot-cognitive-host-output-v1","host_session_id":"self-reported","model":"self-reported"}"#;
        let (session_id, model) = outer_host_identity(AgentHostId::Antigravity, raw);
        assert_eq!(session_id, None);
        assert_eq!(model, None);
    }

    #[test]
    fn antigravity_outer_attestation_rejects_conflicting_model_and_missing_model_arg() {
        let raw = br#"{"schema_version":"eliot-cognitive-host-output-v1"}"#;
        let argv = [
            "--new-project",
            "--agent",
            "eliot-agent",
            "--mode",
            "plan",
            "--sandbox",
            "--model",
            "agy-model",
            "--print",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect();
        let request = antigravity_attestation_request(argv);
        let mut observation = CognitiveHostObservation {
            observation_version: "eliot-cognitive-host-observation-v1".to_owned(),
            governor_session_id: None,
            vendor_session_id: None,
            host: AgentHostId::Antigravity,
            observed_model: None,
            outer_protocol_sha256: sha256_bytes(raw),
        };
        assert!(outer_host_observation_attested(&request, &observation, raw));
        observation.observed_model = Some("conflicting-model".to_owned());
        assert!(!outer_host_observation_attested(
            &request,
            &observation,
            raw
        ));
        observation.observed_model = None;
        let mut missing_model = request;
        missing_model.argv = vec![
            "--new-project".to_owned(),
            "--agent".to_owned(),
            "eliot-agent".to_owned(),
            "--mode".to_owned(),
            "plan".to_owned(),
            "--sandbox".to_owned(),
            "--print".to_owned(),
        ];
        assert!(!outer_host_observation_attested(
            &missing_model,
            &observation,
            raw
        ));
    }

    #[test]
    fn antigravity_argv_requires_one_exact_ordered_surface() -> Result<()> {
        let prompt = "sealed prompt";
        let cwd = PathBuf::from(r"C:\sealed\work");
        let valid = [
            "--new-project",
            "--add-dir",
            cwd.to_str().context("test cwd")?,
            "--agent",
            "eliot-agent",
            "--mode",
            "plan",
            "--sandbox",
            "--model",
            "agy-model",
            "--print-timeout",
            "30s",
            "--print",
            prompt,
        ]
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();
        let mut request = antigravity_attestation_request(valid.clone());
        request.cwd = cwd;
        assert!(host_argv_matches_exact_grammar(
            &request,
            prompt,
            Path::new("unused")
        )?);
        for extra in [
            vec!["-c"],
            vec!["--continue"],
            vec!["--conversation", "attacker"],
            vec!["--project", "attacker"],
            vec!["--dangerously-skip-permissions"],
            vec!["-i"],
            vec!["--prompt-interactive"],
            vec!["--mode", "accept-edits"],
            vec!["--agent", "eliot-agent"],
        ] {
            request.argv = valid
                .iter()
                .cloned()
                .chain(extra.into_iter().map(str::to_owned))
                .collect();
            assert!(!host_argv_matches_exact_grammar(
                &request,
                prompt,
                Path::new("unused")
            )?);
        }
        request.argv = valid;
        request.argv.swap(3, 5);
        assert!(!host_argv_matches_exact_grammar(
            &request,
            prompt,
            Path::new("unused")
        )?);
        Ok(())
    }

    #[test]
    fn opencode_argv_requires_exact_core_and_exact_config_prefix() -> Result<()> {
        let prompt = "sealed prompt";
        let cwd = PathBuf::from(r"C:\sealed\work");
        let valid = [
            "host",
            "launch",
            "--host",
            "opencode",
            "--mode",
            "supervised",
            "--cwd",
            cwd.to_str().context("test cwd")?,
            "--model",
            "opencode-model",
            "--prompt",
            prompt,
        ]
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();
        let mut request = antigravity_attestation_request(valid.clone());
        request.host = AgentHostId::OpenCode;
        request.model = "opencode-model".to_owned();
        request.cwd = cwd;
        assert!(host_argv_matches_exact_grammar(
            &request,
            prompt,
            Path::new("unused")
        )?);
        for extra in [
            vec!["--session", "attacker"],
            vec!["--mode", "plan"],
            vec!["--prompt", prompt],
        ] {
            request.argv = valid
                .iter()
                .cloned()
                .chain(extra.into_iter().map(str::to_owned))
                .collect();
            assert!(!host_argv_matches_exact_grammar(
                &request,
                prompt,
                Path::new("unused")
            )?);
        }
        let root = std::env::temp_dir().join(format!(
            "eliot-cognitive-argv-config-{}",
            uuid::Uuid::new_v4()
        ));
        fs::create_dir_all(&root)?;
        let config = root.join("config.toml");
        let wrong = root.join("wrong.toml");
        fs::write(&config, b"fixture")?;
        fs::write(&wrong, b"fixture")?;
        request.argv = ["--config".to_owned(), config.to_string_lossy().into_owned()]
            .into_iter()
            .chain(valid)
            .collect();
        assert!(host_argv_matches_exact_grammar(&request, prompt, &config)?);
        assert!(!host_argv_matches_exact_grammar(&request, prompt, &wrong)?);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn provider_authority_hash_attestation_fails_closed() {
        assert_eq!(
            hash_attestation("sealed", Some("sealed"), "sealed"),
            (true, true)
        );
        assert_eq!(
            hash_attestation("sealed", Some("drifted"), "sealed"),
            (false, true)
        );
        assert_eq!(hash_attestation("sealed", None, "sealed"), (false, true));
        assert_eq!(
            hash_attestation("different", Some("different"), "sealed"),
            (true, false)
        );
    }

    #[test]
    fn host_executable_authority_rejects_arbitrary_paths() -> Result<()> {
        let local_app_data = std::env::temp_dir().join(format!(
            "eliot-cognitive-executable-authority-{}",
            uuid::Uuid::new_v4()
        ));
        let current = local_app_data.join("Eliot").join("eliot-governor.exe");
        let opencode = local_app_data.join("OpenCode").join("opencode-cli.exe");
        let agy = local_app_data.join("agy").join("bin").join("agy.exe");
        let attacker = local_app_data.join("attacker.exe");
        for executable in [&current, &opencode, &agy, &attacker] {
            fs::create_dir_all(executable.parent().context("test executable parent")?)?;
            fs::write(executable, b"fixture")?;
        }
        let invocations_root = local_app_data.join("Eliot").join("run").join("invocations");
        let opencode_bundle = local_app_data
            .join("Eliot")
            .join("run")
            .join("cognitive-provider-authority")
            .join("integrations")
            .join("opencode");
        let arbitrary_bundle = local_app_data.join("Eliot").join("arbitrary-bundle");
        let home = local_app_data.join("profile");
        let agy_bundle = home
            .join(".gemini")
            .join("config")
            .join("plugins")
            .join("eliot-antigravity")
            .join("agents")
            .join("eliot-agent")
            .join("agent.md");
        fs::create_dir_all(&invocations_root)?;
        fs::create_dir_all(&opencode_bundle)?;
        fs::create_dir_all(&arbitrary_bundle)?;
        fs::create_dir_all(agy_bundle.parent().context("test agent authority parent")?)?;
        fs::write(&agy_bundle, b"fixture agent")?;

        assert!(host_executable_paths_are_approved(
            AgentHostId::OpenCode,
            &current,
            &opencode,
            &current,
            &local_app_data,
        )?);
        assert!(!host_executable_paths_are_approved(
            AgentHostId::OpenCode,
            &current,
            &attacker,
            &current,
            &local_app_data,
        )?);
        assert!(!host_executable_paths_are_approved(
            AgentHostId::OpenCode,
            &attacker,
            &opencode,
            &current,
            &local_app_data,
        )?);
        assert!(host_executable_paths_are_approved(
            AgentHostId::Antigravity,
            &agy,
            &agy,
            &current,
            &local_app_data,
        )?);
        assert!(!host_executable_paths_are_approved(
            AgentHostId::Antigravity,
            &attacker,
            &attacker,
            &current,
            &local_app_data,
        )?);
        assert!(provider_bundle_path_is_approved(
            AgentHostId::OpenCode,
            &opencode_bundle,
            &invocations_root,
            Some(&home),
        )?);
        assert!(!provider_bundle_path_is_approved(
            AgentHostId::OpenCode,
            &arbitrary_bundle,
            &invocations_root,
            Some(&home),
        )?);
        assert!(provider_bundle_path_is_approved(
            AgentHostId::Antigravity,
            &agy_bundle,
            &invocations_root,
            Some(&home),
        )?);
        assert!(!provider_bundle_path_is_approved(
            AgentHostId::Antigravity,
            &arbitrary_bundle,
            &invocations_root,
            Some(&home),
        )?);

        fs::remove_dir_all(local_app_data)?;
        Ok(())
    }

    #[test]
    fn rejects_recursive_hidden_reasoning_fields() {
        let forbidden = ["reasoning"].into_iter().collect();
        assert!(contains_forbidden_field(
            &json!({"nested": [{"reasoning": "x"}]}),
            &forbidden
        ));
        assert!(!contains_forbidden_field(
            &json!({"mechanism_claim": "x"}),
            &forbidden
        ));
    }

    #[test]
    fn canonical_path_projection_removes_windows_extended_prefix() -> Result<()> {
        let projected = canonical_path_string(&std::env::current_dir()?)?;
        assert!(!projected.starts_with("//?/"));
        assert!(!projected.contains('\\'));
        Ok(())
    }

    #[test]
    fn call_output_root_is_the_exact_sealed_invocation_child() -> Result<()> {
        let run_root = std::env::temp_dir().join(format!(
            "eliot-cognitive-output-root-{}",
            uuid::Uuid::new_v4()
        ));
        let expected = run_root.join("invocations").join("call-a");
        let sibling = run_root.join("invocations").join("call-b");
        fs::create_dir_all(&expected)?;
        fs::create_dir_all(&sibling)?;
        let contract_root = canonical_path_string(&run_root)?;

        assert!(request_output_root_matches_call(
            &expected,
            &contract_root,
            "call-a"
        )?);
        assert!(!request_output_root_matches_call(
            &sibling,
            &contract_root,
            "call-a"
        )?);
        assert!(request_output_root_matches_call(&expected, &contract_root, "../call-a").is_err());

        #[cfg(windows)]
        assert!(request_output_root_matches_call(
            &PathBuf::from(expected.to_string_lossy().to_uppercase()),
            &contract_root,
            "call-a"
        )?);

        fs::remove_dir_all(run_root)?;
        Ok(())
    }

    #[test]
    fn cognitive_job_bootstrap_is_opaque_and_call_bound() -> Result<()> {
        let call_id = "opaque-call-17";
        let sealed_packet = "private task authority that must never enter provider argv";
        let bootstrap = cognitive_job_bootstrap(call_id);

        assert_eq!(bootstrap.matches(call_id).count(), 2);
        assert!(bootstrap.starts_with("ELIOT_JOB opaque-call-17."));
        assert!(bootstrap.contains("eliot_cognitive_job_fetch"));
        assert!(!bootstrap.contains(sealed_packet));

        let cwd = PathBuf::from(r"C:\sealed\work");
        let argv = [
            "--new-project",
            "--add-dir",
            cwd.to_str().context("test cwd")?,
            "--agent",
            "eliot-agent",
            "--mode",
            "plan",
            "--sandbox",
            "--model",
            "agy-model",
            "--print-timeout",
            "30s",
            "--print",
            bootstrap.as_str(),
        ]
        .into_iter()
        .map(str::to_owned)
        .collect();
        let mut request = antigravity_attestation_request(argv);
        request.cwd = cwd;
        assert!(host_argv_matches_exact_grammar(
            &request,
            &bootstrap,
            Path::new("unused")
        )?);
        assert!(
            !request
                .argv
                .iter()
                .any(|argument| argument == sealed_packet)
        );
        assert!(!host_argv_matches_exact_grammar(
            &request,
            sealed_packet,
            Path::new("unused")
        )?);
        Ok(())
    }

    #[test]
    fn secret_output_is_cleared_before_any_content_digest() {
        let mut stdout = b"Authorization: Bearer synthetic-token-value-12345".to_vec();
        let mut stderr = b"safe diagnostic".to_vec();
        let (rule, stdout_hash, stderr_hash) = admit_provider_output(&mut stdout, &mut stderr);
        assert_eq!(
            rule,
            Some(eliot_types::SecretBoundaryRule::AuthorizationHeader)
        );
        assert!(stdout.is_empty());
        assert!(stderr.is_empty());
        assert!(stdout_hash.is_none());
        assert!(stderr_hash.is_none());
    }
}
