//! Authenticated Kernel execution and immutable-source evaluation for profile stages.
//!
//! This is the resolver-side half of the ProfileResolver process lane. Kernel
//! owns process admission and the one physical executor; this module retains
//! only the owner-issued grant, the original start/binding/evidence records,
//! and the complete bytes read back from the same immutable Blob sources.

use std::collections::BTreeSet;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use eliot_contracts::{canonical_json_bytes, sha256_hex};
use eliot_instrument_api::{
    ExecutionStatus, InstrumentAdmissionGrant, InstrumentAdmissionRequest, VerificationOutcome,
};
use eliot_process::{
    DurableProcessStreamSource, DurableStreamRepresentation, ExitDisposition,
    ProcessEvidence, ProcessExecutionBinding, ProcessExecutionView, ProcessLifecycle,
    ProcessStartReceipt, ProcessStreamEvidence, ProcessStreamKind, StreamPersistenceStatus,
    StreamTransportStatus,
};
use eliot_process_executor::environment_projection_digest;
use eliot_blob_api::verification_wire::{
    VERIFICATION_STAGE_LAUNCH_WIRE_ID, VERIFICATION_STAGE_LIFECYCLE_WIRE_ID,
    VERIFICATION_STAGE_MAX_DESCENDANTS, VERIFICATION_STAGE_READBACK_WIRE_ID,
    VERIFICATION_STAGE_STDERR_BYTES, VERIFICATION_STAGE_STDOUT_BYTES,
    VERIFICATION_STAGE_TOOL_PROBE_WIRE_ID, VERIFICATION_STAGE_WALL_TIMEOUT_MS,
    VERIFICATION_STAGE_WIRE_REVISION, PROCESS_STREAM_READBACK_MAX_CHUNK_BYTES,
    VerificationStageBinding, VerificationStageExecutionPort, VerificationStageGrantProjection,
    VerificationStageLaunchOutcome, VerificationStageLaunchProjection,
    VerificationStageLaunchRequest, VerificationStageLaunchResponse,
    VerificationStageLifecycleAction, VerificationStageLifecycleOutcome,
    VerificationStageLifecycleRequest, VerificationStageReadbackChunk,
    VerificationStageReadbackOutcome, VerificationStageReadbackRequest,
    VerificationStageToolProbeOutcome, VerificationStageToolProbeProjection,
    VerificationStageToolProbeRequest, VerificationStageToolProbeResponse,
    source_root_identity_sha256,
};

use crate::profile::{
    AdmittedStage, InstrumentRegistry, TargetLayout, PACKAGE_VERIFICATION_COMPILE_ONLY_ALIAS,
};
use crate::profile_run::{
    InstrumentRun, KernelStageGrantEvidence, PlannedStage,
    RetainedExitOutcome, RetainedProcessStreamIdentity, RetainedStreamReadbackChunkProof,
    RetainedToolIdentity, StageEvidence, StagePlan, StageTargetLayout, StageTerminalEvaluation,
};
use crate::registry::ResolvedExecutableIdentity;

/// Wall-clock deadline for one Kernel-owned tool version probe.
const TOOL_PROBE_TIMEOUT: Duration = Duration::from_secs(60);
/// Cadence for exact Kernel process-view observations.
const LIFECYCLE_POLL: Duration = Duration::from_millis(25);
/// Bounded wait for a cancelled process to reach a terminal view.
const CANCELLATION_GRACE: Duration = Duration::from_secs(5);
/// Upper bound for one owner source readback operation.
const READBACK_CALL_TIMEOUT: Duration = Duration::from_secs(30);

/// A machine-observed selected toolchain executable for one admitted stage.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerificationStageTool {
    /// Exact canonical absolute toolchain executable path.
    pub canonical_path: String,
    /// SHA-256 measured over the selected executable bytes.
    pub sha256: String,
}

/// Runs an admitted plan through one authenticated Kernel execution port.
///
/// No process authority is created here. Every launch, lifecycle observation,
/// terminal reconciliation, and source readback crosses the same authenticated
/// `ProfileResolverSession` supplied by the composition root.
pub fn launch_plan_live_verified(
    port: &dyn VerificationStageExecutionPort,
    registry: &InstrumentRegistry,
    plan: &StagePlan,
    layout: &TargetLayout,
    environment: &eliot_process::EnvironmentProjection,
    route_alias: &str,
    tool_for_stage: impl Fn(&PlannedStage) -> Result<VerificationStageTool, String>,
) -> Vec<InstrumentRun> {
    if route_alias != PACKAGE_VERIFICATION_COMPILE_ONLY_ALIAS {
        return plan
            .stages
            .iter()
            .map(|planned| {
                missing_run(
                    planned,
                    plan,
                    route_alias,
                    "Kernel profile-stage lane only admits the compile-only verification alias",
                )
            })
            .collect();
    }
    if environment.inheritance() != eliot_process::EnvironmentInheritance::None
        || !environment.secret_refs().is_empty()
        || environment.non_secret().len() != 3
        || !environment.non_secret().contains_key("PATH")
        || !environment.non_secret().contains_key("CARGO_TARGET_DIR")
        || !environment.non_secret().contains_key("CARGO_HOME")
    {
        return plan
            .stages
            .iter()
            .map(|planned| {
                missing_run(
                    planned,
                    plan,
                    route_alias,
                    "profile-stage environment is not the exact isolated toolchain projection",
                )
            })
            .collect();
    }
    if plan.registry_generation != registry.generation()
        || plan.registry_digest != registry.digest()
    {
        return plan
            .stages
            .iter()
            .map(|planned| {
                missing_run(
                    planned,
                    plan,
                    route_alias,
                    "stage plan was compiled against a different registry generation",
                )
            })
            .collect();
    }

    let mut runs = Vec::with_capacity(plan.stages.len());
    let mut blocked = BTreeSet::new();
    for planned in &plan.stages {
        let dependency = planned
            .stage
            .depends_on
            .iter()
            .find(|dependency| {
                !dependency_has_verified_success(dependency, &blocked, &runs)
            });
        if let Some(dependency) = dependency {
            let run = missing_run(
                planned,
                plan,
                route_alias,
                &format!(
                    "blocked by dependency '{dependency}' without terminal verified PASS"
                ),
            );
            blocked.insert(planned.stage.stage_id.clone());
            runs.push(run);
            continue;
        }

        let run = execute_stage(
            port,
            registry,
            plan,
            planned,
            layout,
            environment,
            route_alias,
            &tool_for_stage,
        );
        if !run.is_verified_success() {
            blocked.insert(planned.stage.stage_id.clone());
        }
        runs.push(run);
    }
    runs
}

fn execute_stage(
    port: &dyn VerificationStageExecutionPort,
    registry: &InstrumentRegistry,
    plan: &StagePlan,
    planned: &PlannedStage,
    layout: &TargetLayout,
    environment: &eliot_process::EnvironmentProjection,
    route_alias: &str,
    tool_for_stage: &impl Fn(&PlannedStage) -> Result<VerificationStageTool, String>,
) -> InstrumentRun {
    let route = &planned.route;
    if !route.external() {
        return missing_run(planned, plan, route_alias, "pure stages are not process launches");
    }
    let tool = match tool_for_stage(planned) {
        Ok(tool) => tool,
        Err(reason) => return missing_run(planned, plan, route_alias, &reason),
    };
    let environment_sha256 = environment_projection_digest(environment);
    let binding = match make_binding(planned, plan, layout, route_alias, &tool, &environment_sha256) {
        Ok(binding) => binding,
        Err(reason) => return missing_run(planned, plan, route_alias, &reason),
    };
    let argv = planned.stage.verification_command.clone();
    let probe_projection = VerificationStageToolProbeProjection {
        source_root: layout.source_root.clone(),
        target_root: layout.target_root.clone(),
        cache_root: layout.cache_root.clone(),
        executable_path: tool.canonical_path.clone(),
        working_directory: layout.source_root.clone(),
        environment: environment.non_secret().clone(),
    };
    let probe_request = VerificationStageToolProbeRequest {
        wire_id: VERIFICATION_STAGE_TOOL_PROBE_WIRE_ID.to_owned(),
        wire_revision: VERIFICATION_STAGE_WIRE_REVISION,
        binding: binding.clone(),
        projection: probe_projection,
        probe_id: unique_operation_id("profile-tool-probe", &planned.stage.stage_id),
        deadline_ms: deadline_from_now(TOOL_PROBE_TIMEOUT),
    };
    let probe_response = match port.probe_tool_version(&probe_request) {
        Ok(response) => response,
        Err(error) => {
            return missing_run(
                planned,
                plan,
                route_alias,
                &format!("Kernel tool-version probe is unavailable: {error}"),
            );
        }
    };
    if let Err(error) = probe_response.validate_for_request(&probe_request) {
        return missing_run(
            planned,
            plan,
            route_alias,
            &format!("Kernel tool-version probe response is invalid: {error}"),
        );
    }
    let (probe_ref, probe_sha256, tool_version) = match validate_probe(&probe_response) {
        Ok(observed) => observed,
        Err(reason) => return missing_run(planned, plan, route_alias, &reason),
    };
    if probe_response_observed_at(&probe_response)
        .is_none_or(|observed| observed > probe_request.deadline_ms)
    {
        return missing_run(
            planned,
            plan,
            route_alias,
            "Kernel tool-version probe completed after its owner deadline",
        );
    }

    let identity = match ResolvedExecutableIdentity::new(
        planned.stage.spec.as_str(),
        tool.canonical_path.clone(),
        tool.sha256.clone(),
        Some(tool_version),
        environment_sha256.clone(),
        argv.clone(),
    ) {
        Ok(identity) => identity,
        Err(error) => {
            return missing_run(
                planned,
                plan,
                route_alias,
                &format!("observed tool identity is invalid: {error}"),
            );
        }
    };
    let admission = InstrumentAdmissionRequest {
        instrument: planned.stage.spec.clone(),
        kind: planned.stage.kind,
        profile: planned.stage.profile.clone(),
        arguments: Vec::new(),
        executable_path: Some(tool.canonical_path.clone()),
        executable_digest: Some(tool.sha256.clone()),
        executable_version: identity.tool_version.clone(),
    };
    let profile_grant = match planned.stage.admit_live(
        registry,
        &admission,
        Some(&identity),
        planned.stage.profile_revision,
    ) {
        Ok(grant) => grant,
        Err(error) => {
            return missing_run(
                planned,
                plan,
                route_alias,
                &format!("profile-stage admission refused after tool probe: {error}"),
            );
        }
    };

    let deadline_ms = deadline_from_now(Duration::from_millis(VERIFICATION_STAGE_WALL_TIMEOUT_MS));
    let launch_request = VerificationStageLaunchRequest {
        wire_id: VERIFICATION_STAGE_LAUNCH_WIRE_ID.to_owned(),
        wire_revision: VERIFICATION_STAGE_WIRE_REVISION,
        launch_id: unique_operation_id("profile-stage-launch", &planned.stage.stage_id),
        binding: binding.clone(),
        projection: VerificationStageLaunchProjection {
            source_root: layout.source_root.clone(),
            target_root: layout.target_root.clone(),
            cache_root: layout.cache_root.clone(),
            executable_path: tool.canonical_path.clone(),
            argv,
            working_directory: layout.source_root.clone(),
            environment: environment.non_secret().clone(),
            wall_timeout_ms: VERIFICATION_STAGE_WALL_TIMEOUT_MS,
            stdout_bytes: VERIFICATION_STAGE_STDOUT_BYTES,
            stderr_bytes: VERIFICATION_STAGE_STDERR_BYTES,
            max_descendants: VERIFICATION_STAGE_MAX_DESCENDANTS,
        },
        probe_ref,
        probe_sha256,
        deadline_ms,
    };
    let launch_started = Instant::now();
    let launch_response = match port.launch_stage(&launch_request) {
        Ok(response) => response,
        Err(error) => {
            return admitted_refusal_run(
                planned,
                plan,
                route_alias,
                &profile_grant,
                &tool,
                Some(StageTargetLayout {
                    layout_revision: eliot_instrument_api::TARGET_LAYOUT_REVISION,
                    build_class: planned.stage.build_class(),
                    workspace_id: None,
                    checkout_id: None,
                    working_directory_observed: layout.source_root.clone(),
                    target_root_observed: Some(layout.target_root.clone()),
                    cache_root_observed: Some(layout.cache_root.clone()),
                }),
                &format!("Kernel stage launch is unavailable: {error}"),
            );
        }
    };
    if let Err(error) = launch_response.validate_for_request(&launch_request) {
        return admitted_refusal_run(
            planned,
            plan,
            route_alias,
            &profile_grant,
            &tool,
            None,
            &format!("Kernel stage launch response is invalid: {error}"),
        );
    }

    let (execution_ref, process_binding, binding_sha256, kernel_grant, start, start_digest, start_at, unknown_launch) =
        match parse_launch(&launch_response, &binding) {
            Ok(launch) => launch,
            Err(reason) => {
                return admitted_refusal_run(
                    planned,
                    plan,
                    route_alias,
                    &profile_grant,
                    &tool,
                    None,
                    &reason,
                );
            }
        };
    let mut run = match InstrumentRun::launched_in_plan(
        route,
        process_binding.operation_id().as_str().to_owned(),
        &profile_grant,
        tool.sha256.as_str(),
        Some(StageTargetLayout {
            layout_revision: eliot_instrument_api::TARGET_LAYOUT_REVISION,
            build_class: planned.stage.build_class(),
            workspace_id: None,
            checkout_id: None,
            working_directory_observed: layout.source_root.clone(),
            target_root_observed: Some(layout.target_root.clone()),
            cache_root_observed: Some(layout.cache_root.clone()),
        }),
        plan,
    ) {
        run => run,
    };
    run.kernel_profile_id = Some(route_alias.to_owned());
    run.kernel_stage_grant = Some(kernel_grant.clone());
    run.kernel_process_binding = Some(process_binding.clone());
    run.kernel_process_binding_sha256 = Some(binding_sha256.clone());
    run.kernel_process_start_receipt = start;
    run.kernel_process_start_receipt_sha256 = start_digest;
    run.kernel_start_observed_at_unix_ms = start_at;
    if run.profile_admission_grant_digest.is_none() {
        run.profile_admission_grant_digest = Some(profile_grant.grant_digest.clone());
    }
    if run.evidence.is_missing() {
        return run;
    }
    if unknown_launch {
        run.execution = ExecutionStatus::Unknown;
        run.evidence = StageEvidence::Omitted {
            reason: "Kernel retained an unresolved profile-stage launch; terminal inspection is required".to_owned(),
        };
    }

    let wall_deadline = launch_started + Duration::from_millis(VERIFICATION_STAGE_WALL_TIMEOUT_MS);
    let supervised = supervise(
        port,
        execution_ref.as_str(),
        binding_sha256.as_str(),
        &process_binding,
        wall_deadline,
    );
    let (process, terminal_observed_at, view, view_observed_at, view_digest) = match supervised {
        Ok(result) => result,
        Err(failure) => {
            run.execution = ExecutionStatus::Unknown;
            run.evidence = StageEvidence::Omitted {
                reason: failure.reason,
            };
            if let Some((view, observed_at, digest)) = failure.last_view {
                run.last_process_observation = Some(view);
                run.last_process_observation_at_unix_ms = Some(observed_at);
                run.last_process_observation_sha256 = Some(digest);
            }
            return run;
        }
    };
    run.last_process_observation = Some(view.clone());
    run.last_process_observation_at_unix_ms = Some(view_observed_at);
    run.last_process_observation_sha256 = Some(view_digest);

    let terminal_status = terminal_execution_status(&process, terminal_observed_at <= deadline_ms);
    let terminal_error = terminal_evidence_skew(&process, &process_binding, &binding_sha256)
        .or_else(|| {
            (!kernel_grant.validates_for(
                planned,
                &process,
                &binding_sha256,
                route_alias,
                &binding,
            ))
            .then(|| "reconciled process differs from the exact Kernel stage-grant binding".to_owned())
        });
    if let Some(reason) = terminal_error {
        run.adopt_terminal_evaluation(
            ExecutionStatus::Unknown,
            &process,
            StageTerminalEvaluation::refused(VerificationOutcome::Unknown, reason),
            None,
        );
        run.kernel_terminal_process_evidence_sha256 = canonical_digest(&process).ok();
        run.terminal_reconciled_at_unix_ms = Some(terminal_observed_at);
        return run;
    }

    let stage_deadline_met = terminal_observed_at <= deadline_ms
        && launch_started.elapsed() <= Duration::from_millis(VERIFICATION_STAGE_WALL_TIMEOUT_MS);
    let readbacks = read_both_streams(
        port,
        execution_ref.as_str(),
        binding_sha256.as_str(),
        &kernel_grant.projection,
        &process,
        terminal_observed_at,
    );
    let (streams, stdout_bytes, _stderr_bytes) = match readbacks {
        Ok(value) => value,
        Err(reason) => {
            let outcome = if terminal_status == ExecutionStatus::Cancelled {
                VerificationOutcome::Cancelled
            } else if terminal_status == ExecutionStatus::Failed {
                VerificationOutcome::Fail
            } else {
                VerificationOutcome::Unknown
            };
            run.adopt_terminal_evaluation(
                terminal_status,
                &process,
                StageTerminalEvaluation::refused(outcome, reason),
                retained_tool_for_process(
                    &process,
                    &tool,
                    &planned.stage.verification_command,
                    environment_sha256.as_str(),
                ),
            );
            run.kernel_terminal_process_evidence_sha256 = canonical_digest(&process).ok();
            run.terminal_reconciled_at_unix_ms = Some(terminal_observed_at);
            return run;
        }
    };
    let process_exit_code = process
        .view()
        .exit()
        .and_then(serialized_exit_code);
    let parser_outcome = evaluate_admitted_parser(&planned.stage, &stdout_bytes, process_exit_code);
    let outcome = if !stage_deadline_met {
        VerificationOutcome::Unknown
    } else if terminal_status != ExecutionStatus::Succeeded {
        match terminal_status {
            ExecutionStatus::Failed => VerificationOutcome::Fail,
            ExecutionStatus::Cancelled => VerificationOutcome::Cancelled,
            _ => VerificationOutcome::Unknown,
        }
    } else {
        parser_outcome
    };
    let detail = match (stage_deadline_met, terminal_status, outcome) {
        (false, _, _) => Some("stage reached terminal after its admitted wall deadline".to_owned()),
        (_, ExecutionStatus::Succeeded, VerificationOutcome::Pass) => None,
        (_, ExecutionStatus::Succeeded, _) => Some("admitted parser did not prove PASS from the complete owner-read-back source".to_owned()),
        (_, ExecutionStatus::Failed, _) => Some("Kernel reconciled a failed or nonzero stage process".to_owned()),
        (_, ExecutionStatus::Cancelled, _) => Some("Kernel reconciled stage cancellation".to_owned()),
        _ => Some("Kernel reconciled a stage without a passing terminal disposition".to_owned()),
    };
    let evaluation = match StageTerminalEvaluation::new(outcome, streams, detail) {
        Ok(evaluation) => evaluation,
        Err(error) => StageTerminalEvaluation::refused(
            VerificationOutcome::Unknown,
            format!("terminal parser proof could not be retained: {error}"),
        ),
    };
    run.adopt_terminal_evaluation(
        terminal_status,
        &process,
        evaluation,
        retained_tool_for_process(
            &process,
            &tool,
            &planned.stage.verification_command,
            environment_sha256.as_str(),
        ),
    );
    run.kernel_terminal_process_evidence_sha256 = canonical_digest(&process).ok();
    run.terminal_reconciled_at_unix_ms = Some(terminal_observed_at);
    run.last_process_observation = Some(process.view().clone());
    run
}

fn dependency_has_verified_success(
    dependency: &str,
    blocked: &BTreeSet<String>,
    runs: &[InstrumentRun],
) -> bool {
    !blocked.contains(dependency)
        && runs
            .iter()
            .find(|run| run.stage.stage_id == dependency)
            .is_some_and(InstrumentRun::is_verified_success)
}

fn make_binding(
    planned: &PlannedStage,
    plan: &StagePlan,
    layout: &TargetLayout,
    route_alias: &str,
    tool: &VerificationStageTool,
    environment_sha256: &str,
) -> Result<VerificationStageBinding, String> {
    let argv = &planned.stage.verification_command;
    let argv_bytes = canonical_json_bytes(argv)
        .map_err(|error| format!("admitted argv cannot be canonicalized: {error}"))?;
    let stage_sha256 = planned
        .stage
        .declaration_sha256()
        .map_err(|error| format!("admitted stage declaration cannot be hashed: {error}"))?;
    let binding = VerificationStageBinding {
        profile_id: route_alias.to_owned(),
        profile_revision: planned.stage.profile_revision,
        profile_sha256: plan.profile_digest.clone(),
        dag_sha256: plan.dag_digest.clone(),
        stage_id: planned.stage.stage_id.clone(),
        stage_sha256,
        tool_sha256: tool.sha256.clone(),
        argv_sha256: sha256_hex(&argv_bytes),
        environment_sha256: environment_sha256.to_owned(),
        source_root_identity_sha256: source_root_identity_sha256(&layout.source_root)
            .map_err(|error| format!("admitted source root cannot be hashed: {error}"))?,
    };
    binding
        .validate()
        .map_err(|error| format!("profile-stage binding is invalid: {error}"))?;
    Ok(binding)
}

fn validate_probe(
    response: &VerificationStageToolProbeResponse,
) -> Result<(String, String, String), String> {
    match &response.outcome {
        VerificationStageToolProbeOutcome::Observed {
            probe_ref,
            probe_sha256,
            process_binding_json,
            process_binding_sha256,
            process_operation_id,
            tool_version,
            process_evidence_json,
            process_evidence_sha256,
            observed_at_unix_ms,
        } => {
            let binding = parse_process_binding(process_binding_json, process_binding_sha256)?;
            if binding.operation_id().as_str() != process_operation_id {
                return Err("Kernel version probe operation does not match its original binding".to_owned());
            }
            let evidence = parse_canonical::<ProcessEvidence>(
                process_evidence_json,
                process_evidence_sha256,
                "Kernel version probe ProcessEvidence",
            )?;
            evidence
                .validate()
                .map_err(|error| format!("Kernel version probe evidence is invalid: {error}"))?;
            if evidence.binding() != &binding
                || evidence.view().lifecycle() != ProcessLifecycle::Exited
                || !evidence.view().exit().is_some_and(|exit| {
                    exit.disposition() == ExitDisposition::Completed
                        && serialized_exit_code(exit) == Some(0)
                })
            {
                return Err("Kernel version probe lacks original terminal zero-exit evidence".to_owned());
            }
            let stdout = evidence.stdout().ok_or_else(|| {
                "Kernel version probe retained no stdout stream".to_owned()
            })?;
            if stdout.stream() != ProcessStreamKind::Stdout
                || stdout.binding() != &binding
                || stdout.transport() != StreamTransportStatus::Complete
                || !stdout.gaps().is_empty()
                || !stdout.preview().omitted_ranges().is_empty()
                || stdout.preview().bytes().len() as u64 != stdout.observed_bytes()
                || sha256_hex(stdout.preview().bytes()) != stdout.observed_sha256()
            {
                return Err("Kernel version probe stdout is partial, truncated, or misbound".to_owned());
            }
            let output = std::str::from_utf8(stdout.preview().bytes())
                .map_err(|_| "Kernel version probe stdout is not UTF-8".to_owned())?;
            let observed_version = output
                .lines()
                .map(str::trim)
                .find(|line| !line.is_empty())
                .ok_or_else(|| "Kernel version probe emitted no nonblank version line".to_owned())?;
            if observed_version != tool_version || observed_version.len() > 4096 {
                return Err("Kernel tool version does not match its original stdout evidence".to_owned());
            }
            if *observed_at_unix_ms == 0 {
                return Err("Kernel tool version probe has no owner observation time".to_owned());
            }
            Ok((probe_ref.clone(), probe_sha256.clone(), tool_version.clone()))
        }
        VerificationStageToolProbeOutcome::Unknown { .. } => {
            Err("Kernel tool-version probe outcome is unresolved".to_owned())
        }
        VerificationStageToolProbeOutcome::Unavailable { reason } => {
            Err(format!("Kernel refused tool-version probe: {reason:?}"))
        }
    }
}

fn probe_response_observed_at(response: &VerificationStageToolProbeResponse) -> Option<u64> {
    match &response.outcome {
        VerificationStageToolProbeOutcome::Observed { observed_at_unix_ms, .. }
        | VerificationStageToolProbeOutcome::Unknown { observed_at_unix_ms, .. } => {
            Some(*observed_at_unix_ms)
        }
        VerificationStageToolProbeOutcome::Unavailable { .. } => None,
    }
}

type ParsedLaunch = (
    String,
    ProcessExecutionBinding,
    String,
    KernelStageGrantEvidence,
    Option<ProcessStartReceipt>,
    Option<String>,
    Option<u64>,
    bool,
);

fn parse_launch(
    response: &VerificationStageLaunchResponse,
    expected_binding: &VerificationStageBinding,
) -> Result<ParsedLaunch, String> {
    match &response.outcome {
        VerificationStageLaunchOutcome::Started {
            execution_ref,
            process_binding_json,
            process_binding_sha256,
            process_start_receipt_json,
            process_start_receipt_sha256,
            grant,
            grant_sha256,
            observed_at_unix_ms,
        } => {
            let process_binding = parse_process_binding(
                process_binding_json,
                process_binding_sha256,
            )?;
            let start: ProcessStartReceipt = parse_canonical(
                process_start_receipt_json,
                process_start_receipt_sha256,
                "Kernel ProcessStartReceipt",
            )?;
            start
                .validate()
                .map_err(|error| format!("Kernel ProcessStartReceipt is invalid: {error}"))?;
            if start.binding() != &process_binding
                || start.operation_id() != process_binding.operation_id()
                || &grant.binding != expected_binding
                || grant.execution_ref != *execution_ref
                || grant.process_binding_sha256 != *process_binding_sha256
                || *observed_at_unix_ms < grant.issued_at_unix_ms
                || *observed_at_unix_ms > grant.expires_at_unix_ms
            {
                return Err("Kernel start, grant, and exact process binding disagree".to_owned());
            }
            let grant = KernelStageGrantEvidence::new((**grant).clone(), grant_sha256.clone())
                .map_err(|error| format!("Kernel stage grant is invalid: {error}"))?;
            Ok((
                execution_ref.clone(),
                process_binding,
                process_binding_sha256.clone(),
                grant,
                Some(start),
                Some(process_start_receipt_sha256.clone()),
                Some(*observed_at_unix_ms),
                false,
            ))
        }
        VerificationStageLaunchOutcome::Unknown {
            execution_ref,
            process_binding_json,
            process_binding_sha256,
            grant,
            grant_sha256,
            observed_at_unix_ms,
        } => {
            let process_binding = parse_process_binding(
                process_binding_json,
                process_binding_sha256,
            )?;
            if &grant.binding != expected_binding
                || grant.execution_ref != *execution_ref
                || grant.process_binding_sha256 != *process_binding_sha256
                || *observed_at_unix_ms < grant.issued_at_unix_ms
                || *observed_at_unix_ms > grant.expires_at_unix_ms
            {
                return Err("unresolved Kernel launch does not match its retained grant".to_owned());
            }
            let grant = KernelStageGrantEvidence::new((**grant).clone(), grant_sha256.clone())
                .map_err(|error| format!("Kernel stage grant is invalid: {error}"))?;
            Ok((
                execution_ref.clone(),
                process_binding,
                process_binding_sha256.clone(),
                grant,
                None,
                None,
                None,
                true,
            ))
        }
        VerificationStageLaunchOutcome::Unavailable { reason } => {
            Err(format!("Kernel refused profile-stage launch: {reason:?}"))
        }
    }
}

struct SupervisedTerminal {
    evidence: ProcessEvidence,
    terminal_observed_at: u64,
    view: ProcessExecutionView,
    view_observed_at: u64,
    view_sha256: String,
}

type ProcessViewObservation = (ProcessExecutionView, u64, String);

#[derive(Debug)]
struct SupervisionFailure {
    reason: String,
    last_view: Option<ProcessViewObservation>,
}

fn supervision_failure(
    reason: impl Into<String>,
    last_view: &Option<ProcessViewObservation>,
) -> SupervisionFailure {
    SupervisionFailure {
        reason: reason.into(),
        last_view: last_view.clone(),
    }
}

fn supervise(
    port: &dyn VerificationStageExecutionPort,
    execution_ref: &str,
    process_binding_sha256: &str,
    original_binding: &ProcessExecutionBinding,
    wall_deadline: Instant,
) -> Result<(ProcessEvidence, u64, ProcessExecutionView, u64, String), SupervisionFailure> {
    let grace_deadline = wall_deadline + CANCELLATION_GRACE;
    let mut last_observation_at = 0_u64;
    let mut last_view: Option<ProcessViewObservation> = None;
    let mut cancellation_requested = false;
    loop {
        let now = Instant::now();
        let action = if now >= wall_deadline && !cancellation_requested {
            cancellation_requested = true;
            VerificationStageLifecycleAction::Cancel
        } else if let Some((view, _, _)) = &last_view {
            if view.lifecycle().is_terminal() {
                VerificationStageLifecycleAction::Reconcile
            } else if now >= grace_deadline {
                return Err(supervision_failure(
                    "Kernel process remained nonterminal after the admitted deadline and cancellation grace",
                    &last_view,
                ));
            } else {
                VerificationStageLifecycleAction::Inspect
            }
        } else {
            VerificationStageLifecycleAction::Inspect
        };
        let request = VerificationStageLifecycleRequest {
            wire_id: VERIFICATION_STAGE_LIFECYCLE_WIRE_ID.to_owned(),
            wire_revision: VERIFICATION_STAGE_WIRE_REVISION,
            execution_ref: execution_ref.to_owned(),
            process_binding_sha256: process_binding_sha256.to_owned(),
            action,
            deadline_ms: deadline_from_now(READBACK_CALL_TIMEOUT),
        };
        let response = port
            .lifecycle(&request)
            .map_err(|error| {
                supervision_failure(
                    format!("Kernel lifecycle operation is unavailable: {error}"),
                    &last_view,
                )
            })?;
        response
            .validate_for_request(&request)
            .map_err(|error| {
                supervision_failure(
                    format!("Kernel lifecycle response is invalid: {error}"),
                    &last_view,
                )
            })?;
        if response.observed_at_unix_ms < last_observation_at {
            return Err(supervision_failure(
                "Kernel lifecycle observation clock moved backwards",
                &last_view,
            ));
        }
        last_observation_at = response.observed_at_unix_ms;
        match (&action, &response.outcome) {
            (
                VerificationStageLifecycleAction::Inspect,
                VerificationStageLifecycleOutcome::Inspected {
                    process_view_json,
                    process_view_sha256,
                },
            ) => {
                let view: ProcessExecutionView = parse_canonical(
                    process_view_json,
                    process_view_sha256,
                    "Kernel ProcessExecutionView",
                )
                .map_err(|reason| supervision_failure(reason, &last_view))?;
                if view.binding() != original_binding {
                    return Err(supervision_failure(
                        "Kernel inspection substituted the original process binding",
                        &last_view,
                    ));
                }
                last_view = Some((view, response.observed_at_unix_ms, process_view_sha256.clone()));
            }
            (
                VerificationStageLifecycleAction::Cancel,
                VerificationStageLifecycleOutcome::Cancelled {
                    cancellation_receipt_json,
                    cancellation_receipt_sha256,
                },
            ) => {
                let cancellation: eliot_process::CancellationReceipt = parse_canonical(
                    cancellation_receipt_json,
                    cancellation_receipt_sha256,
                    "Kernel CancellationReceipt",
                )
                .map_err(|reason| supervision_failure(reason, &last_view))?;
                if cancellation.binding() != original_binding {
                    return Err(supervision_failure(
                        "Kernel cancellation receipt substituted the process binding",
                        &last_view,
                    ));
                }
                // Cancellation is an effect request, not terminal proof. The
                // loop returns to Inspect and reconciles only after an owner
                // view establishes a terminal lifecycle.
            }
            (
                VerificationStageLifecycleAction::Reconcile,
                VerificationStageLifecycleOutcome::Reconciled {
                    process_evidence_json,
                    process_evidence_sha256,
                },
            ) => {
                let evidence: ProcessEvidence = parse_canonical(
                    process_evidence_json,
                    process_evidence_sha256,
                    "Kernel ProcessEvidence",
                )
                .map_err(|reason| supervision_failure(reason, &last_view))?;
                evidence
                    .validate()
                    .map_err(|error| {
                        supervision_failure(
                            format!("Kernel ProcessEvidence is invalid: {error}"),
                            &last_view,
                        )
                    })?;
                let (view, view_at, view_sha) = last_view.clone().ok_or_else(|| {
                    supervision_failure(
                        "Kernel reconciled without a retained terminal inspection",
                        &last_view,
                    )
                })?;
                if !view.lifecycle().is_terminal()
                    || view.binding() != evidence.binding()
                    || view != *evidence.view()
                    || evidence.binding() != original_binding
                    || response.observed_at_unix_ms < view_at
                {
                    return Err(supervision_failure(
                        "Kernel reconciliation disagrees with its prior terminal view",
                        &last_view,
                    ));
                }
                return Ok((
                    evidence,
                    response.observed_at_unix_ms,
                    view,
                    view_at,
                    view_sha,
                ));
            }
            (_, VerificationStageLifecycleOutcome::Unknown) => {
                if Instant::now() >= grace_deadline {
                    return Err(supervision_failure(
                        "Kernel process lifecycle remains unknown after its bounded supervision window",
                        &last_view,
                    ));
                }
            }
            (_, VerificationStageLifecycleOutcome::Unavailable { reason }) => {
                return Err(supervision_failure(
                    format!("Kernel refused lifecycle supervision: {reason:?}"),
                    &last_view,
                ));
            }
            _ => {
                return Err(supervision_failure(
                    "Kernel returned a lifecycle result for the wrong requested action",
                    &last_view,
                ));
            }
        }
        if action == VerificationStageLifecycleAction::Reconcile {
            return Err(supervision_failure(
                "Kernel did not reconcile the terminal process",
                &last_view,
            ));
        }
        if Instant::now() < wall_deadline || cancellation_requested {
            std::thread::sleep(LIFECYCLE_POLL);
        }
        if Instant::now() >= grace_deadline
            && last_view
                .as_ref()
                .is_none_or(|(view, _, _)| !view.lifecycle().is_terminal())
        {
            return Err(supervision_failure(
                "Kernel process remained nonterminal after the admitted deadline and cancellation grace",
                &last_view,
            ));
        }
    }
}

fn terminal_evidence_skew(
    evidence: &ProcessEvidence,
    original_binding: &ProcessExecutionBinding,
    process_binding_sha256: &str,
) -> Option<String> {
    let digest = canonical_json_bytes(evidence.binding())
        .ok()
        .map(|bytes| sha256_hex(&bytes));
    if evidence.binding() != original_binding
        || digest.as_deref() != Some(process_binding_sha256)
        || evidence.operation_id() != original_binding.operation_id()
    {
        Some("reconciled evidence differs from Kernel's original process binding".to_owned())
    } else {
        None
    }
}

fn read_both_streams(
    port: &dyn VerificationStageExecutionPort,
    execution_ref: &str,
    process_binding_sha256: &str,
    grant: &VerificationStageGrantProjection,
    evidence: &ProcessEvidence,
    terminal_observed_at: u64,
) -> Result<(Vec<RetainedProcessStreamIdentity>, Vec<u8>, Vec<u8>), String> {
    let stdout = evidence
        .stdout()
        .ok_or_else(|| "reconciled process has no original stdout evidence".to_owned())?;
    let stderr = evidence
        .stderr()
        .ok_or_else(|| "reconciled process has no original stderr evidence".to_owned())?;
    let (stdout_identity, stdout_bytes) = read_one_stream(
        port,
        execution_ref,
        process_binding_sha256,
        grant,
        stdout,
        terminal_observed_at,
    )?;
    let (stderr_identity, stderr_bytes) = read_one_stream(
        port,
        execution_ref,
        process_binding_sha256,
        grant,
        stderr,
        terminal_observed_at,
    )?;
    Ok((vec![stdout_identity, stderr_identity], stdout_bytes, stderr_bytes))
}

fn read_one_stream(
    port: &dyn VerificationStageExecutionPort,
    execution_ref: &str,
    process_binding_sha256: &str,
    grant: &VerificationStageGrantProjection,
    evidence: &ProcessStreamEvidence,
    terminal_observed_at: u64,
) -> Result<(RetainedProcessStreamIdentity, Vec<u8>), String> {
    evidence
        .validate()
        .map_err(|error| format!("original process stream evidence is invalid: {error}"))?;
    let source = evidence
        .source()
        .ok_or_else(|| format!("{} has no immutable Ready source", stream_label(evidence.stream())))?;
    if source.representation() != DurableStreamRepresentation::ExactTransportBytes
        || source.byte_length() > VERIFICATION_STAGE_STDOUT_BYTES.max(VERIFICATION_STAGE_STDERR_BYTES)
        || evidence.transport() != StreamTransportStatus::Complete
        || evidence.persistence() != StreamPersistenceStatus::CompleteSource
        || !evidence.gaps().is_empty()
        || source.sha256() != evidence.observed_sha256()
        || source.byte_length() != evidence.observed_bytes()
    {
        return Err(format!("{} source is missing, truncated, transformed, or incomplete", stream_label(evidence.stream())));
    }
    let process_binding_sha256 = canonical_json_bytes(evidence.binding())
        .map(|bytes| sha256_hex(&bytes))
        .map_err(|error| format!("original process binding cannot be hashed: {error}"))?;
    if process_binding_sha256 != grant.process_binding_sha256 {
        return Err("stream evidence belongs to a different retained Kernel process binding".to_owned());
    }
    let evidence_digest = evidence
        .identity_sha256()
        .map_err(|error| format!("original stream evidence cannot be hashed: {error}"))?;
    let mut bytes = Vec::with_capacity(source.byte_length() as usize);
    let mut chunks = Vec::new();
    let mut offset = 0_u64;
    let mut source_generation = None;
    let mut receipts = BTreeSet::new();
    loop {
        let request = VerificationStageReadbackRequest {
            wire_id: VERIFICATION_STAGE_READBACK_WIRE_ID.to_owned(),
            wire_revision: VERIFICATION_STAGE_WIRE_REVISION,
            execution_ref: execution_ref.to_owned(),
            stage_grant_sha256: grant
                .digest()
                .map_err(|error| format!("Kernel stage grant digest is invalid: {error}"))?,
            process_binding_sha256: process_binding_sha256.clone(),
            stream: evidence.stream(),
            locator_kind: source.kind(),
            locator: source.locator().to_owned(),
            ready_receipt_ref: source.ready_receipt_ref().to_owned(),
            expected_source_sha256: source.sha256().to_owned(),
            expected_source_byte_length: source.byte_length(),
            offset,
            chunk_limit: PROCESS_STREAM_READBACK_MAX_CHUNK_BYTES as u32,
            deadline_ms: deadline_from_now(READBACK_CALL_TIMEOUT),
        };
        let response = port
            .readback_source(&request)
            .map_err(|error| format!("{} immutable source readback is unavailable: {error}", stream_label(evidence.stream())))?;
        response
            .validate_for_grant(&request, grant)
            .map_err(|error| format!("{} immutable source readback proof is invalid: {error}", stream_label(evidence.stream())))?;
        let VerificationStageReadbackOutcome::Ready { chunk } = response.outcome else {
            return Err(format!(
                "{} immutable source readback did not return a Ready full-source chunk",
                stream_label(evidence.stream())
            ));
        };
        let chunk = *chunk;
        validate_readback_owner(&chunk, grant, source, terminal_observed_at)?;
        if source_generation.is_some_and(|generation| generation != chunk.owner_proof.source_owner_generation)
            || !receipts.insert(chunk.owner_proof.readback_receipt_id.clone())
        {
            return Err("immutable source owner generation changed or reused a chunk readback receipt".to_owned());
        }
        source_generation = Some(chunk.owner_proof.source_owner_generation);
        let chunk_proof = RetainedStreamReadbackChunkProof {
            offset: chunk.chunk_offset,
            byte_length: chunk.chunk_byte_length,
            chunk_sha256: chunk.chunk_sha256.clone(),
            owner_proof_sha256: chunk.owner_proof_sha256.clone(),
            owner_proof: chunk.owner_proof.clone(),
        };
        bytes.extend_from_slice(&chunk.bytes);
        offset = offset.saturating_add(chunk.chunk_byte_length);
        chunks.push(chunk_proof);
        if offset == source.byte_length() {
            break;
        }
        if chunk.chunk_byte_length == 0 || offset > source.byte_length() {
            return Err("immutable source readback made no contiguous progress".to_owned());
        }
    }
    if bytes.len() as u64 != source.byte_length() || sha256_hex(&bytes) != source.sha256() {
        return Err("resolved immutable source bytes do not match the original whole-source digest".to_owned());
    }
    let identity = RetainedProcessStreamIdentity::from_verified_chunks(
        evidence.stream(),
        evidence.binding().clone(),
        source.clone(),
        evidence.policy().clone(),
        evidence_digest,
        process_binding_sha256,
        chunks,
    )
    .map_err(|error| format!("{} readback identity is invalid: {error}", stream_label(evidence.stream())))?;
    Ok((identity, bytes))
}

fn validate_readback_owner(
    chunk: &VerificationStageReadbackChunk,
    grant: &VerificationStageGrantProjection,
    source: &DurableProcessStreamSource,
    terminal_observed_at: u64,
) -> Result<(), String> {
    let owner = &chunk.owner_proof;
    owner
        .validate()
        .map_err(|error| format!("immutable source owner proof is invalid: {error}"))?;
    if chunk.locator_kind != source.kind()
        || chunk.locator != source.locator()
        || chunk.ready_receipt_ref != source.ready_receipt_ref()
        || chunk.whole_source_sha256 != source.sha256()
        || chunk.whole_source_byte_length != source.byte_length()
        || owner.stage_grant_sha256 != grant.digest().map_err(|error| error.to_string())?
        || owner.scope_binding_json != grant.scope_binding_json
        || owner.scope_binding_sha256 != grant.scope_binding_sha256
        || owner.policy_binding_json != grant.policy_binding_json
        || owner.policy_binding_sha256 != grant.policy_binding_sha256
        || owner.observed_fence != grant.state_fence
        || owner.observed_at_unix_ms < terminal_observed_at
        || owner.observed_at_unix_ms > grant.expires_at_unix_ms
        || owner.source_owner_generation == 0
    {
        return Err("immutable source owner proof does not match the Kernel grant, original source, or terminal clock".to_owned());
    }
    Ok(())
}

fn evaluate_admitted_parser(
    stage: &AdmittedStage,
    stdout: &[u8],
    exit_code: Option<i32>,
) -> VerificationOutcome {
    if exit_code != Some(0) {
        return VerificationOutcome::Fail;
    }
    match stage.parser.as_str() {
        eliot_instrument_cargo::CONTRACT_NAME => eliot_instrument_cargo::parse_jsonl(stdout)
            .map(|report| report.outcome())
            .unwrap_or(VerificationOutcome::Unknown),
        eliot_instrument_rustfmt::RUSTFMT_INSTRUMENT => {
            eliot_instrument_rustfmt::parse_output(stdout)
                .map(|report| report.outcome(exit_code, false))
                .unwrap_or(VerificationOutcome::Unknown)
        }
        _ => VerificationOutcome::Unknown,
    }
}

fn retained_tool_for_process(
    evidence: &ProcessEvidence,
    tool: &VerificationStageTool,
    argv: &[String],
    environment_sha256: &str,
) -> Option<RetainedToolIdentity> {
    let exit = evidence.view().exit()?;
    let code = serialized_exit_code(exit);
    let identity = RetainedToolIdentity::sealed(
        &tool.canonical_path,
        argv,
        environment_sha256,
        RetainedExitOutcome {
            disposition: exit.disposition(),
            code,
        },
    );
    identity.ok()
}

fn terminal_execution_status(evidence: &ProcessEvidence, before_deadline: bool) -> ExecutionStatus {
    if !before_deadline {
        return ExecutionStatus::Unknown;
    }
    match evidence.view().lifecycle() {
        ProcessLifecycle::Exited => match evidence.view().exit() {
            Some(exit) if exit.disposition() == ExitDisposition::Completed => {
                if serialized_exit_code(exit) == Some(0) {
                    ExecutionStatus::Succeeded
                } else {
                    ExecutionStatus::Failed
                }
            }
            Some(exit) if exit.disposition() == ExitDisposition::Cancelled => {
                ExecutionStatus::Cancelled
            }
            Some(exit) if matches!(exit.disposition(), ExitDisposition::Signalled | ExitDisposition::ResourceLimit) => {
                ExecutionStatus::Failed
            }
            _ => ExecutionStatus::Unknown,
        },
        ProcessLifecycle::Failed => ExecutionStatus::Failed,
        ProcessLifecycle::Reconciled | ProcessLifecycle::Quarantined | ProcessLifecycle::UnknownOutcome => {
            ExecutionStatus::Unknown
        }
        ProcessLifecycle::Created
        | ProcessLifecycle::Starting
        | ProcessLifecycle::Running
        | ProcessLifecycle::Cancelling => ExecutionStatus::Unknown,
    }
}

fn admitted_refusal_run(
    planned: &PlannedStage,
    plan: &StagePlan,
    route_alias: &str,
    profile_grant: &InstrumentAdmissionGrant,
    tool: &VerificationStageTool,
    target_layout: Option<StageTargetLayout>,
    reason: &str,
) -> InstrumentRun {
    let mut run = InstrumentRun::missing(&planned.route, reason);
    run.candidate_identity.clone_from(&plan.candidate_identity);
    run.executable_digest = Some(tool.sha256.clone());
    run.profile_admission_grant_digest = Some(profile_grant.grant_digest.clone());
    run.kernel_profile_id = Some(route_alias.to_owned());
    run.target_layout = target_layout;
    run
}

fn missing_run(
    planned: &PlannedStage,
    plan: &StagePlan,
    route_alias: &str,
    reason: &str,
) -> InstrumentRun {
    let mut run = InstrumentRun::missing(&planned.route, reason.to_owned());
    run.candidate_identity.clone_from(&plan.candidate_identity);
    run.kernel_profile_id = Some(route_alias.to_owned());
    run
}

fn parse_process_binding(json: &str, expected_sha256: &str) -> Result<ProcessExecutionBinding, String> {
    let binding: ProcessExecutionBinding = parse_canonical(
        json,
        expected_sha256,
        "Kernel ProcessExecutionBinding",
    )?;
    Ok(binding)
}

fn parse_canonical<T: serde::de::DeserializeOwned + serde::Serialize>(
    json: &str,
    expected_sha256: &str,
    label: &str,
) -> Result<T, String> {
    let value: T = serde_json::from_str(json)
        .map_err(|error| format!("{label} cannot be decoded: {error}"))?;
    let canonical = canonical_json_bytes(&value)
        .map_err(|error| format!("{label} cannot be canonicalized: {error}"))?;
    if canonical.as_slice() != json.as_bytes() || sha256_hex(json.as_bytes()) != expected_sha256 {
        return Err(format!("{label} differs from its Kernel canonical commitment"));
    }
    Ok(value)
}

fn canonical_digest<T: serde::Serialize>(value: &T) -> Result<String, String> {
    canonical_json_bytes(value)
        .map(|bytes| sha256_hex(&bytes))
        .map_err(|error| format!("canonical evidence cannot be hashed: {error}"))
}

fn serialized_exit_code(exit: &eliot_process::ExitStatus) -> Option<i32> {
    serde_json::to_value(exit)
        .ok()?
        .get("code")?
        .as_i64()
        .and_then(|code| i32::try_from(code).ok())
}

fn stream_label(stream: ProcessStreamKind) -> &'static str {
    match stream {
        ProcessStreamKind::Stdout => "stdout",
        ProcessStreamKind::Stderr => "stderr",
    }
}

fn unique_operation_id(prefix: &str, stage_id: &str) -> String {
    static NEXT: AtomicU64 = AtomicU64::new(1);
    let sequence = NEXT.fetch_add(1, Ordering::Relaxed);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos());
    let material = format!("{prefix}\0{stage_id}\0{}\0{now}\0{sequence}", std::process::id());
    format!("{prefix}-{}", &sha256_hex(material.as_bytes())[..40])
}

fn unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(1, |duration| u64::try_from(duration.as_millis()).unwrap_or(u64::MAX))
        .max(1)
}

fn deadline_from_now(duration: Duration) -> u64 {
    unix_ms().saturating_add(u64::try_from(duration.as_millis()).unwrap_or(u64::MAX))
}

#[cfg(test)]
mod terminal_consumer_tests {
    use super::*;

    use std::num::NonZeroU64;
    use std::sync::atomic::AtomicU64;

    use eliot_blob_api::verification_wire::{
        VERIFICATION_STAGE_LIFECYCLE_WIRE_ID, VerificationStageLifecycleResponse,
        VerificationStagePortError, VerificationStageSourceKey,
        VerificationStageSourceOwnerProof,
    };
    use eliot_contracts::{EpochId, EpochLineageId, ResourceGeneration, StateFence};
    use eliot_instrument_api::EvidenceAxes;
    use crate::profile::ProfileCompiler;
    use eliot_process::{
        DurableProcessStreamSource, DurableStreamLocatorKind, ProcessExecutionView,
        ProcessStreamPolicyBinding,
    };
    use crate::profile_run::StageOrchestrator;
    use serde::Serialize;
    use serde_json::json;

    struct LifecyclePort {
        view: ProcessExecutionView,
        evidence: ProcessEvidence,
        substituted_view: Option<ProcessExecutionView>,
        unknown_cancel: bool,
        next_observation: AtomicU64,
    }

    impl LifecyclePort {
        fn new(
            view: ProcessExecutionView,
            evidence: ProcessEvidence,
            substituted_view: Option<ProcessExecutionView>,
            unknown_cancel: bool,
        ) -> Self {
            Self {
                view,
                evidence,
                substituted_view,
                unknown_cancel,
                next_observation: AtomicU64::new(100),
            }
        }

        fn json<T: Serialize>(value: &T) -> (String, String) {
            let bytes = canonical_json_bytes(value).expect("canonical test evidence");
            (String::from_utf8(bytes.clone()).expect("canonical JSON is UTF-8"), sha256_hex(&bytes))
        }
    }

    impl VerificationStageExecutionPort for LifecyclePort {
        fn probe_tool_version(
            &self,
            _request: &VerificationStageToolProbeRequest,
        ) -> Result<VerificationStageToolProbeResponse, VerificationStagePortError> {
            Err(VerificationStagePortError::Unavailable)
        }

        fn launch_stage(
            &self,
            _request: &VerificationStageLaunchRequest,
        ) -> Result<VerificationStageLaunchResponse, VerificationStagePortError> {
            Err(VerificationStagePortError::Unavailable)
        }

        fn lifecycle(
            &self,
            request: &VerificationStageLifecycleRequest,
        ) -> Result<VerificationStageLifecycleResponse, VerificationStagePortError> {
            let observed_at_unix_ms = self.next_observation.fetch_add(1, Ordering::Relaxed);
            let outcome = match request.action {
                VerificationStageLifecycleAction::Inspect => {
                    let view = self.substituted_view.as_ref().unwrap_or(&self.view);
                    let (process_view_json, process_view_sha256) = Self::json(view);
                    VerificationStageLifecycleOutcome::Inspected {
                        process_view_json,
                        process_view_sha256,
                    }
                }
                VerificationStageLifecycleAction::Cancel if self.unknown_cancel => {
                    VerificationStageLifecycleOutcome::Unknown
                }
                VerificationStageLifecycleAction::Cancel => {
                    VerificationStageLifecycleOutcome::Unknown
                }
                VerificationStageLifecycleAction::Reconcile => {
                    let (process_evidence_json, process_evidence_sha256) =
                        Self::json(&self.evidence);
                    VerificationStageLifecycleOutcome::Reconciled {
                        process_evidence_json,
                        process_evidence_sha256,
                    }
                }
            };
            Ok(VerificationStageLifecycleResponse {
                wire_id: VERIFICATION_STAGE_LIFECYCLE_WIRE_ID.to_owned(),
                wire_revision: VERIFICATION_STAGE_WIRE_REVISION,
                execution_ref: request.execution_ref.clone(),
                process_binding_sha256: request.process_binding_sha256.clone(),
                observed_at_unix_ms,
                outcome,
            })
        }

        fn readback_source(
            &self,
            _request: &VerificationStageReadbackRequest,
        ) -> Result<VerificationStageReadbackResponse, VerificationStagePortError> {
            Err(VerificationStagePortError::Unavailable)
        }
    }

    fn binding(tag: &str) -> ProcessExecutionBinding {
        let epoch = json!({
            "lineage_id": "4f5b2d84-67b9-4c80-8f87-22b2390a6a44",
            "sequence": 1
        });
        serde_json::from_value(json!({
            "operation_id": format!("operation-{tag}"),
            "process_tree_id": format!("tree-{tag}"),
            "job_id": format!("job-{tag}"),
            "image_id": format!("image-{tag}"),
            "session_id": format!("session-{tag}"),
            "generation": 1,
            "action_lease_ref": format!("lease-{tag}"),
            "authority_id": format!("authority-{tag}"),
            "authority_epoch": epoch,
            "state_fence": {
                "authority_epoch": epoch,
                "generation": 1,
                "nonce": format!("fence-{tag}")
            },
            "request_digest": "a".repeat(64),
            "permit_digest": "b".repeat(64),
            "effect_digest": "c".repeat(64),
            "validation_revision": 1
        }))
        .expect("valid inert process binding")
    }

    fn terminal_evidence(tag: &str) -> ProcessEvidence {
        let binding = binding(tag);
        let view: ProcessExecutionView = serde_json::from_value(json!({
            "binding": binding,
            "lifecycle": "exited",
            "health": {
                "status": "unknown",
                "ready": false,
                "observed_at_unix_ms": 0,
                "detail": null
            },
            "cancellation": "not_requested",
            "identity": null,
            "exit": {
                "disposition": "completed",
                "code": 0,
                "signal": null,
                "observed_at_unix_ms": 99
            },
            "descendants": null
        }))
        .expect("terminal process view");
        ProcessEvidence::new_typed(view, None, None, EvidenceAxes::observed())
            .expect("valid terminal process evidence")
    }

    fn admitted_compile_stage() -> AdmittedStage {
        let registry = InstrumentRegistry::with_verification_route_profiles(7, Vec::new())
            .expect("builtin verification registry");
        let alias = crate::profile::PROFILE_ALIASES
            .iter()
            .find(|entry| entry.alias == PACKAGE_VERIFICATION_COMPILE_ONLY_ALIAS)
            .expect("closed compile-only profile alias");
        ProfileCompiler::new(&registry)
            .compile_exact(alias.profile, alias.revision)
            .expect("compile-only profile")
            .stages
            .into_iter()
            .find(|stage| stage.stage_id == "package-compile")
            .expect("admitted package compile stage")
    }

    #[test]
    fn terminal_stage_uses_original_kernel_view_and_reconciled_evidence() {
        let evidence = terminal_evidence("positive");
        let view = evidence.view().clone();
        let binding_sha256 = canonical_digest(evidence.binding()).expect("binding digest");
        let port = LifecyclePort::new(view.clone(), evidence.clone(), None, false);
        let (reconciled, terminal_at, observed_view, observed_at, _) = supervise(
            &port,
            "execution-positive",
            &binding_sha256,
            evidence.binding(),
            Instant::now() + Duration::from_secs(2),
        )
        .expect("same-binding terminal reconciliation");

        assert_eq!(observed_view, *reconciled.view());
        assert_eq!(observed_view, view);
        assert!(observed_at < terminal_at);
        assert_eq!(terminal_execution_status(&reconciled, true), ExecutionStatus::Succeeded);
        assert_eq!(
            evaluate_admitted_parser(
                &admitted_compile_stage(),
                b"{\"reason\":\"build-finished\",\"success\":true}\n",
                Some(0),
            ),
            VerificationOutcome::Pass
        );
    }

    #[test]
    fn supervisor_refuses_substituted_process_binding() {
        let evidence = terminal_evidence("expected");
        let substituted = terminal_evidence("substituted").view().clone();
        let binding_sha256 = canonical_digest(evidence.binding()).expect("binding digest");
        let port = LifecyclePort::new(
            evidence.view().clone(),
            evidence.clone(),
            Some(substituted),
            false,
        );

        let failure = supervise(
            &port,
            "execution-substituted",
            &binding_sha256,
            evidence.binding(),
            Instant::now() + Duration::from_secs(2),
        )
        .expect_err("substituted owner view is refused");
        assert!(failure.reason.contains("substituted the original process binding"));
        assert!(failure.last_view.is_none());
    }

    #[test]
    fn zero_exit_after_deadline_remains_unknown_and_empty_output_does_not_pass() {
        let evidence = terminal_evidence("late");
        let binding_sha256 = canonical_digest(evidence.binding()).expect("binding digest");
        let port = LifecyclePort::new(evidence.view().clone(), evidence.clone(), None, true);
        let (reconciled, _, _, _, _) = supervise(
            &port,
            "execution-late",
            &binding_sha256,
            evidence.binding(),
            Instant::now() - Duration::from_millis(1),
        )
        .expect("late result still reconciles as evidence");

        assert_eq!(terminal_execution_status(&reconciled, false), ExecutionStatus::Unknown);
        assert_eq!(
            evaluate_admitted_parser(&admitted_compile_stage(), b"", Some(0)),
            VerificationOutcome::Unknown
        );
        assert_eq!(
            evaluate_admitted_parser(
                &admitted_compile_stage(),
                b"{\"reason\":\"build-finished\",\"success\":true}\n",
                Some(7),
            ),
            VerificationOutcome::Fail
        );
    }

    fn canonical_document(value: serde_json::Value) -> (String, String) {
        let bytes = canonical_json_bytes(&value).expect("canonical owner projection");
        (String::from_utf8(bytes.clone()).expect("canonical JSON is UTF-8"), sha256_hex(&bytes))
    }

    fn owner_proof(source_sha256: &str, source_byte_length: u64) -> VerificationStageSourceOwnerProof {
        let epoch = EpochId::new(
            EpochLineageId::new("4f5b2d84-67b9-4c80-8f87-22b2390a6a44")
                .expect("canonical epoch lineage"),
            NonZeroU64::new(1).expect("nonzero epoch sequence"),
        )
        .expect("owner epoch");
        let fence = StateFence::new(epoch, ResourceGeneration::new(1).expect("generation"));
        let (owner_facts_json, owner_facts_sha256) = canonical_document(json!({"owner":"profile-stage"}));
        let (scope_binding_json, scope_binding_sha256) = canonical_document(json!({"scope":"test"}));
        let (policy_binding_json, policy_binding_sha256) = canonical_document(json!({"policy":"test"}));
        let (source_admission_json, source_admission_sha256) = canonical_document(json!({
            "state":"READY",
            "source_id":"source-positive",
            "sha256":source_sha256,
            "byte_length":source_byte_length
        }));
        let (source_admission_write_receipt_json, source_admission_write_receipt_sha256) =
            canonical_document(json!({"receipt":"write-positive"}));
        let (ready_receipt_json, ready_receipt_sha256) = canonical_document(json!({
            "locator":"blob:profile-stage-positive",
            "ready_receipt_ref":"ready-positive",
            "sha256":source_sha256,
            "byte_length":source_byte_length
        }));
        VerificationStageSourceOwnerProof {
            stage_grant_sha256: "a".repeat(64),
            source_key: VerificationStageSourceKey {
                execution_ref: "execution-positive".to_owned(),
                stream: ProcessStreamKind::Stdout,
                session_id: "session-positive".to_owned(),
                source_id: "source-positive".to_owned(),
                terminal_id: "terminal-positive".to_owned(),
                open_request_sha256: "b".repeat(64),
            },
            process_binding_sha256: "c".repeat(64),
            owner_facts_json,
            owner_facts_sha256,
            scope_binding_json,
            scope_binding_sha256,
            policy_binding_json,
            policy_binding_sha256,
            source_admission_json,
            source_admission_sha256,
            source_admission_write_receipt_json,
            source_admission_write_receipt_sha256,
            ready_receipt_json,
            ready_receipt_sha256,
            source_owner_generation: 8,
            observed_fence: fence,
            readback_receipt_id: "readback-positive".to_owned(),
            observed_at_unix_ms: 100,
        }
    }

    #[test]
    fn full_owner_readback_identity_requires_contiguous_nonempty_proof() {
        let bytes = b"full source";
        let source_sha256 = sha256_hex(bytes);
        let source = DurableProcessStreamSource::exact_transport(
            DurableStreamLocatorKind::Blob,
            "blob:profile-stage-positive",
            "ready-positive",
            source_sha256,
            u64::try_from(bytes.len()).expect("small source length"),
        )
        .expect("exact immutable source");
        let policy = ProcessStreamPolicyBinding::new(
            "policy-positive",
            "privacy-positive",
            "visibility-positive",
            "retention-positive",
            "redaction-positive",
        )
        .expect("stream policy binding");
        let proof = owner_proof(source.sha256(), source.byte_length());
        let proof_sha256 = proof.digest().expect("owner proof digest");
        let chunk = RetainedStreamReadbackChunkProof {
            offset: 0,
            byte_length: source.byte_length(),
            chunk_sha256: source.sha256().to_owned(),
            owner_proof: Box::new(proof.clone()),
            owner_proof_sha256: proof_sha256,
        };
        let binding = binding("readback");
        let process_binding_sha256 = canonical_digest(&binding).expect("binding digest");
        let evidence_digest = "d".repeat(64);

        let identity = RetainedProcessStreamIdentity::from_verified_chunks(
            ProcessStreamKind::Stdout,
            binding.clone(),
            source.clone(),
            policy.clone(),
            evidence_digest.clone(),
            process_binding_sha256.clone(),
            vec![chunk.clone()],
        )
        .expect("complete owner-readback identity");
        assert!(identity.is_complete_owner_readback());
        assert_eq!(identity.chunks().len(), 1);

        assert!(RetainedProcessStreamIdentity::from_verified_chunks(
            ProcessStreamKind::Stdout,
            binding.clone(),
            source.clone(),
            policy.clone(),
            evidence_digest.clone(),
            process_binding_sha256.clone(),
            Vec::new(),
        )
        .is_err());

        let mut gap = chunk;
        gap.offset = 1;
        assert!(RetainedProcessStreamIdentity::from_verified_chunks(
            ProcessStreamKind::Stdout,
            binding,
            source,
            policy,
            evidence_digest,
            process_binding_sha256,
            vec![gap],
        )
        .is_err());
    }

    #[test]
    fn missing_or_unverified_prerequisite_blocks_dependent_stage() {
        let registry = InstrumentRegistry::with_verification_route_profiles(7, Vec::new())
            .expect("builtin verification registry");
        let alias = crate::profile::PROFILE_ALIASES
            .iter()
            .find(|entry| entry.alias == PACKAGE_VERIFICATION_COMPILE_ONLY_ALIAS)
            .expect("closed compile-only profile alias");
        let admitted = ProfileCompiler::new(&registry)
            .compile_exact(alias.profile, alias.revision)
            .expect("compile-only profile");
        let plan = StageOrchestrator::plan(&admitted);
        let prerequisite = &plan.stages[0];
        let missing = InstrumentRun::missing(&prerequisite.route, "no verified terminal proof");

        assert!(!dependency_has_verified_success(
            &prerequisite.stage.stage_id,
            &BTreeSet::new(),
            std::slice::from_ref(&missing),
        ));
        assert!(!dependency_has_verified_success(
            &prerequisite.stage.stage_id,
            &BTreeSet::from([prerequisite.stage.stage_id.clone()]),
            &[],
        ));
    }
}
