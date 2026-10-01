use crate::{
    EngineError, WriteAdmissionService, WriterHandle, codecortex_report_ref,
    context::CompletionGate, guard_work_lease_for_files, work::WorkLeaseGuardError,
};
use eliot_instrument_api::InstrumentKind;
use eliot_instrument_runner::profile::{AdmittedProfile, InstrumentRegistry, ProfileCompiler};
use eliot_instrument_runner::{BuildProjectionError, CargoOrigin, restrict_agent_argv};
use eliot_store::BlobStore;
use eliot_types::{
    ActionLease, ActionScope, CodeCortexReport, CommandContext, CompletionGateDecision,
    CompletionProof, CompletionStatus, LeaseDecision, LeaseStatus, LifecycleStatus, PatchRequest,
    PatchRun, PatchRunId, PatchRunStatus, SemanticCommand, TaintClass,
    ToolObservationRecordCommand, VerifierCommandKind, VerifierPlan, VerifierRequirement,
    VerifierRun, VerifierRunId, VerifierRunRef, VerifierStatus, Visibility, WorkLease, WriteId,
    WriteReceiptRef,
};
use std::collections::BTreeSet;
use std::path::{Component, Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration as StdDuration, Instant};
use time::OffsetDateTime;
use tokio::process::Command;

const DEFAULT_TIMEOUT_SECONDS: u64 = 60;
const MAX_OUTPUT_SUMMARY_BYTES: usize = 512;
/// Acceptance-eligibility quarantine carried by every verifier run executed
/// through the legacy command lane (issue #1813 W6, issue #1852 W3): the run
/// executed the quarantined private command map, so no governed profile
/// revision, stage graph, or receipt may rest on it, and the run itself is
/// acceptance-ineligible no matter its status. Every eligibility predicate
/// (`required_verifiers_passed`, the finish gate) reads this marker.
const QUARANTINED_LEGACY_LANE: &str =
    "[quarantined legacy verifier lane: no governed profile receipt; issue #1813 W6]";

pub struct PatchRunner<'a> {
    repo_root: PathBuf,
    blob_store: Option<&'a BlobStore>,
}

pub struct VerifierHarness<'a> {
    repo_root: PathBuf,
    blob_store: Option<&'a BlobStore>,
    timeout_seconds: u64,
}

pub struct PatchRunnerInput<'a> {
    pub request: &'a PatchRequest,
    pub lease: Option<&'a ActionLease>,
    pub work_lease: Option<&'a WorkLease>,
    pub codecortex_reports: &'a [CodeCortexReport],
    pub verifier_plan: Option<&'a VerifierPlan>,
    pub incident_lockdown_active: bool,
}

struct ValidatedPatch {
    scope: ActionScope,
    changed_files: Vec<String>,
    git_head_before: Option<String>,
}

struct BoundedCommandOutput {
    success: bool,
    timed_out: bool,
    exit_code: Option<i32>,
    duration_ms: u64,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    stdout_blob: Option<eliot_types::BlobRef>,
    stderr_blob: Option<eliot_types::BlobRef>,
}

pub struct PatchMemoryWriter;

impl<'a> PatchRunner<'a> {
    pub fn new(repo_root: impl Into<PathBuf>, blob_store: Option<&'a BlobStore>) -> Self {
        Self {
            repo_root: repo_root.into(),
            blob_store,
        }
    }

    pub async fn preflight(&self, input: &PatchRunnerInput<'_>) -> Result<PatchRun, EngineError> {
        let started_at = OffsetDateTime::now_utc();
        let validation = match self.validate(input).await? {
            Ok(validation) => validation,
            Err(reasons) => {
                return Ok(self.patch_run(
                    input.request,
                    PatchRunStatus::Denied,
                    Vec::new(),
                    None,
                    Vec::new(),
                    reasons,
                    CommandBlobs::default(),
                    None,
                    started_at,
                ));
            }
        };

        let diff_path = write_temp_diff(&input.request.diff.text)?;
        let check = run_bounded_command(
            "git",
            &git_apply_args(&self.repo_root, true, false, &diff_path),
            &self.repo_root,
            timeout_seconds(&validation.scope),
            self.blob_store,
        )
        .await;
        let _ = std::fs::remove_file(&diff_path);
        let output = check?;
        if !output.success {
            let mut reasons = vec!["git_apply_check_failed".to_owned()];
            append_command_summary(&mut reasons, &output);
            return Ok(self.patch_run(
                input.request,
                PatchRunStatus::Denied,
                validation.changed_files,
                validation.git_head_before,
                Vec::new(),
                reasons,
                CommandBlobs::from(&output),
                None,
                started_at,
            ));
        }

        Ok(self.patch_run(
            input.request,
            PatchRunStatus::PreflightPassed,
            validation.changed_files,
            validation.git_head_before,
            Vec::new(),
            Vec::new(),
            CommandBlobs::from(&output),
            None,
            started_at,
        ))
    }

    #[allow(clippy::too_many_lines)]
    pub async fn apply(
        &self,
        input: &PatchRunnerInput<'_>,
        verifier: &VerifierHarness<'_>,
    ) -> Result<(PatchRun, Vec<VerifierRun>), EngineError> {
        let started_at = OffsetDateTime::now_utc();
        let validation = match self.validate(input).await? {
            Ok(validation) => validation,
            Err(reasons) => {
                return Ok((
                    self.patch_run(
                        input.request,
                        PatchRunStatus::Denied,
                        Vec::new(),
                        None,
                        Vec::new(),
                        reasons,
                        CommandBlobs::default(),
                        None,
                        started_at,
                    ),
                    Vec::new(),
                ));
            }
        };

        let diff_path = write_temp_diff(&input.request.diff.text)?;
        let check_output = run_bounded_command(
            "git",
            &git_apply_args(&self.repo_root, true, false, &diff_path),
            &self.repo_root,
            timeout_seconds(&validation.scope),
            self.blob_store,
        )
        .await?;
        if !check_output.success {
            let _ = std::fs::remove_file(&diff_path);
            let mut reasons = vec!["git_apply_check_failed".to_owned()];
            append_command_summary(&mut reasons, &check_output);
            return Ok((
                self.patch_run(
                    input.request,
                    PatchRunStatus::Denied,
                    validation.changed_files,
                    validation.git_head_before,
                    Vec::new(),
                    reasons,
                    CommandBlobs::from(&check_output),
                    None,
                    started_at,
                ),
                Vec::new(),
            ));
        }

        let apply_output = run_bounded_command(
            "git",
            &git_apply_args(&self.repo_root, false, false, &diff_path),
            &self.repo_root,
            timeout_seconds(&validation.scope),
            self.blob_store,
        )
        .await?;
        if !apply_output.success {
            let _ = std::fs::remove_file(&diff_path);
            let mut reasons = vec!["git_apply_failed".to_owned()];
            append_command_summary(&mut reasons, &apply_output);
            return Ok((
                self.patch_run(
                    input.request,
                    PatchRunStatus::Denied,
                    validation.changed_files,
                    validation.git_head_before,
                    Vec::new(),
                    reasons,
                    CommandBlobs::from(&apply_output),
                    None,
                    started_at,
                ),
                Vec::new(),
            ));
        }

        let Some(plan) = input.verifier_plan else {
            return Ok((
                self.patch_run(
                    input.request,
                    PatchRunStatus::Denied,
                    validation.changed_files,
                    validation.git_head_before,
                    Vec::new(),
                    vec!["missing_verifier_plan".to_owned()],
                    CommandBlobs::from(&apply_output),
                    None,
                    started_at,
                ),
                Vec::new(),
            ));
        };
        let verifier_runs = verifier
            .run_plan(
                input.request.project_id,
                input.request.task_id,
                input.request.agent_id,
                plan,
            )
            .await?;
        let verifier_refs = verifier_runs
            .iter()
            .map(verifier_run_ref)
            .collect::<Vec<_>>();
        if required_verifiers_passed(&verifier_runs) {
            let _ = std::fs::remove_file(&diff_path);
            let git_head_after = git_head(&self.repo_root).await?;
            return Ok((
                self.patch_run(
                    input.request,
                    PatchRunStatus::AppliedVerifierPassed,
                    validation.changed_files,
                    validation.git_head_before,
                    verifier_refs,
                    Vec::new(),
                    CommandBlobs::from(&apply_output),
                    git_head_after,
                    started_at,
                ),
                verifier_runs,
            ));
        }

        let rollback_output = run_bounded_command(
            "git",
            &git_apply_args(&self.repo_root, false, true, &diff_path),
            &self.repo_root,
            timeout_seconds(&validation.scope),
            self.blob_store,
        )
        .await?;
        let _ = std::fs::remove_file(&diff_path);
        let mut reasons = vec!["required_verifier_failed".to_owned()];
        append_failed_verifiers(&mut reasons, &verifier_runs);
        if rollback_output.success {
            let mut rollback_blobs = CommandBlobs::from(&rollback_output);
            rollback_blobs.rollback_ref = Some(format!(
                "git_apply_reverse:{}",
                input.request.patch_request_id
            ));
            Ok((
                self.patch_run(
                    input.request,
                    PatchRunStatus::RolledBack,
                    validation.changed_files,
                    validation.git_head_before,
                    verifier_refs,
                    reasons,
                    rollback_blobs,
                    None,
                    started_at,
                ),
                verifier_runs,
            ))
        } else {
            append_command_summary(&mut reasons, &rollback_output);
            Ok((
                self.patch_run(
                    input.request,
                    PatchRunStatus::RollbackFailed,
                    validation.changed_files,
                    validation.git_head_before,
                    verifier_refs,
                    reasons,
                    CommandBlobs::from(&rollback_output),
                    None,
                    started_at,
                ),
                verifier_runs,
            ))
        }
    }

    async fn validate(
        &self,
        input: &PatchRunnerInput<'_>,
    ) -> Result<Result<ValidatedPatch, Vec<String>>, EngineError> {
        let mut reasons = Vec::new();
        if input.incident_lockdown_active {
            reasons.push("incident_lockdown_active".to_owned());
        }
        let Some(lease) = input.lease else {
            return Ok(Err(vec!["missing_action_lease".to_owned()]));
        };
        validate_lease(input.request, lease, &mut reasons);
        let scope = lease.allowed_scope.clone();
        let Some(scope) = scope else {
            reasons.push("missing_action_scope".to_owned());
            return Ok(Err(reasons));
        };
        validate_repo_root(&self.repo_root, &scope, &mut reasons);
        validate_verifier_plan(input.verifier_plan, &mut reasons);
        validate_diff_bounds(input.request, &scope, &mut reasons);
        validate_report_refs(input.request, input.codecortex_reports, &mut reasons);

        let changed_files = match parse_changed_files(&input.request.diff.text) {
            Ok(files) => files,
            Err(reason) => {
                reasons.push(reason);
                Vec::new()
            }
        };
        validate_changed_files(
            &changed_files,
            &scope,
            input.codecortex_reports,
            &mut reasons,
        );
        validate_work_lease(
            input.request,
            input.work_lease,
            &changed_files,
            &mut reasons,
        );

        let current_head = git_head(&self.repo_root).await?;
        validate_git_head(input.request, &scope, current_head.as_deref(), &mut reasons);
        for file in &changed_files {
            if target_file_dirty(&self.repo_root, file).await? {
                reasons.push(format!("dirty_target_file:{file}"));
            }
        }

        if reasons.is_empty() {
            Ok(Ok(ValidatedPatch {
                scope,
                changed_files,
                git_head_before: current_head,
            }))
        } else {
            Ok(Err(reasons))
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn patch_run(
        &self,
        request: &PatchRequest,
        status: PatchRunStatus,
        changed_files: Vec<String>,
        git_head_before: Option<String>,
        verifier_runs: Vec<VerifierRunRef>,
        failure_reasons: Vec<String>,
        command_blobs: CommandBlobs,
        git_head_after: Option<String>,
        started_at: OffsetDateTime,
    ) -> PatchRun {
        PatchRun {
            patch_run_id: PatchRunId::new_v7(),
            patch_request_id: request.patch_request_id,
            action_lease_id: request.action_lease_id,
            project_id: request.project_id,
            task_id: request.task_id,
            agent_id: request.agent_id,
            status,
            repo_root: self.repo_root.display().to_string(),
            git_head_before,
            git_head_after,
            changed_files,
            verifier_runs,
            failure_reasons,
            stdout_blob: command_blobs.stdout_blob,
            stderr_blob: command_blobs.stderr_blob,
            rollback_ref: command_blobs.rollback_ref,
            write_receipt: None,
            started_at,
            finished_at: OffsetDateTime::now_utc(),
        }
    }
}

impl<'a> VerifierHarness<'a> {
    pub fn new(repo_root: impl Into<PathBuf>, blob_store: Option<&'a BlobStore>) -> Self {
        Self {
            repo_root: repo_root.into(),
            blob_store,
            timeout_seconds: DEFAULT_TIMEOUT_SECONDS,
        }
    }

    #[must_use]
    pub fn with_timeout_seconds(mut self, timeout_seconds: u64) -> Self {
        self.timeout_seconds = timeout_seconds.max(1);
        self
    }

    pub async fn run_plan(
        &self,
        project_id: eliot_types::ProjectId,
        task_id: eliot_types::TaskId,
        agent_id: eliot_types::AgentId,
        plan: &VerifierPlan,
    ) -> Result<Vec<VerifierRun>, EngineError> {
        // Route every requirement through the single profile compiler (#1813
        // W6): a requirement that claims a governed instrument name must
        // execute its admitted stage DAG, which this composition root cannot
        // provision yet, so it fails closed with an explicit missing proof
        // instead of executing the quarantined command map under a governed
        // name. Quarantined legacy names keep their observable execution with
        // no governed claim, and every such run is visibly attributed as
        // quarantined in its summary and acceptance-ineligible in every
        // eligibility predicate (issue #1852 W3).
        let instrument_registry =
            InstrumentRegistry::with_builtin_profiles(1).map_err(|error| {
                EngineError::ServiceNotReady {
                    service: "instrument-profile".to_owned(),
                    reason: format!("builtin profile registry is unavailable: {error}"),
                }
            })?;
        let mut runs = Vec::new();
        for requirement in plan.required.iter().chain(plan.optional.iter()) {
            let gate = gate_requirement_profile(
                &instrument_registry,
                &requirement.name,
                requirement.command_kind,
            )?;
            runs.push(
                self.run_requirement(project_id, task_id, agent_id, requirement, gate)
                    .await?,
            );
        }
        Ok(runs)
    }

    async fn run_requirement(
        &self,
        project_id: eliot_types::ProjectId,
        task_id: eliot_types::TaskId,
        agent_id: eliot_types::AgentId,
        requirement: &VerifierRequirement,
        gate: Option<AdmittedProfile>,
    ) -> Result<VerifierRun, EngineError> {
        let started_at = OffsetDateTime::now_utc();
        if let Some(admitted) = gate {
            // A governed name is never executed through the quarantined
            // command map: that would forge a governed claim over legacy
            // execution. Stage-DAG execution awaits the W4 execution lane,
            // so the failure localizes here with an explicit missing proof
            // (I10.8.11) and can never become a pass.
            return Ok(verifier_run(
                project_id,
                task_id,
                agent_id,
                requirement,
                VerifierStatus::Failed,
                None,
                0,
                None,
                None,
                format!(
                    "governed profile '{}' revision {} requires stage-DAG execution; \
                     this composition root has no stage execution provisions \
                     (issue #1813 W4), so the requirement fails closed",
                    admitted.name, admitted.revision,
                ),
                started_at,
            ));
        }
        let Some(command) = fixed_verifier_command(requirement.command_kind) else {
            return Ok(verifier_run(
                project_id,
                task_id,
                agent_id,
                requirement,
                VerifierStatus::NotAllowed,
                None,
                0,
                None,
                None,
                "verifier command kind is not allowed in E2".to_owned(),
                started_at,
            ));
        };
        let admitted = match admitted_agent_cargo_argv(&command) {
            Ok(admitted) => admitted,
            Err(refusal) => {
                // I18.26 line 3: an unrestricted agent Cargo selection is
                // refused here, before any process exists. The verifier run
                // records the exact typed refusal and is never `Passed`, so a
                // refused build cannot admit the patch either.
                return Ok(verifier_run(
                    project_id,
                    task_id,
                    agent_id,
                    requirement,
                    VerifierStatus::NotAllowed,
                    None,
                    0,
                    None,
                    None,
                    format!("{QUARANTINED_LEGACY_LANE} {refusal}"),
                    started_at,
                ));
            }
        };
        let output = run_bounded_command(
            &admitted[0],
            &admitted[1..],
            &self.repo_root,
            self.timeout_seconds,
            self.blob_store,
        )
        .await?;
        let status = if output.timed_out {
            VerifierStatus::TimedOut
        } else if output.success {
            VerifierStatus::Passed
        } else {
            VerifierStatus::Failed
        };
        let summary = format!("{QUARANTINED_LEGACY_LANE} {}", command_summary(&output));
        // The quarantine marker above is the acceptance-eligibility signal,
        // not display text: eligibility predicates reject quarantined runs
        // even when the legacy command itself exited 0 (issue #1852 W3).
        Ok(verifier_run(
            project_id,
            task_id,
            agent_id,
            requirement,
            status,
            output.exit_code,
            output.duration_ms,
            output.stdout_blob,
            output.stderr_blob,
            summary,
            started_at,
        ))
    }
}

impl PatchMemoryWriter {
    pub async fn write_patch_run(
        writer: &WriterHandle,
        admission: &WriteAdmissionService,
        patch_run: &mut PatchRun,
    ) -> Result<(), EngineError> {
        let command = SemanticCommand::ToolObservationRecord(ToolObservationRecordCommand {
            context: e2_context(
                patch_run.project_id,
                patch_run.agent_id,
                patch_run.task_id,
                "patch-run",
            ),
            tool_name: "eliot_patch_runner".to_owned(),
            observation: format!(
                "PatchRun {} status {:?}",
                patch_run.patch_run_id, patch_run.status
            ),
            payload: serde_json::json!({ "patch_run": patch_run }),
        });
        let receipt = writer.submit(admission.admit(&command)?).await?;
        patch_run.write_receipt = Some(write_receipt_ref(&receipt));
        Ok(())
    }

    pub async fn write_verifier_run(
        writer: &WriterHandle,
        admission: &WriteAdmissionService,
        verifier_run: &mut VerifierRun,
    ) -> Result<(), EngineError> {
        let command = SemanticCommand::ToolObservationRecord(ToolObservationRecordCommand {
            context: e2_context(
                verifier_run.project_id,
                verifier_run.agent_id,
                verifier_run.task_id,
                "verifier-run",
            ),
            tool_name: "eliot_verifier_harness".to_owned(),
            observation: format!(
                "VerifierRun {} {} status {:?}",
                verifier_run.verifier_run_id, verifier_run.name, verifier_run.status
            ),
            payload: serde_json::json!({ "verifier_run": verifier_run }),
        });
        let receipt = writer.submit(admission.admit(&command)?).await?;
        verifier_run.write_receipt = Some(write_receipt_ref(&receipt));
        Ok(())
    }
}

impl CompletionGate {
    pub fn decide_with_patch_context(
        proof: &CompletionProof,
        patch_run: Option<&PatchRun>,
        verifier_runs: &[VerifierRun],
    ) -> CompletionGateDecision {
        let base = Self::decide(proof);
        let mut reasons = base.reasons;
        let Some(patch_run) = patch_run else {
            reasons.push("missing_patch_run".to_owned());
            return completion_decision(proof, CompletionStatus::PartialProgress, reasons);
        };
        if patch_run.status == PatchRunStatus::RollbackFailed {
            reasons.push("patch_rollback_failed".to_owned());
            return completion_decision(proof, CompletionStatus::UnsafeToFinish, reasons);
        }
        if patch_run.status != PatchRunStatus::AppliedVerifierPassed {
            reasons.push(format!("patch_not_verified:{:?}", patch_run.status));
        }
        if patch_run.write_receipt.is_none() {
            reasons.push("patch_run_missing_canonical_receipt".to_owned());
        }
        if proof.project_id != patch_run.project_id
            || proof.task_id != patch_run.task_id.to_string()
        {
            reasons.push("completion_proof_patch_scope_mismatch".to_owned());
        }
        if proof.changed_files.iter().any(|file| {
            !patch_run
                .changed_files
                .iter()
                .any(|changed| normalize_path(changed) == normalize_path(file))
        }) {
            reasons.push("proof_file_not_in_patch_run".to_owned());
        }
        // A caller-supplied run is usable only when the patch execution itself
        // names that exact run, name, and status. Otherwise an unrelated
        // passing VerifierRun could be paired with an applied PatchRun to
        // manufacture completion evidence.
        let canonical_runs = canonical_verifier_runs(patch_run, verifier_runs, &mut reasons);
        let required_verifier_runs = canonical_runs
            .iter()
            .copied()
            .filter(|run| run.required_for_done)
            .collect::<Vec<_>>();
        if required_verifier_runs.is_empty() {
            reasons.push("missing_required_verifier_run".to_owned());
        } else if required_verifier_runs.iter().copied().any(|run| {
            run.status != VerifierStatus::Passed || is_quarantined_legacy_run(run)
        }) {
            reasons.push("required_verifier_failed".to_owned());
            return completion_decision(proof, CompletionStatus::FailedVerifier, reasons);
        }
        if required_verifier_runs.iter().copied().any(|run| {
            run.project_id != patch_run.project_id
                || run.task_id != patch_run.task_id
                || run.agent_id != patch_run.agent_id
                || run.write_receipt.is_none()
        }) {
            reasons.push("required_verifier_missing_canonical_scope_or_receipt".to_owned());
        }
        // The finish binding only trusts required runs whose claimed profile
        // name survives the single profile compiler (#1813): a governed name
        // with a foreign or unmappable command class can never satisfy
        // DONE_VERIFIED.
        match InstrumentRegistry::with_builtin_profiles(1) {
            Ok(instrument_registry) => {
                for run in canonical_runs
                    .iter()
                    .copied()
                    .filter(|run| run.required_for_done)
                {
                    if gate_requirement_profile(&instrument_registry, &run.name, run.command_kind)
                        .is_err()
                    {
                        reasons.push(format!("required_verifier_profile_mismatch:{}", run.name));
                    }
                }
            }
            Err(_) => reasons.push("instrument_profile_registry_unavailable".to_owned()),
        }
        // Quarantined legacy-lane runs can never satisfy DONE_VERIFIED
        // (issue #1852 W3): the private command map is not an accepted
        // verification source even when the legacy command itself exited 0.
        for run in canonical_runs
            .iter()
            .copied()
            .filter(|run| run.required_for_done)
        {
            if is_quarantined_legacy_run(run) {
                reasons.push(format!("quarantined_legacy_verifier:{}", run.name));
            }
        }
        if !proof
            .evidence
            .iter()
            .any(|evidence| evidence.contains(&patch_run.patch_run_id.to_string()))
        {
            reasons.push("completion_proof_missing_patch_run_ref".to_owned());
        }
        for run in canonical_runs
            .iter()
            .copied()
            .filter(|run| run.required_for_done)
        {
            if !proof
                .evidence
                .iter()
                .any(|evidence| evidence.contains(&run.verifier_run_id.to_string()))
            {
                reasons.push(format!(
                    "completion_proof_missing_verifier_run_ref:{}",
                    run.name
                ));
            }
        }
        if reasons.is_empty() {
            completion_decision(proof, CompletionStatus::DoneVerified, reasons)
        } else {
            completion_decision(proof, CompletionStatus::PartialProgress, reasons)
        }
    }
}

#[derive(Default)]
struct CommandBlobs {
    stdout_blob: Option<eliot_types::BlobRef>,
    stderr_blob: Option<eliot_types::BlobRef>,
    rollback_ref: Option<String>,
}

impl From<&BoundedCommandOutput> for CommandBlobs {
    fn from(output: &BoundedCommandOutput) -> Self {
        Self {
            stdout_blob: output.stdout_blob.clone(),
            stderr_blob: output.stderr_blob.clone(),
            rollback_ref: None,
        }
    }
}

struct FixedCommand {
    program: &'static str,
    args: Vec<&'static str>,
}

/// Maps a harness command class to its instrument class, if it has one.
///
/// Audit, deny, domain-verifier, and manual-review requirements execute no
/// governed instrument, so they can never claim a governed profile name.
fn instrument_kind_for_command(kind: VerifierCommandKind) -> Option<InstrumentKind> {
    match kind {
        VerifierCommandKind::CargoCheck | VerifierCommandKind::CargoClippy => {
            Some(InstrumentKind::Build)
        }
        VerifierCommandKind::CargoTest | VerifierCommandKind::CargoNextest => {
            Some(InstrumentKind::Test)
        }
        VerifierCommandKind::CargoFmtCheck => Some(InstrumentKind::Format),
        VerifierCommandKind::CargoAudit
        | VerifierCommandKind::CargoDeny
        | VerifierCommandKind::DomainVerifier
        | VerifierCommandKind::ManualReview => None,
    }
}

/// Gates one claimed profile name through the single profile compiler.
///
/// Quarantined legacy names pass through with no governed claim (`None`).
/// Governed names require a mappable command class admitted by the profile
/// and return the admission (`Some`), so the caller executes the admitted
/// stage DAG instead of the quarantined command map; anything else fails
/// closed so a forged governed claim can never execute or satisfy a finish
/// gate. The admitted revision is resolved once and pinned: the exact
/// revision recompiles to identical definition digests, so a registry update
/// cannot silently replace the definition under a live gate decision and
/// every consumer of this gate shares one resolution identity.
fn gate_requirement_profile(
    registry: &InstrumentRegistry,
    name: &str,
    command_kind: VerifierCommandKind,
) -> Result<Option<AdmittedProfile>, EngineError> {
    let compiled = ProfileCompiler::new(registry).compile(name);
    if !compiled.is_governed() {
        return Ok(None);
    }
    let Some(kind) = instrument_kind_for_command(command_kind) else {
        return Err(EngineError::ServiceNotReady {
            service: "instrument-profile".to_owned(),
            reason: format!(
                "governed profile '{name}' cannot be claimed by a requirement with no governed instrument class"
            ),
        });
    };
    let Some(admitted) =
        compiled
            .require_kind(kind)
            .map_err(|error| EngineError::ServiceNotReady {
                service: "instrument-profile".to_owned(),
                reason: format!("profile compiler rejected the verifier claim: {error}"),
            })?
    else {
        return Ok(None);
    };
    let pinned = ProfileCompiler::new(registry)
        .compile_exact(name, admitted.revision)
        .map_err(|error| EngineError::ServiceNotReady {
            service: "instrument-profile".to_owned(),
            reason: format!("profile compiler refused the pinned revision: {error}"),
        })?;
    if pinned.profile_digest != admitted.profile_digest || pinned.dag_digest != admitted.dag_digest
    {
        return Err(EngineError::ServiceNotReady {
            service: "instrument-profile".to_owned(),
            reason: format!(
                "governed profile '{name}' revision {} changed during gating; refusing instead of executing a replaced definition",
                admitted.revision
            ),
        });
    }
    Ok(Some(admitted.clone()))
}

fn fixed_verifier_command(kind: VerifierCommandKind) -> Option<FixedCommand> {
    let command = match kind {
        VerifierCommandKind::CargoFmtCheck => FixedCommand {
            program: "cargo",
            args: vec!["fmt", "--check"],
        },
        VerifierCommandKind::CargoCheck => FixedCommand {
            program: "cargo",
            args: vec!["check"],
        },
        VerifierCommandKind::CargoClippy => FixedCommand {
            program: "cargo",
            args: vec!["clippy", "--all-targets", "--", "-D", "warnings"],
        },
        VerifierCommandKind::CargoTest => FixedCommand {
            program: "cargo",
            args: vec!["test"],
        },
        VerifierCommandKind::CargoNextest => FixedCommand {
            program: "cargo",
            args: vec!["nextest", "run"],
        },
        VerifierCommandKind::CargoAudit => FixedCommand {
            program: "cargo",
            args: vec!["audit"],
        },
        VerifierCommandKind::CargoDeny => FixedCommand {
            program: "cargo",
            args: vec!["deny", "check"],
        },
        VerifierCommandKind::DomainVerifier | VerifierCommandKind::ManualReview => return None,
    };
    Some(command)
}

/// Admits one agent-originated Cargo argv through the one
/// InstrumentRunner-controlled build projection (issue #1902).
///
/// I18.26 line 3 reads: "Parallel agents use Cargo package selection and one
/// InstrumentRunner-controlled build projection. They do not independently
/// launch unrestricted `cargo --workspace` commands." This is the shared
/// admission point for the verifier lanes that launch Cargo on agent work:
/// the patch verifier lane below and the registered cargo verifier lane in
/// `eliot-app`. Every caller launches only the returned argv, so the
/// projection cannot be stepped over by calling a launcher directly. A refusal
/// is a typed [`BuildProjectionError`] and the caller launches nothing on that
/// path.
///
/// The argv is presented as [`CargoOrigin::Agent`] because it is
/// agent-originated. The projected origin additionally requires the argv to
/// equal the argv of a live [`ProjectedBuild`](eliot_instrument_runner::ProjectedBuild),
/// and neither verifier lane owns an admitted work-item declaration to present
/// one — no [`DeclaredWorkItem`](eliot_instrument_runner::DeclaredWorkItem)
/// producer, no admitted [`GovernedWorkEnvelope`](eliot_instrument_runner::GovernedWorkEnvelope),
/// and no [`BuildTestGraph`](eliot_build_test_graph::BuildTestGraph) source
/// exists at either seam — so claiming that origin here would be an unbacked
/// assertion rather than an admission.
///
/// # Errors
///
/// Returns the projection's typed refusal ([`BuildProjectionError::NotCargo`]
/// when the argv does not name the cargo tool,
/// [`BuildProjectionError::CargoScope`] when it requests `--workspace` or
/// `--all`).
pub fn admit_agent_cargo_argv(argv: &[String]) -> Result<Vec<String>, BuildProjectionError> {
    restrict_agent_argv(argv, CargoOrigin::Agent)
}

/// Admits the real agent Cargo argv of one verifier requirement through the one
/// InstrumentRunner-controlled build projection (issue #1902).
///
/// This function is the agent verifier lane's only Cargo admission point, and
/// the argv it returns is the only argv [`VerifierHarness::run_requirement`]
/// launches. Admission itself is [`admit_agent_cargo_argv`], shared with the
/// registered cargo verifier lane so both lanes refuse the same selections.
fn admitted_agent_cargo_argv(command: &FixedCommand) -> Result<Vec<String>, BuildProjectionError> {
    let mut argv = Vec::with_capacity(command.args.len() + 1);
    argv.push(command.program.to_owned());
    argv.extend(command.args.iter().map(|arg| (*arg).to_owned()));
    admit_agent_cargo_argv(&argv)
}

#[allow(clippy::too_many_arguments)]
fn verifier_run(
    project_id: eliot_types::ProjectId,
    task_id: eliot_types::TaskId,
    agent_id: eliot_types::AgentId,
    requirement: &VerifierRequirement,
    status: VerifierStatus,
    exit_code: Option<i32>,
    duration_ms: u64,
    stdout_blob: Option<eliot_types::BlobRef>,
    stderr_blob: Option<eliot_types::BlobRef>,
    summary: String,
    started_at: OffsetDateTime,
) -> VerifierRun {
    VerifierRun {
        verifier_run_id: VerifierRunId::new_v7(),
        project_id,
        task_id,
        agent_id,
        name: requirement.name.clone(),
        command_kind: requirement.command_kind,
        command_display: fixed_command_display(requirement.command_kind)
            .unwrap_or("not allowed")
            .to_owned(),
        status,
        exit_code,
        duration_ms,
        stdout_blob,
        stderr_blob,
        summary,
        required_for_done: requirement.required_for_done,
        write_receipt: None,
        started_at,
        finished_at: OffsetDateTime::now_utc(),
    }
}

fn fixed_command_display(kind: VerifierCommandKind) -> Option<&'static str> {
    match kind {
        VerifierCommandKind::CargoFmtCheck => Some("cargo fmt --check"),
        VerifierCommandKind::CargoCheck => Some("cargo check"),
        VerifierCommandKind::CargoClippy => Some("cargo clippy --all-targets -- -D warnings"),
        VerifierCommandKind::CargoTest => Some("cargo test"),
        VerifierCommandKind::CargoNextest => Some("cargo nextest run"),
        VerifierCommandKind::CargoAudit => Some("cargo audit"),
        VerifierCommandKind::CargoDeny => Some("cargo deny check"),
        VerifierCommandKind::DomainVerifier | VerifierCommandKind::ManualReview => None,
    }
}

fn validate_lease(request: &PatchRequest, lease: &ActionLease, reasons: &mut Vec<String>) {
    if lease.lease_id != request.action_lease_id {
        reasons.push("lease_id_mismatch".to_owned());
    }
    if lease.project_id != request.project_id || lease.task_id != request.task_id {
        reasons.push("lease_scope_identity_mismatch".to_owned());
    }
    if lease.decision != LeaseDecision::AllowPatchExecution
        || lease.status != LeaseStatus::ApprovedForExecution
    {
        reasons.push("lease_not_approved_for_patch_execution".to_owned());
    }
    if lease
        .expires_at
        .is_some_and(|expires_at| expires_at < OffsetDateTime::now_utc())
    {
        reasons.push("lease_expired".to_owned());
    }
}

fn validate_work_lease(
    request: &PatchRequest,
    work_lease: Option<&WorkLease>,
    changed_files: &[String],
    reasons: &mut Vec<String>,
) {
    match guard_work_lease_for_files(
        work_lease,
        request.project_id,
        request.task_id,
        request.agent_id,
        changed_files,
    ) {
        Ok(()) => {}
        Err(WorkLeaseGuardError::Missing) => reasons.push("missing_work_lease".to_owned()),
        Err(WorkLeaseGuardError::Inactive) => reasons.push("work_lease_inactive".to_owned()),
        Err(WorkLeaseGuardError::Mismatch) => reasons.push("work_lease_mismatch".to_owned()),
        Err(WorkLeaseGuardError::FileOutsideScope) => {
            reasons.push("file_outside_work_lease".to_owned());
        }
    }
}

fn validate_repo_root(repo_root: &Path, scope: &ActionScope, reasons: &mut Vec<String>) {
    if !same_canonical_path(repo_root, Path::new(&scope.repo_root)) {
        reasons.push("repo_root_outside_action_scope".to_owned());
    }
}

fn validate_verifier_plan(plan: Option<&VerifierPlan>, reasons: &mut Vec<String>) {
    if plan.is_none_or(|plan| plan.required.is_empty()) {
        reasons.push("missing_verifier_plan".to_owned());
    }
}

fn validate_report_refs(
    request: &PatchRequest,
    reports: &[CodeCortexReport],
    reasons: &mut Vec<String>,
) {
    if request.codecortex_report_refs.is_empty() || reports.is_empty() {
        reasons.push("missing_codecortex_report".to_owned());
        return;
    }
    if !reports.iter().any(|report| {
        let reference = codecortex_report_ref(report);
        request
            .codecortex_report_refs
            .iter()
            .any(|candidate| candidate == &reference)
    }) {
        reasons.push("stale_codecortex_report_ref".to_owned());
    }
}

fn validate_diff_bounds(request: &PatchRequest, scope: &ActionScope, reasons: &mut Vec<String>) {
    let actual_len = request.diff.text.len();
    if actual_len != request.diff.byte_len {
        reasons.push("diff_byte_len_mismatch".to_owned());
    }
    if actual_len > scope.max_diff_bytes {
        reasons.push("diff_exceeds_action_scope".to_owned());
    }
    if request.diff.text.contains("GIT binary patch")
        || request.diff.text.contains("Binary files ")
        || request.diff.text.contains('\0')
    {
        reasons.push("binary_patch_rejected".to_owned());
    }
}

fn validate_changed_files(
    changed_files: &[String],
    scope: &ActionScope,
    reports: &[CodeCortexReport],
    reasons: &mut Vec<String>,
) {
    if changed_files.is_empty() {
        reasons.push("diff_contains_no_files".to_owned());
    }
    if changed_files.len() > scope.max_files {
        reasons.push("file_count_exceeds_action_scope".to_owned());
    }
    let allowed = scope
        .allowed_files
        .iter()
        .map(|path| normalize_path(path))
        .collect::<BTreeSet<_>>();
    let known = known_report_files(reports);
    for file in changed_files {
        let normalized = normalize_path(file);
        if !allowed.contains(&normalized) {
            reasons.push(format!("file_outside_action_scope:{file}"));
        }
        if !known.contains(&normalized) {
            reasons.push(format!("file_outside_codecortex_report:{file}"));
        }
    }
}

fn validate_git_head(
    request: &PatchRequest,
    scope: &ActionScope,
    current_head: Option<&str>,
    reasons: &mut Vec<String>,
) {
    if current_head.is_none() {
        reasons.push("git_head_unavailable".to_owned());
        return;
    }
    if let (Some(request_head), Some(scope_head)) = (
        request.git_head_before.as_deref(),
        scope.git_head.as_deref(),
    ) && request_head != scope_head
    {
        reasons.push("request_git_head_mismatch".to_owned());
    }
    for expected in [
        request.git_head_before.as_deref(),
        scope.git_head.as_deref(),
    ]
    .into_iter()
    .flatten()
    {
        if Some(expected) != current_head {
            reasons.push("stale_git_head".to_owned());
        }
    }
}

fn parse_changed_files(diff: &str) -> Result<Vec<String>, String> {
    let mut files = BTreeSet::new();
    for line in diff.lines() {
        if let Some(path) = line.strip_prefix("+++ ") {
            collect_diff_path(path, "b/", &mut files)?;
        } else if let Some(path) = line.strip_prefix("--- ") {
            collect_diff_path(path, "a/", &mut files)?;
        }
    }
    Ok(files.into_iter().collect())
}

fn collect_diff_path(
    raw_path: &str,
    prefix: &str,
    files: &mut BTreeSet<String>,
) -> Result<(), String> {
    let path = raw_path.split_whitespace().next().unwrap_or_default();
    if path == "/dev/null" {
        return Ok(());
    }
    let path = path.strip_prefix(prefix).unwrap_or(path);
    validate_relative_path(path)?;
    files.insert(normalize_path(path));
    Ok(())
}

fn validate_relative_path(path: &str) -> Result<(), String> {
    if path.trim().is_empty() {
        return Err("empty_patch_path".to_owned());
    }
    let path = Path::new(path);
    if path.is_absolute() {
        return Err("absolute_patch_path_rejected".to_owned());
    }
    if path.components().any(|component| {
        matches!(
            component,
            Component::ParentDir | Component::RootDir | Component::Prefix(_)
        )
    }) {
        return Err("path_traversal_rejected".to_owned());
    }
    Ok(())
}

fn known_report_files(reports: &[CodeCortexReport]) -> BTreeSet<String> {
    reports
        .iter()
        .flat_map(|report| {
            report
                .tracked_files
                .iter()
                .chain(report.file_evidence.iter())
                .map(|evidence| evidence.path.clone())
                .chain(
                    report
                        .symbol_evidence
                        .iter()
                        .map(|evidence| evidence.path.clone()),
                )
                .chain(report.blast_radius.files.iter().cloned())
        })
        .map(|path| normalize_path(&path))
        .collect()
}

fn timeout_seconds(scope: &ActionScope) -> u64 {
    scope.max_runtime_seconds.max(1)
}

async fn target_file_dirty(repo_root: &Path, file: &str) -> Result<bool, EngineError> {
    let repo = repo_root.display().to_string();
    let args = vec![
        "-C".to_owned(),
        repo,
        "status".to_owned(),
        "--porcelain".to_owned(),
        "--".to_owned(),
        file.to_owned(),
    ];
    let output =
        run_bounded_command("git", &args, repo_root, DEFAULT_TIMEOUT_SECONDS, None).await?;
    if !output.success {
        return Err(EngineError::WriteRejected(
            "git status failed for patch target".to_owned(),
        ));
    }
    Ok(!output.stdout.is_empty())
}

async fn git_head(repo_root: &Path) -> Result<Option<String>, EngineError> {
    let repo = repo_root.display().to_string();
    let args = vec![
        "-C".to_owned(),
        repo,
        "rev-parse".to_owned(),
        "HEAD".to_owned(),
    ];
    let output =
        run_bounded_command("git", &args, repo_root, DEFAULT_TIMEOUT_SECONDS, None).await?;
    if !output.success {
        return Ok(None);
    }
    let head = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    if head.is_empty() {
        Ok(None)
    } else {
        Ok(Some(head))
    }
}

fn git_apply_args(repo_root: &Path, check: bool, reverse: bool, diff_path: &Path) -> Vec<String> {
    let mut args = vec![
        "-C".to_owned(),
        repo_root.display().to_string(),
        "apply".to_owned(),
    ];
    if check {
        args.push("--check".to_owned());
    }
    if reverse {
        args.push("-R".to_owned());
    }
    args.push(diff_path.display().to_string());
    args
}

async fn run_bounded_command<S>(
    program: &str,
    args: &[S],
    cwd: &Path,
    timeout_seconds: u64,
    blob_store: Option<&BlobStore>,
) -> Result<BoundedCommandOutput, EngineError>
where
    S: AsRef<str>,
{
    let started = Instant::now();
    let mut command = Command::new(program);
    command
        .args(args.iter().map(AsRef::as_ref))
        .current_dir(cwd)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    if program == "cargo" {
        command.env("CARGO_TARGET_DIR", cwd.join("target"));
    }
    let child = command.spawn()?;
    let result = tokio::time::timeout(
        StdDuration::from_secs(timeout_seconds.max(1)),
        child.wait_with_output(),
    )
    .await;
    let duration_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    let output = match result {
        Ok(output) => output?,
        Err(_) => {
            return Ok(BoundedCommandOutput {
                success: false,
                timed_out: true,
                exit_code: None,
                duration_ms,
                stdout: Vec::new(),
                stderr: b"command timed out".to_vec(),
                stdout_blob: None,
                stderr_blob: blob_store
                    .map(|store| store.put_bytes(b"command timed out"))
                    .transpose()?,
            });
        }
    };
    let stdout_blob = blob_store
        .filter(|_| !output.stdout.is_empty())
        .map(|store| store.put_bytes(&output.stdout))
        .transpose()?;
    let stderr_blob = blob_store
        .filter(|_| !output.stderr.is_empty())
        .map(|store| store.put_bytes(&output.stderr))
        .transpose()?;
    Ok(BoundedCommandOutput {
        success: output.status.success(),
        timed_out: false,
        exit_code: output.status.code(),
        duration_ms,
        stdout: output.stdout,
        stderr: output.stderr,
        stdout_blob,
        stderr_blob,
    })
}

fn write_temp_diff(diff: &str) -> Result<PathBuf, EngineError> {
    let path = std::env::temp_dir().join(format!("eliot-patch-{}.diff", PatchRunId::new_v7()));
    std::fs::write(&path, diff)?;
    Ok(path)
}

fn append_command_summary(reasons: &mut Vec<String>, output: &BoundedCommandOutput) {
    let summary = command_summary(output);
    if !summary.is_empty() {
        reasons.push(summary);
    }
}

fn append_failed_verifiers(reasons: &mut Vec<String>, runs: &[VerifierRun]) {
    reasons.extend(
        runs.iter()
            .filter(|run| {
                run.required_for_done
                    && (run.status != VerifierStatus::Passed || is_quarantined_legacy_run(run))
            })
            .map(|run| format!("verifier_failed:{}:{:?}", run.name, run.status)),
    );
}

fn command_summary(output: &BoundedCommandOutput) -> String {
    if output.timed_out {
        return "command timed out".to_owned();
    }
    let stderr = truncate_lossy(&output.stderr);
    if stderr.is_empty() {
        truncate_lossy(&output.stdout)
    } else {
        stderr
    }
}

fn truncate_lossy(bytes: &[u8]) -> String {
    let text = String::from_utf8_lossy(bytes);
    text.chars().take(MAX_OUTPUT_SUMMARY_BYTES).collect()
}

/// Acceptance-eligibility quarantine for the legacy command lane (issue
/// #1852 W3): a run executed through the private command map carries
/// [`QUARANTINED_LEGACY_LANE`] as its summary prefix, and no such run may
/// satisfy a required verifier, no matter its status. Shared with the
/// work-queue selection point so a quarantined run cannot be selected by an
/// authority-facing caller either.
pub(crate) fn is_quarantined_legacy_run(run: &VerifierRun) -> bool {
    run.summary.starts_with(QUARANTINED_LEGACY_LANE)
}

fn required_verifiers_passed(runs: &[VerifierRun]) -> bool {
    runs.iter()
        .filter(|run| run.required_for_done)
        .all(|run| run.status == VerifierStatus::Passed && !is_quarantined_legacy_run(run))
}

fn canonical_verifier_runs<'a>(
    patch_run: &PatchRun,
    verifier_runs: &'a [VerifierRun],
    reasons: &mut Vec<String>,
) -> Vec<&'a VerifierRun> {
    let mut canonical = Vec::with_capacity(patch_run.verifier_runs.len());
    for (index, reference) in patch_run.verifier_runs.iter().enumerate() {
        if patch_run.verifier_runs[..index]
            .iter()
            .any(|prior| prior.verifier_run_id == reference.verifier_run_id)
        {
            reasons.push(format!(
                "patch_run_verifier_ref_duplicate:{}",
                reference.verifier_run_id
            ));
            continue;
        }

        let mut matching = verifier_runs
            .iter()
            .filter(|run| run.verifier_run_id == reference.verifier_run_id);
        let Some(run) = matching.next() else {
            reasons.push(format!(
                "patch_run_verifier_ref_missing:{}",
                reference.verifier_run_id
            ));
            continue;
        };
        if matching.next().is_some() {
            reasons.push(format!(
                "patch_run_verifier_ref_has_duplicate_runs:{}",
                reference.verifier_run_id
            ));
            continue;
        }
        if run.name != reference.name || run.status != reference.status {
            reasons.push(format!(
                "patch_run_verifier_ref_mismatch:{}",
                reference.verifier_run_id
            ));
            continue;
        }
        if run.project_id != patch_run.project_id
            || run.task_id != patch_run.task_id
            || run.agent_id != patch_run.agent_id
        {
            reasons.push(format!(
                "patch_run_verifier_scope_mismatch:{}",
                reference.verifier_run_id
            ));
            continue;
        }
        canonical.push(run);
    }

    for (index, run) in verifier_runs.iter().enumerate() {
        if verifier_runs[..index]
            .iter()
            .any(|prior| prior.verifier_run_id == run.verifier_run_id)
        {
            continue;
        }
        if !patch_run
            .verifier_runs
            .iter()
            .any(|reference| reference.verifier_run_id == run.verifier_run_id)
        {
            reasons.push(format!(
                "verifier_run_not_in_patch_run:{}",
                run.verifier_run_id
            ));
        }
    }

    canonical
}

fn verifier_run_ref(run: &VerifierRun) -> VerifierRunRef {
    VerifierRunRef {
        verifier_run_id: run.verifier_run_id,
        name: run.name.clone(),
        status: run.status,
    }
}

fn e2_context(
    project_id: eliot_types::ProjectId,
    agent_id: eliot_types::AgentId,
    task_id: eliot_types::TaskId,
    scope: &str,
) -> CommandContext {
    CommandContext {
        write_id: WriteId::new_v7(),
        agent_id,
        session_id: None,
        project_id,
        task_id: Some(task_id),
        scope: scope.to_owned(),
        authority: "eliot-patch-runner".to_owned(),
        visibility: Visibility::Internal,
        taint: TaintClass::LocalVerified,
        lifecycle_status: LifecycleStatus::Active,
    }
}

fn write_receipt_ref(receipt: &eliot_types::WriteReceipt) -> WriteReceiptRef {
    WriteReceiptRef {
        receipt_id: receipt.receipt_id,
        write_id: receipt.write_id,
    }
}

fn completion_decision(
    proof: &CompletionProof,
    final_status: CompletionStatus,
    reasons: Vec<String>,
) -> CompletionGateDecision {
    CompletionGateDecision {
        task_id: proof.task_id.clone(),
        project_id: proof.project_id,
        final_status,
        reasons,
    }
}

fn same_canonical_path(left: &Path, right: &Path) -> bool {
    let Ok(left) = std::fs::canonicalize(left) else {
        return false;
    };
    let Ok(right) = std::fs::canonicalize(right) else {
        return false;
    };
    normalize_path(&left.display().to_string()) == normalize_path(&right.display().to_string())
}

fn normalize_path(path: &str) -> String {
    path.replace('\\', "/")
        .trim_start_matches("./")
        .to_ascii_lowercase()
}
