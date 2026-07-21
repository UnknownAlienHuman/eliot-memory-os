use crate::{
    EngineError, WriteAdmissionService, WriterHandle, path_in_scope, work::WorkState,
    work_lease_is_active,
};
use eliot_types::{
    ActionLease, AgentId, AgentSessionId, CandidateDiff, CandidateDiffId, CandidateDiffStatus,
    CandidateReview, CandidateReviewDecision, CommandContext, CompletionGateDecision,
    CompletionProof, CompletionStatus, LifecycleStatus, PatchRequest, SemanticCommand, TaintClass,
    ToolObservationRecordCommand, UnifiedDiff, VerifierRun, VerifierStatus, Visibility, WorkLease,
    WorkScope, WorktreeLease, WorktreeLeaseId, WorktreeLeaseRequest, WorktreeLeaseState, WriteId,
    WriteReceiptRef,
};
#[cfg(windows)]
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::process::Stdio;
use std::time::Duration as StdDuration;
use time::{Duration, OffsetDateTime};
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::process::Command;
use tokio::time::timeout;

const DEFAULT_WORKTREE_TTL_MINUTES: i64 = 45;
const DEFAULT_MAX_DIFF_BYTES: usize = 128 * 1024;
const GIT_TIMEOUT_SECONDS: u64 = 30;
const MAX_GIT_DIFF_CAPTURE_BYTES: usize = 16 * 1024 * 1024;
const MAX_GIT_STDERR_BYTES: usize = 64 * 1024;

#[derive(Clone, Debug)]
pub struct WorktreeCreateInput {
    pub request: WorktreeLeaseRequest,
    pub worktree_root: PathBuf,
    pub ttl_minutes: i64,
}

#[derive(Clone, Debug)]
pub struct CandidateDiffCaptureInput {
    pub worktree_lease_id: WorktreeLeaseId,
    pub diff_root: PathBuf,
    pub max_diff_bytes: usize,
}

#[derive(Clone, Debug)]
pub struct CandidateReviewInput {
    pub candidate_diff_id: CandidateDiffId,
    pub reviewer_session_id: AgentSessionId,
    pub decision: CandidateReviewDecision,
    pub reasons: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct CandidatePatchRequestInput<'a> {
    pub candidate_diff: &'a CandidateDiff,
    pub review: &'a CandidateReview,
    pub action_lease: &'a ActionLease,
    pub diff_text: String,
    pub codecortex_report_refs: Vec<String>,
    pub verifier_plan_ref: String,
}

#[derive(Clone, Copy, Debug)]
pub struct CandidateCompletionContext<'a> {
    pub candidate_diff: Option<&'a CandidateDiff>,
    pub candidate_review: Option<&'a CandidateReview>,
    pub patch_run: Option<&'a eliot_types::PatchRun>,
    pub verifier_runs: &'a [VerifierRun],
}

#[derive(Clone, Copy, Debug, Default)]
pub struct WorktreeLeaseService;

#[derive(Clone, Copy, Debug, Default)]
pub struct CandidateDiffService;

#[derive(Clone, Copy, Debug, Default)]
pub struct CandidateReviewService;

#[derive(Clone, Copy, Debug, Default)]
pub struct WorktreeCleanupService;

pub struct WorktreeMemoryWriter;

impl WorktreeLeaseService {
    pub async fn create(
        &self,
        state: &mut WorkState,
        input: WorktreeCreateInput,
    ) -> Result<WorktreeLease, EngineError> {
        let repo_root = canonical_existing_path(&input.request.repo_root)?;
        let worktree_root = prepare_worktree_root(&repo_root, &input.worktree_root)?;
        validate_requested_branch(input.request.requested_branch_name.as_deref())?;

        let work_lease = active_matching_work_lease(state, &input.request)?.clone();
        validate_requested_scope(&input.request.requested_scope, &work_lease.scope)?;
        if state.worktree_leases.iter().any(|lease| {
            lease.work_lease_id == work_lease.work_lease_id
                && matches!(
                    lease.state,
                    WorktreeLeaseState::Created | WorktreeLeaseState::Active
                )
        }) {
            return Err(rejected("active_worktree_lease_exists_for_work_lease"));
        }

        let head = git_stdout(&repo_root, &["rev-parse", "HEAD"]).await?;
        if input
            .request
            .base_commit
            .as_deref()
            .is_some_and(|base| base != head)
        {
            return Err(rejected("requested_base_commit_is_not_repo_head"));
        }
        if !git_status_clean(&repo_root).await? {
            return Err(rejected("controller_repo_dirty"));
        }

        let worktree_lease_id = WorktreeLeaseId::new_v7();
        let branch_name = input
            .request
            .requested_branch_name
            .clone()
            .unwrap_or_else(|| format!("eliot-f2-{worktree_lease_id}"));
        let worktree_path = worktree_root.join(worktree_lease_id.to_string());
        ensure_child_path(&worktree_root, &worktree_path)?;
        let worktree_path_arg = path_for_git(&worktree_path);

        git_status(
            &repo_root,
            &[
                "worktree",
                "add",
                "-b",
                &branch_name,
                &worktree_path_arg,
                &head,
            ],
        )
        .await?;

        let now = OffsetDateTime::now_utc();
        let lease = WorktreeLease {
            worktree_lease_id,
            project_id: input.request.project_id,
            task_id: input.request.task_id,
            work_item_id: input.request.work_item_id,
            work_lease_id: input.request.work_lease_id,
            holder_session_id: input.request.agent_session_id,
            repo_root: path_for_record(&repo_root),
            worktree_path: path_for_record(&worktree_path),
            branch_name,
            base_commit: head,
            allowed_read_set: input.request.requested_scope.read_set,
            allowed_write_set: input.request.requested_scope.write_set,
            state: WorktreeLeaseState::Active,
            issued_at: now,
            expires_at: now + Duration::minutes(input.ttl_minutes.max(1)),
            cleaned_at: None,
            write_receipt: None,
        };
        state.worktree_leases.push(lease.clone());
        Ok(lease)
    }

    pub fn default_ttl_minutes() -> i64 {
        DEFAULT_WORKTREE_TTL_MINUTES
    }
}

impl CandidateDiffService {
    pub async fn capture(
        &self,
        state: &mut WorkState,
        input: CandidateDiffCaptureInput,
    ) -> Result<CandidateDiff, EngineError> {
        let lease_index = state
            .worktree_leases
            .iter()
            .position(|lease| lease.worktree_lease_id == input.worktree_lease_id)
            .ok_or_else(|| rejected("worktree_lease_not_found"))?;
        let lease = state.worktree_leases[lease_index].clone();
        if !matches!(lease.state, WorktreeLeaseState::Active)
            || lease.expires_at < OffsetDateTime::now_utc()
        {
            return Err(rejected("worktree_lease_not_active"));
        }
        let repo_root = canonical_existing_path(&lease.repo_root)?;
        let worktree_path = canonical_existing_path(&lease.worktree_path)?;
        let diff_root = prepare_diff_root(&input.diff_root)?;
        let current_head = git_stdout(&repo_root, &["rev-parse", "HEAD"]).await?;
        let candidate_diff_id = CandidateDiffId::new_v7();
        let snapshot = capture_candidate_snapshot(
            &worktree_path,
            &diff_root,
            candidate_diff_id,
            &lease.base_commit,
        )
        .await?;
        let changed_files = snapshot.changed_files;

        let mut status = classify_candidate_diff(
            &current_head,
            &lease.base_commit,
            &changed_files,
            &lease.allowed_write_set,
        );

        let diff_text = snapshot.diff_text;
        if status == CandidateDiffStatus::Captured && diff_text.len() > input.max_diff_bytes {
            status = CandidateDiffStatus::TooLarge;
        }
        let diff_ref = diff_root.join(format!("{candidate_diff_id}.diff"));
        std::fs::write(&diff_ref, &diff_text)?;

        let changed_file_paths = changed_files
            .iter()
            .map(|file| file.path.clone())
            .collect::<Vec<_>>();
        let added_files = changed_files
            .iter()
            .filter(|file| file.kind == FileStatusKind::Added)
            .map(|file| file.path.clone())
            .collect::<Vec<_>>();
        let modified_files = changed_files
            .iter()
            .filter(|file| file.kind == FileStatusKind::Modified)
            .map(|file| file.path.clone())
            .collect::<Vec<_>>();
        let deleted_files = changed_files
            .iter()
            .filter(|file| file.kind == FileStatusKind::Deleted)
            .map(|file| file.path.clone())
            .collect::<Vec<_>>();

        if matches!(
            status,
            CandidateDiffStatus::Captured | CandidateDiffStatus::Empty
        ) {
            state.worktree_leases[lease_index].state = WorktreeLeaseState::Captured;
        }
        let diff = CandidateDiff {
            candidate_diff_id,
            worktree_lease_id: lease.worktree_lease_id,
            project_id: lease.project_id,
            task_id: lease.task_id,
            work_item_id: lease.work_item_id,
            base_commit: lease.base_commit,
            worktree_head: Some(snapshot.worktree_head),
            diff_hash: blake3::hash(diff_text.as_bytes()).to_hex().to_string(),
            diff_ref: path_for_record(&diff_ref),
            changed_files: changed_file_paths,
            added_files,
            modified_files,
            deleted_files,
            byte_len: diff_text.len(),
            file_count: changed_files.len(),
            capture_status: status,
            created_at: OffsetDateTime::now_utc(),
            write_receipt: None,
        };
        state.candidate_diffs.push(diff.clone());
        Ok(diff)
    }

    pub fn default_max_diff_bytes() -> usize {
        DEFAULT_MAX_DIFF_BYTES
    }
}

impl CandidateReviewService {
    pub fn review(
        &self,
        state: &mut WorkState,
        input: CandidateReviewInput,
    ) -> Result<CandidateReview, EngineError> {
        let diff_index = state
            .candidate_diffs
            .iter()
            .position(|diff| diff.candidate_diff_id == input.candidate_diff_id)
            .ok_or_else(|| rejected("candidate_diff_not_found"))?;
        let diff = state.candidate_diffs[diff_index].clone();
        let lease = state
            .worktree_leases
            .iter()
            .find(|lease| lease.worktree_lease_id == diff.worktree_lease_id)
            .ok_or_else(|| rejected("worktree_lease_not_found"))?;
        if input.reviewer_session_id == lease.holder_session_id {
            return Err(rejected("candidate_review_requires_independent_reviewer"));
        }
        if input.decision == CandidateReviewDecision::AcceptForPatchRunner {
            if diff.capture_status != CandidateDiffStatus::Captured {
                return Err(rejected("candidate_diff_not_captured"));
            }
            if diff
                .changed_files
                .iter()
                .any(|file| !path_in_scope(file, &lease.allowed_write_set))
            {
                return Err(rejected("candidate_diff_outside_worktree_scope"));
            }
            state.candidate_diffs[diff_index].capture_status =
                CandidateDiffStatus::AcceptedForPatchRunner;
        } else {
            state.candidate_diffs[diff_index].capture_status = CandidateDiffStatus::Rejected;
        }
        let review = CandidateReview {
            review_id: format!("candidate_review:{}", WriteId::new_v7()),
            candidate_diff_id: input.candidate_diff_id,
            reviewer_session_id: input.reviewer_session_id,
            decision: input.decision,
            reasons: input.reasons,
            created_at: OffsetDateTime::now_utc(),
            patch_request_id: None,
            write_receipt: None,
        };
        state.candidate_reviews.push(review.clone());
        Ok(review)
    }

    pub fn patch_request(
        &self,
        input: CandidatePatchRequestInput<'_>,
    ) -> Result<PatchRequest, EngineError> {
        if input.review.decision != CandidateReviewDecision::AcceptForPatchRunner {
            return Err(rejected("candidate_review_not_accepted"));
        }
        if input.candidate_diff.capture_status != CandidateDiffStatus::AcceptedForPatchRunner {
            return Err(rejected("candidate_diff_not_accepted_for_patchrunner"));
        }
        if input.review.candidate_diff_id != input.candidate_diff.candidate_diff_id {
            return Err(rejected("candidate_review_diff_identity_mismatch"));
        }
        let stored_diff = std::fs::read(&input.candidate_diff.diff_ref)?;
        let stored_hash = blake3::hash(&stored_diff).to_hex().to_string();
        if stored_hash != input.candidate_diff.diff_hash {
            return Err(rejected("candidate_diff_artifact_hash_mismatch"));
        }
        if stored_diff.as_slice() != input.diff_text.as_bytes() {
            return Err(rejected("candidate_diff_payload_mismatch"));
        }
        let scope = input
            .action_lease
            .allowed_scope
            .as_ref()
            .ok_or_else(|| rejected("action_lease_missing_allowed_scope"))?;
        if input
            .candidate_diff
            .changed_files
            .iter()
            .any(|file| !path_in_scope(file, &scope.allowed_files))
        {
            return Err(rejected("candidate_diff_outside_action_scope"));
        }
        Ok(PatchRequest {
            patch_request_id: eliot_types::PatchRequestId::new_v7(),
            project_id: input.candidate_diff.project_id,
            task_id: input.candidate_diff.task_id,
            agent_id: input.action_lease.agent_id,
            action_lease_id: input.action_lease.lease_id,
            repo_root: scope.repo_root.clone(),
            git_head_before: scope.git_head.clone(),
            codecortex_report_refs: input.codecortex_report_refs,
            verifier_plan_ref: input.verifier_plan_ref,
            diff: UnifiedDiff {
                byte_len: input.diff_text.len(),
                text: input.diff_text,
            },
            created_at: OffsetDateTime::now_utc(),
        })
    }
}

impl WorktreeCleanupService {
    pub async fn cleanup(
        &self,
        state: &mut WorkState,
        worktree_lease_id: WorktreeLeaseId,
    ) -> Result<WorktreeLease, EngineError> {
        let lease_index = state
            .worktree_leases
            .iter()
            .position(|lease| lease.worktree_lease_id == worktree_lease_id)
            .ok_or_else(|| rejected("worktree_lease_not_found"))?;
        let lease = state.worktree_leases[lease_index].clone();
        if matches!(
            lease.state,
            WorktreeLeaseState::Created | WorktreeLeaseState::Active
        ) {
            return Err(rejected("worktree_lease_not_captured_or_reviewed"));
        }
        let repo_root = canonical_existing_path(&lease.repo_root)?;
        let worktree_path = PathBuf::from(&lease.worktree_path);
        validate_worktree_cleanup_path(&worktree_path, worktree_lease_id)?;
        #[cfg(windows)]
        clear_worktree_metadata_readonly(&repo_root, worktree_lease_id)?;
        if worktree_directory_exists(&worktree_path)? {
            let remove_result =
                if worktree_registration_absent(&repo_root, &worktree_path, worktree_lease_id)? {
                    Ok(())
                } else {
                    let worktree_path_arg = path_for_git(&worktree_path);
                    git_status(
                        &repo_root,
                        &[
                            "-c",
                            "core.longpaths=true",
                            "worktree",
                            "remove",
                            "--force",
                            &worktree_path_arg,
                        ],
                    )
                    .await
                };
            let registration_absent =
                worktree_registration_absent(&repo_root, &worktree_path, worktree_lease_id)?;
            if let Err(error) = remove_result
                && !registration_absent
            {
                return Err(error);
            }
            if worktree_directory_exists(&worktree_path)? {
                if !registration_absent {
                    return Err(rejected("git_worktree_remove_left_registered_path"));
                }
                remove_abandoned_worktree_directory(&repo_root, &worktree_path, worktree_lease_id)?;
            }
        } else {
            git_status(
                &repo_root,
                &[
                    "-c",
                    "core.longpaths=true",
                    "worktree",
                    "prune",
                    "--expire",
                    "now",
                ],
            )
            .await?;
        }
        state.worktree_leases[lease_index].state = WorktreeLeaseState::Cleaned;
        state.worktree_leases[lease_index].cleaned_at = Some(OffsetDateTime::now_utc());
        Ok(state.worktree_leases[lease_index].clone())
    }

    pub fn revoke(
        &self,
        state: &mut WorkState,
        worktree_lease_id: WorktreeLeaseId,
    ) -> Result<WorktreeLease, EngineError> {
        let lease = state
            .worktree_leases
            .iter_mut()
            .find(|lease| lease.worktree_lease_id == worktree_lease_id)
            .ok_or_else(|| rejected("worktree_lease_not_found"))?;
        lease.state = WorktreeLeaseState::Revoked;
        Ok(lease.clone())
    }
}

fn validate_worktree_cleanup_path(
    worktree_path: &Path,
    worktree_lease_id: WorktreeLeaseId,
) -> Result<(), EngineError> {
    let expected_leaf = worktree_lease_id.to_string();
    if !worktree_path.is_absolute()
        || worktree_path.parent().is_none()
        || worktree_path.file_name().and_then(|name| name.to_str()) != Some(expected_leaf.as_str())
    {
        return Err(rejected("invalid_worktree_cleanup_path"));
    }
    Ok(())
}

fn worktree_directory_exists(worktree_path: &Path) -> Result<bool, EngineError> {
    let metadata = match std::fs::symlink_metadata(worktree_path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error.into()),
    };
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(rejected("worktree_cleanup_path_is_not_directory"));
    }
    Ok(true)
}

fn worktree_registration_absent(
    repo_root: &Path,
    worktree_path: &Path,
    worktree_lease_id: WorktreeLeaseId,
) -> Result<bool, EngineError> {
    Ok(!path_entry_exists(&worktree_path.join(".git"))?
        && !path_entry_exists(&worktree_metadata_path(repo_root, worktree_lease_id)?)?)
}

fn remove_abandoned_worktree_directory(
    repo_root: &Path,
    worktree_path: &Path,
    worktree_lease_id: WorktreeLeaseId,
) -> Result<(), EngineError> {
    let deletion_path = canonical_existing_path(worktree_path)?;
    validate_worktree_cleanup_path(&deletion_path, worktree_lease_id)?;
    if deletion_path == repo_root || deletion_path.starts_with(repo_root) {
        return Err(rejected("refuse_worktree_cleanup_inside_controller_repo"));
    }
    std::fs::remove_dir_all(deletion_path)?;
    Ok(())
}

fn path_entry_exists(path: &Path) -> Result<bool, EngineError> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}

fn worktree_metadata_path(
    repo_root: &Path,
    worktree_lease_id: WorktreeLeaseId,
) -> Result<PathBuf, EngineError> {
    let worktrees_root = repo_root.join(".git").join("worktrees");
    let metadata_path = worktrees_root.join(worktree_lease_id.to_string());
    if !metadata_path.starts_with(&worktrees_root) {
        return Err(rejected("worktree metadata path escaped .git/worktrees"));
    }
    Ok(metadata_path)
}

#[cfg(windows)]
fn clear_worktree_metadata_readonly(
    repo_root: &Path,
    worktree_lease_id: WorktreeLeaseId,
) -> Result<(), EngineError> {
    let metadata_path = worktree_metadata_path(repo_root, worktree_lease_id)?;
    clear_readonly_recursive(&metadata_path)
}

#[cfg(windows)]
#[allow(clippy::permissions_set_readonly_false)]
fn clear_readonly_recursive(path: &Path) -> Result<(), EngineError> {
    if !path.exists() {
        return Ok(());
    }
    let metadata = fs::symlink_metadata(path)?;
    if metadata.is_dir() {
        for entry in fs::read_dir(path)? {
            clear_readonly_recursive(&entry?.path())?;
        }
    }
    let mut permissions = metadata.permissions();
    if permissions.readonly() {
        permissions.set_readonly(false);
        fs::set_permissions(path, permissions)?;
    }
    Ok(())
}

impl WorktreeMemoryWriter {
    pub async fn write_worktree_lease(
        writer: &WriterHandle,
        admission: &WriteAdmissionService,
        lease: &mut WorktreeLease,
    ) -> Result<(), EngineError> {
        let receipt = write_worktree_payload(
            writer,
            admission,
            WorktreePayloadInput {
                project_id: lease.project_id,
                task_id: lease.task_id,
                agent_id: AgentId::from_uuid(lease.holder_session_id.as_uuid()),
                scope: "worktree-lease",
                observation: format!(
                    "WorktreeLease {} state {:?}",
                    lease.worktree_lease_id, lease.state
                ),
                payload: serde_json::json!({ "worktree_lease": lease }),
            },
        )
        .await?;
        lease.write_receipt = Some(receipt);
        Ok(())
    }

    pub async fn write_candidate_diff(
        writer: &WriterHandle,
        admission: &WriteAdmissionService,
        diff: &mut CandidateDiff,
        agent_id: AgentId,
    ) -> Result<(), EngineError> {
        let receipt = write_worktree_payload(
            writer,
            admission,
            WorktreePayloadInput {
                project_id: diff.project_id,
                task_id: diff.task_id,
                agent_id,
                scope: "candidate-diff",
                observation: format!(
                    "CandidateDiff {} status {:?}",
                    diff.candidate_diff_id, diff.capture_status
                ),
                payload: serde_json::json!({ "candidate_diff": diff }),
            },
        )
        .await?;
        diff.write_receipt = Some(receipt);
        Ok(())
    }

    pub async fn write_candidate_review(
        writer: &WriterHandle,
        admission: &WriteAdmissionService,
        review: &mut CandidateReview,
        diff: &CandidateDiff,
    ) -> Result<(), EngineError> {
        let receipt = write_worktree_payload(
            writer,
            admission,
            WorktreePayloadInput {
                project_id: diff.project_id,
                task_id: diff.task_id,
                agent_id: AgentId::from_uuid(review.reviewer_session_id.as_uuid()),
                scope: "candidate-review",
                observation: format!(
                    "CandidateReview {} decision {:?}",
                    review.review_id, review.decision
                ),
                payload: serde_json::json!({ "candidate_review": review }),
            },
        )
        .await?;
        review.write_receipt = Some(receipt);
        Ok(())
    }
}

impl crate::CompletionGate {
    pub fn decide_with_candidate_context(
        proof: &CompletionProof,
        context: CandidateCompletionContext<'_>,
    ) -> CompletionGateDecision {
        let base = crate::CompletionGate::decide_with_patch_context(
            proof,
            context.patch_run,
            context.verifier_runs,
        );
        let mut reasons = base.reasons;
        let Some(candidate_diff) = context.candidate_diff else {
            reasons.push("missing_candidate_diff".to_owned());
            return candidate_completion_decision(
                proof,
                CompletionStatus::PartialProgress,
                reasons,
            );
        };
        let Some(candidate_review) = context.candidate_review else {
            reasons.push("missing_candidate_review".to_owned());
            return candidate_completion_decision(
                proof,
                CompletionStatus::PartialProgress,
                reasons,
            );
        };
        if candidate_diff.capture_status != CandidateDiffStatus::AcceptedForPatchRunner {
            reasons.push("candidate_diff_not_accepted_for_patchrunner".to_owned());
        }
        if candidate_review.decision != CandidateReviewDecision::AcceptForPatchRunner {
            reasons.push("candidate_review_not_accepted".to_owned());
        }
        if !proof
            .evidence
            .iter()
            .any(|evidence| evidence.contains(&candidate_diff.candidate_diff_id.to_string()))
        {
            reasons.push("completion_proof_missing_candidate_diff_ref".to_owned());
        }
        if context
            .verifier_runs
            .iter()
            .filter(|run| run.required_for_done)
            .any(|run| run.status != VerifierStatus::Passed)
        {
            return candidate_completion_decision(proof, CompletionStatus::FailedVerifier, reasons);
        }
        if reasons.is_empty() {
            candidate_completion_decision(proof, CompletionStatus::DoneVerified, reasons)
        } else {
            candidate_completion_decision(proof, CompletionStatus::PartialProgress, reasons)
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FileStatusKind {
    Added,
    Modified,
    Deleted,
}

#[derive(Clone, Debug)]
struct StatusFile {
    path: String,
    kind: FileStatusKind,
}

struct WorktreePayloadInput {
    project_id: eliot_types::ProjectId,
    task_id: eliot_types::TaskId,
    agent_id: AgentId,
    scope: &'static str,
    observation: String,
    payload: serde_json::Value,
}

struct CandidateTreeSnapshot {
    worktree_head: String,
    changed_files: Vec<StatusFile>,
    diff_text: String,
}

fn classify_candidate_diff(
    controller_head: &str,
    base_commit: &str,
    changed_files: &[StatusFile],
    allowed_write_set: &[String],
) -> CandidateDiffStatus {
    if changed_files.is_empty() {
        CandidateDiffStatus::Empty
    } else if controller_head != base_commit {
        CandidateDiffStatus::BaseDrift
    } else if changed_files
        .iter()
        .any(|file| !path_in_scope(file.path.as_str(), allowed_write_set))
    {
        CandidateDiffStatus::OutOfScope
    } else {
        CandidateDiffStatus::Captured
    }
}

async fn write_worktree_payload(
    writer: &WriterHandle,
    admission: &WriteAdmissionService,
    input: WorktreePayloadInput,
) -> Result<WriteReceiptRef, EngineError> {
    let command = SemanticCommand::ToolObservationRecord(ToolObservationRecordCommand {
        context: CommandContext {
            write_id: WriteId::new_v7(),
            agent_id: input.agent_id,
            session_id: None,
            project_id: input.project_id,
            task_id: Some(input.task_id),
            scope: input.scope.to_owned(),
            authority: "local-worktree-governor".to_owned(),
            visibility: Visibility::Internal,
            taint: TaintClass::LocalVerified,
            lifecycle_status: LifecycleStatus::Active,
        },
        tool_name: "eliot_worktree_governor".to_owned(),
        observation: input.observation,
        payload: input.payload,
    });
    let receipt = writer.submit(admission.admit(&command)?).await?;
    Ok(write_receipt_ref(&receipt))
}

fn write_receipt_ref(receipt: &eliot_types::WriteReceipt) -> WriteReceiptRef {
    WriteReceiptRef {
        receipt_id: receipt.receipt_id,
        write_id: receipt.write_id,
    }
}

fn active_matching_work_lease<'a>(
    state: &'a WorkState,
    request: &WorktreeLeaseRequest,
) -> Result<&'a WorkLease, EngineError> {
    let lease = state
        .leases
        .iter()
        .find(|lease| lease.work_lease_id == request.work_lease_id)
        .ok_or_else(|| rejected("missing_work_lease"))?;
    if !work_lease_is_active(lease) {
        return Err(rejected("work_lease_inactive"));
    }
    if lease.project_id != request.project_id
        || lease.task_id != request.task_id
        || lease.work_item_id != request.work_item_id
        || lease.agent_session_id != request.agent_session_id
    {
        return Err(rejected("work_lease_request_mismatch"));
    }
    Ok(lease)
}

fn validate_requested_scope(requested: &WorkScope, granted: &WorkScope) -> Result<(), EngineError> {
    let requested_write = requested
        .write_set
        .iter()
        .map(|file| normalize_relative_path(file))
        .collect::<Result<Vec<_>, _>>()?;
    if !requested_write
        .iter()
        .all(|file| path_in_scope(file, &granted.write_set))
    {
        return Err(rejected("worktree_write_scope_not_subset_of_work_lease"));
    }
    let requested_read = requested
        .read_set
        .iter()
        .map(|file| normalize_relative_path(file))
        .collect::<Result<Vec<_>, _>>()?;
    let readable = granted
        .read_set
        .iter()
        .chain(granted.write_set.iter())
        .cloned()
        .collect::<Vec<_>>();
    if !requested_read
        .iter()
        .all(|file| path_in_scope(file, &readable))
    {
        return Err(rejected("worktree_read_scope_not_subset_of_work_lease"));
    }
    Ok(())
}

fn validate_requested_branch(branch: Option<&str>) -> Result<(), EngineError> {
    let Some(branch) = branch else {
        return Ok(());
    };
    if branch.trim().is_empty()
        || branch.contains("..")
        || branch.contains('\\')
        || branch.contains(':')
        || branch.starts_with('-')
        || Path::new(branch)
            .extension()
            .is_some_and(|extension| extension.eq_ignore_ascii_case("lock"))
        || branch
            .chars()
            .any(|ch| ch.is_control() || ch.is_whitespace())
    {
        return Err(rejected("invalid_worktree_branch_name"));
    }
    Ok(())
}

fn canonical_existing_path(path: impl AsRef<Path>) -> Result<PathBuf, EngineError> {
    Ok(PathBuf::from(path.as_ref()).canonicalize()?)
}

fn prepare_worktree_root(repo_root: &Path, worktree_root: &Path) -> Result<PathBuf, EngineError> {
    std::fs::create_dir_all(worktree_root)?;
    let root = worktree_root.canonicalize()?;
    if root == repo_root || root.starts_with(repo_root) {
        return Err(rejected("worktree_root_inside_controller_tree"));
    }
    Ok(root)
}

fn prepare_diff_root(diff_root: &Path) -> Result<PathBuf, EngineError> {
    std::fs::create_dir_all(diff_root)?;
    Ok(diff_root.canonicalize()?)
}

fn path_for_git(path: &Path) -> String {
    strip_windows_verbatim_prefix(path.display().to_string())
}

fn path_for_record(path: &Path) -> String {
    strip_windows_verbatim_prefix(path.display().to_string())
}

fn strip_windows_verbatim_prefix(value: String) -> String {
    #[cfg(windows)]
    {
        if let Some(rest) = value.strip_prefix(r"\\?\UNC\") {
            return format!(r"\\{rest}");
        }
        if let Some(rest) = value.strip_prefix(r"\\?\") {
            return rest.to_owned();
        }
        if let Some(rest) = value.strip_prefix("//?/UNC/") {
            return format!("//{rest}");
        }
        if let Some(rest) = value.strip_prefix("//?/") {
            return rest.to_owned();
        }
    }
    value
}

fn ensure_child_path(parent: &Path, child: &Path) -> Result<(), EngineError> {
    let child_parent = child
        .parent()
        .ok_or_else(|| rejected("invalid_child_path"))?;
    if child_parent != parent {
        return Err(rejected("path_traversal_rejected"));
    }
    Ok(())
}

fn normalize_relative_path(path: &str) -> Result<String, EngineError> {
    let path = Path::new(path);
    if path.is_absolute() {
        return Err(rejected("absolute_path_rejected"));
    }
    let mut parts = Vec::new();
    for component in path.components() {
        match component {
            Component::Normal(part) => parts.push(part.to_string_lossy().to_string()),
            Component::CurDir => {}
            Component::ParentDir | Component::Prefix(_) | Component::RootDir => {
                return Err(rejected("path_traversal_rejected"));
            }
        }
    }
    if parts.is_empty() {
        return Err(rejected("empty_path_rejected"));
    }
    Ok(parts.join("/"))
}

async fn git_status_clean(repo_root: &Path) -> Result<bool, EngineError> {
    Ok(git_stdout_raw(repo_root, &["status", "--porcelain"])
        .await?
        .trim()
        .is_empty())
}

async fn changed_files_between_trees(
    worktree_path: &Path,
    base_commit: &str,
    snapshot_tree: &str,
) -> Result<Vec<StatusFile>, EngineError> {
    let output = run_git(
        worktree_path,
        &[
            "diff",
            "--name-status",
            "-z",
            "--no-renames",
            "--no-ext-diff",
            base_commit,
            snapshot_tree,
            "--",
        ],
    )
    .await?;
    if !output.status.success() {
        return Err(rejected(format!(
            "git_command_failed:{}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    parse_diff_name_status_z(&output.stdout)
}

async fn capture_candidate_snapshot(
    worktree_path: &Path,
    diff_root: &Path,
    candidate_diff_id: CandidateDiffId,
    base_commit: &str,
) -> Result<CandidateTreeSnapshot, EngineError> {
    let worktree_head = git_stdout(worktree_path, &["rev-parse", "HEAD"]).await?;
    let snapshot_tree =
        snapshot_candidate_tree(worktree_path, diff_root, candidate_diff_id, &worktree_head)
            .await?;
    let changed_files =
        changed_files_between_trees(worktree_path, base_commit, &snapshot_tree).await?;
    let diff_bytes = git_stdout_bounded(
        worktree_path,
        &[
            "diff",
            "--binary",
            "--no-renames",
            "--no-ext-diff",
            base_commit,
            &snapshot_tree,
            "--",
        ],
        MAX_GIT_DIFF_CAPTURE_BYTES,
    )
    .await?;
    let diff_text =
        String::from_utf8(diff_bytes).map_err(|_| rejected("git_diff_output_not_utf8"))?;
    Ok(CandidateTreeSnapshot {
        worktree_head,
        changed_files,
        diff_text,
    })
}

fn parse_diff_name_status_z(output: &[u8]) -> Result<Vec<StatusFile>, EngineError> {
    let mut fields = output.split(|byte| *byte == 0).collect::<Vec<_>>();
    if fields.last().is_some_and(|field| field.is_empty()) {
        fields.pop();
    }
    if fields.len() % 2 != 0 {
        return Err(rejected("invalid_git_diff_name_status_z"));
    }
    fields
        .chunks_exact(2)
        .map(|record| {
            let status = std::str::from_utf8(record[0])
                .map_err(|_| rejected("git_diff_status_not_utf8"))?
                .chars()
                .next()
                .ok_or_else(|| rejected("invalid_git_diff_name_status_z"))?;
            let raw_path =
                std::str::from_utf8(record[1]).map_err(|_| rejected("git_diff_path_not_utf8"))?;
            if raw_path.is_empty() {
                return Err(rejected("invalid_git_diff_name_status_z"));
            }
            let path = normalize_relative_path(raw_path)?;
            let kind = match status {
                'A' => FileStatusKind::Added,
                'D' => FileStatusKind::Deleted,
                _ => FileStatusKind::Modified,
            };
            Ok(StatusFile { path, kind })
        })
        .collect()
}

async fn snapshot_candidate_tree(
    worktree_path: &Path,
    diff_root: &Path,
    candidate_diff_id: CandidateDiffId,
    worktree_head: &str,
) -> Result<String, EngineError> {
    let index_path = diff_root.join(format!(".{candidate_diff_id}.index"));
    let mut lock_path = index_path.as_os_str().to_os_string();
    lock_path.push(".lock");
    let lock_path = PathBuf::from(lock_path);
    let result = async {
        git_status_with_index(worktree_path, &index_path, &["read-tree", worktree_head]).await?;
        git_status_with_index(worktree_path, &index_path, &["add", "-A", "--"]).await?;
        git_stdout_with_index(worktree_path, &index_path, &["write-tree"]).await
    }
    .await;
    let mut cleanup_error = None;
    for path in [&lock_path, &index_path] {
        if path.exists()
            && let Err(error) = std::fs::remove_file(path)
        {
            cleanup_error = Some(error);
        }
    }
    match (result, cleanup_error) {
        (Ok(_), Some(error)) => Err(error.into()),
        (Err(operation), Some(cleanup)) => Err(rejected(format!(
            "candidate_snapshot_failed:{operation};cleanup_failed:{cleanup}"
        ))),
        (result, _) => result,
    }
}

async fn git_stdout(cwd: &Path, args: &[&str]) -> Result<String, EngineError> {
    Ok(git_stdout_raw(cwd, args).await?.trim().to_owned())
}

async fn git_stdout_with_index(
    cwd: &Path,
    index_path: &Path,
    args: &[&str],
) -> Result<String, EngineError> {
    let output = run_git_with_index(cwd, index_path, args).await?;
    if !output.status.success() {
        return Err(rejected(format!(
            "git_command_failed:{}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

async fn git_stdout_raw(cwd: &Path, args: &[&str]) -> Result<String, EngineError> {
    let output = run_git(cwd, args).await?;
    if !output.status.success() {
        return Err(rejected(format!(
            "git_command_failed:{}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

async fn git_stdout_bounded(
    cwd: &Path,
    args: &[&str],
    limit: usize,
) -> Result<Vec<u8>, EngineError> {
    let mut command = Command::new("git");
    command
        .args(args)
        .current_dir(cwd)
        .kill_on_drop(true)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn()?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| rejected("git_stdout_pipe_missing"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| rejected("git_stderr_pipe_missing"))?;
    let mut stdout_task = tokio::spawn(read_bounded(stdout, limit));
    let mut stderr_task = tokio::spawn(read_bounded(stderr, MAX_GIT_STDERR_BYTES));
    let mut wait_task = tokio::spawn(async move { child.wait().await });
    let outcome = timeout(StdDuration::from_secs(GIT_TIMEOUT_SECONDS), async {
        let stdout = (&mut stdout_task)
            .await
            .map_err(|error| rejected(format!("git_stdout_join_failed:{error}")))??;
        if stdout.len() > limit {
            return Err(rejected("git_diff_output_exceeds_hard_limit"));
        }
        let stderr = (&mut stderr_task)
            .await
            .map_err(|error| rejected(format!("git_stderr_join_failed:{error}")))??;
        if stderr.len() > MAX_GIT_STDERR_BYTES {
            return Err(rejected("git_stderr_exceeds_hard_limit"));
        }
        let status = (&mut wait_task)
            .await
            .map_err(|error| rejected(format!("git_wait_join_failed:{error}")))??;
        if !status.success() {
            return Err(rejected(format!(
                "git_command_failed:{}",
                String::from_utf8_lossy(&stderr).trim()
            )));
        }
        Ok(stdout)
    })
    .await;
    abort_join_task(&mut stdout_task).await;
    abort_join_task(&mut stderr_task).await;
    abort_join_task(&mut wait_task).await;
    outcome.map_err(|_| rejected("git_command_timeout"))?
}

async fn read_bounded<R>(reader: R, limit: usize) -> std::io::Result<Vec<u8>>
where
    R: AsyncRead + Unpin,
{
    let mut reader = reader.take(limit.saturating_add(1) as u64);
    let mut bytes = Vec::with_capacity(limit.min(64 * 1024).saturating_add(1));
    reader.read_to_end(&mut bytes).await?;
    Ok(bytes)
}

async fn abort_join_task<T>(task: &mut tokio::task::JoinHandle<T>) {
    if !task.is_finished() {
        task.abort();
        let _ = task.await;
    }
}

async fn git_status(cwd: &Path, args: &[&str]) -> Result<(), EngineError> {
    let output = run_git(cwd, args).await?;
    if !output.status.success() {
        return Err(rejected(format!(
            "git_command_failed:{}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    Ok(())
}

async fn git_status_with_index(
    cwd: &Path,
    index_path: &Path,
    args: &[&str],
) -> Result<(), EngineError> {
    let output = run_git_with_index(cwd, index_path, args).await?;
    if !output.status.success() {
        return Err(rejected(format!(
            "git_command_failed:{}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    Ok(())
}

async fn run_git(cwd: &Path, args: &[&str]) -> Result<std::process::Output, EngineError> {
    let mut command = Command::new("git");
    command
        .args(args)
        .current_dir(cwd)
        .kill_on_drop(true)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    timeout(
        StdDuration::from_secs(GIT_TIMEOUT_SECONDS),
        command.output(),
    )
    .await
    .map_err(|_| rejected("git_command_timeout"))?
    .map_err(EngineError::from)
}

async fn run_git_with_index(
    cwd: &Path,
    index_path: &Path,
    args: &[&str],
) -> Result<std::process::Output, EngineError> {
    let mut command = Command::new("git");
    command
        .args(args)
        .current_dir(cwd)
        .env("GIT_INDEX_FILE", path_for_git(index_path))
        .kill_on_drop(true)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    timeout(
        StdDuration::from_secs(GIT_TIMEOUT_SECONDS),
        command.output(),
    )
    .await
    .map_err(|_| rejected("git_command_timeout"))?
    .map_err(EngineError::from)
}

fn candidate_completion_decision(
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

fn rejected(reason: impl Into<String>) -> EngineError {
    EngineError::ServiceNotReady {
        service: "worktree".to_owned(),
        reason: reason.into(),
    }
}
