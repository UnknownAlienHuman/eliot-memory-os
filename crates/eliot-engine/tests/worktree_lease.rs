#![allow(clippy::expect_used, clippy::unwrap_used)]

use eliot_engine::{
    AgentSessionService, CandidateCompletionContext, CandidateDiffCaptureInput,
    CandidateDiffService, CandidatePatchRequestInput, CandidateReviewInput, CandidateReviewService,
    CompletionGate, PatchRunner, PatchRunnerInput, VerifierHarness, WorkClaimRequest,
    WorkCreateRequest, WorkLeaseService, WorkQueueService, WorkState, WorktreeCleanupService,
    WorktreeCreateInput, WorktreeLeaseService, codecortex_report_ref, default_work_scope,
};
use eliot_types::{
    ActionLease, ActionScope, AgentRole, AgentSessionId, CandidateDiffId, CandidateDiffStatus,
    CandidateReviewDecision, CodeCortexReport, CodeEvidenceSource, CompletionAcceptanceItem,
    CompletionProof, CompletionStatus, DiagnosticEvidence, FileEvidence, InvariantCard,
    LeaseDecision, LeaseStatus, PatchRunStatus, ProjectId, ReceiptId, SymbolEvidence, TaskId,
    VerifierCommandKind, VerifierEvidence, VerifierPlan, VerifierRequirement, VerifierRun,
    VerifierStatus, WorkLeaseDecisionKind, WorktreeLeaseRequest, WorktreeLeaseRequestId,
    WorktreeLeaseState, WriteId, WriteReceiptRef,
};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[tokio::test]
async fn worktree_requires_active_work_lease() -> TestResult {
    let mut bundle = Bundle::new("requires-active-work-lease", &["src/lib.rs"])?;
    let mut request = bundle.worktree_request();
    request.work_lease_id = eliot_types::WorkLeaseId::new_v7();
    let input = bundle.create_input(request);
    let result = WorktreeLeaseService.create(&mut bundle.state, input).await;

    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("missing_work_lease")
    );
    Ok(())
}

#[tokio::test]
async fn worktree_scope_must_be_subset_of_work_lease() -> TestResult {
    let mut bundle = Bundle::new("scope-subset", &["src/lib.rs"])?;
    let mut request = bundle.worktree_request();
    request.requested_scope.write_set = vec!["src/other.rs".to_owned()];
    let input = bundle.create_input(request);
    let result = WorktreeLeaseService.create(&mut bundle.state, input).await;

    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("worktree_write_scope_not_subset_of_work_lease")
    );
    Ok(())
}

#[tokio::test]
async fn worktree_created_outside_controller_tree() -> TestResult {
    let mut bundle = Bundle::new("outside-controller-tree", &["src/lib.rs"])?;
    let lease = bundle.create_worktree().await?;
    let repo_root = fs::canonicalize(&bundle.repo_root)?;
    let worktree_path = fs::canonicalize(&lease.worktree_path)?;

    assert_ne!(repo_root, worktree_path);
    assert!(!worktree_path.starts_with(&repo_root));
    Ok(())
}

#[tokio::test]
async fn worktree_rejects_path_traversal() -> TestResult {
    let mut bundle = Bundle::new("rejects-path-traversal", &["src/lib.rs"])?;
    let mut request = bundle.worktree_request();
    request.requested_scope.write_set = vec!["src/../evil.rs".to_owned()];
    let input = bundle.create_input(request);
    let result = WorktreeLeaseService.create(&mut bundle.state, input).await;

    assert!(result.is_err());
    Ok(())
}

#[tokio::test]
async fn candidate_diff_capture_empty() -> TestResult {
    let mut bundle = Bundle::new("capture-empty", &["src/lib.rs"])?;
    let lease = bundle.create_worktree().await?;
    let diff = bundle.capture(lease.worktree_lease_id, 4096).await?;

    assert_eq!(diff.capture_status, CandidateDiffStatus::Empty);
    assert_eq!(diff.byte_len, 0);
    Ok(())
}

#[tokio::test]
async fn candidate_diff_capture_valid_scoped_change() -> TestResult {
    let mut bundle = Bundle::new("capture-valid-scoped-change", &["src/lib.rs"])?;
    let lease = bundle.create_worktree().await?;
    fs::write(
        PathBuf::from(&lease.worktree_path).join("src/lib.rs"),
        "pub fn value() -> u32 { 2 }\n",
    )?;
    let diff = bundle.capture(lease.worktree_lease_id, 4096).await?;

    assert_eq!(diff.capture_status, CandidateDiffStatus::Captured);
    assert_eq!(diff.changed_files, vec!["src/lib.rs"]);
    assert!(fs::read_to_string(diff.diff_ref)?.contains("pub fn value() -> u32 { 2 }"));
    Ok(())
}

#[tokio::test]
async fn candidate_diff_capture_committed_only_added_file() -> TestResult {
    let mut bundle = Bundle::new("capture-committed-added", &["src/committed.rs"])?;
    let lease = bundle.create_worktree().await?;
    let worktree_path = PathBuf::from(&lease.worktree_path);
    fs::write(
        worktree_path.join("src/committed.rs"),
        "pub fn committed() {}\n",
    )?;
    run_process(&worktree_path, "git", &["add", "src/committed.rs"])?;
    run_process(&worktree_path, "git", &["commit", "-m", "candidate"])?;

    let diff = bundle.capture(lease.worktree_lease_id, 4096).await?;

    assert_eq!(diff.capture_status, CandidateDiffStatus::Captured);
    assert_eq!(diff.changed_files, vec!["src/committed.rs"]);
    assert_eq!(diff.added_files, vec!["src/committed.rs"]);
    assert!(diff.modified_files.is_empty());
    assert!(diff.deleted_files.is_empty());
    assert_eq!(diff.file_count, 1);
    assert_eq!(
        diff.worktree_head.as_deref(),
        Some(git_head(&worktree_path)?.as_str())
    );
    assert_ne!(
        diff.worktree_head.as_deref(),
        Some(lease.base_commit.as_str())
    );
    assert!(fs::read_to_string(diff.diff_ref)?.contains("pub fn committed() {}"));
    Ok(())
}

#[tokio::test]
async fn candidate_diff_rejects_committed_only_out_of_scope_file() -> TestResult {
    let mut bundle = Bundle::new("capture-committed-out-of-scope", &["src/lib.rs"])?;
    let lease = bundle.create_worktree().await?;
    let worktree_path = PathBuf::from(&lease.worktree_path);
    fs::write(worktree_path.join("src/other.rs"), "pub fn other() {}\n")?;
    run_process(&worktree_path, "git", &["add", "src/other.rs"])?;
    run_process(&worktree_path, "git", &["commit", "-m", "candidate"])?;

    let diff = bundle.capture(lease.worktree_lease_id, 4096).await?;

    assert_eq!(diff.capture_status, CandidateDiffStatus::OutOfScope);
    assert_eq!(diff.changed_files, vec!["src/other.rs"]);
    assert_eq!(diff.added_files, vec!["src/other.rs"]);
    assert_eq!(diff.file_count, 1);
    Ok(())
}

#[tokio::test]
async fn candidate_diff_preserves_unicode_path_identity() -> TestResult {
    let mut bundle = Bundle::new("capture-committed-unicode", &["src/é.rs"])?;
    let lease = bundle.create_worktree().await?;
    let worktree_path = PathBuf::from(&lease.worktree_path);
    fs::write(worktree_path.join("src/é.rs"), "pub fn unicode() {}\n")?;
    run_process(&worktree_path, "git", &["add", "src/é.rs"])?;
    run_process(
        &worktree_path,
        "git",
        &["commit", "-m", "unicode candidate"],
    )?;

    let diff = bundle.capture(lease.worktree_lease_id, 4096).await?;

    assert_eq!(diff.capture_status, CandidateDiffStatus::Captured);
    assert_eq!(diff.changed_files, vec!["src/é.rs"]);
    assert_eq!(diff.added_files, vec!["src/é.rs"]);
    Ok(())
}

#[tokio::test]
async fn candidate_diff_unicode_path_cannot_alias_ascii_scope() -> TestResult {
    let mut bundle = Bundle::new("capture-unicode-alias", &["src/303/251.rs"])?;
    let lease = bundle.create_worktree().await?;
    let worktree_path = PathBuf::from(&lease.worktree_path);
    fs::write(worktree_path.join("src/é.rs"), "pub fn unicode() {}\n")?;
    run_process(&worktree_path, "git", &["add", "src/é.rs"])?;
    run_process(
        &worktree_path,
        "git",
        &["commit", "-m", "unicode candidate"],
    )?;

    let diff = bundle.capture(lease.worktree_lease_id, 4096).await?;

    assert_eq!(diff.capture_status, CandidateDiffStatus::OutOfScope);
    assert_eq!(diff.changed_files, vec!["src/é.rs"]);
    Ok(())
}

#[tokio::test]
async fn candidate_diff_captures_untracked_unicode_from_immutable_tree() -> TestResult {
    let mut bundle = Bundle::new("capture-untracked-unicode", &["src/é.rs"])?;
    let lease = bundle.create_worktree().await?;
    let worktree_path = PathBuf::from(&lease.worktree_path);
    fs::write(worktree_path.join("src/é.rs"), "pub fn unicode() {}\n")?;

    let diff = bundle.capture(lease.worktree_lease_id, 4096).await?;

    assert_eq!(diff.capture_status, CandidateDiffStatus::Captured);
    assert_eq!(diff.changed_files, vec!["src/é.rs"]);
    assert_eq!(diff.added_files, vec!["src/é.rs"]);
    run_process(&worktree_path, "git", &["diff", "--cached", "--quiet"])?;
    Ok(())
}

#[tokio::test]
async fn candidate_diff_uses_delete_add_for_committed_rename() -> TestResult {
    let mut bundle = Bundle::new(
        "capture-committed-rename",
        &["src/lib.rs", "src/renamed.rs"],
    )?;
    let lease = bundle.create_worktree().await?;
    let worktree_path = PathBuf::from(&lease.worktree_path);
    run_process(
        &worktree_path,
        "git",
        &["mv", "src/lib.rs", "src/renamed.rs"],
    )?;
    run_process(&worktree_path, "git", &["commit", "-m", "rename candidate"])?;

    let diff = bundle.capture(lease.worktree_lease_id, 4096).await?;
    let text = fs::read_to_string(&diff.diff_ref)?;

    assert_eq!(diff.capture_status, CandidateDiffStatus::Captured);
    assert_eq!(diff.added_files, vec!["src/renamed.rs"]);
    assert_eq!(diff.deleted_files, vec!["src/lib.rs"]);
    assert_eq!(diff.file_count, 2);
    assert!(text.contains("--- a/src/lib.rs"));
    assert!(text.contains("+++ b/src/renamed.rs"));
    assert!(!text.contains("rename from"));
    Ok(())
}

#[tokio::test]
async fn candidate_diff_rejects_out_of_scope_change() -> TestResult {
    let mut bundle = Bundle::new("capture-out-of-scope", &["src/lib.rs"])?;
    let lease = bundle.create_worktree().await?;
    fs::write(
        PathBuf::from(&lease.worktree_path).join("src/other.rs"),
        "pub fn other() {}\n",
    )?;
    let diff = bundle.capture(lease.worktree_lease_id, 4096).await?;

    assert_eq!(diff.capture_status, CandidateDiffStatus::OutOfScope);
    assert_eq!(diff.changed_files, vec!["src/other.rs"]);
    Ok(())
}

#[tokio::test]
async fn candidate_diff_rejects_too_large_diff() -> TestResult {
    let mut bundle = Bundle::new("capture-too-large", &["src/lib.rs"])?;
    let lease = bundle.create_worktree().await?;
    fs::write(
        PathBuf::from(&lease.worktree_path).join("src/lib.rs"),
        format!(
            "pub fn value() -> &'static str {{ \"{}\" }}\n",
            "x".repeat(512)
        ),
    )?;
    let diff = bundle.capture(lease.worktree_lease_id, 128).await?;

    assert_eq!(diff.capture_status, CandidateDiffStatus::TooLarge);
    assert!(diff.byte_len > 128);
    Ok(())
}

#[tokio::test]
async fn candidate_diff_default_policy_persists_too_large_status() -> TestResult {
    let mut bundle = Bundle::new("capture-default-too-large", &["src/large.txt"])?;
    let lease = bundle.create_worktree().await?;
    let content = "0123456789abcdef0123456789abcdef\n".repeat(5_000);
    fs::write(
        PathBuf::from(&lease.worktree_path).join("src/large.txt"),
        content,
    )?;
    let policy_limit = CandidateDiffService::default_max_diff_bytes();

    let diff = bundle
        .capture(lease.worktree_lease_id, policy_limit)
        .await?;

    assert_eq!(diff.capture_status, CandidateDiffStatus::TooLarge);
    assert!(diff.byte_len > policy_limit);
    assert!(Path::new(&diff.diff_ref).is_file());
    Ok(())
}

#[tokio::test]
async fn candidate_diff_hard_caps_git_output_before_persistence() -> TestResult {
    let mut bundle = Bundle::new("capture-hard-output-limit", &["src/large.txt"])?;
    let lease = bundle.create_worktree().await?;
    let mut content = Vec::with_capacity(17 * 1024 * 1024);
    let line = b"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n";
    while content.len() <= 17 * 1024 * 1024 {
        content.extend_from_slice(line);
    }
    fs::write(
        PathBuf::from(&lease.worktree_path).join("src/large.txt"),
        content,
    )?;

    let result = bundle.capture(lease.worktree_lease_id, usize::MAX).await;

    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("git_diff_output_exceeds_hard_limit")
    );
    assert!(
        fs::read_dir(&bundle.diff_root)?
            .filter_map(Result::ok)
            .all(|entry| entry.path().extension().is_none_or(|value| value != "diff"))
    );
    Ok(())
}

#[tokio::test]
async fn candidate_diff_detects_base_drift() -> TestResult {
    let mut bundle = Bundle::new("capture-base-drift", &["src/lib.rs"])?;
    let lease = bundle.create_worktree().await?;
    fs::write(
        bundle.repo_root.join("src/lib.rs"),
        "pub fn value() -> u32 { 3 }\n",
    )?;
    run_process(&bundle.repo_root, "git", &["add", "."])?;
    run_process(&bundle.repo_root, "git", &["commit", "-m", "drift"])?;
    fs::write(
        PathBuf::from(&lease.worktree_path).join("src/lib.rs"),
        "pub fn value() -> u32 { 2 }\n",
    )?;
    let diff = bundle.capture(lease.worktree_lease_id, 4096).await?;

    assert_eq!(diff.capture_status, CandidateDiffStatus::BaseDrift);
    Ok(())
}

#[tokio::test]
async fn candidate_review_denies_provider_self_review_without_record() -> TestResult {
    let mut bundle = Bundle::new("review-denies-self", &["src/lib.rs"])?;
    let diff = bundle.valid_candidate_diff().await?;
    let result = CandidateReviewService.review(
        &mut bundle.state,
        CandidateReviewInput {
            candidate_diff_id: diff.candidate_diff_id,
            reviewer_session_id: bundle.work_lease.agent_session_id,
            decision: CandidateReviewDecision::AcceptForPatchRunner,
            reasons: vec!["scoped candidate diff".to_owned()],
        },
    );

    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("candidate_review_requires_independent_reviewer")
    );
    assert!(bundle.state.candidate_reviews.is_empty());
    assert_eq!(
        bundle
            .state
            .candidate_diffs
            .iter()
            .find(|candidate| candidate.candidate_diff_id == diff.candidate_diff_id)
            .unwrap()
            .capture_status,
        CandidateDiffStatus::Captured
    );
    Ok(())
}

#[tokio::test]
async fn candidate_review_accepts_independent_controller_for_patchrunner() -> TestResult {
    let mut bundle = Bundle::new("review-independent-controller", &["src/lib.rs"])?;
    let diff = bundle.valid_candidate_diff().await?;
    let controller = AgentSessionId::new_v7();
    let review = CandidateReviewService.review(
        &mut bundle.state,
        CandidateReviewInput {
            candidate_diff_id: diff.candidate_diff_id,
            reviewer_session_id: controller,
            decision: CandidateReviewDecision::AcceptForPatchRunner,
            reasons: vec!["independent controller review".to_owned()],
        },
    )?;

    assert_eq!(review.reviewer_session_id, controller);
    assert_eq!(
        review.decision,
        CandidateReviewDecision::AcceptForPatchRunner
    );
    assert_eq!(
        bundle
            .state
            .candidate_diffs
            .iter()
            .find(|candidate| candidate.candidate_diff_id == diff.candidate_diff_id)
            .unwrap()
            .capture_status,
        CandidateDiffStatus::AcceptedForPatchRunner
    );
    Ok(())
}

#[tokio::test]
async fn candidate_review_rejects_out_of_scope_diff() -> TestResult {
    let mut bundle = Bundle::new("review-rejects-out-of-scope", &["src/lib.rs"])?;
    let lease = bundle.create_worktree().await?;
    fs::write(
        PathBuf::from(&lease.worktree_path).join("src/other.rs"),
        "pub fn other() {}\n",
    )?;
    let diff = bundle.capture(lease.worktree_lease_id, 4096).await?;
    let result = CandidateReviewService.review(
        &mut bundle.state,
        CandidateReviewInput {
            candidate_diff_id: diff.candidate_diff_id,
            reviewer_session_id: AgentSessionId::new_v7(),
            decision: CandidateReviewDecision::AcceptForPatchRunner,
            reasons: Vec::new(),
        },
    );

    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("candidate_diff_not_captured")
    );
    Ok(())
}

#[tokio::test]
async fn candidate_review_does_not_apply_patch_directly() -> TestResult {
    let mut bundle = Bundle::new("review-no-direct-apply", &["src/lib.rs"])?;
    let before = fs::read_to_string(bundle.repo_root.join("src/lib.rs"))?;
    let diff = bundle.valid_candidate_diff().await?;
    let _ = bundle.accept(diff.candidate_diff_id)?;
    let after = fs::read_to_string(bundle.repo_root.join("src/lib.rs"))?;

    assert_eq!(before, after);
    Ok(())
}

#[tokio::test]
async fn patchrunner_applies_accepted_candidate_diff() -> TestResult {
    let mut bundle = Bundle::new("patchrunner-applies-accepted", &["src/lib.rs"])?;
    let (patch_run, verifier_runs, _) = bundle.apply_accepted_candidate().await?;

    assert_eq!(patch_run.status, PatchRunStatus::AppliedVerifierPassed);
    assert!(
        verifier_runs
            .iter()
            .any(|run| run.status == VerifierStatus::Passed)
    );
    assert!(fs::read_to_string(bundle.repo_root.join("src/lib.rs"))?.contains("{ 2 }"));
    Ok(())
}

#[tokio::test]
async fn patch_request_rejects_payload_different_from_reviewed_artifact() -> TestResult {
    let mut bundle = Bundle::new("patch-request-payload-binding", &["src/lib.rs"])?;
    let diff = bundle.valid_candidate_diff().await?;
    let review = bundle.accept(diff.candidate_diff_id)?;
    let accepted_diff = bundle
        .state
        .candidate_diffs
        .iter()
        .find(|candidate| candidate.candidate_diff_id == diff.candidate_diff_id)
        .expect("accepted candidate")
        .clone();
    let action_lease = bundle.action_lease();
    let altered = fs::read_to_string(&accepted_diff.diff_ref)?.replace("{ 2 }", "{ 3 }");

    let result = CandidateReviewService.patch_request(CandidatePatchRequestInput {
        candidate_diff: &accepted_diff,
        review: &review,
        action_lease: &action_lease,
        diff_text: altered,
        codecortex_report_refs: vec![codecortex_report_ref(&bundle.report)],
        verifier_plan_ref: "verifier_plan:worktree-lease".to_owned(),
    });

    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("candidate_diff_payload_mismatch")
    );
    Ok(())
}

#[tokio::test]
async fn patch_request_rejects_tampered_reviewed_artifact() -> TestResult {
    let mut bundle = Bundle::new("patch-request-artifact-binding", &["src/lib.rs"])?;
    let diff = bundle.valid_candidate_diff().await?;
    let review = bundle.accept(diff.candidate_diff_id)?;
    let accepted_diff = bundle
        .state
        .candidate_diffs
        .iter()
        .find(|candidate| candidate.candidate_diff_id == diff.candidate_diff_id)
        .expect("accepted candidate")
        .clone();
    let action_lease = bundle.action_lease();
    let tampered = fs::read_to_string(&accepted_diff.diff_ref)?.replace("{ 2 }", "{ 3 }");
    fs::write(&accepted_diff.diff_ref, &tampered)?;

    let result = CandidateReviewService.patch_request(CandidatePatchRequestInput {
        candidate_diff: &accepted_diff,
        review: &review,
        action_lease: &action_lease,
        diff_text: tampered,
        codecortex_report_refs: vec![codecortex_report_ref(&bundle.report)],
        verifier_plan_ref: "verifier_plan:worktree-lease".to_owned(),
    });

    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("candidate_diff_artifact_hash_mismatch")
    );
    Ok(())
}

#[tokio::test]
async fn completion_requires_candidate_patch_verifiers() -> TestResult {
    let mut bundle = Bundle::new("completion-requires-candidate", &["src/lib.rs"])?;
    let (patch_run, verifier_runs, candidate_diff) = bundle.apply_accepted_candidate().await?;
    let review = bundle
        .state
        .candidate_reviews
        .last()
        .expect("candidate review")
        .clone();
    let proof = completion_proof(&patch_run, &verifier_runs, &candidate_diff, &review);
    let decision = CompletionGate::decide_with_candidate_context(
        &proof,
        CandidateCompletionContext {
            candidate_diff: Some(&candidate_diff),
            candidate_review: Some(&review),
            patch_run: Some(&patch_run),
            verifier_runs: &verifier_runs,
        },
    );
    let missing = CompletionGate::decide_with_candidate_context(
        &proof,
        CandidateCompletionContext {
            candidate_diff: None,
            candidate_review: Some(&review),
            patch_run: Some(&patch_run),
            verifier_runs: &verifier_runs,
        },
    );

    assert_eq!(decision.final_status, CompletionStatus::DoneVerified);
    assert_eq!(missing.final_status, CompletionStatus::PartialProgress);
    Ok(())
}

#[tokio::test]
async fn worktree_cleanup_after_capture() -> TestResult {
    let mut bundle = Bundle::new("cleanup-after-capture", &["src/lib.rs"])?;
    let lease = bundle.create_worktree().await?;
    let path = PathBuf::from(&lease.worktree_path);
    let _ = bundle.capture(lease.worktree_lease_id, 4096).await?;
    let cleaned = WorktreeCleanupService
        .cleanup(&mut bundle.state, lease.worktree_lease_id)
        .await?;

    assert_eq!(cleaned.state, WorktreeLeaseState::Cleaned);
    assert!(!path.exists());
    Ok(())
}

#[tokio::test]
async fn worktree_cleanup_prunes_metadata_when_path_is_already_missing() -> TestResult {
    let mut bundle = Bundle::new("cleanup-prunes-missing-path", &["src/lib.rs"])?;
    let lease = bundle.create_worktree().await?;
    let path = PathBuf::from(&lease.worktree_path);
    let metadata_path = bundle
        .repo_root
        .join(".git/worktrees")
        .join(lease.worktree_lease_id.to_string());
    let _ = bundle.capture(lease.worktree_lease_id, 4096).await?;
    fs::remove_dir_all(&path)?;

    let cleaned = WorktreeCleanupService
        .cleanup(&mut bundle.state, lease.worktree_lease_id)
        .await?;

    assert_eq!(cleaned.state, WorktreeLeaseState::Cleaned);
    assert!(!path.exists());
    assert!(!metadata_path.exists());
    Ok(())
}

#[tokio::test]
async fn worktree_cleanup_refuses_abandoned_path_inside_controller_repo() -> TestResult {
    let mut bundle = Bundle::new("cleanup-refuses-controller-path", &["src/lib.rs"])?;
    let lease = bundle.create_worktree().await?;
    let actual_path = lease.worktree_path.clone();
    let _ = bundle.capture(lease.worktree_lease_id, 4096).await?;
    fs::remove_file(Path::new(&actual_path).join(".git"))?;
    run_process(
        &bundle.repo_root,
        "git",
        &["worktree", "prune", "--expire", "now"],
    )?;
    let controller_path = bundle.repo_root.join(lease.worktree_lease_id.to_string());
    fs::create_dir_all(controller_path.join("target"))?;
    bundle
        .state
        .worktree_leases
        .iter_mut()
        .find(|candidate| candidate.worktree_lease_id == lease.worktree_lease_id)
        .expect("worktree lease")
        .worktree_path = controller_path.display().to_string();

    let result = WorktreeCleanupService
        .cleanup(&mut bundle.state, lease.worktree_lease_id)
        .await;

    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("refuse_worktree_cleanup_inside_controller_repo")
    );
    assert!(controller_path.exists());
    assert_ne!(
        bundle
            .state
            .worktree_leases
            .iter()
            .find(|candidate| candidate.worktree_lease_id == lease.worktree_lease_id)
            .expect("worktree lease")
            .state,
        WorktreeLeaseState::Cleaned
    );

    fs::remove_dir_all(controller_path)?;
    fs::remove_dir_all(actual_path)?;
    Ok(())
}

#[cfg(windows)]
#[tokio::test]
async fn worktree_cleanup_removes_registered_long_path_output() -> TestResult {
    let mut bundle = Bundle::new("cleanup-registered-long-path", &["src/lib.rs"])?;
    let lease = bundle.create_worktree().await?;
    let path = PathBuf::from(&lease.worktree_path);
    let _ = bundle.capture(lease.worktree_lease_id, 4096).await?;
    create_long_ignored_output(&path)?;

    let cleaned = WorktreeCleanupService
        .cleanup(&mut bundle.state, lease.worktree_lease_id)
        .await?;

    assert_eq!(cleaned.state, WorktreeLeaseState::Cleaned);
    assert!(!path.exists());
    Ok(())
}

#[cfg(windows)]
#[tokio::test]
async fn worktree_cleanup_retries_partially_removed_long_path_worktree() -> TestResult {
    let mut bundle = Bundle::new("cleanup-partial-long-path", &["src/lib.rs"])?;
    let lease = bundle.create_worktree().await?;
    let path = PathBuf::from(&lease.worktree_path);
    let metadata_path = bundle
        .repo_root
        .join(".git/worktrees")
        .join(lease.worktree_lease_id.to_string());
    let _ = bundle.capture(lease.worktree_lease_id, 4096).await?;
    create_long_ignored_output(&path)?;
    fs::remove_file(path.join(".git"))?;
    run_process(
        &bundle.repo_root,
        "git",
        &["worktree", "prune", "--expire", "now"],
    )?;
    assert!(!metadata_path.exists());

    let cleaned = WorktreeCleanupService
        .cleanup(&mut bundle.state, lease.worktree_lease_id)
        .await?;

    assert_eq!(cleaned.state, WorktreeLeaseState::Cleaned);
    assert!(!path.exists());
    Ok(())
}

#[tokio::test]
async fn worktree_revoke_blocks_capture() -> TestResult {
    let mut bundle = Bundle::new("revoke-blocks-capture", &["src/lib.rs"])?;
    let lease = bundle.create_worktree().await?;
    let _ = WorktreeCleanupService.revoke(&mut bundle.state, lease.worktree_lease_id)?;
    let result = bundle.capture(lease.worktree_lease_id, 4096).await;

    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("worktree_lease_not_active")
    );
    Ok(())
}

#[test]
fn mcp_exposes_only_governed_worktree_tools() -> TestResult {
    let mcp = fs::read_to_string(repo_root().join("crates/eliot-app/src/mcp_stdio.rs"))?;

    for tool in [
        "eliot_worktree_create",
        "eliot_worktree_status",
        "eliot_worktree_capture_diff",
        "eliot_worktree_review",
        "eliot_worktree_cleanup",
    ] {
        assert!(mcp.contains(tool));
    }
    Ok(())
}

#[test]
fn mcp_exposes_no_raw_git_shell_file_tools() -> TestResult {
    let mcp = fs::read_to_string(repo_root().join("crates/eliot-app/src/mcp_stdio.rs"))?;

    for forbidden in [
        "eliot_raw",
        "eliot_shell",
        "eliot_git",
        "eliot_rg",
        "eliot_astgrep",
        "eliot_file_read",
        "eliot_file_write",
    ] {
        assert!(!mcp.contains(forbidden));
    }
    Ok(())
}

#[test]
fn accumulated_capabilities_non_regression() -> TestResult {
    let repo = repo_root();
    let context = fs::read_to_string(repo.join("crates/eliot-engine/src/context.rs"))?;
    let patch = fs::read_to_string(repo.join("crates/eliot-engine/src/patch.rs"))?;
    let work = fs::read_to_string(repo.join("crates/eliot-engine/src/work.rs"))?;
    let mcp = fs::read_to_string(repo.join("crates/eliot-app/src/mcp_stdio.rs"))?;

    assert!(context.contains("pub struct CognitiveGate"));
    assert!(patch.contains("pub struct PatchRunner"));
    assert!(work.contains("pub struct WorkLeaseService"));
    assert!(mcp.contains("eliot_codecortex_scan"));
    assert!(!mcp.contains("eliot_shell"));
    assert!(!mcp.contains("eliot_git"));
    Ok(())
}

struct Bundle {
    repo_root: PathBuf,
    worktree_root: PathBuf,
    diff_root: PathBuf,
    state: WorkState,
    work_lease: eliot_types::WorkLease,
    report: CodeCortexReport,
    verifier_plan: VerifierPlan,
}

impl Bundle {
    fn new(name: &str, write_set: &[&str]) -> TestResult<Self> {
        let repo_root = fixture_repo(name)?;
        let worktree_root = repo_root
            .parent()
            .and_then(Path::parent)
            .unwrap_or_else(|| Path::new("."))
            .join("worktree-leases")
            .join(name);
        if worktree_root.exists() {
            fs::remove_dir_all(&worktree_root)?;
        }
        let diff_root = repo_root
            .parent()
            .and_then(Path::parent)
            .unwrap_or_else(|| Path::new("."))
            .join("worktree-lease-candidate-diffs")
            .join(name);
        if diff_root.exists() {
            fs::remove_dir_all(&diff_root)?;
        }
        let mut state = WorkState::default();
        let project_id = ProjectId::new_v7();
        let task_id = TaskId::new_v7();
        let session = AgentSessionService.create_controller(&mut state, project_id);
        let write_set = write_set
            .iter()
            .map(|path| (*path).to_owned())
            .collect::<Vec<_>>();
        let verifier_plan = verifier_plan();
        let item = WorkQueueService.create_work_item(
            &mut state,
            WorkCreateRequest {
                project_id,
                task_id,
                project: "worktree-lease-fixture".to_owned(),
                task: name.to_owned(),
                goal: "Exercise WorktreeLease candidate diff governance".to_owned(),
                scope: default_work_scope(
                    repo_root.display().to_string(),
                    write_set.clone(),
                    write_set,
                    vec!["cargo check".to_owned()],
                ),
                required: true,
                created_by: session.agent_session_id,
                required_verifiers: verifier_plan.required.clone(),
            },
        );
        let decision = WorkLeaseService.claim(
            &mut state,
            WorkClaimRequest {
                work_item_id: item.work_item_id,
                agent_session_id: session.agent_session_id,
                role: AgentRole::Implementer,
                ttl_minutes: 60,
            },
        );
        assert_eq!(decision.kind, WorkLeaseDecisionKind::Granted);
        let work_lease_id = decision.work_lease_id.expect("work lease id");
        let work_lease = state
            .leases
            .iter()
            .find(|lease| lease.work_lease_id == work_lease_id)
            .expect("granted work lease")
            .clone();
        let report = report(&repo_root)?;
        Ok(Self {
            repo_root,
            worktree_root,
            diff_root,
            state,
            work_lease,
            report,
            verifier_plan,
        })
    }

    fn worktree_request(&self) -> WorktreeLeaseRequest {
        WorktreeLeaseRequest {
            request_id: WorktreeLeaseRequestId::new_v7(),
            project_id: self.work_lease.project_id,
            task_id: self.work_lease.task_id,
            work_item_id: self.work_lease.work_item_id,
            work_lease_id: self.work_lease.work_lease_id,
            agent_session_id: self.work_lease.agent_session_id,
            repo_root: self.repo_root.display().to_string(),
            requested_branch_name: None,
            requested_scope: self.work_lease.scope.clone(),
            base_commit: Some(git_head(&self.repo_root).expect("git head")),
            created_at: time::OffsetDateTime::now_utc(),
        }
    }

    fn create_input(&self, request: WorktreeLeaseRequest) -> WorktreeCreateInput {
        WorktreeCreateInput {
            request,
            worktree_root: self.worktree_root.clone(),
            ttl_minutes: WorktreeLeaseService::default_ttl_minutes(),
        }
    }

    async fn create_worktree(&mut self) -> TestResult<eliot_types::WorktreeLease> {
        let request = self.worktree_request();
        let input = self.create_input(request);
        WorktreeLeaseService
            .create(&mut self.state, input)
            .await
            .map_err(Into::into)
    }

    async fn capture(
        &mut self,
        worktree_lease_id: eliot_types::WorktreeLeaseId,
        max_diff_bytes: usize,
    ) -> TestResult<eliot_types::CandidateDiff> {
        CandidateDiffService
            .capture(
                &mut self.state,
                CandidateDiffCaptureInput {
                    worktree_lease_id,
                    diff_root: self.diff_root.clone(),
                    max_diff_bytes,
                },
            )
            .await
            .map_err(Into::into)
    }

    async fn valid_candidate_diff(&mut self) -> TestResult<eliot_types::CandidateDiff> {
        let lease = self.create_worktree().await?;
        fs::write(
            PathBuf::from(&lease.worktree_path).join("src/lib.rs"),
            "pub fn value() -> u32 { 2 }\n",
        )?;
        self.capture(lease.worktree_lease_id, 4096).await
    }

    fn accept(
        &mut self,
        candidate_diff_id: CandidateDiffId,
    ) -> TestResult<eliot_types::CandidateReview> {
        CandidateReviewService
            .review(
                &mut self.state,
                CandidateReviewInput {
                    candidate_diff_id,
                    reviewer_session_id: AgentSessionId::new_v7(),
                    decision: CandidateReviewDecision::AcceptForPatchRunner,
                    reasons: vec!["scoped candidate diff".to_owned()],
                },
            )
            .map_err(Into::into)
    }

    async fn apply_accepted_candidate(
        &mut self,
    ) -> TestResult<(
        eliot_types::PatchRun,
        Vec<VerifierRun>,
        eliot_types::CandidateDiff,
    )> {
        let diff = self.valid_candidate_diff().await?;
        let review = self.accept(diff.candidate_diff_id)?;
        self.state
            .candidate_diffs
            .iter_mut()
            .find(|candidate| candidate.candidate_diff_id == diff.candidate_diff_id)
            .expect("accepted candidate diff")
            .write_receipt = Some(receipt_ref());
        self.state
            .candidate_reviews
            .iter_mut()
            .find(|candidate_review| candidate_review.review_id == review.review_id)
            .expect("accepted candidate review")
            .write_receipt = Some(receipt_ref());
        let accepted_diff = self
            .state
            .candidate_diffs
            .iter()
            .find(|candidate| candidate.candidate_diff_id == diff.candidate_diff_id)
            .expect("accepted candidate diff")
            .clone();
        let action_lease = self.action_lease();
        let diff_text = fs::read_to_string(&accepted_diff.diff_ref)?;
        let request = CandidateReviewService.patch_request(CandidatePatchRequestInput {
            candidate_diff: &accepted_diff,
            review: &review,
            action_lease: &action_lease,
            diff_text,
            codecortex_report_refs: vec![codecortex_report_ref(&self.report)],
            verifier_plan_ref: "verifier_plan:worktree-lease".to_owned(),
        })?;
        let runner = PatchRunner::new(&self.repo_root, None);
        let verifier = VerifierHarness::new(&self.repo_root, None);
        let (mut patch_run, mut verifier_runs) = runner
            .apply(
                &PatchRunnerInput {
                    request: &request,
                    lease: Some(&action_lease),
                    work_lease: Some(&self.work_lease),
                    codecortex_reports: std::slice::from_ref(&self.report),
                    verifier_plan: Some(&self.verifier_plan),
                    incident_lockdown_active: false,
                },
                &verifier,
            )
            .await?;
        patch_run.write_receipt = Some(receipt_ref());
        for verifier_run in &mut verifier_runs {
            verifier_run.write_receipt = Some(receipt_ref());
        }
        Ok((patch_run, verifier_runs, accepted_diff))
    }

    fn action_lease(&self) -> ActionLease {
        ActionLease {
            lease_id: eliot_types::ActionLeaseId::new_v7(),
            request_id: eliot_types::ActionRequestId::new_v7(),
            project_id: self.work_lease.project_id,
            task_id: self.work_lease.task_id,
            agent_id: self.work_lease.agent_id,
            decision: LeaseDecision::AllowPatchExecution,
            status: LeaseStatus::ApprovedForExecution,
            allowed_scope: Some(ActionScope {
                repo_root: self.repo_root.display().to_string(),
                git_head: Some(git_head(&self.repo_root).expect("git head")),
                allowed_files: vec!["src/lib.rs".to_owned()],
                allowed_symbols: Vec::new(),
                forbidden_files: Vec::new(),
                max_files: 1,
                max_diff_bytes: 4096,
                max_runtime_seconds: 60,
            }),
            change_plan: None,
            verifier_plan: Some(self.verifier_plan.clone()),
            skill_refs: Vec::new(),
            denial_reasons: Vec::new(),
            expires_at: Some(time::OffsetDateTime::now_utc() + time::Duration::hours(1)),
            created_at: time::OffsetDateTime::now_utc(),
        }
    }
}

fn fixture_repo(name: &str) -> TestResult<PathBuf> {
    let target = repo_root().join("target").join("worktree-lease-fixtures");
    fs::create_dir_all(&target)?;
    let repo = target.join(name);
    if repo.exists() {
        if !repo.starts_with(&target) {
            return Err("refusing to remove fixture outside target".into());
        }
        fs::remove_dir_all(&repo)?;
    }
    fs::create_dir_all(repo.join("src"))?;
    fs::write(
        repo.join("Cargo.toml"),
        concat!(
            "[package]\n",
            "name = \"worktree-lease-test-fixture\"\n",
            "version = \"0.1.0\"\n",
            "edition = \"2024\"\n\n",
            "[workspace]\n"
        ),
    )?;
    fs::write(repo.join("src/lib.rs"), "pub fn value() -> u32 { 1 }\n")?;
    fs::write(repo.join(".gitignore"), "target/\n")?;
    run_process(&repo, "git", &["init"])?;
    run_process(
        &repo,
        "git",
        &["config", "user.email", "eliot@example.invalid"],
    )?;
    run_process(&repo, "git", &["config", "user.name", "Eliot Governor"])?;
    run_process(&repo, "git", &["add", "."])?;
    run_process(&repo, "git", &["commit", "-m", "init"])?;
    Ok(repo)
}

#[cfg(windows)]
fn create_long_ignored_output(worktree_path: &Path) -> TestResult {
    let mut output = worktree_path.join("target");
    for index in 0..4 {
        output = output.join(format!("provider-build-output-{index}-{}", "x".repeat(48)));
    }
    fs::create_dir_all(&output)?;
    let artifact = output.join("artifact.rlib");
    fs::write(&artifact, b"ignored provider output")?;
    assert!(artifact.as_os_str().to_string_lossy().len() > 260);
    Ok(())
}

fn report(repo_root: &Path) -> TestResult<CodeCortexReport> {
    let evidence = FileEvidence {
        path: "src/lib.rs".to_owned(),
        content_hash: Some("fixture-hash".to_owned()),
        line_start: Some(1),
        line_end: Some(1),
        excerpt: "pub fn value() -> u32 { 1 }".to_owned(),
        source: CodeEvidenceSource::Rg,
    };
    Ok(CodeCortexReport {
        project: "worktree-lease-fixture".to_owned(),
        task: "worktree-lease-test".to_owned(),
        goal: "Patch src/lib.rs through candidate diff".to_owned(),
        generated_at: time::OffsetDateTime::now_utc(),
        repo_root: repo_root.display().to_string(),
        git_head: Some(git_head(repo_root)?),
        dirty: false,
        scope_binding: eliot_types::CodeCortexScopeBinding::default(),
        tracked_files: vec![evidence.clone()],
        workspace_members: vec![repo_root.display().to_string()],
        crates: vec!["worktree-lease-test-fixture".to_owned()],
        targets: vec!["worktree_lease_test_fixture".to_owned()],
        file_evidence: vec![evidence],
        symbol_evidence: vec![SymbolEvidence {
            name: "value".to_owned(),
            kind: "fn".to_owned(),
            path: "src/lib.rs".to_owned(),
            line: Some(1),
            source: CodeEvidenceSource::Rg,
        }],
        diagnostic_evidence: vec![DiagnosticEvidence {
            source: CodeEvidenceSource::Diagnostics,
            status: "clean".to_owned(),
            path: None,
            line: None,
            severity: "info".to_owned(),
            message: "fixture initialized".to_owned(),
        }],
        verifier_evidence: vec![VerifierEvidence {
            name: "fixture".to_owned(),
            command: "cargo check".to_owned(),
            status: "ready".to_owned(),
            summary: "fixture ready".to_owned(),
            source: CodeEvidenceSource::Diagnostics,
        }],
        blast_radius: eliot_types::BlastRadiusView {
            files: vec!["src/lib.rs".to_owned()],
            crates: vec!["worktree-lease-test-fixture".to_owned()],
            reasons: vec!["test fixture".to_owned()],
        },
        invariant_cards: vec![InvariantCard {
            name: "bounded_scope".to_owned(),
            status: "enforced".to_owned(),
            evidence: "src/lib.rs only".to_owned(),
        }],
        evidence_sources: vec![CodeEvidenceSource::Rg, CodeEvidenceSource::Diagnostics],
        adapter_notes: Vec::new(),
        memory_receipt: None,
        operation_status: eliot_types::OperationStatus::OperationCompleted,
    })
}

fn verifier_plan() -> VerifierPlan {
    VerifierPlan {
        required: vec![VerifierRequirement {
            name: "cargo-check".to_owned(),
            command_kind: VerifierCommandKind::CargoCheck,
            command_display: "cargo check".to_owned(),
            scope: vec!["src/lib.rs".to_owned()],
            required_for_done: true,
            expected_signal: "fixture type-checks".to_owned(),
        }],
        optional: Vec::new(),
        acceptance_items: vec!["candidate diff applies and cargo check passes".to_owned()],
    }
}

fn completion_proof(
    patch_run: &eliot_types::PatchRun,
    verifier_runs: &[VerifierRun],
    candidate_diff: &eliot_types::CandidateDiff,
    candidate_review: &eliot_types::CandidateReview,
) -> CompletionProof {
    CompletionProof {
        task_id: patch_run.task_id.to_string(),
        project_id: patch_run.project_id,
        goal: "Patch src/lib.rs through candidate diff".to_owned(),
        changed_files: patch_run.changed_files.clone(),
        memory_refs_used: vec![
            format!("candidate_diff:{}", candidate_diff.candidate_diff_id),
            format!("patch_run:{}", patch_run.patch_run_id),
        ],
        checks_run: verifier_runs.iter().map(|run| run.name.clone()).collect(),
        checks_not_run: Vec::new(),
        acceptance_items: vec![CompletionAcceptanceItem {
            item: "candidate diff applies and cargo check passes".to_owned(),
            status: "verified".to_owned(),
            evidence: format!("candidate_diff:{}", candidate_diff.candidate_diff_id),
            verifier: "cargo-check".to_owned(),
            residual_uncertainty: "none".to_owned(),
        }],
        evidence: std::iter::once(format!(
            "candidate_diff:{}",
            candidate_diff.candidate_diff_id
        ))
        .chain(std::iter::once(format!(
            "patch_run:{}",
            patch_run.patch_run_id
        )))
        .chain(std::iter::once(format!(
            "candidate_review:{}",
            candidate_review.review_id
        )))
        .chain(
            verifier_runs
                .iter()
                .map(|run| format!("verifier_run:{}", run.verifier_run_id)),
        )
        .collect(),
        skill_refs: Vec::new(),
        skill_execution_proof_refs: Vec::new(),
        residual_uncertainty: "none".to_owned(),
        known_risks: Vec::new(),
    }
}

fn receipt_ref() -> WriteReceiptRef {
    WriteReceiptRef {
        receipt_id: ReceiptId::new_v7(),
        write_id: WriteId::new_v7(),
    }
}

fn git_head(repo_root: &Path) -> TestResult<String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(repo_root)
        .arg("rev-parse")
        .arg("HEAD")
        .output()?;
    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).to_string().into());
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

fn run_process(cwd: &Path, program: &str, args: &[&str]) -> TestResult {
    let output = Command::new(program).args(args).current_dir(cwd).output()?;
    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).to_string().into());
    }
    Ok(())
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .unwrap_or_else(|| Path::new("."))
        .to_path_buf()
}
