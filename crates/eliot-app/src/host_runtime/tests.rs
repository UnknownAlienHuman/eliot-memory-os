use super::{
    CanonicalAuthorityBody, CanonicalBodyNormalization, ExistingManagedInvocation,
    MANAGED_ATTEMPT_SCHEMA_V4, ManagedHostAttemptJournal, ManagedInvocationLock,
    ManagedInvocationLockRecord, ManagedLaunchBoundaryAttestation, ManagedSanitizedEnvironment,
    ManagedWorktreeSnapshot, assert_managed_path_is_local_and_private, candidate_unified_diff_hash,
    configure_antigravity_environment, configure_standard_managed_environment,
    encode_managed_invocation_lock, hash_bytes, hash_file_content, hash_json, integration_refs,
    invocation_root, invocation_status, is_claude_desktop_host,
    latest_canonical_authority_observation, launch_argv, managed_attempt_hash,
    managed_launch_boundary_attestation, managed_launch_boundary_is_current, managed_sandbox_root,
    merge_opencode_mcp_config, normalize_relative_path, parse_opencode_jsonc,
    provider_start_marker_path, receipt_ref_from_option, reconcile_existing_managed_invocation,
    registry_entry_by_manifest, remaining_to_deadline, remove_opencode_mcp_config,
    sanitize_managed_output, stable_invocation_id, validate_antigravity_scope,
    validate_attempt_journal, validate_canonical_observation_identity,
    validate_managed_result_integrity,
};
use crate::runtime_instance::{atomic_write_bytes, atomic_write_json};
use eliot_engine::{HostLaunchContractService, WorkState, default_work_scope};
use eliot_store::CanonicalToolObservation;
use eliot_types::{
    AgentCapabilityEnvelope, AgentHostId, AgentHostIdentity, AgentHostRuntimeProfile, AgentId,
    AgentRole, AgentSessionHostBinding, AgentSessionId, DelegationState, HostLaunchScope, HostMode,
    HostProfileStatus, HostProtocolSurfaces, MemoryRevision, ProjectId, ProjectSequence, ReceiptId,
    SemanticCommandKind, TaskId, TaskRoleLease, WorkItemId, WorkLease, WorkLeaseDecision,
    WorkLeaseDecisionKind, WorkLeaseDecisionReason, WorkLeaseId, WorkLeaseState, WorktreeLease,
    WorktreeLeaseId, WorktreeLeaseState, WriteId, WriteReceipt, WriteReceiptRef, WriteStatus,
};
use serde_json::{Value, json};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};
use time::OffsetDateTime;

fn eliot_entry() -> Value {
    json!({
        "type": "local",
        "command": ["C:/Eliot/eliot-governor.exe", "mcp", "stdio"],
        "enabled": true,
        "timeout": 30000
    })
}

fn instruction_entry() -> &'static str {
    "C:/Eliot/instructions/eliot-governor.md"
}

fn write_stale_managed_lock(root: &Path) -> anyhow::Result<()> {
    std::fs::create_dir_all(root)?;
    atomic_write_bytes(
        &root.join("dispatch.lock"),
        &encode_managed_invocation_lock(ManagedInvocationLockRecord {
            owner_pid: 0,
            created_unix_seconds: u64::try_from(
                (OffsetDateTime::now_utc() - time::Duration::minutes(1)).unix_timestamp(),
            )?,
        }),
    )?;
    Ok(())
}

struct ScopeFixture {
    root: PathBuf,
    cwd: PathBuf,
    delegation: DelegationState,
    work: WorkState,
    scope: HostLaunchScope,
}

#[derive(Clone, Copy)]
struct ScopeFixtureIds {
    project: ProjectId,
    task: TaskId,
    work_item: WorkItemId,
    session: AgentSessionId,
    work_lease: WorkLeaseId,
    worktree_lease: WorktreeLeaseId,
}

const ROLE_LEASE_ID: &str = "role:agy-worker";

impl Drop for ScopeFixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn fixture_delegation(ids: ScopeFixtureIds, now: OffsetDateTime) -> DelegationState {
    let mut delegation = DelegationState::default();
    delegation
        .agent_host_sessions
        .push(AgentSessionHostBinding {
            agent_session_id: ids.session,
            host_identity: AgentHostIdentity {
                host_id: AgentHostId::Antigravity,
                implementation_name: "Google Antigravity".to_owned(),
                client_instance_id: "agy-fixture".to_owned(),
            },
            capability_envelope: AgentCapabilityEnvelope {
                capabilities: vec!["lease_scoped_candidate_implementation".to_owned()],
                structured_output: true,
                supervised: true,
                ..AgentCapabilityEnvelope::default()
            },
            bound_project_id: Some(ids.project),
            bound_task_id: Some(ids.task),
            task_role_lease_refs: vec![ROLE_LEASE_ID.to_owned()],
        });
    delegation.task_role_leases.push(TaskRoleLease {
        role_lease_id: ROLE_LEASE_ID.to_owned(),
        task_id: ids.task,
        agent_session_id: ids.session,
        role: AgentRole::Implementer,
        capability_scope: vec!["bounded_write".to_owned()],
        expires_at: now + time::Duration::minutes(30),
        epoch: 1,
    });
    delegation
}

fn fixture_work(
    ids: ScopeFixtureIds,
    root: &Path,
    cwd: &Path,
    write_set: &[String],
    base_commit: &str,
    now: OffsetDateTime,
) -> WorkState {
    let mut work = WorkState::default();
    work.leases.push(WorkLease {
        work_lease_id: ids.work_lease,
        work_item_id: ids.work_item,
        agent_session_id: ids.session,
        agent_id: AgentId::new_v7(),
        project_id: ids.project,
        task_id: ids.task,
        role: AgentRole::Implementer,
        state: WorkLeaseState::Granted,
        epoch: 1,
        scope: default_work_scope(
            root.to_string_lossy(),
            vec!["scripts".to_owned()],
            write_set.to_vec(),
            vec!["cargo test".to_owned()],
        ),
        decision: WorkLeaseDecision {
            kind: WorkLeaseDecisionKind::Granted,
            reason: WorkLeaseDecisionReason::NoConflict,
            message: "fixture".to_owned(),
            work_lease_id: Some(ids.work_lease),
            conflicting_lease_ids: Vec::new(),
            expires_at: Some(now + time::Duration::minutes(30)),
        },
        conflict_refs: Vec::new(),
        granted_at: now,
        expires_at: now + time::Duration::minutes(30),
        renewed_at: None,
        released_at: None,
        revoked_at: None,
        write_receipt: None,
    });
    work.worktree_leases.push(WorktreeLease {
        worktree_lease_id: ids.worktree_lease,
        project_id: ids.project,
        task_id: ids.task,
        work_item_id: ids.work_item,
        work_lease_id: ids.work_lease,
        holder_session_id: ids.session,
        repo_root: root.to_string_lossy().into_owned(),
        worktree_path: cwd.to_string_lossy().into_owned(),
        branch_name: "codex/agy-fixture".to_owned(),
        base_commit: base_commit.to_owned(),
        allowed_read_set: vec!["scripts".to_owned()],
        allowed_write_set: write_set.to_vec(),
        state: WorktreeLeaseState::Active,
        issued_at: now,
        expires_at: now + time::Duration::minutes(30),
        cleaned_at: None,
        write_receipt: None,
    });
    work
}

fn scope_fixture() -> anyhow::Result<ScopeFixture> {
    let now = OffsetDateTime::now_utc();
    let local = std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .ok_or_else(|| anyhow::anyhow!("LOCALAPPDATA"))?;
    let root = local
        .join("Eliot")
        .join("tests")
        .join(format!("eliot-agy-host-{}", TaskId::new_v7()));
    let cwd = root.join("worktree");
    std::fs::create_dir_all(&cwd)?;
    std::fs::write(cwd.join("README.md"), "governed fixture\n")?;
    for args in [
        vec!["init"],
        vec!["config", "user.email", "eliot-fixture@example.invalid"],
        vec!["config", "user.name", "Eliot Fixture"],
        vec!["add", "README.md"],
        vec!["commit", "-m", "fixture baseline"],
    ] {
        let output = Command::new("git").current_dir(&cwd).args(args).output()?;
        if !output.status.success() {
            anyhow::bail!(
                "git fixture setup failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }
    let output = Command::new("git")
        .current_dir(&cwd)
        .args(["rev-parse", "HEAD"])
        .output()?;
    let base_commit = String::from_utf8(output.stdout)?.trim().to_owned();
    let ids = ScopeFixtureIds {
        project: ProjectId::new_v7(),
        task: TaskId::new_v7(),
        work_item: WorkItemId::new_v7(),
        session: AgentSessionId::new_v7(),
        work_lease: WorkLeaseId::new_v7(),
        worktree_lease: WorktreeLeaseId::new_v7(),
    };
    let write_set = vec!["scripts/cognitive-contract".to_owned()];
    let delegation = fixture_delegation(ids, now);
    let work = fixture_work(ids, &root, &cwd, &write_set, &base_commit, now);
    Ok(ScopeFixture {
        root,
        cwd,
        delegation,
        work,
        scope: HostLaunchScope {
            project_id: Some(ids.project),
            agent_session_id: Some(ids.session),
            task_id: Some(ids.task),
            work_item_id: Some(ids.work_item),
            role_lease_id: Some(ROLE_LEASE_ID.to_owned()),
            work_lease_id: Some(ids.work_lease),
            worktree_lease_id: Some(ids.worktree_lease),
            planned_verifier_ref: Some(
                crate::mcp_stdio::RegisteredTaskVerifier::ReceiptResolution.reference(),
            ),
            baseline_commit: Some(base_commit),
            allowed_paths: write_set,
            forbidden_paths: Vec::new(),
        },
    })
}

fn require_error<T>(result: anyhow::Result<T>, message: &str) -> anyhow::Result<anyhow::Error> {
    match result {
        Ok(_) => anyhow::bail!(message.to_owned()),
        Err(error) => Ok(error),
    }
}

fn antigravity_profile() -> AgentHostRuntimeProfile {
    AgentHostRuntimeProfile {
        host_id: AgentHostId::Antigravity,
        implementation_name: "Google Antigravity".to_owned(),
        executable_path: "C:/Profiles/test/AppData/Local/agy/bin/agy.exe".to_owned(),
        executable_hash: "blake3:fixture".to_owned(),
        version: "1.1.3".to_owned(),
        discovered_at: OffsetDateTime::now_utc(),
        supported_modes: vec!["supervised_noninteractive".to_owned()],
        protocol_surfaces: HostProtocolSurfaces {
            mcp_stdio: true,
            structured_output: true,
            worktree: true,
            permissions: true,
            ..HostProtocolSurfaces::default()
        },
        launch_capabilities: vec!["lease_scoped_candidate_implementation".to_owned()],
        result_capture: vec!["governor_launch_receipt".to_owned()],
        resume_contract: "no blind retry".to_owned(),
        timeout_and_unknown_outcome_contract: "reconcile before retry".to_owned(),
        known_version_constraints: Vec::new(),
        operator_configuration_refs: Vec::new(),
        capability_probe_receipt: "blake3:agy-profile".to_owned(),
        status: HostProfileStatus::Current,
    }
}

#[test]
fn antigravity_scope_denies_missing_expired_and_mismatched_authority_before_call()
-> anyhow::Result<()> {
    let now = OffsetDateTime::now_utc();

    let mut missing = scope_fixture()?;
    missing.scope.project_id = None;
    let error = require_error(
        validate_antigravity_scope(
            &missing.delegation,
            &missing.work,
            Some(&missing.cwd),
            &mut missing.scope,
            now,
        ),
        "missing project must fail closed",
    )?;
    assert!(error.to_string().contains("--project"));

    let mut missing_verifier = scope_fixture()?;
    missing_verifier.scope.planned_verifier_ref = None;
    let error = require_error(
        validate_antigravity_scope(
            &missing_verifier.delegation,
            &missing_verifier.work,
            Some(&missing_verifier.cwd),
            &mut missing_verifier.scope,
            now,
        ),
        "missing planned verifier must fail closed",
    )?;
    assert!(error.to_string().contains("--planned-verifier-ref"));

    let mut fabricated_verifier = scope_fixture()?;
    fabricated_verifier.scope.planned_verifier_ref =
        Some("eliot/verifier/fabricated@v1#blake3:deadbeef".to_owned());
    let error = require_error(
        validate_antigravity_scope(
            &fabricated_verifier.delegation,
            &fabricated_verifier.work,
            Some(&fabricated_verifier.cwd),
            &mut fabricated_verifier.scope,
            now,
        ),
        "fabricated planned verifier must fail closed",
    )?;
    assert!(error.to_string().contains("unregistered or stale"));

    let mut expired = scope_fixture()?;
    expired.work.worktree_leases[0].expires_at = now - time::Duration::seconds(1);
    let error = require_error(
        validate_antigravity_scope(
            &expired.delegation,
            &expired.work,
            Some(&expired.cwd),
            &mut expired.scope,
            now,
        ),
        "expired worktree lease must fail closed",
    )?;
    assert!(error.to_string().contains("expired or scope-mismatched"));

    let mut mismatched = scope_fixture()?;
    mismatched.scope.agent_session_id = Some(AgentSessionId::new_v7());
    let error = require_error(
        validate_antigravity_scope(
            &mismatched.delegation,
            &mismatched.work,
            Some(&mismatched.cwd),
            &mut mismatched.scope,
            now,
        ),
        "mismatched session must fail closed",
    )?;
    assert!(error.to_string().contains("scope-mismatched"));
    Ok(())
}

#[test]
fn antigravity_scope_denies_worktree_and_write_set_escape() -> anyhow::Result<()> {
    let now = OffsetDateTime::now_utc();
    let mut cwd_escape = scope_fixture()?;
    let outside = cwd_escape.root.join("outside");
    std::fs::create_dir_all(&outside)?;
    let error = require_error(
        validate_antigravity_scope(
            &cwd_escape.delegation,
            &cwd_escape.work,
            Some(&outside),
            &mut cwd_escape.scope,
            now,
        ),
        "cwd outside the lease must fail closed",
    )?;
    assert!(
        error
            .to_string()
            .contains("must equal the canonical WorktreeLease path")
    );

    let mut write_escape = scope_fixture()?;
    write_escape.scope.allowed_paths = vec!["../outside".to_owned()];
    let error = require_error(
        validate_antigravity_scope(
            &write_escape.delegation,
            &write_escape.work,
            Some(&write_escape.cwd),
            &mut write_escape.scope,
            now,
        ),
        "write path traversal must fail closed",
    )?;
    assert!(
        error.to_string().contains("escapes the governed worktree"),
        "unexpected rejection: {error}"
    );
    assert!(normalize_relative_path("C:/outside").is_err());
    Ok(())
}

#[test]
fn antigravity_is_a_scoped_managed_launch_target() -> anyhow::Result<()> {
    let fixture = scope_fixture()?;
    let repo = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .ok_or_else(|| anyhow::anyhow!("workspace root"))?;
    let contract = HostLaunchContractService.render(
        repo,
        &antigravity_profile(),
        HostMode::Supervised,
        &fixture.cwd,
        Some("gemini-2.5-pro".to_owned()),
        None,
        &fixture.scope,
    )?;
    let (_program, args) = launch_argv(
        AgentHostId::Antigravity,
        "agy.exe",
        &repo.join("integrations/antigravity"),
        false,
        &contract,
        Some("bounded candidate task".to_owned()),
    )?;
    assert!(args.windows(2).any(|pair| pair == ["--mode", "plan"]));
    assert!(!args.iter().any(|argument| argument == "accept-edits"));
    assert!(
        args.windows(2)
            .any(|pair| pair == ["--model", "gemini-2.5-pro"])
    );
    assert!(args.iter().any(|arg| arg == "--new-project"));
    assert!(args.iter().any(|arg| arg == "--sandbox"));
    assert!(args.iter().any(|arg| arg == "--print"));
    let prompt = args.last().map(String::as_str).unwrap_or_default();
    assert!(prompt.contains("READ-ONLY GOVERNED PLAN"));
    assert!(prompt.contains("candidate unified diff"));
    assert!(prompt.contains("no Markdown fences, prose, or summary"));
    assert!(prompt.contains("bounded candidate task"));
    assert!(
            candidate_unified_diff_hash(
                b"diff --git a/scripts/a.txt b/scripts/a.txt\n--- a/scripts/a.txt\n+++ b/scripts/a.txt\n@@ -1 +1 @@\n-a\n+b\n",
                &["scripts".to_owned()],
            )
            .is_some()
        );
    assert!(
        candidate_unified_diff_hash(
            b"Here is the requested patch:\n```diff\n",
            &["scripts".to_owned()],
        )
        .is_none()
    );
    assert!(candidate_unified_diff_hash(b"", &["scripts".to_owned()]).is_none());
    assert!(
            candidate_unified_diff_hash(
                b"diff --git a/outside.txt b/outside.txt\n--- a/outside.txt\n+++ b/outside.txt\n@@ -1 +1 @@\n-a\n+b\n",
                &["scripts".to_owned()],
            )
            .is_none()
        );
    Ok(())
}

#[test]
fn opencode_managed_launch_preserves_the_exact_dynamic_model_route() -> anyhow::Result<()> {
    let fixture = scope_fixture()?;
    let repo = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .ok_or_else(|| anyhow::anyhow!("workspace root"))?;
    let mut profile = antigravity_profile();
    profile.host_id = AgentHostId::OpenCode;
    profile.implementation_name = "OpenCode".to_owned();
    let selected_model = "openai/certification-reader";
    let contract = HostLaunchContractService.render(
        repo,
        &profile,
        HostMode::Supervised,
        &fixture.cwd,
        Some(selected_model.to_owned()),
        None,
        &fixture.scope,
    )?;
    let (_program, args) = launch_argv(
        AgentHostId::OpenCode,
        "opencode-cli.exe",
        &repo.join("integrations/opencode"),
        false,
        &contract,
        Some("sealed reader task".to_owned()),
    )?;
    let model_pairs = args
        .windows(2)
        .filter(|pair| pair[0] == "--model")
        .collect::<Vec<_>>();
    assert_eq!(model_pairs.len(), 1);
    assert_eq!(model_pairs[0][1], selected_model);
    assert!(!args.iter().any(|argument| argument == "--session"));
    assert_eq!(args.last().map(String::as_str), Some("sealed reader task"));
    Ok(())
}

/// ELIOT must reach a Claude session exactly once. The plugin already
/// carries its own `.mcp.json`, so passing that file again through
/// `--mcp-config` attached the tool set twice under two MCP namespaces,
/// giving one session two competing ELIOT authorities.
#[test]
fn claude_managed_launch_attaches_eliot_exactly_once() -> anyhow::Result<()> {
    let fixture = scope_fixture()?;
    let repo = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .ok_or_else(|| anyhow::anyhow!("workspace root"))?;
    let mut profile = antigravity_profile();
    profile.host_id = AgentHostId::Claude;
    profile.implementation_name = "Claude Code".to_owned();
    let contract = HostLaunchContractService.render(
        repo,
        &profile,
        HostMode::Supervised,
        &fixture.cwd,
        None,
        None,
        &fixture.scope,
    )?;
    let bundle = repo.join("integrations/claude/eliot");

    let attachments = |args: &[String]| {
        args.iter()
            .filter(|argument| {
                argument.as_str() == "--plugin-dir" || argument.as_str() == "--mcp-config"
            })
            .count()
    };

    // Canonical path: Claude discovered the installed plugin, so it loads
    // the MCP server itself and the launcher must add nothing.
    let (_program, installed) = launch_argv(
        AgentHostId::Claude,
        "claude.exe",
        &bundle,
        false,
        &contract,
        Some("bounded task".to_owned()),
    )?;
    assert_eq!(
        attachments(&installed),
        0,
        "an installed plugin already provides ELIOT: {installed:?}"
    );

    // Development fallback: no installed plugin, so the bundle is pointed
    // at directly -- still one attachment, never both.
    let (_program, fallback) = launch_argv(
        AgentHostId::Claude,
        "claude.exe",
        &bundle,
        true,
        &contract,
        Some("bounded task".to_owned()),
    )?;
    assert_eq!(
        attachments(&fallback),
        1,
        "the development fallback must attach ELIOT once: {fallback:?}"
    );
    assert!(
        !fallback.iter().any(|argument| argument == "--mcp-config"),
        "--plugin-dir already carries .mcp.json: {fallback:?}"
    );
    Ok(())
}

/// The one blocking rule this gate exists for: a session carrying a task
/// must not mutate without a work lease. Deleting the deny branch makes
/// this test fail rather than quietly turning the gate into a recorder.
#[test]
fn a_bound_session_without_a_work_lease_is_denied_before_it_mutates() {
    for event in ["PreToolUse", "tool.execute.before"] {
        assert_eq!(
            super::claude_hook_decision(event, true, false),
            "deny",
            "{event} must block an attached task that holds no work lease"
        );
        assert_eq!(
            super::claude_hook_decision(event, true, true),
            "recorded",
            "{event} must allow an attached task that holds a work lease"
        );
    }
}

/// The plugin is installed at user scope and sees every project on the
/// machine. An unrelated session must never be blocked, whatever it does.
#[test]
fn an_unbound_session_is_never_blocked() {
    for event in [
        "PreToolUse",
        "tool.execute.before",
        "PostToolUseFailure",
        "SessionStart",
        "SessionEnd",
    ] {
        assert_eq!(
            super::claude_hook_decision(event, false, false),
            "passive",
            "{event} must not gate a session with no attached task"
        );
    }
}

/// Only the mutation entry point gates. Observations of an attached task
/// are evidence, not decisions, and must not deny.
#[test]
fn observation_events_do_not_gate_even_when_a_task_is_attached() {
    for event in [
        "SessionStart",
        "SessionEnd",
        "PostToolUseFailure",
        "SubagentStart",
        "SubagentStop",
        "PreCompact",
        "TaskCompleted",
    ] {
        assert_eq!(
            super::claude_hook_decision(event, true, false),
            "recorded",
            "{event} observes; it must not block"
        );
    }
}

/// Every declared hook must be an event this Claude Code version knows,
/// and each one must earn its place: the unfiltered `PostToolUse` spawned a
/// Governor process after every successful tool call in every project.
#[test]
fn the_declared_hooks_are_the_ones_that_carry_eliot_evidence() -> anyhow::Result<()> {
    let repo = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .ok_or_else(|| anyhow::anyhow!("workspace root"))?;
    let hooks: Value = serde_json::from_slice(&std::fs::read(
        repo.join("integrations/claude/eliot/hooks/hooks.json"),
    )?)?;
    let declared = hooks
        .get("hooks")
        .and_then(Value::as_object)
        .ok_or_else(|| anyhow::anyhow!("hooks object"))?;

    assert!(
        !declared.contains_key("PostToolUse"),
        "an unfiltered PostToolUse fires on every successful tool call"
    );
    for required in ["SessionStart", "PreToolUse"] {
        assert!(declared.contains_key(required), "{required} is required");
    }

    // The mutation gate must stay filtered to the tools that can mutate.
    let matcher = hooks
        .pointer("/hooks/PreToolUse/0/matcher")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("PreToolUse matcher"))?;
    for tool in ["Bash", "Edit", "Write", "NotebookEdit"] {
        assert!(matcher.contains(tool), "{tool} must reach the gate");
    }

    // An enforcement point must run the dedicated handler. The generic
    // `host event` path answers every event with one shape and hardcodes
    // `PreToolUse` into its deny response, so routing a gate through it
    // means the emitted decision schema is only accidentally right.
    for (event, expected) in [
        ("PreToolUse", "pre-tool-use"),
        ("Stop", "stop"),
        ("PreCompact", "pre-compact"),
    ] {
        let args = hooks
            .pointer(&format!("/hooks/{event}/0/hooks/0/args"))
            .and_then(Value::as_array)
            .ok_or_else(|| anyhow::anyhow!("{event} args"))?
            .iter()
            .filter_map(Value::as_str)
            .collect::<Vec<_>>();
        assert_eq!(
            args,
            ["hook", expected],
            "{event} must reach the dedicated handler, not the generic event path"
        );
    }

    // The finish gate blocks with a top-level `{"decision": "block"}`, which
    // is the Stop schema. TaskCompleted blocks with `continue: false` or
    // exit code 2 instead, so declaring the gate there would emit a
    // decision Claude Code does not read -- a gate that silently allows.
    assert!(
        !declared.contains_key("TaskCompleted"),
        "the stop handler emits the Stop decision schema, not TaskCompleted's"
    );

    // A hook that can block must be able to answer before the turn moves
    // on; one that only records must not hold the turn up.
    for (event, blocking) in [
        ("SessionStart", true),
        ("PreToolUse", true),
        ("PreCompact", true),
        ("Stop", true),
        ("PostToolUseFailure", false),
        ("SubagentStart", false),
        ("SubagentStop", false),
        ("SessionEnd", false),
    ] {
        let is_async = hooks
            .pointer(&format!("/hooks/{event}/0/hooks/0/async"))
            .and_then(Value::as_bool)
            .unwrap_or(false);
        assert_eq!(
            is_async,
            !blocking,
            "{event} is declared {}synchronous",
            if blocking { "a" } else { "" }
        );
    }
    Ok(())
}

#[test]
fn antigravity_integration_bundle_is_complete_and_hashable() -> anyhow::Result<()> {
    let repo = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .ok_or_else(|| anyhow::anyhow!("workspace root"))?;
    let bundle = repo.join("integrations/antigravity");
    let (config_ref, lifecycle_ref) = integration_refs(&bundle, AgentHostId::Antigravity);
    let config: Value = serde_json::from_reader(std::fs::File::open(&config_ref)?)?;
    assert_eq!(config["schema_version"], "eliot-antigravity-integration-v1");
    assert!(lifecycle_ref.is_file());
    assert!(!eliot_engine::bundle_hash(&bundle, AgentHostId::Antigravity)?.is_empty());
    Ok(())
}

#[test]
fn candidate_diff_validates_hunk_semantics_and_all_metadata_paths() {
    let allowed = ["scripts".to_owned()];
    let rename = b"diff --git a/scripts/old.txt b/scripts/new.txt\nsimilarity index 90%\nrename from scripts/old.txt\nrename to scripts/new.txt\n--- a/scripts/old.txt\n+++ b/scripts/new.txt\n@@ -1 +1 @@\n-old\n+new\n";
    assert!(candidate_unified_diff_hash(rename, &allowed).is_some());
    let new_file = b"diff --git a/scripts/new.txt b/scripts/new.txt\nnew file mode 100644\n--- /dev/null\n+++ b/scripts/new.txt\n@@ -0,0 +1 @@\n+new\n";
    assert!(candidate_unified_diff_hash(new_file, &allowed).is_some());

    let wrong_counts = b"diff --git a/scripts/a.txt b/scripts/a.txt\n--- a/scripts/a.txt\n+++ b/scripts/a.txt\n@@ -1,2 +1,2 @@\n-old\n+new\n";
    assert!(candidate_unified_diff_hash(wrong_counts, &allowed).is_none());
    let malformed_range = b"diff --git a/scripts/a.txt b/scripts/a.txt\n--- a/scripts/a.txt\n+++ b/scripts/a.txt\n@@ -x +1 @@\n-old\n+new\n";
    assert!(candidate_unified_diff_hash(malformed_range, &allowed).is_none());
    let context_only = b"diff --git a/scripts/a.txt b/scripts/a.txt\n--- a/scripts/a.txt\n+++ b/scripts/a.txt\n@@ -1 +1 @@\n unchanged\n";
    assert!(candidate_unified_diff_hash(context_only, &allowed).is_none());
    let escaped_copy = b"diff --git a/scripts/a.txt b/scripts/b.txt\ncopy from scripts/a.txt\ncopy to outside/b.txt\n--- a/scripts/a.txt\n+++ b/scripts/b.txt\n@@ -1 +1 @@\n-old\n+new\n";
    assert!(candidate_unified_diff_hash(escaped_copy, &allowed).is_none());
    let overlapping = b"diff --git a/scripts/a.txt b/scripts/a.txt\n--- a/scripts/a.txt\n+++ b/scripts/a.txt\n@@ -1 +1 @@\n-old\n+new\n@@ -1 +1 @@\n-old-again\n+new-again\n";
    assert!(candidate_unified_diff_hash(overlapping, &allowed).is_none());
    let fake_new_file = b"diff --git a/scripts/a.txt b/scripts/a.txt\nnew file mode 100644\n--- a/scripts/a.txt\n+++ b/scripts/a.txt\n@@ -1 +1 @@\n-old\n+new\n";
    assert!(candidate_unified_diff_hash(fake_new_file, &allowed).is_none());
}

#[tokio::test]
async fn antigravity_environment_is_allowlisted_and_global_paths_are_denied() -> anyhow::Result<()>
{
    let fixture = scope_fixture()?;
    let repo = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .ok_or_else(|| anyhow::anyhow!("workspace root"))?;
    let contract = HostLaunchContractService.render(
        repo,
        &antigravity_profile(),
        HostMode::Supervised,
        &fixture.cwd,
        Some("gemini-2.5-pro".to_owned()),
        None,
        &fixture.scope,
    )?;
    let comspec = std::env::var_os("ComSpec")
        .ok_or_else(|| anyhow::anyhow!("ComSpec is required on Windows"))?;
    let mut command = tokio::process::Command::new(comspec);
    command.args(["/D", "/C", "set"]);
    configure_antigravity_environment(
        &mut command,
        repo,
        &contract,
        "C:/Eliot/eliot-governor.exe",
    )?;
    let output = command.output().await?;
    assert!(output.status.success());
    let environment = String::from_utf8(output.stdout)?.to_ascii_uppercase();
    for forbidden in [
        "ONEDRIVE=",
        "PROGRAMDATA=",
        "PATH=",
        "USERNAME=",
        "USERDOMAIN=",
    ] {
        assert!(
            !environment.lines().any(|line| line.starts_with(forbidden)),
            "forbidden inherited environment variable: {forbidden}"
        );
    }
    let local = PathBuf::from(
        std::env::var_os("LOCALAPPDATA")
            .ok_or_else(|| anyhow::anyhow!("LOCALAPPDATA is required"))?,
    );
    assert_managed_path_is_local_and_private(&local.join("Eliot/private"))?;
    if let Some(program_data) = std::env::var_os("ProgramData") {
        assert!(
            assert_managed_path_is_local_and_private(&PathBuf::from(program_data).join("agy"))
                .is_err()
        );
    }
    if let Some(one_drive) = std::env::var_os("OneDrive") {
        assert!(
            assert_managed_path_is_local_and_private(&PathBuf::from(one_drive).join("agy"))
                .is_err()
        );
    }
    std::fs::remove_dir_all(managed_sandbox_root(&contract)?)?;
    Ok(())
}

#[cfg(windows)]
#[tokio::test]
async fn standard_managed_environment_clears_unlisted_secrets() -> anyhow::Result<()> {
    let comspec = std::env::var_os("ComSpec")
        .ok_or_else(|| anyhow::anyhow!("ComSpec is required on Windows"))?;
    let mut command = tokio::process::Command::new(comspec);
    command
        .args(["/D", "/C", "set"])
        .env("ELIOT_SENTINEL_SECRET", "must-not-reach-managed-host");
    configure_standard_managed_environment(&mut command, "C:/Eliot/eliot-governor.exe");
    let output = command.output().await?;
    assert!(output.status.success());
    let environment = String::from_utf8(output.stdout)?.to_ascii_uppercase();
    assert!(!environment.contains("ELIOT_SENTINEL_SECRET="));
    assert!(environment.contains("ELIOT_GOVERNOR_EXE="));
    Ok(())
}

#[test]
fn managed_output_is_redacted_before_persistence() -> anyhow::Result<()> {
    let secret = format!("{}{}{}", "github_", "pat_", "A".repeat(40));
    let jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJlbGlvdCJ9.signaturebytes";
    let output = format!(
        "safe event\napi_key={secret}\n{{\"password\":\"must-not-persist\"}}\napi_token=must-not-persist-either\nAWS_SECRET_ACCESS_KEY=must-not-persist-aws\nAuthorization: Basic must-not-persist-basic\nAuthorization:\n Basic must-not-persist-folded\n second-must-not-persist-folded\nraw={jwt}\ntokens=128\n"
    );
    let sanitized = sanitize_managed_output(output.as_bytes());
    let text = String::from_utf8(sanitized.bytes)?;
    assert!(sanitized.receipt.redacted);
    assert!(!text.contains(&secret));
    assert!(!text.contains("must-not-persist"));
    assert!(!text.contains(jwt));
    assert!(text.contains("safe event"));
    assert!(text.contains("tokens=128"));
    assert!(
        sanitized
            .receipt
            .markers
            .contains(&"provider_credential".to_owned())
    );
    assert!(sanitized.receipt.markers.contains(&"password".to_owned()));
    assert!(sanitized.receipt.markers.contains(&"jwt".to_owned()));
    assert!(
        sanitized
            .receipt
            .markers
            .contains(&"credential_continuation".to_owned())
    );
    Ok(())
}

#[tokio::test]
async fn managed_launch_recovers_stale_lock_before_attempt() -> anyhow::Result<()> {
    let root = std::env::temp_dir().join(format!("eliot-agy-lock-{}", TaskId::new_v7()));
    let live = root.join("live");
    let live_lock = ManagedInvocationLock::acquire(&live)?;
    assert!(matches!(
        reconcile_existing_managed_invocation(&live, &live, "unused").await?,
        ExistingManagedInvocation::InProgress
    ));
    drop(live_lock);

    let stale = root.join("stale");
    std::fs::create_dir_all(&stale)?;
    let mut exited = Command::new("cmd").args(["/C", "exit", "0"]).spawn()?;
    let exited_pid = exited.id();
    exited.wait()?;
    atomic_write_bytes(
        &stale.join("dispatch.lock"),
        &encode_managed_invocation_lock(ManagedInvocationLockRecord {
            owner_pid: exited_pid,
            created_unix_seconds: u64::try_from(
                (OffsetDateTime::now_utc() - time::Duration::minutes(1)).unix_timestamp(),
            )?,
        }),
    )?;
    assert!(matches!(
        reconcile_existing_managed_invocation(&stale, &stale, "unused").await?,
        ExistingManagedInvocation::New
    ));
    assert!(!stale.join("dispatch.lock").exists());
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[tokio::test]
async fn managed_launch_recovers_truncated_pre_provider_journals() -> anyhow::Result<()> {
    let root = std::env::temp_dir().join(format!("eliot-agy-truncated-{}", TaskId::new_v7()));
    let truncated_lock = root.join("lock");
    std::fs::create_dir_all(&truncated_lock)?;
    std::fs::write(truncated_lock.join("dispatch.lock"), b"ELIOT-MANAGED-LOCK")?;
    tokio::time::sleep(Duration::from_millis(1_100)).await;
    assert!(matches!(
        reconcile_existing_managed_invocation(&truncated_lock, &truncated_lock, "unused").await?,
        ExistingManagedInvocation::New
    ));

    let truncated_attempt = root.join("attempt");
    write_stale_managed_lock(&truncated_attempt)?;
    std::fs::write(truncated_attempt.join("attempt.json"), b"{\"truncated\":")?;
    assert!(matches!(
        reconcile_existing_managed_invocation(&truncated_attempt, &truncated_attempt, "unused")
            .await?,
        ExistingManagedInvocation::New
    ));
    assert!(!truncated_attempt.join("attempt.json").exists());
    assert!(!truncated_attempt.join("dispatch.lock").exists());
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[tokio::test]
async fn managed_launch_never_retries_malformed_post_provider_journal() -> anyhow::Result<()> {
    let root = std::env::temp_dir().join(format!("eliot-agy-post-start-{}", TaskId::new_v7()));
    std::fs::create_dir_all(&root)?;
    std::fs::write(root.join("attempt.json"), b"{\"truncated\":")?;
    atomic_write_bytes(&provider_start_marker_path(&root), b"provider-started")?;
    assert!(matches!(
        reconcile_existing_managed_invocation(&root, &root, "unused").await?,
        ExistingManagedInvocation::UnknownOutcome
    ));
    assert!(root.join("attempt.json").exists());
    assert!(provider_start_marker_path(&root).exists());
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[tokio::test]
async fn managed_cleanup_never_resets_an_exhausted_absolute_deadline() {
    let deadline = Instant::now();
    let started = Instant::now();
    let bounded = tokio::time::timeout(
        remaining_to_deadline(deadline),
        std::future::pending::<()>(),
    )
    .await;
    assert!(bounded.is_err());
    assert!(started.elapsed() < Duration::from_millis(100));
    assert_eq!(remaining_to_deadline(deadline), Duration::ZERO);
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn managed_launch_cas_blocks_concurrent_spawn_and_attempt_tampering() -> anyhow::Result<()> {
    let root = std::env::temp_dir().join(format!("eliot-agy-journal-{}", TaskId::new_v7()));
    std::fs::create_dir_all(&root)?;
    let request_hash = "blake3:request";
    let snapshot = ManagedWorktreeSnapshot {
        head: "head".to_owned(),
        status_hash: hash_bytes(&[]),
        diff_hash: hash_bytes(&[]),
        untracked_hash: hash_bytes(&[]),
        aggregate_hash: "blake3:tree".to_owned(),
    };
    let launch_boundary = ManagedLaunchBoundaryAttestation {
        schema_version: "eliot-managed-launch-boundary-v1".to_owned(),
        executable_path: "C:/fixture/agy.exe".to_owned(),
        executable_hash: "blake3:executable".to_owned(),
        executable_version: "1.1.3".to_owned(),
        capability_probe_receipt: "blake3:agy-profile".to_owned(),
        integration_bundle_ref: "C:/fixture/integrations/antigravity".to_owned(),
        integration_bundle_hash: "blake3:bundle".to_owned(),
        invocation_root: root.to_string_lossy().into_owned(),
        environment: ManagedSanitizedEnvironment {
            inherited_environment_cleared: true,
            inherited_environment_allowlist: Vec::new(),
            environment_names: Vec::new(),
            sandbox_root: root.join("sandbox").to_string_lossy().into_owned(),
            isolated_paths: Vec::new(),
        },
    };
    let mut attempt = ManagedHostAttemptJournal {
        schema_version: MANAGED_ATTEMPT_SCHEMA_V4.to_owned(),
        invocation_id: stable_invocation_id("fixture-key"),
        idempotency_key: "fixture-key".to_owned(),
        request_hash: request_hash.to_owned(),
        contract_hash: "contract".to_owned(),
        host: AgentHostId::Antigravity,
        project_id: Some(ProjectId::new_v7()),
        task_id: Some(TaskId::new_v7()),
        work_item_id: None,
        agent_session_id: Some(AgentSessionId::new_v7()),
        role_lease_id: None,
        work_lease_id: None,
        worktree_lease_id: None,
        cwd_or_worktree: "C:/fixture".to_owned(),
        write_set: vec!["scripts".to_owned()],
        tool: "agy".to_owned(),
        tool_version: "1.1.3".to_owned(),
        model: Some("gemini-2.5-pro".to_owned()),
        prompt_hash: "blake3:prompt".to_owned(),
        owner_pid: std::process::id(),
        authority_hash: "blake3:authority".to_owned(),
        worktree_before: snapshot,
        launch_boundary,
        broker_job_id: "operation-job:fixture".to_owned(),
        broker_result_id: "agent-result:fixture".to_owned(),
        broker_host_session_id: "agy-fixture".to_owned(),
        planned_verifier_ref: crate::mcp_stdio::RegisteredTaskVerifier::ReceiptResolution
            .reference(),
        attempt_hash: String::new(),
        attempt_recorded_before_provider_call: true,
        provider_call_budget_consumed: true,
        redispatch_allowed: false,
        started_at: OffsetDateTime::now_utc(),
    };
    attempt.attempt_hash = managed_attempt_hash(&attempt)?;
    atomic_write_json(&root.join("attempt.json"), &attempt)?;
    let lock = ManagedInvocationLock::acquire(&root)?;
    assert!(ManagedInvocationLock::acquire(&root).is_err());
    assert!(matches!(
        reconcile_existing_managed_invocation(&root, &root, request_hash).await?,
        ExistingManagedInvocation::InProgress
    ));
    let mut tampered = attempt.clone();
    tampered.authority_hash = "blake3:tampered".to_owned();
    assert!(validate_attempt_journal(&tampered).is_err());

    let stdout = root.join("stdout.txt");
    let stderr = root.join("stderr.log");
    std::fs::write(&stdout, "candidate diff")?;
    std::fs::write(&stderr, "")?;
    let mut result = json!({
        "request_hash": request_hash,
        "contract_hash": attempt.contract_hash,
        "attempt_hash": attempt.attempt_hash,
        "reason": "fixture terminal result",
        "execution_evidence": {
            "stdout_ref": stdout,
            "stdout_hash": hash_bytes(b"candidate diff"),
            "stderr_ref": stderr,
            "stderr_hash": hash_bytes(b""),
        },
        "canonical_authority": { "body_hash": "blake3:fixture" },
    });
    let receipt_hash = hash_json(&result)?;
    result
        .as_object_mut()
        .ok_or_else(|| anyhow::anyhow!("fixture result object"))?
        .insert("receipt_hash".to_owned(), Value::String(receipt_hash));
    validate_managed_result_integrity(&attempt, &result, request_hash)?;
    let mut tampered_result = result.clone();
    tampered_result["reason"] = json!("fabricated replacement");
    assert!(validate_managed_result_integrity(&attempt, &tampered_result, request_hash).is_err());
    std::fs::write(root.join("stdout.txt"), "mutated output")?;
    assert!(validate_managed_result_integrity(&attempt, &result, request_hash).is_err());
    drop(lock);
    let replacement = ManagedInvocationLock::acquire(&root)?;
    drop(replacement);
    attempt.schema_version = "eliot-managed-host-attempt-v2".to_owned();
    attempt.attempt_hash = managed_attempt_hash(&attempt)?;
    atomic_write_json(&root.join("attempt.json"), &attempt)?;
    atomic_write_bytes(&provider_start_marker_path(&root), b"provider-started")?;
    assert!(matches!(
        reconcile_existing_managed_invocation(&root, &root, request_hash).await?,
        ExistingManagedInvocation::UnknownOutcome
    ));
    assert!(root.join("attempt.json").exists());
    assert!(provider_start_marker_path(&root).exists());
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn managed_authority_requires_receipts() {
    assert!(receipt_ref_from_option(None, "WorkLease").is_err());
}

#[test]
fn managed_launch_attestation_does_not_traverse_provider_private_roots() {
    let production = include_str!("../host_runtime.rs")
        .split("\n#[cfg(test)]")
        .next()
        .unwrap_or_default();
    for forbidden in [
        "provider_global_state_roots",
        "global_agy_state_snapshot",
        "forbidden_global_state_roots",
        "start_forbidden_state_watch",
        "DirectoryMutationGuard::watch",
    ] {
        assert!(
            !production.contains(forbidden),
            "managed launch must not traverse provider-private state through {forbidden}"
        );
    }
}

#[cfg(windows)]
#[test]
fn managed_launch_preparation_ignores_unrelated_windows_trailing_dot_files() -> anyhow::Result<()> {
    let local_app_data = std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .ok_or_else(|| anyhow::anyhow!("LOCALAPPDATA is required for this Windows test"))?;
    let root = local_app_data
        .join("Eliot")
        .join("tests")
        .join(format!("launch-boundary-{}", TaskId::new_v7()));
    let executable = root.join("bin").join("agy.exe");
    let bundle = root.join("integrations").join("antigravity");
    let invocation = root
        .join("reports")
        .join("host-invocations")
        .join("fixture");
    let sandbox = root.join("sandbox");
    let isolated_paths = [
        sandbox.join("home"),
        sandbox.join("local"),
        sandbox.join("roaming"),
        sandbox.join("temp"),
        sandbox.join("config"),
    ];
    let executable_parent = executable
        .parent()
        .ok_or_else(|| anyhow::anyhow!("fixture executable has no parent"))?;
    std::fs::create_dir_all(executable_parent)?;
    std::fs::create_dir_all(&bundle)?;
    std::fs::create_dir_all(&invocation)?;
    for path in &isolated_paths {
        std::fs::create_dir_all(path)?;
    }
    std::fs::write(&executable, b"fixture agy executable")?;
    atomic_write_json(
        &bundle.join("integration.json"),
        &json!({
            "schema_version": "eliot-antigravity-integration-v1",
            "host": "antigravity",
        }),
    )?;
    std::fs::write(bundle.join("README.md"), b"managed integration fixture")?;

    let unrelated_private_root = root.join("unrelated").join(".gemini");
    std::fs::create_dir_all(&unrelated_private_root)?;
    let logical_trailing_dot = unrelated_private_root.join("credentials.json.");
    let exact_trailing_dot = PathBuf::from(format!(
        r"\\?\{}",
        std::path::absolute(&logical_trailing_dot)?
            .to_string_lossy()
            .replace('/', "\\")
    ));
    std::fs::write(&exact_trailing_dot, b"unrelated provider-private state")?;

    let canonical_executable = executable.canonicalize()?;
    let mut profile = antigravity_profile();
    profile.executable_path = canonical_executable.to_string_lossy().into_owned();
    profile.executable_hash = hash_file_content(&canonical_executable)?;
    let environment = ManagedSanitizedEnvironment {
        inherited_environment_cleared: true,
        inherited_environment_allowlist: Vec::new(),
        environment_names: vec![
            "AGY_CLI_DISABLE_AUTO_UPDATE".to_owned(),
            "AGY_CLI_HIDE_ACCOUNT_INFO".to_owned(),
            "USERPROFILE".to_owned(),
        ],
        sandbox_root: sandbox.to_string_lossy().into_owned(),
        isolated_paths: isolated_paths
            .iter()
            .map(|path| path.to_string_lossy().into_owned())
            .collect(),
    };
    let boundary = managed_launch_boundary_attestation(
        &profile,
        canonical_executable
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("fixture executable path is not UTF-8"))?,
        &bundle,
        &invocation,
        environment,
    )?;
    assert!(managed_launch_boundary_is_current(&boundary));
    assert_eq!(boundary.executable_hash, profile.executable_hash);
    assert!(
        !serde_json::to_string(&boundary)?.contains(".gemini"),
        "provider-private roots must not be part of launch attestation"
    );

    std::fs::remove_file(exact_trailing_dot)?;
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[tokio::test]
async fn pre_dispatch_failure_authority_remains_redispatchable_without_provider_call()
-> anyhow::Result<()> {
    let root = std::env::temp_dir().join(format!("eliot-pre-dispatch-{}", TaskId::new_v7()));
    let config = root.join("config").join("governor.toml");
    let config_parent = config
        .parent()
        .ok_or_else(|| anyhow::anyhow!("fixture config has no parent"))?;
    std::fs::create_dir_all(config_parent)?;
    let idempotency_key = "fixture-pre-dispatch-failure";
    let invocation_id = stable_invocation_id(idempotency_key);
    let invocation = invocation_root(&config, &invocation_id);
    std::fs::create_dir_all(&invocation)?;
    atomic_write_json(
        &invocation.join("attempt.json"),
        &json!({
            "schema_version": MANAGED_ATTEMPT_SCHEMA_V4,
            "failure_stage": "pre_dispatch",
        }),
    )?;

    let status = invocation_status(&config, idempotency_key).await?;
    assert_eq!(status.get("status"), Some(&json!("not_attempted")));
    assert_eq!(
        status.get("provider_call_budget_consumed"),
        Some(&json!(false))
    );
    assert_eq!(status.get("redispatch_allowed"), Some(&json!(true)));
    assert!(!provider_start_marker_path(&invocation).exists());
    assert!(!invocation.join("attempt.json").exists());

    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn canonical_authority_requires_exact_body_and_created_record_identity() -> anyhow::Result<()> {
    let project_id = ProjectId::new_v7();
    let task_id = TaskId::new_v7();
    let write_id = WriteId::new_v7();
    let revision = MemoryRevision::new(7);
    let sequence = ProjectSequence::new(9);
    let body = json!({
        "work_lease_id": WorkLeaseId::new_v7(),
        "state": "granted",
        "started_at": "2026-07-17T09:15:42.8503046Z",
        "decision": {
            "expires_at": "2026-07-17T10:00:42.8503046Z",
        },
        "write_receipt": Value::Null,
    });
    let mut observed_body = body.clone();
    observed_body["started_at"] = json!("2026-07-17T09:15:42.850304600+00:00");
    observed_body["decision"]["expires_at"] = json!("2026-07-17T10:00:42.850304600+00:00");
    observed_body["write_receipt"] = json!({
        "receipt_id": ReceiptId::new_v7(),
        "write_id": WriteId::new_v7(),
    });
    let receipt = WriteReceipt {
        receipt_id: ReceiptId::new_v7(),
        write_id,
        input_hash: "blake3:input".to_owned(),
        project_id,
        task_id: Some(task_id),
        command_kind: SemanticCommandKind::ToolObservationRecord,
        status: WriteStatus::Committed,
        memory_revision: Some(revision),
        project_sequence: Some(sequence),
        created_records: vec![write_id.to_string()],
        created_relations: Vec::new(),
        weak_records: Vec::new(),
        rejected_reason: None,
        db_operation_id: None,
        created_at: OffsetDateTime::now_utc(),
    };
    let observation = CanonicalToolObservation {
        observation_id: write_id.to_string(),
        project_id,
        task_id: Some(task_id),
        scope: "work/work-lease".to_owned(),
        authority: "eliot-work-coordination-service".to_owned(),
        tool_name: "eliot_work_coordination".to_owned(),
        observation: "WorkLease fixture".to_owned(),
        payload: json!({ "work_lease": observed_body }),
        memory_revision: revision,
        project_sequence: sequence,
        write_id,
    };
    let expected = CanonicalAuthorityBody {
        label: "WorkLease",
        task_id: Some(task_id),
        scope: "work/work-lease",
        authority: "eliot-work-coordination-service",
        tool_name: "eliot_work_coordination",
        payload_key: "work_lease",
        body: &body,
        normalization: CanonicalBodyNormalization::Rfc3339Fields(&[
            "started_at",
            "decision.expires_at",
        ]),
    };
    validate_canonical_observation_identity(&observation, &receipt, project_id, &expected)?;
    let mut tampered_timestamp = observation.clone();
    tampered_timestamp.payload["work_lease"]["decision"]["expires_at"] =
        json!("2026-07-17T10:00:43.8503046Z");
    assert!(
        validate_canonical_observation_identity(
            &tampered_timestamp,
            &receipt,
            project_id,
            &expected,
        )
        .is_err()
    );
    let mut tampered = observation;
    tampered.payload["work_lease"]["state"] = json!("revoked");
    assert!(
        validate_canonical_observation_identity(&tampered, &receipt, project_id, &expected)
            .is_err()
    );
    Ok(())
}

#[test]
fn canonical_revocation_before_projection_replace_rejects_old_active_receipt() -> anyhow::Result<()>
{
    let project_id = ProjectId::new_v7();
    let task_id = TaskId::new_v7();
    let lease_id = WorkLeaseId::new_v7();
    let old_write = WriteId::new_v7();
    let revoked_write = WriteId::new_v7();
    let observation = |write_id: WriteId, revision: u64, state: &str| CanonicalToolObservation {
        observation_id: write_id.to_string(),
        project_id,
        task_id: Some(task_id),
        scope: "work/work-lease".to_owned(),
        authority: "eliot-work-coordination-service".to_owned(),
        tool_name: "eliot_work_coordination".to_owned(),
        observation: format!("WorkLease state {state}"),
        payload: json!({
            "work_lease": { "work_lease_id": lease_id, "state": state }
        }),
        memory_revision: MemoryRevision::new(revision),
        project_sequence: ProjectSequence::new(revision),
        write_id,
    };
    let latest = observation(revoked_write, 8, "revoked");
    let old = observation(old_write, 7, "granted");
    let old_reference = WriteReceiptRef {
        receipt_id: ReceiptId::new_v7(),
        write_id: old_write,
    };
    assert!(
            latest_canonical_authority_observation(
                &[latest.clone(), old],
                &old_reference,
                "WorkLease",
            )
            .is_err()
        );
    let current_reference = WriteReceiptRef {
        receipt_id: ReceiptId::new_v7(),
        write_id: revoked_write,
    };
    assert_eq!(
        latest_canonical_authority_observation(
            std::slice::from_ref(&latest),
            &current_reference,
            "WorkLease",
        )?
        .write_id,
        revoked_write
    );
    Ok(())
}

#[test]
fn claude_desktop_registry_lookup_uses_manifest_identity() {
    let registry = json!({
        "extensions": {
            "ant.dir.example.other": {
                "id": "ant.dir.example.other",
                "version": "9.0.0",
                "manifest": { "name": "other" }
            },
            "ant.local.eliot-governor": {
                "id": "ant.local.eliot-governor",
                "version": "0.1.0",
                "manifest": { "name": "eliot-governor" }
            }
        }
    });
    let Some((id, entry)) = registry_entry_by_manifest(&registry, "eliot-governor") else {
        panic!("ELIOT registry entry must be discoverable by manifest name");
    };
    assert_eq!(id, "ant.local.eliot-governor");
    assert_eq!(entry["version"], "0.1.0");
    assert!(is_claude_desktop_host("Claude-Desktop"));
    assert!(is_claude_desktop_host("claude_desktop"));
    assert!(!is_claude_desktop_host("claude"));
}

#[test]
fn opencode_jsonc_merge_preserves_comments_and_unrelated_values() -> anyhow::Result<()> {
    let original = br#"{
  // keep this comment
  "$schema": "https://opencode.ai/config.json",
  "mcp": {
    // keep this MCP too
    "context7": { "type": "remote", "url": "https://example.test/a//b" },
  },
  "instructions": ["shared.md"],
  "provider": { "name": "unchanged" },
}
"#;
    let merged = merge_opencode_mcp_config(original, &eliot_entry(), instruction_entry())?;
    let text = std::str::from_utf8(&merged.bytes)?;
    assert!(text.contains("// keep this comment"));
    assert!(text.contains("// keep this MCP too"));
    assert!(text.contains("https://example.test/a//b"));
    assert!(merged.mcp_field_existed_before);
    assert!(merged.mcp_entry_before.is_none());
    assert!(merged.instructions_field_existed_before);
    assert!(!merged.instruction_entry_existed_before);

    let root = parse_opencode_jsonc(&merged.bytes)?;
    let root_object = root
        .object_value()
        .ok_or_else(|| anyhow::anyhow!("root object"))?;
    let mcp = root_object
        .object_value("mcp")
        .ok_or_else(|| anyhow::anyhow!("mcp object"))?;
    assert_eq!(
        mcp.get("eliot")
            .and_then(|property| property.to_serde_value()),
        Some(eliot_entry())
    );

    let restored =
        remove_opencode_mcp_config(&merged.bytes, None, true, instruction_entry(), true, false)?;
    let restored_text = std::str::from_utf8(&restored)?;
    assert!(restored_text.contains("// keep this comment"));
    assert!(restored_text.contains("// keep this MCP too"));
    let restored_root = parse_opencode_jsonc(&restored)?;
    let restored_mcp = restored_root
        .object_value()
        .and_then(|root| root.object_value("mcp"))
        .ok_or_else(|| anyhow::anyhow!("restored mcp object"))?;
    assert!(restored_mcp.get("eliot").is_none());
    assert!(restored_mcp.get("context7").is_some());
    let restored_instructions = restored_root
        .object_value()
        .and_then(|root| root.get("instructions"))
        .and_then(|property| property.to_serde_value());
    assert_eq!(restored_instructions, Some(json!(["shared.md"])));
    Ok(())
}

#[test]
fn opencode_jsonc_rollback_removes_eliot_owned_mcp_container() -> anyhow::Result<()> {
    let original = b"{\n  // untouched\n  \"provider\": { \"name\": \"local\" },\n}\n";
    let merged = merge_opencode_mcp_config(original, &eliot_entry(), instruction_entry())?;
    assert!(!merged.mcp_field_existed_before);
    assert!(!merged.instructions_field_existed_before);
    let restored = remove_opencode_mcp_config(
        &merged.bytes,
        None,
        false,
        instruction_entry(),
        false,
        false,
    )?;
    let root = parse_opencode_jsonc(&restored)?;
    let root_object = root
        .object_value()
        .ok_or_else(|| anyhow::anyhow!("root object"))?;
    assert!(root_object.get("mcp").is_none());
    assert!(root_object.get("instructions").is_none());
    assert!(std::str::from_utf8(&restored)?.contains("// untouched"));
    Ok(())
}

#[test]
fn opencode_jsonc_rollback_restores_preexisting_eliot_entry() -> anyhow::Result<()> {
    let original = br#"{
  "mcp": {
    "eliot": { "type": "remote", "url": "https://old.example/mcp" },
  },
  "instructions": ["C:/Eliot/instructions/eliot-governor.md"],
}
"#;
    let merged = merge_opencode_mcp_config(original, &eliot_entry(), instruction_entry())?;
    let before = merged
        .mcp_entry_before
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("preexisting entry"))?;
    assert!(merged.instruction_entry_existed_before);
    let restored = remove_opencode_mcp_config(
        &merged.bytes,
        Some(before),
        true,
        instruction_entry(),
        true,
        true,
    )?;
    let root = parse_opencode_jsonc(&restored)?;
    let actual = root
        .object_value()
        .and_then(|root| root.object_value("mcp"))
        .and_then(|mcp| mcp.get("eliot"))
        .and_then(|property| property.to_serde_value());
    assert_eq!(actual.as_ref(), Some(before));
    let instructions = root
        .object_value()
        .and_then(|root| root.get("instructions"))
        .and_then(|property| property.to_serde_value());
    assert_eq!(instructions, Some(json!([instruction_entry()])));
    Ok(())
}
