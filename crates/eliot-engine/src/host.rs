use crate::EngineError;
use eliot_types::{
    AgentCapabilityEnvelope, AgentHostId, AgentHostIdentity, AgentHostRuntimeProfile,
    AgentInvocationRequest, AgentResultDisposition, AgentResultDispositionKind,
    AgentResultEnvelope, AgentResultStatus, AgentRole, AgentSessionHostBinding, AgentSessionId,
    ControllerLease, DelegationState, HostEventEnvelope, HostLaunchContract, HostLaunchScope,
    HostMode, HostProfileStatus, HostProtocolSurfaces, OperationJob, OperationJobState, ProjectId,
    TaintClass, TaskId, TaskRoleLease,
};
use serde::Serialize;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use time::OffsetDateTime;

pub const ELIOT_SKILL_NAMES: [&str; 4] = [
    "eliot-task-cycle",
    "eliot-understanding",
    "eliot-delegation",
    "eliot-verify-finish",
];

#[derive(Clone, Debug, Serialize)]
pub struct SkillPackEntryReport {
    pub name: String,
    pub description_characters: usize,
    pub nonblank_lines: usize,
    pub estimated_tokens: usize,
    pub canonical_hash: String,
    pub opencode_parity: bool,
    pub claude_parity: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct SkillPackLintReport {
    pub valid: bool,
    pub skill_count: usize,
    pub listing_characters: usize,
    pub entries: Vec<SkillPackEntryReport>,
    pub errors: Vec<String>,
    pub pack_hash: String,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct SkillPackService;

impl SkillPackService {
    #[allow(clippy::too_many_lines)]
    pub fn lint(self, repo_root: &Path) -> Result<SkillPackLintReport, EngineError> {
        let canonical_root = repo_root.join("integrations/agent-skills");
        let opencode_root = repo_root.join("integrations/opencode/skills");
        let claude_root = repo_root.join("integrations/claude/eliot/skills");
        let mut errors = Vec::new();
        let mut entries = Vec::new();
        let mut descriptions = 0;
        let mut paragraph_owners = BTreeMap::<String, String>::new();
        let mut pack_material = String::new();

        for name in ELIOT_SKILL_NAMES {
            let canonical_path = canonical_root.join(name).join("SKILL.md");
            let body = std::fs::read_to_string(&canonical_path)?;
            let (frontmatter, markdown) =
                split_frontmatter(&body).ok_or_else(|| EngineError::ServiceNotReady {
                    service: "skill-pack".to_owned(),
                    reason: format!("{} has invalid frontmatter", canonical_path.display()),
                })?;
            let parsed_name = frontmatter_value(frontmatter, "name").unwrap_or_default();
            let description = frontmatter_value(frontmatter, "description").unwrap_or_default();
            if parsed_name != name {
                errors.push(format!("{name}: frontmatter name does not match directory"));
            }
            if description.is_empty() {
                errors.push(format!("{name}: description is empty"));
            }
            descriptions += description.chars().count();
            let nonblank_lines = body.lines().filter(|line| !line.trim().is_empty()).count();
            let estimated_tokens = body.chars().count().div_ceil(4);
            if nonblank_lines > 100 {
                errors.push(format!("{name}: body exceeds 100 nonblank lines"));
            }
            if estimated_tokens > 900 {
                errors.push(format!("{name}: body exceeds estimated 900 token budget"));
            }
            let lower = body.to_ascii_lowercase();
            for forbidden in [
                "surrealdb",
                "rocksdb",
                "surrealql",
                "claude is auditor",
                "opencode is worker",
                "codex is controller",
            ] {
                if lower.contains(forbidden) {
                    errors.push(format!("{name}: contains forbidden phrase {forbidden}"));
                }
            }
            for paragraph in markdown.split("\n\n") {
                let normalized = paragraph.split_whitespace().collect::<Vec<_>>().join(" ");
                if normalized.len() < 120 || normalized.starts_with('#') {
                    continue;
                }
                if let Some(owner) = paragraph_owners.insert(normalized, name.to_owned())
                    && owner != name
                {
                    errors.push(format!("{name}: duplicates a paragraph from {owner}"));
                }
            }
            if markdown.contains("](") {
                errors.push(format!(
                    "{name}: reference links require explicit lint support"
                ));
            }

            let canonical_hash = canonical_skill_content_hash(&body);
            let opencode = std::fs::read(opencode_root.join(name).join("SKILL.md"))?;
            let claude = std::fs::read(claude_root.join(name).join("SKILL.md"))?;
            let opencode_parity = opencode == body.as_bytes();
            let claude_parity = claude == body.as_bytes();
            if !opencode_parity || !claude_parity {
                errors.push(format!("{name}: generated host package drift"));
            }
            pack_material.push_str(name);
            pack_material.push(':');
            pack_material.push_str(&canonical_hash);
            pack_material.push('\n');
            entries.push(SkillPackEntryReport {
                name: name.to_owned(),
                description_characters: description.chars().count(),
                nonblank_lines,
                estimated_tokens,
                canonical_hash,
                opencode_parity,
                claude_parity,
            });
        }
        if descriptions > 1_200 {
            errors.push("combined descriptions exceed 1,200 characters".to_owned());
        }
        let skill_count = entries.len();
        let pack_hash = blake3::hash(pack_material.as_bytes()).to_hex().to_string();
        let manifest_path = canonical_root.join("skill-pack.manifest.json");
        let manifest: Value = serde_json::from_reader(File::open(&manifest_path)?)?;
        if manifest.get("hash_algorithm").and_then(Value::as_str)
            != Some("blake3(name:content_blake3 joined with LF in manifest order)")
        {
            errors.push(
                "skill manifest hash algorithm is not the canonical BLAKE3 recipe".to_owned(),
            );
        }
        if manifest.get("pack_hash").and_then(Value::as_str) != Some(pack_hash.as_str()) {
            errors.push("skill manifest pack_hash drift".to_owned());
        }
        let manifest_skills = manifest
            .get("skills")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        for entry in &entries {
            let manifest_hash = manifest_skills.iter().find_map(|value| {
                (value.get("name").and_then(Value::as_str) == Some(entry.name.as_str()))
                    .then(|| value.get("content_blake3").and_then(Value::as_str))
                    .flatten()
            });
            if manifest_hash != Some(entry.canonical_hash.as_str()) {
                errors.push(format!("{}: skill manifest content hash drift", entry.name));
            }
        }
        Ok(SkillPackLintReport {
            valid: errors.is_empty() && skill_count == 4,
            skill_count,
            listing_characters: descriptions,
            entries,
            errors,
            pack_hash,
        })
    }
}

fn canonical_skill_content_hash(body: &str) -> String {
    blake3::hash(body.replace("\r\n", "\n").as_bytes())
        .to_hex()
        .to_string()
}

#[cfg(test)]
mod skill_pack_tests {
    use super::canonical_skill_content_hash;

    #[test]
    fn canonical_skill_hash_is_line_ending_independent() {
        assert_eq!(
            canonical_skill_content_hash("---\r\nname: fixture\r\n---\r\nbody\r\n"),
            canonical_skill_content_hash("---\nname: fixture\n---\nbody\n")
        );
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct HostProfileService;

impl HostProfileService {
    pub fn probe(self, host_id: AgentHostId) -> Result<AgentHostRuntimeProfile, EngineError> {
        let executable =
            resolve_executable(host_id).ok_or_else(|| EngineError::ServiceNotReady {
                service: format!("{} host", host_id.as_str()),
                reason: "installed executable was not found in supported user locations".to_owned(),
            })?;
        let version_output = command_text(&executable, &["--version"])?;
        let mut help_output = command_text(&executable, &["--help"])?;
        if host_id == AgentHostId::OpenCode {
            help_output.push('\n');
            help_output.push_str(&command_text(&executable, &["run", "--help"])?);
        }
        let version = version_output
            .lines()
            .next()
            .unwrap_or("unknown")
            .trim()
            .to_owned();
        let executable_hash = hash_file(&executable)?;
        let help_lower = help_output.to_ascii_lowercase();
        let (surfaces, supported_modes, launch_capabilities, result_capture, constraints, valid) =
            capability_matrix(host_id, &help_lower);
        let capability_probe_receipt =
            host_profile_fingerprint(&executable_hash, &version, &help_output);
        Ok(AgentHostRuntimeProfile {
            host_id,
            implementation_name: implementation_name(host_id).to_owned(),
            executable_path: executable.to_string_lossy().into_owned(),
            executable_hash,
            version,
            discovered_at: OffsetDateTime::now_utc(),
            supported_modes,
            protocol_surfaces: surfaces,
            launch_capabilities,
            result_capture,
            resume_contract: "resume only a recorded host session; reconcile unknown outcome before retry"
                .to_owned(),
            timeout_and_unknown_outcome_contract:
                "bounded wall clock; capture exit/stdout/stderr; unknown outcome is reconciled, never blindly re-dispatched"
                    .to_owned(),
            known_version_constraints: constraints,
            operator_configuration_refs: vec![match host_id {
                AgentHostId::Claude => "integrations/claude/eliot/README.md".to_owned(),
                _ => format!("integrations/{}/README.md", host_id.as_str()),
            }],
            capability_probe_receipt,
            status: if valid {
                HostProfileStatus::Current
            } else {
                HostProfileStatus::Degraded
            },
        })
    }

    pub fn connected(self, binding: &AgentSessionHostBinding) -> AgentHostRuntimeProfile {
        let envelope = &binding.capability_envelope;
        let usable = (envelope.interactive || envelope.supervised) && envelope.structured_output;
        let receipt = serde_json::to_vec(binding).map_or_else(
            |_| "unavailable".to_owned(),
            |bytes| blake3::hash(&bytes).to_hex().to_string(),
        );
        AgentHostRuntimeProfile {
            host_id: binding.host_identity.host_id,
            implementation_name: binding.host_identity.implementation_name.clone(),
            executable_path: format!(
                "connected-session://{}/{}",
                binding.host_identity.host_id.as_str(),
                binding.host_identity.client_instance_id
            ),
            executable_hash: "not-applicable:connected-session".to_owned(),
            version: "connected-session-v1".to_owned(),
            discovered_at: OffsetDateTime::now_utc(),
            supported_modes: vec!["connected_session".to_owned()],
            protocol_surfaces: HostProtocolSurfaces {
                mcp_stdio: true,
                structured_output: envelope.structured_output,
                ..HostProtocolSurfaces::default()
            },
            launch_capabilities: envelope.capabilities.clone(),
            result_capture: vec!["agent_result_envelope".to_owned()],
            resume_contract: "same authenticated connected session only".to_owned(),
            timeout_and_unknown_outcome_contract:
                "reconcile broker job before connected-session redispatch".to_owned(),
            known_version_constraints: Vec::new(),
            operator_configuration_refs: Vec::new(),
            capability_probe_receipt: format!("connected-binding:{receipt}"),
            status: if usable {
                HostProfileStatus::Current
            } else {
                HostProfileStatus::Stale
            },
        }
    }
}

pub fn host_profile_fingerprint(executable_hash: &str, version: &str, help_output: &str) -> String {
    let receipt_material = format!(
        "{}\n{}\n{}",
        executable_hash,
        version,
        blake3::hash(help_output.as_bytes()).to_hex()
    );
    format!(
        "blake3:{}",
        blake3::hash(receipt_material.as_bytes()).to_hex()
    )
}

#[derive(Clone, Copy, Debug, Default)]
pub struct HostLaunchContractService;

impl HostLaunchContractService {
    #[allow(clippy::too_many_arguments)]
    pub fn render(
        self,
        repo_root: &Path,
        profile: &AgentHostRuntimeProfile,
        mode: HostMode,
        cwd: &Path,
        model_route: Option<String>,
        session_id: Option<String>,
        scope: &HostLaunchScope,
    ) -> Result<HostLaunchContract, EngineError> {
        if profile.status != HostProfileStatus::Current {
            return Err(EngineError::ServiceNotReady {
                service: "host-launch".to_owned(),
                reason: format!(
                    "{} runtime profile is {:?}; run host inspect before launch",
                    profile.host_id.as_str(),
                    profile.status
                ),
            });
        }
        let bundle = bundle_root(repo_root, profile.host_id);
        if profile.host_id != AgentHostId::Antigravity && !bundle.is_dir() {
            return Err(EngineError::ServiceNotReady {
                service: "host-launch".to_owned(),
                reason: format!("integration bundle missing: {}", bundle.display()),
            });
        }
        let invocation_id = uuid_like("host-invocation");
        let idempotency_material = format!(
            "{}\n{}\n{:?}\n{}\n{}\n{}\n{}",
            profile.capability_probe_receipt,
            profile.host_id.as_str(),
            mode,
            cwd.display(),
            model_route.as_deref().unwrap_or_default(),
            session_id.as_deref().unwrap_or_default(),
            serde_json::to_string(scope)?
        );
        let idempotency_key = format!(
            "host-idempotency:{}",
            blake3::hash(idempotency_material.as_bytes()).to_hex()
        );
        let (integration_bundle_ref, mcp_config_ref, skill_bundle_ref, lifecycle_bridge_ref) =
            launch_integration_refs(profile.host_id, &bundle);
        let mut contract = HostLaunchContract {
            invocation_id,
            host_profile_ref: profile.capability_probe_receipt.clone(),
            mode,
            project_id: scope.project_id,
            agent_session_id: scope.agent_session_id,
            task_id: scope.task_id,
            work_item_id: scope.work_item_id,
            role_lease_id: scope.role_lease_id.clone(),
            work_lease_id: scope.work_lease_id,
            worktree_lease_id: scope.worktree_lease_id,
            planned_verifier_ref: scope.planned_verifier_ref.clone(),
            cwd_or_worktree: cwd.to_string_lossy().into_owned(),
            baseline_commit: scope.baseline_commit.clone(),
            allowed_paths: if scope.allowed_paths.is_empty() {
                vec![cwd.to_string_lossy().into_owned()]
            } else {
                scope.allowed_paths.clone()
            },
            forbidden_paths: scope.forbidden_paths.clone(),
            integration_bundle_ref,
            mcp_config_ref,
            skill_bundle_ref,
            lifecycle_bridge_ref,
            environment_allowlist: vec![
                "ELIOT_GOVERNOR_EXE".to_owned(),
                "ELIOT_AGENT_SESSION_ID".to_owned(),
                "ELIOT_PROJECT_ID".to_owned(),
                "ELIOT_TASK_ID".to_owned(),
                "ELIOT_WORK_ITEM_ID".to_owned(),
                "ELIOT_WORK_LEASE_ID".to_owned(),
                "ELIOT_WORKTREE_LEASE_ID".to_owned(),
                "ELIOT_ROLE_LEASE_ID".to_owned(),
            ],
            permission_profile: if mode == HostMode::Supervised && scope.role_lease_id.is_some() {
                "lease_scoped".to_owned()
            } else if mode == HostMode::Supervised {
                "unattached_readonly".to_owned()
            } else {
                "host_interactive".to_owned()
            },
            model_route_if_selected: model_route,
            max_turns_or_steps: None,
            wall_clock_budget_seconds: if mode == HostMode::Supervised { 900 } else { 0 },
            cost_budget_if_supported: None,
            session_id,
            resume_policy: "recorded_session_only".to_owned(),
            structured_output_schema_ref: (mode == HostMode::Supervised)
                .then(|| "eliot://schema/agent-result-envelope-v1".to_owned()),
            stdout_stderr_spool: "runtime://host-invocations".to_owned(),
            artifact_manifest_ref: "runtime://host-artifacts".to_owned(),
            idempotency_key,
            expected_result_kind: "agent_result_envelope".to_owned(),
            contract_hash: String::new(),
        };
        contract.contract_hash = blake3::hash(&serde_json::to_vec(&contract)?)
            .to_hex()
            .to_string();
        Ok(contract)
    }
}

fn launch_integration_refs(
    host_id: AgentHostId,
    bundle: &Path,
) -> (String, String, String, String) {
    match host_id {
        AgentHostId::OpenCode => (
            bundle.to_string_lossy().into_owned(),
            bundle.join("opencode.json").to_string_lossy().into_owned(),
            bundle.join("skills").to_string_lossy().into_owned(),
            bundle
                .join("plugins")
                .join("eliot.js")
                .to_string_lossy()
                .into_owned(),
        ),
        AgentHostId::Claude => (
            bundle.to_string_lossy().into_owned(),
            bundle.join(".mcp.json").to_string_lossy().into_owned(),
            bundle.join("skills").to_string_lossy().into_owned(),
            bundle
                .join("hooks")
                .join("hooks.json")
                .to_string_lossy()
                .into_owned(),
        ),
        AgentHostId::Antigravity => (
            "governor://managed-antigravity-cli-v1".to_owned(),
            "governor://mcp/stdio".to_owned(),
            "governor://skills/eliot-agent".to_owned(),
            "governor://host-invocations/attempt-journal-v1".to_owned(),
        ),
        AgentHostId::Codex => (
            bundle.to_string_lossy().into_owned(),
            bundle.join("README.md").to_string_lossy().into_owned(),
            bundle.join("skills").to_string_lossy().into_owned(),
            bundle.join("README.md").to_string_lossy().into_owned(),
        ),
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct HostEventService;

impl HostEventService {
    pub fn normalize(
        self,
        host_id: AgentHostId,
        declared_event: &str,
        raw: &[u8],
    ) -> Result<HostEventEnvelope, EngineError> {
        if raw.len() > 64 * 1024 {
            return Err(EngineError::ServiceNotReady {
                service: "host-event".to_owned(),
                reason: "event input exceeds 64 KiB".to_owned(),
            });
        }
        let value: Value = if raw.is_empty() {
            Value::Object(serde_json::Map::default())
        } else {
            serde_json::from_slice(raw)?
        };
        let event_kind = value
            .get("event_kind")
            .and_then(Value::as_str)
            .unwrap_or(declared_event)
            .to_owned();
        let tool_or_command = string_field(&value, &["tool", "tool_name", "command"]);
        let changed_path_refs = ["changed_path", "file_path", "path"]
            .into_iter()
            .filter_map(|key| value.get(key).and_then(Value::as_str).map(str::to_owned))
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        Ok(HostEventEnvelope {
            host_id,
            host_session_id: string_field(&value, &["host_session_id", "session_id"]),
            eliot_session_id: None,
            task_id: None,
            work_item_id: None,
            event_kind: event_kind.clone(),
            event_time: OffsetDateTime::now_utc(),
            tool_or_command,
            normalized_input_hash: blake3::hash(raw).to_hex().to_string(),
            output_or_error_ref: value
                .get("error")
                .and_then(Value::as_str)
                .map(|_| format!("host-event-error:{}", blake3::hash(raw).to_hex())),
            changed_path_refs,
            permission_event: event_kind
                .to_ascii_lowercase()
                .contains("permission")
                .then_some(event_kind.clone()),
            compaction_or_resume: (event_kind.to_ascii_lowercase().contains("compact")
                || event_kind.to_ascii_lowercase().contains("resume"))
            .then_some(event_kind),
            raw_event_ref: None,
            taint: TaintClass::ExternalAgent,
        })
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct HostBrokerService;

impl HostBrokerService {
    pub fn register_session(
        self,
        state: &mut DelegationState,
        agent_session_id: AgentSessionId,
        host_id: AgentHostId,
        implementation_name: String,
        client_instance_id: String,
        capability_envelope: AgentCapabilityEnvelope,
    ) -> Result<AgentSessionHostBinding, EngineError> {
        if let Some(existing) = state
            .agent_host_sessions
            .iter()
            .find(|binding| binding.agent_session_id == agent_session_id)
        {
            if existing.host_identity.host_id != host_id {
                return Err(host_broker_error(
                    "agent session is already bound to a different host",
                ));
            }
            return Ok(existing.clone());
        }
        if let Some(existing) = state.agent_host_sessions.iter().find(|binding| {
            binding.host_identity.host_id == host_id
                && binding.host_identity.client_instance_id == client_instance_id
        }) {
            return Ok(existing.clone());
        }
        let binding = AgentSessionHostBinding {
            agent_session_id,
            host_identity: AgentHostIdentity {
                host_id,
                implementation_name,
                client_instance_id,
            },
            capability_envelope,
            bound_project_id: None,
            bound_task_id: None,
            task_role_lease_refs: Vec::new(),
        };
        state.agent_host_sessions.push(binding.clone());
        Ok(binding)
    }

    pub fn bind_session_scope(
        self,
        state: &mut DelegationState,
        agent_session_id: AgentSessionId,
        project_id: ProjectId,
        task_id: TaskId,
    ) -> Result<AgentSessionHostBinding, EngineError> {
        let binding = state
            .agent_host_sessions
            .iter_mut()
            .find(|binding| binding.agent_session_id == agent_session_id)
            .ok_or_else(|| host_broker_error("agent host session is not registered"))?;
        if binding
            .bound_project_id
            .is_some_and(|bound| bound != project_id)
        {
            return Err(host_broker_error(
                "agent session is already bound to a different project",
            ));
        }
        if binding.bound_task_id.is_some_and(|bound| bound != task_id) {
            return Err(host_broker_error(
                "agent session is already bound to a different task",
            ));
        }
        binding.bound_project_id = Some(project_id);
        binding.bound_task_id = Some(task_id);
        Ok(binding.clone())
    }

    pub fn grant_role(
        self,
        state: &mut DelegationState,
        task_id: TaskId,
        agent_session_id: AgentSessionId,
        role: AgentRole,
        capability_scope: Vec<String>,
        ttl_minutes: i64,
    ) -> Result<(TaskRoleLease, Option<ControllerLease>), EngineError> {
        if ttl_minutes <= 0 {
            return Err(host_broker_error("role lease TTL must be positive"));
        }
        if !state
            .agent_host_sessions
            .iter()
            .any(|binding| binding.agent_session_id == agent_session_id)
        {
            return Err(host_broker_error("agent host session is not registered"));
        }
        let now = OffsetDateTime::now_utc();
        if let Some(existing) = state.task_role_leases.iter().find(|lease| {
            lease.task_id == task_id
                && lease.agent_session_id == agent_session_id
                && lease.role == role
                && lease.expires_at > now
        }) {
            let controller = state
                .controller_leases
                .iter()
                .find(|lease| {
                    lease.task_id == task_id
                        && lease.agent_session_id == agent_session_id
                        && lease.expires_at > now
                })
                .cloned();
            return Ok((existing.clone(), controller));
        }
        if role == AgentRole::Controller
            && state.controller_leases.iter().any(|lease| {
                lease.task_id == task_id
                    && lease.agent_session_id != agent_session_id
                    && lease.expires_at > now
            })
        {
            return Err(host_broker_error(
                "task already has a different active ControllerLease",
            ));
        }
        let epoch = state
            .task_role_leases
            .iter()
            .filter(|lease| lease.task_id == task_id)
            .map(|lease| lease.epoch)
            .max()
            .unwrap_or(0)
            + 1;
        let lease = TaskRoleLease {
            role_lease_id: uuid_like("task-role-lease"),
            task_id,
            agent_session_id,
            role,
            capability_scope,
            expires_at: now + time::Duration::minutes(ttl_minutes),
            epoch,
        };
        let controller = (role == AgentRole::Controller).then(|| ControllerLease {
            controller_lease_id: uuid_like("controller-lease"),
            task_id,
            agent_session_id,
            expires_at: lease.expires_at,
            epoch,
        });
        if let Some(binding) = state
            .agent_host_sessions
            .iter_mut()
            .find(|binding| binding.agent_session_id == agent_session_id)
        {
            binding
                .task_role_lease_refs
                .push(lease.role_lease_id.clone());
        }
        state.task_role_leases.push(lease.clone());
        if let Some(controller) = &controller {
            state.controller_leases.push(controller.clone());
        }
        Ok((lease, controller))
    }

    pub fn enqueue(
        self,
        state: &mut DelegationState,
        request: &AgentInvocationRequest,
        host_profile: &AgentHostRuntimeProfile,
        work_lease_active: bool,
    ) -> Result<OperationJob, EngineError> {
        if host_profile.status != HostProfileStatus::Current {
            return Err(host_broker_error("host runtime profile is not current"));
        }
        let now = OffsetDateTime::now_utc();
        let role = state
            .task_role_leases
            .iter()
            .find(|lease| {
                lease.role_lease_id == request.role_lease_id
                    && lease.task_id == request.task_id
                    && lease.expires_at > now
            })
            .ok_or_else(|| host_broker_error("invocation has no active matching TaskRoleLease"))?;
        if request.work_lease_id.is_some() && !work_lease_active {
            return Err(host_broker_error(
                "invocation references a WorkLease that is not active",
            ));
        }
        for capability in &request.requested_capabilities {
            if !role.capability_scope.contains(capability) {
                return Err(host_broker_error(
                    "invocation requests capability outside the TaskRoleLease",
                ));
            }
        }
        if let Some(existing) = state
            .operation_jobs
            .iter()
            .find(|job| job.idempotency_key == request.idempotency_key)
        {
            if existing.invocation_id != request.invocation_id {
                return Err(host_broker_error(
                    "idempotency key is already bound to a different invocation",
                ));
            }
            let same_request = state
                .agent_invocations
                .iter()
                .find(|item| item.invocation_id == existing.invocation_id)
                .is_some_and(|item| item == request);
            if !same_request {
                return Err(host_broker_error(
                    "idempotency replay changed the AgentInvocationRequest",
                ));
            }
            return Ok(existing.clone());
        }
        let job = OperationJob {
            job_id: uuid_like("operation-job"),
            invocation_id: request.invocation_id.clone(),
            host_id: host_profile.host_id,
            state: OperationJobState::Queued,
            attempt: 0,
            resume_session_id: None,
            result_ref: None,
            idempotency_key: request.idempotency_key.clone(),
            created_at: now,
            updated_at: now,
        };
        state.agent_invocations.push(request.clone());
        state.operation_jobs.push(job.clone());
        Ok(job)
    }

    pub fn transition(
        self,
        job: &mut OperationJob,
        next: OperationJobState,
        resume_session_id: Option<String>,
    ) -> Result<(), EngineError> {
        let legal = matches!(
            (job.state, next),
            (
                OperationJobState::Queued | OperationJobState::UnknownOutcome,
                OperationJobState::Running
            ) | (
                OperationJobState::Running,
                OperationJobState::Completed
                    | OperationJobState::Failed
                    | OperationJobState::TimedOut
                    | OperationJobState::UnknownOutcome
            ) | (
                OperationJobState::UnknownOutcome,
                OperationJobState::Reconciled
            )
        );
        if !legal {
            return Err(host_broker_error("illegal OperationJob transition"));
        }
        if next == OperationJobState::Running {
            job.attempt += 1;
        }
        if resume_session_id.is_some() {
            job.resume_session_id = resume_session_id;
        }
        job.state = next;
        job.updated_at = OffsetDateTime::now_utc();
        Ok(())
    }

    pub fn record_result(
        self,
        state: &mut DelegationState,
        result: AgentResultEnvelope,
    ) -> Result<AgentResultEnvelope, EngineError> {
        if !result.candidate_only {
            return Err(host_broker_error(
                "external agent result must remain candidate-only",
            ));
        }
        if let Some(existing) = state
            .agent_results
            .iter()
            .find(|existing| existing.result_id == result.result_id)
        {
            let mut existing_semantic = existing.clone();
            existing_semantic.canonical_receipt = None;
            if existing_semantic != result {
                return Err(host_broker_error(
                    "result id replay changed the AgentResultEnvelope",
                ));
            }
            return Ok(existing.clone());
        }
        let job = state
            .operation_jobs
            .iter_mut()
            .find(|job| job.invocation_id == result.invocation_id)
            .ok_or_else(|| host_broker_error("AgentResultEnvelope has no matching OperationJob"))?;
        if job.host_id != result.host_id {
            return Err(host_broker_error("result host does not match OperationJob"));
        }
        if job.state != OperationJobState::Running {
            return Err(host_broker_error(
                "AgentResultEnvelope requires a running OperationJob",
            ));
        }
        job.state = match result.status {
            AgentResultStatus::Succeeded | AgentResultStatus::Partial => {
                OperationJobState::Completed
            }
            AgentResultStatus::Blocked | AgentResultStatus::Failed => OperationJobState::Failed,
            AgentResultStatus::TimedOut => OperationJobState::TimedOut,
            AgentResultStatus::UnknownOutcome => OperationJobState::UnknownOutcome,
        };
        job.result_ref = Some(result.result_id.clone());
        job.updated_at = OffsetDateTime::now_utc();
        state.agent_results.push(result.clone());
        Ok(result)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn disposition_result(
        self,
        state: &mut DelegationState,
        controller_session_id: AgentSessionId,
        result_id: &str,
        kind: AgentResultDispositionKind,
        reason: String,
        evidence_refs: Vec<String>,
        idempotency_key: String,
    ) -> Result<AgentResultDisposition, EngineError> {
        let (invocation_id, task_id) = result_disposition_scope(state, result_id)?;
        let now = OffsetDateTime::now_utc();
        let controller_active = state.controller_leases.iter().any(|lease| {
            lease.task_id == task_id
                && lease.agent_session_id == controller_session_id
                && lease.expires_at > now
        });
        if !controller_active {
            return Err(host_broker_error(
                "result disposition requires the active ControllerLease",
            ));
        }
        record_result_disposition(
            state,
            controller_session_id,
            result_id,
            &invocation_id,
            task_id,
            kind,
            reason,
            evidence_refs,
            idempotency_key,
            now,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn disposition_result_as_human_operator(
        self,
        state: &mut DelegationState,
        operator_session_id: AgentSessionId,
        result_id: &str,
        kind: AgentResultDispositionKind,
        reason: String,
        evidence_refs: Vec<String>,
        idempotency_key: String,
    ) -> Result<AgentResultDisposition, EngineError> {
        if kind == AgentResultDispositionKind::Accepted {
            return Err(host_broker_error(
                "HumanOperator result acceptance requires the governed controller finalization path",
            ));
        }
        let (invocation_id, task_id) = result_disposition_scope(state, result_id)?;
        record_result_disposition(
            state,
            operator_session_id,
            result_id,
            &invocation_id,
            task_id,
            kind,
            reason,
            evidence_refs,
            idempotency_key,
            OffsetDateTime::now_utc(),
        )
    }
}

fn result_disposition_scope(
    state: &DelegationState,
    result_id: &str,
) -> Result<(String, TaskId), EngineError> {
    let result = state
        .agent_results
        .iter()
        .find(|result| result.result_id == result_id)
        .ok_or_else(|| host_broker_error("result disposition has no AgentResultEnvelope"))?;
    let invocation = state
        .agent_invocations
        .iter()
        .find(|request| request.invocation_id == result.invocation_id)
        .ok_or_else(|| host_broker_error("result disposition has no AgentInvocationRequest"))?;
    Ok((invocation.invocation_id.clone(), invocation.task_id))
}

#[allow(clippy::too_many_arguments)]
fn record_result_disposition(
    state: &mut DelegationState,
    authority_session_id: AgentSessionId,
    result_id: &str,
    invocation_id: &str,
    task_id: TaskId,
    kind: AgentResultDispositionKind,
    reason: String,
    evidence_refs: Vec<String>,
    idempotency_key: String,
    now: OffsetDateTime,
) -> Result<AgentResultDisposition, EngineError> {
    if let Some(existing) = state
        .agent_result_dispositions
        .iter()
        .find(|item| item.idempotency_key == idempotency_key)
    {
        if existing.result_id != result_id
            || existing.controller_session_id != authority_session_id
            || existing.kind != kind
            || existing.reason != reason
            || existing.evidence_refs != evidence_refs
        {
            return Err(host_broker_error(
                "disposition idempotency replay changed semantic input",
            ));
        }
        return Ok(existing.clone());
    }
    let disposition = AgentResultDisposition {
        disposition_id: uuid_like("agent-result-disposition"),
        result_id: result_id.to_owned(),
        invocation_id: invocation_id.to_owned(),
        task_id,
        controller_session_id: authority_session_id,
        kind,
        reason,
        evidence_refs,
        idempotency_key,
        created_at: now,
        canonical_receipt: None,
    };
    state.agent_result_dispositions.push(disposition.clone());
    Ok(disposition)
}

fn host_broker_error(reason: &str) -> EngineError {
    EngineError::ServiceNotReady {
        service: "host-broker".to_owned(),
        reason: reason.to_owned(),
    }
}

pub fn bundle_root(repo_root: &Path, host_id: AgentHostId) -> PathBuf {
    match host_id {
        AgentHostId::OpenCode => repo_root.join("integrations/opencode"),
        AgentHostId::Claude => repo_root.join("integrations/claude/eliot"),
        AgentHostId::Codex => repo_root.join("integrations/codex"),
        AgentHostId::Antigravity => repo_root.join("integrations/antigravity"),
    }
}

pub fn bundle_hash(path: &Path, host_id: AgentHostId) -> Result<String, EngineError> {
    let mut files = Vec::new();
    collect_files(path, host_id, &mut files)?;
    files.sort();
    let mut hasher = blake3::Hasher::new();
    for file in files {
        let relative = file.strip_prefix(path).unwrap_or(&file);
        hasher.update(relative.to_string_lossy().replace('\\', "/").as_bytes());
        hasher.update(&[0]);
        let mut reader = BufReader::new(File::open(&file)?);
        let mut buffer = vec![0_u8; 64 * 1024];
        loop {
            let read = reader.read(&mut buffer)?;
            if read == 0 {
                break;
            }
            hasher.update(&buffer[..read]);
        }
        hasher.update(&[0]);
    }
    Ok(hasher.finalize().to_hex().to_string())
}

fn split_frontmatter(body: &str) -> Option<(&str, &str)> {
    let rest = body
        .strip_prefix("---\n")
        .or_else(|| body.strip_prefix("---\r\n"))?;
    let marker = if rest.contains("\n---\n") {
        "\n---\n"
    } else {
        "\r\n---\r\n"
    };
    let (frontmatter, markdown) = rest.split_once(marker)?;
    Some((frontmatter, markdown))
}

fn frontmatter_value(frontmatter: &str, key: &str) -> Option<String> {
    frontmatter.lines().find_map(|line| {
        let (candidate, value) = line.split_once(':')?;
        (candidate.trim() == key).then(|| value.trim().trim_matches('"').to_owned())
    })
}

fn resolve_executable(host_id: AgentHostId) -> Option<PathBuf> {
    let env_key = format!("ELIOT_{}_EXE", host_id.as_str().to_ascii_uppercase());
    if let Some(path) = std::env::var_os(env_key).map(PathBuf::from)
        && path.is_file()
    {
        return Some(path);
    }
    let local = std::env::var_os("LOCALAPPDATA").map(PathBuf::from);
    let home = std::env::var_os("USERPROFILE").map(PathBuf::from);
    let candidates = match host_id {
        AgentHostId::OpenCode => local
            .into_iter()
            .map(|root| root.join("OpenCode/opencode-cli.exe"))
            .collect(),
        AgentHostId::Claude => {
            let mut result = Vec::new();
            if let Some(root) = local {
                let packages = root.join("Microsoft/WinGet/Packages");
                if let Ok(entries) = std::fs::read_dir(packages) {
                    for entry in entries.flatten() {
                        if entry
                            .file_name()
                            .to_string_lossy()
                            .starts_with("Anthropic.ClaudeCode_")
                        {
                            result.push(entry.path().join("claude.exe"));
                        }
                    }
                }
            }
            if let Some(root) = home {
                result.push(root.join(".local/bin/claude.exe"));
            }
            result
        }
        AgentHostId::Antigravity => local
            .into_iter()
            .map(|root| root.join("agy/bin/agy.exe"))
            .collect(),
        AgentHostId::Codex => Vec::new(),
    };
    candidates
        .into_iter()
        .find(|path| path.is_file())
        .or_else(|| {
            search_path(match host_id {
                AgentHostId::OpenCode => "opencode.exe",
                AgentHostId::Claude => "claude.exe",
                AgentHostId::Antigravity => "agy.exe",
                AgentHostId::Codex => "codex.exe",
            })
        })
}

fn search_path(name: &str) -> Option<PathBuf> {
    std::env::var_os("PATH").and_then(|path| {
        std::env::split_paths(&path)
            .map(|directory| directory.join(name))
            .find(|candidate| candidate.is_file())
    })
}

fn command_text(executable: &Path, args: &[&str]) -> Result<String, EngineError> {
    let output = Command::new(executable).args(args).output()?;
    let mut text = String::from_utf8_lossy(&output.stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&output.stderr));
    if !output.status.success() && text.trim().is_empty() {
        return Err(EngineError::ServiceNotReady {
            service: "host-profile".to_owned(),
            reason: format!("{} {:?} failed", executable.display(), args),
        });
    }
    Ok(text)
}

fn hash_file(path: &Path) -> Result<String, EngineError> {
    let mut reader = BufReader::new(File::open(path)?);
    let mut hasher = blake3::Hasher::new();
    let mut buffer = vec![0_u8; 1024 * 1024];
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(format!("blake3:{}", hasher.finalize().to_hex()))
}

#[allow(clippy::type_complexity)]
fn capability_matrix(
    host_id: AgentHostId,
    help: &str,
) -> (
    HostProtocolSurfaces,
    Vec<String>,
    Vec<String>,
    Vec<String>,
    Vec<String>,
    bool,
) {
    match host_id {
        AgentHostId::OpenCode => {
            let valid = help.contains("opencode run")
                && help.contains("--format")
                && help.contains("--session")
                && help.contains("--model");
            (
                HostProtocolSurfaces {
                    mcp_stdio: true,
                    acp_or_sdk: help.contains(" acp "),
                    plugin: true,
                    hooks_or_events: true,
                    skills: true,
                    structured_output: help.contains("--format"),
                    permissions: help.contains("permissions"),
                    ..HostProtocolSurfaces::default()
                },
                vec![
                    "interactive_client".to_owned(),
                    "supervised_noninteractive".to_owned(),
                    "resume".to_owned(),
                    "background_or_server".to_owned(),
                ],
                vec!["run_json".to_owned(), "session_resume".to_owned()],
                vec!["json_events".to_owned(), "exit_status".to_owned()],
                Vec::new(),
                valid,
            )
        }
        AgentHostId::Claude => {
            let valid = help.contains("--plugin-dir")
                && help.contains("--mcp-config")
                && help.contains("--output-format")
                && help.contains("--include-hook-events")
                && help.contains("--resume");
            (
                HostProtocolSurfaces {
                    mcp_stdio: true,
                    plugin: true,
                    hooks_or_events: true,
                    skills: true,
                    structured_output: help.contains("--json-schema"),
                    worktree: help.contains("--worktree"),
                    permissions: help.contains("--permission-mode"),
                    ..HostProtocolSurfaces::default()
                },
                vec![
                    "interactive_client".to_owned(),
                    "supervised_noninteractive".to_owned(),
                    "resume".to_owned(),
                    "background_or_server".to_owned(),
                ],
                vec!["stream_json".to_owned(), "session_resume".to_owned()],
                vec![
                    "stream_json".to_owned(),
                    "hook_events".to_owned(),
                    "structured_result".to_owned(),
                ],
                (!help.contains("--max-turns"))
                    .then(|| {
                        "installed CLI has no --max-turns; use external wall-clock bound".to_owned()
                    })
                    .into_iter()
                    .collect(),
                valid,
            )
        }
        AgentHostId::Antigravity => antigravity_capability_matrix(help),
        AgentHostId::Codex => (
            HostProtocolSurfaces {
                mcp_stdio: true,
                ..HostProtocolSurfaces::default()
            },
            vec!["interactive_client".to_owned()],
            Vec::new(),
            vec!["exit_status".to_owned()],
            Vec::new(),
            true,
        ),
    }
}

#[allow(clippy::type_complexity)]
fn antigravity_capability_matrix(
    help: &str,
) -> (
    HostProtocolSurfaces,
    Vec<String>,
    Vec<String>,
    Vec<String>,
    Vec<String>,
    bool,
) {
    let required = [
        "--add-dir",
        "--agent",
        "--mode",
        "--model",
        "--new-project",
        "--print",
        "--print-timeout",
        "--sandbox",
    ];
    let valid = required.iter().all(|flag| help.contains(flag));
    (
        HostProtocolSurfaces {
            mcp_stdio: true,
            structured_output: true,
            worktree: true,
            permissions: true,
            ..HostProtocolSurfaces::default()
        },
        vec![
            "interactive_client".to_owned(),
            "supervised_noninteractive".to_owned(),
        ],
        vec![
            "lease_scoped_candidate_implementation".to_owned(),
            "attempt_before_call_journal".to_owned(),
            "unknown_outcome_reconciliation".to_owned(),
        ],
        vec![
            "governor_launch_receipt".to_owned(),
            "stdout_stderr_spool".to_owned(),
            "exit_status".to_owned(),
        ],
        (!valid)
            .then(|| "installed agy CLI lacks one or more governed launch flags".to_owned())
            .into_iter()
            .collect(),
        valid,
    )
}

fn implementation_name(host_id: AgentHostId) -> &'static str {
    match host_id {
        AgentHostId::Codex => "OpenAI Codex",
        AgentHostId::Antigravity => "Google Antigravity",
        AgentHostId::OpenCode => "OpenCode",
        AgentHostId::Claude => "Claude Code",
    }
}

pub fn host_generated_bundle_entry(host_id: AgentHostId, path: &Path) -> bool {
    if matches!(
        path.file_name().and_then(|name| name.to_str()),
        Some(
            "bin"
                | "eliot-launch-bundle.json"
                | "eliot-global-install.json"
                | "INSTALL-MANIFEST.json"
        )
    ) {
        return true;
    }
    if host_id != AgentHostId::OpenCode {
        return false;
    }
    matches!(
        path.file_name().and_then(|name| name.to_str()),
        Some("node_modules" | "package.json" | "package-lock.json" | "bun.lock" | ".gitignore")
    )
}

fn collect_files(
    root: &Path,
    host_id: AgentHostId,
    files: &mut Vec<PathBuf>,
) -> Result<(), EngineError> {
    for entry in std::fs::read_dir(root)? {
        let entry = entry?;
        let path = entry.path();
        if host_generated_bundle_entry(host_id, &path) {
            continue;
        }
        if path.is_dir() {
            collect_files(&path, host_id, files)?;
        } else if path.is_file() {
            files.push(path);
        }
    }
    Ok(())
}

fn string_field(value: &Value, keys: &[&str]) -> Option<String> {
    keys.iter()
        .find_map(|key| value.get(*key).and_then(Value::as_str).map(str::to_owned))
}

fn uuid_like(prefix: &str) -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    format!(
        "{prefix}:{}-{}-{}",
        std::process::id(),
        OffsetDateTime::now_utc().unix_timestamp_nanos(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    )
}
