use crate::EngineError;
use eliot_types::{
    AgentCapabilityEnvelope, AgentHostId, AgentHostIdentity, AgentHostRuntimeProfile,
    AgentInvocationRequest, AgentResultDisposition, AgentResultDispositionKind,
    AgentResultEnvelope, AgentResultStatus, AgentRole, AgentSessionHostBinding, AgentSessionId,
    AgentSessionState, AuthorityLeaseLifetime, AuthorityLeaseState, AuthorityRevocationReceipt,
    ControllerLease, DelegationState, HostEventEnvelope, HostLaunchContract, HostLaunchScope,
    HostMode, HostProfileStatus, HostProtocolSurfaces, OperationJob, OperationJobState,
    OperationPhase, ProjectId, TaintClass, TaskId, TaskRoleLease,
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
    "eliot-work",
    "eliot-remember",
    "eliot-recover",
    "eliot-finish",
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
    pub package_parity: BTreeMap<String, bool>,
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
        let codex_root = repo_root.join("plugin/eliot-governor/skills");
        let antigravity_root = repo_root.join("plugin/eliot-antigravity-official/skills");
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
            if estimated_tokens > 500 {
                errors.push(format!("{name}: body exceeds estimated 500 token budget"));
            }
            if description.chars().count().div_ceil(4) > 25 {
                errors.push(format!(
                    "{name}: description exceeds estimated 25 token budget"
                ));
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
            let codex = std::fs::read(codex_root.join(name).join("SKILL.md"))?;
            let antigravity = std::fs::read(antigravity_root.join(name).join("SKILL.md"))?;
            let opencode_parity = opencode == body.as_bytes();
            let claude_parity = claude == body.as_bytes();
            let codex_parity = codex == body.as_bytes();
            let antigravity_parity = antigravity == body.as_bytes();
            if !opencode_parity || !claude_parity || !codex_parity || !antigravity_parity {
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
                package_parity: BTreeMap::from([
                    ("codex".to_owned(), codex_parity),
                    ("antigravity".to_owned(), antigravity_parity),
                ]),
            });
        }
        if descriptions.div_ceil(4) > 100 {
            errors.push("combined descriptions exceed estimated 100 token budget".to_owned());
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

/// The host packages that carry a copy of the canonical skill bodies.
/// Declared in `skill-pack.manifest.json` as `derived_packages`; kept here so
/// the sync and the lint cannot disagree about what is derived.
pub const DERIVED_SKILL_PACKAGES: [&str; 4] = [
    "integrations/opencode/skills",
    "integrations/claude/eliot/skills",
    "plugin/eliot-governor/skills",
    "plugin/eliot-antigravity-official/skills",
];

const DERIVED_PACKAGE_NOTICE: &str = "\
# Generated skill copies -- do not edit

Every `SKILL.md` under this directory is a byte-for-byte copy of
`integrations/agent-skills/<name>/SKILL.md`, written by:

```
just sync-skills
```

Edit the canonical body under `integrations/agent-skills` and re-run that
command. Editing a file here is silently reverted by the next sync, and
`SkillPackService::lint` fails the build in the meantime.
";

/// Report of one sync pass: which copies were rewritten and whether the
/// manifest hashes moved.
#[derive(Clone, Debug, Default, Serialize)]
pub struct SkillPackSyncReport {
    pub rewritten: Vec<String>,
    pub already_current: Vec<String>,
    pub manifest_updated: bool,
    pub pack_hash: String,
}

// Structs keep manifest field order stable; `serde_json` map ordering is not
// part of the package contract.
#[derive(Serialize)]
struct SkillPackManifest<'a> {
    schema_version: &'a str,
    hash_algorithm: &'a str,
    pack_hash: &'a str,
    listing_characters: usize,
    skills: &'a [ManifestSkill],
    derived_packages: &'a [&'a str],
}

#[derive(Serialize)]
struct ManifestSkill {
    name: &'static str,
    content_blake3: String,
}

impl SkillPackService {
    /// Rewrites every derived host copy from the canonical body and refreshes
    /// the manifest hashes. This is the only writer of the derived packages:
    /// the goal is one editable source, not three that a lint compares.
    pub fn sync(self, repo_root: &Path) -> Result<SkillPackSyncReport, EngineError> {
        let canonical_root = repo_root.join("integrations/agent-skills");
        let mut report = SkillPackSyncReport::default();
        let mut pack_material = String::new();
        let mut manifest_skills = Vec::new();
        let mut listing_characters = 0usize;

        for name in ELIOT_SKILL_NAMES {
            let body = std::fs::read_to_string(canonical_root.join(name).join("SKILL.md"))?;
            let hash = canonical_skill_content_hash(&body);
            if let Some((frontmatter, _)) = split_frontmatter(&body) {
                listing_characters += frontmatter_value(frontmatter, "description")
                    .unwrap_or_default()
                    .chars()
                    .count();
            }

            for package in DERIVED_SKILL_PACKAGES {
                let target_dir = repo_root.join(package).join(name);
                let target = target_dir.join("SKILL.md");
                let current = std::fs::read(&target).ok();
                let label = format!("{package}/{name}/SKILL.md");
                if current.as_deref() == Some(body.as_bytes()) {
                    report.already_current.push(label);
                    continue;
                }
                std::fs::create_dir_all(&target_dir)?;
                std::fs::write(&target, body.as_bytes())?;
                report.rewritten.push(label);
            }

            pack_material.push_str(name);
            pack_material.push(':');
            pack_material.push_str(&hash);
            pack_material.push('\n');
            manifest_skills.push(ManifestSkill {
                name,
                content_blake3: hash,
            });
        }

        for package in DERIVED_SKILL_PACKAGES
            .into_iter()
            .filter(|package| package.starts_with("integrations/"))
        {
            let notice = repo_root.join(package).join("README.md");
            if std::fs::read_to_string(&notice).ok().as_deref() != Some(DERIVED_PACKAGE_NOTICE) {
                std::fs::write(&notice, DERIVED_PACKAGE_NOTICE)?;
                report.rewritten.push(format!("{package}/README.md"));
            }
        }

        report.pack_hash = blake3::hash(pack_material.as_bytes()).to_hex().to_string();
        let manifest_path = canonical_root.join("skill-pack.manifest.json");
        let manifest = SkillPackManifest {
            schema_version: "eliot-agent-skill-pack-v1",
            hash_algorithm: "blake3(name:content_blake3 joined with LF in manifest order)",
            pack_hash: &report.pack_hash,
            listing_characters,
            skills: &manifest_skills,
            derived_packages: &DERIVED_SKILL_PACKAGES,
        };
        let rendered = format!("{}\n", serde_json::to_string_pretty(&manifest)?);
        if std::fs::read_to_string(&manifest_path).ok().as_deref() != Some(rendered.as_str()) {
            std::fs::write(&manifest_path, rendered)?;
            report.manifest_updated = true;
        }
        Ok(report)
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
            role_lease_epoch: scope.role_lease_epoch,
            operation_generation: scope.operation_generation,
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
                "ELIOT_GOVERNOR_CONFIG".to_owned(),
                "ELIOT_MCP_ACCESS_PROFILE".to_owned(),
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
        AgentHostId::Claude | AgentHostId::Codex => (
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

fn prior_idempotency_job_is_superseded_predispatch(
    state: &DelegationState,
    job: &OperationJob,
    request: &AgentInvocationRequest,
) -> bool {
    job.invocation_id == request.invocation_id
        && job.generation < request.operation_generation
        && job.state == OperationJobState::Abandoned
        && job.phase == OperationPhase::Abandoned
        && job.attempt == 0
        && job
            .result_ref
            .as_deref()
            .is_some_and(|result| result.starts_with("abandoned:"))
        && job.role_lease_id.as_ref().is_some_and(|role_lease_id| {
            state.task_role_leases.iter().any(|lease| {
                lease.role_lease_id == *role_lease_id && lease.state == AuthorityLeaseState::Revoked
            })
        })
}

#[cfg(test)]
mod generation_replay_tests {
    use super::prior_idempotency_job_is_superseded_predispatch;
    use eliot_types::{
        AgentHostId, AgentInvocationRequest, AgentRole, AgentSessionId, AuthorityLeaseLifetime,
        AuthorityLeaseState, DelegationState, OperationJob, OperationJobState, OperationPhase,
        ProjectId, TaskId, TaskRoleLease, WorkItemId,
    };
    use time::OffsetDateTime;

    #[test]
    fn prior_generation_requires_exact_zero_attempt_supersession() {
        let now = OffsetDateTime::now_utc();
        let task_id = TaskId::new_v7();
        let session_id = AgentSessionId::new_v7();
        let lease_id = "role-lease:prior-generation".to_owned();
        let invocation_id = "invocation:stable".to_owned();
        let mut state = DelegationState::default();
        state.task_role_leases.push(TaskRoleLease {
            role_lease_id: lease_id.clone(),
            task_id,
            agent_session_id: session_id,
            role: AgentRole::Auditor,
            capability_scope: vec!["emit_candidate_observation".to_owned()],
            expires_at: now + time::Duration::minutes(5),
            epoch: 2,
            state: AuthorityLeaseState::Revoked,
            lifetime: AuthorityLeaseLifetime::SealBound,
            owner_operation_id: Some("operation-job:prior".to_owned()),
            seal_attempt_id: Some("seal:prior".to_owned()),
            generation: 2,
            issued_at: Some(now),
            activated_at: Some(now),
            consumed_at: None,
            revoked_at: Some(now),
            revoke_reason: Some("published_seal_superseded_runtime_drift".to_owned()),
            superseded_by_epoch: Some(3),
        });
        let mut job = OperationJob {
            job_id: "operation-job:prior".to_owned(),
            invocation_id: invocation_id.clone(),
            host_id: AgentHostId::Antigravity,
            state: OperationJobState::Abandoned,
            attempt: 0,
            resume_session_id: None,
            result_ref: Some("abandoned:published_seal_superseded_runtime_drift".to_owned()),
            idempotency_key: "idempotency:stable".to_owned(),
            created_at: now,
            updated_at: now,
            generation: 2,
            phase: OperationPhase::Abandoned,
            phase_started_at: Some(now),
            last_progress_at: Some(now),
            phase_deadline_at: None,
            absolute_deadline_at: None,
            restart_count: 0,
            runtime_contract_sha256: Some("a".repeat(64)),
            role_lease_id: Some(lease_id),
            role_lease_epoch: Some(2),
        };
        let request = AgentInvocationRequest {
            invocation_id,
            project_id: ProjectId::new_v7(),
            task_id,
            work_item_id: WorkItemId::new_v7(),
            requested_capabilities: vec!["emit_candidate_observation".to_owned()],
            role_lease_id: "role-lease:current".to_owned(),
            role_lease_epoch: 3,
            operation_generation: 3,
            runtime_contract_sha256: Some("b".repeat(64)),
            work_lease_id: None,
            packet_refs: Vec::new(),
            expected_result_kind: "provider_execution_evidence".to_owned(),
            verifier_ref: "verifier:stable".to_owned(),
            idempotency_key: "idempotency:stable".to_owned(),
        };
        assert!(prior_idempotency_job_is_superseded_predispatch(
            &state, &job, &request
        ));
        job.attempt = 1;
        assert!(!prior_idempotency_job_is_superseded_predispatch(
            &state, &job, &request
        ));
        job.attempt = 0;
        job.state = OperationJobState::UnknownOutcome;
        assert!(!prior_idempotency_job_is_superseded_predispatch(
            &state, &job, &request
        ));
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AgentResultAdmission {
    Accepted(AgentResultEnvelope),
    StaleEvidencePreserved(AgentResultEnvelope),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingRoleGrant {
    pub role_lease_id: String,
    pub task_id: TaskId,
    pub agent_session_id: AgentSessionId,
    pub role: AgentRole,
    pub capability_scope: Vec<String>,
    pub expires_at: OffsetDateTime,
    pub epoch: u64,
    pub owner_operation_id: Option<String>,
}

#[derive(Clone, Debug)]
pub struct ActiveRoleAuthorityCheck<'a> {
    pub operation_id: &'a str,
    pub task_id: TaskId,
    pub role_lease_id: &'a str,
    pub expected_epoch: u64,
    pub generation: u64,
    pub host_id: AgentHostId,
    pub requested_capabilities: &'a [String],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActiveRoleAuthority {
    pub role_lease: TaskRoleLease,
    pub host_binding: AgentSessionHostBinding,
    pub operation_job: Option<OperationJob>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AuthorityCleanupReport {
    pub expired_role_lease_ids: Vec<String>,
    pub retired_session_ids: Vec<AgentSessionId>,
    pub abandoned_operation_ids: Vec<String>,
    pub revocation_receipt_ids: Vec<String>,
}

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
        self.register_session_generation(
            state,
            agent_session_id,
            host_id,
            implementation_name,
            client_instance_id,
            capability_envelope,
            1,
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn register_session_generation(
        self,
        state: &mut DelegationState,
        agent_session_id: AgentSessionId,
        host_id: AgentHostId,
        implementation_name: String,
        client_instance_id: String,
        capability_envelope: AgentCapabilityEnvelope,
        generation: u64,
        owner_operation_id: Option<String>,
    ) -> Result<AgentSessionHostBinding, EngineError> {
        if generation == 0 {
            return Err(host_broker_error(
                "fresh agent session requires nonzero generation",
            ));
        }
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
            if existing.state != AgentSessionState::Active || existing.generation != generation {
                return Err(host_broker_error(
                    "agent session ID is retired, disconnected, or generation-mismatched",
                ));
            }
            return Ok(existing.clone());
        }
        if let Some(existing) = state.agent_host_sessions.iter().find(|binding| {
            binding.host_identity.host_id == host_id
                && binding.host_identity.client_instance_id == client_instance_id
        }) {
            if existing.state != AgentSessionState::Active || existing.generation != generation {
                return Err(host_broker_error(
                    "host client instance is retired, disconnected, or generation-mismatched",
                ));
            }
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
            state: AgentSessionState::Active,
            generation,
            owner_operation_id,
            disconnected_at: None,
            disconnect_reason: None,
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
        let now = OffsetDateTime::now_utc();
        if let Some(existing) = state.task_role_leases.iter().find(|lease| {
            lease.task_id == task_id
                && lease.agent_session_id == agent_session_id
                && lease.role == role
                && lease.state == AuthorityLeaseState::Active
                && lease.expires_at > now
        }) {
            let controller = state
                .controller_leases
                .iter()
                .find(|lease| {
                    lease.task_id == task_id
                        && lease.agent_session_id == agent_session_id
                        && lease.state == AuthorityLeaseState::Active
                        && lease.expires_at > now
                })
                .cloned();
            return Ok((existing.clone(), controller));
        }
        let grant = self.prepare_role_grant(
            state,
            task_id,
            agent_session_id,
            role,
            capability_scope,
            ttl_minutes,
            None,
        )?;
        let mut leases = self.activate_role_grants(
            state,
            &[grant],
            AuthorityLeaseLifetime::Persistent,
            None,
            1,
        )?;
        let lease = leases
            .pop()
            .ok_or_else(|| host_broker_error("role activation returned no lease"))?;
        let controller = state
            .controller_leases
            .iter()
            .find(|candidate| {
                candidate.task_id == task_id
                    && candidate.agent_session_id == agent_session_id
                    && candidate.epoch == lease.epoch
                    && candidate.generation == lease.generation
                    && candidate.state == AuthorityLeaseState::Active
            })
            .cloned();
        Ok((lease, controller))
    }

    #[allow(clippy::too_many_arguments)]
    pub fn prepare_role_grant(
        self,
        state: &DelegationState,
        task_id: TaskId,
        agent_session_id: AgentSessionId,
        role: AgentRole,
        capability_scope: Vec<String>,
        ttl_minutes: i64,
        owner_operation_id: Option<String>,
    ) -> Result<PendingRoleGrant, EngineError> {
        if ttl_minutes <= 0 {
            return Err(host_broker_error("role lease TTL must be positive"));
        }
        let session = state
            .agent_host_sessions
            .iter()
            .find(|binding| binding.agent_session_id == agent_session_id)
            .ok_or_else(|| host_broker_error("agent host session is not registered"))?;
        if session.state != AgentSessionState::Active {
            return Err(host_broker_error(
                "retired or disconnected session cannot acquire authority",
            ));
        }
        if session.bound_task_id.is_some_and(|bound| bound != task_id) {
            return Err(host_broker_error(
                "agent host session is bound to a different task",
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
        Ok(PendingRoleGrant {
            role_lease_id: uuid_like("task-role-lease"),
            task_id,
            agent_session_id,
            role,
            capability_scope,
            expires_at: OffsetDateTime::now_utc() + time::Duration::minutes(ttl_minutes),
            epoch,
            owner_operation_id,
        })
    }

    #[allow(
        clippy::too_many_lines,
        reason = "one cloned-state activation keeps lifetime validation and lease/controller writes atomic"
    )]
    pub fn activate_role_grants(
        self,
        state: &mut DelegationState,
        grants: &[PendingRoleGrant],
        lifetime: AuthorityLeaseLifetime,
        seal_attempt_id: Option<&str>,
        generation: u64,
    ) -> Result<Vec<TaskRoleLease>, EngineError> {
        if generation == 0 {
            return Err(host_broker_error(
                "authority activation requires nonzero generation",
            ));
        }
        match lifetime {
            AuthorityLeaseLifetime::Legacy => {
                return Err(host_broker_error("new code cannot mint Legacy authority"));
            }
            AuthorityLeaseLifetime::Persistent => {
                if seal_attempt_id.is_some()
                    || grants
                        .iter()
                        .any(|grant| grant.owner_operation_id.is_some())
                {
                    return Err(host_broker_error(
                        "Persistent authority cannot carry an operation or seal owner",
                    ));
                }
            }
            AuthorityLeaseLifetime::OperationBound => {
                if seal_attempt_id.is_some()
                    || grants
                        .iter()
                        .any(|grant| grant.owner_operation_id.is_none())
                {
                    return Err(host_broker_error(
                        "OperationBound authority requires an operation owner and no seal owner",
                    ));
                }
            }
            AuthorityLeaseLifetime::SealBound => {
                if seal_attempt_id.is_none_or(|value| value.trim().is_empty()) {
                    return Err(host_broker_error(
                        "SealBound authority requires an exact seal attempt",
                    ));
                }
            }
        }
        let now = OffsetDateTime::now_utc();
        let mut next = state.clone();
        let mut activated = Vec::with_capacity(grants.len());
        let mut seen_ids = BTreeSet::new();
        for grant in grants {
            if !seen_ids.insert(grant.role_lease_id.clone())
                || next
                    .task_role_leases
                    .iter()
                    .any(|lease| lease.role_lease_id == grant.role_lease_id)
            {
                return Err(host_broker_error("duplicate prepared role lease ID"));
            }
            let binding = next
                .agent_host_sessions
                .iter_mut()
                .find(|binding| binding.agent_session_id == grant.agent_session_id)
                .ok_or_else(|| host_broker_error("prepared role session is not registered"))?;
            if binding.state != AgentSessionState::Active
                || binding.generation != generation
                || binding
                    .bound_task_id
                    .is_some_and(|task| task != grant.task_id)
            {
                return Err(host_broker_error(
                    "prepared role session is stale, retired, or task-mismatched",
                ));
            }
            if grant.role == AgentRole::Controller
                && next.controller_leases.iter().any(|lease| {
                    lease.task_id == grant.task_id
                        && lease.agent_session_id != grant.agent_session_id
                        && lease.state == AuthorityLeaseState::Active
                        && lease.expires_at > now
                })
            {
                return Err(host_broker_error(
                    "task already has a different active ControllerLease",
                ));
            }
            let lease = TaskRoleLease {
                role_lease_id: grant.role_lease_id.clone(),
                task_id: grant.task_id,
                agent_session_id: grant.agent_session_id,
                role: grant.role,
                capability_scope: grant.capability_scope.clone(),
                expires_at: grant.expires_at,
                epoch: grant.epoch,
                state: AuthorityLeaseState::Active,
                lifetime,
                owner_operation_id: grant.owner_operation_id.clone(),
                seal_attempt_id: seal_attempt_id.map(str::to_owned),
                generation,
                issued_at: Some(now),
                activated_at: Some(now),
                consumed_at: None,
                revoked_at: None,
                revoke_reason: None,
                superseded_by_epoch: None,
            };
            binding
                .task_role_lease_refs
                .push(lease.role_lease_id.clone());
            binding.task_role_lease_refs.sort();
            binding.task_role_lease_refs.dedup();
            if grant.role == AgentRole::Controller {
                next.controller_leases.push(ControllerLease {
                    controller_lease_id: uuid_like("controller-lease"),
                    task_id: grant.task_id,
                    agent_session_id: grant.agent_session_id,
                    expires_at: grant.expires_at,
                    epoch: grant.epoch,
                    state: AuthorityLeaseState::Active,
                    lifetime,
                    owner_operation_id: grant.owner_operation_id.clone(),
                    seal_attempt_id: seal_attempt_id.map(str::to_owned),
                    generation,
                    issued_at: Some(now),
                    activated_at: Some(now),
                    revoked_at: None,
                    revoke_reason: None,
                    superseded_by_epoch: None,
                });
            }
            next.task_role_leases.push(lease.clone());
            activated.push(lease);
        }
        *state = next;
        Ok(activated)
    }

    pub fn revoke_role(
        self,
        state: &mut DelegationState,
        role_lease_id: &str,
        expected_epoch: u64,
        reason: &str,
        superseding_epoch: Option<u64>,
    ) -> Result<TaskRoleLease, EngineError> {
        let now = OffsetDateTime::now_utc();
        let lease = state
            .task_role_leases
            .iter_mut()
            .find(|lease| lease.role_lease_id == role_lease_id)
            .ok_or_else(|| host_broker_error("role lease does not exist"))?;
        if lease.epoch != expected_epoch {
            return Err(host_broker_error(
                "role lease epoch fence rejected revocation",
            ));
        }
        if matches!(
            lease.state,
            AuthorityLeaseState::Revoked | AuthorityLeaseState::Expired
        ) {
            return Ok(lease.clone());
        }
        let prior = lease.clone();
        lease.state = AuthorityLeaseState::Revoked;
        lease.revoked_at = Some(now);
        lease.revoke_reason = Some(reason.to_owned());
        lease.superseded_by_epoch = superseding_epoch;
        for controller in &mut state.controller_leases {
            if controller.task_id == prior.task_id
                && controller.agent_session_id == prior.agent_session_id
                && controller.epoch == prior.epoch
                && controller.generation == prior.generation
            {
                controller.state = AuthorityLeaseState::Revoked;
                controller.revoked_at = Some(now);
                controller.revoke_reason = Some(reason.to_owned());
                controller.superseded_by_epoch = superseding_epoch;
            }
        }
        let receipt = AuthorityRevocationReceipt {
            receipt_id: uuid_like("authority-revocation"),
            role_lease_id: prior.role_lease_id,
            prior_epoch: prior.epoch,
            prior_generation: prior.generation,
            task_id: prior.task_id,
            agent_session_id: prior.agent_session_id,
            reason: reason.to_owned(),
            owner_operation_id: prior.owner_operation_id,
            seal_attempt_id: prior.seal_attempt_id,
            superseded_by_epoch: superseding_epoch,
            revoked_at: now,
        };
        if !state.authority_revocation_receipts.iter().any(|existing| {
            existing.role_lease_id == receipt.role_lease_id
                && existing.prior_epoch == receipt.prior_epoch
                && existing.prior_generation == receipt.prior_generation
        }) {
            state.authority_revocation_receipts.push(receipt);
        }
        Ok(lease.clone())
    }

    pub fn retire_session(
        self,
        state: &mut DelegationState,
        session_id: AgentSessionId,
        reason: &str,
    ) -> Result<AgentSessionHostBinding, EngineError> {
        let binding = state
            .agent_host_sessions
            .iter_mut()
            .find(|binding| binding.agent_session_id == session_id)
            .ok_or_else(|| host_broker_error("agent host session is not registered"))?;
        binding.state = AgentSessionState::Retired;
        binding.disconnected_at = Some(OffsetDateTime::now_utc());
        binding.disconnect_reason = Some(reason.to_owned());
        Ok(binding.clone())
    }

    pub fn abandon_operation(
        self,
        state: &mut DelegationState,
        operation_id: &str,
        reason: &str,
    ) -> Result<OperationJob, EngineError> {
        let job = state
            .operation_jobs
            .iter_mut()
            .find(|job| job.job_id == operation_id || job.invocation_id == operation_id)
            .ok_or_else(|| host_broker_error("operation job does not exist"))?;
        job.state = OperationJobState::Abandoned;
        job.phase = OperationPhase::Abandoned;
        job.last_progress_at = Some(OffsetDateTime::now_utc());
        job.result_ref = Some(format!("abandoned:{reason}"));
        job.updated_at = OffsetDateTime::now_utc();
        Ok(job.clone())
    }

    pub fn expire_authority(
        self,
        state: &mut DelegationState,
        now: OffsetDateTime,
    ) -> AuthorityCleanupReport {
        let mut report = AuthorityCleanupReport::default();
        let expired = state
            .task_role_leases
            .iter()
            .filter(|lease| lease.state == AuthorityLeaseState::Active && lease.expires_at <= now)
            .map(|lease| (lease.role_lease_id.clone(), lease.epoch))
            .collect::<Vec<_>>();
        for (role_lease_id, epoch) in expired {
            if let Ok(lease) = self.revoke_role(state, &role_lease_id, epoch, "lease_expired", None)
            {
                if let Some(updated) = state
                    .task_role_leases
                    .iter_mut()
                    .find(|candidate| candidate.role_lease_id == role_lease_id)
                {
                    updated.state = AuthorityLeaseState::Expired;
                }
                report.expired_role_lease_ids.push(lease.role_lease_id);
            }
        }
        report.revocation_receipt_ids = state
            .authority_revocation_receipts
            .iter()
            .filter(|receipt| receipt.revoked_at == now || receipt.reason == "lease_expired")
            .map(|receipt| receipt.receipt_id.clone())
            .collect();
        report.expired_role_lease_ids.sort();
        report.revocation_receipt_ids.sort();
        report
    }

    #[allow(
        clippy::too_many_lines,
        reason = "one validator keeps every lease lifetime and exact owner rule on the shared admission path"
    )]
    pub fn validate_active_role_authority(
        self,
        state: &DelegationState,
        check: &ActiveRoleAuthorityCheck<'_>,
    ) -> Result<ActiveRoleAuthority, EngineError> {
        if check.expected_epoch == 0 || check.generation == 0 {
            return Err(host_broker_error(
                "fresh authority check requires nonzero epoch and generation",
            ));
        }
        let now = OffsetDateTime::now_utc();
        let role = state
            .task_role_leases
            .iter()
            .find(|lease| {
                lease.role_lease_id == check.role_lease_id
                    && lease.task_id == check.task_id
                    && lease.state == AuthorityLeaseState::Active
                    && lease.epoch == check.expected_epoch
                    && lease.generation == check.generation
                    && lease.expires_at > now
            })
            .ok_or_else(|| host_broker_error("no active matching TaskRoleLease"))?;
        let binding = state
            .agent_host_sessions
            .iter()
            .find(|binding| binding.agent_session_id == role.agent_session_id)
            .ok_or_else(|| host_broker_error("role lease owner session is missing"))?;
        if binding.state != AgentSessionState::Active
            || binding.host_identity.host_id != check.host_id
            || binding.generation != check.generation
            || binding
                .bound_task_id
                .is_some_and(|task| task != check.task_id)
            || !binding
                .task_role_lease_refs
                .iter()
                .any(|role_lease_id| role_lease_id == check.role_lease_id)
        {
            return Err(host_broker_error(
                "role lease owner binding is inactive, stale, or scope-mismatched",
            ));
        }
        if check
            .requested_capabilities
            .iter()
            .any(|capability| !role.capability_scope.contains(capability))
        {
            return Err(host_broker_error(
                "operation requests capability outside the TaskRoleLease",
            ));
        }
        let operation_job = match role.lifetime {
            AuthorityLeaseLifetime::Legacy => {
                return Err(host_broker_error(
                    "Legacy authority is decode/recovery-only and cannot dispatch",
                ));
            }
            AuthorityLeaseLifetime::Persistent => {
                if role.owner_operation_id.is_some() || role.seal_attempt_id.is_some() {
                    return Err(host_broker_error(
                        "Persistent authority has an invalid owner",
                    ));
                }
                None
            }
            AuthorityLeaseLifetime::OperationBound => {
                if role.owner_operation_id.as_deref() != Some(check.operation_id)
                    || role.seal_attempt_id.is_some()
                {
                    return Err(host_broker_error(
                        "OperationBound authority does not match the exact operation owner",
                    ));
                }
                let job = state
                    .operation_jobs
                    .iter()
                    .find(|job| {
                        job.job_id == check.operation_id
                            && job.invocation_id == check.operation_id
                            && job.generation == check.generation
                            && job.role_lease_id.as_deref() == Some(check.role_lease_id)
                            && job.role_lease_epoch == Some(check.expected_epoch)
                    })
                    .ok_or_else(|| {
                        host_broker_error("OperationBound authority owner job is missing or stale")
                    })?;
                if !matches!(
                    job.state,
                    OperationJobState::Queued | OperationJobState::Running
                ) {
                    return Err(host_broker_error(
                        "OperationBound authority owner job is already terminal",
                    ));
                }
                Some(job.clone())
            }
            AuthorityLeaseLifetime::SealBound => {
                if role.seal_attempt_id.as_deref().is_none_or(str::is_empty) {
                    return Err(host_broker_error("SealBound authority has no seal owner"));
                }
                let owner = role.owner_operation_id.as_deref().ok_or_else(|| {
                    host_broker_error("SealBound authority has no operation job owner")
                })?;
                let job = state
                    .operation_jobs
                    .iter()
                    .find(|job| {
                        job.job_id == owner
                            && job.invocation_id == check.operation_id
                            && job.generation == check.generation
                            && job.role_lease_id.as_deref() == Some(check.role_lease_id)
                            && job.role_lease_epoch == Some(check.expected_epoch)
                    })
                    .ok_or_else(|| {
                        host_broker_error("SealBound authority owner job is missing or stale")
                    })?;
                Some(job.clone())
            }
        };
        Ok(ActiveRoleAuthority {
            role_lease: role.clone(),
            host_binding: binding.clone(),
            operation_job,
        })
    }

    #[allow(
        clippy::too_many_lines,
        reason = "enqueue keeps validation, exact operation adoption, and new-job admission in one transaction"
    )]
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
        let authority = self.validate_active_role_authority(
            state,
            &ActiveRoleAuthorityCheck {
                operation_id: &request.invocation_id,
                task_id: request.task_id,
                role_lease_id: &request.role_lease_id,
                expected_epoch: request.role_lease_epoch,
                generation: request.operation_generation,
                host_id: host_profile.host_id,
                requested_capabilities: &request.requested_capabilities,
            },
        )?;
        if request.work_lease_id.is_some() && !work_lease_active {
            return Err(host_broker_error(
                "invocation references a WorkLease that is not active",
            ));
        }
        if authority.role_lease.lifetime == AuthorityLeaseLifetime::OperationBound {
            let existing = authority
                .operation_job
                .ok_or_else(|| host_broker_error("operation owner job is missing"))?;
            if existing.host_id != host_profile.host_id
                || existing.idempotency_key != request.idempotency_key
                || (existing.runtime_contract_sha256.is_some()
                    && existing.runtime_contract_sha256 != request.runtime_contract_sha256)
            {
                return Err(host_broker_error(
                    "existing operation owner differs from the invocation binding",
                ));
            }
            if let Some(persisted) = state
                .agent_invocations
                .iter()
                .find(|item| item.invocation_id == request.invocation_id)
                && persisted != request
            {
                return Err(host_broker_error(
                    "operation adoption changed the AgentInvocationRequest",
                ));
            }
            if !state
                .agent_invocations
                .iter()
                .any(|item| item.invocation_id == request.invocation_id)
            {
                state.agent_invocations.push(request.clone());
            }
            let adopted = state
                .operation_jobs
                .iter_mut()
                .find(|job| job.job_id == existing.job_id)
                .ok_or_else(|| host_broker_error("operation owner job disappeared"))?;
            if adopted.runtime_contract_sha256.is_none() {
                adopted
                    .runtime_contract_sha256
                    .clone_from(&request.runtime_contract_sha256);
                adopted.updated_at = OffsetDateTime::now_utc();
            }
            return Ok(adopted.clone());
        }
        if let Some(existing) = state.operation_jobs.iter().find(|job| {
            job.idempotency_key == request.idempotency_key
                && job.generation == request.operation_generation
        }) {
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
        let prior_jobs = state
            .operation_jobs
            .iter()
            .filter(|job| job.idempotency_key == request.idempotency_key)
            .collect::<Vec<_>>();
        if !prior_jobs.is_empty() {
            let prior_safe = prior_jobs
                .iter()
                .all(|job| prior_idempotency_job_is_superseded_predispatch(state, job, request))
                && !state
                    .agent_results
                    .iter()
                    .any(|result| result.invocation_id == request.invocation_id);
            if !prior_safe {
                return Err(host_broker_error(
                    "idempotency key has prior authority without exact pre-dispatch supersession",
                ));
            }
            if let Some(persisted) = state
                .agent_invocations
                .iter_mut()
                .find(|item| item.invocation_id == request.invocation_id)
            {
                if persisted.operation_generation >= request.operation_generation {
                    return Err(host_broker_error(
                        "idempotency replay did not advance the invocation generation",
                    ));
                }
                persisted.clone_from(request);
            }
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
            generation: request.operation_generation,
            phase: OperationPhase::Prepared,
            phase_started_at: Some(now),
            last_progress_at: Some(now),
            phase_deadline_at: None,
            absolute_deadline_at: None,
            restart_count: 0,
            runtime_contract_sha256: request.runtime_contract_sha256.clone(),
            role_lease_id: Some(request.role_lease_id.clone()),
            role_lease_epoch: Some(request.role_lease_epoch),
        };
        if !state
            .agent_invocations
            .iter()
            .any(|item| item.invocation_id == request.invocation_id)
        {
            state.agent_invocations.push(request.clone());
        }
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
                    | OperationJobState::Cancelled
                    | OperationJobState::Abandoned
            ) | (
                OperationJobState::UnknownOutcome,
                OperationJobState::Reconciled | OperationJobState::Abandoned
            ) | (
                OperationJobState::Queued,
                OperationJobState::Cancelled | OperationJobState::Abandoned
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
        job.phase = match next {
            OperationJobState::Queued => OperationPhase::Prepared,
            OperationJobState::Running => OperationPhase::Running,
            OperationJobState::Completed | OperationJobState::Reconciled => {
                OperationPhase::Completed
            }
            OperationJobState::Abandoned => OperationPhase::Abandoned,
            OperationJobState::Cancelled
            | OperationJobState::Failed
            | OperationJobState::TimedOut
            | OperationJobState::UnknownOutcome => OperationPhase::Failed,
        };
        let now = OffsetDateTime::now_utc();
        job.phase_started_at = Some(now);
        job.last_progress_at = Some(now);
        job.updated_at = now;
        Ok(())
    }

    pub fn record_result(
        self,
        state: &mut DelegationState,
        result: AgentResultEnvelope,
    ) -> Result<AgentResultAdmission, EngineError> {
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
            return Ok(AgentResultAdmission::Accepted(existing.clone()));
        }
        let job = state
            .operation_jobs
            .iter()
            .find(|job| job.invocation_id == result.invocation_id)
            .ok_or_else(|| host_broker_error("AgentResultEnvelope has no matching OperationJob"))?;
        if job.host_id != result.host_id {
            return Err(host_broker_error("result host does not match OperationJob"));
        }
        let invocation = state
            .agent_invocations
            .iter()
            .find(|invocation| invocation.invocation_id == result.invocation_id)
            .cloned()
            .ok_or_else(|| host_broker_error("result invocation request is missing"))?;
        let current_authority = invocation.role_lease_epoch == result.role_lease_epoch
            && invocation.operation_generation == result.operation_generation
            && job.generation == result.operation_generation
            && job.role_lease_epoch == Some(result.role_lease_epoch)
            && self
                .validate_active_role_authority(
                    state,
                    &ActiveRoleAuthorityCheck {
                        operation_id: &result.invocation_id,
                        task_id: invocation.task_id,
                        role_lease_id: &invocation.role_lease_id,
                        expected_epoch: result.role_lease_epoch,
                        generation: result.operation_generation,
                        host_id: result.host_id,
                        requested_capabilities: &invocation.requested_capabilities,
                    },
                )
                .is_ok();
        if !current_authority {
            if !state
                .agent_results
                .iter()
                .any(|existing| existing.result_id == result.result_id)
            {
                state.agent_results.push(result.clone());
            }
            return Ok(AgentResultAdmission::StaleEvidencePreserved(result));
        }
        let job = state
            .operation_jobs
            .iter_mut()
            .find(|job| job.invocation_id == result.invocation_id)
            .ok_or_else(|| host_broker_error("AgentResultEnvelope owner job disappeared"))?;
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
        job.phase = if job.state == OperationJobState::Completed {
            OperationPhase::Completed
        } else {
            OperationPhase::Failed
        };
        job.last_progress_at = Some(OffsetDateTime::now_utc());
        job.updated_at = OffsetDateTime::now_utc();
        state.agent_results.push(result.clone());
        Ok(AgentResultAdmission::Accepted(result))
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
                && lease.state == AuthorityLeaseState::Active
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
        AgentHostId::Codex => {
            let source_plugin = repo_root.join("plugin/eliot-governor");
            if source_plugin.is_dir() {
                source_plugin
            } else {
                repo_root.join("integrations/codex/plugins/eliot-governor")
            }
        }
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
