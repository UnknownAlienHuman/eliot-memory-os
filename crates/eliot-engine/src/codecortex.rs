use crate::EngineError;
#[cfg(test)]
use crate::WriteAdmissionService;
use eliot_types::{
    AgentId, BlastRadiusView, CodeCortexPacketView, CodeCortexReport, CodeCortexRequest,
    CodeCortexScopeBinding, CodeEvidenceSource, CommandContext, DiagnosticEvidence, FileEvidence,
    InvariantCard, LifecycleStatus, OperationStatus, ProjectId, SemanticCommand, SessionId,
    SymbolEvidence, TaintClass, TaskId, ToolObservationRecordCommand, VerifierEvidence, Visibility,
    WriteId,
};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};

mod memory_writer;
pub use memory_writer::CodeCortexMemoryWriter;
use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::process::Command;
use time::OffsetDateTime;

const DEFAULT_MAX_FILES: usize = 160;
const DEFAULT_MAX_MATCHES_PER_PATTERN: usize = 24;
const CODECORTEX_MEMORY_PAYLOAD_SCHEMA_VERSION: &str = "codecortex-memory-projection-v1";
const CODECORTEX_MEMORY_PAYLOAD_MAX_BYTES: usize = 96 * 1024;
const CODECORTEX_MEMORY_EVIDENCE_LIMIT: usize = 12;
const CODECORTEX_MEMORY_TEXT_MAX_BYTES: usize = 512;
const CODECORTEX_MEMORY_LIST_TEXT_MAX_BYTES: usize = 256;

#[derive(Clone, Debug)]
pub struct CodeCortexService {
    repo_root: PathBuf,
}

impl CodeCortexService {
    pub fn new(repo_root: impl Into<PathBuf>) -> Self {
        Self {
            repo_root: repo_root.into(),
        }
    }

    pub fn health(&self, project: &str) -> Result<CodeCortexReport, EngineError> {
        let request = CodeCortexRequest {
            project: project.to_owned(),
            task: "codecortex-health".to_owned(),
            goal: "Check CodeCortex D1 adapter availability".to_owned(),
            exact_patterns: Vec::new(),
            max_files: DEFAULT_MAX_FILES,
            max_matches_per_pattern: DEFAULT_MAX_MATCHES_PER_PATTERN,
            include_diagnostics: false,
        };
        self.build_report(&request, false)
    }

    pub fn scan(&self, request: &CodeCortexRequest) -> Result<CodeCortexReport, EngineError> {
        self.build_report(request, true)
    }

    pub fn report_is_fresh(
        &self,
        report: &CodeCortexReport,
        request: &CodeCortexRequest,
    ) -> Result<bool, EngineError> {
        let repo_root = resolve_repo_root(&self.repo_root)?;
        let binding = scope_binding(&repo_root, request)?;
        Ok(report.project == request.project
            && report.task == request.task
            && report.goal == request.goal
            && normalized_path(&report.repo_root)
                == normalized_path(&repo_root.display().to_string())
            && report.git_head.as_deref() == Some(binding.commit.as_str())
            && report.scope_binding == binding)
    }

    fn build_report(
        &self,
        request: &CodeCortexRequest,
        include_search: bool,
    ) -> Result<CodeCortexReport, EngineError> {
        let mut verifier_evidence = Vec::new();
        let git_root = run_process(&self.repo_root, "git", &["rev-parse", "--show-toplevel"])?;
        let repo_root = if git_root.status {
            PathBuf::from(git_root.stdout.trim())
        } else {
            self.repo_root.clone()
        };
        verifier_evidence.push(verifier(
            "git_repo_root_adapter",
            "git rev-parse --show-toplevel",
            git_root.status,
            git_root.summary(),
            CodeEvidenceSource::Git,
        ));

        let git_head = git_text(&repo_root, &["rev-parse", "HEAD"], &mut verifier_evidence)?;
        let dirty = git_dirty(&repo_root, &mut verifier_evidence)?;
        let scope_binding = scope_binding(&repo_root, request)?;
        let tracked_files = tracked_files(&repo_root, &mut verifier_evidence)?;

        let manifest = cargo_manifest(&repo_root, &mut verifier_evidence)?;

        let mut file_evidence = Vec::new();
        let mut symbol_evidence = Vec::new();
        if include_search {
            let patterns = effective_patterns(request);
            let rg_available = rg_search(
                &repo_root,
                &patterns,
                bounded_max(request.max_files, DEFAULT_MAX_FILES),
                bounded_max(
                    request.max_matches_per_pattern,
                    DEFAULT_MAX_MATCHES_PER_PATTERN,
                ),
                &mut file_evidence,
                &mut symbol_evidence,
                &mut verifier_evidence,
            )?;
            if rg_available {
                ast_grep_scan(&repo_root, &mut symbol_evidence, &mut verifier_evidence)?;
            } else {
                verifier_evidence.push(verifier(
                    "ast_grep_adapter",
                    "sg -p <pattern> -l rust crates",
                    false,
                    "skipped because rg adapter was unavailable".to_owned(),
                    CodeEvidenceSource::AstGrep,
                ));
            }
        } else {
            verifier_evidence.push(verifier(
                "rg_adapter",
                "rg --fixed-strings --line-number",
                true,
                "not executed in health mode".to_owned(),
                CodeEvidenceSource::Rg,
            ));
            ast_grep_health(&repo_root, &mut verifier_evidence)?;
        }

        let diagnostic_evidence = diagnostics(
            &repo_root,
            request.include_diagnostics,
            &mut verifier_evidence,
        )?;

        unavailable_adapters(&mut verifier_evidence);
        let blast_radius = blast_radius(&file_evidence, &symbol_evidence);
        let invariant_cards = invariant_cards();
        let evidence_sources = evidence_sources(&verifier_evidence);
        let operation_status = if core_adapters_ready(&verifier_evidence) {
            OperationStatus::OperationCompleted
        } else {
            OperationStatus::Blocked
        };

        Ok(CodeCortexReport {
            project: request.project.clone(),
            task: request.task.clone(),
            goal: request.goal.clone(),
            generated_at: OffsetDateTime::now_utc(),
            repo_root: repo_root.display().to_string(),
            git_head,
            dirty,
            scope_binding,
            tracked_files,
            workspace_members: manifest.workspace_members,
            crates: manifest.crates,
            targets: manifest.targets,
            file_evidence,
            symbol_evidence,
            diagnostic_evidence,
            verifier_evidence,
            blast_radius,
            invariant_cards,
            evidence_sources,
            adapter_notes: vec![
                "project_memory/codebase-memory D1 adapter is interface-only unless directly wired"
                    .to_owned(),
                "domain API adapter is disabled by default in D1".to_owned(),
            ],
            memory_receipt: None,
            operation_status,
        })
    }
}

fn resolve_repo_root(root: &Path) -> Result<PathBuf, EngineError> {
    let git_root = run_process(root, "git", &["rev-parse", "--show-toplevel"])?;
    Ok(if git_root.status {
        PathBuf::from(git_root.stdout.trim())
    } else {
        root.to_path_buf()
    })
}

fn scope_binding(
    repo_root: &Path,
    request: &CodeCortexRequest,
) -> Result<CodeCortexScopeBinding, EngineError> {
    let branch = successful_stdout(repo_root, "git", &["rev-parse", "--abbrev-ref", "HEAD"]);
    let commit = successful_stdout(repo_root, "git", &["rev-parse", "HEAD"]);
    let dirty_state_hash = dirty_state_hash(repo_root)?;
    let mut adapter_versions = BTreeMap::new();
    insert_adapter_version(
        &mut adapter_versions,
        repo_root,
        "git",
        "git",
        &["--version"],
    );
    insert_adapter_version(
        &mut adapter_versions,
        repo_root,
        "cargo",
        "cargo",
        &["--version"],
    );
    insert_adapter_version(&mut adapter_versions, repo_root, "rg", "rg", &["--version"]);
    insert_adapter_version(
        &mut adapter_versions,
        repo_root,
        "ast-grep",
        "sg",
        &["--version"],
    );
    let verifier_config_hash = blake3::hash(&serde_json::to_vec(request)?)
        .to_hex()
        .to_string();
    Ok(CodeCortexScopeBinding {
        branch,
        commit,
        dirty_state_hash,
        adapter_versions,
        verifier_config_hash,
    })
}

fn successful_stdout(cwd: &Path, program: &str, args: &[&str]) -> String {
    run_process(cwd, program, args).map_or_else(
        |_| "unavailable".to_owned(),
        |output| {
            if output.status {
                output.stdout.trim().to_owned()
            } else {
                "unavailable".to_owned()
            }
        },
    )
}

fn insert_adapter_version(
    versions: &mut BTreeMap<String, String>,
    cwd: &Path,
    name: &str,
    program: &str,
    args: &[&str],
) {
    let version = successful_stdout(cwd, program, args)
        .lines()
        .next()
        .unwrap_or("unavailable")
        .trim()
        .to_owned();
    versions.insert(name.to_owned(), version);
}

fn dirty_state_hash(repo_root: &Path) -> Result<String, EngineError> {
    let diff = run_process(repo_root, "git", &["diff", "--binary", "HEAD", "--"])?;
    let untracked = run_process(
        repo_root,
        "git",
        &["ls-files", "--others", "--exclude-standard"],
    )?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(diff.stdout.as_bytes());
    let mut paths = untracked
        .stdout
        .lines()
        .map(str::trim)
        .filter(|path| !path.is_empty())
        .collect::<Vec<_>>();
    paths.sort_unstable();
    for relative in paths {
        hasher.update(relative.as_bytes());
        let path = repo_root.join(relative);
        match fs::read(path) {
            Ok(bytes) => {
                hasher.update(&bytes);
            }
            Err(error) => {
                hasher.update(error.to_string().as_bytes());
            }
        }
    }
    Ok(hasher.finalize().to_hex().to_string())
}

fn normalized_path(path: &str) -> String {
    path.replace('\\', "/").to_ascii_lowercase()
}

fn codecortex_observation_command(
    report: &CodeCortexReport,
    payload: Value,
    scope: Option<(SessionId, ProjectId, TaskId)>,
) -> SemanticCommand {
    let (session_id, project_id, task_id) = scope.map_or_else(
        || (None, ProjectId::new_v7(), TaskId::new_v7()),
        |(session_id, project_id, task_id)| (Some(session_id), project_id, task_id),
    );
    SemanticCommand::ToolObservationRecord(ToolObservationRecordCommand {
        context: CommandContext {
            write_id: WriteId::new_v7(),
            agent_id: AgentId::new_v7(),
            session_id,
            project_id,
            task_id: Some(task_id),
            scope: "codecortex-d1".to_owned(),
            authority: "local-codecortex".to_owned(),
            visibility: Visibility::Internal,
            taint: TaintClass::LocalVerified,
            lifecycle_status: LifecycleStatus::Active,
        },
        tool_name: "codecortex_internal_report".to_owned(),
        observation: format!(
            "CodeCortex internal report for task {}",
            truncate_text(&report.task, CODECORTEX_MEMORY_LIST_TEXT_MAX_BYTES)
        ),
        payload,
    })
}

fn bounded_codecortex_memory_payload(report: &CodeCortexReport) -> Result<Value, EngineError> {
    let mut canonical_report = report.clone();
    canonical_report.memory_receipt = None;
    let full_report_bytes = serde_json::to_vec(&canonical_report)?;
    let full_report_digest = format!("blake3:{}", blake3::hash(&full_report_bytes).to_hex());

    let mut evidence_limit = CODECORTEX_MEMORY_EVIDENCE_LIMIT;
    loop {
        let payload = codecortex_memory_payload_at_limit(
            &canonical_report,
            &full_report_digest,
            full_report_bytes.len(),
            evidence_limit,
        );
        if serde_json::to_vec(&payload)?.len() <= CODECORTEX_MEMORY_PAYLOAD_MAX_BYTES {
            return Ok(payload);
        }
        if evidence_limit == 0 {
            return Err(EngineError::WriteRejected(
                "CodeCortex memory projection exceeds its bounded payload".to_owned(),
            ));
        }
        evidence_limit /= 2;
    }
}

fn codecortex_memory_payload_at_limit(
    report: &CodeCortexReport,
    full_report_digest: &str,
    full_report_bytes: usize,
    evidence_limit: usize,
) -> Value {
    let report_ref = crate::context::codecortex_report_ref(report);
    let packet_view = CodeCortexPacketView {
        report_refs: vec![report_ref.clone()],
        git_head: report.git_head.clone(),
        scope_binding: bounded_scope_binding(&report.scope_binding),
        file_evidence: report
            .file_evidence
            .iter()
            .take(evidence_limit)
            .map(bounded_file_evidence)
            .collect(),
        symbol_evidence: report
            .symbol_evidence
            .iter()
            .take(evidence_limit)
            .map(bounded_symbol_evidence)
            .collect(),
        diagnostic_evidence: report
            .diagnostic_evidence
            .iter()
            .take(evidence_limit)
            .map(bounded_diagnostic_evidence)
            .collect(),
        verifier_map: report
            .verifier_evidence
            .iter()
            .take(evidence_limit)
            .map(bounded_verifier_evidence)
            .collect(),
        blast_radius: bounded_blast_radius(&report.blast_radius),
        unknowns: crate::context::codecortex_unknowns(report)
            .iter()
            .take(CODECORTEX_MEMORY_EVIDENCE_LIMIT)
            .map(|value| truncate_text(value, CODECORTEX_MEMORY_TEXT_MAX_BYTES))
            .collect(),
    };
    let included = json!({
        "file_evidence": packet_view.file_evidence.len(),
        "symbol_evidence": packet_view.symbol_evidence.len(),
        "diagnostic_evidence": packet_view.diagnostic_evidence.len(),
        "verifier_evidence": packet_view.verifier_map.len(),
        "blast_radius_files": packet_view.blast_radius.files.len(),
        "blast_radius_crates": packet_view.blast_radius.crates.len(),
        "blast_radius_reasons": packet_view.blast_radius.reasons.len(),
        "unknowns": packet_view.unknowns.len(),
    });
    let counts = json!({
        "tracked_files": report.tracked_files.len(),
        "workspace_members": report.workspace_members.len(),
        "crates": report.crates.len(),
        "targets": report.targets.len(),
        "file_evidence": report.file_evidence.len(),
        "symbol_evidence": report.symbol_evidence.len(),
        "diagnostic_evidence": report.diagnostic_evidence.len(),
        "verifier_evidence": report.verifier_evidence.len(),
        "invariant_cards": report.invariant_cards.len(),
        "evidence_sources": report.evidence_sources.len(),
        "adapter_notes": report.adapter_notes.len(),
    });
    let projection_truncated = report.file_evidence.len() > packet_view.file_evidence.len()
        || report.symbol_evidence.len() > packet_view.symbol_evidence.len()
        || report.diagnostic_evidence.len() > packet_view.diagnostic_evidence.len()
        || report.verifier_evidence.len() > packet_view.verifier_map.len()
        || report.blast_radius.files.len() > packet_view.blast_radius.files.len()
        || report.blast_radius.crates.len() > packet_view.blast_radius.crates.len()
        || report.blast_radius.reasons.len() > packet_view.blast_radius.reasons.len()
        || crate::context::codecortex_unknowns(report).len() > packet_view.unknowns.len()
        || !report.tracked_files.is_empty()
        || !report.workspace_members.is_empty()
        || !report.crates.is_empty()
        || !report.targets.is_empty()
        || !report.invariant_cards.is_empty()
        || !report.evidence_sources.is_empty()
        || !report.adapter_notes.is_empty();

    json!({
        "schema_version": CODECORTEX_MEMORY_PAYLOAD_SCHEMA_VERSION,
        "report_ref": report_ref,
        "project": truncate_text(&report.project, CODECORTEX_MEMORY_TEXT_MAX_BYTES),
        "task": truncate_text(&report.task, CODECORTEX_MEMORY_TEXT_MAX_BYTES),
        "goal": truncate_text(&report.goal, CODECORTEX_MEMORY_TEXT_MAX_BYTES),
        "generated_at": report.generated_at,
        "final_status": report.operation_status,
        "dirty": report.dirty,
        "full_report_digest": full_report_digest,
        "full_report_bytes": full_report_bytes,
        "counts": counts,
        "included": included,
        "projection_truncated": projection_truncated,
        "packet_view": packet_view,
    })
}

fn bounded_scope_binding(binding: &CodeCortexScopeBinding) -> CodeCortexScopeBinding {
    CodeCortexScopeBinding {
        branch: binding.branch.clone(),
        commit: binding.commit.clone(),
        dirty_state_hash: binding.dirty_state_hash.clone(),
        adapter_versions: binding.adapter_versions.clone(),
        verifier_config_hash: binding.verifier_config_hash.clone(),
    }
}

fn bounded_file_evidence(evidence: &FileEvidence) -> FileEvidence {
    FileEvidence {
        path: truncate_text(&evidence.path, CODECORTEX_MEMORY_TEXT_MAX_BYTES),
        content_hash: evidence
            .content_hash
            .as_deref()
            .map(|value| truncate_text(value, CODECORTEX_MEMORY_LIST_TEXT_MAX_BYTES)),
        line_start: evidence.line_start,
        line_end: evidence.line_end,
        excerpt: truncate_text(&evidence.excerpt, CODECORTEX_MEMORY_TEXT_MAX_BYTES),
        source: evidence.source,
    }
}

fn bounded_symbol_evidence(evidence: &SymbolEvidence) -> SymbolEvidence {
    SymbolEvidence {
        name: truncate_text(&evidence.name, CODECORTEX_MEMORY_LIST_TEXT_MAX_BYTES),
        kind: truncate_text(&evidence.kind, CODECORTEX_MEMORY_LIST_TEXT_MAX_BYTES),
        path: truncate_text(&evidence.path, CODECORTEX_MEMORY_TEXT_MAX_BYTES),
        line: evidence.line,
        source: evidence.source,
    }
}

fn bounded_diagnostic_evidence(evidence: &DiagnosticEvidence) -> DiagnosticEvidence {
    DiagnosticEvidence {
        source: evidence.source,
        status: truncate_text(&evidence.status, CODECORTEX_MEMORY_LIST_TEXT_MAX_BYTES),
        path: evidence
            .path
            .as_deref()
            .map(|value| truncate_text(value, CODECORTEX_MEMORY_TEXT_MAX_BYTES)),
        line: evidence.line,
        severity: truncate_text(&evidence.severity, CODECORTEX_MEMORY_LIST_TEXT_MAX_BYTES),
        message: truncate_text(&evidence.message, CODECORTEX_MEMORY_TEXT_MAX_BYTES),
    }
}

fn bounded_verifier_evidence(evidence: &VerifierEvidence) -> VerifierEvidence {
    VerifierEvidence {
        name: truncate_text(&evidence.name, CODECORTEX_MEMORY_LIST_TEXT_MAX_BYTES),
        command: truncate_text(&evidence.command, CODECORTEX_MEMORY_TEXT_MAX_BYTES),
        status: truncate_text(&evidence.status, CODECORTEX_MEMORY_LIST_TEXT_MAX_BYTES),
        summary: truncate_text(&evidence.summary, CODECORTEX_MEMORY_TEXT_MAX_BYTES),
        source: evidence.source,
    }
}

fn bounded_blast_radius(blast_radius: &BlastRadiusView) -> BlastRadiusView {
    BlastRadiusView {
        files: bounded_text_list(&blast_radius.files),
        crates: bounded_text_list(&blast_radius.crates),
        reasons: bounded_text_list(&blast_radius.reasons),
    }
}

fn bounded_text_list(values: &[String]) -> Vec<String> {
    values
        .iter()
        .take(CODECORTEX_MEMORY_EVIDENCE_LIMIT)
        .map(|value| truncate_text(value, CODECORTEX_MEMORY_TEXT_MAX_BYTES))
        .collect()
}

fn truncate_text(value: &str, max_bytes: usize) -> String {
    const SUFFIX: &str = "...[truncated]";

    if value.len() <= max_bytes {
        return value.to_owned();
    }
    let target = max_bytes.saturating_sub(SUFFIX.len());
    let mut end = target.min(value.len());
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}{}", &value[..end], SUFFIX)
}

pub(crate) struct ProcessOutput {
    pub(crate) status: bool,
    pub(crate) code: Option<i32>,
    pub(crate) stdout: String,
    pub(crate) stderr: String,
}

struct ManifestView {
    workspace_members: Vec<String>,
    crates: Vec<String>,
    targets: Vec<String>,
}

impl ProcessOutput {
    fn summary(&self) -> String {
        let text = if self.status {
            first_line(&self.stdout)
        } else {
            first_line(&self.stderr).or_else(|| first_line(&self.stdout))
        };
        text.unwrap_or_else(|| format!("exit_code={:?}", self.code))
    }
}

pub(crate) fn run_process(
    cwd: &Path,
    program: &str,
    args: &[&str],
) -> Result<ProcessOutput, EngineError> {
    let output = Command::new(program).args(args).current_dir(cwd).output()?;
    Ok(ProcessOutput {
        status: output.status.success(),
        code: output.status.code(),
        stdout: String::from_utf8_lossy(&output.stdout).to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).to_string(),
    })
}

fn git_text(
    repo_root: &Path,
    args: &[&str],
    verifier_evidence: &mut Vec<VerifierEvidence>,
) -> Result<Option<String>, EngineError> {
    let output = run_process(repo_root, "git", args)?;
    verifier_evidence.push(verifier(
        &format!("git_{}_adapter", args.join("_")),
        &format!("git {}", args.join(" ")),
        output.status,
        output.summary(),
        CodeEvidenceSource::Git,
    ));
    Ok(output.status.then(|| output.stdout.trim().to_owned()))
}

fn git_dirty(
    repo_root: &Path,
    verifier_evidence: &mut Vec<VerifierEvidence>,
) -> Result<bool, EngineError> {
    let output = run_process(repo_root, "git", &["status", "--porcelain"])?;
    verifier_evidence.push(verifier(
        "git_dirty_adapter",
        "git status --porcelain",
        output.status,
        if output.stdout.trim().is_empty() {
            "working tree clean".to_owned()
        } else {
            "working tree has changes".to_owned()
        },
        CodeEvidenceSource::Git,
    ));
    Ok(!output.stdout.trim().is_empty())
}

fn tracked_files(
    repo_root: &Path,
    verifier_evidence: &mut Vec<VerifierEvidence>,
) -> Result<Vec<FileEvidence>, EngineError> {
    let output = run_process(repo_root, "git", &["ls-files"])?;
    verifier_evidence.push(verifier(
        "git_tracked_files_adapter",
        "git ls-files",
        output.status,
        output.summary(),
        CodeEvidenceSource::Git,
    ));
    if !output.status {
        return Ok(Vec::new());
    }
    Ok(output
        .stdout
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|path| FileEvidence {
            path: normalize_path(path),
            content_hash: file_hash(repo_root, path),
            line_start: None,
            line_end: None,
            excerpt: "tracked file".to_owned(),
            source: CodeEvidenceSource::Git,
        })
        .collect())
}

fn cargo_manifest(
    repo_root: &Path,
    verifier_evidence: &mut Vec<VerifierEvidence>,
) -> Result<ManifestView, EngineError> {
    let output = run_process(
        repo_root,
        "cargo",
        &["metadata", "--no-deps", "--format-version", "1"],
    )?;
    if !output.status {
        verifier_evidence.push(verifier(
            "cargo_manifest_adapter",
            "cargo metadata --no-deps --format-version 1",
            false,
            output.summary(),
            CodeEvidenceSource::CargoMetadata,
        ));
        return Ok(ManifestView {
            workspace_members: Vec::new(),
            crates: Vec::new(),
            targets: Vec::new(),
        });
    }
    let value: Value = serde_json::from_str(&output.stdout)?;
    let workspace_members: Vec<String> = value
        .get("workspace_members")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(ToOwned::to_owned)
        .collect();
    let mut crates = Vec::new();
    let mut targets = Vec::new();
    if let Some(packages) = value.get("packages").and_then(Value::as_array) {
        for package in packages {
            if let Some(name) = package.get("name").and_then(Value::as_str) {
                crates.push(name.to_owned());
            }
            if let Some(package_targets) = package.get("targets").and_then(Value::as_array) {
                for target in package_targets {
                    if let Some(name) = target.get("name").and_then(Value::as_str) {
                        targets.push(name.to_owned());
                    }
                }
            }
        }
    }
    crates.sort();
    crates.dedup();
    targets.sort();
    targets.dedup();
    verifier_evidence.push(verifier(
        "cargo_manifest_adapter",
        "cargo metadata --no-deps --format-version 1",
        true,
        format!(
            "workspace_members={} crates={} targets={}",
            workspace_members.len(),
            crates.len(),
            targets.len()
        ),
        CodeEvidenceSource::CargoMetadata,
    ));
    Ok(ManifestView {
        workspace_members,
        crates,
        targets,
    })
}

fn rg_search(
    repo_root: &Path,
    patterns: &[String],
    max_files: usize,
    max_matches_per_pattern: usize,
    file_evidence: &mut Vec<FileEvidence>,
    symbol_evidence: &mut Vec<SymbolEvidence>,
    verifier_evidence: &mut Vec<VerifierEvidence>,
) -> Result<bool, EngineError> {
    let version = match run_process(repo_root, "rg", &["--version"]) {
        Ok(output) => output,
        Err(EngineError::Io(error)) if error.kind() == ErrorKind::NotFound => {
            verifier_evidence.push(VerifierEvidence {
                name: "rg_adapter".to_owned(),
                command: "rg --version".to_owned(),
                status: "unavailable".to_owned(),
                summary: "rg executable was not found".to_owned(),
                source: CodeEvidenceSource::Rg,
            });
            return Ok(false);
        }
        Err(error) => return Err(error),
    };
    verifier_evidence.push(verifier(
        "rg_adapter",
        "rg --version",
        version.status,
        version.summary(),
        CodeEvidenceSource::Rg,
    ));
    if !version.status {
        return Ok(false);
    }

    for pattern in patterns {
        if file_evidence.len() >= max_files {
            break;
        }
        let output = run_process(
            repo_root,
            "rg",
            &[
                "--fixed-strings",
                "--line-number",
                "--no-heading",
                "--glob",
                "!target/**",
                "--glob",
                "!.eliot-governor/**",
                pattern,
                "crates",
                "Justfile",
                "Cargo.toml",
            ],
        )?;
        let found = output.status || output.code == Some(1);
        verifier_evidence.push(verifier(
            &format!("rg_pattern_{}", sanitize_name(pattern)),
            &format!("rg --fixed-strings --line-number {pattern}"),
            found,
            if output.status {
                output.summary()
            } else {
                "no matches or bounded search completed".to_owned()
            },
            CodeEvidenceSource::Rg,
        ));
        for line in output.stdout.lines().take(max_matches_per_pattern) {
            if file_evidence.len() >= max_files {
                break;
            }
            if let Some((path, line_number, excerpt)) = parse_rg_line(line) {
                let evidence = FileEvidence {
                    path: normalize_path(&path),
                    content_hash: file_hash(repo_root, &path),
                    line_start: Some(line_number),
                    line_end: Some(line_number),
                    excerpt: excerpt.clone(),
                    source: CodeEvidenceSource::Rg,
                };
                if let Some(symbol) = symbol_from_excerpt(&path, line_number, &excerpt) {
                    symbol_evidence.push(symbol);
                }
                file_evidence.push(evidence);
            }
        }
    }
    Ok(true)
}

fn ast_grep_health(
    repo_root: &Path,
    verifier_evidence: &mut Vec<VerifierEvidence>,
) -> Result<(), EngineError> {
    let output = match run_process(repo_root, "sg", &["--version"]) {
        Ok(output) => output,
        Err(EngineError::Io(error)) if error.kind() == ErrorKind::NotFound => {
            verifier_evidence.push(VerifierEvidence {
                name: "ast_grep_adapter".to_owned(),
                command: "sg --version".to_owned(),
                status: "unavailable".to_owned(),
                summary: "sg executable was not found".to_owned(),
                source: CodeEvidenceSource::AstGrep,
            });
            return Ok(());
        }
        Err(error) => return Err(error),
    };
    verifier_evidence.push(verifier(
        "ast_grep_adapter",
        "sg --version",
        output.status,
        output.summary(),
        CodeEvidenceSource::AstGrep,
    ));
    Ok(())
}

fn ast_grep_scan(
    repo_root: &Path,
    symbol_evidence: &mut Vec<SymbolEvidence>,
    verifier_evidence: &mut Vec<VerifierEvidence>,
) -> Result<(), EngineError> {
    let version = match run_process(repo_root, "sg", &["--version"]) {
        Ok(output) => output,
        Err(EngineError::Io(error)) if error.kind() == ErrorKind::NotFound => {
            verifier_evidence.push(VerifierEvidence {
                name: "ast_grep_adapter".to_owned(),
                command: "sg --version".to_owned(),
                status: "unavailable".to_owned(),
                summary: "sg executable was not found".to_owned(),
                source: CodeEvidenceSource::AstGrep,
            });
            return Ok(());
        }
        Err(error) => return Err(error),
    };
    verifier_evidence.push(verifier(
        "ast_grep_adapter",
        "sg --version",
        version.status,
        version.summary(),
        CodeEvidenceSource::AstGrep,
    ));
    if !version.status {
        return Ok(());
    }
    for (pattern, name, kind) in [
        ("pub struct ContextCompiler", "ContextCompiler", "struct"),
        ("pub struct CognitiveGate", "CognitiveGate", "struct"),
        (
            "pub struct UnderstandingProofValidator",
            "UnderstandingProofValidator",
            "struct",
        ),
        ("impl CognitiveGate", "CognitiveGate", "impl"),
        (
            "pub struct CodeCortexService",
            "CodeCortexService",
            "struct",
        ),
    ] {
        let output = run_process(repo_root, "sg", &["-p", pattern, "-l", "rust", "crates"])?;
        verifier_evidence.push(verifier(
            &format!("ast_grep_{}", sanitize_name(name)),
            &format!("sg -p {pattern} -l rust crates"),
            output.status || output.code == Some(1),
            output.summary(),
            CodeEvidenceSource::AstGrep,
        ));
        if let Some((path, line, _)) = output.stdout.lines().find_map(parse_rg_line) {
            symbol_evidence.push(SymbolEvidence {
                name: name.to_owned(),
                kind: kind.to_owned(),
                path: normalize_path(&path),
                line: Some(line),
                source: CodeEvidenceSource::AstGrep,
            });
        }
    }
    Ok(())
}

fn diagnostics(
    repo_root: &Path,
    include_diagnostics: bool,
    verifier_evidence: &mut Vec<VerifierEvidence>,
) -> Result<Vec<DiagnosticEvidence>, EngineError> {
    if !include_diagnostics {
        verifier_evidence.push(verifier(
            "diagnostics_adapter",
            "cargo check --workspace --all-targets --all-features",
            true,
            "skipped by request".to_owned(),
            CodeEvidenceSource::Diagnostics,
        ));
        return Ok(vec![DiagnosticEvidence {
            source: CodeEvidenceSource::Diagnostics,
            status: "skipped".to_owned(),
            path: None,
            line: None,
            severity: "info".to_owned(),
            message: "diagnostics skipped by request".to_owned(),
        }]);
    }

    let output = run_process(
        repo_root,
        "cargo",
        &["check", "--workspace", "--all-targets", "--all-features"],
    )?;
    verifier_evidence.push(verifier(
        "diagnostics_adapter",
        "cargo check --workspace --all-targets --all-features",
        output.status,
        output.summary(),
        CodeEvidenceSource::Diagnostics,
    ));
    if output.status {
        return Ok(vec![DiagnosticEvidence {
            source: CodeEvidenceSource::Diagnostics,
            status: "clean".to_owned(),
            path: None,
            line: None,
            severity: "info".to_owned(),
            message: "cargo check passed".to_owned(),
        }]);
    }
    Ok(output
        .stderr
        .lines()
        .take(20)
        .map(|message| DiagnosticEvidence {
            source: CodeEvidenceSource::Diagnostics,
            status: "failed".to_owned(),
            path: None,
            line: None,
            severity: "error".to_owned(),
            message: message.to_owned(),
        })
        .collect())
}

fn unavailable_adapters(verifier_evidence: &mut Vec<VerifierEvidence>) {
    verifier_evidence.push(VerifierEvidence {
        name: "codebase_memory_adapter".to_owned(),
        command: "direct project_memory/codebase-memory adapter".to_owned(),
        status: "unavailable".to_owned(),
        summary: "no direct in-process adapter is wired in D1".to_owned(),
        source: CodeEvidenceSource::CodebaseMemory,
    });
    verifier_evidence.push(VerifierEvidence {
        name: "domain_api_adapter".to_owned(),
        command: "domain API reference adapter".to_owned(),
        status: "disabled".to_owned(),
        summary: "domain API adapter is disabled by default in D1".to_owned(),
        source: CodeEvidenceSource::DomainApi,
    });
}

fn effective_patterns(request: &CodeCortexRequest) -> Vec<String> {
    if !request.exact_patterns.is_empty() {
        return unique(request.exact_patterns.clone());
    }
    let mut patterns = vec![
        "governed_tool_names".to_owned(),
        "eliot_cognitive_gate".to_owned(),
        "CognitiveGate".to_owned(),
        "UnderstandingProofValidator".to_owned(),
        "ContextCompiler".to_owned(),
        "run_phase_c_closeout".to_owned(),
    ];
    for word in request
        .goal
        .split(|ch: char| !ch.is_ascii_alphanumeric() && ch != '_')
        .filter(|word| word.len() >= 8)
    {
        patterns.push(word.to_owned());
    }
    unique(patterns)
}

fn parse_rg_line(line: &str) -> Option<(String, u32, String)> {
    let mut parts = line.splitn(3, ':');
    let path = parts.next()?.to_owned();
    let line = parts.next()?.parse().ok()?;
    let excerpt = parts.next().unwrap_or_default().trim().to_owned();
    Some((path, line, excerpt))
}

fn symbol_from_excerpt(path: &str, line: u32, excerpt: &str) -> Option<SymbolEvidence> {
    let trimmed = excerpt.trim();
    for (prefix, kind) in [
        ("pub struct ", "struct"),
        ("struct ", "struct"),
        ("pub enum ", "enum"),
        ("enum ", "enum"),
        ("pub fn ", "function"),
        ("fn ", "function"),
        ("impl ", "impl"),
    ] {
        if let Some(rest) = trimmed.strip_prefix(prefix) {
            let name = rest
                .split(|ch: char| ch.is_whitespace() || matches!(ch, '<' | '(' | '{' | ';' | ':'))
                .next()
                .unwrap_or_default();
            if !name.is_empty() {
                return Some(SymbolEvidence {
                    name: name.to_owned(),
                    kind: kind.to_owned(),
                    path: normalize_path(path),
                    line: Some(line),
                    source: CodeEvidenceSource::Rg,
                });
            }
        }
    }
    None
}

fn blast_radius(
    file_evidence: &[FileEvidence],
    symbol_evidence: &[SymbolEvidence],
) -> BlastRadiusView {
    let mut files = BTreeSet::new();
    let mut crates = BTreeSet::new();
    for path in file_evidence
        .iter()
        .map(|evidence| evidence.path.as_str())
        .chain(
            symbol_evidence
                .iter()
                .map(|evidence| evidence.path.as_str()),
        )
    {
        files.insert(path.to_owned());
        if let Some(crate_name) = crate_from_path(path) {
            crates.insert(crate_name);
        }
    }
    BlastRadiusView {
        files: files.into_iter().collect(),
        crates: crates.into_iter().collect(),
        reasons: vec![
            "bounded exact text and structural matches define D1 read surface".to_owned(),
            "Cargo metadata maps file evidence back to workspace crates".to_owned(),
        ],
    }
}

fn invariant_cards() -> Vec<InvariantCard> {
    vec![
        InvariantCard {
            name: "writer_actor_memory_path".to_owned(),
            status: "enforced".to_owned(),
            evidence: "CodeCortexMemoryWriter submits SemanticCommand through WriterActor"
                .to_owned(),
        },
        InvariantCard {
            name: "no_public_codecortex_mcp_tools".to_owned(),
            status: "enforced".to_owned(),
            evidence: "CodeCortex remains behind the governed MCP tool boundary".to_owned(),
        },
        InvariantCard {
            name: "domain_api_disabled".to_owned(),
            status: "enforced".to_owned(),
            evidence: "domain API adapter reports disabled by default".to_owned(),
        },
    ]
}

fn evidence_sources(verifier_evidence: &[VerifierEvidence]) -> Vec<CodeEvidenceSource> {
    let mut sources: Vec<_> = verifier_evidence
        .iter()
        .map(|evidence| evidence.source)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    sources.push(CodeEvidenceSource::MemoryWrite);
    sources.sort();
    sources.dedup();
    sources
}

fn core_adapters_ready(verifier_evidence: &[VerifierEvidence]) -> bool {
    let mut status_by_name = BTreeMap::new();
    for evidence in verifier_evidence {
        status_by_name.insert(evidence.name.as_str(), evidence.status.as_str());
    }
    [
        "git_repo_root_adapter",
        "cargo_manifest_adapter",
        "rg_adapter",
    ]
    .iter()
    .all(|name| matches!(status_by_name.get(name), Some(&"pass")))
}

fn verifier(
    name: &str,
    command: &str,
    status: bool,
    summary: String,
    source: CodeEvidenceSource,
) -> VerifierEvidence {
    VerifierEvidence {
        name: name.to_owned(),
        command: command.to_owned(),
        status: if status { "pass" } else { "failed" }.to_owned(),
        summary,
        source,
    }
}

fn bounded_max(value: usize, fallback: usize) -> usize {
    match value {
        0 => fallback,
        1..=512 => value,
        _ => 512,
    }
}

fn unique(values: Vec<String>) -> Vec<String> {
    let mut seen = BTreeSet::new();
    values
        .into_iter()
        .filter(|value| !value.trim().is_empty())
        .filter(|value| seen.insert(value.clone()))
        .collect()
}

fn first_line(value: &str) -> Option<String> {
    value
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .map(ToOwned::to_owned)
}

fn file_hash(repo_root: &Path, relative_path: &str) -> Option<String> {
    fs::read(repo_root.join(relative_path))
        .ok()
        .map(|bytes| blake3::hash(&bytes).to_hex().to_string())
}

fn crate_from_path(path: &str) -> Option<String> {
    let path = normalize_path(path);
    let mut parts = path.split('/');
    if parts.next()? != "crates" {
        return None;
    }
    parts.next().map(ToOwned::to_owned)
}

fn normalize_path(path: &str) -> String {
    path.replace('\\', "/")
}

fn sanitize_name(value: &str) -> String {
    value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() {
                ch.to_ascii_lowercase()
            } else {
                '_'
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oversized_codecortex_report_uses_bounded_memory_projection() -> Result<(), EngineError> {
        let report = large_report();
        let full_payload = serde_json::to_value(&report)?;
        let full_command = codecortex_observation_command(&report, full_payload, None);
        let full_command_bytes = serde_json::to_vec(&full_command)?.len();
        assert!(
            full_command_bytes > 128 * 1024,
            "fixture must exercise the generic semantic-command size guard"
        );
        assert!(matches!(
            WriteAdmissionService.admit(&full_command),
            Err(EngineError::WriteRejected(reason))
                if reason == "semantic command payload is too large"
        ));

        let payload = bounded_codecortex_memory_payload(&report)?;
        let payload_bytes = serde_json::to_vec(&payload)?.len();
        assert!(payload_bytes <= CODECORTEX_MEMORY_PAYLOAD_MAX_BYTES);
        assert_eq!(
            payload.get("schema_version").and_then(Value::as_str),
            Some(CODECORTEX_MEMORY_PAYLOAD_SCHEMA_VERSION)
        );
        assert_eq!(payload["counts"]["tracked_files"], json!(1_080));
        assert_eq!(payload["counts"]["workspace_members"], json!(2));
        assert_eq!(payload["projection_truncated"], json!(true));
        assert!(payload.get("tracked_files").is_none());
        assert!(payload.get("workspace_members").is_none());
        assert!(payload.get("repo_root").is_none());
        assert!(
            payload["packet_view"]["file_evidence"]
                .as_array()
                .is_some_and(|items| items.len() <= CODECORTEX_MEMORY_EVIDENCE_LIMIT)
        );
        assert!(
            payload["full_report_digest"]
                .as_str()
                .is_some_and(|digest| digest.starts_with("blake3:"))
        );
        assert_eq!(
            payload["report_ref"],
            json!(crate::context::codecortex_report_ref(&report))
        );

        let bounded_command = codecortex_observation_command(&report, payload, None);
        WriteAdmissionService.admit(&bounded_command)?;
        Ok(())
    }

    #[test]
    fn bounded_memory_text_preserves_utf8_boundaries() {
        let value = "current-truth-🙂".repeat(100);
        let truncated = truncate_text(&value, 128);
        assert!(truncated.len() <= 128);
        assert!(truncated.ends_with("...[truncated]"));
        assert!(std::str::from_utf8(truncated.as_bytes()).is_ok());
    }

    #[test]
    fn long_task_identity_does_not_escape_the_command_bound() -> Result<(), EngineError> {
        let mut report = large_report();
        report.task = "task-segment".repeat(1_500);

        let payload = bounded_codecortex_memory_payload(&report)?;
        assert_eq!(
            payload["report_ref"],
            json!(crate::context::codecortex_report_ref(&report))
        );
        let command = codecortex_observation_command(&report, payload, None);
        let observation = match &command {
            SemanticCommand::ToolObservationRecord(body) => &body.observation,
            _ => unreachable!("helper must build a ToolObservationRecord"),
        };
        assert!(observation.len() < 512);
        WriteAdmissionService.admit(&command)?;
        Ok(())
    }

    #[test]
    fn scoped_command_uses_authenticated_project_task_and_session() {
        let report = large_report();
        let session_id = SessionId::new_v7();
        let project_id = ProjectId::new_v7();
        let task_id = TaskId::new_v7();
        let command = codecortex_observation_command(
            &report,
            json!({ "bounded": true }),
            Some((session_id, project_id, task_id)),
        );
        let context = command.context();
        assert_eq!(context.session_id, Some(session_id));
        assert_eq!(context.project_id, project_id);
        assert_eq!(context.task_id, Some(task_id));
    }

    #[test]
    fn pathological_task_identity_is_rejected_fail_closed() {
        let mut report = large_report();
        report.task = "task-segment".repeat(10_000);
        assert!(matches!(
            bounded_codecortex_memory_payload(&report),
            Err(EngineError::WriteRejected(reason))
                if reason == "CodeCortex memory projection exceeds its bounded payload"
        ));
    }

    fn large_report() -> CodeCortexReport {
        let tracked_files = (0..1_080)
            .map(|index| FileEvidence {
                path: format!(
                    "crates/fixture-{index:04}/src/{}.rs",
                    "large-inventory-segment".repeat(6)
                ),
                content_hash: Some(format!("blake3:{index:064x}")),
                line_start: None,
                line_end: None,
                excerpt: String::new(),
                source: CodeEvidenceSource::Git,
            })
            .collect();
        let file_evidence = (0..24)
            .map(|index| FileEvidence {
                path: format!("crates/eliot-engine/src/fixture_{index}.rs"),
                content_hash: Some(format!("blake3:{index:064x}")),
                line_start: Some(index + 1),
                line_end: Some(index + 1),
                excerpt: format!("pub fn fixture_{index}() {{}}"),
                source: CodeEvidenceSource::Rg,
            })
            .collect();
        let mut adapter_versions = BTreeMap::new();
        adapter_versions.insert("git".to_owned(), "2.51.0".to_owned());
        adapter_versions.insert("rg".to_owned(), "14.1.1".to_owned());
        CodeCortexReport {
            project: "eliot-memory-os".to_owned(),
            task: "codecortex-bounded-persistence".to_owned(),
            goal: "Persist an authority-bound CodeCortex summary without bypassing admission"
                .to_owned(),
            generated_at: OffsetDateTime::UNIX_EPOCH,
            repo_root: r"C:\Development\Rust\projects\eliot-memory-os".to_owned(),
            git_head: Some("d5f0fdc".to_owned()),
            dirty: true,
            scope_binding: CodeCortexScopeBinding {
                branch: "main".to_owned(),
                commit: "d5f0fdc".to_owned(),
                dirty_state_hash: "dirty-state-hash".to_owned(),
                adapter_versions,
                verifier_config_hash: "verifier-config-hash".to_owned(),
            },
            tracked_files,
            workspace_members: vec!["eliot-engine".to_owned(), "eliot-types".to_owned()],
            crates: vec!["eliot-engine".to_owned(), "eliot-types".to_owned()],
            targets: vec!["eliot_engine".to_owned()],
            file_evidence,
            symbol_evidence: vec![SymbolEvidence {
                name: "CodeCortexMemoryWriter".to_owned(),
                kind: "struct".to_owned(),
                path: "crates/eliot-engine/src/codecortex.rs".to_owned(),
                line: Some(297),
                source: CodeEvidenceSource::Rg,
            }],
            diagnostic_evidence: vec![DiagnosticEvidence {
                source: CodeEvidenceSource::Diagnostics,
                status: "clean".to_owned(),
                path: None,
                line: None,
                severity: "info".to_owned(),
                message: "focused diagnostics passed".to_owned(),
            }],
            verifier_evidence: vec![VerifierEvidence {
                name: "bounded_projection".to_owned(),
                command: "cargo test -p eliot-engine oversized_codecortex_report".to_owned(),
                status: "pass".to_owned(),
                summary: "bounded projection accepted while full payload was rejected".to_owned(),
                source: CodeEvidenceSource::Diagnostics,
            }],
            blast_radius: BlastRadiusView {
                files: vec!["crates/eliot-engine/src/codecortex.rs".to_owned()],
                crates: vec!["eliot-engine".to_owned()],
                reasons: vec!["memory persistence payload only".to_owned()],
            },
            invariant_cards: invariant_cards(),
            evidence_sources: vec![CodeEvidenceSource::Git, CodeEvidenceSource::Diagnostics],
            adapter_notes: vec!["full report remains the local artifact".to_owned()],
            memory_receipt: None,
            operation_status: OperationStatus::OperationCompleted,
        }
    }
}
