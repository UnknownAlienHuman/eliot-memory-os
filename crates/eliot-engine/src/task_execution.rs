use eliot_types::{
    CompilePacketL3Request, MaterialPacketFrame, TaskExecutionAction, TaskExecutionArtifact,
    TaskExecutionClass, TaskExecutionClassSource, TaskExecutionDomain, normalize_query_tokens,
    path_cue_tokens,
};
use std::collections::BTreeSet;
use std::path::Path;

pub struct TaskExecutionClassifier;

impl TaskExecutionClassifier {
    #[must_use]
    pub fn classify(
        request: &CompilePacketL3Request,
        frame: Option<&MaterialPacketFrame>,
        touched_paths: &[String],
        handles: &[String],
    ) -> TaskExecutionClass {
        let explicit_domain = structured_value(handles, "task-domain:").and_then(parse_domain);
        let explicit_action = structured_value(handles, "task-action:").and_then(parse_action);
        let explicit_artifact =
            structured_value(handles, "task-artifact:").and_then(parse_artifact);
        let explicit_contract =
            explicit_domain.is_some() || explicit_action.is_some() || explicit_artifact.is_some();
        let project_profile = handles
            .iter()
            .any(|handle| handle.trim().starts_with("project-profile:"));

        let mut paths = touched_paths
            .iter()
            .chain(
                frame
                    .into_iter()
                    .flat_map(|frame| frame.predicted_changed_paths.iter()),
            )
            .cloned()
            .collect::<BTreeSet<_>>();
        for handle in handles.iter().chain(&request.candidate_handles) {
            paths.extend(path_cue_tokens(handle));
        }

        let mut subsystem_refs = handles
            .iter()
            .chain(&request.candidate_handles)
            .filter_map(|handle| handle.trim().strip_prefix("subsystem:"))
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned)
            .collect::<BTreeSet<_>>();
        subsystem_refs.extend(paths.iter().filter_map(|path| subsystem_ref(path)));

        let path_artifact = artifact_from_paths(&paths);
        let source = if explicit_contract {
            TaskExecutionClassSource::ExplicitContract
        } else if project_profile {
            TaskExecutionClassSource::ProjectProfile
        } else if !touched_paths.is_empty()
            || frame.is_some_and(|frame| !frame.predicted_changed_paths.is_empty())
        {
            TaskExecutionClassSource::TouchedPaths
        } else if !paths.is_empty()
            || handles
                .iter()
                .chain(&request.candidate_handles)
                .any(|handle| is_structured_code_handle(handle))
        {
            TaskExecutionClassSource::Handles
        } else {
            TaskExecutionClassSource::Fallback
        };

        let fallback_tokens = normalize_query_tokens(&request.goal)
            .into_iter()
            .collect::<BTreeSet<_>>();
        let artifact = explicit_artifact
            .or(path_artifact)
            .or_else(|| frame.and_then(artifact_from_frame))
            .unwrap_or_else(|| fallback_artifact(&fallback_tokens));
        let domain =
            explicit_domain.unwrap_or_else(|| domain_from_artifact(artifact, &fallback_tokens));
        let action = explicit_action.unwrap_or_else(|| {
            action_from_structure(&paths, &subsystem_refs)
                .unwrap_or_else(|| fallback_action(&fallback_tokens))
        });

        TaskExecutionClass {
            domain,
            action,
            artifact,
            subsystem_refs: subsystem_refs.into_iter().collect(),
            source,
        }
    }
}

fn structured_value<'a>(handles: &'a [String], prefix: &str) -> Option<&'a str> {
    handles
        .iter()
        .find_map(|handle| handle.trim().strip_prefix(prefix))
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

fn parse_domain(value: &str) -> Option<TaskExecutionDomain> {
    match value {
        "code" => Some(TaskExecutionDomain::Code),
        "docs" => Some(TaskExecutionDomain::Docs),
        "research" => Some(TaskExecutionDomain::Research),
        "operations" => Some(TaskExecutionDomain::Operations),
        "mixed" => Some(TaskExecutionDomain::Mixed),
        _ => None,
    }
}

fn parse_action(value: &str) -> Option<TaskExecutionAction> {
    match value {
        "read_only" => Some(TaskExecutionAction::ReadOnly),
        "single_file" => Some(TaskExecutionAction::SingleFile),
        "multi_file" => Some(TaskExecutionAction::MultiFile),
        "cross_subsystem" => Some(TaskExecutionAction::CrossSubsystem),
        "destructive" => Some(TaskExecutionAction::Destructive),
        _ => None,
    }
}

fn parse_artifact(value: &str) -> Option<TaskExecutionArtifact> {
    match value {
        "code" => Some(TaskExecutionArtifact::Code),
        "config" => Some(TaskExecutionArtifact::Config),
        "docs" => Some(TaskExecutionArtifact::Docs),
        "report" => Some(TaskExecutionArtifact::Report),
        "runtime" => Some(TaskExecutionArtifact::Runtime),
        "mixed" => Some(TaskExecutionArtifact::Mixed),
        _ => None,
    }
}

fn artifact_from_paths(paths: &BTreeSet<String>) -> Option<TaskExecutionArtifact> {
    let artifacts = paths
        .iter()
        .filter_map(|path| {
            let extension = Path::new(path).extension()?.to_str()?;
            match extension {
                "rs" | "c" | "cc" | "cpp" | "h" | "hpp" | "go" | "java" | "kt" | "swift" | "ts"
                | "tsx" | "js" | "jsx" | "lua" => Some(TaskExecutionArtifact::Code),
                "toml" | "yaml" | "yml" | "json" | "jsonc" | "ron" | "ini" => {
                    Some(TaskExecutionArtifact::Config)
                }
                "md" | "adoc" | "rst" => Some(TaskExecutionArtifact::Docs),
                "log" | "trace" => Some(TaskExecutionArtifact::Runtime),
                _ => None,
            }
        })
        .collect::<BTreeSet<_>>();
    if artifacts.len() > 1 {
        Some(TaskExecutionArtifact::Mixed)
    } else {
        artifacts.into_iter().next()
    }
}

fn artifact_from_frame(frame: &MaterialPacketFrame) -> Option<TaskExecutionArtifact> {
    let verifier = frame.verifier.trim();
    if verifier.is_empty() {
        None
    } else if verifier.starts_with("cargo ") || verifier.starts_with("rustc ") {
        Some(TaskExecutionArtifact::Code)
    } else {
        Some(TaskExecutionArtifact::Runtime)
    }
}

fn domain_from_artifact(
    artifact: TaskExecutionArtifact,
    fallback_tokens: &BTreeSet<String>,
) -> TaskExecutionDomain {
    match artifact {
        TaskExecutionArtifact::Code | TaskExecutionArtifact::Config => TaskExecutionDomain::Code,
        TaskExecutionArtifact::Docs | TaskExecutionArtifact::Report => TaskExecutionDomain::Docs,
        TaskExecutionArtifact::Runtime => TaskExecutionDomain::Operations,
        TaskExecutionArtifact::Mixed => fallback_domain(fallback_tokens),
    }
}

fn action_from_structure(
    paths: &BTreeSet<String>,
    subsystem_refs: &BTreeSet<String>,
) -> Option<TaskExecutionAction> {
    if paths.is_empty() {
        None
    } else if subsystem_refs.len() > 1 {
        Some(TaskExecutionAction::CrossSubsystem)
    } else if paths.len() > 1 {
        Some(TaskExecutionAction::MultiFile)
    } else {
        Some(TaskExecutionAction::SingleFile)
    }
}

fn fallback_domain(tokens: &BTreeSet<String>) -> TaskExecutionDomain {
    let code = has_any(
        tokens,
        &[
            "code",
            "rust",
            "crate",
            "implementation",
            "function",
            "module",
            "код",
            "крейт",
            "реализация",
            "функция",
            "модуль",
            "исходник",
        ],
    );
    let docs = has_any(
        tokens,
        &[
            "docs",
            "documentation",
            "readme",
            "документация",
            "документ",
            "описание",
        ],
    );
    let research = has_any(
        tokens,
        &[
            "research",
            "investigate",
            "compare",
            "исследование",
            "изучить",
            "сравнить",
        ],
    );
    let operations = has_any(
        tokens,
        &[
            "runtime",
            "deploy",
            "service",
            "process",
            "рантайм",
            "сервис",
            "процесс",
            "развернуть",
        ],
    );
    match [code, docs, research, operations]
        .into_iter()
        .filter(|matched| *matched)
        .count()
    {
        1 if code => TaskExecutionDomain::Code,
        1 if docs => TaskExecutionDomain::Docs,
        1 if research => TaskExecutionDomain::Research,
        1 if operations => TaskExecutionDomain::Operations,
        _ => TaskExecutionDomain::Mixed,
    }
}

fn fallback_artifact(tokens: &BTreeSet<String>) -> TaskExecutionArtifact {
    if has_any(
        tokens,
        &[
            "config",
            "configuration",
            "конфигурация",
            "конфиг",
            "настройка",
        ],
    ) {
        TaskExecutionArtifact::Config
    } else if has_any(tokens, &["report", "отчёт", "отчет"]) {
        TaskExecutionArtifact::Report
    } else if has_any(
        tokens,
        &[
            "docs",
            "documentation",
            "readme",
            "документация",
            "документ",
        ],
    ) {
        TaskExecutionArtifact::Docs
    } else if has_any(
        tokens,
        &[
            "runtime",
            "service",
            "process",
            "рантайм",
            "сервис",
            "процесс",
        ],
    ) {
        TaskExecutionArtifact::Runtime
    } else if has_any(
        tokens,
        &[
            "code",
            "rust",
            "crate",
            "function",
            "module",
            "код",
            "крейт",
            "функция",
            "модуль",
        ],
    ) {
        TaskExecutionArtifact::Code
    } else {
        TaskExecutionArtifact::Mixed
    }
}

fn fallback_action(tokens: &BTreeSet<String>) -> TaskExecutionAction {
    if has_any(
        tokens,
        &[
            "delete",
            "remove",
            "destroy",
            "удалить",
            "удали",
            "уничтожить",
        ],
    ) {
        TaskExecutionAction::Destructive
    } else if has_any(
        tokens,
        &[
            "read",
            "inspect",
            "explain",
            "review",
            "прочитать",
            "проверить",
            "объяснить",
            "изучить",
        ],
    ) {
        TaskExecutionAction::ReadOnly
    } else {
        TaskExecutionAction::MultiFile
    }
}

fn has_any(tokens: &BTreeSet<String>, candidates: &[&str]) -> bool {
    candidates
        .iter()
        .any(|candidate| tokens.contains(*candidate))
}

fn subsystem_ref(path: &str) -> Option<String> {
    let mut components = path.split('/').filter(|component| !component.is_empty());
    let first = components.next()?;
    if first == "crates" || first == "packages" || first == "projects" {
        components.next().map(|second| format!("{first}/{second}"))
    } else {
        Some(first.to_owned())
    }
}

fn is_structured_code_handle(handle: &str) -> bool {
    let handle = handle.trim();
    ["file:", "symbol:", "module:", "codecortex:"]
        .iter()
        .any(|prefix| handle.starts_with(prefix))
}
