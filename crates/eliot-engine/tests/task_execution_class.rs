use eliot_engine::TaskExecutionClassifier;
use eliot_types::{
    CompilePacketL3Request, ProjectId, TaskExecutionAction, TaskExecutionArtifact,
    TaskExecutionClassSource, TaskExecutionDomain,
};

fn request(goal: &str, handles: &[&str]) -> CompilePacketL3Request {
    CompilePacketL3Request {
        project_id: ProjectId::new_v7(),
        task_id: "unicode-task".to_owned(),
        goal: goal.to_owned(),
        candidate_handles: handles.iter().map(|value| (*value).to_owned()).collect(),
        max_tokens: 1_200,
    }
}

#[test]
fn russian_and_english_code_tasks_route_equivalently() {
    let handles = ["file:crates/eliot-engine/src/context.rs"];
    let russian = TaskExecutionClassifier::classify(
        &request("Исправь реализацию функции в модуле", &handles),
        None,
        &[],
        &handles.map(str::to_owned),
    );
    let english = TaskExecutionClassifier::classify(
        &request("Fix the function implementation in the module", &handles),
        None,
        &[],
        &handles.map(str::to_owned),
    );

    assert_eq!(russian, english);
    assert_eq!(russian.domain, TaskExecutionDomain::Code);
    assert_eq!(russian.artifact, TaskExecutionArtifact::Code);
    assert_eq!(russian.action, TaskExecutionAction::SingleFile);
    assert_eq!(russian.source, TaskExecutionClassSource::Handles);
    assert!(russian.requires_codecortex());
}

#[test]
fn explicit_contract_beats_fallback_words() {
    let handles = [
        "task-domain:docs",
        "task-action:read_only",
        "task-artifact:report",
        "subsystem:certification",
    ];
    let class = TaskExecutionClassifier::classify(
        &request("Delete Rust code", &handles),
        None,
        &[],
        &handles.map(str::to_owned),
    );

    assert_eq!(class.domain, TaskExecutionDomain::Docs);
    assert_eq!(class.action, TaskExecutionAction::ReadOnly);
    assert_eq!(class.artifact, TaskExecutionArtifact::Report);
    assert_eq!(class.source, TaskExecutionClassSource::ExplicitContract);
    assert_eq!(class.subsystem_refs, ["certification"]);
    assert!(!class.requires_codecortex());
}
