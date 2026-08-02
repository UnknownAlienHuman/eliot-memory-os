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

#[test]
fn codecortex_attachment_is_disposed_by_the_evidence_contract() {
    let claim_only = request(
        "Fix code using the verified claim",
        &["claim:01900000-0000-7000-8000-000000000001"],
    );
    let claim_class =
        TaskExecutionClassifier::classify(&claim_only, None, &[], &claim_only.candidate_handles);
    assert!(claim_class.requires_codecortex());
    assert!(!TaskExecutionClassifier::should_attach_codecortex(
        &claim_only,
        None,
        &[],
        &claim_class,
    ));

    let code_handle = request(
        "Fix code using current source truth",
        &["file:crates/eliot-engine/src/context.rs"],
    );
    let code_class =
        TaskExecutionClassifier::classify(&code_handle, None, &[], &code_handle.candidate_handles);
    assert!(TaskExecutionClassifier::should_attach_codecortex(
        &code_handle,
        None,
        &[],
        &code_class,
    ));

    let ambiguous = request("reserve deterministic control arm", &[]);
    let ambiguous_class =
        TaskExecutionClassifier::classify(&ambiguous, None, &[], &ambiguous.candidate_handles);
    assert!(!TaskExecutionClassifier::should_attach_codecortex(
        &ambiguous,
        None,
        &[],
        &ambiguous_class,
    ));
}

#[test]
fn fallback_classification_keeps_its_explicit_twelve_token_boundary() {
    let request = request(
        "alpha beta gamma delta epsilon zeta eta theta iota kappa lambda mu code",
        &[],
    );
    let class = TaskExecutionClassifier::classify(&request, None, &[], &[]);

    assert_eq!(class.source, TaskExecutionClassSource::Fallback);
    assert_eq!(class.domain, TaskExecutionDomain::Mixed);
    assert_eq!(class.artifact, TaskExecutionArtifact::Mixed);
    assert_eq!(class.action, TaskExecutionAction::MultiFile);
}
