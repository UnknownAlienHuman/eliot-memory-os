use eliot_engine::{
    UlExamPlan, UlReasoningOutcome, UlReasoningRunner, build_cold_exam_request, build_exam_plan,
    grade_exam, invoke_reasoner_once, weekly_exam_due, weekly_exam_route,
};
use eliot_types::{
    ConceptKind, ConceptNode, DependencyManifest, ProjectId, SubsystemCapsule, UlExamAnswer,
    UlReasoningRequest, UlReasoningRoute,
};
use std::sync::atomic::{AtomicUsize, Ordering};

#[test]
fn u10_6_exam_generator_and_grader() {
    let project_id = ProjectId::new_v7();
    let concepts = (0..3)
        .map(|index| concept(project_id, index))
        .collect::<Vec<_>>();
    let capsules = (0..3)
        .map(|index| capsule(project_id, index))
        .collect::<Vec<_>>();
    let plan = build_exam_plan(
        project_id,
        &concepts,
        &capsules,
        &[],
        &[],
        vec!["charter:current".to_owned(), "map:current".to_owned()],
    );
    assert_eq!(plan.questions.len(), 9);
    for question in &plan.questions {
        assert!(
            question
                .ground_truth_values
                .iter()
                .all(|value| !question.prompt.contains(value))
        );
    }

    let answers = plan
        .questions
        .iter()
        .map(|question| {
            let answer_values = if question.subsystem_concept_id == "concept-0" {
                vec!["definitely-wrong".to_owned()]
            } else {
                question.ground_truth_values.clone()
            };
            UlExamAnswer {
                question_id: question.question_id.clone(),
                answer_values,
                cited_refs: question.ground_truth_refs.clone(),
            }
        })
        .collect::<Vec<_>>();
    let (grades, scores) = grade_exam(&plan, &answers);
    assert_eq!(grades.len(), 9);
    assert!(
        scores
            .iter()
            .any(|(concept_id, score)| concept_id == "concept-0" && *score < 500)
    );
    assert!(
        scores
            .iter()
            .filter(|(concept_id, _)| concept_id != "concept-0")
            .all(|(_, score)| *score == 1_000)
    );
}

#[tokio::test]
async fn u10_7_cold_model_request_boundary() -> Result<(), Box<dyn std::error::Error>> {
    let project_id = ProjectId::new_v7();
    let plan = UlExamPlan {
        exam_id: "exam-cold".to_owned(),
        project_id,
        questions: build_exam_plan(
            project_id,
            &[concept(project_id, 0)],
            &[capsule(project_id, 0)],
            &[],
            &[],
            Vec::new(),
        )
        .questions,
        cold_input_refs: vec!["charter:current".to_owned(), "map:current".to_owned()],
    };
    let request = build_cold_exam_request(
        &plan,
        UlReasoningRoute::Claude,
        Some("CHARTER_PAYLOAD"),
        Some("SYSTEM_MAP_PAYLOAD"),
    );
    let serialized = serde_json::to_vec(&request)?;
    assert!(request.prompt.contains("CHARTER_PAYLOAD"));
    assert!(request.prompt.contains("SYSTEM_MAP_PAYLOAD"));
    assert!(request.prompt.contains("QUESTIONS"));
    assert!(!request.prompt.contains("ground_truth"));
    assert!(!request.prompt.contains("CAPSULE_SECRET"));
    assert!(!request.prompt.contains("module_card"));
    assert!(serialized.len() <= 4_096);
    let oversized = build_cold_exam_request(
        &plan,
        UlReasoningRoute::Claude,
        Some(&"charter ".repeat(2_000)),
        Some(&"map ".repeat(2_000)),
    );
    assert!(serde_json::to_vec(&oversized)?.len() <= 4_096);
    assert!(oversized.prompt.contains("OUTPUT JSON SCHEMA"));
    assert!(weekly_exam_due(7, 3));
    assert!(!weekly_exam_due(7, 2));
    assert_eq!(weekly_exam_route(2), UlReasoningRoute::Claude);
    assert_eq!(weekly_exam_route(3), UlReasoningRoute::Antigravity);

    let runner = UnknownRunner {
        calls: AtomicUsize::new(0),
    };
    assert!(matches!(
        invoke_reasoner_once(&runner, &request).await?,
        UlReasoningOutcome::UnknownOutcome(_)
    ));
    assert_eq!(runner.calls.load(Ordering::SeqCst), 1);
    Ok(())
}

struct UnknownRunner {
    calls: AtomicUsize,
}

impl UlReasoningRunner for UnknownRunner {
    fn run<'a>(
        &'a self,
        _request: &'a UlReasoningRequest,
    ) -> eliot_engine::BoxUlReasoningFuture<'a> {
        Box::pin(async move {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(UlReasoningOutcome::UnknownOutcome(
                "provider outcome unknown".to_owned(),
            ))
        })
    }
}

fn concept(project_id: ProjectId, index: usize) -> ConceptNode {
    ConceptNode {
        concept_id: format!("concept-{index}"),
        project_id,
        name: format!("Subsystem {index}"),
        kind: ConceptKind::Subsystem,
        purpose: format!("Owns subsystem {index}."),
        boundary_paths: vec![format!("src/subsystem-{index}")],
        invariant_refs: vec![format!("invariant:stable-{index}")],
        hotspot_refs: vec![format!("hotspot:{index}")],
        entrypoint_refs: vec![format!("file:src/subsystem-{index}/lib.rs")],
        parent_concept_id: None,
        cue_bindings: Vec::new(),
        source_refs: vec![format!("source:{index}")],
    }
}

fn capsule(project_id: ProjectId, index: usize) -> SubsystemCapsule {
    SubsystemCapsule {
        capsule_id: format!("capsule-{index}"),
        project_id,
        concept_id: format!("concept-{index}"),
        body_md: format!(
            "PURPOSE\nsecret capsule {index}\n\nBOUNDARIES\n- src/subsystem-{index}\n\nKEY ENTRYPOINTS\n- file:src/subsystem-{index}/lib.rs\n\nINVARIANTS\n- invariant:stable-{index}\n\nDRAGONS\n- none\n\nKEY DECISIONS\n- none\n\nVERIFIERS\n- cargo test"
        ),
        dependency_manifest: DependencyManifest::default(),
        build_id: format!("build-{index}"),
        cue_bindings: Vec::new(),
        source_refs: vec![format!("verifier:cargo-test-{index}")],
    }
}
