use eliot_engine::{
    CalibrationService, parse_expected_observable, prediction_id, resolve_prediction,
};
use eliot_types::{
    PredictionExpectation, PredictionRecord, PredictionResolution, ProjectId, SessionId, TaskId,
    VerificationResult, ul_token_estimate,
};
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

#[test]
fn t07_prediction_hit_and_replay() -> Result<(), Box<dyn std::error::Error>> {
    let project_id = ProjectId::new_v7();
    let task_id = TaskId::new_v7();
    let session_id = SessionId::new_v7();
    let parsed =
        parse_expected_observable("verifier:cargo test -p eliot-engine --features=a=b=pass");
    let (verifier, expected) = parsed.ok_or("machine-checkable prediction missing")?;
    let first = prediction_id(
        project_id,
        task_id,
        session_id,
        "packet:one",
        &verifier,
        expected,
        "frame-hash",
    );
    let replay = prediction_id(
        project_id,
        task_id,
        session_id,
        "packet:one",
        &verifier,
        expected,
        "frame-hash",
    );
    let rows = [first, replay].into_iter().collect::<BTreeSet<_>>();

    assert_eq!(verifier, "cargo test -p eliot-engine --features=a=b");
    assert_eq!(expected, PredictionExpectation::Pass);
    assert_eq!(rows.len(), 1);
    assert_eq!(
        resolve_prediction(expected, VerificationResult::Passed),
        PredictionResolution::Hit
    );
    Ok(())
}

#[test]
fn t07_prediction_miss_and_unresolvable_are_separate() {
    let project_id = ProjectId::new_v7();
    let miss = prediction(project_id, Some("alpha"), Some(PredictionResolution::Miss));
    let unresolved = prediction(project_id, Some("alpha"), None);
    let scores = CalibrationService::scores(project_id, &[miss, unresolved]);

    assert_eq!(
        resolve_prediction(PredictionExpectation::Pass, VerificationResult::Failed),
        PredictionResolution::Miss
    );
    assert_eq!(scores.len(), 1);
    assert_eq!(scores[0].resolved_predictions, 1);
    assert_eq!(scores[0].hits, 0);
    assert_eq!(scores[0].misses, 1);
    assert!(scores[0].hit_rate.abs() <= f64::EPSILON);
}

#[test]
fn t07_calibration_is_per_subsystem() -> Result<(), Box<dyn std::error::Error>> {
    let project_id = ProjectId::new_v7();
    let other_project = ProjectId::new_v7();
    let records = vec![
        prediction(project_id, Some("alpha"), Some(PredictionResolution::Hit)),
        prediction(project_id, Some("alpha"), Some(PredictionResolution::Miss)),
        prediction(project_id, Some("beta"), Some(PredictionResolution::Hit)),
        prediction(
            other_project,
            Some("alpha"),
            Some(PredictionResolution::Miss),
        ),
    ];
    let scores = CalibrationService::scores(project_id, &records);

    assert_eq!(scores.len(), 2);
    let alpha = scores
        .iter()
        .find(|score| score.subsystem_concept_id.as_deref() == Some("alpha"))
        .ok_or("alpha score missing")?;
    let beta = scores
        .iter()
        .find(|score| score.subsystem_concept_id.as_deref() == Some("beta"))
        .ok_or("beta score missing")?;
    assert_eq!((alpha.hits, alpha.misses), (1, 1));
    assert!((alpha.hit_rate - 0.5).abs() <= f64::EPSILON);
    assert_eq!((beta.hits, beta.misses), (1, 0));
    assert!((beta.hit_rate - 1.0).abs() <= f64::EPSILON);
    Ok(())
}

#[test]
fn t07_skill_and_description_budget() -> Result<(), Box<dyn std::error::Error>> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let skills = [
        root.join("integrations/agent-skills/eliot-understanding/SKILL.md"),
        root.join("integrations/claude/eliot/skills/eliot-understanding/SKILL.md"),
        root.join("integrations/opencode/skills/eliot-understanding/SKILL.md"),
    ];
    let bodies = skills
        .iter()
        .map(fs::read_to_string)
        .collect::<Result<Vec<_>, _>>()?;
    assert!(bodies.windows(2).all(|pair| pair[0] == pair[1]));
    let body = bodies[0]
        .splitn(3, "---")
        .nth(2)
        .ok_or("skill frontmatter missing")?
        .trim();
    let required = [
        "1. Read `ul_boot` and `ul_fired`; do not fetch injected content again.",
        "2. Before material work, compile a packet and use `frame_stub`; keep the",
        "3. On failure, inspect pushed negative memory before debugging from scratch.",
        "4. Save a non-obvious lesson with `expected_reuse_note`; the server derives",
        "5. Acknowledge only memory actually injected or fetched. Influence claims",
        "6. A stale capsule is historical guidance; verify against current code.",
    ];
    assert!(required.iter().all(|line| body.contains(line)));
    assert_eq!(
        body.lines()
            .filter(|line| line.starts_with(char::is_numeric))
            .count(),
        6
    );
    assert!(ul_token_estimate(body) <= 500);

    let catalog = fs::read_to_string(root.join("crates/eliot-app/src/mcp_stdio/catalog.rs"))?;
    let descriptions = [
        "Search memory by keywords when pushed UL context is insufficient. Needs query. Returns handles and previews.",
        "Compile task context and a complete frame_stub before material work. Needs goal; task/project may be session-bound.",
        "Save a reusable claim, decision, or failure. Needs statement and expected_reuse_note; cue bindings can be derived from touched paths.",
        "Acknowledge memory use. Minimal form: memory_handle, influence_class, and downstream_outcome_ref when it changed action.",
    ];
    for description in descriptions {
        assert!(catalog.contains(description));
        assert!(ul_token_estimate(description) <= 90);
    }
    Ok(())
}

fn prediction(
    project_id: ProjectId,
    subsystem: Option<&str>,
    resolution: Option<PredictionResolution>,
) -> PredictionRecord {
    PredictionRecord {
        prediction_id: uuid::Uuid::new_v4().to_string(),
        project_id,
        task_id: TaskId::new_v7(),
        session_id: SessionId::new_v7(),
        subsystem_concept_id: subsystem.map(str::to_owned),
        packet_id: uuid::Uuid::new_v4().to_string(),
        verifier: "receipt-resolution".to_owned(),
        expected: PredictionExpectation::Pass,
        resolution,
        actual: resolution.map(|resolution| match resolution {
            PredictionResolution::Hit => VerificationResult::Passed,
            PredictionResolution::Miss => VerificationResult::Failed,
            PredictionResolution::Unresolvable => VerificationResult::Inconclusive,
        }),
        verification_ref: resolution.map(|_| "verification:test".to_owned()),
        source_frame_hash: "frame".to_owned(),
    }
}
