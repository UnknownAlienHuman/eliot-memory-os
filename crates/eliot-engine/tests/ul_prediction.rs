use eliot_engine::{
    CalibrationService, blast_fraction_milli, blast_score, calibration_trend,
    diagnostic_expectation_matches, normalize_diagnostic_signature,
    normalize_diagnostic_signatures, parse_expected_observable, prediction_id, resolve_prediction,
};
use eliot_types::{
    CalibrationTrend, DiagnosticExpectation, PredictionConfidence, PredictionExpectation,
    PredictionRecord, PredictionResolution, ProjectId, SessionId, TaskId, VerificationResult,
    ul_token_estimate,
};
use std::collections::{BTreeMap, BTreeSet};
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
        root.join("integrations/agent-skills/eliot-work/SKILL.md"),
        root.join("integrations/claude/eliot/skills/eliot-work/SKILL.md"),
        root.join("integrations/opencode/skills/eliot-work/SKILL.md"),
        root.join("plugin/eliot-governor/skills/eliot-work/SKILL.md"),
        root.join("plugin/eliot-antigravity-official/skills/eliot-work/SKILL.md"),
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
        "context arrives with the first successful ELIOT call.",
        "Call `eliot_compile_packet_l3` with `goal`.",
        "check `ul_fired` for a matching",
        "Run the packet verifier.",
        "[STALE ...]",
    ];
    assert!(required.iter().all(|line| body.contains(line)));
    assert!(ul_token_estimate(body) <= 500);

    let catalog = fs::read_to_string(root.join("crates/eliot-app/src/mcp_stdio/catalog.rs"))?;
    let descriptions = [
        "Search the current multi-kind memory projection by keywords. Scope and lifecycle filtering happen before ranking; lifecycle_audit explicitly exposes audit-only records. Returns at most 12 compact handles plus inspectable integer rank features.",
        "Task context packet + prefilled frame_stub. Use BEFORE any material edit. Needs: goal (task_id auto). Returns: packet, frame_stub (edit <=5 fields), verifier, ul_gate.",
        "Save a lesson/decision/failure to memory. Use after solving anything non-obvious or failing. Needs: statement, kind, expected_reuse_note (bindings auto from your session). Returns: handle.",
        "Acknowledge memory you used. Minimal form: memory_handle, influence_class[, downstream_outcome_ref]. Server fills the rest. Returns: receipt.",
        "Record a tool/test observation (errors, diagnostics). Use on notable failures. Needs: payload. Returns: receipt; may trigger ul_fired on next call.",
    ];
    for description in descriptions {
        assert!(catalog.contains(description));
        assert!(ul_token_estimate(description) <= 90);
    }
    Ok(())
}

#[test]
fn u10_1_verifier_compatibility() -> Result<(), Box<dyn std::error::Error>> {
    let project_id = ProjectId::new_v7();
    let task_id = TaskId::new_v7();
    let session_id = SessionId::new_v7();
    let legacy = serde_json::json!({
        "prediction_id": "legacy",
        "project_id": project_id,
        "task_id": task_id,
        "session_id": session_id,
        "subsystem_concept_id": "alpha",
        "packet_id": "packet",
        "verifier": "cargo test",
        "expected": "pass",
        "resolution": null,
        "actual": null,
        "verification_ref": null,
        "source_frame_hash": "frame"
    });
    let decoded: PredictionRecord = serde_json::from_value(legacy)?;
    assert!(decoded.prediction.is_none());

    let captured = prediction(project_id, Some("alpha"), None);
    assert!(matches!(
        captured.prediction,
        Some(eliot_types::UlPrediction::VerifierVerdict { .. })
    ));
    assert_eq!(captured.verifier, "receipt-resolution");
    assert_eq!(
        resolve_prediction(PredictionExpectation::Pass, VerificationResult::Passed),
        PredictionResolution::Hit
    );
    assert_eq!(
        resolve_prediction(PredictionExpectation::Fail, VerificationResult::Passed),
        PredictionResolution::Miss
    );
    assert_eq!(
        resolve_prediction(
            PredictionExpectation::Pass,
            VerificationResult::Inconclusive
        ),
        PredictionResolution::Unresolvable
    );
    Ok(())
}

#[test]
fn u10_2_diagnostic_delta() {
    let signature = normalize_diagnostic_signature("E0308 mismatched types at src/lib.rs:42");
    let before = normalize_diagnostic_signatures(&[]);
    let after =
        normalize_diagnostic_signatures(&["E0308 mismatched types at src/lib.rs:42".to_owned()]);
    assert!(diagnostic_expectation_matches(
        &DiagnosticExpectation::Appears,
        &signature,
        &before,
        &after
    ));
    assert!(diagnostic_expectation_matches(
        &DiagnosticExpectation::Disappears,
        &signature,
        &after,
        &before
    ));
    assert!(diagnostic_expectation_matches(
        &DiagnosticExpectation::Unchanged,
        &signature,
        &after,
        &after
    ));
}

#[test]
fn u10_3_blast_fractions() {
    let score = blast_score(
        &["a".to_owned(), "b".to_owned(), "c".to_owned()],
        &["a".to_owned(), "b".to_owned()],
        &["v1".to_owned(), "v2".to_owned()],
        &["v1".to_owned()],
    );
    assert_eq!(
        (
            score.path_precision_num,
            score.path_precision_den,
            score.path_recall_num,
            score.path_recall_den
        ),
        (2, 3, 2, 2)
    );
    assert_eq!(
        (
            score.verifier_precision_num,
            score.verifier_precision_den,
            score.verifier_recall_num,
            score.verifier_recall_den
        ),
        (1, 2, 1, 1)
    );
    assert_eq!(blast_fraction_milli(2, 3), 666);
    assert_eq!(blast_fraction_milli(2, 2), 1_000);
}

#[test]
fn u10_4_unresolvable_sweep_is_idempotent_projection() -> Result<(), Box<dyn std::error::Error>> {
    let mut row = prediction(ProjectId::new_v7(), Some("alpha"), None);
    assert!(row.resolution.is_none());
    row.resolution = Some(PredictionResolution::Unresolvable);
    row.actual = None;
    row.actual_detail = None;
    row.verification_ref = Some("deadline:24h".to_owned());
    let first = serde_json::to_vec(&row)?;
    let replay = serde_json::to_vec(&row)?;
    assert_eq!(first, replay);
    assert!(row.resolution.is_some());
    Ok(())
}

#[test]
fn u10_5_calibration_brier_and_trends() -> Result<(), Box<dyn std::error::Error>> {
    let project_id = ProjectId::new_v7();
    let mut hit = prediction(project_id, Some("alpha"), Some(PredictionResolution::Hit));
    hit.confidence = Some(PredictionConfidence::Low);
    let mut miss = prediction(project_id, Some("alpha"), Some(PredictionResolution::Miss));
    miss.confidence = Some(PredictionConfidence::Medium);
    let mut unresolvable = prediction(
        project_id,
        Some("alpha"),
        Some(PredictionResolution::Unresolvable),
    );
    unresolvable.confidence = Some(PredictionConfidence::High);
    let mut windows = BTreeMap::new();
    windows.insert(Some("alpha".to_owned()), vec![500, 600, 700]);
    let scores = CalibrationService::scores_with_weekly_hit_rate(
        project_id,
        &[hit, miss, unresolvable],
        &windows,
    );
    let score = scores.first().ok_or("calibration group missing")?;
    assert_eq!(score.brier_milli, Some(400));
    assert_eq!(score.unresolvable, 1);
    assert_eq!(score.trend, CalibrationTrend::Improving);
    assert_eq!(
        calibration_trend(&[700, 600, 500]),
        CalibrationTrend::Degrading
    );
    assert_eq!(calibration_trend(&[500, 500, 600]), CalibrationTrend::Flat);
    assert_eq!(
        calibration_trend(&[500, 600]),
        CalibrationTrend::InsufficientData
    );
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
        prediction: Some(eliot_types::UlPrediction::VerifierVerdict {
            verifier: "receipt-resolution".to_owned(),
            expected: PredictionExpectation::Pass,
        }),
        confidence: None,
        resolution,
        actual: resolution.map(|resolution| match resolution {
            PredictionResolution::Hit => VerificationResult::Passed,
            PredictionResolution::Miss => VerificationResult::Failed,
            PredictionResolution::Unresolvable => VerificationResult::Inconclusive,
        }),
        actual_detail: None,
        blast_score: None,
        verification_ref: resolution.map(|_| "verification:test".to_owned()),
        source_frame_hash: "frame".to_owned(),
    }
}
