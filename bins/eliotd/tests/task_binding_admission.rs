//! Task-binding admission proof for issue #1929 (I5.5/I5.6).
//!
//! Smallest acceptance proof only: unbound capture stays cold with no task
//! effects; promotion without evidence rejects with
//! `TASK_SELECTION_REQUIRED`; wrong-scope evidence rejects with
//! `TASK_SCOPE_INCOMPATIBLE` and changes nothing.

use eliot_observation::TaskSelectionEvidence;
use eliotd::task_binding_admission::{
    CaptureAdmission, CompatibilityDisposition, TASK_SCOPE_INCOMPATIBLE, TASK_SELECTION_REQUIRED,
    admit_capture, admit_task_bound,
};

fn fence() -> eliot_contracts::StateFence {
    use eliot_contracts::{EpochId, EpochLineageId, ResourceGeneration};
    use std::num::NonZeroU64;
    let lineage = EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000").expect("lineage");
    let epoch = EpochId::new(lineage, NonZeroU64::new(1).expect("seq")).expect("epoch");
    eliot_contracts::StateFence::new(epoch, ResourceGeneration::genesis())
}

fn evidence(task: &str, scope: &str) -> TaskSelectionEvidence {
    TaskSelectionEvidence {
        task_ref: task.to_owned(),
        task_revision: 7,
        acceptance_digest: "a".repeat(64),
        work_scope_ref: scope.to_owned(),
        selection_source_ref: "owner-selection".to_owned(),
        evidence_ref: "evidence-1".to_owned(),
        contamination_flags: Vec::new(),
    }
}

#[test]
fn unbound_observation_is_retained_cold_without_task_effects() {
    let admission = admit_capture(
        "candidate-1929-1".to_owned(),
        fence(),
        None,
        0,
        CompatibilityDisposition::Compatible,
    )
    .expect("absent selection stays cold");
    match admission {
        CaptureAdmission::ColdUnbound(candidate) => {
            assert_eq!(candidate.reason_ref, "unbound-capture");
            assert!(!candidate.affects_task());
        }
        CaptureAdmission::TaskBound(_) => panic!("absent selection must not bind a task"),
    }
    // Ambiguity (two candidates) also stays cold: no latest/open-task guess.
    let ambiguous = admit_capture(
        "candidate-1929-2".to_owned(),
        fence(),
        Some(&evidence("task-a", "scope-a")),
        2,
        CompatibilityDisposition::Compatible,
    )
    .expect("ambiguous selection stays cold");
    assert!(matches!(ambiguous, CaptureAdmission::ColdUnbound(_)));
}

#[test]
fn promotion_without_evidence_returns_selection_required() {
    let error = admit_task_bound(
        None,
        "task-a",
        "scope-a",
        &fence(),
        CompatibilityDisposition::Compatible,
    )
    .expect_err("missing evidence must reject");
    assert_eq!(error.code(), TASK_SELECTION_REQUIRED);
}

#[test]
fn wrong_scope_evidence_returns_incompatible_without_changing_tasks() {
    let fence = fence();
    let other_scope = evidence("task-a", "scope-other");
    let before = other_scope.clone();
    let error = admit_task_bound(
        Some(&other_scope),
        "task-a",
        "scope-a",
        &fence,
        CompatibilityDisposition::Compatible,
    )
    .expect_err("wrong-scope evidence must reject");
    assert_eq!(error.code(), TASK_SCOPE_INCOMPATIBLE);
    assert_eq!(other_scope, before, "rejection mutates nothing");
}

#[test]
fn contaminated_selection_never_promotes() {
    let mut tainted = evidence("task-a", "scope-a");
    tainted.contamination_flags = vec!["crossover-suspect".to_owned()];
    // Capture stays cold instead of binding the tainted selection.
    let cold = admit_capture(
        "candidate-1929-3".to_owned(),
        fence(),
        Some(&tainted),
        1,
        CompatibilityDisposition::Compatible,
    )
    .expect("contaminated selection stays cold");
    assert!(matches!(cold, CaptureAdmission::ColdUnbound(_)));
    // Promotion rejects tainted evidence as non-current.
    let error = admit_task_bound(
        Some(&tainted),
        "task-a",
        "scope-a",
        &fence(),
        CompatibilityDisposition::Compatible,
    )
    .expect_err("contaminated promotion must reject");
    assert_eq!(error.code(), TASK_SELECTION_REQUIRED);
}
