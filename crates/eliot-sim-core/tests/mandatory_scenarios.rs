//! Mandatory-scenario acceptance: every scenario from `I18.41` is modeled
//! or coverage-gap-dispositioned, accepted with all invariants green, and
//! unsupported slugs fail closed.

use eliot_sim_core::{
    MANDATORY_SCENARIOS, OpStatus, ScenarioDisposition, ScenarioId, SimError,
    command::{CommandKind, StoreOutcome},
    event::{DeliveryFault, SimOutcome},
    fault::{Failpoint, FaultPlan, ScriptedFault},
    run,
};

#[test]
fn every_mandatory_scenario_is_accepted_with_green_invariants() {
    for scenario in MANDATORY_SCENARIOS {
        let report = run(scenario.id, 1916);
        assert!(
            report.drained,
            "scenario {} did not drain",
            scenario.id.slug()
        );
        assert!(
            report.artifact.accepted,
            "scenario {} not accepted",
            scenario.id.slug()
        );
        for verdict in &report.invariants {
            assert!(
                verdict.passed,
                "scenario {} invariant {} failed: {}",
                scenario.id.slug(),
                verdict.id,
                verdict.detail
            );
        }
        assert!(
            !scenario.live_proof_required.is_empty(),
            "scenario {} names no live proof",
            scenario.id.slug()
        );
        assert!(
            report.artifact.failure_capsule.is_none(),
            "accepted scenario {} carries a failure capsule",
            scenario.id.slug()
        );
        assert_eq!(
            report.artifact.trace_len,
            u64::try_from(report.trace.len()).unwrap_or(u64::MAX),
            "trace length mismatch for {}",
            scenario.id.slug()
        );
    }
}

#[test]
fn disposition_mix_is_explicit() {
    let mut modeled = 0_u32;
    let mut gaps = 0_u32;
    let mut unsupported = 0_u32;
    for scenario in MANDATORY_SCENARIOS {
        match scenario.disposition {
            ScenarioDisposition::Modeled => modeled = modeled.saturating_add(1),
            ScenarioDisposition::CoverageGap {
                reason,
                compensating_proof,
            } => {
                assert!(!reason.is_empty(), "empty gap reason");
                assert!(!compensating_proof.is_empty(), "empty compensating proof");
                gaps = gaps.saturating_add(1);
            }
            ScenarioDisposition::Unsupported { .. } => {
                unsupported = unsupported.saturating_add(1);
            }
        }
    }
    assert_eq!(modeled, 8, "expected eight modeled scenarios");
    assert_eq!(gaps, 3, "expected three coverage gaps");
    assert_eq!(
        unsupported, 0,
        "mandatory set must not hide unsupported work"
    );
    assert_eq!(MANDATORY_SCENARIOS.len(), ScenarioId::ALL.len());
}

#[test]
fn coverage_gaps_cover_supervision_and_race_timing() {
    for scenario in MANDATORY_SCENARIOS {
        let is_gap = matches!(
            scenario.disposition,
            ScenarioDisposition::CoverageGap { .. }
        );
        let expected_gap = matches!(
            scenario.id,
            ScenarioId::PromotionCutoverRollbackRace
                | ScenarioId::WatchdogLoss
                | ScenarioId::TestdLoss
        );
        assert_eq!(
            is_gap,
            expected_gap,
            "gap disposition wrong for {}",
            scenario.id.slug()
        );
    }
}

#[test]
fn stale_fencing_never_commits() {
    let report = run(ScenarioId::StaleFencing, 1916);
    assert!(
        report
            .terminal
            .ops
            .get(&1)
            .is_some_and(|record| record.status == OpStatus::Completed),
        "op 1 must complete"
    );
    assert!(
        report
            .terminal
            .ops
            .get(&2)
            .is_some_and(|record| record.status == OpStatus::Fenced && record.applied == 0),
        "op 2 must stay fenced without effects"
    );
}

#[test]
fn duplicate_delivery_applies_exactly_once() {
    let report = run(ScenarioId::DuplicateDelivery, 1916);
    assert!(
        report.terminal.ops.get(&1).is_some_and(|record| {
            record.status == OpStatus::Completed && record.applied == 1 && record.acked
        }),
        "op 1 must complete exactly once with its ack"
    );
    assert!(
        report
            .trace
            .iter()
            .any(|event| matches!(event.outcome, SimOutcome::DuplicateIgnored { .. }))
    );
}

#[test]
fn ack_loss_after_commit_keeps_exactly_one_commit() {
    let report = run(ScenarioId::AckLossAfterCommit, 1916);
    assert!(
        report.terminal.ops.get(&1).is_some_and(|record| {
            record.status == OpStatus::Committed && record.applied == 1 && !record.acked
        }),
        "op 1 must stay committed, applied once, unacked"
    );
    assert!(
        report
            .trace
            .iter()
            .any(|event| matches!(event.outcome, SimOutcome::AckLostAfterCommit { .. }))
    );
}

#[test]
fn unknown_store_outcome_never_completes() {
    let report = run(ScenarioId::UnknownStoreOutcome, 1916);
    assert!(
        report.terminal.ops.get(&1).is_some_and(|record| {
            record.status == OpStatus::Unknown && record.store == Some(StoreOutcome::Unknown)
        }),
        "op 1 must stay unknown"
    );
}

#[test]
fn cancel_complete_race_resolves_to_one_terminal() {
    let report = run(ScenarioId::CancelCompleteRace, 1916);
    assert!(
        report.terminal.ops.get(&1).is_some_and(|record| {
            record.status == OpStatus::Cancelled || record.status == OpStatus::Completed
        }),
        "op 1 must reach exactly one terminal"
    );
    assert!(
        report
            .trace
            .iter()
            .any(|event| matches!(event.outcome, SimOutcome::CancelCompleteResolved { .. }))
    );
}

#[test]
fn writer_restart_keeps_commits_and_drops_volatile_pending() {
    let report = run(ScenarioId::WriterRestart, 1916);
    assert!(
        report
            .terminal
            .ops
            .get(&1)
            .is_some_and(|record| record.status == OpStatus::Completed),
        "op 1 must stay completed"
    );
    assert!(
        report
            .terminal
            .ops
            .get(&2)
            .is_some_and(|record| record.status == OpStatus::Unknown),
        "op 2 must be unknown after the restart"
    );
    assert_eq!(report.terminal.writer_restarts, 1);
}

#[test]
fn promotion_cutover_rollback_race_has_single_winner() {
    let report = run(ScenarioId::PromotionCutoverRollbackRace, 1916);
    let mut moves: Vec<u64> = Vec::new();
    for event in &report.trace {
        if let SimOutcome::EpochMoved { epoch } = &event.outcome {
            moves.push(*epoch);
        }
    }
    assert_eq!(moves.len(), 3);
    assert_eq!(report.terminal.epoch, moves[moves.len() - 1]);
}

#[test]
fn overload_sheds_within_bound() {
    let report = run(ScenarioId::OverloadShedding, 1916);
    assert!(report.terminal.mailbox_depth <= report.terminal.mailbox_capacity);
    assert_eq!(report.terminal.shed_total, 3);
    assert_eq!(report.terminal.depth_check(), report.terminal.mailbox_depth);
}

#[test]
fn old_generation_output_is_rejected() {
    let report = run(ScenarioId::OldGenerationRejection, 1916);
    assert!(
        report
            .terminal
            .ops
            .get(&1)
            .is_some_and(|record| record.status == OpStatus::Committed),
        "op 1 must stay committed"
    );
    assert!(
        report
            .terminal
            .ops
            .get(&2)
            .is_some_and(|record| record.status == OpStatus::OldGeneration),
        "op 2 must be rejected as old generation"
    );
}

#[test]
fn watchdog_loss_downgrades_coverage_without_false_success() {
    let report = run(ScenarioId::WatchdogLoss, 1916);
    assert_eq!(report.terminal.watchdog, eliot_sim_core::Coverage::Unknown);
    assert_eq!(report.terminal.testd, eliot_sim_core::Coverage::Full);
    assert!(
        report
            .terminal
            .ops
            .get(&1)
            .is_some_and(|record| record.status == OpStatus::Completed),
        "op 1 must still complete on its store record"
    );
}

#[test]
fn testd_loss_downgrades_coverage_without_false_success() {
    let report = run(ScenarioId::TestdLoss, 1916);
    assert_eq!(report.terminal.testd, eliot_sim_core::Coverage::Unknown);
    assert_eq!(report.terminal.watchdog, eliot_sim_core::Coverage::Full);
}

#[test]
fn unknown_slug_fails_closed_as_unsupported() {
    let error = ScenarioId::from_slug("tokio-timing-fuzz");
    assert!(
        matches!(error, Err(SimError::UnsupportedScenario { .. })),
        "unknown slug must be unsupported"
    );
    if let Err(SimError::UnsupportedScenario { slug, reason }) = error {
        assert_eq!(slug, "tokio-timing-fuzz");
        assert!(reason.contains("outside the pure simulation boundary"));
    }
    for id in ScenarioId::ALL {
        assert!(
            ScenarioId::from_slug(id.slug()).is_ok_and(|resolved| resolved == id),
            "mandatory slug {} must resolve",
            id.slug()
        );
    }
}

#[test]
fn fault_plan_validation_fails_closed() {
    let unarmed = FaultPlan {
        armed: vec![Failpoint::SubmitPath],
        script: vec![ScriptedFault {
            kind: CommandKind::Ack,
            occurrence: 0,
            fault: DeliveryFault::Lost,
            delay_ticks: 0,
        }],
        background_jitter_max_ticks: 0,
    };
    assert!(unarmed.validate().is_err(), "unarmed failpoint must fail");

    let required_loss = FaultPlan {
        armed: vec![Failpoint::SubmitPath],
        script: vec![ScriptedFault {
            kind: CommandKind::Submit,
            occurrence: 0,
            fault: DeliveryFault::Lost,
            delay_ticks: 0,
        }],
        background_jitter_max_ticks: 0,
    };
    assert!(
        required_loss.validate().is_err(),
        "loss on a required path must fail"
    );

    let clean = FaultPlan::clean();
    assert!(clean.validate().is_ok(), "clean plan must validate");
}
