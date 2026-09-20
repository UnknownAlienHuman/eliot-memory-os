//! Daemon-side first-run wiring for issue #1962.
//!
//! This module is wiring only. It resolves typed per-role route state and
//! Human-board maintenance recommendations through the canonical
//! `eliot-config::first_run` owner. It never mints paid routes, never starts
//! jobs on the disabled-automation path, and owns no canonical write, store,
//! provider, or scheduling semantics.

#![forbid(unsafe_code)]

use eliot_config::first_run::{
    FirstRunAutomation, FirstRunDecision, FirstRunInput, HumanBoardRecommendation,
    RecommendationBoard, decide_first_run, describe_defaults, recommend_when_automation_disabled,
};
use thiserror::Error;

/// Daemon wiring failures. All fail closed.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum FirstRunWiringError {
    #[error("first-run decision rejected: {0}")]
    Decision(String),
    #[error("board recommendation rejected: {0}")]
    Board(String),
}

/// Resolves the daemon's view of first-run route state through the canonical
/// owner. Omitted roles stay `UNASSIGNED`; hidden paid routes are rejected.
pub fn resolve_first_run_routes(
    input: &FirstRunInput,
) -> Result<FirstRunDecision, FirstRunWiringError> {
    decide_first_run(input).map_err(|error| FirstRunWiringError::Decision(error.to_string()))
}

/// Inspects every default through the same typed path the setup CLI uses.
#[must_use]
pub fn inspect_first_run_defaults() -> Vec<(String, String)> {
    describe_defaults(&FirstRunDecision::defaults())
}

/// Outcome of the disabled-automation maintenance path: one deduplicated
/// Human-board recommendation and an explicit `admits_job == false`. No job
/// is admitted or started here.
pub struct DisabledAutomationOutcome {
    pub recommendation: HumanBoardRecommendation,
    pub admits_job: bool,
    pub board_entries: usize,
    pub is_new: bool,
}

/// Records one needed maintenance/requalification action as a deduplicated
/// Human-board recommendation when automation is disabled. Returns an error
/// when automation is enabled (the governed job path owns that case).
pub fn recommend_for_disabled_automation(
    board: &mut RecommendationBoard,
    mode: FirstRunAutomation,
    explicit_request: bool,
    family: &str,
    scope_ref: &str,
) -> Result<DisabledAutomationOutcome, FirstRunWiringError> {
    let Some((recommendation, admits_job)) =
        recommend_when_automation_disabled(mode, explicit_request, family, scope_ref)
    else {
        return Err(FirstRunWiringError::Board(
            "automation mode permits the governed job path".to_owned(),
        ));
    };
    if admits_job {
        return Err(FirstRunWiringError::Board(
            "disabled-automation path must never admit a job".to_owned(),
        ));
    }
    let is_new = board
        .insert_dedup(&recommendation)
        .map_err(|error| FirstRunWiringError::Board(error.to_string()))?;
    Ok(DisabledAutomationOutcome {
        recommendation,
        admits_job,
        board_entries: board.len(),
        is_new,
    })
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "daemon wiring tests assert exact first-run shapes"
)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    #[test]
    fn daemon_resolves_omitted_dreamer_watchdog_as_unassigned_without_paid_route() {
        let decision = resolve_first_run_routes(&FirstRunInput {
            selections: BTreeMap::new(),
            automation: None,
        })
        .expect("daemon resolves");
        assert_eq!(
            decision.route_for(eliot_config::first_run::FirstRunRole::Dreamer),
            eliot_config::first_run::RouteState::Unassigned
        );
        assert_eq!(
            decision.route_for(eliot_config::first_run::FirstRunRole::WatchdogAgent),
            eliot_config::first_run::RouteState::Unassigned
        );
        assert!(!decision.has_paid_route());
    }

    #[test]
    fn daemon_disabled_automation_records_one_board_entry_and_no_job() {
        let mut board = RecommendationBoard::new();
        let first = recommend_for_disabled_automation(
            &mut board,
            FirstRunAutomation::Off,
            false,
            "RESEARCH_EXCHANGE_CLEANUP",
            "scope-1",
        )
        .expect("daemon recommends");
        assert!(!first.admits_job);
        assert!(first.is_new);
        let second = recommend_for_disabled_automation(
            &mut board,
            FirstRunAutomation::Off,
            false,
            "RESEARCH_EXCHANGE_CLEANUP",
            "scope-1",
        )
        .expect("daemon deduplicates");
        assert!(!second.is_new);
        assert_eq!(second.board_entries, 1);
    }
}
