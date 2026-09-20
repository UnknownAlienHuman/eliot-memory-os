//! Governor-backed first-run setup flow for the `eliot` CLI.
//!
//! Issue #1962. This module is wiring only: it decodes CLI arguments,
//! constructs the typed owner input in `eliot-config::first_run`, and
//! projects a terminal receipt. All route-state, paid-route, default, and
//! Human-board dedup semantics live in the owner crate. The legacy
//! `governor.toml` file is never adopted as authority; when the legacy gate
//! reports a present file this flow fails closed before deciding anything.

#![forbid(unsafe_code)]

use anyhow::{Context, Result};
use eliot_config::first_run::{
    FirstRunAutomation, FirstRunInput, FirstRunRole, RecommendationBoard, RouteSelection,
    apply_update, decide_first_run, describe_defaults, parse_kind, parse_role,
    recommend_when_automation_disabled,
};
use std::collections::BTreeMap;

/// Decoded `setup apply` arguments. Every field is caller-supplied text; the
/// owner validates it.
#[allow(
    clippy::struct_excessive_bools,
    reason = "CLI-decoded flag bundle mirrors the clap surface"
)]
pub struct SetupApplyArgs {
    pub dreamer_route: Option<String>,
    pub watchdog_route: Option<String>,
    pub dreamer_displayed: bool,
    pub watchdog_displayed: bool,
    pub dreamer_explicit: bool,
    pub watchdog_explicit: bool,
}

/// Decoded `setup set` arguments: one role update through the same typed
/// path used by `setup apply` and inspected by `setup show`.
pub struct SetupSetArgs {
    pub role: String,
    pub route: Option<String>,
    pub displayed: bool,
    pub explicit_consent: bool,
}

/// Decoded `setup recommend` arguments for a needed maintenance action when
/// automation is disabled.
pub struct SetupRecommendArgs {
    pub automation: String,
    pub family: String,
    pub scope: String,
}

fn selection_for(
    route: Option<&str>,
    displayed: bool,
    explicit: bool,
) -> Result<Option<RouteSelection>> {
    let Some(route) = route else {
        return Ok(None);
    };
    let kind = parse_kind(route).map_err(|error| anyhow::anyhow!(error.to_string()))?;
    Ok(Some(RouteSelection {
        kind,
        displayed,
        explicit_consent: explicit,
    }))
}

fn parse_automation(value: &str) -> Result<FirstRunAutomation> {
    match value.trim().to_ascii_lowercase().as_str() {
        "suggest_only" | "suggest-only" | "suggest" => Ok(FirstRunAutomation::SuggestOnly),
        "manual" => Ok(FirstRunAutomation::Manual),
        "idle_only" | "idle-only" | "idle" => Ok(FirstRunAutomation::IdleOnly),
        "scheduled" => Ok(FirstRunAutomation::Scheduled),
        "continuous_bounded" | "continuous-bounded" | "continuous" => {
            Ok(FirstRunAutomation::ContinuousBounded)
        }
        "off" => Ok(FirstRunAutomation::Off),
        _ => anyhow::bail!("unknown automation mode: {value}"),
    }
}

/// Runs `setup apply`: decides typed per-role route state and projects it as
/// JSON. Omitted roles are `UNASSIGNED`; no paid route is selected without
/// explicit consent.
pub fn run_setup_apply(args: &SetupApplyArgs) -> Result<i32> {
    let mut selections = BTreeMap::new();
    if let Some(selection) = selection_for(
        args.dreamer_route.as_deref(),
        args.dreamer_displayed,
        args.dreamer_explicit,
    )? {
        selections.insert(FirstRunRole::Dreamer, selection);
    }
    if let Some(selection) = selection_for(
        args.watchdog_route.as_deref(),
        args.watchdog_displayed,
        args.watchdog_explicit,
    )? {
        selections.insert(FirstRunRole::WatchdogAgent, selection);
    }
    let decision = decide_first_run(&FirstRunInput {
        selections,
        automation: None,
    })
    .map_err(|error| anyhow::anyhow!(error.to_string()))
    .context("decide first-run route state")?;
    println!(
        "{}",
        serde_json::json!({
            "routes": describe_defaults(&decision),
            "has_paid_route": decision.has_paid_route(),
        })
    );
    Ok(0)
}

/// Runs `setup show`: inspects every compiled-safe default through the same
/// typed path, reversibly.
#[allow(
    clippy::unnecessary_wraps,
    reason = "uniform fallible CLI wiring with sibling setup commands"
)]
pub fn run_setup_show() -> Result<i32> {
    let defaults = eliot_config::first_run::FirstRunDecision::defaults();
    println!(
        "{}",
        serde_json::json!({
            "defaults": describe_defaults(&defaults),
            "has_paid_route": defaults.has_paid_route(),
        })
    );
    Ok(0)
}

/// Runs `setup set`: reversibly updates one role through the same typed path.
pub fn run_setup_set(args: &SetupSetArgs) -> Result<i32> {
    let role = parse_role(&args.role).map_err(|error| anyhow::anyhow!(error.to_string()))?;
    let selection = selection_for(args.route.as_deref(), args.displayed, args.explicit_consent)?;
    let defaults = eliot_config::first_run::FirstRunDecision::defaults();
    let updated = apply_update(&defaults, role, selection)
        .map_err(|error| anyhow::anyhow!(error.to_string()))
        .context("apply first-run update")?;
    println!(
        "{}",
        serde_json::json!({
            "routes": describe_defaults(&updated),
            "has_paid_route": updated.has_paid_route(),
        })
    );
    Ok(0)
}

/// Runs `setup recommend`: with automation disabled, stores one deduplicated
/// Human-board recommendation and starts no job.
pub fn run_setup_recommend(args: &SetupRecommendArgs) -> Result<i32> {
    let automation = parse_automation(&args.automation)?;
    let Some((recommendation, admits_job)) = recommend_when_automation_disabled(
        automation,
        false,
        args.family.as_str(),
        args.scope.as_str(),
    ) else {
        anyhow::bail!("automation mode permits the governed job path; no board recommendation");
    };
    let mut board = RecommendationBoard::new();
    let is_new = board
        .insert_dedup(&recommendation)
        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    // A second insert of the same trigger must not duplicate.
    let is_new_again = board
        .insert_dedup(&recommendation)
        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    assert!(!is_new_again, "deduplicated board holds one entry");
    println!(
        "{}",
        serde_json::json!({
            "recommendation": recommendation,
            "admits_job": admits_job,
            "board_entries": board.len(),
            "is_new": is_new,
        })
    );
    Ok(0)
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "setup wiring tests assert exact CLI receipts"
)]
mod tests {
    use super::*;

    #[test]
    fn setup_apply_with_omitted_roles_reports_unassigned_and_no_paid_route() {
        let args = SetupApplyArgs {
            dreamer_route: None,
            watchdog_route: None,
            dreamer_displayed: false,
            watchdog_displayed: false,
            dreamer_explicit: false,
            watchdog_explicit: false,
        };
        assert_eq!(run_setup_apply(&args).expect("apply"), 0);
    }

    #[test]
    fn setup_recommend_with_automation_off_reports_one_entry_and_no_job() {
        let args = SetupRecommendArgs {
            automation: "off".to_owned(),
            family: "RESEARCH_EXCHANGE_CLEANUP".to_owned(),
            scope: "scope-1".to_owned(),
        };
        assert_eq!(run_setup_recommend(&args).expect("recommend"), 0);
    }
}
