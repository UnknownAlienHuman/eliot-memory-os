//! Governor-backed first-run setup flow for the `eliot` CLI.
//!
//! Issue #1962. This module is wiring only: it decodes CLI arguments,
//! constructs the typed owner input in `eliot-config::first_run`, and
//! projects a terminal receipt carrying both the human-readable decision
//! and the canonical `Setting` persistence payload. All route-state,
//! paid-route, default, and Human-board dedup semantics live in the owner
//! crate. This flow reads no configuration files, so the legacy
//! `governor.toml` file is never adopted as authority here; `run_setup` in
//! `main.rs` rejects a present legacy file before dispatch (canary/install
//! paths gate independently).

#![forbid(unsafe_code)]

use anyhow::{Context, Result};
use eliot_config::first_run::{
    FirstRunAutomation, FirstRunDecision, FirstRunInput, FirstRunRole, RecommendationBoard,
    RouteSelection, apply_automation_update, apply_update, decide_first_run, describe_defaults,
    parse_kind, parse_role, recommend_when_automation_disabled, to_settings,
};
use eliot_config::initial_snapshot::{
    InitialSnapshotIdentity, PrivacyChoice, prepare_initial_snapshot_payload,
};
use eliot_contracts::{EpochId, EpochLineageId, ResourceGeneration, StateFence};
use std::collections::BTreeMap;
use std::num::NonZeroU64;

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
    /// Automation mode (`suggest_only`, `manual`, `idle_only`, `scheduled`,
    /// `continuous_bounded`, `off`). Omitted keeps the visible
    /// `SUGGEST_ONLY` default.
    pub automation: Option<String>,
    /// Human owner ref recorded on every persisted setting. Required and
    /// non-blank: no identity is invented here.
    pub owner_ref: String,
}

/// Decoded `setup set` arguments: one role and/or automation update through
/// the same typed path used by `setup apply` and inspected by `setup show`.
pub struct SetupSetArgs {
    pub role: Option<String>,
    pub route: Option<String>,
    pub displayed: bool,
    pub explicit_consent: bool,
    /// Automation mode update. At least one of `route` or `automation` is
    /// required; `role` is required with `route`.
    pub automation: Option<String>,
    /// Human owner ref recorded on every persisted setting. Required and
    /// non-blank: no identity is invented here.
    pub owner_ref: String,
}

/// Decoded `setup recommend` arguments for a needed maintenance action when
/// automation is disabled.
pub struct SetupRecommendArgs {
    pub automation: String,
    pub family: String,
    pub scope: String,
}

/// Decoded `setup initial-config` arguments for the first signed configuration
/// payload (I3.2 milestone 7).
///
/// Every identity value is an observed or user-confirmed fact supplied by the
/// installation owner; this module never invents an identity, a root, or a key.
#[allow(
    clippy::struct_excessive_bools,
    reason = "CLI-decoded flag bundle mirrors the clap surface"
)]
pub struct SetupInitialConfigArgs {
    pub snapshot_id: String,
    pub installation_id: String,
    pub profile_ref: String,
    pub owner_ref: String,
    pub key_identity: String,
    pub machine_id: String,
    pub scope_id: String,
    pub runtime_state_roots_digest: String,
    pub setup_revision: u64,
    pub authority_lineage: String,
    pub authority_sequence: u64,
    pub resource_generation: u64,
    pub privacy: String,
    pub dreamer_route: Option<String>,
    pub watchdog_route: Option<String>,
    pub dreamer_displayed: bool,
    pub watchdog_displayed: bool,
    pub dreamer_explicit: bool,
    pub watchdog_explicit: bool,
    pub automation: Option<String>,
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

fn parse_privacy(value: &str) -> Result<PrivacyChoice> {
    match value.trim().to_ascii_lowercase().as_str() {
        "local_only" | "local-only" | "localonly" => Ok(PrivacyChoice::LocalOnly),
        "standard" => Ok(PrivacyChoice::Standard),
        _ => anyhow::bail!("unknown privacy mode: {value}"),
    }
}

fn first_run_decision(
    dreamer: Option<(&str, bool, bool)>,
    watchdog: Option<(&str, bool, bool)>,
    automation: Option<&str>,
) -> Result<FirstRunDecision> {
    let mut selections = BTreeMap::new();
    if let Some((route, displayed, explicit)) = dreamer
        && let Some(selection) = selection_for(Some(route), displayed, explicit)?
    {
        selections.insert(FirstRunRole::Dreamer, selection);
    }
    if let Some((route, displayed, explicit)) = watchdog
        && let Some(selection) = selection_for(Some(route), displayed, explicit)?
    {
        selections.insert(FirstRunRole::WatchdogAgent, selection);
    }
    decide_first_run(&FirstRunInput {
        selections,
        automation: automation.map(parse_automation).transpose()?,
    })
    .map_err(|error| anyhow::anyhow!(error.to_string()))
    .context("decide first-run route state")
}

fn route_choice(
    route: Option<&String>,
    displayed: bool,
    explicit: bool,
) -> Option<(&str, bool, bool)> {
    route.map(|route| (route.as_str(), displayed, explicit))
}

/// Runs `setup apply`: decides typed per-role route state and projects it as
/// JSON with the canonical `Setting` persistence payload. Omitted roles are
/// `UNASSIGNED`; no paid route is selected without explicit consent.
pub fn run_setup_apply(args: &SetupApplyArgs) -> Result<i32> {
    let owner_ref = args.owner_ref.trim();
    if owner_ref.is_empty() {
        anyhow::bail!("settings owner_ref must be non-blank");
    }
    let decision = first_run_decision(
        route_choice(
            args.dreamer_route.as_ref(),
            args.dreamer_displayed,
            args.dreamer_explicit,
        ),
        route_choice(
            args.watchdog_route.as_ref(),
            args.watchdog_displayed,
            args.watchdog_explicit,
        ),
        args.automation.as_deref(),
    )?;
    println!(
        "{}",
        serde_json::json!({
            "routes": describe_defaults(&decision),
            "has_paid_route": decision.has_paid_route(),
            "settings": to_settings(&decision, owner_ref),
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

/// Runs `setup set`: reversibly updates one role and/or the automation mode
/// through the same typed path, projecting the updated decision with its
/// canonical `Setting` persistence payload.
pub fn run_setup_set(args: &SetupSetArgs) -> Result<i32> {
    let owner_ref = args.owner_ref.trim();
    if owner_ref.is_empty() {
        anyhow::bail!("settings owner_ref must be non-blank");
    }
    if args.route.is_none() && args.automation.is_none() {
        anyhow::bail!("setup set requires --route, --automation, or both");
    }
    let defaults = eliot_config::first_run::FirstRunDecision::defaults();
    let updated = match args.role.as_deref() {
        None => {
            if args.route.is_some() {
                anyhow::bail!("setup set --route requires --role");
            }
            defaults
        }
        Some(role_text) => {
            let role = parse_role(role_text).map_err(|error| anyhow::anyhow!(error.to_string()))?;
            let selection =
                selection_for(args.route.as_deref(), args.displayed, args.explicit_consent)?;
            apply_update(&defaults, role, selection)
                .map_err(|error| anyhow::anyhow!(error.to_string()))
                .context("apply first-run update")?
        }
    };
    let updated = match args.automation.as_deref() {
        None => updated,
        Some(mode) => apply_automation_update(&updated, parse_automation(mode)?),
    };
    println!(
        "{}",
        serde_json::json!({
            "routes": describe_defaults(&updated),
            "has_paid_route": updated.has_paid_route(),
            "settings": to_settings(&updated, owner_ref),
        })
    );
    Ok(0)
}

/// Runs `setup recommend`: with automation disabled, stores one deduplicated
/// Human-board recommendation and starts no job.
pub fn run_setup_recommend(args: &SetupRecommendArgs) -> Result<i32> {
    let automation = parse_automation(&args.automation)?;
    if args.family.trim().is_empty() || args.scope.trim().is_empty() {
        anyhow::bail!("recommendation family and scope must be non-blank");
    }
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
    // A second insert of the same trigger must not duplicate; a failure here
    // is a typed CLI error, never a panic.
    let is_new_again = board
        .insert_dedup(&recommendation)
        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    if is_new_again {
        anyhow::bail!("deduplicated board admitted a duplicate entry");
    }
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

/// Runs `setup initial-config`: prepares the first signed configuration payload
/// from the confirmed privacy mode and the confirmed first-run choices.
///
/// Preparation is deterministic, model-free and read-only. It signs nothing,
/// publishes nothing, and starts nothing: the installation owner signs with
/// the protected key reference, publishes through its own operational journal,
/// re-reads and verifies the result, and only then advances the setup binding.
/// Omitted model roles stay `UNASSIGNED`, so setup finishes without a model
/// subscription.
pub fn run_setup_initial_config(args: &SetupInitialConfigArgs) -> Result<i32> {
    let privacy = parse_privacy(&args.privacy)?;
    let decision = first_run_decision(
        route_choice(
            args.dreamer_route.as_ref(),
            args.dreamer_displayed,
            args.dreamer_explicit,
        ),
        route_choice(
            args.watchdog_route.as_ref(),
            args.watchdog_displayed,
            args.watchdog_explicit,
        ),
        args.automation.as_deref(),
    )?;
    let lineage = EpochLineageId::new(args.authority_lineage.trim())
        .map_err(|error| anyhow::anyhow!(error.to_string()))
        .context("authority lineage identity")?;
    let sequence = NonZeroU64::new(args.authority_sequence)
        .ok_or_else(|| anyhow::anyhow!("authority_sequence must be non-zero"))?;
    let authority_epoch = EpochId::new(lineage, sequence)
        .map_err(|error| anyhow::anyhow!(error.to_string()))
        .context("authority epoch")?;
    let resource_generation = ResourceGeneration::new(args.resource_generation)
        .map_err(|error| anyhow::anyhow!(error.to_string()))
        .context("resource generation")?;
    let state_fence = StateFence::new(authority_epoch, resource_generation);
    let identity = InitialSnapshotIdentity {
        snapshot_id: args.snapshot_id.trim().to_owned(),
        installation_id: args.installation_id.trim().to_owned(),
        profile_ref: args.profile_ref.trim().to_owned(),
        owner_ref: args.owner_ref.trim().to_owned(),
        key_identity: args.key_identity.trim().to_owned(),
        machine_id: args.machine_id.trim().to_owned(),
        scope_id: args.scope_id.trim().to_owned(),
        runtime_state_roots_digest: args.runtime_state_roots_digest.trim().to_owned(),
        setup_revision: args.setup_revision,
        state_fence,
    };
    let payload = prepare_initial_snapshot_payload(&identity, privacy, &decision)
        .map_err(|error| anyhow::anyhow!(error.to_string()))
        .context("prepare the first signed configuration payload")?;
    println!(
        "{}",
        serde_json::json!({
            "payload": payload,
            "payload_digest": payload
                .digest()
                .map_err(|error| anyhow::anyhow!(error.to_string()))
                .context("canonical payload digest")?,
            "privacy_choice": privacy,
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
            automation: None,
            owner_ref: "human-1".to_owned(),
        };
        assert_eq!(run_setup_apply(&args).expect("apply"), 0);
    }

    #[test]
    fn setup_apply_records_automation_and_rejects_blank_owner() {
        let args = SetupApplyArgs {
            dreamer_route: None,
            watchdog_route: None,
            dreamer_displayed: false,
            watchdog_displayed: false,
            dreamer_explicit: false,
            watchdog_explicit: false,
            automation: Some("scheduled".to_owned()),
            owner_ref: "human-1".to_owned(),
        };
        assert_eq!(run_setup_apply(&args).expect("apply with automation"), 0);

        let blank_owner = SetupApplyArgs {
            dreamer_route: None,
            watchdog_route: None,
            dreamer_displayed: false,
            watchdog_displayed: false,
            dreamer_explicit: false,
            watchdog_explicit: false,
            automation: None,
            owner_ref: "   ".to_owned(),
        };
        assert!(
            run_setup_apply(&blank_owner).is_err(),
            "blank settings owner must fail closed"
        );
    }

    #[test]
    fn setup_set_updates_automation_without_role_and_rejects_empty_update() {
        let args = SetupSetArgs {
            role: None,
            route: None,
            displayed: false,
            explicit_consent: false,
            automation: Some("off".to_owned()),
            owner_ref: "human-1".to_owned(),
        };
        assert_eq!(run_setup_set(&args).expect("automation-only set"), 0);

        let missing_target = SetupSetArgs {
            role: None,
            route: None,
            displayed: false,
            explicit_consent: false,
            automation: None,
            owner_ref: "human-1".to_owned(),
        };
        assert!(
            run_setup_set(&missing_target).is_err(),
            "set without route or automation must fail closed"
        );

        let route_without_role = SetupSetArgs {
            role: None,
            route: Some("local".to_owned()),
            displayed: true,
            explicit_consent: false,
            automation: None,
            owner_ref: "human-1".to_owned(),
        };
        assert!(
            run_setup_set(&route_without_role).is_err(),
            "set --route without --role must fail closed"
        );
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

    #[test]
    fn setup_recommend_rejects_blank_family_or_scope_before_deciding() {
        for (family, scope) in [
            ("   ".to_owned(), "scope-1".to_owned()),
            ("RESEARCH_EXCHANGE_CLEANUP".to_owned(), "  ".to_owned()),
        ] {
            let args = SetupRecommendArgs {
                automation: "off".to_owned(),
                family,
                scope,
            };
            assert!(
                run_setup_recommend(&args).is_err(),
                "blank recommendation input must fail closed"
            );
        }
    }
}
