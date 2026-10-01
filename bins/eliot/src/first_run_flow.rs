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
//!
//! Persistence (W2) is CLI-owned: when `ELIOT_SETUP_STATE_PATH` names a
//! state file, `setup apply` and `setup set` persist the canonical
//! `Setting` payload produced by the owner (`to_settings`) there, and
//! `setup show` / `setup set` read it back through the owner validators
//! (`parse_role`, `parse_automation`, `decide_first_run`) plus a
//! canonical round-trip check. The stored vocabulary only admits owner
//! states (`UNASSIGNED`, `LOCAL_DISPLAYED`, `ECONOMY_DISPLAYED`,
//! `PAID_EXPLICIT`), so a hand-edited file cannot smuggle in a route the
//! owner would reject. When the variable is unset, the commands project
//! decisions without persisting them and `setup show` reports the compiled
//! defaults, which keeps every displayed default inspectable and
//! reversible (W6) through the same CLI path once a state file is
//! configured. Board durability (W5/AC2) follows the same path: when the
//! variable is set, `setup recommend` loads the retained Human-board entries
//! at entry from the sibling `<stem>.board.json` file and saves after
//! insert, so a deduplicated recommendation persists across invocations;
//! when unset, the board lives for the invocation only.

#![forbid(unsafe_code)]

use anyhow::{Context, Result};
use eliot_config::{BlobProcessPolicyValue, Setting};
use eliot_config::first_run::{
    FirstRunAutomation, FirstRunDecision, FirstRunInput, FirstRunRole, HumanBoardRecommendation,
    RecommendationBoard, RouteKind, RouteSelection, apply_automation_update, apply_update,
    decide_first_run, describe_defaults, parse_kind, parse_role,
    recommend_when_automation_disabled, to_settings,
};
use eliot_config::initial_snapshot::{
    InitialSnapshotIdentity, PrivacyChoice, prepare_initial_snapshot_payload_with_blob_policy,
};
use eliot_contracts::{EpochId, EpochLineageId, ResourceGeneration, StateFence};
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};
use std::num::NonZeroU64;
use std::path::{Path, PathBuf};

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
    /// Explicit closed S-04 policy and six-domain residency JSON. No policy
    /// or owner domain is inferred by the setup flow.
    pub blob_process_policy_json: String,
    pub dreamer_route: Option<String>,
    pub watchdog_route: Option<String>,
    pub dreamer_displayed: bool,
    pub watchdog_displayed: bool,
    pub dreamer_explicit: bool,
    pub watchdog_explicit: bool,
    pub automation: Option<String>,
}

/// Environment variable selecting the CLI-owned first-run setup-state file.
///
/// When set, `setup apply` and `setup set` persist the canonical `Setting`
/// payload there and `setup show` / `setup set` read it back through the
/// owner validators. When unset, commands project decisions without storing
/// them. No path is invented: persistence only happens at the configured
/// location.
pub const SETUP_STATE_PATH_ENV: &str = "ELIOT_SETUP_STATE_PATH";

/// Schema marker for the CLI-owned setup-state document. The document wraps
/// the canonical `Setting` payload verbatim; any other schema is rejected.
const SETUP_STATE_SCHEMA: &str = "eliot.first-run-decision/1";

/// Schema marker for the CLI-owned board-state document. The document wraps
/// the retained Human-board recommendations verbatim; any other schema is
/// rejected.
const BOARD_STATE_SCHEMA: &str = "eliot.first-run-board/1";

/// CLI-owned setup-state document: the canonical `Setting` persistence
/// payload produced by [`to_settings`], verbatim.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SetupStateDocument {
    schema: String,
    settings: Vec<Setting>,
}

/// CLI-owned board-state document: the Human-board recommendations retained
/// across `setup recommend` invocations, verbatim.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BoardStateDocument {
    schema: String,
    recommendations: Vec<HumanBoardRecommendation>,
}

/// Resolves the CLI-owned setup-state path. `None` means persistence is not
/// configured and commands project decisions without storing them.
fn setup_state_path() -> Result<Option<PathBuf>> {
    let Some(raw) = std::env::var_os(SETUP_STATE_PATH_ENV) else {
        return Ok(None);
    };
    let raw = raw.to_string_lossy().into_owned();
    if raw.trim().is_empty() {
        anyhow::bail!("{SETUP_STATE_PATH_ENV} must be non-blank");
    }
    Ok(Some(PathBuf::from(raw)))
}

/// Terminal receipt fragment describing where the decision lives: the
/// configured state file when persistence is active, `projected-only`
/// otherwise.
fn state_receipt(state_path: Option<&PathBuf>) -> serde_json::Value {
    match state_path {
        Some(path) => serde_json::json!({
            "source": "stored",
            "path": path.display().to_string(),
        }),
        None => serde_json::json!({"source": "projected-only"}),
    }
}

/// Rebuilds the typed decision from stored canonical settings, validating
/// the ORIGINAL stored values through the owner layer.
///
/// Every entry must be a known canonical key (`route.<role>` or
/// `automation.maintenance_mode`) with a `literal:<STATE>` value. Role
/// entries re-enter through [`parse_role`] and the stored state token maps
/// back to the selection the owner originally admitted (`PAID_EXPLICIT`
/// records the explicit consent given at apply/set time); the assembled
/// input is re-decided by [`decide_first_run`], and the result must
/// re-project to the identical `Setting` payload. A hand-edited file can
/// therefore only ever select states the owner itself admits, and any
/// drift fails closed.
fn decision_from_settings(settings: &[Setting]) -> Result<(FirstRunDecision, String)> {
    let mut owner_ref: Option<&str> = None;
    let mut seen_keys = BTreeSet::new();
    let mut selections = BTreeMap::new();
    let mut automation: Option<FirstRunAutomation> = None;
    for setting in settings {
        if setting.key.trim().is_empty()
            || setting.value_ref.trim().is_empty()
            || setting.owner_ref.trim().is_empty()
        {
            anyhow::bail!("stored setup state carries a blank setting field");
        }
        if !seen_keys.insert(setting.key.as_str()) {
            anyhow::bail!("stored setup state carries duplicate key: {}", setting.key);
        }
        match owner_ref {
            None => owner_ref = Some(setting.owner_ref.as_str()),
            Some(known) if known == setting.owner_ref.as_str() => {}
            Some(_) => anyhow::bail!("stored setup state mixes settings owners"),
        }
        if let Some(role_key) = setting.key.strip_prefix("route.") {
            let role = parse_role(role_key).map_err(|error| anyhow::anyhow!(error.to_string()))?;
            let state = setting.value_ref.strip_prefix("literal:").ok_or_else(|| {
                anyhow::anyhow!("stored route value is not a literal: {}", setting.key)
            })?;
            match state {
                "UNASSIGNED" => {}
                "LOCAL_DISPLAYED" => {
                    selections.insert(
                        role,
                        RouteSelection {
                            kind: RouteKind::Local,
                            displayed: true,
                            explicit_consent: false,
                        },
                    );
                }
                "ECONOMY_DISPLAYED" => {
                    selections.insert(
                        role,
                        RouteSelection {
                            kind: RouteKind::Economy,
                            displayed: true,
                            explicit_consent: false,
                        },
                    );
                }
                "PAID_EXPLICIT" => {
                    selections.insert(
                        role,
                        RouteSelection {
                            kind: RouteKind::Paid,
                            displayed: true,
                            explicit_consent: true,
                        },
                    );
                }
                _ => anyhow::bail!(
                    "stored setup state carries unknown route state: {}",
                    setting.key
                ),
            }
        } else if setting.key == "automation.maintenance_mode" {
            let mode = setting.value_ref.strip_prefix("literal:").ok_or_else(|| {
                anyhow::anyhow!("stored automation value is not a literal: {}", setting.key)
            })?;
            automation = Some(parse_automation(mode)?);
        } else {
            anyhow::bail!("stored setup state carries unknown key: {}", setting.key);
        }
    }
    let owner_ref =
        owner_ref.ok_or_else(|| anyhow::anyhow!("stored setup state carries no settings"))?;
    let decision = decide_first_run(&FirstRunInput {
        selections,
        automation,
    })
    .map_err(|error| anyhow::anyhow!(error.to_string()))
    .context("re-decide stored first-run route state")?;
    let mut stored: BTreeMap<&str, &str> = BTreeMap::new();
    for setting in settings {
        stored.insert(setting.key.as_str(), setting.value_ref.as_str());
    }
    let projected = to_settings(&decision, owner_ref);
    let mut expected: BTreeMap<&str, &str> = BTreeMap::new();
    for setting in &projected {
        expected.insert(setting.key.as_str(), setting.value_ref.as_str());
    }
    if stored != expected {
        anyhow::bail!("stored setup state does not match the canonical projection");
    }
    Ok((decision, owner_ref.to_owned()))
}

/// Loads the stored decision. `None` when no state file exists yet (a fresh
/// setup inspects the compiled defaults); a present-but-invalid file fails
/// closed rather than silently falling back to defaults.
fn load_stored_decision(path: &Path) -> Result<Option<(FirstRunDecision, String)>> {
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(anyhow::anyhow!("read stored setup state: {error}")),
    };
    let document: SetupStateDocument = serde_json::from_slice(&bytes)
        .map_err(|error| anyhow::anyhow!("stored setup state is not valid JSON: {error}"))?;
    if document.schema != SETUP_STATE_SCHEMA {
        anyhow::bail!("stored setup state schema is not {SETUP_STATE_SCHEMA}");
    }
    decision_from_settings(&document.settings).map(Some)
}

/// Persists the typed decision as the canonical `Setting` payload produced
/// by the owner.
fn save_stored_decision(path: &Path, decision: &FirstRunDecision, owner_ref: &str) -> Result<()> {
    let document = serde_json::json!({
        "schema": SETUP_STATE_SCHEMA,
        "settings": to_settings(decision, owner_ref),
    });
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)
            .map_err(|error| anyhow::anyhow!("create stored setup state dir: {error}"))?;
    }
    let encoded = serde_json::to_string_pretty(&document).context("encode stored setup state")?;
    std::fs::write(path, encoded)
        .map_err(|error| anyhow::anyhow!("write stored setup state: {error}"))?;
    Ok(())
}

/// Derives the CLI-owned board-state path from the configured setup-state
/// path: the same directory, `<stem>.board.json`. Board durability is only
/// configured through [`SETUP_STATE_PATH_ENV`]; no second location is
/// invented.
fn board_state_path(state_path: &Path) -> PathBuf {
    let stem = state_path
        .file_stem()
        .map(|stem| stem.to_string_lossy().into_owned())
        .unwrap_or_default();
    state_path.with_file_name(format!("{stem}.board.json"))
}

/// Loads the retained Human-board entries. An absent file means no entries
/// are retained yet; a present-but-invalid file fails closed rather than
/// silently starting from an empty board.
fn load_stored_board(path: &Path) -> Result<Vec<HumanBoardRecommendation>> {
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(anyhow::anyhow!("read stored board state: {error}")),
    };
    let document: BoardStateDocument = serde_json::from_slice(&bytes)
        .map_err(|error| anyhow::anyhow!("stored board state is not valid JSON: {error}"))?;
    if document.schema != BOARD_STATE_SCHEMA {
        anyhow::bail!("stored board state schema is not {BOARD_STATE_SCHEMA}");
    }
    Ok(document.recommendations)
}

/// Persists the retained Human-board entries verbatim.
fn save_stored_board(path: &Path, recommendations: &[HumanBoardRecommendation]) -> Result<()> {
    let document = serde_json::json!({
        "schema": BOARD_STATE_SCHEMA,
        "recommendations": recommendations,
    });
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)
            .map_err(|error| anyhow::anyhow!("create stored board state dir: {error}"))?;
    }
    let encoded = serde_json::to_string_pretty(&document).context("encode stored board state")?;
    std::fs::write(path, encoded)
        .map_err(|error| anyhow::anyhow!("write stored board state: {error}"))?;
    Ok(())
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
/// `UNASSIGNED`; no paid route is selected without explicit consent. When
/// `ELIOT_SETUP_STATE_PATH` is configured, the canonical payload is
/// persisted there so later `setup show` / `setup set` invocations observe
/// it; otherwise the decision is projected without being stored.
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
    let state_path = setup_state_path()?;
    if let Some(path) = &state_path {
        save_stored_decision(path, &decision, owner_ref)?;
    }
    println!(
        "{}",
        serde_json::json!({
            "routes": describe_defaults(&decision),
            "has_paid_route": decision.has_paid_route(),
            "settings": to_settings(&decision, owner_ref),
            "state": state_receipt(state_path.as_ref()),
        })
    );
    Ok(0)
}

/// Runs `setup show`: inspects every default through the same typed path,
/// reversibly. With a configured state file holding an applied decision,
/// the stored decision is shown; otherwise the compiled-safe defaults are
/// shown. A present-but-invalid state file fails closed.
pub fn run_setup_show() -> Result<i32> {
    let state_path = setup_state_path()?;
    let (decision, source, owner_ref) = match &state_path {
        Some(path) => match load_stored_decision(path)? {
            Some((decision, owner)) => (decision, "stored", Some(owner)),
            None => (FirstRunDecision::defaults(), "compiled-defaults", None),
        },
        None => (FirstRunDecision::defaults(), "compiled-defaults", None),
    };
    println!(
        "{}",
        serde_json::json!({
            "routes": describe_defaults(&decision),
            "has_paid_route": decision.has_paid_route(),
            "source": source,
            "owner_ref": owner_ref,
            "state": state_receipt(state_path.as_ref()),
        })
    );
    Ok(0)
}

/// Runs `setup set`: reversibly updates one role and/or the automation mode
/// through the same typed path, projecting the updated decision with its
/// canonical `Setting` persistence payload. The update applies on top of
/// the stored decision when a state file is configured (falling back to
/// the compiled defaults on a fresh setup), and the result is persisted
/// back so the next `setup show` observes it.
pub fn run_setup_set(args: &SetupSetArgs) -> Result<i32> {
    let owner_ref = args.owner_ref.trim();
    if owner_ref.is_empty() {
        anyhow::bail!("settings owner_ref must be non-blank");
    }
    if args.route.is_none() && args.automation.is_none() {
        anyhow::bail!("setup set requires --route, --automation, or both");
    }
    let state_path = setup_state_path()?;
    let base = match &state_path {
        Some(path) => match load_stored_decision(path)? {
            Some((decision, _)) => decision,
            None => FirstRunDecision::defaults(),
        },
        None => FirstRunDecision::defaults(),
    };
    let updated = match args.role.as_deref() {
        None => {
            if args.route.is_some() {
                anyhow::bail!("setup set --route requires --role");
            }
            base
        }
        Some(role_text) => {
            let role = parse_role(role_text).map_err(|error| anyhow::anyhow!(error.to_string()))?;
            let selection =
                selection_for(args.route.as_deref(), args.displayed, args.explicit_consent)?;
            apply_update(&base, role, selection)
                .map_err(|error| anyhow::anyhow!(error.to_string()))
                .context("apply first-run update")?
        }
    };
    let updated = match args.automation.as_deref() {
        None => updated,
        Some(mode) => apply_automation_update(&updated, parse_automation(mode)?),
    };
    if let Some(path) = &state_path {
        save_stored_decision(path, &updated, owner_ref)?;
    }
    println!(
        "{}",
        serde_json::json!({
            "routes": describe_defaults(&updated),
            "has_paid_route": updated.has_paid_route(),
            "settings": to_settings(&updated, owner_ref),
            "state": state_receipt(state_path.as_ref()),
        })
    );
    Ok(0)
}

/// Runs `setup recommend`: with automation disabled, stores one deduplicated
/// Human-board recommendation and starts no job. When `ELIOT_SETUP_STATE_PATH`
/// is configured, the retained entries are loaded at entry from the sibling
/// board-state file and saved after insert, so a recommendation persists
/// across invocations and a repeat trigger deduplicates against the retained
/// entries; otherwise the board lives for the invocation only.
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
    let state_path = setup_state_path()?;
    let board_path = state_path.as_deref().map(board_state_path);
    let mut retained: Vec<HumanBoardRecommendation> = match &board_path {
        Some(path) => load_stored_board(path)?,
        None => Vec::new(),
    };
    let mut board = RecommendationBoard::new();
    // Every ORIGINAL retained entry re-enters through the owner dedup rule,
    // so a hand-edited file can only ever select recommendations the owner
    // itself admits; a duplicate or rejected entry fails closed here.
    for stored in &retained {
        let admitted = board
            .insert_dedup(stored)
            .map_err(|error| anyhow::anyhow!(error.to_string()))?;
        if !admitted {
            anyhow::bail!("stored board state carries a duplicate entry");
        }
    }
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
    if is_new {
        retained.push(recommendation.clone());
    }
    if let Some(path) = &board_path {
        save_stored_board(path, &retained)?;
    }
    println!(
        "{}",
        serde_json::json!({
            "recommendation": recommendation,
            "admits_job": admits_job,
            "board_entries": board.len(),
            "is_new": is_new,
            "state": state_receipt(state_path.as_ref()),
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
    let blob_process_policy = BlobProcessPolicyValue::from_json(&args.blob_process_policy_json)
        .map_err(|error| anyhow::anyhow!(error.to_string()))
        .context("validate explicit Blob process policy and residency input")?;
    let payload = prepare_initial_snapshot_payload_with_blob_policy(
        &identity,
        privacy,
        &decision,
        &blob_process_policy,
    )
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
