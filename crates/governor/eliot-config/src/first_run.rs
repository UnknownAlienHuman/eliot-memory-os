//! First-run user decisions without hidden paid or automatic routes.
//!
//! Issue #1962 (I3.5 `I03-05-first-run-user-decisions.md`, I3.6
//! `I03-06-model-route-and-portfolio-policy.md`, I3.9
//! `I03-09-configuration-layers.md`). This module is the canonical
//! policy/config layer for typed per-role route state. It is pure: it
//! validates candidates and produces typed decisions. It does not read
//! sources, persist snapshots, publish state, or start jobs.
//!
//! Rules enforced here:
//! - an omitted role selection stores `UNASSIGNED` unless the setup screen
//!   displayed and the user accepted a local/economy default;
//! - Dreamer and Watchdog receive no hidden paid route: a paid route for
//!   those roles (and for any role without explicit consent) is rejected;
//! - when automation is disabled, a needed maintenance/requalification action
//!   is represented as one deduplicated Human-board recommendation and no job
//!   is admitted (`admits_job` is always false on that path);
//! - every displayed default is inspectable (`describe_defaults`) and
//!   reversible through the same typed update path (`apply_update`).

#![forbid(unsafe_code)]

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;

/// Roles asked about at first run (I3.5 role list).
#[derive(
    Clone, Copy, Debug, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FirstRunRole {
    MainAgent,
    Worker,
    Auditor,
    VerifierModel,
    WatchdogAgent,
    Dreamer,
    Research,
}

impl FirstRunRole {
    /// All roles in stable order.
    #[must_use]
    pub const fn all() -> [Self; 7] {
        [
            Self::MainAgent,
            Self::Worker,
            Self::Auditor,
            Self::VerifierModel,
            Self::WatchdogAgent,
            Self::Dreamer,
            Self::Research,
        ]
    }

    /// Canonical settings key for this role (`route.<role>`).
    #[must_use]
    pub const fn settings_key(self) -> &'static str {
        match self {
            Self::MainAgent => "route.main_agent",
            Self::Worker => "route.worker",
            Self::Auditor => "route.auditor",
            Self::VerifierModel => "route.verifier_model",
            Self::WatchdogAgent => "route.watchdog",
            Self::Dreamer => "route.dreamer",
            Self::Research => "route.research",
        }
    }
}

/// Route kind selectable per role.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RouteKind {
    Unassigned,
    Local,
    Economy,
    Paid,
}

/// One user-supplied per-role selection.
///
/// `displayed` must be true for a local/economy default to count as
/// explicitly shown; `explicit_consent` must be true for any paid route.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteSelection {
    pub kind: RouteKind,
    pub displayed: bool,
    pub explicit_consent: bool,
}

/// Stored typed per-role route state.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RouteState {
    Unassigned,
    LocalDisplayed,
    EconomyDisplayed,
    PaidExplicit,
}

impl RouteState {
    /// Whether this state selects a paid provider route.
    #[must_use]
    pub const fn is_paid(self) -> bool {
        matches!(self, Self::PaidExplicit)
    }
}

/// Human-owned first-run automation mode for maintenance.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FirstRunAutomation {
    SuggestOnly,
    Manual,
    IdleOnly,
    Scheduled,
    ContinuousBounded,
    Off,
}

/// Typed first-run decision: one route state per role plus automation mode.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FirstRunDecision {
    pub routes: BTreeMap<FirstRunRole, RouteState>,
    pub automation: FirstRunAutomation,
}

impl FirstRunDecision {
    /// Visible compiled-safe defaults: every role `UNASSIGNED`, automation
    /// `SUGGEST_ONLY` (recommend, never start). Inspectable via
    /// [`describe_defaults`], reversible via [`apply_update`].
    #[must_use]
    pub fn defaults() -> Self {
        let mut routes = BTreeMap::new();
        for role in FirstRunRole::all() {
            routes.insert(role, RouteState::Unassigned);
        }
        Self {
            routes,
            automation: FirstRunAutomation::SuggestOnly,
        }
    }

    /// Route state for one role (`UNASSIGNED` when absent, which cannot
    /// happen for decisions built by [`decide_first_run`]).
    #[must_use]
    pub fn route_for(&self, role: FirstRunRole) -> RouteState {
        self.routes
            .get(&role)
            .copied()
            .unwrap_or(RouteState::Unassigned)
    }

    /// Whether any role holds a paid provider route.
    #[must_use]
    pub fn has_paid_route(&self) -> bool {
        self.routes.values().any(|state| state.is_paid())
    }
}

/// First-run validation failures. All fail closed; nothing is defaulted
/// silently.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum FirstRunError {
    #[error("local/economy default was not displayed for role")]
    UndisplayedDefault,
    #[error("paid route requires explicit consent")]
    PaidWithoutConsent,
    #[error("dreamer and watchdog receive no hidden paid route")]
    HiddenPaidRoute,
    #[error("unknown role key: {0}")]
    UnknownRole(String),
    #[error("unknown route kind: {0}")]
    UnknownKind(String),
    #[error("invalid first-run field: {0}")]
    InvalidField(&'static str),
}

/// User-supplied per-role choices. `None` means the setup screen omitted the
/// role.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FirstRunInput {
    #[serde(default)]
    pub selections: BTreeMap<FirstRunRole, RouteSelection>,
    #[serde(default)]
    pub automation: Option<FirstRunAutomation>,
}

fn resolve_selection(
    role: FirstRunRole,
    selection: Option<RouteSelection>,
) -> Result<RouteState, FirstRunError> {
    let Some(selection) = selection else {
        return Ok(RouteState::Unassigned);
    };
    match selection.kind {
        RouteKind::Unassigned => Ok(RouteState::Unassigned),
        RouteKind::Local => {
            if !selection.displayed {
                return Err(FirstRunError::UndisplayedDefault);
            }
            Ok(RouteState::LocalDisplayed)
        }
        RouteKind::Economy => {
            if !selection.displayed {
                return Err(FirstRunError::UndisplayedDefault);
            }
            Ok(RouteState::EconomyDisplayed)
        }
        RouteKind::Paid => {
            if !selection.explicit_consent {
                if matches!(role, FirstRunRole::Dreamer | FirstRunRole::WatchdogAgent) {
                    return Err(FirstRunError::HiddenPaidRoute);
                }
                return Err(FirstRunError::PaidWithoutConsent);
            }
            // Explicit consent is recorded, but Dreamer/Watchdog paid routes
            // are still only admitted when that consent flag is set, which the
            // caller above guarantees. No hidden path exists.
            Ok(RouteState::PaidExplicit)
        }
    }
}

/// Decides typed per-role route state from first-run input.
///
/// Omitted roles become `UNASSIGNED`. Displayed local/economy defaults are
/// honoured; undisplayed defaults and non-consented paid routes are
/// rejected, with a dedicated rejection for Dreamer/Watchdog hidden paid
/// routes.
pub fn decide_first_run(input: &FirstRunInput) -> Result<FirstRunDecision, FirstRunError> {
    let mut routes = BTreeMap::new();
    for role in FirstRunRole::all() {
        routes.insert(
            role,
            resolve_selection(role, input.selections.get(&role).copied())?,
        );
    }
    Ok(FirstRunDecision {
        routes,
        automation: input.automation.unwrap_or(FirstRunAutomation::SuggestOnly),
    })
}

/// Parses a CLI-supplied role key (`dreamer`, `watchdog`, ...).
pub fn parse_role(value: &str) -> Result<FirstRunRole, FirstRunError> {
    match value.trim().to_ascii_lowercase().as_str() {
        "main" | "main_agent" | "main-agent" => Ok(FirstRunRole::MainAgent),
        "worker" => Ok(FirstRunRole::Worker),
        "auditor" => Ok(FirstRunRole::Auditor),
        "verifier" | "verifier_model" | "verifier-model" => Ok(FirstRunRole::VerifierModel),
        "watchdog" | "watchdog_agent" | "watchdog-agent" => Ok(FirstRunRole::WatchdogAgent),
        "dreamer" => Ok(FirstRunRole::Dreamer),
        "research" => Ok(FirstRunRole::Research),
        other => Err(FirstRunError::UnknownRole(other.to_owned())),
    }
}

/// Parses a CLI-supplied route kind (`unassigned`, `local`, `economy`, `paid`).
pub fn parse_kind(value: &str) -> Result<RouteKind, FirstRunError> {
    match value.trim().to_ascii_lowercase().as_str() {
        "unassigned" => Ok(RouteKind::Unassigned),
        "local" => Ok(RouteKind::Local),
        "economy" => Ok(RouteKind::Economy),
        "paid" => Ok(RouteKind::Paid),
        other => Err(FirstRunError::UnknownKind(other.to_owned())),
    }
}

/// One inspectable default entry (`key`, `value`), covering every role route
/// plus the automation mode. This is the same surface the setup CLI prints
/// (`setup show`) and accepts back (`setup set`).
#[must_use]
pub fn describe_defaults(decision: &FirstRunDecision) -> Vec<(String, String)> {
    let mut entries = Vec::with_capacity(8);
    for role in FirstRunRole::all() {
        let value = match decision.route_for(role) {
            RouteState::Unassigned => "UNASSIGNED",
            RouteState::LocalDisplayed => "LOCAL_DISPLAYED",
            RouteState::EconomyDisplayed => "ECONOMY_DISPLAYED",
            RouteState::PaidExplicit => "PAID_EXPLICIT",
        };
        entries.push((role.settings_key().to_owned(), value.to_owned()));
    }
    let automation = match decision.automation {
        FirstRunAutomation::SuggestOnly => "SUGGEST_ONLY",
        FirstRunAutomation::Manual => "MANUAL",
        FirstRunAutomation::IdleOnly => "IDLE_ONLY",
        FirstRunAutomation::Scheduled => "SCHEDULED",
        FirstRunAutomation::ContinuousBounded => "CONTINUOUS_BOUNDED",
        FirstRunAutomation::Off => "OFF",
    };
    entries.push((
        "automation.maintenance_mode".to_owned(),
        automation.to_owned(),
    ));
    entries
}

/// Reversibly updates one role through the same typed path the setup CLI
/// uses. `None` selection clears the role back to `UNASSIGNED`.
pub fn apply_update(
    decision: &FirstRunDecision,
    role: FirstRunRole,
    selection: Option<RouteSelection>,
) -> Result<FirstRunDecision, FirstRunError> {
    let mut next = decision.clone();
    next.routes
        .insert(role, resolve_selection(role, selection)?);
    Ok(next)
}

/// Persists the typed decision through the canonical policy/config layer as
/// deterministic `Setting` entries (`route.<role>` + automation mode).
#[must_use]
pub fn to_settings(decision: &FirstRunDecision, owner_ref: &str) -> Vec<crate::Setting> {
    let mut settings = Vec::with_capacity(8);
    for (key, value) in describe_defaults(decision) {
        settings.push(crate::Setting {
            key,
            value_ref: format!("literal:{value}"),
            owner_ref: owner_ref.to_owned(),
        });
    }
    settings
}

/// Whether maintenance automation is disabled (recommend, never start).
#[must_use]
pub const fn automation_disabled(mode: FirstRunAutomation, explicit_request: bool) -> bool {
    match mode {
        FirstRunAutomation::Off | FirstRunAutomation::SuggestOnly => true,
        FirstRunAutomation::Manual => !explicit_request,
        FirstRunAutomation::IdleOnly
        | FirstRunAutomation::Scheduled
        | FirstRunAutomation::ContinuousBounded => false,
    }
}

/// One deduplicated Human-board recommendation. It carries no admission
/// authority and never starts a job.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HumanBoardRecommendation {
    pub dedup_key: String,
    pub family: String,
    pub scope_ref: String,
    pub reason: String,
}

impl HumanBoardRecommendation {
    fn validate(&self) -> Result<(), FirstRunError> {
        if self.dedup_key.trim().is_empty()
            || self.family.trim().is_empty()
            || self.scope_ref.trim().is_empty()
            || self.reason.trim().is_empty()
            || [&self.dedup_key, &self.family, &self.scope_ref, &self.reason]
                .iter()
                .any(|value| value.chars().any(char::is_control))
        {
            return Err(FirstRunError::InvalidField("recommendation"));
        }
        Ok(())
    }
}

/// In-memory deduplication board for Human-board recommendations. Production
/// durability lives behind the canonical store; this type owns only the
/// deterministic dedup rule (one entry per `dedup_key`).
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RecommendationBoard {
    seen: BTreeSet<String>,
    entries: Vec<HumanBoardRecommendation>,
}

impl RecommendationBoard {
    /// Creates an empty board.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Inserts one recommendation, deduplicated by `dedup_key`. Returns true
    /// when the entry is new, false when it was already present. Never starts
    /// a job.
    pub fn insert_dedup(
        &mut self,
        recommendation: &HumanBoardRecommendation,
    ) -> Result<bool, FirstRunError> {
        recommendation.validate()?;
        if !self.seen.insert(recommendation.dedup_key.clone()) {
            return Ok(false);
        }
        self.entries.push(recommendation.clone());
        Ok(true)
    }

    /// Current recommendation count.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the board holds no recommendations.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Builds the single Human-board recommendation for a needed maintenance or
/// requalification action when automation is disabled. Returns `None` when
/// automation is enabled (the caller then follows the governed job path).
/// The returned value always has `admits_job == false`.
#[must_use]
pub fn recommend_when_automation_disabled(
    mode: FirstRunAutomation,
    explicit_request: bool,
    family: &str,
    scope_ref: &str,
) -> Option<(HumanBoardRecommendation, bool)> {
    if !automation_disabled(mode, explicit_request) {
        return None;
    }
    let family = family.trim();
    let scope_ref = scope_ref.trim();
    if family.is_empty() || scope_ref.is_empty() {
        return None;
    }
    let dedup_key = format!("maintenance:{family}:{scope_ref}");
    Some((
        HumanBoardRecommendation {
            dedup_key,
            family: family.to_owned(),
            scope_ref: scope_ref.to_owned(),
            reason: "AUTOMATION_DISABLED".to_owned(),
        },
        false,
    ))
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "first-run acceptance proofs assert exact typed shapes with real inputs"
)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    #[test]
    fn omitted_dreamer_and_watchdog_are_unassigned_with_no_paid_route() {
        let input = FirstRunInput {
            selections: BTreeMap::new(),
            automation: None,
        };
        let decision = decide_first_run(&input).expect("omitted roles decide");
        assert_eq!(
            decision.route_for(FirstRunRole::Dreamer),
            RouteState::Unassigned
        );
        assert_eq!(
            decision.route_for(FirstRunRole::WatchdogAgent),
            RouteState::Unassigned
        );
        assert!(!decision.has_paid_route());
    }

    #[test]
    fn disabled_automation_yields_one_deduplicated_board_entry_and_no_job() {
        let (recommendation, admits_job) = recommend_when_automation_disabled(
            FirstRunAutomation::Off,
            false,
            "RESEARCH_EXCHANGE_CLEANUP",
            "scope-1",
        )
        .expect("disabled automation recommends");
        assert!(!admits_job);
        let mut board = RecommendationBoard::new();
        assert!(board.insert_dedup(&recommendation).expect("insert"));
        assert!(!board.insert_dedup(&recommendation).expect("re-insert"));
        assert_eq!(board.len(), 1);
    }

    #[test]
    fn defaults_are_inspectable_and_reversible_through_the_same_path() {
        let defaults = FirstRunDecision::defaults();
        let described = describe_defaults(&defaults);
        assert_eq!(described.len(), 8);
        assert!(
            described
                .iter()
                .any(|(key, value)| key == "route.dreamer" && value == "UNASSIGNED")
        );

        let updated = apply_update(
            &defaults,
            FirstRunRole::Dreamer,
            Some(RouteSelection {
                kind: RouteKind::Local,
                displayed: true,
                explicit_consent: false,
            }),
        )
        .expect("displayed local default applies");
        assert_eq!(
            updated.route_for(FirstRunRole::Dreamer),
            RouteState::LocalDisplayed
        );

        let reverted = apply_update(&updated, FirstRunRole::Dreamer, None).expect("revert");
        assert_eq!(reverted, defaults);

        assert_eq!(
            apply_update(
                &defaults,
                FirstRunRole::WatchdogAgent,
                Some(RouteSelection {
                    kind: RouteKind::Paid,
                    displayed: true,
                    explicit_consent: false,
                }),
            ),
            Err(FirstRunError::HiddenPaidRoute)
        );
    }
}
