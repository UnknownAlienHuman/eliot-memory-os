//! Canonical quiet-hours configuration projection for notification delivery.
//!
//! Issue #1780 / PR #2252 runtime-owner request (I11.5
//! `I11-05-persistent-notifications.md`, I11.7
//! `I11-07-notification-behavior.md`). This module projects typed
//! quiet-hours state out of an admitted [`ConfigPolicySnapshot`]. It is
//! pure: it validates candidates and produces typed decisions. It does not
//! read sources, persist snapshots, resolve timezones, read clocks, or start
//! jobs.
//!
//! Rules enforced here:
//! - `enabled: false` is an explicit owner decision requiring no window;
//! - a missing `enabled` key is a fail-closed error, never a silent default;
//! - an enabled window is a validated non-equal `0..=23` half-open UTC
//!   window (wrap past midnight allowed), mirroring the notify surface;
//! - the carried fence must bind the snapshot revision
//!   (`fence.policy_revision == Some(snapshot.revision)`);
//! - the snapshot must be complete and applicable to the target
//!   machine/scope/fence/revision; anything else fails closed, never into
//!   an unrecorded policy choice.

#![forbid(unsafe_code)]

use super::{Applicability, ApplicabilityContext, ConfigError, ConfigPolicySnapshot};
use eliot_contracts::{PolicyRevision, StateFence};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Setting key for the explicit quiet-hours decision (`literal:true|false`).
pub const QUIET_HOURS_ENABLED_KEY: &str = "notification.quiet_hours.enabled";
/// Setting key for the UTC window start (`literal:<0..=23>`).
pub const QUIET_HOURS_START_KEY: &str = "notification.quiet_hours.start_hour_utc";
/// Setting key for the UTC window end (`literal:<0..=23>`).
pub const QUIET_HOURS_END_KEY: &str = "notification.quiet_hours.end_hour_utc";

/// Canonical quiet-hours configuration export for notification delivery.
///
/// `start_hour_utc`/`end_hour_utc` are a UTC half-open window validated only
/// when `enabled`; a disabled projection carries `0, 0`, which is
/// deliberately not a valid window, so consumers must branch on `enabled`
/// first and only pass a configuration onward when it is true.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NotificationQuietHoursProjection {
    /// Explicit owner decision; false means the owner selected no window.
    pub enabled: bool,
    /// UTC half-open window start; required and validated only when enabled.
    pub start_hour_utc: u8,
    /// UTC half-open window end; required and validated only when enabled.
    pub end_hour_utc: u8,
    /// Immutable revision of the snapshot that supplied this value.
    pub policy_revision: PolicyRevision,
    /// The same fence used by the notification request route.
    pub state_fence: StateFence,
    /// Canonical snapshot identity/provenance.
    pub snapshot_id: String,
}

fn find_setting<'a>(snapshot: &'a ConfigPolicySnapshot, key: &str) -> Option<&'a str> {
    snapshot
        .settings
        .iter()
        .find(|setting| setting.key == key)
        .map(|setting| setting.value_ref.as_str())
}

fn parse_hour(raw: Option<&str>) -> Result<u8, ConfigError> {
    let literal = raw
        .ok_or(ConfigError::InvalidSnapshot("quiet_hours window missing"))?
        .strip_prefix("literal:")
        .ok_or(ConfigError::InvalidSnapshot("quiet_hours window malformed"))?;
    if literal.is_empty() || !literal.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(ConfigError::InvalidSnapshot("quiet_hours window malformed"));
    }
    let hour: u8 = literal
        .parse()
        .map_err(|_| ConfigError::InvalidSnapshot("quiet_hours window malformed"))?;
    if hour > 23 {
        return Err(ConfigError::InvalidSnapshot("quiet_hours window invalid"));
    }
    Ok(hour)
}

/// Projects typed quiet-hours state out of an admitted snapshot.
///
/// Fails closed on a missing, malformed, stale, foreign, inapplicable, or
/// fence-mismatched input. A disabled projection is the only non-error path
/// that carries no window.
///
/// # Errors
///
/// Returns the snapshot/applicability failure for stale, foreign, or
/// structurally invalid inputs, or `ConfigError::InvalidSnapshot` for a
/// missing/malformed decision or window, an unsupported scope, a
/// non-applicable outcome, or a fence/revision mismatch.
pub fn project_quiet_hours(
    snapshot: &ConfigPolicySnapshot,
    context: &ApplicabilityContext,
) -> Result<NotificationQuietHoursProjection, ConfigError> {
    let applicability = snapshot.applicability(context)?;
    if applicability.outcome != Applicability::Applicable {
        if applicability.outcome == Applicability::Unsupported {
            return Err(ConfigError::InvalidSnapshot(
                "quiet_hours scope unsupported",
            ));
        }
        return Err(ConfigError::InvalidSnapshot("quiet_hours not applicable"));
    }
    if snapshot.state_fence.policy_revision != Some(snapshot.revision) {
        return Err(ConfigError::InvalidSnapshot(
            "quiet_hours fence revision mismatch",
        ));
    }
    let enabled = match find_setting(snapshot, QUIET_HOURS_ENABLED_KEY) {
        None => {
            return Err(ConfigError::InvalidSnapshot("quiet_hours.enabled missing"));
        }
        Some(value) => match value.strip_prefix("literal:") {
            Some("true") => true,
            Some("false") => false,
            _ => {
                return Err(ConfigError::InvalidSnapshot(
                    "quiet_hours.enabled malformed",
                ));
            }
        },
    };
    let (start_hour_utc, end_hour_utc) = if enabled {
        let start = parse_hour(find_setting(snapshot, QUIET_HOURS_START_KEY))?;
        let end = parse_hour(find_setting(snapshot, QUIET_HOURS_END_KEY))?;
        if start == end {
            return Err(ConfigError::InvalidSnapshot("quiet_hours window invalid"));
        }
        (start, end)
    } else {
        (0, 0)
    };
    Ok(NotificationQuietHoursProjection {
        enabled,
        start_hour_utc,
        end_hour_utc,
        policy_revision: snapshot.revision,
        state_fence: snapshot.state_fence.clone(),
        snapshot_id: snapshot.snapshot_id.clone(),
    })
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    reason = "quiet-hours projection tests build exact fixture identities"
)]
mod tests {
    use super::*;
    use crate::{HumanOwner, Setting, SourceCompleteness};
    use eliot_contracts::{EpochId, EpochLineageId, ResourceGeneration};
    use eliot_security_contracts::PolicyFence;
    use std::num::NonZeroU64;

    const TEST_LINEAGE: &str = "550e8400-e29b-41d4-a716-446655440000";

    fn fence() -> StateFence {
        let epoch = EpochId::new(
            EpochLineageId::new(TEST_LINEAGE).expect("valid test lineage"),
            NonZeroU64::new(1).expect("nonzero test sequence"),
        )
        .expect("valid test epoch");
        let mut fence = StateFence::new(epoch, ResourceGeneration::genesis());
        fence.policy_revision = Some(PolicyRevision::genesis());
        fence
    }

    fn setting(key: &str, value: &str) -> Setting {
        Setting {
            key: key.to_owned(),
            value_ref: value.to_owned(),
            owner_ref: "human-1".to_owned(),
        }
    }

    fn snapshot_with(settings: Vec<Setting>) -> ConfigPolicySnapshot {
        let fence = fence();
        ConfigPolicySnapshot {
            snapshot_id: "snapshot-1".to_owned(),
            machine_id: "machine-1".to_owned(),
            scope_id: "scope-1".to_owned(),
            revision: PolicyRevision::genesis(),
            source_completeness: SourceCompleteness::Complete,
            settings,
            policy_owner: HumanOwner {
                owner_ref: "human-1".to_owned(),
            },
            policy_fence: PolicyFence {
                policy_snapshot_id: "snapshot-1".to_owned(),
                state_fence: fence.clone(),
            },
            state_fence: fence,
            parent_snapshot_id: None,
            rollback_of: None,
        }
    }

    fn context() -> ApplicabilityContext {
        ApplicabilityContext {
            machine_id: "machine-1".to_owned(),
            scope_id: Some("scope-1".to_owned()),
            state_fence: fence(),
            active_revision: PolicyRevision::genesis(),
        }
    }

    fn enabled_settings() -> Vec<Setting> {
        vec![
            setting(QUIET_HOURS_ENABLED_KEY, "literal:true"),
            setting(QUIET_HOURS_START_KEY, "literal:22"),
            setting(QUIET_HOURS_END_KEY, "literal:6"),
        ]
    }

    #[test]
    fn enabled_window_projects_exact_fields() {
        let projection = project_quiet_hours(&snapshot_with(enabled_settings()), &context())
            .expect("enabled window projects");
        assert!(projection.enabled);
        assert_eq!(projection.start_hour_utc, 22);
        assert_eq!(projection.end_hour_utc, 6);
        assert_eq!(projection.policy_revision, PolicyRevision::genesis());
        assert_eq!(projection.state_fence, fence());
        assert_eq!(projection.snapshot_id, "snapshot-1");
    }

    #[test]
    fn explicit_disabled_needs_no_window() {
        let projection = project_quiet_hours(
            &snapshot_with(vec![setting(QUIET_HOURS_ENABLED_KEY, "literal:false")]),
            &context(),
        )
        .expect("explicit disabled projects");
        assert!(!projection.enabled);
    }

    #[test]
    fn missing_or_malformed_enabled_fails_closed() {
        assert_eq!(
            project_quiet_hours(&snapshot_with(vec![]), &context()),
            Err(ConfigError::InvalidSnapshot("quiet_hours.enabled missing"))
        );
        assert_eq!(
            project_quiet_hours(
                &snapshot_with(vec![setting(QUIET_HOURS_ENABLED_KEY, "literal:yes")]),
                &context(),
            ),
            Err(ConfigError::InvalidSnapshot(
                "quiet_hours.enabled malformed"
            ))
        );
    }

    #[test]
    fn invalid_windows_are_rejected() {
        for (start, end) in [
            ("literal:22", "literal:22"),
            ("literal:24", "literal:6"),
            ("literal:22", "literal:24"),
            ("literal:+2", "literal:6"),
            ("literal:2", "literal:ab"),
        ] {
            let mut settings = vec![setting(QUIET_HOURS_ENABLED_KEY, "literal:true")];
            settings.push(setting(QUIET_HOURS_START_KEY, start));
            settings.push(setting(QUIET_HOURS_END_KEY, end));
            assert!(
                project_quiet_hours(&snapshot_with(settings), &context()).is_err(),
                "window {start}/{end} must fail closed"
            );
        }
    }

    #[test]
    fn stale_foreign_or_fence_mismatched_snapshots_are_rejected() {
        assert!(matches!(
            project_quiet_hours(
                &snapshot_with(enabled_settings()),
                &ApplicabilityContext {
                    machine_id: "other".to_owned(),
                    ..context()
                }
            ),
            Err(ConfigError::ForeignMachine { .. })
        ));
        // Applicability passes (fences equal, revision current) but the
        // fence does not bind the snapshot revision.
        let mut mismatched = snapshot_with(enabled_settings());
        mismatched.revision = PolicyRevision::new(2).expect("nonzero revision");
        assert_eq!(
            project_quiet_hours(&mismatched, &context()),
            Err(ConfigError::InvalidSnapshot(
                "quiet_hours fence revision mismatch"
            ))
        );
    }
}
