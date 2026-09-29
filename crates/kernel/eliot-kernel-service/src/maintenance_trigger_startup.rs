//! Replacement startup and protected routing for retained triggers (issue #1694 W6).
//!
//! I14.22 keeps the trigger durable while the evaluator is unavailable: "If
//! the evaluator is unavailable, the relevant trigger remains durable and is
//! surfaced on the next startup; safety/recovery triggers use their existing
//! protected paths." I14.24 assigns the supervision half to the Kernel owner:
//! on `eliotd` crash the "Kernel revokes daemon epoch", then a "compatible
//! daemon generation" recovers through "rebuild hot mirrors". This module is
//! that Kernel-owner wiring over the delivery ledger in
//! [`crate::maintenance_trigger_delivery`]: it retains pending claims on
//! daemon loss by revoking the lost consumer authority, it surfaces the
//! bounded pending set to the replacement only after replacement
//! authentication plus mirror recovery and before maintenance reconciliation
//! may be claimed complete, and it keeps safety/recovery triggers visible on
//! their registered Host/Kernel/Watchdog/Doctor route while the evaluator is
//! down.
//!
//! Ordinary pending debt surfaced here acquires no runtime lease and blocks
//! no unrelated safe work (I14.22: "The assessment does not keep ELIOT alive
//! merely because data exists."): these entrypoints return owned bounded
//! pages and hold no guard, so scheduling stays with the daemon/Kernel
//! owners, never this module. Protected visibility is classification-only:
//! an owner-issued [`MaintenanceTriggerRouteGrant`](eliot_protocol::MaintenanceTriggerRouteGrant)
//! opens one bound trigger on its registered route, and one trigger identity
//! is listed at most once, so duplicated delivery can never authorize
//! duplicated containment — containment itself stays with the route owner.
//!
//! Invocation is declared STITCH: the Kernel daemon-supervision seam calls
//! [`note_maintenance_daemon_loss`] after fencing the lost generation and
//! calls [`replacement_startup_pending_set`] after admitting the replacement
//! generation and rebuilding its hot mirrors; route owners call
//! [`protected_route_pending_set`] while the evaluator is down.

use std::collections::BTreeSet;

use eliot_contracts::StateFence;
use eliot_protocol::{
    MAINTENANCE_TRIGGER_PAGE_WIRE_ID, MAINTENANCE_TRIGGER_PAGE_WIRE_VERSION,
    MAINTENANCE_TRIGGER_REVOCATION_WIRE_ID, MAINTENANCE_TRIGGER_REVOCATION_WIRE_VERSION,
    MaintenanceTriggerGap, MaintenanceTriggerGapKind, MaintenanceTriggerPage,
    MaintenanceTriggerRevocation, MaintenanceTriggerRoute, MaintenanceTriggerRouteGrant,
    MaintenanceTriggerRoutingClass,
};

use crate::maintenance_trigger_delivery::{
    AuthenticatedMaintenanceTriggerSession, MaintenanceTriggerDeliveryError,
    MaintenanceTriggerDeliveryLedger, handle_maintenance_trigger_replacement_pending_set,
    handle_maintenance_trigger_revocation,
};
use crate::{KernelService, validate_text};

/// Lost daemon consumer whose trigger authority dies with its generation.
///
/// The fence and session identify the exact lost generation/session; the
/// Kernel owner principal in `revoking_owner` issues the revocation through
/// the existing Kernel owner, never through the lost daemon itself.
#[derive(Clone, Debug)]
pub struct LostMaintenanceConsumer {
    /// Exact daemon fence whose consumer authority is revoked.
    pub daemon_fence: StateFence,
    /// Daemon session identity within the lost generation.
    pub daemon_session: String,
    /// Kernel owner principal issuing this revocation.
    pub revoking_owner: String,
    /// Stable reason reference for the loss (for example `eliotd-crash`).
    pub reason: String,
    /// Revocation time as Unix milliseconds; must be nonzero.
    pub revoked_at_unix_ms: u64,
}

/// Replacement-generation startup gate for the retained pending set.
///
/// `replacement_principal` authenticates the replacement through live Kernel
/// authority; `mirror_recovered` reports whether the required hot-mirror
/// recovery completed for it.
#[derive(Clone, Debug)]
pub struct ReplacementMaintenanceStartup {
    /// Authenticated principal reference for the replacement generation.
    pub replacement_principal: String,
    /// Resume cursor into the bounded pending enumeration; `None` restarts it.
    pub continuation: Option<String>,
    /// Whether the required hot-mirror recovery completed for the replacement.
    pub mirror_recovered: bool,
    /// Observation time as Unix milliseconds.
    pub now_unix_ms: u64,
}

/// Retains pending claims on daemon loss and revokes the old consumer authority.
///
/// Builds the owner-issued [`MaintenanceTriggerRevocation`] for the lost
/// fence/session and records it through the existing Kernel owner
/// ([`handle_maintenance_trigger_revocation`]): `Claimed` rows return to
/// `Pending` under the same identity and revision for the replacement to
/// reclaim, `DecisionRecorded` rows move to `Reconciling` with the committed
/// receipt preserved, and every later old-generation claim or ack fails
/// against the revocation list. No row is deleted and no trigger identity is
/// re-minted.
///
/// # Errors
///
/// Returns [`MaintenanceTriggerDeliveryError`] when the owner session is not
/// live authority, or when the revocation shape is invalid (unbounded owner,
/// session, or reason text, zero revocation time, or an invalid fence).
pub fn note_maintenance_daemon_loss(
    service: &KernelService,
    owner: &AuthenticatedMaintenanceTriggerSession,
    ledger: &mut MaintenanceTriggerDeliveryLedger,
    lost: LostMaintenanceConsumer,
) -> Result<(), MaintenanceTriggerDeliveryError> {
    validate_text(
        &lost.revoking_owner,
        "maintenance_trigger_revocation.revoking_owner",
    )?;
    let revocation = MaintenanceTriggerRevocation {
        wire_id: MAINTENANCE_TRIGGER_REVOCATION_WIRE_ID.to_owned(),
        wire_version: MAINTENANCE_TRIGGER_REVOCATION_WIRE_VERSION,
        daemon_fence: lost.daemon_fence,
        daemon_session: lost.daemon_session,
        revoking_owner: lost.revoking_owner,
        reason: lost.reason,
        revoked_at_unix_ms: lost.revoked_at_unix_ms,
    };
    handle_maintenance_trigger_revocation(service, owner, ledger, revocation)
}

/// Surfaces the bounded pending set to an authenticated replacement generation.
///
/// Binds the replacement session from live Kernel authority (fails closed on
/// a fenced generation, a non-ready service, or an epoch/generation
/// mismatch), then delegates to
/// [`handle_maintenance_trigger_replacement_pending_set`]: with
/// `mirror_recovered == false` the ledger refuses with
/// [`MaintenanceTriggerDeliveryError::MirrorRecoveryRequired`], so
/// maintenance reconciliation can never be claimed complete before the
/// mirrors are rebuilt. The caller must surface the returned page before
/// marking maintenance reconciliation complete. Ordinary pending debt in the
/// page acquires no runtime lease and blocks no unrelated safe work.
///
/// # Errors
///
/// Returns [`MaintenanceTriggerDeliveryError`] when replacement
/// authentication fails, mirror recovery is incomplete, or the continuation
/// names no retained position.
pub fn replacement_startup_pending_set(
    service: &KernelService,
    ledger: &MaintenanceTriggerDeliveryLedger,
    startup: ReplacementMaintenanceStartup,
) -> Result<MaintenanceTriggerPage, MaintenanceTriggerDeliveryError> {
    validate_text(
        &startup.replacement_principal,
        "maintenance_trigger.principal",
    )?;
    let session = AuthenticatedMaintenanceTriggerSession::bind(
        service,
        &startup.replacement_principal,
    )?;
    handle_maintenance_trigger_replacement_pending_set(
        service,
        &session,
        ledger,
        startup.continuation.as_deref(),
        startup.mirror_recovered,
        startup.now_unix_ms,
    )
}

/// Surfaces protected safety/recovery triggers on one registered owner route.
///
/// While the evaluator is down, triggers classified `Protected` remain
/// visible to their registered Host/Kernel/Watchdog/Doctor route. The page is
/// fetched through the same authenticated replacement path as
/// [`replacement_startup_pending_set`] (live session plus mirror-recovery
/// gate), then projected: a member is listed only when its record carries
/// `Protected` routing with an owner-issued grant for `route` that validates
/// at `now_unix_ms` and binds the record's exact trigger identity and
/// operation hash. Ordinary triggers keep their existing policy owner and are
/// withheld from this protected projection without widening ordinary
/// authority. One trigger identity is listed at most once, so duplicated
/// delivery cannot authorize duplicated containment.
///
/// # Errors
///
/// Returns [`MaintenanceTriggerDeliveryError`] for the same refusals as
/// [`replacement_startup_pending_set`].
pub fn protected_route_pending_set(
    service: &KernelService,
    owner: &AuthenticatedMaintenanceTriggerSession,
    ledger: &MaintenanceTriggerDeliveryLedger,
    route: MaintenanceTriggerRoute,
    grants: &[MaintenanceTriggerRouteGrant],
    continuation: Option<&str>,
    mirror_recovered: bool,
    now_unix_ms: u64,
) -> Result<MaintenanceTriggerPage, MaintenanceTriggerDeliveryError> {
    let page = handle_maintenance_trigger_replacement_pending_set(
        service,
        owner,
        ledger,
        continuation,
        mirror_recovered,
        now_unix_ms,
    )?;
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    let mut members = Vec::new();
    for summary in &page.members {
        if !seen.insert(summary.trigger_id.as_str()) {
            continue;
        }
        // Members enumerate rows of this same ledger synchronously, so the
        // row lookup holds; a miss lists nothing rather than inventing state.
        let Some(row) = ledger.row(&summary.trigger_id) else {
            continue;
        };
        if row.record.routing_class != MaintenanceTriggerRoutingClass::Protected {
            continue;
        }
        // The record grant was bound at intake; the route owner must still
        // present that same owner-issued classification for this trigger on
        // this route, unexpired at observation time.
        let classified = row.record.route_grant.as_ref().is_some_and(|grant| {
            grant.route == route
                && grant.validate_at(now_unix_ms).is_ok()
                && grant.binds(&row.record.trigger_id, &row.record.operation_hash)
                && grants.iter().any(|owner_grant| {
                    owner_grant.route == route
                        && owner_grant.owner_id == grant.owner_id
                        && owner_grant.key_id == grant.key_id
                        && owner_grant.grant_digest == grant.grant_digest
                        && owner_grant.binds(
                            &row.record.trigger_id,
                            &row.record.operation_hash,
                        )
                })
        });
        if !classified {
            continue;
        }
        members.push(summary.clone());
    }
    let mut gaps = page.gaps.clone();
    if members.is_empty() && gaps.is_empty() {
        gaps.push(MaintenanceTriggerGap {
            gap_id: match continuation {
                Some(cursor) => format!("protected-route:{route:?}:{cursor}:no-listed"),
                None => format!("protected-route:{route:?}:start:no-listed"),
            },
            trigger_id: None,
            kind: MaintenanceTriggerGapKind::IncompleteEnumeration,
            detail: match continuation {
                Some(cursor) => format!(
                    "no protected triggers for route {route:?} listed past continuation {cursor}; not a certified-complete set"
                ),
                None => format!(
                    "no protected triggers for route {route:?} listed from the start; not a certified-complete set"
                ),
            },
            recorded_at_unix_ms: now_unix_ms,
        });
    }
    let protected = MaintenanceTriggerPage {
        wire_id: MAINTENANCE_TRIGGER_PAGE_WIRE_ID.to_owned(),
        wire_version: MAINTENANCE_TRIGGER_PAGE_WIRE_VERSION,
        members,
        continuation: page.continuation.clone(),
        has_more: page.has_more,
        gaps,
    };
    protected.validate()?;
    Ok(protected)
}
