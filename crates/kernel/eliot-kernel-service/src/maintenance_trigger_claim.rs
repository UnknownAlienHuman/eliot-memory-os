//! Fenced bounded claim and replay caller seam (issue #1694 W3).
//!
//! The Kernel-owned delivery ledger
//! ([`MaintenanceTriggerDeliveryLedger`](crate::MaintenanceTriggerDeliveryLedger))
//! already fixes the W3 domain: finite claims bound to the current compatible
//! daemon generation/session, trigger revision, and delivery identity, with
//! exact-retry deduplication, competing-claim refusal, bounded pending pages
//! with stable continuation and explicit gaps, same-identity timeout release,
//! consumer revocation, and crash replay by record or by committed receipt.
//! This module is the caller side of that seam: it binds one
//! [`AuthenticatedMaintenanceTriggerSession`](crate::AuthenticatedMaintenanceTriggerSession)
//! from live Kernel authority and threads it together with the ledger
//! reference, so the daemon front-door has one closed entry per W3 operation
//! and can never present a claim, page cursor, revocation, or replay against
//! stale authority.
//!
//! What this module adds over the ledger seams is composition with branching:
//!
//! ```text
//! claim_trigger_for_daemon          — bind + finite fenced claim
//! enumerate_pending_for_reconnect   — bind + bounded page, cursor resumes,
//!                                     never a guessed complete-empty set
//! redeliver_after_timeout           — release the timed-out claim under the
//!                                     same identity, then either re-issue one
//!                                     fresh finite claim or, when a decision
//!                                     is already committed, return its receipt
//!                                     so the owner acknowledges without
//!                                     repeating the downstream effect
//! revoke_consumer_and_surface_pending — revoke the old consumer authority,
//!                                     then surface the mirror-gated bounded
//!                                     pending set to the replacement
//! recover_trigger_for_replacement   — route by disposition: replay the same
//!                                     record before commit, reuse the same
//!                                     receipt after commit, refuse settled
//!                                     rows instead of minting fresh claims
//! ```
//!
//! I14.22 keeps the trigger durable while the evaluator is unavailable and
//! surfaces it on startup; I14.24 (`eliotd` crash row: "Kernel revokes daemon
//! epoch ... compatible daemon generation; rebuild hot mirrors") fixes the
//! revoke-then-reclaim order this module performs; I5.2 keeps every staged
//! payload opaque (this ledger indexes delivery metadata only, never semantic
//! meaning); I1.8 keeps the call path governed (live authority is re-proved
//! on every entry, and old-generation responses fail after revocation).
//!
//! The ledger rows themselves persist through the store owner via
//! [`MaintenanceTriggerDeliveryLedger::durable_rows`] /
//! [`MaintenanceTriggerDeliveryLedger::restore_rows`](crate::MaintenanceTriggerDeliveryLedger);
//! this module holds no rows and runs no poller. The daemon-facing transport
//! route that calls these entries lives with the front-door owner (STITCH:
//! exact placement is reported by the W3 delivery, not implemented here).

use eliot_protocol::{
    MaintenanceTriggerClaim, MaintenanceTriggerDecisionReceipt, MaintenanceTriggerDisposition,
    MaintenanceTriggerPage, MaintenanceTriggerRecord, MaintenanceTriggerRevocation, ProtocolError,
};

use crate::{
    AuthenticatedMaintenanceTriggerSession, KernelService, MaintenanceTriggerClaimRequest,
    MaintenanceTriggerDeliveryError, MaintenanceTriggerDeliveryLedger,
    handle_maintenance_trigger_claim, handle_maintenance_trigger_pending_page,
    handle_maintenance_trigger_release_expired, handle_maintenance_trigger_replacement_pending_set,
    handle_maintenance_trigger_revocation, recover_maintenance_trigger_commit,
    replay_maintenance_trigger_after_crash,
};

/// Owner-mediated outcome of reclaiming one timed-out claim.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MaintenanceTriggerRedeliveryOutcome {
    /// The expired claim was released and one fresh finite claim was issued
    /// under the same trigger identity and revision.
    Reclaimed(MaintenanceTriggerClaim),
    /// A decision was already committed before the timeout: the row moved to
    /// `Reconciling` with its receipt preserved. The owner must acknowledge
    /// this exact receipt without another job, recommendation, or wake —
    /// never repeat the uncertain downstream effect.
    ReconcileByReceipt(MaintenanceTriggerDecisionReceipt),
}

/// Replacement-generation recovery route for one retained trigger.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MaintenanceTriggerRecoveryRoute {
    /// No decision is committed: re-present this exact retained record to the
    /// evaluator under the same identity. Never mint a new trigger.
    ReplayRecord(Box<MaintenanceTriggerRecord>),
    /// A decision is committed but unacknowledged: acknowledge this exact
    /// receipt without another job, recommendation, or wake.
    AcknowledgeReceipt(Box<MaintenanceTriggerDecisionReceipt>),
}

/// Binds one maintenance-trigger session from live Kernel authority.
///
/// The principal reference comes from the authenticated composition boundary,
/// never from a request DTO; a fenced generation, a non-ready service, or a
/// stale epoch/generation fails closed before any ledger transition.
fn bind_session(
    service: &KernelService,
    principal_ref: &str,
) -> Result<AuthenticatedMaintenanceTriggerSession, MaintenanceTriggerDeliveryError> {
    AuthenticatedMaintenanceTriggerSession::bind(service, principal_ref)
        .map_err(MaintenanceTriggerDeliveryError::Service)
}

/// Issues one finite fenced claim for the calling daemon generation.
///
/// Binds the session from live authority, then issues the claim bound to the
/// current compatible daemon generation/session, trigger revision, and
/// delivery identity. An exact retry returns the live claim; a concurrent
/// claim under another identity is refused with `ClaimConflict`; an
/// old-generation request fails at the fence check before any transition.
pub fn claim_trigger_for_daemon(
    service: &KernelService,
    principal_ref: &str,
    ledger: &mut MaintenanceTriggerDeliveryLedger,
    request: MaintenanceTriggerClaimRequest,
) -> Result<MaintenanceTriggerClaim, MaintenanceTriggerDeliveryError> {
    let session = bind_session(service, principal_ref)?;
    let claim = handle_maintenance_trigger_claim(service, &session, ledger, request)?;
    claim.validate()?;
    Ok(claim)
}

/// Enumerates one bounded pending page for a reconnecting consumer.
///
/// Binds the session from live authority, then lists the unresolved set in
/// trigger-identity order past `continuation`. An unknown continuation and an
/// empty listing both close with an explicit `IncompleteEnumeration` gap: a
/// reconnect resumes from its cursor and never resets progress to a guessed
/// complete-empty set.
pub fn enumerate_pending_for_reconnect(
    service: &KernelService,
    principal_ref: &str,
    ledger: &MaintenanceTriggerDeliveryLedger,
    continuation: Option<&str>,
    now_unix_ms: u64,
) -> Result<MaintenanceTriggerPage, MaintenanceTriggerDeliveryError> {
    let session = bind_session(service, principal_ref)?;
    let page = handle_maintenance_trigger_pending_page(
        service,
        &session,
        ledger,
        continuation,
        now_unix_ms,
    )?;
    page.validate()?;
    Ok(page)
}

/// Reclaims one timed-out claim through owner-mediated redelivery.
///
/// Releases the expired claim under the same trigger identity — a `Claimed`
/// row returns to `Pending`, a `DecisionRecorded` row moves to `Reconciling`
/// with its committed receipt preserved — then either re-issues one fresh
/// finite claim from the presented request or, when a decision is already
/// committed, returns its receipt for acknowledgement. A timeout never mints
/// a new trigger ID and never authorizes repeating an uncertain effect. The
/// presented request must carry a fresh finite deadline: a stale deadline
/// fails at issuance and the row stays open under its existing disposition.
pub fn redeliver_after_timeout(
    service: &KernelService,
    principal_ref: &str,
    ledger: &mut MaintenanceTriggerDeliveryLedger,
    request: MaintenanceTriggerClaimRequest,
    now_unix_ms: u64,
) -> Result<MaintenanceTriggerRedeliveryOutcome, MaintenanceTriggerDeliveryError> {
    let session = bind_session(service, principal_ref)?;
    let trigger_id = request.trigger_id.clone();
    handle_maintenance_trigger_release_expired(
        service,
        &session,
        ledger,
        &trigger_id,
        now_unix_ms,
    )?;
    let (disposition, has_receipt) = {
        let row = ledger
            .row(&trigger_id)
            .ok_or(MaintenanceTriggerDeliveryError::UnknownTrigger)?;
        (row.disposition, row.decision_receipt.is_some())
    };
    match (disposition, has_receipt) {
        (
            MaintenanceTriggerDisposition::Pending | MaintenanceTriggerDisposition::Reconciling,
            false,
        ) => {
            let claim = handle_maintenance_trigger_claim(service, &session, ledger, request)?;
            claim.validate()?;
            Ok(MaintenanceTriggerRedeliveryOutcome::Reclaimed(claim))
        }
        (
            MaintenanceTriggerDisposition::Pending
            | MaintenanceTriggerDisposition::Reconciling
            | MaintenanceTriggerDisposition::DecisionRecorded,
            _,
        ) => {
            let receipt =
                recover_maintenance_trigger_commit(service, &session, ledger, &trigger_id)?;
            Ok(MaintenanceTriggerRedeliveryOutcome::ReconcileByReceipt(
                receipt,
            ))
        }
        (
            MaintenanceTriggerDisposition::Claimed
            | MaintenanceTriggerDisposition::Acknowledged
            | MaintenanceTriggerDisposition::Expired
            | MaintenanceTriggerDisposition::Superseded,
            _,
        ) => Err(ProtocolError::ReplayConflict.into()),
    }
}

/// Revokes one daemon generation/session and surfaces the pending set.
///
/// Revocation comes first: pending claims return under the same identity for
/// the replacement, committed rows move to `Reconciling` with receipts
/// preserved, and every later old-generation claim or ack fails. The bounded
/// pending set is then surfaced only after the required mirror recovery, so
/// reconciliation can never be claimed complete before the mirrors are
/// rebuilt. Ordinary pending debt acquires no runtime lease here.
pub fn revoke_consumer_and_surface_pending(
    service: &KernelService,
    principal_ref: &str,
    ledger: &mut MaintenanceTriggerDeliveryLedger,
    revocation: MaintenanceTriggerRevocation,
    continuation: Option<&str>,
    mirror_recovered: bool,
    now_unix_ms: u64,
) -> Result<MaintenanceTriggerPage, MaintenanceTriggerDeliveryError> {
    let session = bind_session(service, principal_ref)?;
    handle_maintenance_trigger_revocation(service, &session, ledger, revocation)?;
    let page = handle_maintenance_trigger_replacement_pending_set(
        service,
        &session,
        ledger,
        continuation,
        mirror_recovered,
        now_unix_ms,
    )?;
    page.validate()?;
    Ok(page)
}

/// Routes one retained trigger to its replacement-generation recovery.
///
/// Open rows (`Pending`, `Claimed`, `Reconciling`) replay the same retained
/// record; a committed row reuses the same decision receipt; settled rows
/// (`Acknowledged`, `Expired`, `Superseded`) refuse with a replay conflict so
/// the replacement reconciles through the stored outcome instead of minting
/// a fresh claim. Receipt absence during an outage stays open: only rows with
/// a recorded receipt take the receipt route.
pub fn recover_trigger_for_replacement(
    service: &KernelService,
    principal_ref: &str,
    ledger: &MaintenanceTriggerDeliveryLedger,
    trigger_id: &str,
) -> Result<MaintenanceTriggerRecoveryRoute, MaintenanceTriggerDeliveryError> {
    let session = bind_session(service, principal_ref)?;
    let (disposition, has_receipt) = {
        let row = ledger
            .row(trigger_id)
            .ok_or(MaintenanceTriggerDeliveryError::UnknownTrigger)?;
        (row.disposition, row.decision_receipt.is_some())
    };
    match (disposition, has_receipt) {
        (
            MaintenanceTriggerDisposition::Pending
            | MaintenanceTriggerDisposition::Claimed
            | MaintenanceTriggerDisposition::Reconciling,
            false,
        ) => {
            let record =
                replay_maintenance_trigger_after_crash(service, &session, ledger, trigger_id)?;
            Ok(MaintenanceTriggerRecoveryRoute::ReplayRecord(Box::new(
                record,
            )))
        }
        (
            MaintenanceTriggerDisposition::Pending
            | MaintenanceTriggerDisposition::Claimed
            | MaintenanceTriggerDisposition::Reconciling
            | MaintenanceTriggerDisposition::DecisionRecorded,
            _,
        ) => {
            let receipt =
                recover_maintenance_trigger_commit(service, &session, ledger, trigger_id)?;
            Ok(MaintenanceTriggerRecoveryRoute::AcknowledgeReceipt(
                Box::new(receipt),
            ))
        }
        (
            MaintenanceTriggerDisposition::Acknowledged
            | MaintenanceTriggerDisposition::Expired
            | MaintenanceTriggerDisposition::Superseded,
            _,
        ) => Err(ProtocolError::ReplayConflict.into()),
    }
}
