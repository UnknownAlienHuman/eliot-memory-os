//! Kernel-owned retained maintenance-trigger delivery authority (issue #1694).
//!
//! This module is the runtime side of the provider-neutral wire family in
//! `eliot_protocol::maintenance_trigger` (I14.22: "if the evaluator is
//! unavailable, the relevant trigger remains durable and is surfaced on the
//! next startup"). It owns intake-before-ack admission, fenced bounded claim
//! issuance, bounded pending enumeration, commit-before-ack decision and
//! acknowledgement validation, crash-recovery replay, consumer revocation,
//! and explicit expiry/damage/retention handling for retained triggers.
//!
//! Durability boundary: this module is pure domain logic over durable rows,
//! following the `versioned_artifact` precedent in `eliot-ors`. The retained
//! [`MaintenanceTriggerRecord`] bytes themselves are staged through the ORS
//! owner as a [`RecoveryPayloadEnvelope`](eliot_ors::RecoveryPayloadEnvelope);
//! this ledger carries only operational delivery metadata (identity, hashes,
//! revision, disposition, claim, decision receipt, revocations, terminal
//! dispositions, gap records) and exposes it through
//! [`MaintenanceTriggerDeliveryLedger::durable_rows`] /
//! [`MaintenanceTriggerDeliveryLedger::restore_rows`] so the store owner can
//! write and read back the same rows across a restart. It never invents
//! authority, receipts, or evidence: every transition is checked by the
//! existing protocol validators (`validate_for`, `authorize_for`,
//! `matches_trigger`, `validate_for_claim`, `validate_advance`), and the
//! Governor-owned evaluator (#1688) plus the policy owner (#1692) keep
//! interpretation and mode/route/session checks. The daemon submit path
//! (Governor `PreparedTransition` into the named Store transaction) and the
//! Kernel front-door/daemon session binding call this ledger; they are not
//! reimplemented here.
//!
//! Source-to-ack mapping (I14.22, I14.24 daemon-crash row, I5.2 opaque ORS
//! payload, I1.8 governed writes):
//!
//! ```text
//! admit_intake → Pending → issue_claim → Claimed → record_decision
//! → DecisionRecorded → acknowledge → Acknowledged (sink)
//! claim timeout → Pending (same identity) · ambiguous commit → Reconciling
//! → Claimed | DecisionRecorded · expiry/supersession → Expired | Superseded
//! (sinks, identity and evidence preserved)
//! ```

use std::collections::BTreeMap;

use eliot_contracts::StateFence;
use eliot_protocol::{
    MAINTENANCE_TRIGGER_CLAIM_WIRE_ID, MAINTENANCE_TRIGGER_CLAIM_WIRE_VERSION,
    MAINTENANCE_TRIGGER_INTAKE_RECEIPT_WIRE_ID, MAINTENANCE_TRIGGER_INTAKE_RECEIPT_WIRE_VERSION,
    MAINTENANCE_TRIGGER_PAGE_WIRE_ID, MAINTENANCE_TRIGGER_PAGE_WIRE_VERSION,
    MAINTENANCE_TRIGGER_TERMINAL_DISPOSITION_WIRE_ID,
    MAINTENANCE_TRIGGER_TERMINAL_DISPOSITION_WIRE_VERSION, MAX_MAINTENANCE_TRIGGER_PAGE_GAPS,
    MAX_MAINTENANCE_TRIGGER_PAGE_MEMBERS, MaintenanceTriggerAck, MaintenanceTriggerClaim,
    MaintenanceTriggerDecisionReceipt, MaintenanceTriggerDisposition, MaintenanceTriggerGap,
    MaintenanceTriggerGapKind, MaintenanceTriggerIntakeOutcome, MaintenanceTriggerIntakeReceipt,
    MaintenanceTriggerPage, MaintenanceTriggerPendingSummary, MaintenanceTriggerRecord,
    MaintenanceTriggerRevocation, MaintenanceTriggerTerminalDisposition,
    MaintenanceTriggerTerminalKind, ProtocolError,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Upper bound on one finite claim lease.
///
/// A claim must expire while a replacement generation can still reclaim the
/// trigger promptly after daemon loss (I14.24: "Kernel revokes daemon epoch",
/// "compatible daemon generation; rebuild hot mirrors"), yet leave the daemon
/// room to resolve policy, evaluate, and commit one decision. Fifteen minutes
/// is that operator-chosen finite bound; timeout permits owner-mediated
/// redelivery under the same trigger identity, never a new trigger ID.
pub const MAX_MAINTENANCE_TRIGGER_CLAIM_LEASE_MS: u64 = 15 * 60 * 1_000;

/// Closed claim-issuance request for one retained trigger.
///
/// Bundles the claiming consumer identity, the finite deadline, and the
/// point-of-use context so issuance stays one call with named fields.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MaintenanceTriggerClaimRequest {
    /// Stable trigger identity being claimed.
    pub trigger_id: String,
    /// Claiming daemon's authority fence; must match the current generation.
    pub daemon_fence: StateFence,
    /// Claiming daemon's session identity within its generation.
    pub daemon_session: String,
    /// Stable delivery identity for this claim epoch.
    pub delivery_id: String,
    /// Latest time at which this claim authorizes delivery.
    pub claim_deadline_unix_ms: u64,
    /// Current Kernel fence the claim is issued under.
    pub current_fence: StateFence,
    /// Issuance time as Unix milliseconds.
    pub now_unix_ms: u64,
}

/// Delivery error for one retained-trigger transition.
///
/// Validation failures reuse the exact [`ProtocolError`] the wire validators
/// produce, so callers see the same bounded failure the wire family names;
/// ledger-level refusals (unknown trigger, competing claim, revoked consumer,
/// stale eligibility, missing mirror recovery) are distinct variants.
#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum MaintenanceTriggerDeliveryError {
    /// The presented wire value failed protocol validation.
    #[error("maintenance trigger delivery rejected: {0}")]
    Protocol(#[from] ProtocolError),
    /// No retained trigger exists under the requested identity.
    #[error("unknown maintenance trigger")]
    UnknownTrigger,
    /// A live claim under another delivery identity already holds the trigger.
    #[error("maintenance trigger is already claimed under another delivery identity")]
    ClaimConflict,
    /// The presenting consumer fence/session was revoked by the Kernel owner.
    #[error("maintenance trigger consumer authority was revoked")]
    RevokedConsumer,
    /// The trigger is past its applicability window; record terminal expiry first.
    #[error("maintenance trigger is no longer applicable; terminal expiry is required")]
    ExpiredEligibility,
    /// Mirror recovery has not completed, so the pending set is not surfacing yet.
    #[error("mirror recovery must complete before the pending set is claimed reconciled")]
    MirrorRecoveryRequired,
}

/// Durable delivery row for one retained trigger.
///
/// The row is the ledger's unit of durable state: the retained record plus
/// the operational delivery metadata the Kernel indexes. The store owner
/// persists and restores whole rows; transitions below mutate the live row.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MaintenanceTriggerDeliveryRow {
    /// Retained canonical trigger; staged payload bytes live in ORS.
    pub record: MaintenanceTriggerRecord,
    /// Retained revision; claims and decision receipts bind this exact value.
    pub revision: u64,
    /// Current lifecycle disposition.
    pub disposition: MaintenanceTriggerDisposition,
    /// Live finite claim, present exactly while `disposition` is `Claimed`.
    pub claim: Option<MaintenanceTriggerClaim>,
    /// Committed decision receipt, present from `DecisionRecorded` onward.
    pub decision_receipt: Option<MaintenanceTriggerDecisionReceipt>,
    /// Terminal expiry/supersession record; present exactly in terminal states.
    pub terminal: Option<MaintenanceTriggerTerminalDisposition>,
    /// Visible recovery/gap records attached to this trigger.
    pub gaps: Vec<MaintenanceTriggerGap>,
}

/// Role-filtered recovery counts over the retained trigger set.
///
/// The existing recovery surface applies role filtering; this ledger reports
/// the per-disposition counts it filters.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MaintenanceTriggerRecoveryCounts {
    /// Triggers awaiting a first claim.
    pub pending: u64,
    /// Triggers held under a live finite claim.
    pub claimed: u64,
    /// Triggers with a committed decision awaiting acknowledgement.
    pub decision_recorded: u64,
    /// Triggers acknowledged with the exact decision receipt.
    pub acknowledged: u64,
    /// Triggers awaiting receipt reconciliation after an ambiguous commit.
    pub reconciling: u64,
    /// Triggers in terminal expiry with identity and evidence preserved.
    pub expired: u64,
    /// Triggers superseded by an explicitly linked successor.
    pub superseded: u64,
}

/// Kernel-owned retained-trigger delivery ledger.
///
/// Holds one durable row per admitted trigger plus the ordered revocation
/// list. Ordinary pending debt lives here as rows; it acquires no runtime
/// lease and blocks no unrelated work — scheduling stays with the
/// daemon/Kernel owners, never this ledger.
#[derive(Clone, Debug, Default)]
pub struct MaintenanceTriggerDeliveryLedger {
    rows: BTreeMap<String, MaintenanceTriggerDeliveryRow>,
    revocations: Vec<MaintenanceTriggerRevocation>,
}

impl MaintenanceTriggerDeliveryLedger {
    /// Creates an empty delivery ledger.
    #[must_use]
    pub fn new() -> Self {
        Self {
            rows: BTreeMap::new(),
            revocations: Vec::new(),
        }
    }

    /// Returns the durable rows in stable trigger-identity order.
    ///
    /// The store owner writes these rows back; a restart restores the same
    /// ledger through [`Self::restore_rows`]. Rows are the same delivery
    /// state, not a second trigger owner.
    #[must_use]
    pub fn durable_rows(&self) -> Vec<MaintenanceTriggerDeliveryRow> {
        self.rows.values().cloned().collect()
    }

    /// Restores the ledger from previously persisted durable rows.
    ///
    /// Every row is revalidated (record, live claim, decision receipt,
    /// terminal disposition, gaps); a damaged row fails the restore instead
    /// of entering the ledger as a guessed-complete entry.
    pub fn restore_rows(
        &mut self,
        rows: Vec<MaintenanceTriggerDeliveryRow>,
    ) -> Result<(), MaintenanceTriggerDeliveryError> {
        let mut restored = BTreeMap::new();
        for row in rows {
            row.record.validate()?;
            if row.revision == 0 {
                return Err(ProtocolError::InvalidField {
                    field: "maintenance_trigger_delivery.revision",
                    reason: "must be nonzero",
                }
                .into());
            }
            match (&row.disposition, &row.claim) {
                (MaintenanceTriggerDisposition::Claimed, Some(_))
                | (
                    MaintenanceTriggerDisposition::Pending
                    | MaintenanceTriggerDisposition::DecisionRecorded
                    | MaintenanceTriggerDisposition::Acknowledged
                    | MaintenanceTriggerDisposition::Reconciling
                    | MaintenanceTriggerDisposition::Expired
                    | MaintenanceTriggerDisposition::Superseded,
                    _,
                ) => {}
                _ => {
                    return Err(ProtocolError::InvalidField {
                        field: "maintenance_trigger_delivery.claim",
                        reason: "a live claim exists exactly while claimed",
                    }
                    .into());
                }
            }
            if let Some(receipt) = &row.decision_receipt {
                receipt.matches_trigger(&row.record)?;
            }
            if let Some(terminal) = &row.terminal {
                terminal.validate()?;
            }
            for gap in &row.gaps {
                gap.validate()?;
            }
            if restored
                .insert(row.record.trigger_id.clone(), row)
                .is_some()
            {
                return Err(ProtocolError::ReplayConflict.into());
            }
        }
        self.rows = restored;
        Ok(())
    }

    /// Admits one retained trigger before acknowledging intake.
    ///
    /// The complete opaque input must already be staged through the ORS
    /// owner; the record carries its envelope reference and payload hash.
    /// Exact identity/hash replay returns the same staging receipt
    /// (`ReplaySame`); changed content under the same identity conflicts.
    /// Any failure returns an error and no receipt: the producer keeps its
    /// retry identity and its cursor must not advance.
    pub fn admit_intake(
        &mut self,
        record: MaintenanceTriggerRecord,
    ) -> Result<MaintenanceTriggerIntakeReceipt, MaintenanceTriggerDeliveryError> {
        record.validate()?;
        if let Some(row) = self.rows.get(&record.trigger_id) {
            if row.record.operation_hash != record.operation_hash
                || row.record.payload.envelope_reference != record.payload.envelope_reference
                || row.record.payload.payload_hash != record.payload.payload_hash
            {
                return Err(ProtocolError::ReplayConflict.into());
            }
            return Ok(Self::intake_receipt(
                &row.record,
                MaintenanceTriggerIntakeOutcome::ReplaySame,
            ));
        }
        let receipt = Self::intake_receipt(&record, MaintenanceTriggerIntakeOutcome::StagedNew);
        self.rows.insert(
            record.trigger_id.clone(),
            MaintenanceTriggerDeliveryRow {
                record,
                revision: 1,
                disposition: MaintenanceTriggerDisposition::Pending,
                claim: None,
                decision_receipt: None,
                terminal: None,
                gaps: Vec::new(),
            },
        );
        Ok(receipt)
    }

    /// Issues a finite claim bound to the current compatible daemon
    /// generation/session, trigger revision, and delivery identity.
    ///
    /// An exact retry (same revision, delivery identity, fence, session)
    /// returns the live claim without minting a competing one; a concurrent
    /// claim under another identity is refused. Expired eligibility blocks
    /// stale execution: the caller must record terminal expiry first.
    /// Claim timeout does not rename the trigger: the owner releases the
    /// expired claim back to `Pending` through [`Self::release_expired`]
    /// and reissues under the same identity.
    pub fn issue_claim(
        &mut self,
        request: MaintenanceTriggerClaimRequest,
    ) -> Result<MaintenanceTriggerClaim, MaintenanceTriggerDeliveryError> {
        let MaintenanceTriggerClaimRequest {
            trigger_id,
            daemon_fence,
            daemon_session,
            delivery_id,
            claim_deadline_unix_ms,
            current_fence,
            now_unix_ms,
        } = request;
        Self::reject_revoked(&self.revocations, &daemon_fence, &daemon_session)?;
        let row = self
            .rows
            .get_mut(&trigger_id)
            .ok_or(MaintenanceTriggerDeliveryError::UnknownTrigger)?;
        row.record
            .validate_at(now_unix_ms)
            .map_err(|_| MaintenanceTriggerDeliveryError::ExpiredEligibility)?;
        if claim_deadline_unix_ms <= now_unix_ms
            || claim_deadline_unix_ms - now_unix_ms > MAX_MAINTENANCE_TRIGGER_CLAIM_LEASE_MS
        {
            return Err(ProtocolError::InvalidField {
                field: "maintenance_trigger_claim.claim_deadline_unix_ms",
                reason: "claim must be finite and within the claim lease bound",
            }
            .into());
        }
        current_fence
            .validate()
            .map_err(ProtocolError::Foundation)?;
        if !daemon_fence
            .authority_epoch
            .is_same_authority(&current_fence.authority_epoch)
            || daemon_fence.resource_generation != current_fence.resource_generation
        {
            return Err(ProtocolError::InvalidField {
                field: "maintenance_trigger_claim.daemon_fence",
                reason: "claim generation is stale or revoked",
            }
            .into());
        }
        let candidate = MaintenanceTriggerClaim {
            wire_id: MAINTENANCE_TRIGGER_CLAIM_WIRE_ID.to_owned(),
            wire_version: MAINTENANCE_TRIGGER_CLAIM_WIRE_VERSION,
            trigger_id: row.record.trigger_id.clone(),
            revision: row.revision,
            delivery_id,
            daemon_fence,
            daemon_session,
            claim_deadline_unix_ms,
        };
        candidate.validate()?;
        if let Some(live) = row.claim.clone() {
            if live.is_exact_retry_of(&candidate) {
                return Ok(live);
            }
            return Err(MaintenanceTriggerDeliveryError::ClaimConflict);
        }
        MaintenanceTriggerDisposition::validate_advance(
            row.disposition,
            MaintenanceTriggerDisposition::Claimed,
        )?;
        candidate.authorize_for(&row.record, &current_fence, now_unix_ms)?;
        row.claim = Some(candidate.clone());
        row.disposition = MaintenanceTriggerDisposition::Claimed;
        Ok(candidate)
    }

    /// Releases an expired claim back to `Pending` under the same identity.
    ///
    /// The trigger keeps its identity and revision; redelivery needs a fresh
    /// finite claim, never a new trigger ID.
    pub fn release_expired(
        &mut self,
        trigger_id: &str,
        now_unix_ms: u64,
    ) -> Result<(), MaintenanceTriggerDeliveryError> {
        let row = self
            .rows
            .get_mut(trigger_id)
            .ok_or(MaintenanceTriggerDeliveryError::UnknownTrigger)?;
        let live = row.claim.clone().ok_or(ProtocolError::InvalidField {
            field: "maintenance_trigger_delivery.claim",
            reason: "no live claim to release",
        })?;
        if now_unix_ms < live.claim_deadline_unix_ms {
            return Err(ProtocolError::InvalidField {
                field: "maintenance_trigger_claim.claim_deadline_unix_ms",
                reason: "live claim has not timed out",
            }
            .into());
        }
        MaintenanceTriggerDisposition::validate_advance(
            row.disposition,
            MaintenanceTriggerDisposition::Pending,
        )?;
        row.claim = None;
        row.disposition = MaintenanceTriggerDisposition::Pending;
        Ok(())
    }

    /// Enumerates the unresolved set in bounded pages with stable continuation.
    ///
    /// Keys iterate in trigger-identity order; `continuation` resumes after
    /// the last returned trigger identity. An unknown continuation yields a
    /// closed page carrying an `IncompleteEnumeration` gap — a reconnect
    /// never resets progress to a guessed complete-empty set. Acknowledged
    /// and terminal rows are not pending and never appear as members.
    pub fn pending_page(
        &self,
        continuation: Option<&str>,
        now_unix_ms: u64,
    ) -> Result<MaintenanceTriggerPage, MaintenanceTriggerDeliveryError> {
        let mut started = continuation.is_none();
        if let Some(cursor) = continuation
            && !cursor.trim().is_empty()
            && cursor.chars().all(|c| !c.is_control())
            && !self.rows.contains_key(cursor)
        {
            let page = MaintenanceTriggerPage {
                wire_id: MAINTENANCE_TRIGGER_PAGE_WIRE_ID.to_owned(),
                wire_version: MAINTENANCE_TRIGGER_PAGE_WIRE_VERSION,
                members: Vec::new(),
                continuation: None,
                has_more: false,
                gaps: vec![MaintenanceTriggerGap {
                    gap_id: format!("page:{cursor}:incomplete-enumeration"),
                    trigger_id: None,
                    kind: MaintenanceTriggerGapKind::IncompleteEnumeration,
                    detail: format!("unknown continuation {cursor}; resume from empty"),
                    recorded_at_unix_ms: now_unix_ms,
                }],
            };
            page.validate()?;
            return Ok(page);
        }
        let mut members = Vec::new();
        let mut gaps = Vec::new();
        let mut last_listed: Option<String> = None;
        let mut more = false;
        for (identity, row) in &self.rows {
            if !started {
                if Some(identity.as_str()) == continuation {
                    started = true;
                }
                continue;
            }
            match row.disposition {
                MaintenanceTriggerDisposition::Pending
                | MaintenanceTriggerDisposition::Claimed
                | MaintenanceTriggerDisposition::DecisionRecorded
                | MaintenanceTriggerDisposition::Reconciling => {
                    if members.len() >= MAX_MAINTENANCE_TRIGGER_PAGE_MEMBERS {
                        more = true;
                        break;
                    }
                    members.push(MaintenanceTriggerPendingSummary {
                        trigger_id: row.record.trigger_id.clone(),
                        operation_hash: row.record.operation_hash.clone(),
                        revision: row.revision,
                        disposition: row.disposition,
                        applicable_until_unix_ms: row.record.applicable_until_unix_ms,
                    });
                    last_listed = Some(identity.clone());
                    if gaps.len() + row.gaps.len() <= MAX_MAINTENANCE_TRIGGER_PAGE_GAPS {
                        gaps.extend(row.gaps.iter().cloned());
                    }
                }
                MaintenanceTriggerDisposition::Acknowledged
                | MaintenanceTriggerDisposition::Expired
                | MaintenanceTriggerDisposition::Superseded => {}
            }
        }
        // `more` fires only on an unresolved row that was not listed, so a
        // further page always follows under the last listed identity.
        let page = MaintenanceTriggerPage {
            wire_id: MAINTENANCE_TRIGGER_PAGE_WIRE_ID.to_owned(),
            wire_version: MAINTENANCE_TRIGGER_PAGE_WIRE_VERSION,
            members,
            continuation: if more { last_listed } else { None },
            has_more: more,
            gaps,
        };
        page.validate()?;
        Ok(page)
    }

    /// Commits the daemon's decision before any delivery acknowledgement.
    ///
    /// The receipt must content-match the retained trigger (identity, hash,
    /// scope) and bind this row's revision plus evaluation/policy revisions
    /// and at least one durable intent reference. A decision plus a durable
    /// downstream intent is distinct from an executed job: this ledger
    /// records the commitment, never execution. Replaying the identical
    /// receipt reuses it; a different receipt while one is recorded is a
    /// competing decision and is refused.
    pub fn record_decision(
        &mut self,
        trigger_id: &str,
        receipt: MaintenanceTriggerDecisionReceipt,
    ) -> Result<(), MaintenanceTriggerDeliveryError> {
        let row = self
            .rows
            .get_mut(trigger_id)
            .ok_or(MaintenanceTriggerDeliveryError::UnknownTrigger)?;
        receipt.matches_trigger(&row.record)?;
        if receipt.revision != row.revision {
            return Err(ProtocolError::ReplayConflict.into());
        }
        if let Some(stored) = &row.decision_receipt {
            if *stored == receipt {
                return Ok(());
            }
            return Err(ProtocolError::ReplayConflict.into());
        }
        MaintenanceTriggerDisposition::validate_advance(
            row.disposition,
            MaintenanceTriggerDisposition::DecisionRecorded,
        )?;
        row.decision_receipt = Some(receipt);
        row.disposition = MaintenanceTriggerDisposition::DecisionRecorded;
        Ok(())
    }

    /// Acknowledges delivery against the exact committed decision receipt.
    ///
    /// The ack must echo the live claim's delivery identity, fence, and
    /// session exactly, the claim must still authorize under the current
    /// generation, and the embedded receipt must equal the recorded
    /// commitment byte for byte. An arbitrary receipt ID or transport `Ok`
    /// cannot complete delivery, and a stale consumer cannot ack after
    /// revocation. Expired eligibility blocks the ack; terminal expiry must
    /// be recorded instead.
    pub fn acknowledge(
        &mut self,
        ack: &MaintenanceTriggerAck,
        current_fence: &StateFence,
        now_unix_ms: u64,
    ) -> Result<(), MaintenanceTriggerDeliveryError> {
        Self::reject_revoked(&self.revocations, &ack.daemon_fence, &ack.daemon_session)?;
        let row = self
            .rows
            .get_mut(&ack.trigger_id)
            .ok_or(MaintenanceTriggerDeliveryError::UnknownTrigger)?;
        row.record
            .validate_at(now_unix_ms)
            .map_err(|_| MaintenanceTriggerDeliveryError::ExpiredEligibility)?;
        let claim = row.claim.clone().ok_or(ProtocolError::InvalidField {
            field: "maintenance_trigger_delivery.claim",
            reason: "no live claim answers this acknowledgement",
        })?;
        ack.validate_for_claim(&claim, &row.record, current_fence, now_unix_ms)?;
        let stored = row
            .decision_receipt
            .as_ref()
            .ok_or(ProtocolError::InvalidField {
                field: "maintenance_trigger_delivery.decision_receipt",
                reason: "no committed decision answers this acknowledgement",
            })?;
        if *stored != ack.decision_receipt {
            return Err(ProtocolError::InvalidField {
                field: "maintenance_trigger_ack.decision_receipt",
                reason: "ack receipt differs from the committed decision",
            }
            .into());
        }
        MaintenanceTriggerDisposition::validate_advance(
            row.disposition,
            MaintenanceTriggerDisposition::Acknowledged,
        )?;
        row.disposition = MaintenanceTriggerDisposition::Acknowledged;
        row.claim = None;
        Ok(())
    }

    /// Replays the same retained trigger after a crash before decision commit.
    ///
    /// Returns the exact retained record; the caller re-presents it to the
    /// evaluator instead of minting a new trigger.
    pub fn replay_after_crash(
        &self,
        trigger_id: &str,
    ) -> Result<MaintenanceTriggerRecord, MaintenanceTriggerDeliveryError> {
        let row = self
            .rows
            .get(trigger_id)
            .ok_or(MaintenanceTriggerDeliveryError::UnknownTrigger)?;
        match row.disposition {
            MaintenanceTriggerDisposition::Pending
            | MaintenanceTriggerDisposition::Claimed
            | MaintenanceTriggerDisposition::Reconciling => Ok(row.record.clone()),
            _ => Err(ProtocolError::InvalidField {
                field: "maintenance_trigger.disposition",
                reason: "a committed or terminal trigger replays by receipt, not by trigger",
            }
            .into()),
        }
    }

    /// Reuses the existing decision receipt after commit but before ack.
    ///
    /// The caller acknowledges this exact receipt without another
    /// job, recommendation, or wake.
    pub fn recover_commit_before_ack(
        &self,
        trigger_id: &str,
    ) -> Result<MaintenanceTriggerDecisionReceipt, MaintenanceTriggerDeliveryError> {
        let row = self
            .rows
            .get(trigger_id)
            .ok_or(MaintenanceTriggerDeliveryError::UnknownTrigger)?;
        row.decision_receipt
            .clone()
            .ok_or(ProtocolError::InvalidField {
                field: "maintenance_trigger_delivery.decision_receipt",
                reason: "no committed decision to recover",
            })
            .map_err(MaintenanceTriggerDeliveryError::from)
    }

    /// Marks a lost or ambiguous commit response as reconciling.
    ///
    /// Receipt absence during an outage is not proof of non-commit: the
    /// trigger stays open, gains an `AmbiguousCommit` gap record, and must
    /// be reconciled by receipt lookup before any further effect.
    pub fn mark_ambiguous(
        &mut self,
        trigger_id: &str,
        now_unix_ms: u64,
    ) -> Result<(), MaintenanceTriggerDeliveryError> {
        let row = self
            .rows
            .get_mut(trigger_id)
            .ok_or(MaintenanceTriggerDeliveryError::UnknownTrigger)?;
        MaintenanceTriggerDisposition::validate_advance(
            row.disposition,
            MaintenanceTriggerDisposition::Reconciling,
        )?;
        row.disposition = MaintenanceTriggerDisposition::Reconciling;
        let gap = MaintenanceTriggerGap {
            gap_id: format!("{trigger_id}:ambiguous-commit:{}", row.gaps.len()),
            trigger_id: Some(trigger_id.to_owned()),
            kind: MaintenanceTriggerGapKind::AmbiguousCommit,
            detail: "commit response lost; reconcile by receipt lookup before any effect"
                .to_owned(),
            recorded_at_unix_ms: now_unix_ms,
        };
        gap.validate()?;
        row.gaps.push(gap);
        Ok(())
    }

    /// Revokes one daemon generation/session's trigger-consumer authority.
    ///
    /// Pending claims under the revoked identity are retained as `Pending`
    /// rows under the same identity and revision so the replacement
    /// generation can reclaim them; their old consumer authority is gone.
    /// Old-generation responses fail after this revocation because every
    /// claim and ack is checked against the revocation list and the current
    /// fence.
    pub fn revoke_consumer(
        &mut self,
        revocation: MaintenanceTriggerRevocation,
    ) -> Result<(), MaintenanceTriggerDeliveryError> {
        revocation.validate()?;
        for row in self.rows.values_mut() {
            let matches = row.claim.as_ref().is_some_and(|claim| {
                claim.daemon_fence == revocation.daemon_fence
                    && claim.daemon_session == revocation.daemon_session
            });
            if matches {
                MaintenanceTriggerDisposition::validate_advance(
                    row.disposition,
                    MaintenanceTriggerDisposition::Pending,
                )?;
                row.claim = None;
                row.disposition = MaintenanceTriggerDisposition::Pending;
            }
        }
        self.revocations.push(revocation);
        Ok(())
    }

    /// Surfaces the bounded pending set to a replacement generation.
    ///
    /// The caller must have completed replacement authentication and the
    /// required mirror recovery first: `mirror_recovered == false` refuses
    /// with [`MaintenanceTriggerDeliveryError::MirrorRecoveryRequired`], so
    /// maintenance reconciliation can never be claimed complete before the
    /// mirrors are rebuilt.
    pub fn replacement_pending_set(
        &self,
        continuation: Option<&str>,
        mirror_recovered: bool,
        now_unix_ms: u64,
    ) -> Result<MaintenanceTriggerPage, MaintenanceTriggerDeliveryError> {
        if !mirror_recovered {
            return Err(MaintenanceTriggerDeliveryError::MirrorRecoveryRequired);
        }
        self.pending_page(continuation, now_unix_ms)
    }

    /// Records terminal expiry for a trigger past its applicability window.
    ///
    /// Expired eligibility blocks stale execution but never deletes the
    /// unresolved trigger or its effects: the row, its record, and its
    /// evidence locators are preserved under the retention policy.
    pub fn apply_expiry(
        &mut self,
        trigger_id: &str,
        reason: &str,
        now_unix_ms: u64,
    ) -> Result<(), MaintenanceTriggerDeliveryError> {
        let row = self
            .rows
            .get_mut(trigger_id)
            .ok_or(MaintenanceTriggerDeliveryError::UnknownTrigger)?;
        if row.record.validate_at(now_unix_ms).is_ok() {
            return Err(ProtocolError::InvalidField {
                field: "applicable_until_unix_ms",
                reason: "a still-applicable trigger must not expire",
            }
            .into());
        }
        MaintenanceTriggerDisposition::validate_advance(
            row.disposition,
            MaintenanceTriggerDisposition::Expired,
        )?;
        let terminal = MaintenanceTriggerTerminalDisposition {
            wire_id: MAINTENANCE_TRIGGER_TERMINAL_DISPOSITION_WIRE_ID.to_owned(),
            wire_version: MAINTENANCE_TRIGGER_TERMINAL_DISPOSITION_WIRE_VERSION,
            trigger_id: trigger_id.to_owned(),
            operation_hash: row.record.operation_hash.clone(),
            kind: MaintenanceTriggerTerminalKind::Expired,
            successor_trigger_id: None,
            reason: reason.to_owned(),
            recorded_at_unix_ms: now_unix_ms,
        };
        terminal.validate()?;
        row.terminal = Some(terminal);
        row.claim = None;
        row.disposition = MaintenanceTriggerDisposition::Expired;
        Ok(())
    }

    /// Records supersession by an explicitly linked successor trigger.
    ///
    /// The old result is never overwritten: the successor is named, both
    /// rows stay readable, and the old row keeps its record and receipts.
    pub fn apply_supersession(
        &mut self,
        trigger_id: &str,
        successor_trigger_id: &str,
        reason: &str,
        now_unix_ms: u64,
    ) -> Result<(), MaintenanceTriggerDeliveryError> {
        if !self.rows.contains_key(successor_trigger_id) {
            return Err(MaintenanceTriggerDeliveryError::UnknownTrigger);
        }
        let row = self
            .rows
            .get_mut(trigger_id)
            .ok_or(MaintenanceTriggerDeliveryError::UnknownTrigger)?;
        MaintenanceTriggerDisposition::validate_advance(
            row.disposition,
            MaintenanceTriggerDisposition::Superseded,
        )?;
        let terminal = MaintenanceTriggerTerminalDisposition {
            wire_id: MAINTENANCE_TRIGGER_TERMINAL_DISPOSITION_WIRE_ID.to_owned(),
            wire_version: MAINTENANCE_TRIGGER_TERMINAL_DISPOSITION_WIRE_VERSION,
            trigger_id: trigger_id.to_owned(),
            operation_hash: row.record.operation_hash.clone(),
            kind: MaintenanceTriggerTerminalKind::Superseded,
            successor_trigger_id: Some(successor_trigger_id.to_owned()),
            reason: reason.to_owned(),
            recorded_at_unix_ms: now_unix_ms,
        };
        terminal.validate()?;
        row.terminal = Some(terminal);
        row.claim = None;
        row.disposition = MaintenanceTriggerDisposition::Superseded;
        Ok(())
    }

    /// Records a visible recovery gap for damage the ledger cannot repair.
    ///
    /// Missing keys, corrupt payloads, inaccessible sources, and incomplete
    /// enumeration produce this record — never a plaintext fallback and
    /// never silent deletion.
    pub fn record_gap(
        &mut self,
        trigger_id: &str,
        kind: MaintenanceTriggerGapKind,
        detail: &str,
        now_unix_ms: u64,
    ) -> Result<(), MaintenanceTriggerDeliveryError> {
        if matches!(
            kind,
            MaintenanceTriggerGapKind::IncompleteEnumeration
                | MaintenanceTriggerGapKind::AmbiguousCommit
        ) {
            return Err(ProtocolError::InvalidField {
                field: "maintenance_trigger_gap.kind",
                reason: "enumeration and commit gaps are recorded by their owning transitions",
            }
            .into());
        }
        let row = self
            .rows
            .get_mut(trigger_id)
            .ok_or(MaintenanceTriggerDeliveryError::UnknownTrigger)?;
        let gap = MaintenanceTriggerGap {
            gap_id: format!("{trigger_id}:{kind:?}:{}", row.gaps.len()),
            trigger_id: Some(trigger_id.to_owned()),
            kind,
            detail: detail.to_owned(),
            recorded_at_unix_ms: now_unix_ms,
        };
        gap.validate()?;
        row.gaps.push(gap);
        Ok(())
    }

    /// Compacts one settled row after exact ack or terminal disposition.
    ///
    /// Only the consumed live-claim binding is dropped; the record, decision
    /// receipt, terminal disposition, and gap records stay readable under
    /// the retention policy. Compaction of an unsettled row is refused.
    pub fn compact(&mut self, trigger_id: &str) -> Result<(), MaintenanceTriggerDeliveryError> {
        let row = self
            .rows
            .get_mut(trigger_id)
            .ok_or(MaintenanceTriggerDeliveryError::UnknownTrigger)?;
        match row.disposition {
            MaintenanceTriggerDisposition::Acknowledged
            | MaintenanceTriggerDisposition::Expired
            | MaintenanceTriggerDisposition::Superseded => {
                row.claim = None;
                Ok(())
            }
            _ => Err(ProtocolError::InvalidField {
                field: "maintenance_trigger.disposition",
                reason: "only acknowledged or terminal rows may compact",
            }
            .into()),
        }
    }

    /// Reports per-disposition counts for the role-filtered recovery surface.
    #[must_use]
    pub fn recovery_counts(&self) -> MaintenanceTriggerRecoveryCounts {
        let mut counts = MaintenanceTriggerRecoveryCounts::default();
        for row in self.rows.values() {
            match row.disposition {
                MaintenanceTriggerDisposition::Pending => counts.pending += 1,
                MaintenanceTriggerDisposition::Claimed => counts.claimed += 1,
                MaintenanceTriggerDisposition::DecisionRecorded => counts.decision_recorded += 1,
                MaintenanceTriggerDisposition::Acknowledged => counts.acknowledged += 1,
                MaintenanceTriggerDisposition::Reconciling => counts.reconciling += 1,
                MaintenanceTriggerDisposition::Expired => counts.expired += 1,
                MaintenanceTriggerDisposition::Superseded => counts.superseded += 1,
            }
        }
        counts
    }

    /// Returns the delivery row for one trigger identity, when retained.
    #[must_use]
    pub fn row(&self, trigger_id: &str) -> Option<&MaintenanceTriggerDeliveryRow> {
        self.rows.get(trigger_id)
    }

    fn intake_receipt(
        record: &MaintenanceTriggerRecord,
        outcome: MaintenanceTriggerIntakeOutcome,
    ) -> MaintenanceTriggerIntakeReceipt {
        MaintenanceTriggerIntakeReceipt {
            wire_id: MAINTENANCE_TRIGGER_INTAKE_RECEIPT_WIRE_ID.to_owned(),
            wire_version: MAINTENANCE_TRIGGER_INTAKE_RECEIPT_WIRE_VERSION,
            trigger_id: record.trigger_id.clone(),
            operation_hash: record.operation_hash.clone(),
            envelope_reference: record.payload.envelope_reference.clone(),
            payload_hash: record.payload.payload_hash.clone(),
            outcome,
        }
    }

    fn reject_revoked(
        revocations: &[MaintenanceTriggerRevocation],
        fence: &StateFence,
        session: &str,
    ) -> Result<(), MaintenanceTriggerDeliveryError> {
        if revocations.iter().any(|revocation| {
            revocation.daemon_fence == *fence && revocation.daemon_session == session
        }) {
            return Err(MaintenanceTriggerDeliveryError::RevokedConsumer);
        }
        Ok(())
    }
}
