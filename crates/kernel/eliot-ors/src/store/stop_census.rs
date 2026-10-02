//! Complete, read-only Store-stop obligation projection from one ORS snapshot.
//!
//! The projection is deliberately built at the ORS owner. It reads each
//! current work family in one redb read transaction, validates every retained
//! row, records exact source counts, and binds the result to the installed ORS
//! object, the requested State Fence, the existing admission revision, and a
//! content revision over the complete source rows. No row is released or
//! expired by this read.

use super::restore_journal::{
    RESTORE_JOURNAL_INTENTS, RESTORE_JOURNAL_META, RESTORE_JOURNAL_RESULTS,
};
use super::{
    ACTIVATION_LIFECYCLES, AUTHORITY_HANDOFFS, BRIDGE_EVENT_CURSORS, BRIDGE_EVENT_GAPS,
    BRIDGE_EVENT_HANDOFFS, BRIDGE_EVENT_OWNER_MAINTENANCE_CURSORS, BRIDGE_EVENT_PROJECTIONS,
    BRIDGE_EVENT_RECORDS, CAMPAIGN_SOURCE_PENDING, COLD_START_READINESS_BINDINGS,
    COLD_START_READINESS_HEADS, COLD_START_READINESS_RECORDS, CUTOVER_OWNERSHIP, DOCTOR_ATTEMPTS,
    DOCTOR_EFFECTS, DurableInboxRecord, DurableOperationalRecord, EFFECT_DELIVERY_RECORDS,
    EFFECT_OPERATION_LEASES, EFFECT_REPLAY_RECONCILIATIONS, EFFECT_REVOCATION_EVENTS,
    GENERATION_LIFECYCLES, GOVERNOR_ADMISSION_RECEIPTS, HOST_REQUEST_LOGICAL_KEYS, HOST_REQUESTS,
    KERNEL_RESTART_RECONCILIATIONS, META, NATIVE_WORKER_CLAIMS, OPERATIONAL_CURRENT,
    PROCESS_START_REPLAY, PROCESS_STREAM_RECOVERY, RECOVERY_INBOX, RECOVERY_PROBLEMS, REPLAY_ACKS,
    REPLAY_EVENTS, RESERVATIONS, RUNTIME_LEASE_CURRENT, RedbRecoveryStore, SCAN_DISCLOSURE_RECORDS,
    STORE_FAILURE_RETENTION, STORE_REBIND_REPLAY, SUPERVISION_LEASE_CURRENT,
    SUPERVISION_LEASE_STAGED, UNKNOWN_COMMIT_RECOVERY, decode, decode_named,
    read_store_object_identity, storage,
};
use crate::model::{SupervisionLeaseSnapshot, SupervisionLeaseStageReceipt};
use crate::{
    AdmissionReservationState, HostRequestRecord, KernelReconciliationItem, OperationalPhase,
    RecoveryInboxDisposition, RecoveryProblem, ReservationRecord, UnknownCommitRecord,
};
use eliot_contracts::StateFence;
use eliot_runtime_contracts::RuntimeLease;
use redb::{ReadableDatabase, ReadableTable};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Per-family counts from the complete Store-stop owner scan.
#[derive(Clone, Copy, Debug, Default, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoreStopObligationCounts {
    /// Persisted non-terminal runtime leases, independent of wall-clock expiry.
    pub runtime_leases: u64,
    /// Persisted non-terminal supervision leases, independent of wall-clock expiry.
    pub supervision_leases: u64,
    /// Supervision lease transitions staged but not committed or resolved.
    pub supervision_lease_stages: u64,
    /// Canonical commits whose outcome still requires exact receipt resolution.
    pub unknown_commits: u64,
    /// Non-terminal canonical data/maintenance write reservations.
    pub write_reservations: u64,
    /// Non-terminal #1678 admission reservations.
    pub admission_reservations: u64,
    /// Other current Store-dependent operational work.
    pub operational_work: u64,
    /// Imported recovery inbox rows awaiting owner disposition.
    pub recovery_inbox: u64,
    /// Recovery problems without a terminal receipt disposition.
    pub recovery_problems: u64,
    /// Non-terminal effect leases or leases with unresolved acknowledgement.
    pub effect_operation_leases: u64,
    /// Durable effect-replay reconciliation intents.
    pub effect_reconciliations: u64,
    /// Host requests whose durable operation state is not terminal.
    pub host_requests: u64,
    /// Process-stream records whose owning operation or coverage is unresolved.
    pub process_stream_recovery: u64,
    /// Pending Store rebind operations without their committed owner receipt.
    pub store_rebinds: u64,
    /// Unknown-outcome Store failures without a reconciling receipt.
    pub unresolved_store_failures: u64,
    /// Prepared data-disclosure writes without a committed owner receipt.
    pub prepared_scan_disclosures: u64,
    /// Cold-start readiness leases without their owner terminal receipt.
    pub cold_start_readiness_leases: u64,
    /// Agent activation tickets whose admission/result lifecycle is unresolved.
    pub activation_lifecycles: u64,
    /// Native-worker claims that have not reached their owner terminal state.
    pub native_worker_claims: u64,
    /// Campaign source-head CAS reservations without their owner transition.
    pub campaign_source_reservations: u64,
    /// Doctor repair attempts that have not reached their owner terminal state.
    pub doctor_attempts: u64,
    /// Doctor effects without a reported, owner-recorded outcome.
    pub doctor_effects: u64,
    /// Worker replay events without an APPLIED/REJECTED acknowledgement.
    pub worker_replay_events: u64,
    /// Durably staged bridge events not yet retired by their owner.
    pub bridge_event_records: u64,
    /// Durable normalized bridge projections retained with their source event.
    pub bridge_event_projections: u64,
    /// Bridge handoffs without receiver-owned terminal disposition.
    pub bridge_event_handoffs: u64,
    /// Bridge coverage gaps still held by the durable owner.
    pub bridge_event_gaps: u64,
    /// Persisted bridge repair, retirement, reconcile, and owner-sweep continuations.
    pub bridge_event_maintenance_continuations: u64,
    /// Restore-journal intents without an owner-recorded result.
    pub restore_journal_intents: u64,
    /// Process starts reserved or unresolved by exact replay identity.
    pub process_start_replays: u64,
    /// Authority handoffs without a durable consumed disposition.
    pub authority_handoffs: u64,
    /// Generation cutovers that have not reached their committed state.
    pub cutover_ownership: u64,
    /// Recorded manifest-side restart escalations, one per appended attempt.
    ///
    /// This family has no terminal disposition: a recorded refusal is preserved
    /// escalation evidence, not a settled fact, so every attempt a generation
    /// accumulated is retained until its owner removes the row. One recorded
    /// escalation is therefore enough to keep a Store stop from being reported
    /// as clean.
    pub restart_reconciliations: u64,
    /// Generation Registry rows whose recorded disposition is `Degraded` or
    /// `Quarantined`.
    ///
    /// This is the count of AFFECTED GENERATIONS, one row per
    /// `{module_id, generation}`. A recorded degradation is what blocks launch,
    /// routes and new effect operation leases for its generation, so a Store
    /// that holds one cannot report a clean stop while the row exists.
    pub degraded_generations: u64,
}

impl StoreStopObligationCounts {
    /// Returns the total blocking Store obligations, failing closed on overflow.
    pub fn total(&self) -> Result<u64, crate::OrsError> {
        [
            self.runtime_leases,
            self.supervision_leases,
            self.supervision_lease_stages,
            self.unknown_commits,
            self.write_reservations,
            self.admission_reservations,
            self.operational_work,
            self.recovery_inbox,
            self.recovery_problems,
            self.effect_operation_leases,
            self.effect_reconciliations,
            self.host_requests,
            self.process_stream_recovery,
            self.store_rebinds,
            self.unresolved_store_failures,
            self.prepared_scan_disclosures,
            self.cold_start_readiness_leases,
            self.activation_lifecycles,
            self.native_worker_claims,
            self.campaign_source_reservations,
            self.doctor_attempts,
            self.doctor_effects,
            self.worker_replay_events,
            self.bridge_event_records,
            self.bridge_event_projections,
            self.bridge_event_handoffs,
            self.bridge_event_gaps,
            self.bridge_event_maintenance_continuations,
            self.restore_journal_intents,
            self.process_start_replays,
            self.authority_handoffs,
            self.cutover_ownership,
            self.restart_reconciliations,
            self.degraded_generations,
        ]
        .into_iter()
        .try_fold(0_u64, u64::checked_add)
        .ok_or_else(|| crate::OrsError::IntegrityProblem {
            record_type: "store_stop_census",
            reason: "total obligation count overflowed its wire range".to_owned(),
        })
    }

    /// A known-zero result is available only when every included owner reports zero.
    #[must_use]
    pub fn is_zero(&self) -> bool {
        self.runtime_leases == 0
            && self.supervision_leases == 0
            && self.supervision_lease_stages == 0
            && self.unknown_commits == 0
            && self.write_reservations == 0
            && self.admission_reservations == 0
            && self.operational_work == 0
            && self.recovery_inbox == 0
            && self.recovery_problems == 0
            && self.effect_operation_leases == 0
            && self.effect_reconciliations == 0
            && self.host_requests == 0
            && self.process_stream_recovery == 0
            && self.store_rebinds == 0
            && self.unresolved_store_failures == 0
            && self.prepared_scan_disclosures == 0
            && self.cold_start_readiness_leases == 0
            && self.activation_lifecycles == 0
            && self.native_worker_claims == 0
            && self.campaign_source_reservations == 0
            && self.doctor_attempts == 0
            && self.doctor_effects == 0
            && self.worker_replay_events == 0
            && self.bridge_event_records == 0
            && self.bridge_event_projections == 0
            && self.bridge_event_handoffs == 0
            && self.bridge_event_gaps == 0
            && self.bridge_event_maintenance_continuations == 0
            && self.restore_journal_intents == 0
            && self.process_start_replays == 0
            && self.authority_handoffs == 0
            && self.cutover_ownership == 0
            && self.restart_reconciliations == 0
            && self.degraded_generations == 0
    }
}

/// Validated Store-stop owner result over one coherent ORS read snapshot.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoreStopObligationCensus {
    /// Installation identity read from this ORS object's durable metadata.
    pub installation_id: String,
    /// Durable ORS object generation read from the same metadata snapshot.
    pub store_object_generation: u64,
    /// Exact state fence selected by the Kernel admission owner.
    pub state_fence: StateFence,
    /// Exact activation identity when the ORS supervision row supplies it.
    pub activation_id: Option<String>,
    /// Activation/resource generation selected by `state_fence`.
    pub activation_generation: eliot_contracts::ResourceGeneration,
    /// Existing monotone `OPERATIONAL_CURRENT` revision for #1678 admission state.
    pub admission_revision: u64,
    /// Content revision over every row in each source family scanned here.
    pub observation_revision: String,
    /// Complete source counts. No page or connection count is used as a proxy.
    pub counts: StoreStopObligationCounts,
}

impl StoreStopObligationCensus {
    /// Validates the exact generation binding, source revisions, and count range.
    pub fn validate(&self) -> Result<(), crate::OrsError> {
        self.state_fence
            .validate()
            .map_err(eliot_store_api::StoreError::Foundation)?;
        crate::model::validate_text(&self.installation_id, "store_stop_installation_id")?;
        if self.store_object_generation == 0
            || self.activation_generation != self.state_fence.resource_generation
        {
            return Err(crate::OrsError::IntegrityProblem {
                record_type: "store_stop_census",
                reason: "Store object or activation generation binding is invalid".to_owned(),
            });
        }
        if let Some(activation_id) = &self.activation_id {
            crate::model::validate_text(activation_id, "store_stop_activation_id")?;
        }
        crate::model::validate_digest(
            &self.observation_revision,
            "store_stop_observation_revision",
        )?;
        self.counts.total()?;
        Ok(())
    }

    /// Returns whether every Store-dependent obligation family is authoritatively empty.
    #[must_use]
    pub fn is_known_zero(&self) -> bool {
        self.counts.is_zero()
    }
}

impl RedbRecoveryStore {
    /// Reads the complete Store-stop denominator from one ORS read snapshot.
    ///
    /// Every non-terminal runtime lease, canonical write reservation, admission
    /// reservation, current Store-dependent operation, imported inbox item,
    /// unresolved recovery problem, and unresolved effect record is retained in
    /// the count until its owner writes a legal terminal disposition. Expiry is
    /// never synthesized from the local clock. `activation_id` is the current
    /// owner-bound activation when available; the State Fence and resource
    /// generation are always exact.
    pub fn load_store_stop_obligation_census(
        &self,
        state_fence: &StateFence,
        activation_id: Option<&str>,
    ) -> Result<StoreStopObligationCensus, crate::OrsError> {
        state_fence
            .validate()
            .map_err(eliot_store_api::StoreError::Foundation)?;
        if let Some(activation_id) = activation_id {
            crate::model::validate_text(activation_id, "store_stop_activation_id")?;
        }
        let read = self.database.begin_read().map_err(storage)?;
        census_in_read(&read, state_fence, activation_id)
    }
}

pub(super) fn census_in_read(
    read: &redb::ReadTransaction,
    state_fence: &StateFence,
    activation_id: Option<&str>,
) -> Result<StoreStopObligationCensus, crate::OrsError> {
    let identity = {
        let meta = read.open_table(META).map_err(storage)?;
        read_store_object_identity(&meta)?.installed_identity()?
    };
    let admission_revision = RedbRecoveryStore::recovery_inventory_snapshot_from_read(read)?
        .operational_current_revision;
    let mut builder = CensusBuilder::new();

    observe_runtime_lease_current(read, &mut builder)?;

    observe_supervision_lease_current(read, &mut builder)?;

    observe_supervision_lease_staged(read, &mut builder)?;

    // Reservation identity indexes and scope terminal receipts are part of
    // the same owner snapshot: dangling or missing primary rows must not
    // disappear behind a zero count.
    super::validate_write_reservation_inventory_in_read(read, &mut |family, key, value| {
        builder.observe(family, key, value);
    })?;
    observe_reservations(read, &mut builder)?;

    observe_unknown_commit_recovery(read, &mut builder)?;

    observe_operational_current(read, &mut builder)?;

    observe_recovery_inbox(read, &mut builder)?;

    observe_recovery_problems(read, &mut builder)?;

    observe_effect_operation_leases(read, &mut builder)?;

    observe_effect_replay_reconciliations(read, &mut builder)?;

    observe_store_rebind_replay(read, &mut builder)?;

    observe_store_failure_retention(read, &mut builder)?;

    observe_scan_disclosure_records(read, &mut builder)?;

    observe_cold_start_readiness(read, &identity, &mut builder)?;

    observe_activation_lifecycles(read, &mut builder)?;

    observe_native_worker_claims(read, &mut builder)?;

    observe_host_requests(read, &mut builder)?;

    // The logical index is a second durable representation of HostRequest
    // ownership. A missing operation row behind a live link would otherwise
    // disappear from the request denominator and could make a corrupt Store
    // appear empty. Validate all index entries in this same read snapshot.
    observe_host_request_logical_keys(read, &mut builder)?;

    observe_process_stream_recovery(read, &mut builder)?;

    observe_campaign_source_pending(read, &mut builder)?;

    observe_process_start_replay(read, &mut builder)?;

    observe_authority_handoffs(read, &mut builder)?;

    observe_cutover_ownership(read, &mut builder)?;

    // #1884 (W1.1, W1.5, AUD5): the five families this delivery adds around the
    // admitted manifest are read in this same snapshot, so a row under any of
    // them that does not belong to its own decoded identity fails the census
    // closed instead of being invisible to the revision. Two of them are not
    // merely inventoried: a recorded manifest-side restart escalation and a
    // recorded generation degradation are live obligations, and both are counted,
    // so `total()` and `is_zero()` cannot report a clean Store stop while either
    // exists.
    observe_governor_admission_receipts(read, &mut builder)?;

    observe_generation_lifecycles(read, &mut builder)?;

    observe_effect_revocation_events(read, &mut builder)?;

    observe_effect_delivery_records(read, &mut builder)?;

    observe_kernel_restart_reconciliations(read, &mut builder)?;

    observe_doctor_attempts(read, &mut builder)?;

    observe_doctor_effects(read, &mut builder)?;

    observe_replay_events(read, &mut builder)?;

    observe_bridge_event_records(read, &mut builder)?;

    observe_bridge_event_projections(read, &mut builder)?;

    observe_bridge_event_handoffs(read, &mut builder)?;

    observe_bridge_event_gaps(read, &mut builder)?;

    observe_bridge_event_maintenance(read, &mut builder)?;

    builder.counts.restore_journal_intents =
        super::RedbRecoveryStore::unresolved_intents_for_store_stop_in(read)?;
    observe_restore_journal_intents(read, &mut builder)?;
    observe_restore_journal_results(read, &mut builder)?;
    observe_restore_journal_meta(read, &mut builder)?;

    Ok(StoreStopObligationCensus {
        installation_id: identity.installation_id().to_owned(),
        store_object_generation: identity.ors_generation(),
        state_fence: state_fence.clone(),
        activation_id: activation_id.map(str::to_owned),
        activation_generation: state_fence.resource_generation,
        admission_revision,
        observation_revision: builder.revision,
        counts: builder.counts,
    })
}

fn observe_runtime_lease_current(
    read: &redb::ReadTransaction,
    builder: &mut CensusBuilder,
) -> Result<(), crate::OrsError> {
    let leases = read.open_table(RUNTIME_LEASE_CURRENT).map_err(storage)?;
    for row in leases.iter().map_err(storage)? {
        let (key, value) = row.map_err(storage)?;
        let lease: RuntimeLease = decode(value.value())?;
        if key.value() != lease.lease_id {
            return Err(integrity(
                "runtime_lease_current",
                "current key does not match lease identity",
            ));
        }
        builder.observe("runtime_leases", key.value(), value.value());
        if !runtime_lease_is_terminal(lease.state) {
            builder.counts.runtime_leases = increment(builder.counts.runtime_leases)?;
        }
    }
    Ok(())
}

fn observe_supervision_lease_current(
    read: &redb::ReadTransaction,
    builder: &mut CensusBuilder,
) -> Result<(), crate::OrsError> {
    let leases = read
        .open_table(SUPERVISION_LEASE_CURRENT)
        .map_err(storage)?;
    for row in leases.iter().map_err(storage)? {
        let (key, value) = row.map_err(storage)?;
        let snapshot: SupervisionLeaseSnapshot =
            decode_named(value.value(), "supervision_lease_current")?;
        snapshot.validate()?;
        if key.value() != snapshot.record.lease_id.as_str() {
            return Err(integrity(
                "supervision_lease_current",
                "current key does not match lease identity",
            ));
        }
        builder.observe("supervision_leases", key.value(), value.value());
        if !runtime_lease_is_terminal(snapshot.record.state) {
            builder.counts.supervision_leases = increment(builder.counts.supervision_leases)?;
        }
    }
    Ok(())
}

fn observe_supervision_lease_staged(
    read: &redb::ReadTransaction,
    builder: &mut CensusBuilder,
) -> Result<(), crate::OrsError> {
    let staged = read.open_table(SUPERVISION_LEASE_STAGED).map_err(storage)?;
    for row in staged.iter().map_err(storage)? {
        let (key, value) = row.map_err(storage)?;
        let stage: SupervisionLeaseStageReceipt =
            decode_named(value.value(), "supervision_lease_staged")?;
        stage.validate()?;
        if key.value() != stage.ticket.lease_id.as_str() {
            return Err(integrity(
                "supervision_lease_staged",
                "staged key does not match lease identity",
            ));
        }
        builder.observe("supervision_lease_stages", key.value(), value.value());
        builder.counts.supervision_lease_stages =
            increment(builder.counts.supervision_lease_stages)?;
    }
    Ok(())
}

fn observe_reservations(
    read: &redb::ReadTransaction,
    builder: &mut CensusBuilder,
) -> Result<(), crate::OrsError> {
    let reservations = read.open_table(RESERVATIONS).map_err(storage)?;
    for row in reservations.iter().map_err(storage)? {
        let (key, value) = row.map_err(storage)?;
        let record: ReservationRecord = decode(value.value())?;
        if key.value() != record.token.reservation_id.as_str() {
            return Err(integrity(
                "store_stop_reservations",
                "reservation key does not match its owner identity",
            ));
        }
        builder.observe("write_reservations", key.value(), value.value());
        if !record.state.is_terminal() {
            builder.counts.write_reservations = increment(builder.counts.write_reservations)?;
        }
    }
    Ok(())
}

fn observe_unknown_commit_recovery(
    read: &redb::ReadTransaction,
    builder: &mut CensusBuilder,
) -> Result<(), crate::OrsError> {
    let commits = read.open_table(UNKNOWN_COMMIT_RECOVERY).map_err(storage)?;
    for row in commits.iter().map_err(storage)? {
        let (key, value) = row.map_err(storage)?;
        let record: UnknownCommitRecord = decode(value.value())?;
        if key.value() != record.idempotency_key {
            return Err(integrity(
                "store_stop_unknown_commits",
                "unknown-commit key does not match its owner identity",
            ));
        }
        builder.observe("unknown_commits", key.value(), value.value());
        if record.is_open() {
            builder.counts.unknown_commits = increment(builder.counts.unknown_commits)?;
        }
    }
    Ok(())
}

fn observe_operational_current(
    read: &redb::ReadTransaction,
    builder: &mut CensusBuilder,
) -> Result<(), crate::OrsError> {
    let current = read.open_table(OPERATIONAL_CURRENT).map_err(storage)?;
    for row in current.iter().map_err(storage)? {
        let (key, value) = row.map_err(storage)?;
        let record: DurableOperationalRecord = decode_named(value.value(), "operational_current")?;
        let expected_key =
            RedbRecoveryStore::operational_key(record.kind, &record.input.subject_id);
        if key.value() != expected_key {
            return Err(integrity(
                "store_stop_operational_current",
                "current key does not match its typed owner identity",
            ));
        }
        builder.observe("operational_current", key.value(), value.value());
        if record.kind == super::OperationalKind::AdmissionReservation {
            let reservation = record.admission_reservation.as_ref().ok_or_else(|| {
                integrity(
                    "store_stop_admission_reservation",
                    "current admission row has no typed reservation state",
                )
            })?;
            if !matches!(
                reservation.state,
                AdmissionReservationState::Released | AdmissionReservationState::Expired
            ) {
                builder.counts.admission_reservations =
                    increment(builder.counts.admission_reservations)?;
            }
        } else if is_store_dependent_operational_kind(record.kind)
            && !matches!(
                record.phase,
                OperationalPhase::Terminal | OperationalPhase::Released
            )
        {
            builder.counts.operational_work = increment(builder.counts.operational_work)?;
        }
    }
    Ok(())
}

fn observe_recovery_inbox(
    read: &redb::ReadTransaction,
    builder: &mut CensusBuilder,
) -> Result<(), crate::OrsError> {
    let inbox = read.open_table(RECOVERY_INBOX).map_err(storage)?;
    for row in inbox.iter().map_err(storage)? {
        let (key, value) = row.map_err(storage)?;
        let record: DurableInboxRecord = decode_named(value.value(), "recovery_inbox")?;
        if key.value() != record.item.item_id.as_str() {
            return Err(integrity(
                "store_stop_recovery_inbox",
                "inbox key does not match its owner identity",
            ));
        }
        builder.observe("recovery_inbox", key.value(), value.value());
        if record.disposition == RecoveryInboxDisposition::Imported {
            builder.counts.recovery_inbox = increment(builder.counts.recovery_inbox)?;
        }
    }
    Ok(())
}

fn observe_recovery_problems(
    read: &redb::ReadTransaction,
    builder: &mut CensusBuilder,
) -> Result<(), crate::OrsError> {
    let problems = read.open_table(RECOVERY_PROBLEMS).map_err(storage)?;
    for row in problems.iter().map_err(storage)? {
        let (key, value) = row.map_err(storage)?;
        let problem: RecoveryProblem = decode(value.value())?;
        if key.value() != problem.operation_or_checkpoint_id.as_str() {
            return Err(integrity(
                "store_stop_recovery_problems",
                "problem key does not match its owner identity",
            ));
        }
        builder.observe("recovery_problems", key.value(), value.value());
        if problem.terminal_receipt_id.is_none() {
            builder.counts.recovery_problems = increment(builder.counts.recovery_problems)?;
        }
    }
    Ok(())
}

fn observe_effect_operation_leases(
    read: &redb::ReadTransaction,
    builder: &mut CensusBuilder,
) -> Result<(), crate::OrsError> {
    let leases = read.open_table(EFFECT_OPERATION_LEASES).map_err(storage)?;
    for row in leases.iter().map_err(storage)? {
        let (key, value) = row.map_err(storage)?;
        let lease: crate::EffectOperationLease = decode(value.value())?;
        if key.value() != lease.lease_id.as_str() {
            return Err(integrity(
                "store_stop_effect_leases",
                "effect lease key does not match lease identity",
            ));
        }
        builder.observe("effect_operation_leases", key.value(), value.value());
        if !runtime_lease_is_terminal(lease.state)
            || lease.delivery == crate::EffectDeliveryAcknowledgement::GapOpen
            || lease.revocation == crate::RevocationAcknowledgement::Unacknowledged
        {
            builder.counts.effect_operation_leases =
                increment(builder.counts.effect_operation_leases)?;
        }
    }
    Ok(())
}

fn observe_effect_replay_reconciliations(
    read: &redb::ReadTransaction,
    builder: &mut CensusBuilder,
) -> Result<(), crate::OrsError> {
    let reconciliations = read
        .open_table(EFFECT_REPLAY_RECONCILIATIONS)
        .map_err(storage)?;
    for row in reconciliations.iter().map_err(storage)? {
        let (key, value) = row.map_err(storage)?;
        let item: KernelReconciliationItem = decode(value.value())?;
        let operation_id = item.operation_id.as_ref().ok_or_else(|| {
            integrity(
                "store_stop_effect_reconciliation",
                "durable effect reconciliation has no operation identity",
            )
        })?;
        // #1884 W1.5: this family appends like the manifest-side restart family,
        // so one operation identity owns a `{prefix}{attempt:020}` series and the
        // first cause a denial was recorded under is never overwritten by a later
        // one. The census assertion is not weakened by that: the typed owner
        // identity is still re-derived from the DECODED item alone, and no key
        // shape outside this one series' two forms is accepted.
        //
        // The pre-append shape is the same series' attempt 0 and is accepted as
        // such: rows written before #1884 W1.5 are keyed
        // `{module_id}::{generation:020}::{operation_id}` with no trailing `::`
        // and no ordinal, and this family DOES have production writers on `main`
        // (`authorize_effect_replay_for_operation` and
        // `deny_effect_replay_without_lease`), so such rows exist on installed
        // databases. Rejecting them would make the Store-stop census fail with an
        // integrity error on a healthy installed store. The legacy key is
        // recognised only as that exact typed identity — a key that merely starts
        // with the module or operation component is still refused — so the
        // assertion keeps binding the key to the DECODED item.
        let series_prefix = format!(
            "{}::{:020}::{}",
            RedbRecoveryStore::encode_key_component(&item.module_id),
            item.generation.value(),
            RedbRecoveryStore::encode_key_component(operation_id.as_str()),
        );
        let attempt = match key.value().strip_prefix(series_prefix.as_str()) {
            // Pre-append row: the exact series key with no trailing `::` and no
            // ordinal at all, i.e. attempt 0 of this same series. This is the ONE
            // accepted key that carries no ordinal, and it is recognised here by
            // its own shape rather than by the digit check below.
            Some("") => None,
            // Appended row: `::` then the decimal attempt ordinal.
            //
            // #1884 W4: an EMPTY ordinal is refused here. `{prefix}::` — a
            // present identity, two delimiters and no ordinal — is a third key
            // form this function's own documentation does not name, and it used
            // to pass because `all(is_ascii_digit)` is vacuously true for the
            // empty string, which is the same reason the legacy arm above has to
            // be spelled out instead of falling through to that check.
            //
            // Rejecting it is free: the writer emits
            // `format!("{prefix}{attempt:020}")`, `{:020}` on a `u64` is a
            // MINIMUM width of 20 and `u64::MAX` is exactly 20 decimal digits,
            // so the writer can never produce an empty ordinal and no row this
            // family can legally hold is refused by this arm.
            Some(rest) => match rest.strip_prefix("::") {
                Some("") => {
                    return Err(integrity(
                        "store_stop_effect_reconciliation",
                        "reconciliation key ends in an empty attempt ordinal",
                    ));
                }
                Some(ordinal) => Some(ordinal),
                None => {
                    return Err(integrity(
                        "store_stop_effect_reconciliation",
                        "reconciliation key does not match its typed owner identity",
                    ));
                }
            },
            None => {
                return Err(integrity(
                    "store_stop_effect_reconciliation",
                    "reconciliation key does not match its typed owner identity",
                ));
            }
        };
        if attempt.is_some_and(|ordinal| !ordinal.bytes().all(|byte| byte.is_ascii_digit())) {
            return Err(integrity(
                "store_stop_effect_reconciliation",
                "reconciliation key does not end in a decimal attempt ordinal",
            ));
        }
        builder.observe("effect_replay_reconciliations", key.value(), value.value());
        builder.counts.effect_reconciliations = increment(builder.counts.effect_reconciliations)?;
    }
    Ok(())
}

fn observe_store_rebind_replay(
    read: &redb::ReadTransaction,
    builder: &mut CensusBuilder,
) -> Result<(), crate::OrsError> {
    let rebinds = read.open_table(STORE_REBIND_REPLAY).map_err(storage)?;
    for row in rebinds.iter().map_err(storage)? {
        let (key, value) = row.map_err(storage)?;
        let record: crate::StoreRebindReplayRecord = decode(value.value())?;
        record.validate()?;
        let expected_key = format!(
            "{}::{}",
            record.operation_id.as_str(),
            record.request_digest
        );
        if key.value() != expected_key {
            return Err(integrity(
                "store_rebind_replay",
                "rebind key does not match its typed owner identity",
            ));
        }
        builder.observe("store_rebinds", key.value(), value.value());
        if record.state == crate::StoreRebindReplayState::Pending {
            builder.counts.store_rebinds = increment(builder.counts.store_rebinds)?;
        }
    }
    Ok(())
}

fn observe_store_failure_retention(
    read: &redb::ReadTransaction,
    builder: &mut CensusBuilder,
) -> Result<(), crate::OrsError> {
    let failures = read.open_table(STORE_FAILURE_RETENTION).map_err(storage)?;
    for row in failures.iter().map_err(storage)? {
        let (key, value) = row.map_err(storage)?;
        let record: crate::StoreFailureRetentionRecord = decode(value.value())?;
        record.validate()?;
        if key.value() != record.record_key() {
            return Err(integrity(
                "store_failure_retention",
                "failure key does not match its typed owner identity",
            ));
        }
        builder.observe("store_failure_retention", key.value(), value.value());
        if record.failure.disposition == eliot_store_api::StoreFailureDisposition::UnknownOutcome
            && record.reconciled_receipt.is_none()
        {
            builder.counts.unresolved_store_failures =
                increment(builder.counts.unresolved_store_failures)?;
        }
    }
    Ok(())
}

fn observe_scan_disclosure_records(
    read: &redb::ReadTransaction,
    builder: &mut CensusBuilder,
) -> Result<(), crate::OrsError> {
    let disclosures = read.open_table(SCAN_DISCLOSURE_RECORDS).map_err(storage)?;
    for row in disclosures.iter().map_err(storage)? {
        let (key, value) = row.map_err(storage)?;
        let record: crate::ScanDisclosureOrsRecord = decode(value.value())?;
        record.validate()?;
        if key.value() != record.operation_key {
            return Err(integrity(
                "scan_disclosure",
                "disclosure key does not match its typed owner identity",
            ));
        }
        builder.observe("scan_disclosure", key.value(), value.value());
        if record.state == crate::ScanDisclosureRecordState::Prepared {
            builder.counts.prepared_scan_disclosures =
                increment(builder.counts.prepared_scan_disclosures)?;
        }
    }
    Ok(())
}

fn observe_activation_lifecycles(
    read: &redb::ReadTransaction,
    builder: &mut CensusBuilder,
) -> Result<(), crate::OrsError> {
    let lifecycles = read.open_table(ACTIVATION_LIFECYCLES).map_err(storage)?;
    for row in lifecycles.iter().map_err(storage)? {
        let (key, value) = row.map_err(storage)?;
        let record: crate::ActivationLifecycleRecord = decode(value.value())?;
        record.validate()?;
        if key.value() != record.record_key() {
            return Err(integrity(
                "activation_lifecycle",
                "lifecycle key does not match ticket identity",
            ));
        }
        builder.observe("activation_lifecycles", key.value(), value.value());
        match record.state {
            crate::ActivationLifecycleState::Pending
            | crate::ActivationLifecycleState::Claimed
            | crate::ActivationLifecycleState::Reconciling => {
                builder.counts.activation_lifecycles =
                    increment(builder.counts.activation_lifecycles)?;
            }
            // This immutable predecessor result may schedule a successor
            // on a later activation, but it carries no live Store work.
            // Retaining it must not keep the Store branch alive by itself.
            crate::ActivationLifecycleState::DeferredNotReady
            | crate::ActivationLifecycleState::ResultAccepted
            | crate::ActivationLifecycleState::Cancelled
            | crate::ActivationLifecycleState::Expired => {}
        }
    }
    Ok(())
}

fn observe_native_worker_claims(
    read: &redb::ReadTransaction,
    builder: &mut CensusBuilder,
) -> Result<(), crate::OrsError> {
    let claims = read.open_table(NATIVE_WORKER_CLAIMS).map_err(storage)?;
    for row in claims.iter().map_err(storage)? {
        let (key, value) = row.map_err(storage)?;
        let record: crate::NativeWorkerClaimRecord = decode(value.value())?;
        record.validate()?;
        if key.value() != record.record_key() {
            return Err(integrity(
                "native_worker_claim",
                "claim key does not match its typed owner identity",
            ));
        }
        builder.observe("native_worker_claims", key.value(), value.value());
        if !record.state.is_terminal() {
            builder.counts.native_worker_claims = increment(builder.counts.native_worker_claims)?;
        }
    }
    Ok(())
}

fn observe_host_requests(
    read: &redb::ReadTransaction,
    builder: &mut CensusBuilder,
) -> Result<(), crate::OrsError> {
    let requests = read.open_table(HOST_REQUESTS).map_err(storage)?;
    for row in requests.iter().map_err(storage)? {
        let (key, value) = row.map_err(storage)?;
        let record: HostRequestRecord = decode(value.value())?;
        if key.value() != record.record_key() {
            return Err(integrity(
                "store_stop_host_requests",
                "host-request key does not match its owner identity",
            ));
        }
        builder.observe("host_requests", key.value(), value.value());
        if !record.state.is_terminal() {
            builder.counts.host_requests = increment(builder.counts.host_requests)?;
        }
    }
    Ok(())
}

fn observe_host_request_logical_keys(
    read: &redb::ReadTransaction,
    builder: &mut CensusBuilder,
) -> Result<(), crate::OrsError> {
    let requests = read.open_table(HOST_REQUESTS).map_err(storage)?;
    let links = read
        .open_table(HOST_REQUEST_LOGICAL_KEYS)
        .map_err(storage)?;
    for row in links.iter().map_err(storage)? {
        let (key, value) = row.map_err(storage)?;
        let parsed: serde_json::Value = serde_json::from_str(value.value()).map_err(|_| {
            integrity(
                "host_request_logical_index",
                "index value is not valid JSON",
            )
        })?;
        builder.observe("host_request_logical_index", key.value(), value.value());
        if parsed.as_object().is_some_and(|object| {
            object.contains_key("kind")
                && object.contains_key("session")
                && object.contains_key("occurrence")
        }) {
            let presence: super::HostRequestLegacyPresence = decode(value.value())?;
            if RedbRecoveryStore::host_request_legacy_presence_key(
                presence.kind,
                &presence.session,
                &presence.occurrence,
            ) != key.value()
            {
                return Err(integrity(
                    "host_request_legacy_presence",
                    "presence index key diverges from its stored facts",
                ));
            }
            continue;
        }
        if parsed.as_object().is_some_and(|object| {
            object.contains_key("tombstone")
                && object.contains_key("operation_id")
                && object.contains_key("request_digest")
        }) {
            let marker: super::HostRequestLogicalTombstone = decode(value.value())?;
            let row_key = format!(
                "{}::{}",
                marker.operation_id.as_str(),
                marker.request_digest
            );
            let stored = requests
                .get(row_key.as_str())
                .map_err(storage)?
                .ok_or_else(|| {
                    integrity(
                        "host_request_logical_tombstone",
                        "logical tombstone has no retained terminal host-request row",
                    )
                })?;
            let record: HostRequestRecord = decode(stored.value())?;
            if record.operation_id != marker.operation_id
                || record.request_digest != marker.request_digest
                || record.state != crate::HostRequestState::Terminal
                || RedbRecoveryStore::host_request_logical_key_for_record(&record)?.as_deref()
                    != Some(key.value())
            {
                return Err(integrity(
                    "host_request_logical_tombstone",
                    "logical tombstone diverges from its retained host-request row",
                ));
            }
            continue;
        }

        let link: super::HostRequestLogicalLink = decode(value.value())?;
        let row_key = format!("{}::{}", link.operation_id.as_str(), link.request_digest);
        let stored = requests
            .get(row_key.as_str())
            .map_err(storage)?
            .ok_or_else(|| {
                integrity(
                    "host_request_logical_link",
                    "logical link points at a missing host-request row",
                )
            })?;
        let record: HostRequestRecord = decode(stored.value())?;
        if record.operation_id != link.operation_id
            || record.request_digest != link.request_digest
            || RedbRecoveryStore::host_request_logical_key_for_record(&record)?.as_deref()
                != Some(key.value())
        {
            return Err(integrity(
                "host_request_logical_link",
                "logical link diverges from its host-request row",
            ));
        }
    }
    Ok(())
}

fn observe_process_stream_recovery(
    read: &redb::ReadTransaction,
    builder: &mut CensusBuilder,
) -> Result<(), crate::OrsError> {
    let projections = read.open_table(PROCESS_STREAM_RECOVERY).map_err(storage)?;
    for row in projections.iter().map_err(storage)? {
        let (key, value) = row.map_err(storage)?;
        let projection: crate::ProcessStreamRecoveryProjection = decode(value.value())?;
        if key.value() != projection.record_key()? {
            return Err(integrity(
                "store_stop_process_stream_recovery",
                "process-stream key does not match its owner identity",
            ));
        }
        builder.observe("process_stream_recovery", key.value(), value.value());
        if projection.activation != crate::StreamRecoveryActivation::Retired
            || projection.reconciliation.state
                != crate::StreamRecoveryReconciliationState::Reconciled
            || !projection.gaps.is_empty()
        {
            builder.counts.process_stream_recovery =
                increment(builder.counts.process_stream_recovery)?;
        }
    }
    Ok(())
}

fn observe_campaign_source_pending(
    read: &redb::ReadTransaction,
    builder: &mut CensusBuilder,
) -> Result<(), crate::OrsError> {
    let pending = read.open_table(CAMPAIGN_SOURCE_PENDING).map_err(storage)?;
    for row in pending.iter().map_err(storage)? {
        let (key, value) = row.map_err(storage)?;
        let reservation: super::CampaignSourceReservation = decode(value.value())?;
        crate::model::validate_text(
            &reservation.operation_id,
            "campaign_source_pending_operation",
        )?;
        crate::model::validate_digest(
            &reservation.request_digest,
            "campaign_source_pending_request_digest",
        )?;
        reservation.publication.validate()?;
        let expected_key = super::campaign_source_key(&reservation.publication.record)?;
        if key.value() != expected_key {
            return Err(integrity(
                "campaign_source_pending",
                "pending source key does not match its owner record",
            ));
        }
        builder.observe("campaign_source_pending", key.value(), value.value());
        builder.counts.campaign_source_reservations =
            increment(builder.counts.campaign_source_reservations)?;
    }
    Ok(())
}

fn observe_process_start_replay(
    read: &redb::ReadTransaction,
    builder: &mut CensusBuilder,
) -> Result<(), crate::OrsError> {
    let starts = read.open_table(PROCESS_START_REPLAY).map_err(storage)?;
    for row in starts.iter().map_err(storage)? {
        let (key, value) = row.map_err(storage)?;
        let record: crate::ProcessStartReplayRecord = decode(value.value())?;
        record.validate()?;
        if key.value() != record.operation_id.as_str() {
            return Err(integrity(
                "process_start_replay",
                "replay key does not match its typed owner identity",
            ));
        }
        builder.observe("process_start_replay", key.value(), value.value());
        if record.state != crate::ProcessStartReplayState::Completed {
            builder.counts.process_start_replays = increment(builder.counts.process_start_replays)?;
        }
    }
    Ok(())
}

fn observe_authority_handoffs(
    read: &redb::ReadTransaction,
    builder: &mut CensusBuilder,
) -> Result<(), crate::OrsError> {
    let handoffs = read.open_table(AUTHORITY_HANDOFFS).map_err(storage)?;
    for row in handoffs.iter().map_err(storage)? {
        let (key, value) = row.map_err(storage)?;
        let record: crate::AuthorityHandoffRecord = decode(value.value())?;
        record.validate()?;
        if key.value() != record.handoff_id.as_str() {
            return Err(integrity(
                "authority_handoff",
                "handoff key does not match its typed owner identity",
            ));
        }
        builder.observe("authority_handoffs", key.value(), value.value());
        if record.state != crate::AuthorityHandoffState::Consumed {
            builder.counts.authority_handoffs = increment(builder.counts.authority_handoffs)?;
        }
    }
    Ok(())
}

fn observe_cutover_ownership(
    read: &redb::ReadTransaction,
    builder: &mut CensusBuilder,
) -> Result<(), crate::OrsError> {
    let cutovers = read.open_table(CUTOVER_OWNERSHIP).map_err(storage)?;
    for row in cutovers.iter().map_err(storage)? {
        let (key, value) = row.map_err(storage)?;
        let stored: super::StoredCutoverOwnership =
            decode_named(value.value(), "cutover_ownership")?;
        stored.validate_persisted()?;
        if key.value() != stored.record.cutover_id {
            return Err(integrity(
                "cutover_ownership",
                "cutover key does not match its typed owner identity",
            ));
        }
        builder.observe("cutover_ownership", key.value(), value.value());
        if stored.record.state != eliot_runtime_contracts::GenerationCutoverState::Committed {
            builder.counts.cutover_ownership = increment(builder.counts.cutover_ownership)?;
        }
    }
    Ok(())
}

/// Reads the canonical Governor admission receipts (issue #1884; I1.9 line 35,
/// W1.1, AUD1).
///
/// The row is keyed by the receipt's OWN canonical operation identity, exactly as
/// the receipt records it — the writer states no `::` prefix and no ordinal, so
/// nothing is escaped or rendered here — and the identity is re-derived from the
/// DECODED receipt alone. A row filed under another operation's identity, or one
/// whose decoded `operation_id` disagrees with its key, fails the census closed.
fn observe_governor_admission_receipts(
    read: &redb::ReadTransaction,
    builder: &mut CensusBuilder,
) -> Result<(), crate::OrsError> {
    let receipts = read
        .open_table(GOVERNOR_ADMISSION_RECEIPTS)
        .map_err(storage)?;
    for row in receipts.iter().map_err(storage)? {
        let (key, value) = row.map_err(storage)?;
        let receipt: crate::admission_receipt::GovernorAdmissionReceipt = decode(value.value())?;
        if key.value() != receipt.operation_id.as_str() {
            return Err(integrity(
                "governor_admission_receipt",
                "admission receipt key does not match its canonical operation identity",
            ));
        }
        builder.observe("governor_admission_receipts", key.value(), value.value());
    }
    Ok(())
}

/// Reads the Generation Registry lifecycle owner (issue #1884; I1.9 line 8,
/// W1.5, AUD5).
///
/// The row is keyed `{module_id}::{generation:020}` with the escaped `module_id`
/// component `encode_key_component` produces, so `::` is an unambiguous
/// delimiter, and both the module and the generation are re-derived from the
/// DECODED record alone. A row under a key that names another generation fails
/// the census closed.
///
/// #1884 AUD5: a recorded degradation is a BLOCKING obligation here, not only an
/// inventoried row. `GenerationLifecycleRecord::admits_launch`,
/// `admits_new_effect_leases` and `blocks_routes` answer from exactly this
/// disposition, so a Store that holds a `Degraded` or `Quarantined` generation
/// while reporting a clean stop would report a stop the launch, route and lease
/// gates are still refusing. The record's own `validate()` runs first — both
/// lifecycle writers validate before they write — so the disposition this counts
/// is the disposition that satisfies the record's disposition/cause invariant.
fn observe_generation_lifecycles(
    read: &redb::ReadTransaction,
    builder: &mut CensusBuilder,
) -> Result<(), crate::OrsError> {
    let lifecycles = read.open_table(GENERATION_LIFECYCLES).map_err(storage)?;
    for row in lifecycles.iter().map_err(storage)? {
        let (key, value) = row.map_err(storage)?;
        let record: crate::generation_lifecycle::GenerationLifecycleRecord = decode(value.value())?;
        let expected_key = format!(
            "{}::{:020}",
            RedbRecoveryStore::encode_key_component(record.module_id.as_str()),
            record.generation.value()
        );
        if key.value() != expected_key {
            return Err(integrity(
                "generation_lifecycle",
                "generation lifecycle key does not match its recorded module and generation",
            ));
        }
        record.validate()?;
        builder.observe("generation_lifecycles", key.value(), value.value());
        // The RECORD's own predicate, not a second spelling of its disposition:
        // `blocks_routes` is true exactly for `Degraded` and `Quarantined`, the
        // two dispositions that withhold launch, routes and new effect operation
        // leases. Reusing it is what keeps this count and the launch/route/lease
        // gate from ever disagreeing about which generations are degraded.
        if record.blocks_routes() {
            builder.counts.degraded_generations = increment(builder.counts.degraded_generations)?;
        }
    }
    Ok(())
}

/// Reads the observed revocation events of effect operation leases (issue #1884;
/// I1.9 line 48, AUD5).
///
/// The row is keyed by the lease's OWN identity, exactly as the lease records
/// it, and that identity is re-derived from the DECODED event alone. A row filed
/// under another lease's identity fails the census closed.
fn observe_effect_revocation_events(
    read: &redb::ReadTransaction,
    builder: &mut CensusBuilder,
) -> Result<(), crate::OrsError> {
    let events = read.open_table(EFFECT_REVOCATION_EVENTS).map_err(storage)?;
    for row in events.iter().map_err(storage)? {
        let (key, value) = row.map_err(storage)?;
        let event: crate::effect_current_state::RevocationEventRecord = decode(value.value())?;
        if key.value() != event.lease_id.as_str() {
            return Err(integrity(
                "effect_revocation_event",
                "revocation event key does not match its lease identity",
            ));
        }
        builder.observe("effect_revocation_events", key.value(), value.value());
    }
    Ok(())
}

/// Reads the observed delivery acknowledgements of effect operation leases
/// (issue #1884; I1.9 line 48, AUD5).
///
/// The row is keyed by the lease's OWN identity, exactly as the lease records
/// it, and that identity is re-derived from the DECODED record alone. A row
/// filed under another lease's identity fails the census closed.
fn observe_effect_delivery_records(
    read: &redb::ReadTransaction,
    builder: &mut CensusBuilder,
) -> Result<(), crate::OrsError> {
    let records = read.open_table(EFFECT_DELIVERY_RECORDS).map_err(storage)?;
    for row in records.iter().map_err(storage)? {
        let (key, value) = row.map_err(storage)?;
        let record: crate::effect_current_state::EffectDeliveryRecord = decode(value.value())?;
        if key.value() != record.lease_id.as_str() {
            return Err(integrity(
                "effect_delivery_record",
                "delivery record key does not match its lease identity",
            ));
        }
        builder.observe("effect_delivery_records", key.value(), value.value());
    }
    Ok(())
}

/// Reads the manifest-side restart escalations (issue #1884; I1.9, W1.5, AUD5).
///
/// #1884 AUD5: this family was absent from this census altogether, so
/// `total()` and `is_zero()` could report a CLEAN STOP while a restart had been
/// refused, the refusal was durably escalated, and the affected generation sat
/// degraded in `GENERATION_LIFECYCLES`. It is opened, key-checked and counted
/// here, so a recorded escalation is a live Store obligation.
///
/// The row is keyed `{module_id}::{generation:020}::{attempt:020}`, where
/// `module_id` is the escaped component `encode_key_component` produces (it
/// escapes only `%` and `:`, so `::` is an unambiguous delimiter) and
/// `KernelReconciliationItem` has no attempt field — the ordinal lives in the key
/// alone. Exactly TWO key forms are this series and both are accepted:
///
/// * the appended `{M}::{G:020}::{attempt:020}` rows, and
/// * the exact pre-append key `{M}::{G:020}` with no trailing `::` and no
///   ordinal, which is a STRICT PREFIX of the series prefix and therefore sorts
///   before every one of its extensions in redb's byte-ordered key space, so it
///   can only be reached by an exact `get()`.
///
/// The module and the generation are re-derived from the DECODED item alone,
/// exactly as `observe_effect_replay_reconciliations` does for the sibling family
/// that shares this record type, so a row filed under another generation's series
/// fails the census closed as corruption instead of being counted as evidence
/// about this one. An EMPTY ordinal (`{M}::{G:020}::`) is refused for the same
/// reason the effect-replay series refuses it: `all(is_ascii_digit)` is vacuously
/// true for the empty string, and the writer emits `{:020}` on a `u64` whose
/// maximum is exactly twenty decimal digits, so no row this family can legally
/// hold carries one.
///
/// Every recorded row is counted. This family has no terminal disposition and no
/// receipt that could retire it, so a recorded refusal stays live Store work
/// until its owner removes the row; that is what makes one escalation enough to
/// keep the stop non-clean.
fn observe_kernel_restart_reconciliations(
    read: &redb::ReadTransaction,
    builder: &mut CensusBuilder,
) -> Result<(), crate::OrsError> {
    let escalations = read
        .open_table(KERNEL_RESTART_RECONCILIATIONS)
        .map_err(storage)?;
    for row in escalations.iter().map_err(storage)? {
        let (key, value) = row.map_err(storage)?;
        let item: KernelReconciliationItem = decode(value.value())?;
        let series_identity = format!(
            "{}::{:020}",
            RedbRecoveryStore::encode_key_component(item.module_id.as_str()),
            item.generation.value()
        );
        let series_prefix = format!("{series_identity}::");
        let attempt = if key.value() == series_identity {
            // The exact pre-append key of this same series, recognised by its own
            // shape rather than by falling through to the digit check.
            None
        } else {
            match key.value().strip_prefix(series_prefix.as_str()) {
                Some("") => {
                    return Err(integrity(
                        "store_stop_restart_reconciliation",
                        "restart reconciliation key ends in an empty attempt ordinal",
                    ));
                }
                Some(ordinal) => Some(ordinal),
                None => {
                    return Err(integrity(
                        "store_stop_restart_reconciliation",
                        "restart reconciliation key does not match its recorded module and generation",
                    ));
                }
            }
        };
        if attempt.is_some_and(|ordinal| !ordinal.bytes().all(|byte| byte.is_ascii_digit())) {
            return Err(integrity(
                "store_stop_restart_reconciliation",
                "restart reconciliation key does not end in a decimal attempt ordinal",
            ));
        }
        builder.observe("kernel_restart_reconciliations", key.value(), value.value());
        builder.counts.restart_reconciliations = increment(builder.counts.restart_reconciliations)?;
    }
    Ok(())
}

fn observe_doctor_attempts(
    read: &redb::ReadTransaction,
    builder: &mut CensusBuilder,
) -> Result<(), crate::OrsError> {
    let attempts = read.open_table(DOCTOR_ATTEMPTS).map_err(storage)?;
    for row in attempts.iter().map_err(storage)? {
        let (key, value) = row.map_err(storage)?;
        let record: crate::DoctorAttemptRecord = decode(value.value())?;
        record.validate()?;
        if key.value() != record.record_key() {
            return Err(integrity(
                "doctor_attempt",
                "attempt key does not match its typed owner identity",
            ));
        }
        builder.observe("doctor_attempts", key.value(), value.value());
        if !record.state.is_terminal() {
            builder.counts.doctor_attempts = increment(builder.counts.doctor_attempts)?;
        }
    }
    Ok(())
}

fn observe_doctor_effects(
    read: &redb::ReadTransaction,
    builder: &mut CensusBuilder,
) -> Result<(), crate::OrsError> {
    let effects = read.open_table(DOCTOR_EFFECTS).map_err(storage)?;
    for row in effects.iter().map_err(storage)? {
        let (key, value) = row.map_err(storage)?;
        let record: crate::DoctorEffectRecord = decode(value.value())?;
        record.validate()?;
        if key.value() != record.record_key() {
            return Err(integrity(
                "doctor_effect",
                "effect key does not match its typed owner identity",
            ));
        }
        builder.observe("doctor_effects", key.value(), value.value());
        if !record.state.is_terminal() {
            builder.counts.doctor_effects = increment(builder.counts.doctor_effects)?;
        }
    }
    Ok(())
}

fn observe_replay_events(
    read: &redb::ReadTransaction,
    builder: &mut CensusBuilder,
) -> Result<(), crate::OrsError> {
    let mut acknowledgements = std::collections::BTreeMap::new();
    let acks = read.open_table(REPLAY_ACKS).map_err(storage)?;
    for row in acks.iter().map_err(storage)? {
        let (key, value) = row.map_err(storage)?;
        let acknowledgement: crate::WorkerReplayAckRecord = decode(value.value())?;
        acknowledgement.validate()?;
        let expected_key = acknowledgement.record_key();
        if key.value() != expected_key {
            return Err(integrity(
                "worker_replay_ack",
                "acknowledgement key does not match its typed owner identity",
            ));
        }
        builder.observe("worker_replay_acks", key.value(), value.value());
        if acknowledgements
            .insert(key.value().to_owned(), acknowledgement)
            .is_some()
        {
            return Err(integrity(
                "worker_replay_ack",
                "duplicate acknowledgement identity was returned",
            ));
        }
    }

    let events = read.open_table(REPLAY_EVENTS).map_err(storage)?;
    for row in events.iter().map_err(storage)? {
        let (key, value) = row.map_err(storage)?;
        let event: crate::WorkerReplayEvent = decode(value.value())?;
        event.validate()?;
        let expected_key = event.record_key();
        if key.value() != expected_key {
            return Err(integrity(
                "worker_replay_event",
                "event key does not match its typed owner identity",
            ));
        }
        builder.observe("worker_replay_events", key.value(), value.value());
        match acknowledgements.remove(key.value()) {
            Some(acknowledgement)
                if acknowledgement.stream_id == event.stream_id
                    && acknowledgement.event_id == event.event_id
                    && acknowledgement.sequence == event.sequence =>
            {
                if !matches!(
                    acknowledgement.phase,
                    crate::WorkerReplayPhase::Applied | crate::WorkerReplayPhase::Rejected
                ) {
                    builder.counts.worker_replay_events =
                        increment(builder.counts.worker_replay_events)?;
                }
            }
            Some(_) => {
                return Err(integrity(
                    "worker_replay_ack",
                    "acknowledgement does not bind its exact event",
                ));
            }
            None => {
                builder.counts.worker_replay_events =
                    increment(builder.counts.worker_replay_events)?;
            }
        }
    }
    if !acknowledgements.is_empty() {
        return Err(integrity(
            "worker_replay_ack",
            "acknowledgement has no retained source event",
        ));
    }
    Ok(())
}

fn observe_bridge_event_records(
    read: &redb::ReadTransaction,
    builder: &mut CensusBuilder,
) -> Result<(), crate::OrsError> {
    let records = read.open_table(BRIDGE_EVENT_RECORDS).map_err(storage)?;
    for row in records.iter().map_err(storage)? {
        let (key, value) = row.map_err(storage)?;
        let record: super::BridgeEventRow = decode(value.value())?;
        record.validate()?;
        let namespace = if record.owner_namespace.is_empty() {
            record.stream_id.as_str()
        } else {
            record.owner_namespace.as_str()
        };
        let expected_key = format!("{namespace}::{}", record.event_id);
        if key.value() != expected_key {
            return Err(integrity(
                "bridge_event_record",
                "event key does not match its typed owner identity",
            ));
        }
        builder.observe("bridge_event_records", key.value(), value.value());
        builder.counts.bridge_event_records = increment(builder.counts.bridge_event_records)?;
    }
    Ok(())
}

fn observe_bridge_event_projections(
    read: &redb::ReadTransaction,
    builder: &mut CensusBuilder,
) -> Result<(), crate::OrsError> {
    let projections = read.open_table(BRIDGE_EVENT_PROJECTIONS).map_err(storage)?;
    for row in projections.iter().map_err(storage)? {
        let (key, value) = row.map_err(storage)?;
        let projection: super::BridgeEventProjectionRow = decode(value.value())?;
        projection.validate()?;
        let namespace = if projection.owner_namespace.is_empty() {
            projection.stream_id.as_str()
        } else {
            projection.owner_namespace.as_str()
        };
        let expected_key = format!("{namespace}::{}", projection.event_id);
        if key.value() != expected_key {
            return Err(integrity(
                "bridge_event_projection",
                "projection key does not match its typed owner identity",
            ));
        }
        builder.observe("bridge_event_projections", key.value(), value.value());
        builder.counts.bridge_event_projections =
            increment(builder.counts.bridge_event_projections)?;
    }
    Ok(())
}

fn observe_bridge_event_handoffs(
    read: &redb::ReadTransaction,
    builder: &mut CensusBuilder,
) -> Result<(), crate::OrsError> {
    let handoffs = read.open_table(BRIDGE_EVENT_HANDOFFS).map_err(storage)?;
    for row in handoffs.iter().map_err(storage)? {
        let (key, value) = row.map_err(storage)?;
        let record: super::BridgeEventHandoffRow = decode(value.value())?;
        record.validate()?;
        let namespace = if record.owner_namespace.is_empty() {
            record.stream_id.as_str()
        } else {
            record.owner_namespace.as_str()
        };
        let expected_key = format!("{namespace}::{}", record.event_id);
        if key.value() != expected_key {
            return Err(integrity(
                "bridge_event_handoff",
                "handoff key does not match its typed owner identity",
            ));
        }
        builder.observe("bridge_event_handoffs", key.value(), value.value());
        // Even RECONCILED is not receiver-owned terminal evidence for this
        // contract; retirement remains unavailable until that evidence is
        // represented and the owner removes the row.
        builder.counts.bridge_event_handoffs = increment(builder.counts.bridge_event_handoffs)?;
    }
    Ok(())
}

fn observe_bridge_event_gaps(
    read: &redb::ReadTransaction,
    builder: &mut CensusBuilder,
) -> Result<(), crate::OrsError> {
    let gaps = read.open_table(BRIDGE_EVENT_GAPS).map_err(storage)?;
    for row in gaps.iter().map_err(storage)? {
        let (key, value) = row.map_err(storage)?;
        let record: super::BridgeEventGapRow = decode(value.value())?;
        record.validate()?;
        if key.value() != record.gap_id {
            return Err(integrity(
                "bridge_event_gap",
                "gap key does not match its typed owner identity",
            ));
        }
        builder.observe("bridge_event_gaps", key.value(), value.value());
        builder.counts.bridge_event_gaps = increment(builder.counts.bridge_event_gaps)?;
    }
    Ok(())
}

fn observe_restore_journal_intents(
    read: &redb::ReadTransaction,
    builder: &mut CensusBuilder,
) -> Result<(), crate::OrsError> {
    let intents = read.open_table(RESTORE_JOURNAL_INTENTS).map_err(storage)?;
    for row in intents.iter().map_err(storage)? {
        let (key, value) = row.map_err(storage)?;
        builder.observe("restore_journal_intents", key.value(), value.value());
    }
    Ok(())
}

fn observe_restore_journal_results(
    read: &redb::ReadTransaction,
    builder: &mut CensusBuilder,
) -> Result<(), crate::OrsError> {
    let results = read.open_table(RESTORE_JOURNAL_RESULTS).map_err(storage)?;
    for row in results.iter().map_err(storage)? {
        let (key, value) = row.map_err(storage)?;
        builder.observe("restore_journal_results", key.value(), value.value());
    }
    Ok(())
}

fn observe_restore_journal_meta(
    read: &redb::ReadTransaction,
    builder: &mut CensusBuilder,
) -> Result<(), crate::OrsError> {
    let meta = read.open_table(RESTORE_JOURNAL_META).map_err(storage)?;
    for row in meta.iter().map_err(storage)? {
        let (key, value) = row.map_err(storage)?;
        builder.observe("restore_journal_meta", key.value(), value.value());
    }
    Ok(())
}

fn observe_cold_start_readiness(
    read: &redb::ReadTransaction,
    identity: &super::OrsStoreIdentity,
    builder: &mut CensusBuilder,
) -> Result<(), crate::OrsError> {
    let mut newest_by_base = std::collections::BTreeMap::<String, (String, u64)>::new();
    let mut newest_by_binding = std::collections::BTreeMap::<String, (String, String, u64)>::new();
    {
        let records = read
            .open_table(COLD_START_READINESS_RECORDS)
            .map_err(storage)?;
        for row in records.iter().map_err(storage)? {
            let (key, value) = row.map_err(storage)?;
            let record: crate::ColdStartReadinessOrsRecord = decode(value.value())?;
            record.validate()?;
            super::validate_cold_start_installation(&record.claim, identity)?;
            if key.value() != record.record_key {
                return Err(integrity(
                    "cold_start_readiness",
                    "readiness row key does not match its typed owner identity",
                ));
            }
            builder.observe("cold_start_readiness_records", key.value(), value.value());
            if record.terminal.is_none() {
                builder.counts.cold_start_readiness_leases =
                    increment(builder.counts.cold_start_readiness_leases)?;
            }

            let base = record.claim.base_identity_digest.clone();
            let candidate = (record.record_key.clone(), record.record_revision);
            if newest_by_base
                .get(&base)
                .is_none_or(|(_, revision)| candidate.1 > *revision)
            {
                newest_by_base.insert(base, candidate.clone());
            }

            let binding = record.claim.binding_digest.clone();
            let candidate = (
                record.claim.base_identity_digest.clone(),
                record.record_key.clone(),
                record.record_revision,
            );
            if newest_by_binding
                .get(&binding)
                .is_none_or(|(_, _, revision)| candidate.2 > *revision)
            {
                newest_by_binding.insert(binding, candidate);
            }
        }
    }

    observe_cold_start_heads(read, builder, &newest_by_base)?;

    let mut binding_count = 0_usize;
    {
        let bindings = read
            .open_table(COLD_START_READINESS_BINDINGS)
            .map_err(storage)?;
        for row in bindings.iter().map_err(storage)? {
            let (key, value) = row.map_err(storage)?;
            let binding: super::ColdStartReadinessBindingIndex = decode(value.value())?;
            binding.validate()?;
            let expected = newest_by_binding.get(key.value());
            if key.value() != binding.binding_digest.as_str()
                || expected
                    != Some(&(
                        binding.base_identity_digest.clone(),
                        binding.record_key.clone(),
                        binding.record_revision,
                    ))
            {
                return Err(integrity(
                    "cold_start_readiness_binding",
                    "binding index does not identify the latest exact readiness row",
                ));
            }
            builder.observe("cold_start_readiness_bindings", key.value(), value.value());
            binding_count = binding_count.checked_add(1).ok_or_else(|| {
                integrity(
                    "cold_start_readiness_binding",
                    "binding-index count overflowed its platform range",
                )
            })?;
        }
    }
    if binding_count != newest_by_binding.len() {
        return Err(integrity(
            "cold_start_readiness_binding",
            "a readiness binding has no exact durable index",
        ));
    }
    Ok(())
}

fn observe_cold_start_heads(
    read: &redb::ReadTransaction,
    builder: &mut CensusBuilder,
    newest_by_base: &std::collections::BTreeMap<String, (String, u64)>,
) -> Result<(), crate::OrsError> {
    let mut head_count = 0_usize;
    {
        let heads = read
            .open_table(COLD_START_READINESS_HEADS)
            .map_err(storage)?;
        for row in heads.iter().map_err(storage)? {
            let (key, value) = row.map_err(storage)?;
            let head: super::ColdStartReadinessRevisionHead = decode(value.value())?;
            head.validate()?;
            if key.value() != head.base_identity_digest.as_str()
                || newest_by_base.get(key.value())
                    != Some(&(head.record_key.clone(), head.record_revision))
            {
                return Err(integrity(
                    "cold_start_readiness_head",
                    "revision head does not identify the latest exact readiness row",
                ));
            }
            builder.observe("cold_start_readiness_heads", key.value(), value.value());
            head_count = head_count.checked_add(1).ok_or_else(|| {
                integrity(
                    "cold_start_readiness_head",
                    "revision-head count overflowed its platform range",
                )
            })?;
        }
    }
    if head_count != newest_by_base.len() {
        return Err(integrity(
            "cold_start_readiness_head",
            "a readiness identity has no exact durable revision head",
        ));
    }

    Ok(())
}

fn observe_bridge_event_maintenance(
    read: &redb::ReadTransaction,
    builder: &mut CensusBuilder,
) -> Result<(), crate::OrsError> {
    {
        let cursors = read.open_table(BRIDGE_EVENT_CURSORS).map_err(storage)?;
        for row in cursors.iter().map_err(storage)? {
            let (key, value) = row.map_err(storage)?;
            let cursor: super::BridgeEventCursorRow = decode(value.value())?;
            cursor.validate()?;
            let expected_key = if cursor.owner_namespace.is_empty() {
                cursor.stream_id.as_str()
            } else {
                cursor.owner_namespace.as_str()
            };
            if key.value() != expected_key {
                return Err(integrity(
                    "bridge_event_cursor",
                    "cursor key does not match its typed owner identity",
                ));
            }
            builder.observe("bridge_event_cursors", key.value(), value.value());
            for scan in [
                cursor.handoff_repair_scan.as_ref(),
                cursor.handoff_retirement_scan.as_ref(),
                cursor.handoff_reconcile_scan.as_ref(),
            ]
            .into_iter()
            .flatten()
            {
                scan.validate()?;
                builder.counts.bridge_event_maintenance_continuations =
                    increment(builder.counts.bridge_event_maintenance_continuations)?;
            }
        }
    }

    {
        let cursors = read
            .open_table(BRIDGE_EVENT_OWNER_MAINTENANCE_CURSORS)
            .map_err(storage)?;
        for row in cursors.iter().map_err(storage)? {
            let (key, value) = row.map_err(storage)?;
            let cursor: super::BridgeEventOwnerMaintenanceCursorRow = decode(value.value())?;
            cursor.validate()?;
            if key.value() != cursor.owner_scope_digest {
                return Err(integrity(
                    "bridge_event_owner_maintenance_cursor",
                    "owner maintenance key does not match its typed presenter scope",
                ));
            }
            builder.observe(
                "bridge_event_owner_maintenance_cursors",
                key.value(),
                value.value(),
            );
            if cursor.after_sequence != 0 {
                builder.counts.bridge_event_maintenance_continuations =
                    increment(builder.counts.bridge_event_maintenance_continuations)?;
            }
        }
    }
    Ok(())
}

fn is_store_dependent_operational_kind(kind: super::OperationalKind) -> bool {
    matches!(
        kind,
        super::OperationalKind::Operation
            | super::OperationalKind::Retry
            | super::OperationalKind::JobCheckpoint
            | super::OperationalKind::DeliveryCursor
            | super::OperationalKind::GenerationTransition
            | super::OperationalKind::GenerationCutover
            | super::OperationalKind::RootTransition
    )
}

fn runtime_lease_is_terminal(state: eliot_runtime_contracts::LeaseState) -> bool {
    matches!(
        state,
        eliot_runtime_contracts::LeaseState::Released
            | eliot_runtime_contracts::LeaseState::Expired
            | eliot_runtime_contracts::LeaseState::Revoked
            | eliot_runtime_contracts::LeaseState::Superseded
            | eliot_runtime_contracts::LeaseState::Closed
    )
}

fn increment(value: u64) -> Result<u64, crate::OrsError> {
    value
        .checked_add(1)
        .ok_or_else(|| crate::OrsError::IntegrityProblem {
            record_type: "store_stop_census",
            reason: "obligation count overflowed its wire range".to_owned(),
        })
}

fn integrity(record_type: &'static str, reason: &'static str) -> crate::OrsError {
    crate::OrsError::IntegrityProblem {
        record_type,
        reason: reason.to_owned(),
    }
}

struct CensusBuilder {
    counts: StoreStopObligationCounts,
    revision: String,
}

impl CensusBuilder {
    fn new() -> Self {
        Self {
            counts: StoreStopObligationCounts::default(),
            revision: crate::model::sha256_hex(b"eliot.ors.store-stop-census.v2"),
        }
    }

    fn observe(&mut self, family: &str, key: &str, value: &str) {
        let key_digest = crate::model::sha256_hex(key.as_bytes());
        let value_digest = crate::model::sha256_hex(value.as_bytes());
        let next = format!("{}\n{family}\n{key_digest}\n{value_digest}", self.revision);
        self.revision = crate::model::sha256_hex(next.as_bytes());
    }
}

/// Issue #1884 AUD5: a recorded manifest-side restart escalation, and a recorded
/// generation degradation, are live Store obligations.
///
/// These are the proofs for the two families this census previously left
/// uncounted: the whole `StoreStopObligationCounts` denominator could report
/// `is_zero()` on a store that held a durable restart refusal and a generation
/// the launch, route and lease gates were still refusing.
///
/// They drive the two OBSERVERS over one read transaction rather than
/// `load_store_stop_obligation_census`, and that is a stated limit of the proof
/// rather than a convenience: `census_in_read` opens every family and several of
/// them are `CreatedOnFirstWrite` (`RUNTIME_LEASE_CURRENT`, `HOST_REQUESTS`,
/// `CUTOVER_OWNERSHIP`, `STORE_FAILURE_RETENTION`, `SCAN_DISCLOSURE_RECORDS`,
/// `BRIDGE_EVENT_PROJECTIONS`, the `COLD_START_READINESS_*` triple), so a store
/// that has recorded nothing but a manifest refusal cannot be read by the whole
/// census at all. That fail-closed property is pre-existing and is not changed
/// here; what these proofs establish is exactly the two counts this change adds
/// and the corruption refusal the new observer applies.
#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test fixtures use unwrap/expect; production lints remain -D warnings"
)]
mod tests {
    use std::path::PathBuf;

    use eliot_contracts::ResourceGeneration;

    use super::*;
    use crate::KernelReconciliationKind;
    use crate::generation_lifecycle::{
        GENERATION_LIFECYCLE_SCHEMA_VERSION, GenerationDisposition, GenerationLifecycleRecord,
    };
    use crate::store::persistence_codec::encode;
    use crate::test_support::kernel_fixture_dir;

    const INSTALLATION_ID: &str = "installation-ors-1884-census";
    const MODULE_ID: &str = "module-ors-1884-census";
    const GENERATION: u64 = 7;
    const OBSERVED_AT_MS: i64 = 1_700_000_000_000;

    fn resource_generation(value: u64) -> ResourceGeneration {
        ResourceGeneration::new(value).expect("non-zero generation")
    }

    /// Opens one installed, otherwise empty ORS under a unique temp root.
    ///
    /// The installation identity is bound so the fixture is the same durable shape
    /// a production store has, store-object identity row included. Nothing in these
    /// proofs reads that row; the identical fixture shape is used by the
    /// `export_snapshot` proof in `store/backup_snapshot.rs`, which does compare
    /// against it.
    fn installed_store(tag: &str) -> (PathBuf, RedbRecoveryStore) {
        let dir = kernel_fixture_dir(tag).expect("unique fixture temp root");
        let (store, _identity) =
            RedbRecoveryStore::open_for_installation(dir.join("ors.redb"), INSTALLATION_ID)
                .expect("installed store opens");
        (dir, store)
    }

    /// The manifest-side restart escalation a missing manifest produces: the same
    /// item shape the production refusal path persists, with no operation or
    /// lease identity because a restart is not an effect replay.
    fn restart_escalation(module_id: &str, generation: u64) -> KernelReconciliationItem {
        KernelReconciliationItem {
            kind: KernelReconciliationKind::ManifestAbsent,
            module_id: module_id.to_owned(),
            generation: resource_generation(generation),
            bound_manifest_sha256: None,
            recorded_manifest_sha256: None,
            lease_id: None,
            operation_id: None,
            observed_at_ms: OBSERVED_AT_MS,
        }
    }

    /// Places one raw row under an exact key, bypassing every owner writer.
    ///
    /// It exists for two reasons and no others: to present a row the owner CANNOT
    /// write — a row whose recorded identity disagrees with its key, which is the
    /// only way to reach the corruption refusal — and to place a lifecycle row on
    /// its own, without the escalation the refusal writer would append beside it.
    /// Every escalation a production refusal produces is written through the owner
    /// writer instead.
    fn insert_raw_row(
        store: &RedbRecoveryStore,
        table: redb::TableDefinition<&'static str, &'static str>,
        key: &str,
        payload: &str,
    ) {
        let write = store
            .database
            .begin_write()
            .expect("write transaction opens");
        {
            let mut rows = write.open_table(table).expect("test table opens");
            let _ = rows.insert(key, payload).expect("test row inserts");
        }
        write.commit().expect("test row commits");
    }

    /// POSITIVE: one recorded manifest-side restart escalation is not a clean
    /// stop, and it is counted in the same denominator as every other family.
    ///
    /// The owner writer is used, so the escalation row AND the
    /// `GENERATION_LIFECYCLES` degradation it records in the same transaction are
    /// exactly what production writes: one recorded refusal and one affected
    /// generation. Both observers run here, because `census_in_read` runs both and
    /// the point is that neither of them can be absorbed into a clean stop.
    #[test]
    fn a_recorded_restart_escalation_is_not_a_clean_stop() {
        let (dir, store) = installed_store("stop-census-1884-escalation");
        store
            .persist_kernel_restart_reconciliation(&restart_escalation(MODULE_ID, GENERATION))
            .expect("the owner writer persists the escalation and the degradation");
        let read = store.database.begin_read().expect("read transaction opens");
        let mut builder = CensusBuilder::new();
        observe_kernel_restart_reconciliations(&read, &mut builder)
            .expect("the restart-escalation observer reads its own family");
        observe_generation_lifecycles(&read, &mut builder)
            .expect("the generation-lifecycle observer reads its own family");
        assert_eq!(builder.counts.restart_reconciliations, 1);
        assert_eq!(builder.counts.degraded_generations, 1);
        assert!(
            !builder.counts.is_zero(),
            "a store holding a recorded restart refusal must not report a clean stop"
        );
        assert_eq!(builder.counts.total().expect("total is representable"), 2);
        drop(read);
        drop(store);
        let _ = std::fs::remove_dir_all(dir);
    }

    /// POSITIVE: a recorded generation DEGRADATION blocks a clean stop on its
    /// own, with no escalation row present.
    ///
    /// The lifecycle row is placed directly rather than through the refusal
    /// writer, because that writer always appends an escalation row too and would
    /// leave the two families indistinguishable. Only the recorded disposition is
    /// under test, and `GenerationLifecycleRecord` is the record that owns it.
    #[test]
    fn a_degraded_generation_lifecycle_row_is_not_a_clean_stop() {
        let (dir, store) = installed_store("stop-census-1884-degraded");
        let record = GenerationLifecycleRecord {
            schema_version: GENERATION_LIFECYCLE_SCHEMA_VERSION,
            module_id: MODULE_ID.to_owned(),
            generation: resource_generation(GENERATION),
            disposition: GenerationDisposition::Degraded,
            first_refusal_cause: Some(KernelReconciliationKind::ManifestAbsent),
            recorded_at_ms: OBSERVED_AT_MS,
        };
        record
            .validate()
            .expect("the lifecycle fixture satisfies its own shape");
        let key = format!("{MODULE_ID}::{GENERATION:020}");
        insert_raw_row(
            &store,
            GENERATION_LIFECYCLES,
            key.as_str(),
            encode(&record).expect("the lifecycle row encodes").as_str(),
        );
        let read = store.database.begin_read().expect("read transaction opens");
        let mut builder = CensusBuilder::new();
        observe_generation_lifecycles(&read, &mut builder)
            .expect("the generation-lifecycle observer reads its own family");
        assert_eq!(builder.counts.degraded_generations, 1);
        assert_eq!(
            builder.counts.restart_reconciliations, 0,
            "this store holds no escalation row, so the degradation is the only obligation"
        );
        assert!(
            !builder.counts.is_zero(),
            "a generation recorded degraded must not report a clean stop"
        );
        assert_eq!(builder.counts.total().expect("total is representable"), 1);
        drop(read);
        drop(store);
        let _ = std::fs::remove_dir_all(dir);
    }

    /// REFUSAL: an escalation row whose recorded module/generation does not
    /// match the series it is filed under is corruption, exactly as the sibling
    /// effect-replay family and every other observer in this census treat a
    /// misfiled row. The row is placed raw because no owner writer can produce
    /// one.
    #[test]
    fn a_restart_escalation_row_filed_under_another_generation_is_refused() {
        let (dir, store) = installed_store("stop-census-1884-misfiled");
        let item = restart_escalation(MODULE_ID, GENERATION);
        let misfiled_key = format!("{MODULE_ID}::{:020}::00000000000000000000", GENERATION + 1);
        insert_raw_row(
            &store,
            KERNEL_RESTART_RECONCILIATIONS,
            misfiled_key.as_str(),
            encode(&item).expect("the escalation row encodes").as_str(),
        );
        let read = store.database.begin_read().expect("read transaction opens");
        let mut builder = CensusBuilder::new();
        let error = observe_kernel_restart_reconciliations(&read, &mut builder)
            .expect_err("a misfiled escalation row must fail the census closed");
        match error {
            crate::OrsError::IntegrityProblem {
                record_type,
                reason,
            } => {
                assert_eq!(record_type, "store_stop_restart_reconciliation");
                assert_eq!(
                    reason,
                    "restart reconciliation key does not match its recorded module and generation"
                );
            }
            other => panic!("expected a typed integrity refusal, got {other:?}"),
        }
        drop(read);
        drop(store);
        let _ = std::fs::remove_dir_all(dir);
    }
}
