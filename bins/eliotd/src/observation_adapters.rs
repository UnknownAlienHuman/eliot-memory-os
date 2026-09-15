//! Private Governor-backed observation/verified-repair port adapters.
//!
//! The forwarding adapter translates between the daemon composition root and
//! one Governor
//! [`GovernorObservationReconciliation`](eliot_governor::GovernorObservationReconciliation)
//! borrowed from the single [`DaemonComposition`](super::DaemonComposition)
//! by its `observation_reconciliation` accessor. It forwards authenticated
//! input and translates typed results only:
//!
//! - No policy, admission, or semantic rules live here. Fence agreement,
//!   verifier endorsement, problem binding, scratch legality, and the two
//!   canonical commits stay with the Governor observation owner; this adapter
//!   never invents a verification, a problem revision, or a receipt.
//! - `admit_doctor_verification` forwards the exact admitted identity,
//!   operation identity, and verification report to the Governor canonical
//!   path. Only a `Committed` observation receipt admits the recovery leg;
//!   every terminal receipt is returned exactly as issued, and a lost
//!   acknowledgement reconciles the same operation receipt.
//! - Watchdog export acknowledgement mapping is pure and lives here (never
//!   in the Governor, which must not depend on the Watchdog): a terminal
//!   canonical receipt maps to its sink disposition, an unknown outcome maps
//!   to `Unknown`, and gap-like entries resolve through `GapRequiresRecovery`.
//!   `Received`, `Durable`, and `AdmittedCandidate` are never emitted by this
//!   mapping and never advance the cursor. Acknowledgements echo the exact
//!   batch digest and predecessor cursor; cursor-advance decisions stay with
//!   the Watchdog owner via its own validation.
//!
//! The adapter performs no I/O of its own beyond awaiting the inner Governor
//! owner, so it cannot block the single-thread async reactor beyond the
//! already-admitted canonical commits. The current Kernel binding is observed
//! through the Governor composition, never through a second client.

#![forbid(unsafe_code)]

use eliot_governor::{
    CompositionError, GovernorObservationReconciliation, KernelTransitionPort,
    WatchdogEntryAdmission, WatchdogEntryKind,
};

/// Forwards doctor-verification admission to the single Governor owner.
///
/// The wrapper owns the inner Governor adapter (which itself borrows the
/// single Governor owner triple) and forwards each call unchanged. It adds no
/// validation, retry, or state of its own; every typed success or fail-closed
/// error comes from the Governor owner.
pub struct ForwardingObservationReconciliation<'a, P: ?Sized> {
    inner: GovernorObservationReconciliation<'a, P>,
}

impl<'a, P: ?Sized> ForwardingObservationReconciliation<'a, P> {
    /// Wraps the single Governor reconciliation owner for forwarding.
    pub fn new(inner: GovernorObservationReconciliation<'a, P>) -> Self {
        Self { inner }
    }
}

impl<P: KernelTransitionPort + ?Sized> ForwardingObservationReconciliation<'_, P> {
    /// Forwards one independently verified Doctor result to the Governor
    /// canonical path and returns only the exact issued receipt.
    pub async fn admit_doctor_verification(
        &self,
        identity: &eliot_protocol::RequestIdentity,
        operation_id: &eliot_contracts::OperationId,
        report: &eliot_doctor_core::VerificationReport,
    ) -> Result<eliot_store_api::WriteReceipt, CompositionError> {
        self.inner
            .admit_doctor_verification(identity, operation_id, report)
            .await
    }

    /// Forwards one Watchdog spool export batch through Governor admission
    /// and returns the exact sink-owned acknowledgement.
    ///
    /// Each export entry becomes one Governor-side [`WatchdogEntryAdmission`]
    /// view (sequence plus opaque digests, no semantics) and the batch is
    /// admitted via the inner Governor owner. Per-entry canonical outcomes
    /// map through [`forward_watchdog_batch`]: a terminal receipt becomes its
    /// sink disposition while an unknown (`None`) outcome stays `Unknown` and
    /// never advances the cursor. A whole-call failure propagates as
    /// [`CompositionError`] without invention: the caller reports the honest
    /// store-unavailable stage with [`durable_acknowledgement_for_batch`] or
    /// [`unknown_acknowledgement_for_batch`]. No policy, admission, or
    /// semantic rule lives here.
    pub async fn admit_watchdog_batch(
        &self,
        identity: &eliot_protocol::RequestIdentity,
        base_operation_id: &eliot_contracts::OperationId,
        batch: &eliot_watchdog_core::WatchdogSpoolExportBatch,
    ) -> Result<eliot_watchdog_core::WatchdogSpoolAcknowledgement, CompositionError> {
        let entries: Vec<WatchdogEntryAdmission> = batch
            .entries
            .iter()
            .map(|entry| {
                let kind = match entry.payload_kind {
                    eliot_watchdog_core::WatchdogSpoolPayloadKind::Heartbeat => {
                        WatchdogEntryKind::Heartbeat
                    }
                    eliot_watchdog_core::WatchdogSpoolPayloadKind::Gap => WatchdogEntryKind::Gap,
                    eliot_watchdog_core::WatchdogSpoolPayloadKind::Recovery => {
                        WatchdogEntryKind::Recovery
                    }
                };
                WatchdogEntryAdmission {
                    sequence: entry.sequence,
                    kind,
                    record_digest: entry.record_digest.clone(),
                    payload_digest: entry.payload_digest.clone(),
                    observed_at_ms: entry.observed_at_ms,
                }
            })
            .collect();
        let admitted = self
            .inner
            .admit_watchdog_batch(
                identity,
                base_operation_id,
                &batch.batch_id,
                &batch.batch_digest,
                &entries,
            )
            .await?;
        let outcomes: Vec<Option<eliot_store_api::WriteReceiptStatus>> = admitted
            .iter()
            .map(|entry| entry.receipt.as_ref().map(|receipt| receipt.status))
            .collect();
        Ok(forward_watchdog_batch(batch, &outcomes))
    }
}

/// Maps a canonical outcome to its Watchdog spool sink disposition.
///
/// `None` (no receipt: the commit outcome is unknown) maps to `Unknown`,
/// which never advances the cursor. `Committed` maps to `Applied`;
/// `Rejected`, `DeadLetter`, and `Cancelled` are terminal-as-decided and map
/// to `Rejected` with an explicit reason so the cursor advances past the
/// decided entry exactly like an applied one. This mapping never emits
/// `Received`, `Durable`, or `AdmittedCandidate`: none of them advances the
/// cursor. Gap-like entries resolve through [`gap_requires_recovery`], never
/// through a canonical receipt mapping.
///
/// Live: consumed by [`forward_watchdog_batch`] below.
pub fn sink_disposition_for_canonical_outcome(
    status: Option<eliot_store_api::WriteReceiptStatus>,
) -> eliot_watchdog_core::WatchdogSpoolSinkDisposition {
    use eliot_watchdog_core::WatchdogSpoolSinkDisposition as Disposition;
    match status {
        None => Disposition::Unknown,
        Some(eliot_store_api::WriteReceiptStatus::Committed) => Disposition::Applied,
        Some(eliot_store_api::WriteReceiptStatus::Rejected) => Disposition::Rejected {
            reason: "canonical rejected".to_owned(),
        },
        Some(eliot_store_api::WriteReceiptStatus::DeadLetter) => Disposition::Rejected {
            reason: "canonical dead-letter".to_owned(),
        },
        Some(eliot_store_api::WriteReceiptStatus::Cancelled) => Disposition::Rejected {
            reason: "canonical cancelled".to_owned(),
        },
    }
}

/// Returns the terminal gap-resolution disposition for gap-like spool
/// entries. It advances the cursor only for `Gap`/`Recovery` payload kinds;
/// applying it to a `Heartbeat` entry is the wrong phase and never advances
/// (enforced by the Watchdog owner's own classifier).
///
/// Live: consumed by [`forward_watchdog_batch`] below.
pub fn gap_requires_recovery() -> eliot_watchdog_core::WatchdogSpoolSinkDisposition {
    eliot_watchdog_core::WatchdogSpoolSinkDisposition::GapRequiresRecovery
}

/// Builds the sink-owned acknowledgement for exactly one export batch.
///
/// Every owner-identity field echoes the batch exactly: the batch digest, the
/// predecessor acknowledged sequence, the covered range, the sink, the
/// generation/epoch, and the installation. Per-entry dispositions come from
/// [`sink_disposition_for_canonical_outcome`] (or [`gap_requires_recovery`]
/// for gap-like entries) in batch order. Cursor-advance validation stays
/// with the Watchdog owner; this constructor invents no digest or cursor.
///
/// Live: consumed by [`forward_watchdog_batch`] and the store-unavailable
/// constructors below.
pub fn acknowledgement_for_batch(
    batch: &eliot_watchdog_core::WatchdogSpoolExportBatch,
    dispositions: Vec<eliot_watchdog_core::WatchdogSpoolEntryDisposition>,
) -> eliot_watchdog_core::WatchdogSpoolAcknowledgement {
    eliot_watchdog_core::WatchdogSpoolAcknowledgement {
        schema_version: batch.schema_version,
        batch_id: batch.batch_id.clone(),
        batch_digest: batch.batch_digest.clone(),
        predecessor_sequence: batch.predecessor_cursor.acknowledged_sequence,
        first_sequence: batch.first_sequence,
        last_sequence: batch.last_sequence,
        sink_id: batch.predecessor_cursor.sink_id.clone(),
        watchdog_generation: batch.watchdog_generation,
        watchdog_epoch: batch.watchdog_epoch,
        installation_id: batch.installation_id.clone(),
        dispositions,
    }
}

/// Forwards one Watchdog export batch through the live disposition mapping.
///
/// Takes the immutable export batch plus the per-entry canonical outcomes in
/// batch order (`None` per entry means the commit outcome is unknown) and
/// returns the exact sink-owned acknowledgement. Heartbeat entries map
/// through [`sink_disposition_for_canonical_outcome`]; gap-like
/// (`Gap`/`Recovery`) entries resolve through [`gap_requires_recovery`] when
/// the canonical outcome is `Committed` and through the terminal-as-decided
/// mapping when the canonical outcome is `Rejected`/`DeadLetter`/`Cancelled`;
/// unknown outcomes stay `Unknown` and never advance the cursor. A shorter
/// outcome slice pads with `Unknown` and a longer one truncates, so a length
/// mismatch fails closed as non-terminal instead of panicking. No policy,
/// admission, or semantic rule lives here; cursor-advance validation stays
/// with the Watchdog owner. The Governor composition accessor is deferred
/// (see PR residual); this mapping is the daemon-side consumer that feeds
/// `WatchdogSpool::apply_acknowledgement`.
pub fn forward_watchdog_batch(
    batch: &eliot_watchdog_core::WatchdogSpoolExportBatch,
    outcomes: &[Option<eliot_store_api::WriteReceiptStatus>],
) -> eliot_watchdog_core::WatchdogSpoolAcknowledgement {
    let mut dispositions = Vec::with_capacity(batch.entries.len());
    for (index, entry) in batch.entries.iter().enumerate() {
        let outcome = outcomes.get(index).copied().flatten();
        let is_gap_like = matches!(
            entry.payload_kind,
            eliot_watchdog_core::WatchdogSpoolPayloadKind::Gap
                | eliot_watchdog_core::WatchdogSpoolPayloadKind::Recovery
        );
        let disposition =
            if is_gap_like && outcome == Some(eliot_store_api::WriteReceiptStatus::Committed) {
                gap_requires_recovery()
            } else {
                sink_disposition_for_canonical_outcome(outcome)
            };
        dispositions.push(eliot_watchdog_core::WatchdogSpoolEntryDisposition {
            sequence: entry.sequence,
            disposition,
            record_digest: entry.record_digest.clone(),
        });
    }
    acknowledgement_for_batch(batch, dispositions)
}

/// Builds the honest store-unavailable acknowledgement for the durable stage:
/// every entry reports `Durable` (stored without admission). It never
/// advances the cursor; the Watchdog owner refuses it as non-terminal and the
/// batch stays replayable.
pub fn durable_acknowledgement_for_batch(
    batch: &eliot_watchdog_core::WatchdogSpoolExportBatch,
) -> eliot_watchdog_core::WatchdogSpoolAcknowledgement {
    let dispositions = batch
        .entries
        .iter()
        .map(|entry| eliot_watchdog_core::WatchdogSpoolEntryDisposition {
            sequence: entry.sequence,
            disposition: eliot_watchdog_core::WatchdogSpoolSinkDisposition::Durable,
            record_digest: entry.record_digest.clone(),
        })
        .collect();
    acknowledgement_for_batch(batch, dispositions)
}

/// Builds the honest store-unavailable acknowledgement for the unknown stage:
/// every entry reports `Unknown`. It fails acknowledgement validation
/// (`UnknownOutcome`) so the cursor stays unchanged and the batch stays
/// replayable.
pub fn unknown_acknowledgement_for_batch(
    batch: &eliot_watchdog_core::WatchdogSpoolExportBatch,
) -> eliot_watchdog_core::WatchdogSpoolAcknowledgement {
    let dispositions = batch
        .entries
        .iter()
        .map(|entry| eliot_watchdog_core::WatchdogSpoolEntryDisposition {
            sequence: entry.sequence,
            disposition: eliot_watchdog_core::WatchdogSpoolSinkDisposition::Unknown,
            record_digest: entry.record_digest.clone(),
        })
        .collect();
    acknowledgement_for_batch(batch, dispositions)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::sync::{Arc, Mutex};

    use eliot_contracts::{
        ClockReading, EpochId, EpochLineageId, OperationId, ProductId, RequestId, RequestMetadata,
        ResourceGeneration, SessionId, SourceId,
    };
    use eliot_governor::{
        GovernorComposition, GovernorGenesisOwnerRecord, GovernorGenesisRequest,
        KernelDurableJobPort, KernelGenerationExpectation, KernelGenerationSnapshot,
        KernelGenerationSnapshotProvider, KernelNamedReadReply, KernelNamedReadRequest,
        KernelPortError, KernelPortFuture, KernelRecoveryPort, KernelServiceObservationPort,
        KernelServiceRecovery, QueueLimits, RecoveryOwner, ServiceObservation,
    };
    use eliot_store_api::{
        CommitId, OrderingHeadExpectation, PreparedTransition, Resubmission,
        RevisionHeadExpectation, ScopeId, ScopeRevisionView, StoreHealth, WriteReceipt,
        WriteReceiptStatus, issue_store_receipt_envelope, validate_store_receipt_envelope,
    };

    fn fixture_digest(byte: u8) -> String {
        format!("{byte:02x}").repeat(32)
    }

    fn fixture_batch() -> eliot_watchdog_core::WatchdogSpoolExportBatch {
        let predecessor = eliot_watchdog_core::WatchdogSpoolCursor {
            schema_version: 1,
            acknowledged_sequence: 0,
            watchdog_generation: 7,
            watchdog_epoch: 3,
            installation_id: "installation-test".to_owned(),
            sink_id: "sink-test".to_owned(),
        };
        eliot_watchdog_core::WatchdogSpoolExportBatch {
            schema_version: 1,
            batch_id: "batch-test-1".to_owned(),
            installation_id: "installation-test".to_owned(),
            watchdog_generation: 7,
            watchdog_epoch: 3,
            predecessor_cursor: predecessor,
            first_sequence: 1,
            last_sequence: 2,
            high_water_sequence: 2,
            entries: vec![
                eliot_watchdog_core::WatchdogSpoolExportEntry {
                    sequence: 1,
                    schema_version: 1,
                    observed_at_ms: 1_000,
                    payload_kind: eliot_watchdog_core::WatchdogSpoolPayloadKind::Heartbeat,
                    payload_digest: fixture_digest(0x0c),
                    record_digest: fixture_digest(0x0d),
                },
                eliot_watchdog_core::WatchdogSpoolExportEntry {
                    sequence: 2,
                    schema_version: 1,
                    observed_at_ms: 1_001,
                    payload_kind: eliot_watchdog_core::WatchdogSpoolPayloadKind::Gap,
                    payload_digest: fixture_digest(0x0e),
                    record_digest: fixture_digest(0x0f),
                },
            ],
            item_count: 2,
            byte_size: 128,
            batch_digest: fixture_digest(0x0b),
            is_empty_batch: false,
            created_at_ms: 1_000,
            expires_at_ms: 2_000,
        }
    }

    #[test]
    fn forwards_heartbeat_and_gap_with_durable_unknown_branches() {
        let batch = fixture_batch();
        let ack = forward_watchdog_batch(
            &batch,
            &[
                Some(eliot_store_api::WriteReceiptStatus::Committed),
                Some(eliot_store_api::WriteReceiptStatus::Committed),
            ],
        );
        assert_eq!(ack.batch_id, batch.batch_id);
        assert_eq!(ack.batch_digest, batch.batch_digest);
        assert_eq!(
            ack.predecessor_sequence,
            batch.predecessor_cursor.acknowledged_sequence
        );
        assert_eq!(ack.first_sequence, batch.first_sequence);
        assert_eq!(ack.last_sequence, batch.last_sequence);
        assert_eq!(ack.sink_id, batch.predecessor_cursor.sink_id);
        assert_eq!(ack.dispositions.len(), 2);
        assert_eq!(
            ack.dispositions[0].disposition,
            eliot_watchdog_core::WatchdogSpoolSinkDisposition::Applied
        );
        assert_eq!(
            ack.dispositions[1].disposition,
            eliot_watchdog_core::WatchdogSpoolSinkDisposition::GapRequiresRecovery
        );

        let unknown = forward_watchdog_batch(&batch, &[None, None]);
        assert!(unknown.dispositions.iter().all(|line| {
            line.disposition == eliot_watchdog_core::WatchdogSpoolSinkDisposition::Unknown
        }));

        let durable = durable_acknowledgement_for_batch(&batch);
        assert!(durable.dispositions.iter().all(|line| {
            line.disposition == eliot_watchdog_core::WatchdogSpoolSinkDisposition::Durable
        }));

        let unknown_stage = unknown_acknowledgement_for_batch(&batch);
        assert!(unknown_stage.dispositions.iter().all(|line| {
            line.disposition == eliot_watchdog_core::WatchdogSpoolSinkDisposition::Unknown
        }));
    }

    /// Minimal neutral Kernel port behind a real Governor composition.
    ///
    /// Recovery serves the all-absent genesis branch: `named_read` returns
    /// `None` until `initialize_governor_genesis` stores the exact genesis
    /// packet records, which are then served back verbatim. Transitions
    /// execute through the real store-receipt envelope contract, so the
    /// Governor admission under test commits exactly like production.
    struct GenesisKernel {
        snapshot: KernelGenerationSnapshot,
        genesis: Mutex<Option<BTreeMap<RecoveryOwner, GovernorGenesisOwnerRecord>>>,
        committed: Mutex<BTreeMap<String, (String, String, WriteReceipt)>>,
        apply_calls: Mutex<u64>,
    }

    impl GenesisKernel {
        fn apply_count(&self) -> u64 {
            *self.apply_calls.lock().expect("apply lock")
        }
    }

    /// Rejects identity/transition binding and head mismatches like the
    /// neutral port contract requires, before any test receipt is issued.
    fn check_test_bindings(
        identity: &eliot_protocol::RequestIdentity,
        transition: &PreparedTransition,
        expected_revision_heads: &[RevisionHeadExpectation],
        expected_ordering_heads: &[OrderingHeadExpectation],
    ) -> Result<(), KernelPortError> {
        identity
            .validate()
            .map_err(|error| KernelPortError::Contract(error.to_string()))?;
        transition
            .validate()
            .map_err(|error| KernelPortError::Contract(error.to_string()))?;
        if identity.request.metadata.state_fence != transition.state_fence
            || identity.request.state_fence != transition.state_fence
        {
            return Err(KernelPortError::Contract(
                "test gateway: identity fence does not match transition".to_owned(),
            ));
        }
        if identity.idempotency_key != transition.identity.idempotency_key {
            return Err(KernelPortError::Contract(
                "test gateway: identity idempotency does not match transition".to_owned(),
            ));
        }
        for head in expected_revision_heads {
            head.validate()
                .map_err(|error| KernelPortError::Contract(error.to_string()))?;
            if head.state_fence != transition.state_fence {
                return Err(KernelPortError::Contract(
                    "test gateway: revision head fence mismatch".to_owned(),
                ));
            }
        }
        for head in expected_ordering_heads {
            head.validate()
                .map_err(|error| KernelPortError::Contract(error.to_string()))?;
            if head.state_fence != transition.state_fence {
                return Err(KernelPortError::Contract(
                    "test gateway: ordering head fence mismatch".to_owned(),
                ));
            }
        }
        Ok(())
    }

    impl KernelGenerationSnapshotProvider for GenesisKernel {
        fn snapshot(&self) -> &KernelGenerationSnapshot {
            &self.snapshot
        }
    }

    impl KernelTransitionPort for GenesisKernel {
        fn apply_prepared<'a>(
            &'a self,
            identity: &eliot_protocol::RequestIdentity,
            transition: PreparedTransition,
            expected_revision_heads: Vec<RevisionHeadExpectation>,
            expected_ordering_heads: Vec<OrderingHeadExpectation>,
        ) -> KernelPortFuture<'a, WriteReceipt> {
            let identity = identity.clone();
            Box::pin(async move {
                check_test_bindings(
                    &identity,
                    &transition,
                    &expected_revision_heads,
                    &expected_ordering_heads,
                )?;
                let key = transition.identity.operation_id.as_str().to_owned();
                let hash = transition.identity.canonical_request_hash.clone();
                let mut committed = self.committed.lock().expect("committed lock");
                if let Some((_, stored_hash, receipt)) = committed.get(&key) {
                    if *stored_hash == hash {
                        return Ok(receipt.clone());
                    }
                    return Err(KernelPortError::Contract(
                        "test gateway: committed operation identity conflict".to_owned(),
                    ));
                }
                let sequence = u64::try_from(committed.len())
                    .map_err(|error| KernelPortError::Contract(error.to_string()))?
                    + 1;
                let operation_id = transition.identity.operation_id.clone();
                let candidate = WriteReceipt {
                    operation_id: operation_id.clone(),
                    idempotency_key: transition.identity.idempotency_key.clone(),
                    canonical_request_hash: hash.clone(),
                    transition_class: transition.transition_class,
                    status: WriteReceiptStatus::Committed,
                    commit_id: Some(
                        CommitId::new(format!("commit-{operation_id}"))
                            .map_err(|error| KernelPortError::Contract(error.to_string()))?,
                    ),
                    state_fence: transition.state_fence.clone(),
                    ordering_sequences: Vec::new(),
                    revision_before_after: Vec::new(),
                    applied_command_ids: vec!["cmd-1".to_owned()],
                    emitted_event_ids: Vec::new(),
                    projection_refs: Vec::new(),
                    outbox_refs: Vec::new(),
                    operation_manifest_digest: transition.operation_manifest_digest.clone(),
                    error_code: None,
                    resubmission: Resubmission::None,
                    committed_at: Some(format!("commit-sequence-{sequence:016}")),
                    envelope: None,
                };
                candidate
                    .validate()
                    .map_err(|error| KernelPortError::Contract(error.to_string()))?;
                let envelope = issue_store_receipt_envelope(
                    &identity.request.metadata,
                    &transition,
                    &candidate,
                    sequence,
                )
                .map_err(|error| KernelPortError::Contract(error.to_string()))?;
                let mut receipt = candidate;
                receipt.envelope = Some(envelope);
                validate_store_receipt_envelope(&identity.request.metadata, &transition, &receipt)
                    .map_err(|error| KernelPortError::Contract(error.to_string()))?;
                *self.apply_calls.lock().expect("apply lock") += 1;
                committed.insert(
                    key,
                    (
                        transition.identity.idempotency_key.clone(),
                        hash,
                        receipt.clone(),
                    ),
                );
                Ok(receipt)
            })
        }

        fn receipt(&self, operation_id: OperationId) -> KernelPortFuture<'_, Option<WriteReceipt>> {
            Box::pin(async move {
                Ok(self
                    .committed
                    .lock()
                    .expect("committed lock")
                    .get(operation_id.as_str())
                    .map(|(_, _, receipt)| receipt.clone()))
            })
        }

        fn health(&self) -> KernelPortFuture<'_, StoreHealth> {
            Box::pin(async { Err(KernelPortError::NotAdmitted("test port".to_owned())) })
        }
    }

    impl KernelRecoveryPort for GenesisKernel {
        fn named_read(
            &self,
            request: KernelNamedReadRequest,
        ) -> Result<Option<KernelNamedReadReply>, KernelPortError> {
            let genesis = self.genesis.lock().expect("genesis lock");
            match genesis
                .as_ref()
                .and_then(|records| records.get(&request.owner))
            {
                None => Ok(None),
                Some(record) => Ok(Some(KernelNamedReadReply {
                    owner: request.owner,
                    state_fence: request.state_fence,
                    revision: record.revision,
                    schema: record.schema.clone(),
                    payload: record.payload.clone(),
                    value_digest: record.value_digest.clone(),
                })),
            }
        }

        fn initialize_governor_genesis(
            &self,
            request: &GovernorGenesisRequest,
        ) -> Result<(), KernelPortError> {
            request
                .validate(
                    &self.snapshot.state_fence(),
                    &self.snapshot.protected_snapshot_digest,
                )
                .map_err(|error| KernelPortError::Contract(error.to_string()))?;
            let mut genesis = self.genesis.lock().expect("genesis lock");
            if genesis.is_none() {
                genesis.replace(
                    request
                        .owner_records
                        .iter()
                        .map(|record| (record.owner, record.clone()))
                        .collect(),
                );
            }
            Ok(())
        }

        fn canonical_scope(
            &self,
            state_fence: &eliot_contracts::StateFence,
            _protected_snapshot_digest: &str,
        ) -> Result<ScopeRevisionView, KernelPortError> {
            Ok(ScopeRevisionView {
                scope_id: ScopeId::new("governor").expect("scope"),
                revision_heads: Vec::new(),
                ordering_heads: Vec::new(),
                state_fence: state_fence.clone(),
            })
        }

        fn receipts(
            &self,
            _state_fence: &eliot_contracts::StateFence,
            _protected_snapshot_digest: &str,
        ) -> Result<Vec<WriteReceipt>, KernelPortError> {
            Ok(Vec::new())
        }

        fn durable_jobs(
            &self,
            _state_fence: &eliot_contracts::StateFence,
            _protected_snapshot_digest: &str,
        ) -> Result<Vec<eliot_maintenance::MaintenanceJob>, KernelPortError> {
            Ok(Vec::new())
        }
    }

    impl KernelServiceObservationPort for GenesisKernel {
        fn services(
            &self,
            state_fence: &eliot_contracts::StateFence,
            _protected_snapshot_digest: &str,
        ) -> Result<Vec<KernelServiceRecovery>, KernelPortError> {
            Ok(eliot_governor::STARTUP_ORDER
                .into_iter()
                .map(|service| KernelServiceRecovery {
                    service,
                    observation: ServiceObservation {
                        state: eliot_runtime_contracts::ServiceProcessState::Ready,
                        health: eliot_runtime_contracts::HealthVector::healthy(),
                        generation: state_fence.resource_generation,
                        authority_epoch: state_fence.authority_epoch.clone(),
                    },
                })
                .collect())
        }
    }

    impl KernelDurableJobPort for GenesisKernel {
        fn load_durable_job(
            &self,
            _job_id: &str,
            _state_fence: &eliot_contracts::StateFence,
        ) -> Result<Option<eliot_maintenance::MaintenanceJob>, KernelPortError> {
            Ok(None)
        }

        fn save_durable_job(
            &self,
            _job: &eliot_maintenance::MaintenanceJob,
        ) -> Result<(), KernelPortError> {
            Ok(())
        }
    }

    /// The async watchdog forwarder admits a real export batch through a real
    /// Governor composition and maps the canonical outcomes to the sink
    /// acknowledgement: heartbeat to `Applied`, gap to `GapRequiresRecovery`.
    #[tokio::test]
    async fn forwards_watchdog_batch_through_governor_admission() {
        use eliot_protocol::RequestIdentity;
        use eliot_receipts::RequestBinding;

        let snapshot = KernelGenerationSnapshot {
            service: "eliot-kernel".to_owned(),
            protocol: "eliot.kernel.v1".to_owned(),
            generation: ResourceGeneration::genesis(),
            authority_epoch: EpochId::new(
                EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000")
                    .expect("valid test lineage"),
                std::num::NonZeroU64::new(1).expect("nonzero test sequence"),
            )
            .expect("valid test epoch"),
            artifact_digest: "a".repeat(64),
            protected_snapshot_digest: "b".repeat(64),
            principal: "S-1-5-18".to_owned(),
        };
        let expected = KernelGenerationExpectation::from_snapshot(&snapshot).expect("expectation");
        let kernel = Arc::new(GenesisKernel {
            snapshot,
            genesis: Mutex::new(None),
            committed: Mutex::new(BTreeMap::new()),
            apply_calls: Mutex::new(0),
        });
        let fence = kernel.snapshot.state_fence();
        let kernel_handle = Arc::clone(&kernel);
        let composition = GovernorComposition::new(kernel, None, &expected, QueueLimits::default())
            .expect("genesis composition is ready");
        let metadata = RequestMetadata {
            request_id: RequestId::new("req-watchdog-wave-c-1").expect("request id"),
            session_id: Some(SessionId::new("session-watchdog-wave-c-1").expect("session")),
            task_id: None,
            product_id: ProductId::new("test-product").expect("product"),
            source_id: SourceId::new("agent-bridge").expect("source"),
            state_fence: fence.clone(),
            clock: ClockReading::default(),
        };
        let identity = RequestIdentity {
            request: RequestBinding {
                metadata,
                state_fence: fence,
            },
            idempotency_key: "idem-watchdog-wave-c-1".to_owned(),
            deadline_unix_ms: 1_800_000_000_000,
            cancellation_id: "cancel-watchdog-wave-c-1".to_owned(),
        };
        let forwarder =
            ForwardingObservationReconciliation::new(composition.observation_reconciliation());
        let base = OperationId::new("op-watchdog-wave-c-1").expect("base operation");
        let batch = fixture_batch();
        let ack = forwarder
            .admit_watchdog_batch(&identity, &base, &batch)
            .await
            .expect("watchdog batch forwards through Governor admission");
        assert_eq!(kernel_handle.apply_count(), 2);
        assert_eq!(ack.batch_id, batch.batch_id);
        assert_eq!(ack.batch_digest, batch.batch_digest);
        assert_eq!(
            ack.predecessor_sequence,
            batch.predecessor_cursor.acknowledged_sequence
        );
        assert_eq!(ack.first_sequence, batch.first_sequence);
        assert_eq!(ack.last_sequence, batch.last_sequence);
        assert_eq!(ack.sink_id, batch.predecessor_cursor.sink_id);
        assert_eq!(ack.dispositions.len(), 2);
        assert_eq!(
            ack.dispositions[0].disposition,
            eliot_watchdog_core::WatchdogSpoolSinkDisposition::Applied
        );
        assert_eq!(
            ack.dispositions[1].disposition,
            eliot_watchdog_core::WatchdogSpoolSinkDisposition::GapRequiresRecovery
        );
    }
}
