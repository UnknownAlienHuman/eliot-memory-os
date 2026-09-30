//! Watchdog spool export driver: one bounded export through a sink acknowledgement.
//!
//! Architecture: ARCH-MOD-01, ARCH-MOD-02, ARCH-WDG-01.
//! Implementation: I8.1, I8.2, I2.23.
//! Wave C of the spool export decomposition (spool export through Governor
//! admission). The Watchdog owns the spool records and the export cursor; the
//! sink owns only its per-entry dispositions and never deletes, mutates, or
//! compacts source records. Cursor semantics stay with the Governor lane
//! (`admit_watchdog_batch`) and the owner-neutral core; this driver chains the
//! exact export, acknowledgement, and compaction calls without adding
//! transport, admission, canonical-store, or semantic authority. There is no
//! process execution, executor, or child-launch path here by construction.
//!
//! Spool-local intents are ordinary covered records of this window, not a
//! parked boundary: the fenced Kernel `watchdog-spool-batch-v1` intent route
//! reconciles each one, and the Watchdog keeps the original record (compaction
//! never removes an intent) so the Kernel record and the Governor's later
//! canonical Problem/Incident decision stay forensically linked to it.

use eliot_contracts::{
    ArtifactId, ClockReading, ContractId, ContractVersion, ProductId, RequestId, RequestMetadata,
    SourceId, canonical_json_bytes, sha256_hex,
};
use eliot_protocol::{
    ClientHello, EliotPipeName, EncodingProfile, Frame, FrameKind, MessageType, ProtocolPayload,
    ProtocolRange, ProtocolVersion, WATCHDOG_SPOOL_BATCH_ROUTE,
    WATCHDOG_SPOOL_INTENT_BATCH_WIRE_ID, WatchdogIntentKind, WatchdogSpoolIntentBatchPayload,
    WatchdogSpoolIntentSubmission, watchdog_intent_reconciliation_idempotency_key,
};
use eliot_runtime_contracts::{
    ModuleContract, ModuleGeneration, ModuleGenerationState, VerifiedSupervisionLease,
};
use eliot_watchdog_core::{
    WatchdogSpoolAcknowledgement, WatchdogSpoolExportBatch, WatchdogSpoolPayloadKind,
    validate_batch, validate_batch_freshness,
};

use crate::watchdog_spool::intent::{
    IntentSubmissionDisposition, PendingWatchdogIntent, WatchdogIntentSubmission,
};
use crate::watchdog_spool::publication::WatchdogPublicationClass;
use crate::{
    IndependentKernelSensor, SERVICE_NAME, SpoolError, WatchdogSpoolExportLimits, current_unix_ms,
};

const WATCHDOG_FRONT_DOOR_MODULE_ID: &str = "eliot-watchdog";

/// Pure admission-entry projection of one export batch, in batch order.
///
/// Positions mirror the Governor admission view field-for-field: sequence,
/// kind, record digest, payload digest, observed timestamp. The kind is the
/// owner-neutral core payload class; the Governor lane maps it 1:1 onto its
/// own admission kind without a Watchdog dependency from this crate.
pub type WatchdogEntryView = (u64, WatchdogSpoolPayloadKind, String, String, u64);

/// Transport-agnostic sink for one Watchdog spool export batch.
///
/// The real Kernel/EBP plus Governor adapter implements this trait in the
/// Governor lane; this crate ships no transport client. The fake sink lives
/// only in tests: production [`export_once`] takes a real implementation.
pub trait WatchdogExportSink {
    /// Returns the bound sink identity for this export contour.
    ///
    /// The identity becomes the export predecessor cursor sink, so every
    /// acknowledgement the sink returns must echo it back; any divergence
    /// fails closed in the spool owner without writing.
    fn sink_id(&self) -> &str;

    /// Submits one immutable batch and returns its complete acknowledgement.
    ///
    /// The acknowledgement must echo the exact batch identity (id, digest,
    /// predecessor, range, sink, generation, epoch, installation) with
    /// per-entry digest coverage for every covered entry. Store-unavailable
    /// stages are expressed honestly as `Durable` or `Unknown` dispositions
    /// inside the returned acknowledgement — never as an error — so the spool
    /// owner refuses them as non-terminal, the cursor stays put, and the batch
    /// stays replayable.
    ///
    /// # Errors
    ///
    /// Returns [`SpoolError`] only when the sink cannot form an
    /// acknowledgement at all (for example a sink-side encoding fault).
    /// Transport outages with a known stage must still return an
    /// acknowledgement carrying that stage, not an error.
    fn submit(
        &self,
        batch: &WatchdogSpoolExportBatch,
    ) -> Result<WatchdogSpoolAcknowledgement, SpoolError>;
}

/// Drives one bounded spool export through the sink acknowledgement.
///
/// The chain is exactly: `export_spool_batch(sink.sink_id(), limits)` over the
/// Watchdog-owned spool, then `sink.submit(batch)`, then
/// `apply_spool_acknowledgement(&batch, &ack)`, then
/// `compact_spool_below_cursor` over the new cursor. An empty spool
/// short-circuits after the read-only export: the sink is never submitted to
/// (the core refuses cursor advance over an empty batch) and the current
/// acknowledged sequence is returned unchanged.
///
/// A failing acknowledgement fails closed inside the spool owner: `Received`,
/// `Durable`, `AdmittedCandidate`, and `Unknown` dispositions never advance
/// the cursor, so the error propagates, nothing compacts, and the exact batch
/// stays replayable. A duplicate acknowledgement returns the stored sequence
/// unchanged without writing, followed by the idempotent compaction no-op. A
/// compaction failure after a successful acknowledgement propagates as an
/// error even though the cursor has advanced; the leftover prefix stays
/// compactable because every later export compacts below its own cursor.
///
/// There is no semantic interpretation here and no canonical store write.
/// Cursor-advance validation stays with the Watchdog owner on every step.
///
/// # Errors
///
/// Returns [`SpoolError`] when the bounded export window is unusable, the sink
/// cannot acknowledge, the acknowledgement is forged, expired, non-terminal,
/// or mismatched, or compaction below the advanced cursor fails validation.
pub fn export_once(
    sensor: &IndependentKernelSensor,
    sink: &impl WatchdogExportSink,
    limits: WatchdogSpoolExportLimits,
) -> Result<u64, SpoolError> {
    let batch = sensor.export_spool_batch(sink.sink_id(), limits)?;
    if batch.is_empty_batch {
        return Ok(batch.predecessor_cursor.acknowledged_sequence);
    }
    let acknowledgement = sink.submit(&batch)?;
    let advanced = sensor.apply_spool_acknowledgement(&batch, &acknowledgement)?;
    sensor.compact_spool_below_cursor(advanced)?;
    Ok(advanced)
}

/// Projects one export batch onto pure admission-entry views, in batch order.
///
/// Positions mirror the Governor admission view: sequence, payload kind,
/// record digest, payload digest, observed timestamp. The projection carries
/// no sink identity and performs no I/O; the Governor-lane adapter maps each
/// view onto its admission entry and each canonical outcome back onto the
/// terminal sink disposition for its payload kind. A spool-local intent is
/// projected like any other record: only the fenced Kernel intent route may
/// turn one into a pending intent projection.
#[must_use]
pub fn watchdog_entry_views(batch: &WatchdogSpoolExportBatch) -> Vec<WatchdogEntryView> {
    batch
        .entries
        .iter()
        .map(|entry| {
            (
                entry.sequence,
                entry.payload_kind,
                entry.record_digest.clone(),
                entry.payload_digest.clone(),
                entry.observed_at_ms,
            )
        })
        .collect()
}

/// Handoff spelling of [`watchdog_entry_views`] for the RECHECK-0914 item text.
///
/// Delegates exactly; new callers prefer [`watchdog_entry_views`].
#[must_use]
pub fn watchog_entry_views(batch: &WatchdogSpoolExportBatch) -> Vec<WatchdogEntryView> {
    watchdog_entry_views(batch)
}

/// Kernel acknowledgement of one fenced Watchdog intent submission.
///
/// The acknowledgement proves only that the fenced Kernel intent route
/// recorded a pending intent projection for the exact retained spool record
/// under the exact reconciliation key. It is not a canonical Problem or
/// Incident decision: the Governor performs that transition later, and the
/// Watchdog's own record stays retained for forensic linkage either way.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WatchdogIntentAcknowledgement {
    /// Retained spool sequence the fenced route recorded.
    pub sequence: u64,
    /// Responding sink identity echoed by the fenced route.
    pub sink_id: String,
    /// Reconciliation key the fenced route derived for the record.
    pub idempotency_key: String,
    /// Digest over the exact acknowledgement the fenced route returned.
    pub acknowledgement_digest: String,
}

/// Owner-generated spool export window plus the still-pending intent records
/// covered by that exact window.
///
/// The export envelope remains intact so a Kernel client can carry its real
/// predecessor, full-window range, high-water, identity, digest, and freshness
/// bounds. The intent list is only a projection of records inside the window;
/// non-intent records still contribute to the owner-computed export digest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WatchdogIntentExportBatch {
    export_batch: WatchdogSpoolExportBatch,
    intents: Vec<PendingWatchdogIntent>,
}

impl WatchdogIntentExportBatch {
    /// Returns the complete owner-generated spool window envelope.
    #[must_use]
    pub fn export_batch(&self) -> &WatchdogSpoolExportBatch {
        &self.export_batch
    }

    /// Returns pending intent records covered by `export_batch`.
    #[must_use]
    pub fn intents(&self) -> &[PendingWatchdogIntent] {
        &self.intents
    }

    /// Revalidates the exact export envelope and its record-level joins before
    /// a transport adapter is allowed to use it.
    fn validate(&self, now_ms: u64) -> Result<(), SpoolError> {
        validate_batch(&self.export_batch, self.export_batch.high_water_sequence)?;
        validate_batch_freshness(&self.export_batch, now_ms)?;
        if self.intents.is_empty() {
            return Err(SpoolError::Corrupt(
                "watchdog intent export window contains no pending intent".to_owned(),
            ));
        }
        let mut previous_sequence = None;
        for pending in &self.intents {
            let sequence = pending.record.sequence;
            if sequence < self.export_batch.first_sequence
                || sequence > self.export_batch.last_sequence
                || previous_sequence.is_some_and(|previous| sequence <= previous)
            {
                return Err(SpoolError::Corrupt(
                    "watchdog intent export window has an out-of-range or unordered record"
                        .to_owned(),
                ));
            }
            previous_sequence = Some(sequence);

            let raw = super::encode_entry(&pending.record)?;
            let (payload_digest, record_digest) =
                super::export_record_digests(&pending.record, &raw);
            if payload_digest != pending.payload_digest || record_digest != pending.record_digest {
                return Err(SpoolError::Corrupt(
                    "watchdog intent export window digest does not match the retained record"
                        .to_owned(),
                ));
            }
            let expected_class =
                super::intent::WatchdogIntentClass::of_payload(&pending.record.payload)?;
            if expected_class != pending.intent_class {
                return Err(SpoolError::Corrupt(
                    "watchdog intent export window class does not match the retained record"
                        .to_owned(),
                ));
            }
            let exported = self
                .export_batch
                .entries
                .iter()
                .find(|entry| entry.sequence == sequence)
                .ok_or_else(|| {
                    SpoolError::Corrupt(
                        "watchdog intent export window omits a pending retained record".to_owned(),
                    )
                })?;
            if exported.schema_version != pending.record.schema_version
                || exported.observed_at_ms != pending.record.observed_at_ms
                || exported.payload_kind != WatchdogSpoolPayloadKind::Recovery
                || exported.payload_digest != pending.payload_digest
                || exported.record_digest != pending.record_digest
            {
                return Err(SpoolError::Corrupt(
                    "watchdog intent export entry diverges from the retained record".to_owned(),
                ));
            }
        }
        Ok(())
    }
}

/// Transport-agnostic fenced Kernel route for one Watchdog intent submission.
///
/// The production EBP client below implements this trait against the admitted
/// `watchdog-spool-batch-v1` Kernel route. It presents the exact original
/// record, evidence, and lineage through a fenced Kernel mutation, then lets
/// the owner persist its submit-once receipt from the correlated response.
/// This side makes no semantic interpretation.
pub trait WatchdogIntentSink {
    /// Returns the bound sink identity this reconciliation contour uses.
    ///
    /// The identity becomes the export predecessor cursor sink, so it must be
    /// the exact sink the acknowledgement echoes.
    fn sink_id(&self) -> &str;

    /// Submits pending intents from one immutable owner-generated export window
    /// through the fenced Kernel route.
    ///
    /// `supervision_lease_id` is the exact lease the Watchdog last verified; the
    /// fenced route resolves it against its own retained supervision authority,
    /// so a submission naming a lease the Kernel does not hold is fenced. The
    /// batch carries the exact spool owner's predecessor, full covered range,
    /// high-water, identity, digest, and freshness window. Its intent projection
    /// carries each original record's bytes and the Watchdog's own epoch lineage;
    /// non-intent entries remain bound by the owner-computed batch digest. The
    /// route re-derives the reconciliation key and the record digests and fences on
    /// any presented value it cannot reproduce.
    ///
    /// A transport outage with an unknown stage must be reported as an error and
    /// must never be reported as an acknowledgement: the submit-once receipt is
    /// written only for a real acknowledgement, so a lost acknowledgement
    /// replays instead of skipping.
    ///
    /// # Errors
    ///
    /// Returns [`SpoolError`] when the submission cannot be delivered or the
    /// fenced route cannot form an acknowledgement at all.
    fn submit_intent(
        &self,
        supervision_lease_id: &str,
        batch: &WatchdogIntentExportBatch,
    ) -> Result<Vec<WatchdogIntentAcknowledgement>, SpoolError>;

    /// Submits retained Signal-linked publication records from one immutable
    /// owner-generated export window through the same fenced route.
    ///
    /// This is a separate entry point rather than an overloading of
    /// [`Self::submit_intent`] so the two windows keep their own validated
    /// envelope types. What it does **not** do is keep a separate protocol: both
    /// windows present the same `watchdog-spool-intent-batch` payload, the same
    /// `watchdog-spool-batch-v1` route, the same shared idempotency-key
    /// derivation, and the same `watchdog_intent_submit` capability. One
    /// admitted route with one exactly-once ledger is what makes a lost
    /// acknowledgement resumable across both intent classes; a second route or a
    /// second key scheme would leave one of them able to duplicate.
    ///
    /// Every requirement of [`Self::submit_intent`] applies here unchanged,
    /// including the refusal to report a transport outage with an unknown stage
    /// as an acknowledgement.
    ///
    /// # Errors
    ///
    /// Returns [`SpoolError`] when the submission cannot be delivered or the
    /// fenced route cannot form an acknowledgement at all.
    fn submit_publication(
        &self,
        supervision_lease_id: &str,
        batch: &WatchdogPublicationExportBatch,
    ) -> Result<Vec<WatchdogIntentAcknowledgement>, SpoolError>;
}

/// Authenticated Kernel front-door sink for the Watchdog's retained intent
/// records. The constructor binds every connection to fields in the already
/// verified signed lease; no endpoint, peer identity, or server artifact is
/// accepted from the caller.
pub struct KernelFrontDoorWatchdogIntentSink {
    lease: VerifiedSupervisionLease,
    sink_id: String,
}

impl KernelFrontDoorWatchdogIntentSink {
    /// Binds a stable sink identity and authenticated server expectation to
    /// the exact verified supervision lease.
    #[must_use]
    pub fn new(lease: VerifiedSupervisionLease) -> Self {
        let payload = lease.lease();
        let sink_id = format!(
            "watchdog-kernel-frontdoor:{}:{}",
            payload.installation_id,
            payload.activation_generation.value()
        );
        Self { lease, sink_id }
    }
}

impl WatchdogIntentSink for KernelFrontDoorWatchdogIntentSink {
    fn sink_id(&self) -> &str {
        &self.sink_id
    }

    fn submit_intent(
        &self,
        supervision_lease_id: &str,
        batch: &WatchdogIntentExportBatch,
    ) -> Result<Vec<WatchdogIntentAcknowledgement>, SpoolError> {
        self.check_lease_lineage(supervision_lease_id, batch.export_batch())?;
        let payload = intent_batch_payload(supervision_lease_id, self.sink_id(), batch)?;
        self.deliver_intent_batch(&payload)
    }

    fn submit_publication(
        &self,
        supervision_lease_id: &str,
        batch: &WatchdogPublicationExportBatch,
    ) -> Result<Vec<WatchdogIntentAcknowledgement>, SpoolError> {
        self.check_lease_lineage(supervision_lease_id, batch.export_batch())?;
        // The same payload, route and derivation as the escalation window: one
        // admitted route with one exactly-once ledger over both intent classes.
        let payload = WatchdogSpoolIntentBatchPayload {
            wire_id: WATCHDOG_SPOOL_INTENT_BATCH_WIRE_ID.to_owned(),
            wire_version: WatchdogSpoolIntentBatchPayload::CONTRACT_VERSION,
            route: WATCHDOG_SPOOL_BATCH_ROUTE.to_owned(),
            installation_id: batch.export_batch().installation_id.clone(),
            watchdog_generation: batch.export_batch().watchdog_generation,
            watchdog_epoch: batch.export_batch().watchdog_epoch,
            supervision_lease_id: supervision_lease_id.to_owned(),
            sink_id: self.sink_id().to_owned(),
            predecessor_sequence: batch
                .export_batch()
                .predecessor_cursor
                .acknowledged_sequence,
            first_sequence: batch.export_batch().first_sequence,
            last_sequence: batch.export_batch().last_sequence,
            high_water_sequence: batch.export_batch().high_water_sequence,
            created_at_ms: batch.export_batch().created_at_ms,
            expires_at_ms: batch.export_batch().expires_at_ms,
            batch_id: batch.export_batch().batch_id.clone(),
            batch_digest: batch.export_batch().batch_digest.clone(),
            intents: batch
                .publications()
                .iter()
                .map(|pending| {
                    publication_submission(&batch.export_batch().installation_id, pending)
                })
                .collect::<Result<Vec<_>, SpoolError>>()?,
            payload_sha256: String::new(),
        }
        .with_computed_digest()
        .and_then(|payload| {
            payload.validate()?;
            Ok(payload)
        })
        .map_err(|error| {
            SpoolError::Corrupt(format!("invalid Kernel publication batch: {error}"))
        })?;
        self.deliver_intent_batch(&payload)
    }
}

impl KernelFrontDoorWatchdogIntentSink {
    /// Fails closed unless the presented window continues the exact lineage the
    /// verified lease binds.
    ///
    /// A window naming a different installation, generation or epoch than the
    /// lease the Watchdog actually verified is refused here rather than offered
    /// to the route, so a stale owner never reaches the transport at all.
    ///
    /// # Errors
    ///
    /// Returns [`SpoolError::LeaseFenced`] when any lineage field differs from
    /// the signed lease.
    fn check_lease_lineage(
        &self,
        supervision_lease_id: &str,
        batch: &WatchdogSpoolExportBatch,
    ) -> Result<(), SpoolError> {
        if supervision_lease_id != self.lease.lease().lease_id
            || batch.installation_id != self.lease.lease().installation_id
            || batch.watchdog_generation != self.lease.lease().activation_generation.value()
            || batch.watchdog_epoch != self.lease.lease().watchdog_epoch.value()
        {
            return Err(SpoolError::LeaseFenced(
                "intent batch does not match the signed supervision lease lineage".to_owned(),
            ));
        }
        Ok(())
    }

    /// Delivers one already-validated intent-batch payload through the
    /// authenticated Kernel front door.
    ///
    /// # Errors
    ///
    /// Returns [`SpoolError`] when the authenticated connection cannot be
    /// established, the frame cannot be sent or proven delivered, the response
    /// does not correlate to the submitted request, or the response is not a
    /// known outcome bound to this sink.
    fn deliver_intent_batch(
        &self,
        payload: &WatchdogSpoolIntentBatchPayload,
    ) -> Result<Vec<WatchdogIntentAcknowledgement>, SpoolError> {
        #[cfg(windows)]
        {
            tokio::runtime::Handle::try_current()
                .map_err(|error| {
                    SpoolError::Corrupt(format!("Kernel sink requires Tokio: {error}"))
                })?
                .block_on(transact_intent_batch(&self.lease, payload))
        }
        #[cfg(not(windows))]
        {
            let _ = payload;
            Err(SpoolError::Corrupt(
                "authenticated Kernel front-door transport is available only on Windows".to_owned(),
            ))
        }
    }
}

fn intent_batch_payload(
    supervision_lease_id: &str,
    sink_id: &str,
    batch: &WatchdogIntentExportBatch,
) -> Result<WatchdogSpoolIntentBatchPayload, SpoolError> {
    let export = &batch.export_batch;
    let intents = batch
        .intents
        .iter()
        .map(|pending| intent_batch_submission(&export.installation_id, pending))
        .collect::<Result<Vec<_>, SpoolError>>()?;
    WatchdogSpoolIntentBatchPayload {
        wire_id: WATCHDOG_SPOOL_INTENT_BATCH_WIRE_ID.to_owned(),
        wire_version: WatchdogSpoolIntentBatchPayload::CONTRACT_VERSION,
        route: WATCHDOG_SPOOL_BATCH_ROUTE.to_owned(),
        installation_id: export.installation_id.clone(),
        watchdog_generation: export.watchdog_generation,
        watchdog_epoch: export.watchdog_epoch,
        supervision_lease_id: supervision_lease_id.to_owned(),
        sink_id: sink_id.to_owned(),
        predecessor_sequence: export.predecessor_cursor.acknowledged_sequence,
        first_sequence: export.first_sequence,
        last_sequence: export.last_sequence,
        high_water_sequence: export.high_water_sequence,
        created_at_ms: export.created_at_ms,
        expires_at_ms: export.expires_at_ms,
        batch_id: export.batch_id.clone(),
        batch_digest: export.batch_digest.clone(),
        intents,
        payload_sha256: String::new(),
    }
    .with_computed_digest()
    .and_then(|payload| {
        payload.validate()?;
        Ok(payload)
    })
    .map_err(|error| SpoolError::Corrupt(format!("invalid Kernel intent batch: {error}")))
}

fn intent_batch_submission(
    installation_id: &str,
    pending: &PendingWatchdogIntent,
) -> Result<WatchdogSpoolIntentSubmission, SpoolError> {
    let (
        intent_kind,
        evidence_refs,
        lineage_installation_id,
        lineage_generation,
        lineage_epoch,
        governor_unavailable_reason,
    ) = match &pending.record.payload {
        super::WatchdogSpoolPayload::ProblemIntent {
            evidence_refs,
            lineage_installation_id,
            lineage_generation,
            lineage_epoch,
            governor_unavailable_reason,
            ..
        } => (
            WatchdogIntentKind::ProblemIntent,
            evidence_refs,
            lineage_installation_id,
            *lineage_generation,
            *lineage_epoch,
            serde_json::to_value(governor_unavailable_reason),
        ),
        super::WatchdogSpoolPayload::IncidentIntent {
            evidence_refs,
            lineage_installation_id,
            lineage_generation,
            lineage_epoch,
            governor_unavailable_reason,
            ..
        } => (
            WatchdogIntentKind::IncidentIntent,
            evidence_refs,
            lineage_installation_id,
            *lineage_generation,
            *lineage_epoch,
            serde_json::to_value(governor_unavailable_reason),
        ),
        _ => {
            return Err(SpoolError::Corrupt(
                "pending Watchdog intent no longer has an intent payload".to_owned(),
            ));
        }
    };
    let governor_unavailable_reason = governor_unavailable_reason
        .map_err(|error| SpoolError::Serialization(error.to_string()))?
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| {
            SpoolError::Corrupt(
                "Watchdog intent reason did not serialize as its closed wire code".to_owned(),
            )
        })?;
    Ok(WatchdogSpoolIntentSubmission {
        sequence: pending.record.sequence,
        intent_kind,
        record_digest: pending.record_digest.clone(),
        payload_digest: pending.payload_digest.clone(),
        observed_at_ms: pending.record.observed_at_ms,
        idempotency_key: watchdog_intent_reconciliation_idempotency_key(
            installation_id,
            pending.record.sequence,
            &pending.record_digest,
        ),
        evidence_refs: evidence_refs.clone(),
        lineage_installation_id: lineage_installation_id.clone(),
        lineage_generation,
        lineage_epoch,
        lineage_epoch_id: pending.epoch_lineage.as_str().to_owned(),
        governor_unavailable_reason,
        record: serde_json::to_value(&pending.record)
            .map_err(|error| SpoolError::Serialization(error.to_string()))?,
    })
}

#[cfg(windows)]
async fn transact_intent_batch(
    lease: &VerifiedSupervisionLease,
    payload: &WatchdogSpoolIntentBatchPayload,
) -> Result<Vec<WatchdogIntentAcknowledgement>, SpoolError> {
    use eliot_ipc::{DeliveryOutcome, TransportLimits};

    let signed = lease.lease();
    let connection_id = format!("{}:{}", SERVICE_NAME, signed.lease_id);
    let (mut transport, protocol_version) =
        connect_watchdog_front_door(lease, &connection_id).await?;
    let limits = TransportLimits::default();
    let frame = watchdog_intent_request(lease, payload, &connection_id, protocol_version)?;
    let request_id = frame.request_id.clone().ok_or_else(|| {
        SpoolError::Corrupt("Kernel intent request omitted its request ID".to_owned())
    })?;
    if transport
        .send_frame(&frame, limits)
        .await
        .map_err(|error| SpoolError::LeaseFenced(error.to_string()))?
        != DeliveryOutcome::Delivered
    {
        return Err(SpoolError::LeaseFenced(
            "Kernel intent batch delivery was not proven".to_owned(),
        ));
    }
    let response = transport
        .receive_frame(limits)
        .await
        .map_err(|error| SpoolError::LeaseFenced(error.to_string()))?;
    if response.validate().is_err()
        || response.connection_id != connection_id
        || response.request_id.as_ref() != Some(&request_id)
        || response.kind != FrameKind::Response
        || response.message_type != MessageType::Result
        || response.request_identity.is_some()
    {
        return Err(SpoolError::LeaseFenced(
            "Kernel intent response did not correlate to the submitted batch".to_owned(),
        ));
    }
    let ProtocolPayload::Json(value) = response.payload else {
        return Err(SpoolError::LeaseFenced(
            "Kernel intent response was not JSON".to_owned(),
        ));
    };
    acknowledgements_from_kernel_outcome(&value, payload)
}

#[cfg(windows)]
async fn connect_watchdog_front_door(
    lease: &VerifiedSupervisionLease,
    connection_id: &str,
) -> Result<(eliot_ipc::NamedPipeTransport, ProtocolVersion), SpoolError> {
    use std::time::Duration;

    use eliot_ipc::{DeliveryOutcome, NamedPipeTransport, TransportLimits};
    use eliot_platform_windows::{KernelFrontDoorAclMode, KernelFrontDoorServerExpectation};

    let signed = lease.lease();
    let expectation = KernelFrontDoorServerExpectation::new(
        signed.kernel_front_door_server_sid.as_str(),
        signed.kernel_front_door_session_id,
        signed.kernel_front_door_artifact_sha256.as_str(),
        KernelFrontDoorAclMode::SystemAndLocalServiceWithOptionalUserClient,
    )
    .map_err(|error| SpoolError::LeaseFenced(error.to_string()))?;
    let mut transport = NamedPipeTransport::connect_authenticated_kernel_front_door(
        &EliotPipeName::kernel_frontdoor().to_string(),
        Duration::from_secs(5),
        &expectation,
    )
    .await
    .map_err(|error| SpoolError::LeaseFenced(error.to_string()))?;
    match transport.peer_identity() {
        eliot_ipc::PeerIdentity::Authenticated {
            process_id,
            user_identity,
            session_identity,
            ..
        } if *process_id != 0
            && user_identity == signed.kernel_front_door_server_sid.as_str()
            && session_identity == &signed.kernel_front_door_session_id.to_string() => {}
        _ => {
            return Err(SpoolError::LeaseFenced(
                "authenticated Kernel peer identity differed from the signed front-door lease"
                    .to_owned(),
            ));
        }
    }
    let limits = TransportLimits::default();
    let hello = watchdog_client_hello(lease)?;
    let hello_frame = eliot_ipc::client_hello_frame(connection_id, &hello)
        .map_err(|error| SpoolError::Corrupt(error.to_string()))?;
    if transport
        .send_frame(&hello_frame, limits)
        .await
        .map_err(|error| SpoolError::LeaseFenced(error.to_string()))?
        != DeliveryOutcome::Delivered
    {
        return Err(SpoolError::LeaseFenced(
            "Kernel hello delivery was not proven".to_owned(),
        ));
    }
    let server_frame = transport
        .receive_frame(limits)
        .await
        .map_err(|error| SpoolError::LeaseFenced(error.to_string()))?;
    let server = eliot_ipc::decode_server_hello_frame(&server_frame, connection_id)
        .map_err(|error| SpoolError::LeaseFenced(error.to_string()))?;
    if server.selected_protocol != ProtocolVersion::CURRENT
        || !server
            .authority_epoch
            .is_same_authority(&signed.kernel_epoch)
        || !server
            .allowed_capabilities
            .iter()
            .any(|item| item == "watchdog_intent_submit")
        || server.rejection_reason.is_some()
    {
        return Err(SpoolError::LeaseFenced(
            "Kernel denied the Watchdog intent capability or lease epoch".to_owned(),
        ));
    }
    Ok((transport, server.selected_protocol))
}

#[cfg(windows)]
fn watchdog_intent_request(
    lease: &VerifiedSupervisionLease,
    payload: &WatchdogSpoolIntentBatchPayload,
    connection_id: &str,
    protocol_version: ProtocolVersion,
) -> Result<Frame, SpoolError> {
    use std::collections::BTreeMap;

    let signed = lease.lease();
    let sequence = payload.intents.first().map_or(0, |item| item.sequence);
    let request_id = RequestId::new(format!("watchdog:{}:{sequence}", payload.batch_id))
        .map_err(|error| SpoolError::Corrupt(error.to_string()))?;
    let fence = signed.state_fence.clone();
    let now_ms = crate::current_unix_ms()?.max(1);
    let metadata = RequestMetadata {
        request_id: request_id.clone(),
        session_id: None,
        task_id: None,
        product_id: ProductId::new(SERVICE_NAME)
            .map_err(|error| SpoolError::Corrupt(error.to_string()))?,
        source_id: SourceId::new(SERVICE_NAME)
            .map_err(|error| SpoolError::Corrupt(error.to_string()))?,
        state_fence: fence.clone(),
        clock: ClockReading {
            valid_time_ms: i64::try_from(now_ms).ok(),
            known_time_ms: i64::try_from(now_ms).ok(),
            transaction_sequence: None,
            monotonic_ns: None,
        },
    };
    let identity = eliot_protocol::RequestIdentity {
        request: eliot_receipts::RequestBinding {
            metadata,
            state_fence: fence,
        },
        idempotency_key: format!("watchdog-intent:{}:{sequence}", payload.batch_id),
        deadline_unix_ms: now_ms.saturating_add(10_000),
        cancellation_id: format!("watchdog-intent:{}:{sequence}:cancel", payload.batch_id),
    };
    Ok(Frame {
        protocol_version,
        encoding_profile: EncodingProfile::JsonV1,
        connection_id: connection_id.to_owned(),
        request_id: Some(request_id),
        kind: FrameKind::Request,
        message_type: MessageType::Execute,
        request_identity: Some(identity),
        payload: ProtocolPayload::Json(serde_json::json!({
            "operation": "watchdog_intent_submit",
            "intent_batch": payload,
        })),
        trace_context: BTreeMap::new(),
    })
}

#[cfg(windows)]
fn acknowledgements_from_kernel_outcome(
    outcome: &serde_json::Value,
    payload: &WatchdogSpoolIntentBatchPayload,
) -> Result<Vec<WatchdogIntentAcknowledgement>, SpoolError> {
    if outcome.get("status").and_then(serde_json::Value::as_str) != Some("known") {
        return Err(SpoolError::LeaseFenced(
            "Kernel did not return a known intent outcome".to_owned(),
        ));
    }
    let known = outcome.get("value").ok_or_else(|| {
        SpoolError::LeaseFenced("Kernel known intent outcome omitted its value".to_owned())
    })?;
    if known.get("accepted").and_then(serde_json::Value::as_bool) != Some(true)
        || known.get("sink_id").and_then(serde_json::Value::as_str)
            != Some(payload.sink_id.as_str())
        || outcome.get("recovery") != Some(&serde_json::Value::Null)
    {
        return Err(SpoolError::LeaseFenced("Kernel intent outcome did not affirm the bound sink and non-canonical pending projection".to_owned()));
    }
    let projections = known
        .get("intents")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| {
            SpoolError::LeaseFenced("Kernel intent outcome omitted its projections".to_owned())
        })?;
    if projections.len() != payload.intents.len() {
        return Err(SpoolError::LeaseFenced(
            "Kernel intent outcome coverage differed from submitted records".to_owned(),
        ));
    }
    let acknowledgement_digest = sha256_hex(
        &canonical_json_bytes(outcome).map_err(|error| SpoolError::Corrupt(error.to_string()))?,
    );
    projections
        .iter()
        .zip(&payload.intents)
        .map(|(projection, submitted)| {
            if projection
                .get("sequence")
                .and_then(serde_json::Value::as_u64)
                != Some(submitted.sequence)
                || projection
                    .get("idempotency_key")
                    .and_then(serde_json::Value::as_str)
                    != Some(submitted.idempotency_key.as_str())
                || projection
                    .get("intent_kind")
                    .and_then(serde_json::Value::as_str)
                    != Some(submitted.intent_kind.as_str())
                || projection
                    .get("record_digest")
                    .and_then(serde_json::Value::as_str)
                    != Some(submitted.record_digest.as_str())
                || projection
                    .get("payload_digest")
                    .and_then(serde_json::Value::as_str)
                    != Some(submitted.payload_digest.as_str())
                || projection.get("state").and_then(serde_json::Value::as_str) != Some("ADMITTED")
                || projection
                    .get("operation_id")
                    .and_then(serde_json::Value::as_str)
                    .is_none_or(str::is_empty)
                || projection
                    .get("admitted_now")
                    .and_then(serde_json::Value::as_bool)
                    .is_none()
            {
                return Err(SpoolError::LeaseFenced(
                    "Kernel intent projection did not bind the exact retained record".to_owned(),
                ));
            }
            Ok(WatchdogIntentAcknowledgement {
                sequence: submitted.sequence,
                sink_id: payload.sink_id.clone(),
                idempotency_key: submitted.idempotency_key.clone(),
                acknowledgement_digest: acknowledgement_digest.clone(),
            })
        })
        .collect()
}

#[cfg(windows)]
fn watchdog_client_hello(lease: &VerifiedSupervisionLease) -> Result<ClientHello, SpoolError> {
    let signed = lease.lease();
    let module_id = ContractId::new(WATCHDOG_FRONT_DOOR_MODULE_ID)
        .map_err(|error| SpoolError::Corrupt(error.to_string()))?;
    let artifact_id = ArtifactId::new(signed.kernel_front_door_artifact_sha256.as_str())
        .map_err(|error| SpoolError::Corrupt(error.to_string()))?;
    let contract = watchdog_module_contract(module_id.clone(), artifact_id.clone());
    let generation = ModuleGeneration {
        module_id,
        generation: signed.activation_generation,
        artifact_id,
        state: ModuleGenerationState::Starting,
        health: eliot_runtime_contracts::HealthVector::healthy(),
        state_fence: signed.state_fence.clone(),
    };
    Ok(ClientHello {
        protocol_range: ProtocolRange {
            minimum: ProtocolVersion::CURRENT,
            maximum: ProtocolVersion::CURRENT,
        },
        module_bridge_identity: WATCHDOG_FRONT_DOOR_MODULE_ID.to_owned(),
        artifact_hash: generation.artifact_id.clone(),
        module_contract: contract,
        module_generation: generation,
        launch_nonce: signed.lease_id.clone(),
        capabilities: vec!["watchdog_intent_submit".to_owned()],
        privacy_classes: vec!["PUBLIC".to_owned()],
        max_frame: u32::try_from(eliot_protocol::MAX_FRAME_BYTES)
            .map_err(|error| SpoolError::Corrupt(error.to_string()))?,
        authority_epoch: signed.kernel_epoch.clone(),
    })
}

#[cfg(windows)]
fn watchdog_module_contract(module_id: ContractId, artifact_id: ArtifactId) -> ModuleContract {
    ModuleContract {
        module_id,
        version: ContractVersion::new(1, 0, 0),
        artifact_id,
        protocols: vec![crate::PROTOCOL_VERSION.to_owned()],
        capabilities: Vec::new(),
        required_capabilities: Vec::new(),
        optional_capabilities: Vec::new(),
        advisory_capabilities: Vec::new(),
        state_owner: SERVICE_NAME.to_owned(),
        failure_domain: "watchdog".to_owned(),
        owner: SERVICE_NAME.to_owned(),
        hot_replace: true,
        startup_after: Vec::new(),
        drain_before: Vec::new(),
        invalidation_triggers: Vec::new(),
        supervision_plan: "one_for_one".to_owned(),
        child_restart: "transient".to_owned(),
        restart_intensity: "3/10m".to_owned(),
        resource_profile: "background-medium".to_owned(),
        privacy_classes: vec!["PUBLIC".to_owned()],
        permissions: Vec::new(),
        health_contract: "health/eliot-watchdog-v1".to_owned(),
        checkpoint_contract: "checkpoint/watchdog-v1".to_owned(),
        compatibility_state: "rebuildable".to_owned(),
        independent_test_profile: "module/eliot-watchdog".to_owned(),
        contract_fixture_set: "eliot.watchdog.v1/watchdog".to_owned(),
        affected_test_tags: vec!["eliot-watchdog".to_owned()],
        architecture: Vec::new(),
        telemetry: "telemetry/eliot-watchdog-v1".to_owned(),
        removal_boundary: "eliot-watchdog".to_owned(),
    }
}

/// Owner-generated export window plus the retained records inside it that the
/// admitted owner has not yet taken.
///
/// One window carries both intent classes. That is deliberate: the window's
/// identity, its batch digest and its reconciliation keys are derived by the
/// shared owner, and a publication record that travelled in its own window would
/// need a second exactly-once scheme over the same route. Sharing the window is
/// what makes one lost acknowledgement resumable for both classes under one
/// ledger.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WatchdogPublicationExportBatch {
    export_batch: WatchdogSpoolExportBatch,
    publications: Vec<super::publication::PendingPublication>,
}

impl WatchdogPublicationExportBatch {
    /// Returns the complete owner-generated spool window envelope.
    #[must_use]
    pub fn export_batch(&self) -> &WatchdogSpoolExportBatch {
        &self.export_batch
    }

    /// Returns the retained publication records covered by `export_batch`.
    #[must_use]
    pub fn publications(&self) -> &[super::publication::PendingPublication] {
        &self.publications
    }

    /// Revalidates the exact export envelope and its record-level joins before a
    /// transport adapter is allowed to use it.
    ///
    /// Every retained record is re-encoded and re-digested, its class is re-read
    /// from its own bytes, and the export entry that covers it is compared field
    /// by field. A window whose envelope, digests, class or coverage disagree is
    /// refused here rather than offered to the admitted owner, so a publication
    /// can never be presented under a batch that does not actually contain it.
    ///
    /// # Errors
    ///
    /// Returns [`SpoolError`] when the export envelope is not fresh and
    /// self-consistent, a retained record no longer encodes to the digest the
    /// window binds, a record's class disagrees with the retained bytes, a
    /// sequence is out of the window's range or unordered, or the window carries
    /// no publication at all.
    fn validate(&self, now_ms: u64) -> Result<(), SpoolError> {
        validate_batch(&self.export_batch, self.export_batch.high_water_sequence)?;
        validate_batch_freshness(&self.export_batch, now_ms)?;
        if self.publications.is_empty() {
            return Err(SpoolError::Corrupt(
                "watchdog publication export window contains no retained publication".to_owned(),
            ));
        }
        let mut previous_sequence = None;
        for pending in &self.publications {
            let sequence = pending.record.sequence;
            if sequence < self.export_batch.first_sequence
                || sequence > self.export_batch.last_sequence
                || previous_sequence.is_some_and(|previous| sequence <= previous)
            {
                return Err(SpoolError::Corrupt(
                    "watchdog publication export window has an out-of-range or unordered record"
                        .to_owned(),
                ));
            }
            previous_sequence = Some(sequence);
            let raw = super::encode_entry(&pending.record)?;
            let (payload_digest, record_digest) =
                super::export_record_digests(&pending.record, &raw);
            if payload_digest != pending.payload_digest || record_digest != pending.record_digest {
                return Err(SpoolError::Corrupt(
                    "watchdog publication export window digest does not match the retained record"
                        .to_owned(),
                ));
            }
            if super::publication::WatchdogPublicationClass::of_payload(&pending.record.payload)?
                != pending.publication_class
            {
                return Err(SpoolError::Corrupt(
                    "watchdog publication export window class does not match the retained record"
                        .to_owned(),
                ));
            }
            let exported = self
                .export_batch
                .entries
                .iter()
                .find(|entry| entry.sequence == sequence)
                .ok_or_else(|| {
                    SpoolError::Corrupt(
                        "watchdog publication export window omits a retained record".to_owned(),
                    )
                })?;
            if exported.schema_version != pending.record.schema_version
                || exported.observed_at_ms != pending.record.observed_at_ms
                || exported.payload_kind != WatchdogSpoolPayloadKind::Recovery
                || exported.payload_digest != pending.payload_digest
                || exported.record_digest != pending.record_digest
            {
                return Err(SpoolError::Corrupt(
                    "watchdog publication export entry diverges from the retained record"
                        .to_owned(),
                ));
            }
        }
        Ok(())
    }
}

/// Reconciles one bounded window of retained Signal-linked publication intents
/// through the admitted owner and records their submit-once receipts.
///
/// This is the export half of the Watchdog's Problem/attention route. It reads
/// the retained records the publication owner committed, presents each one
/// verbatim through the same admitted `watchdog-spool-batch-v1` route the
/// escalation intents use, and then persists one receipt per acknowledgement
/// inside `watchdog.redb`. Nothing here interprets an intent, declares a
/// canonical Problem or Incident, or decides that anything was resolved.
///
/// A lost acknowledgement resumes from the retained record under the same
/// identity: the receipt is written only after a real acknowledgement, the
/// idempotency key is the shared derivation over installation, retained sequence
/// and record digest, and the intent identity is read out of the retained bytes
/// rather than regenerated. So a retry presents byte-identical material under an
/// identical key, and a replay of an already-acknowledged record observes the
/// existing receipt instead of presenting a second intent.
///
/// An unavailable canonical owner is expressed honestly as an error, never as an
/// acknowledgement: the receipts stay unwritten, the export cursor stays put, and
/// the retained records stay pending for the next pass.
///
/// # Errors
///
/// Returns [`SpoolError`] when the retained spool or its receipt ledger fails
/// validation, no verified supervision lease was admitted, the retained
/// publication lies outside the current bounded window, a submission cannot be
/// proved against its own retained bytes, the route cannot acknowledge, the
/// acknowledgement does not answer the exact submitted sequence and derived
/// idempotency key, or a receipt cannot be persisted.
pub fn reconcile_watchdog_publications(
    sensor: &IndependentKernelSensor,
    sink: &impl WatchdogIntentSink,
) -> Result<WatchdogPublicationReconciliation, SpoolError> {
    let pending = sensor
        .pending_watchdog_publications(super::intent::INTENT_RECONCILIATION_MAX_SUBMISSIONS)?;
    if pending.is_empty() {
        return Ok(WatchdogPublicationReconciliation::NothingPending);
    }
    // A gap-only sensor that never verified a lease has no lease the admitted
    // route could resolve, so it fails closed here rather than offering a
    // submission the route must fence anyway.
    let supervision_lease_id = sensor
        .verified_supervision_lease_id()
        .ok_or_else(|| {
            SpoolError::InvalidLease(
                "watchdog publication reconciliation requires a verified supervision lease; none was admitted"
                    .to_owned(),
            )
        })?;
    let sink_id = sink.sink_id().to_owned();
    let export_batch = sensor.export_spool_batch(&sink_id, WatchdogSpoolExportLimits::default())?;
    if export_batch.predecessor_cursor.sink_id != sink_id {
        return Err(SpoolError::Corrupt(
            "watchdog publication export predecessor does not match the captured sink identity"
                .to_owned(),
        ));
    }
    let window_first = export_batch.first_sequence;
    let window_last = export_batch.last_sequence;
    let pending_sequence = pending[0].record.sequence;
    let reason = if pending_sequence < window_first {
        Some(WatchdogIntentWindowBlock::CursorAlreadyPassedPendingRecord)
    } else if pending_sequence > window_last {
        Some(WatchdogIntentWindowBlock::PendingRecordBeyondBoundedWindow)
    } else {
        None
    };
    if let Some(reason) = reason {
        return Ok(WatchdogPublicationReconciliation::Blocked {
            pending_sequence,
            predecessor_sequence: export_batch.predecessor_cursor.acknowledged_sequence,
            first_sequence: window_first,
            last_sequence: window_last,
            reason,
        });
    }
    let covered = pending
        .into_iter()
        .take_while(|item| item.record.sequence <= window_last)
        .collect::<Vec<_>>();
    // The window is read before the submissions are built, so a publication that
    // the envelope does not actually cover is refused before any of them is
    // offered. The envelope's own installation is the one the shared key
    // derivation is checked against.
    let installation_id = export_batch.installation_id.clone();
    let submissions = covered
        .iter()
        .map(|pending| publication_submission(&installation_id, pending))
        .collect::<Result<Vec<_>, SpoolError>>()?;
    let first_sequence = submissions.first().map_or(0, |item| item.sequence);
    let batch = WatchdogPublicationExportBatch {
        export_batch,
        publications: covered,
    };
    batch.validate(current_unix_ms()?.max(1))?;
    let acknowledgements = sink.submit_publication(&supervision_lease_id, &batch)?;
    if acknowledgements.len() != batch.publications.len() {
        return Err(SpoolError::Corrupt(
            "watchdog publication acknowledgement does not cover the submitted batch".to_owned(),
        ));
    }
    let submitted_at_ms = current_unix_ms()?.max(1);
    let mut recorded = 0_usize;
    let mut already_acknowledged = 0_usize;
    for (submission, acknowledgement) in submissions.iter().zip(&acknowledgements) {
        let expected_idempotency_key = watchdog_intent_reconciliation_idempotency_key(
            &installation_id,
            submission.sequence,
            &submission.record_digest,
        );
        if acknowledgement.sequence != submission.sequence
            || acknowledgement.sink_id != sink_id
            || acknowledgement.idempotency_key != expected_idempotency_key
        {
            return Err(SpoolError::Corrupt(
                "watchdog publication acknowledgement does not answer the exact submitted record and derived idempotency key"
                    .to_owned(),
            ));
        }
        let receipt = WatchdogIntentSubmission {
            sequence: acknowledgement.sequence,
            idempotency_key: acknowledgement.idempotency_key.clone(),
            acknowledgement_digest: acknowledgement.acknowledgement_digest.clone(),
            submitted_at_ms,
        };
        match sensor.record_intent_submission(&receipt)? {
            IntentSubmissionDisposition::Recorded => recorded += 1,
            IntentSubmissionDisposition::AlreadySubmitted => already_acknowledged += 1,
        }
    }
    Ok(WatchdogPublicationReconciliation::Reconciled {
        first_sequence,
        recorded,
        already_acknowledged,
    })
}

/// Result of one bounded publication reconciliation pass.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WatchdogPublicationReconciliation {
    /// No retained Signal-linked publication is awaiting the admitted owner.
    ///
    /// This is not a claim that anything was decided: acknowledgement is not a
    /// canonical transition, and this owner holds no evidence that a publication
    /// was acted on.
    NothingPending,
    /// A retained publication cannot be carried by the current owner-generated
    /// export window. No route call or receipt write occurred, and the record
    /// stays retained and pending.
    Blocked {
        /// Retained sequence of the oldest publication the window could not
        /// carry.
        pending_sequence: u64,
        /// The export predecessor the window continues from.
        predecessor_sequence: u64,
        /// First sequence the window covers.
        first_sequence: u64,
        /// Last sequence the window covers.
        last_sequence: u64,
        /// Why the window cannot carry it.
        reason: WatchdogIntentWindowBlock,
    },
    /// One bounded batch was presented and its submit-once receipts are now
    /// durable. `recorded` counts receipts this pass wrote; `already_acknowledged`
    /// counts records whose receipt already existed, so no second presentation of
    /// those records is possible.
    Reconciled {
        /// Retained sequence of the first record in the batch.
        first_sequence: u64,
        /// Receipts written by this pass.
        recorded: usize,
        /// Records whose receipt already existed.
        already_acknowledged: usize,
    },
}

/// One publication submission inside a bounded owner-generated export window.
///
/// It presents the retained record verbatim rather than a projection of it, so
/// the admitted owner receives the same bytes this owner bound its digests over
/// and can re-derive every digest itself. It carries the same owner identities
/// the escalation submissions carry, plus the exact Signal revision and distinct
/// evidence identities the threshold was decided on, because those are what the
/// receiver needs in order to revalidate applicability rather than trusting a
/// claim that a threshold was crossed.
///
/// The idempotency key is the *shared* `watchdog-spool-batch-v1` derivation over
/// installation, retained sequence and record digest — the same key the
/// escalation submissions use and the route re-derives. That is deliberate: it
/// makes a lost acknowledgement replay resolve to the same durable submission
/// under one ledger, instead of letting the two intent classes maintain
/// independent exactly-once schemes over one batch route.
pub fn publication_submission(
    installation_id: &str,
    pending: &super::publication::PendingPublication,
) -> Result<WatchdogSpoolIntentSubmission, SpoolError> {
    let record = PublicationRecordFields::of(pending)?;
    // The class is re-derived from the retained bytes and compared with the
    // index the spool read. A record whose class disagrees with what the spool
    // says it is would let one observation be presented under another
    // observation's label, so the disagreement fails closed here rather than
    // being resolved in favour of either side.
    if record.class != pending.publication_class {
        return Err(SpoolError::Corrupt(
            "Watchdog publication class does not match the retained record".to_owned(),
        ));
    }
    if record.crossing_evidence.is_empty()
        || record.crossing_evidence.len() > eliot_protocol::MAX_WATCHDOG_INTENT_EVIDENCE_REFS
    {
        return Err(SpoolError::Corrupt(
            "Watchdog publication submission carries no usable crossing evidence".to_owned(),
        ));
    }
    let publication_class = match record.class {
        WatchdogPublicationClass::ProblemAttention => class_code::PROBLEM_ATTENTION,
        WatchdogPublicationClass::IncidentCandidateAttention => {
            class_code::INCIDENT_CANDIDATE_ATTENTION
        }
    };
    // The intent kind is the *problem* escalation kind for both classes, and
    // that is not a narrowing: the fenced route's job is to record a bounded
    // pending intent projection for a Watchdog observation and never a canonical
    // transition, so the projection is the same shape either way. The class
    // itself travels in `record` and in `publication_class`, which is where the
    // admitted owner reads it. Choosing the incident kind for a *candidate*
    // class would instead assert an escalation this owner did not decide.
    let submission = WatchdogSpoolIntentSubmission {
        sequence: pending.record.sequence,
        intent_kind: WatchdogIntentKind::ProblemIntent,
        record_digest: pending.record_digest.clone(),
        payload_digest: pending.payload_digest.clone(),
        observed_at_ms: pending.record.observed_at_ms,
        idempotency_key: watchdog_intent_reconciliation_idempotency_key(
            installation_id,
            pending.record.sequence,
            &pending.record_digest,
        ),
        evidence_refs: record.crossing_evidence.clone(),
        lineage_installation_id: record.lineage_installation_id.to_owned(),
        lineage_generation: record.lineage_generation,
        lineage_epoch: record.lineage_epoch,
        lineage_epoch_id: pending.epoch_lineage.as_str().to_owned(),
        // The closed observation label this publication actually is. The field is
        // the route's bounded reason slot; carrying the class code here is
        // honest, because the reason a publication is being submitted *is* the
        // class it was decided under, and it is what lets the admitted owner
        // distinguish a candidate from a problem without parsing the record.
        governor_unavailable_reason: publication_class.to_string(),
        record: serde_json::to_value(&pending.record)
            .map_err(|error| SpoolError::Serialization(error.to_string()))?,
    };
    // The digest and lineage bindings are re-checked here, on the same path the
    // protocol's own `validate` applies, so a submission that cannot be proven
    // against its retained bytes is refused by the Watchdog before it is offered
    // rather than by the receiver afterwards.
    submission.validate(installation_id).map_err(|error| {
        SpoolError::Corrupt(format!("invalid Watchdog publication submission: {error}"))
    })?;
    // The submission now names an exact Signal, policy revision and target. They
    // are re-validated against the record's own retained bytes — the same bytes
    // the digests above already bound — so a submission that passes `validate`
    // while describing a *different* Signal than the one whose threshold was
    // crossed cannot be built.
    record.validate_binding(pending)?;
    Ok(submission)
}

/// The exact fields one retained publication record binds a submission to.
///
/// It reads out of the retained record rather than accepting a caller's copies,
/// so every fact a submission presents about the Signal, its policy revision and
/// its target is provably the fact the retained record states. A separate type
/// rather than a tuple of locals because the binding is re-checked against the
/// record after the submission is built, and a tuple would give the check nothing
/// to name.
struct PublicationRecordFields<'a> {
    class: WatchdogPublicationClass,
    intent_id: &'a str,
    signal_id: &'a str,
    signal_revision: u64,
    policy_id: &'a str,
    policy_revision: u64,
    crossing_evidence: &'a Vec<String>,
    subject_id: &'a str,
    scope_id: &'a str,
    generation: u64,
    lineage_installation_id: &'a str,
    lineage_generation: u64,
    lineage_epoch: u64,
}

impl<'a> PublicationRecordFields<'a> {
    /// Reads the fields one pending publication binds, failing closed when the
    /// retained record is not a publication record at all.
    ///
    /// # Errors
    ///
    /// Returns [`SpoolError::Corrupt`] when the retained record carries no
    /// publication payload.
    fn of(pending: &'a super::publication::PendingPublication) -> Result<Self, SpoolError> {
        let super::WatchdogSpoolPayload::PublicationIntent {
            class,
            intent_id,
            signal_id,
            signal_revision,
            policy_id,
            policy_revision,
            crossing_evidence,
            subject_id,
            scope_id,
            generation,
            lineage_installation_id,
            lineage_generation,
            lineage_epoch,
            ..
        } = &pending.record.payload
        else {
            return Err(SpoolError::Corrupt(
                "pending Watchdog publication no longer has a publication payload".to_owned(),
            ));
        };
        Ok(Self {
            class: *class,
            intent_id: intent_id.as_str(),
            signal_id: signal_id.as_str(),
            signal_revision: *signal_revision,
            policy_id: policy_id.as_str(),
            policy_revision: *policy_revision,
            crossing_evidence,
            subject_id: subject_id.as_str(),
            scope_id: scope_id.as_str(),
            generation: *generation,
            lineage_installation_id: lineage_installation_id.as_str(),
            lineage_generation: *lineage_generation,
            lineage_epoch: *lineage_epoch,
        })
    }

    /// Fails closed unless every bound fact is present, initialized, and stated
    /// by the retained record's own bytes.
    ///
    /// # Errors
    ///
    /// Returns [`SpoolError::Corrupt`] when the stored intent identity is not the
    /// one the retained record carries, when any identity is blank or carries a
    /// control character, or when a revision or generation is uninitialized.
    fn validate_binding(
        &self,
        pending: &super::publication::PendingPublication,
    ) -> Result<(), SpoolError> {
        // The stable intent identity is re-read from the record a second time and
        // compared. A submission is resumable only because that identity is
        // recoverable from the retained bytes, so it has to be *the record's* and
        // not one the caller supplied.
        if self.intent_id != pending.intent_id()? {
            return Err(SpoolError::Corrupt(
                "Watchdog publication submission does not carry the retained record's own intent identity"
                    .to_owned(),
            ));
        }
        for identity in [
            (self.signal_id, "signal_id"),
            (self.policy_id, "policy_id"),
            (self.subject_id, "subject_id"),
            (self.scope_id, "scope_id"),
            (self.lineage_installation_id, "lineage_installation_id"),
        ] {
            if identity.0.trim().is_empty() || identity.0.chars().any(char::is_control) {
                return Err(SpoolError::Corrupt(format!(
                    "Watchdog publication {} is not a usable bounded identity",
                    identity.1
                )));
            }
        }
        if self.signal_revision == 0 || self.policy_revision == 0 || self.generation == 0 {
            return Err(SpoolError::Corrupt(
                "Watchdog publication submission carries an uninitialized revision or generation"
                    .to_owned(),
            ));
        }
        Ok(())
    }
}

/// Closed wire codes of the two publication classes.
///
/// These are observation labels, not semantic codes: the admitted owner reads
/// them to distinguish a Problem attention intent from an Incident-*candidate*
/// attention intent, and there is no Incident-declaring code at all, so this
/// owner cannot present a canonical Incident even by mistake.
mod class_code {
    /// `problem_attention_intent`.
    pub(super) const PROBLEM_ATTENTION: &str = "PROBLEM_ATTENTION_INTENT";
    /// `incident_candidate_attention_intent`; never a canonical Incident.
    pub(super) const INCIDENT_CANDIDATE_ATTENTION: &str = "INCIDENT_CANDIDATE_ATTENTION_INTENT";
}

/// Why the oldest unsubmitted intent is not in the current exact export window.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WatchdogIntentWindowBlock {
    /// The shared export cursor already passed this retained intent record.
    CursorAlreadyPassedPendingRecord,
    /// The next pending record lies beyond this bounded export window.
    PendingRecordBeyondBoundedWindow,
}

/// Result of one bounded fenced-Kernel intent reconciliation pass.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WatchdogIntentReconciliation {
    /// No retained intent is awaiting reconciliation.
    NothingPending,
    /// A retained intent cannot be carried by the current owner-generated
    /// export window. No sink call or receipt write occurred.
    Blocked {
        pending_sequence: u64,
        predecessor_sequence: u64,
        first_sequence: u64,
        last_sequence: u64,
        reason: WatchdogIntentWindowBlock,
    },
    /// One bounded batch was submitted and its submit-once receipts are now
    /// durable. `recorded` counts receipts this call wrote; `already_submitted`
    /// counts records whose receipt already existed, so no second submission
    /// of those records is possible.
    Reconciled {
        first_sequence: u64,
        recorded: usize,
        already_submitted: usize,
    },
}

/// Reconciles one bounded window of retained Watchdog intents through the fenced
/// Kernel route and records their submit-once receipts.
///
/// The pass is: read the oldest retained intents that have no receipt, submit
/// the exact original records through the fenced route, verify the
/// acknowledgements answer exactly those sequences for the bound sink, then
/// persist one receipt per acknowledgement inside `watchdog.redb`. A receipt is
/// written only after a real acknowledgement, so a lost acknowledgement replays
/// the same submission instead of skipping it, and the durable receipt makes a
/// second submission of the same spool record impossible. Retained records are
/// never removed: the Kernel record and the Governor's later canonical
/// decision stay forensically linked to the original Watchdog record.
///
/// # Errors
///
/// Returns [`SpoolError`] when the retained spool or its receipt ledger fails
/// validation, the fenced route cannot acknowledge, the acknowledgement
/// coverage or sink identity does not answer the submitted batch, or a receipt
/// cannot be persisted.
pub fn reconcile_watchdog_intents(
    sensor: &IndependentKernelSensor,
    sink: &impl WatchdogIntentSink,
) -> Result<WatchdogIntentReconciliation, SpoolError> {
    let pending = sensor.pending_watchdog_intents()?;
    if pending.is_empty() {
        return Ok(WatchdogIntentReconciliation::NothingPending);
    }
    // A gap-only sensor that never verified a lease has no lease the fenced
    // route could resolve, so it fails closed here instead of submitting a
    // batch the Kernel must fence anyway.
    let supervision_lease_id = sensor
        .verified_supervision_lease_id()
        .ok_or_else(|| {
            SpoolError::InvalidLease(
                "watchdog intent reconciliation requires a verified supervision lease; none was admitted"
                .to_owned(),
            )
        })?;
    let sink_id = sink.sink_id().to_owned();
    let export_batch = sensor.export_spool_batch(&sink_id, WatchdogSpoolExportLimits::default())?;
    if export_batch.predecessor_cursor.sink_id != sink_id {
        return Err(SpoolError::Corrupt(
            "watchdog intent export predecessor does not match the captured sink identity"
                .to_owned(),
        ));
    }
    let window_first = export_batch.first_sequence;
    let window_last = export_batch.last_sequence;
    let pending_sequence = pending[0].record.sequence;
    let reason = if pending_sequence < window_first {
        Some(WatchdogIntentWindowBlock::CursorAlreadyPassedPendingRecord)
    } else if pending_sequence > window_last {
        Some(WatchdogIntentWindowBlock::PendingRecordBeyondBoundedWindow)
    } else {
        None
    };
    if let Some(reason) = reason {
        return Ok(WatchdogIntentReconciliation::Blocked {
            pending_sequence,
            predecessor_sequence: export_batch.predecessor_cursor.acknowledged_sequence,
            first_sequence: window_first,
            last_sequence: window_last,
            reason,
        });
    }
    let covered_intents = pending
        .into_iter()
        .take_while(|item| item.record.sequence <= window_last)
        .collect::<Vec<_>>();
    let batch = WatchdogIntentExportBatch {
        export_batch,
        intents: covered_intents,
    };
    batch.validate(current_unix_ms()?.max(1))?;
    let first_sequence = batch.intents.first().map_or(0, |item| item.record.sequence);
    let acknowledgements = sink.submit_intent(&supervision_lease_id, &batch)?;
    if acknowledgements.len() != batch.intents.len() {
        return Err(SpoolError::Corrupt(
            "watchdog intent acknowledgement does not cover the submitted batch".to_owned(),
        ));
    }
    let submitted_at_ms = current_unix_ms()?.max(1);
    let mut recorded = 0_usize;
    let mut already_submitted = 0_usize;
    for (pending, acknowledgement) in batch.intents.iter().zip(&acknowledgements) {
        let expected_idempotency_key = watchdog_intent_reconciliation_idempotency_key(
            &batch.export_batch.installation_id,
            pending.record.sequence,
            &pending.record_digest,
        );
        if acknowledgement.sequence != pending.record.sequence
            || acknowledgement.sink_id != batch.export_batch.predecessor_cursor.sink_id
            || acknowledgement.idempotency_key != expected_idempotency_key
        {
            return Err(SpoolError::Corrupt(
                "watchdog intent acknowledgement does not answer the exact submitted record and derived idempotency key".to_owned(),
            ));
        }
        let submission = WatchdogIntentSubmission {
            sequence: acknowledgement.sequence,
            idempotency_key: acknowledgement.idempotency_key.clone(),
            acknowledgement_digest: acknowledgement.acknowledgement_digest.clone(),
            submitted_at_ms,
        };
        match sensor.record_intent_submission(&submission)? {
            IntentSubmissionDisposition::Recorded => recorded += 1,
            IntentSubmissionDisposition::AlreadySubmitted => already_submitted += 1,
        }
    }
    Ok(WatchdogIntentReconciliation::Reconciled {
        first_sequence,
        recorded,
        already_submitted,
    })
}
