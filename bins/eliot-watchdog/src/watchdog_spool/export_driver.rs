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
    ProtocolRange, ProtocolVersion, WATCHDOG_SPOOL_BATCH_ROUTE, WATCHDOG_SPOOL_EXPORT_BATCH_WIRE_ID,
    WATCHDOG_SPOOL_EXPORT_ROUTE, WATCHDOG_SPOOL_INTENT_BATCH_WIRE_ID, WatchdogIntentKind,
    WatchdogSpoolEntryKind, WatchdogSpoolEntryOutcome, WatchdogSpoolExportBatchPayload,
    WatchdogSpoolExportSubmission, WatchdogSpoolIntentBatchPayload, WatchdogSpoolIntentSubmission,
    watchdog_export_reconciliation_idempotency_key, watchdog_intent_reconciliation_idempotency_key,
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
use crate::{
    IndependentKernelSensor, SERVICE_NAME, SpoolError, WatchdogSpoolExportLimits, current_unix_ms,
};

const WATCHDOG_FRONT_DOOR_MODULE_ID: &str = "eliot-watchdog";

/// Closed front-door operation carrying one Watchdog spool intent batch.
///
/// It is the wire vocabulary the Kernel's `watchdog_intent_submit` entry and
/// its admitted Watchdog session capability are named by, so the two processes
/// cannot drift into two spellings of the same closed route.
const WATCHDOG_INTENT_SUBMIT_OPERATION: &str = "watchdog_intent_submit";

/// Closed front-door operation carrying one Watchdog spool export batch.
///
/// It is the sibling of [`WATCHDOG_INTENT_SUBMIT_OPERATION`] for the drain
/// window: a bounded observation intake over the retained spool, admitted
/// through the Kernel's `watchdog_export_submit` entry and its own admitted
/// Watchdog session capability.
const WATCHDOG_EXPORT_SUBMIT_OPERATION: &str = "watchdog_export_submit";

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
        if supervision_lease_id != self.lease.lease().lease_id
            || batch.export_batch.installation_id != self.lease.lease().installation_id
            || batch.export_batch.watchdog_generation
                != self.lease.lease().activation_generation.value()
            || batch.export_batch.watchdog_epoch != self.lease.lease().watchdog_epoch.value()
        {
            return Err(SpoolError::LeaseFenced(
                "intent batch does not match the signed supervision lease lineage".to_owned(),
            ));
        }
        let payload = intent_batch_payload(supervision_lease_id, self.sink_id(), batch)?;
        #[cfg(windows)]
        {
            tokio::runtime::Handle::try_current()
                .map_err(|error| {
                    SpoolError::Corrupt(format!("Kernel sink requires Tokio: {error}"))
                })?
                .block_on(transact_intent_batch(&self.lease, &payload))
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
        connect_watchdog_front_door(lease, &connection_id, WATCHDOG_INTENT_SUBMIT_OPERATION).await?;
    let limits = TransportLimits::default();
    let body = serde_json::to_value(payload)
        .map_err(|error| SpoolError::Serialization(error.to_string()))?;
    let frame = watchdog_spool_request(
        lease,
        WATCHDOG_INTENT_SUBMIT_OPERATION,
        "intent_batch",
        &body,
        &payload.batch_id,
        &connection_id,
        protocol_version,
    )?;
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
    capability: &str,
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
    let hello = watchdog_client_hello(lease, capability)?;
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
            .any(|item| item == capability)
        || server.rejection_reason.is_some()
    {
        return Err(SpoolError::LeaseFenced(
            "Kernel denied the Watchdog observation capability or lease epoch".to_owned(),
        ));
    }
    Ok((transport, server.selected_protocol))
}

#[cfg(windows)]
fn watchdog_spool_request(
    lease: &VerifiedSupervisionLease,
    operation: &str,
    payload_key: &str,
    payload: &serde_json::Value,
    batch_id: &str,
    connection_id: &str,
    protocol_version: ProtocolVersion,
) -> Result<Frame, SpoolError> {
    use std::collections::BTreeMap;

    let signed = lease.lease();
    let identity_text = format!("{operation}:{batch_id}");
    let request_id = RequestId::new(identity_text.clone())
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
        idempotency_key: identity_text.clone(),
        deadline_unix_ms: now_ms.saturating_add(10_000),
        cancellation_id: format!("{identity_text}:cancel"),
    };
    Ok(Frame {
        protocol_version,
        encoding_profile: EncodingProfile::JsonV1,
        connection_id: connection_id.to_owned(),
        request_id: Some(request_id),
        kind: FrameKind::Request,
        message_type: MessageType::Execute,
        request_identity: Some(identity),
        payload: ProtocolPayload::Json(
            serde_json::json!({ "operation": operation, payload_key: payload }),
        ),
        trace_context: BTreeMap::new(),
    })
}

/// Closed front-door operation carrying one Watchdog spool export batch.
#[cfg(windows)]
async fn transact_export_batch(
    lease: &VerifiedSupervisionLease,
    payload: &WatchdogSpoolExportBatchPayload,
) -> Result<WatchdogSpoolAcknowledgement, SpoolError> {
    use eliot_ipc::{DeliveryOutcome, TransportLimits};

    let signed = lease.lease();
    let connection_id = format!("{}:{}", SERVICE_NAME, signed.lease_id);
    let (mut transport, protocol_version) =
        connect_watchdog_front_door(lease, &connection_id, WATCHDOG_EXPORT_SUBMIT_OPERATION)
            .await?;
    let limits = TransportLimits::default();
    let body = serde_json::to_value(payload)
        .map_err(|error| SpoolError::Serialization(error.to_string()))?;
    let frame = watchdog_spool_request(
        lease,
        WATCHDOG_EXPORT_SUBMIT_OPERATION,
        "export_batch",
        &body,
        &payload.batch_id,
        &connection_id,
        protocol_version,
    )?;
    let request_id = frame.request_id.clone().ok_or_else(|| {
        SpoolError::Corrupt("Kernel export request omitted its request ID".to_owned())
    })?;
    if transport
        .send_frame(&frame, limits)
        .await
        .map_err(|error| SpoolError::LeaseFenced(error.to_string()))?
        != DeliveryOutcome::Delivered
    {
        return Err(SpoolError::LeaseFenced(
            "Kernel export batch delivery was not proven".to_owned(),
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
            "Kernel export response did not correlate to the submitted batch".to_owned(),
        ));
    }
    let ProtocolPayload::Json(value) = response.payload else {
        return Err(SpoolError::LeaseFenced(
            "Kernel export response was not JSON".to_owned(),
        ));
    };
    acknowledgement_from_kernel_outcome(&value, payload, batch.schema_version)
}

/// Projects one owner-generated export window onto the typed Kernel payload.
///
/// The payload carries the real batch content: the owner-computed predecessor,
/// full covered range, high-water, identity, digest, freshness window, and every
/// retained entry's sequence, revision, timestamp, payload class, and two
/// owner-computed digests. It carries no handle to anything: a downstream
/// consumer can admit every entry from this payload alone, and every digest it
/// reads is the Watchdog's own recorded value over its own retained bytes.
fn export_batch_payload(
    supervision_lease_id: &str,
    sink_id: &str,
    batch: &WatchdogSpoolExportBatch,
    epoch_lineage_id: &str,
) -> Result<WatchdogSpoolExportBatchPayload, SpoolError> {
    let entries = batch
        .entries
        .iter()
        .map(|entry| {
            Ok(WatchdogSpoolExportSubmission {
                sequence: entry.sequence,
                schema_version: entry.schema_version,
                observed_at_ms: entry.observed_at_ms,
                entry_kind: match entry.payload_kind {
                    WatchdogSpoolPayloadKind::Heartbeat => WatchdogSpoolEntryKind::Heartbeat,
                    WatchdogSpoolPayloadKind::Gap => WatchdogSpoolEntryKind::Gap,
                    WatchdogSpoolPayloadKind::Recovery => WatchdogSpoolEntryKind::Recovery,
                },
                payload_digest: entry.payload_digest.clone(),
                record_digest: entry.record_digest.clone(),
                idempotency_key: watchdog_export_reconciliation_idempotency_key(
                    &batch.installation_id,
                    entry.sequence,
                    &entry.record_digest,
                ),
            })
        })
        .collect::<Result<Vec<_>, SpoolError>>()?;
    WatchdogSpoolExportBatchPayload {
        wire_id: WATCHDOG_SPOOL_EXPORT_BATCH_WIRE_ID.to_owned(),
        wire_version: WatchdogSpoolExportBatchPayload::CONTRACT_VERSION,
        route: WATCHDOG_SPOOL_EXPORT_ROUTE.to_owned(),
        installation_id: batch.installation_id.clone(),
        schema_version: batch.schema_version,
        watchdog_generation: batch.watchdog_generation,
        watchdog_epoch: batch.watchdog_epoch,
        watchdog_epoch_lineage_id: epoch_lineage_id.to_owned(),
        supervision_lease_id: supervision_lease_id.to_owned(),
        sink_id: sink_id.to_owned(),
        predecessor_sequence: batch.predecessor_cursor.acknowledged_sequence,
        first_sequence: batch.first_sequence,
        last_sequence: batch.last_sequence,
        high_water_sequence: batch.high_water_sequence,
        created_at_ms: batch.created_at_ms,
        expires_at_ms: batch.expires_at_ms,
        batch_id: batch.batch_id.clone(),
        batch_digest: batch.batch_digest.clone(),
        byte_size: batch.byte_size,
        entries,
        payload_sha256: String::new(),
    }
    .with_computed_digest()
    .and_then(|payload| {
        payload.validate()?;
        Ok(payload)
    })
    .map_err(|error| SpoolError::Corrupt(format!("invalid Kernel export batch: {error}")))
}

/// Projects one Kernel export answer onto the sink-owned acknowledgement.
///
/// The Kernel route records one durable *pending export projection* per retained
/// spool record and nothing more, so the only honest sink disposition is
/// `AdmittedCandidate`: the entry is stored, it is not yet a canonical
/// application, and the Watchdog's cursor must not advance on it. Any other
/// durable state is refused instead of being reinterpreted, and the sink never
/// invents a terminal outcome for an entry the Governor has not decided.
fn acknowledgement_from_kernel_outcome(
    outcome: &serde_json::Value,
    payload: &WatchdogSpoolExportBatchPayload,
    schema_version: u16,
) -> Result<WatchdogSpoolAcknowledgement, SpoolError> {
    use eliot_watchdog_core::{WatchdogSpoolEntryDisposition, WatchdogSpoolSinkDisposition};

    if outcome.get("status").and_then(serde_json::Value::as_str) != Some("known") {
        return Err(SpoolError::LeaseFenced(
            "Kernel did not return a known export outcome".to_owned(),
        ));
    }
    let known = outcome.get("value").ok_or_else(|| {
        SpoolError::LeaseFenced("Kernel known export outcome omitted its value".to_owned())
    })?;
    if known.get("accepted").and_then(serde_json::Value::as_bool) != Some(true)
        || known.get("sink_id").and_then(serde_json::Value::as_str)
            != Some(payload.sink_id.as_str())
        || outcome.get("recovery") != Some(&serde_json::Value::Null)
    {
        return Err(SpoolError::LeaseFenced(
            "Kernel export outcome did not affirm the bound sink and non-canonical pending projection"
                .to_owned(),
        ));
    }
    let entries = known
        .get("entries")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| {
            SpoolError::LeaseFenced("Kernel export outcome omitted its projections".to_owned())
        })?;
    if entries.len() != payload.entries.len() {
        return Err(SpoolError::LeaseFenced(
            "Kernel export outcome coverage differed from submitted records".to_owned(),
        ));
    }
    entries
        .iter()
        .zip(&payload.entries)
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
                    .get("entry_kind")
                    .and_then(serde_json::Value::as_str)
                    != Some(submitted.entry_kind.as_str())
                || projection
                    .get("record_digest")
                    .and_then(serde_json::Value::as_str)
                    != Some(submitted.record_digest.as_str())
                || projection
                    .get("payload_digest")
                    .and_then(serde_json::Value::as_str)
                    != Some(submitted.payload_digest.as_str())
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
                    "Kernel export projection did not bind the exact retained record".to_owned(),
                ));
            }
            // Only the Governor's own recorded terminal disposition may answer an
            // entry. While the durable record is a pending projection with no
            // recorded outcome, the honest sink disposition is the non-terminal
            // `AdmittedCandidate`, which this owner refuses to advance on: the
            // window replays and the cursor stays exactly where it is.
            let disposition = match projection.get("outcome") {
                None | Some(serde_json::Value::Null) => {
                    if projection.get("state").and_then(serde_json::Value::as_str)
                        != Some("ADMITTED")
                    {
                        return Err(SpoolError::LeaseFenced(
                            "Kernel export projection reported no outcome for an undecided record"
                                .to_owned(),
                        ));
                    }
                    WatchdogSpoolSinkDisposition::AdmittedCandidate
                }
                Some(outcome) => {
                    if projection.get("state").and_then(serde_json::Value::as_str)
                        != Some("RESULT_RECEIVED")
                    {
                        return Err(SpoolError::LeaseFenced(
                            "Kernel export projection reported an outcome for an undecided record"
                                .to_owned(),
                        ));
                    }
                    terminal_disposition_from_kernel_outcome(outcome)?
                }
            };
            Ok(WatchdogSpoolEntryDisposition {
                sequence: submitted.sequence,
                disposition,
                record_digest: submitted.record_digest.clone(),
            })
        })
        .collect::<Result<Vec<_>, SpoolError>>()
        .map(|dispositions| WatchdogSpoolAcknowledgement {
            schema_version,
            batch_id: payload.batch_id.clone(),
            batch_digest: payload.batch_digest.clone(),
            predecessor_sequence: payload.predecessor_sequence,
            first_sequence: payload.first_sequence,
            last_sequence: payload.last_sequence,
            sink_id: payload.sink_id.clone(),
            watchdog_generation: payload.watchdog_generation,
            watchdog_epoch: payload.watchdog_epoch,
            installation_id: payload.installation_id.clone(),
            dispositions,
        })
}

/// Decodes the one closed terminal disposition the Governor recorded.
///
/// The wire value is the typed `WatchdogSpoolEntryOutcome`, decoded here through
/// its own contract rather than by string matching, so this sink cannot invent
/// a disposition and cannot map a non-terminal state onto a terminal one. A value
/// outside the closed vocabulary fences rather than falling back to a
/// non-terminal disposition, because silently downgrading a recorded decision
/// would strand the entry forever.
fn terminal_disposition_from_kernel_outcome(
    value: &serde_json::Value,
) -> Result<eliot_watchdog_core::WatchdogSpoolSinkDisposition, SpoolError> {
    use eliot_watchdog_core::WatchdogSpoolSinkDisposition as Disposition;

    let outcome: WatchdogSpoolEntryOutcome =
        serde_json::from_value(value.clone()).map_err(|_| {
            SpoolError::LeaseFenced(
                "Kernel recorded export outcome is not the closed disposition vocabulary"
                    .to_owned(),
            )
        })?;
    Ok(match outcome {
        WatchdogSpoolEntryOutcome::Applied => Disposition::Applied,
        WatchdogSpoolEntryOutcome::Rejected { reason } => Disposition::Rejected { reason },
        WatchdogSpoolEntryOutcome::GapRequiresRecovery => Disposition::GapRequiresRecovery,
    })
}

/// Authenticated Kernel front-door sink for one bounded Watchdog spool export.
///
/// The constructor binds every connection to fields in the already verified
/// signed lease and to this owner's own retained epoch lineage; no endpoint,
/// peer identity, server artifact, or lineage identity is accepted from the
/// caller. It is the production [`WatchdogExportSink`], so [`export_once`] has
/// a real transport in production instead of a test double.
pub struct KernelFrontDoorWatchdogExportSink {
    lease: VerifiedSupervisionLease,
    epoch_lineage_id: String,
    sink_id: String,
}

impl KernelFrontDoorWatchdogExportSink {
    /// Binds a stable sink identity, authenticated server expectation, and the
    /// Watchdog's own epoch lineage to the exact verified supervision lease.
    #[must_use]
    pub fn new(lease: VerifiedSupervisionLease, epoch_lineage_id: &str) -> Self {
        let payload = lease.lease();
        let sink_id = format!(
            "watchdog-kernel-frontdoor-export:{}:{}",
            payload.installation_id,
            payload.activation_generation.value()
        );
        Self {
            lease,
            epoch_lineage_id: epoch_lineage_id.to_owned(),
            sink_id,
        }
    }
}

impl WatchdogExportSink for KernelFrontDoorWatchdogExportSink {
    fn sink_id(&self) -> &str {
        &self.sink_id
    }

    fn submit(
        &self,
        batch: &WatchdogSpoolExportBatch,
    ) -> Result<WatchdogSpoolAcknowledgement, SpoolError> {
        let lease_id = self.lease.lease().lease_id.clone();
        if batch.installation_id != self.lease.lease().installation_id
            || batch.watchdog_generation
                != self.lease.lease().activation_generation.value()
            || batch.watchdog_epoch != self.lease.lease().watchdog_epoch.value()
        {
            return Err(SpoolError::LeaseFenced(
                "export batch does not match the signed supervision lease lineage".to_owned(),
            ));
        }
        let payload = export_batch_payload(
            &lease_id,
            self.sink_id(),
            batch,
            self.epoch_lineage_id.as_str(),
        )?;
        #[cfg(windows)]
        {
            tokio::runtime::Handle::try_current()
                .map_err(|error| {
                    SpoolError::Corrupt(format!("Kernel export sink requires Tokio: {error}"))
                })?
                .block_on(transact_export_batch(&self.lease, &payload))
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
fn watchdog_client_hello(
    lease: &VerifiedSupervisionLease,
    capability: &str,
) -> Result<ClientHello, SpoolError> {
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
        capabilities: vec![capability.to_owned()],
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
