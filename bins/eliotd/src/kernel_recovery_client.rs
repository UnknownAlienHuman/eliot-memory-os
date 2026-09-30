//! Neutral Store-backed recovery client for the authenticated Kernel route.
//!
//! The daemon owns semantic decoding of Governor owner and maintenance
//! payloads. The Store owns durable records and atomic persistence; the Kernel
//! authenticates the route and fence and owns the transition gateway; and
//! Governor/eliotd owns semantic decoding and owner meaning. This module owns
//! only the typed transport and Store-neutral recovery projection: exact
//! fences, protected handoff digest, record identity, bounded schema/payload
//! validation, and response cardinality.
//!
//! Architecture: A2.3, A12.3, A13.2, A13.6, ARCH-AUTH-01, ARCH-SEC-02,
//! ARCH-RES-01, ARCH-RES-03.
//! Implementation: I1.8, I2.23, P.3, I14.21, I14.26.
//! Forbidden authority: no local canonical read path, owner/job default
//! synthesis, semantic authority, lease/token minting, or success on an
//! unknown or partially observed Store result.
//!
//! Governor genesis is lowered here without interpretation: the complete
//! Governor packet is validated, converted to opaque Store recovery records,
//! submitted with one stable request identity, and accepted only after the
//! Store-owned receipt envelope validates against that exact request.

use std::collections::BTreeSet;

use eliot_contracts::{ClockReading, ProductId, RequestId, RequestMetadata, SourceId, StateFence};
use eliot_governor::{
    GovernorGenesisRequest, KernelNamedReadReply, KernelNamedReadRequest, KernelPortError,
    KernelRecoveryPort,
};
use eliot_maintenance::MaintenanceJob;
use eliot_protocol::{
    MaintenanceTriggerAck, MaintenanceTriggerClaim, MaintenanceTriggerDecisionReceipt,
    MaintenanceTriggerGap, MaintenanceTriggerGapKind, MaintenanceTriggerPage,
    MaintenanceTriggerRecord, MaintenanceTriggerTerminalDisposition,
    MaintenanceTriggerTerminalKind, RequestIdentity,
};
use eliot_receipts::RequestBinding;
use eliot_store_api::{
    CONTRACT_VERSION, RecoveryRecord, RecoveryRecordKey, ScopeRevisionView, StoreGenesisRequest,
    StoreRecoveryRequest, StoreRecoverySnapshot, WriteReceipt, validate_genesis_receipt_envelope,
};

use super::{DaemonKernelClient, SERVICE_NAME, kind_value, unix_ms, unix_ms_i64};

const OWNER_RECOVERY_NAMESPACE: &str = "owner";
const JOB_RECOVERY_NAMESPACE: &str = "job";

impl KernelRecoveryPort for DaemonKernelClient {
    fn named_read(
        &self,
        request: KernelNamedReadRequest,
    ) -> Result<Option<KernelNamedReadReply>, KernelPortError> {
        // #740: request/result span over the recovery-read boundary. Record
        // identity and cardinality travel; payload bytes never do.
        let _span = tracing::info_span!("eliotd.recovery_read").entered();
        let key = RecoveryRecordKey::new(OWNER_RECOVERY_NAMESPACE, request.owner.as_str())
            .map_err(|error| KernelPortError::Contract(error.to_string()))?;
        let snapshot = self.recovery_snapshot(
            &request.state_fence,
            &request.protected_snapshot_digest,
            vec![key.clone()],
            false,
            false,
        )?;
        if snapshot.owner_records.len() > 1 {
            return Err(KernelPortError::Contract(
                "Kernel Store recovery returned multiple records for one named owner read"
                    .to_owned(),
            ));
        }
        let Some(record) = snapshot.owner_records.into_iter().next() else {
            return Ok(None);
        };
        if record.record_key() != key || record.state_fence != request.state_fence {
            return Err(KernelPortError::Contract(
                "Kernel Store recovery returned a substituted owner record".to_owned(),
            ));
        }
        Ok(Some(KernelNamedReadReply {
            owner: request.owner,
            state_fence: record.state_fence,
            revision: record.revision,
            schema: record.schema,
            payload: record.payload,
            value_digest: record.value_digest,
        }))
    }

    fn initialize_governor_genesis(
        &self,
        request: &GovernorGenesisRequest,
    ) -> Result<(), KernelPortError> {
        // #740: request/result span over the genesis rebuild boundary.
        // Requested/in-progress/completed stays an owner result; the span
        // only marks the daemon-side submission and its receipt outcome.
        let _span = tracing::info_span!("eliotd.recovery_genesis").entered();
        request
            .validate(
                &self.snapshot.state_fence(),
                &self.snapshot.protected_snapshot_digest,
            )
            .map_err(|error| KernelPortError::Contract(error.to_string()))?;
        // #740 A8: the Governor's rebuild request validated against the
        // admitted snapshot, so the rebuild is requested under the validated
        // owner digest. In-progress and completed follow below at the Store
        // submit and the validated receipt; the three phases stay distinct.
        let _ = crate::diagnostics::emit_rebuild(
            crate::diagnostics::RebuildState::Requested,
            &request.protected_snapshot_digest,
        );
        let identity = stable_genesis_identity(self, request)?;
        let context = identity.request.metadata.clone();
        let owner_records = request
            .owner_records
            .iter()
            .map(|record| RecoveryRecord {
                namespace: OWNER_RECOVERY_NAMESPACE.to_owned(),
                key: record.owner.as_str().to_owned(),
                state_fence: request.state_fence.clone(),
                revision: record.revision,
                schema: record.schema.clone(),
                payload: record.payload.clone(),
                value_digest: record.value_digest.clone(),
            })
            .collect();
        let store_request = StoreGenesisRequest {
            contract_version: CONTRACT_VERSION,
            operation_id: request.operation_id.clone(),
            idempotency_key: identity.idempotency_key.clone(),
            canonical_request_hash: String::new(),
            state_fence: request.state_fence.clone(),
            owner_records,
        }
        .with_computed_digest()
        .map_err(|error| KernelPortError::Contract(error.to_string()))?;
        store_request
            .validate_for_context(&context)
            .map_err(|error| KernelPortError::Contract(error.to_string()))?;
        // #740 A8: the validated rebuild is now submitted to the Store
        // owner, so it is in progress; completion is only the validated
        // receipt below, never this submission.
        let _ = crate::diagnostics::emit_rebuild(
            crate::diagnostics::RebuildState::InProgress,
            &request.protected_snapshot_digest,
        );
        let value = self.request_blocking_with_identity(
            "store_initialize_genesis",
            serde_json::json!({
                "context": context,
                "request": store_request,
            }),
            identity.clone(),
        )?;
        let value = kind_value(&value, "store_initialize_genesis")?;
        let receipt: WriteReceipt = serde_json::from_value(value)
            .map_err(|error| KernelPortError::Contract(error.to_string()))?;
        if receipt.operation_id != request.operation_id
            || receipt.idempotency_key != identity.idempotency_key
            || receipt.state_fence != request.state_fence
        {
            return Err(KernelPortError::Contract(
                "Kernel Store genesis receipt does not match the submitted request".to_owned(),
            ));
        }
        validate_genesis_receipt_envelope(&identity.request.metadata, &store_request, &receipt)
            .map_err(|error| KernelPortError::Contract(error.to_string()))?;
        // #740 A8: the Store receipt envelope validated against the exact
        // submitted request, so the rebuild is completed with owner evidence.
        let _ = crate::diagnostics::emit_rebuild(
            crate::diagnostics::RebuildState::Completed,
            &request.protected_snapshot_digest,
        );
        Ok(())
    }

    fn canonical_scope(
        &self,
        state_fence: &StateFence,
        protected_snapshot_digest: &str,
    ) -> Result<ScopeRevisionView, KernelPortError> {
        let snapshot = self.recovery_snapshot(
            state_fence,
            protected_snapshot_digest,
            Vec::new(),
            false,
            false,
        )?;
        Ok(snapshot.canonical_scope)
    }

    fn receipts(
        &self,
        state_fence: &StateFence,
        protected_snapshot_digest: &str,
    ) -> Result<Vec<WriteReceipt>, KernelPortError> {
        let snapshot = self.recovery_snapshot(
            state_fence,
            protected_snapshot_digest,
            Vec::new(),
            true,
            false,
        )?;
        Ok(snapshot.receipts)
    }

    fn durable_jobs(
        &self,
        state_fence: &StateFence,
        protected_snapshot_digest: &str,
    ) -> Result<Vec<MaintenanceJob>, KernelPortError> {
        let snapshot = self.recovery_snapshot(
            state_fence,
            protected_snapshot_digest,
            Vec::new(),
            false,
            true,
        )?;
        let mut job_ids = BTreeSet::new();
        snapshot
            .job_records
            .into_iter()
            .map(|record| {
                if record.namespace != JOB_RECOVERY_NAMESPACE {
                    return Err(KernelPortError::Contract(
                        "Kernel Store recovery returned a non-job durable record".to_owned(),
                    ));
                }
                let job: MaintenanceJob = serde_json::from_slice(&record.payload)
                    .map_err(|error| KernelPortError::Contract(error.to_string()))?;
                job.validate()
                    .map_err(|error| KernelPortError::Contract(error.to_string()))?;
                if record.key != job.job_id
                    || job.state_fence != *state_fence
                    || !job_ids.insert(job.job_id.clone())
                {
                    return Err(KernelPortError::Contract(
                        "Kernel Store recovery returned an invalid or duplicate durable job"
                            .to_owned(),
                    ));
                }
                Ok(job)
            })
            .collect()
    }
}

fn stable_genesis_identity(
    client: &DaemonKernelClient,
    request: &GovernorGenesisRequest,
) -> Result<RequestIdentity, KernelPortError> {
    let operation = request.operation_id.as_str();
    let idempotency_key = format!("{SERVICE_NAME}:governor-genesis:{operation}");
    let request_id = RequestId::new(format!(
        "{}:store_initialize_genesis:{operation}",
        client.connection_id
    ))
    .map_err(|error| KernelPortError::Contract(error.to_string()))?;
    let fence = request.state_fence.clone();
    let now = unix_ms_i64();
    let metadata = RequestMetadata {
        request_id: request_id.clone(),
        session_id: None,
        task_id: None,
        product_id: ProductId::new(SERVICE_NAME)
            .map_err(|error| KernelPortError::Contract(error.to_string()))?,
        source_id: SourceId::new(SERVICE_NAME)
            .map_err(|error| KernelPortError::Contract(error.to_string()))?,
        state_fence: fence.clone(),
        clock: ClockReading {
            valid_time_ms: Some(now),
            known_time_ms: Some(now),
            transaction_sequence: None,
            monotonic_ns: None,
        },
    };
    Ok(RequestIdentity {
        request: RequestBinding {
            metadata,
            state_fence: fence,
        },
        idempotency_key: idempotency_key.clone(),
        deadline_unix_ms: unix_ms().saturating_add(30_000),
        cancellation_id: format!("{idempotency_key}:cancel"),
    })
}

impl DaemonKernelClient {
    fn recovery_snapshot(
        &self,
        state_fence: &StateFence,
        protected_snapshot_digest: &str,
        records: Vec<RecoveryRecordKey>,
        include_receipts: bool,
        include_jobs: bool,
    ) -> Result<StoreRecoverySnapshot, KernelPortError> {
        if self.snapshot.state_fence() != *state_fence {
            return Err(KernelPortError::Contract(
                "Kernel recovery request fence does not match the admitted snapshot".to_owned(),
            ));
        }
        if self.snapshot.protected_snapshot_digest != protected_snapshot_digest {
            return Err(KernelPortError::Contract(
                "Kernel recovery request digest does not match the admitted snapshot".to_owned(),
            ));
        }
        let expected_records = records.clone();
        let request = StoreRecoveryRequest {
            contract_version: CONTRACT_VERSION,
            state_fence: state_fence.clone(),
            records,
            include_receipts,
            include_jobs,
        };
        request
            .validate()
            .map_err(|error| KernelPortError::Contract(error.to_string()))?;
        let value =
            self.request_blocking("store_recovery", serde_json::json!({ "request": request }))?;
        let value = kind_value(&value, "store_recovery")?;
        let snapshot: StoreRecoverySnapshot = serde_json::from_value(value)
            .map_err(|error| KernelPortError::Contract(error.to_string()))?;
        snapshot
            .validate()
            .map_err(|error| KernelPortError::Contract(error.to_string()))?;
        if snapshot.state_fence != *state_fence {
            return Err(KernelPortError::Contract(
                "Kernel Store recovery response fence does not match request".to_owned(),
            ));
        }
        let expected_keys: BTreeSet<RecoveryRecordKey> = expected_records.into_iter().collect();
        let observed_keys: BTreeSet<RecoveryRecordKey> = snapshot
            .owner_records
            .iter()
            .map(eliot_store_api::RecoveryRecord::record_key)
            .collect();
        if snapshot.owner_records.len() != expected_keys.len() || observed_keys != expected_keys {
            return Err(KernelPortError::Contract(
                "Kernel Store recovery response does not match requested owner records".to_owned(),
            ));
        }
        if !include_receipts && !snapshot.receipts.is_empty() {
            return Err(KernelPortError::Contract(
                "Kernel Store recovery returned excluded receipts".to_owned(),
            ));
        }
        if !include_jobs && !snapshot.job_records.is_empty() {
            return Err(KernelPortError::Contract(
                "Kernel Store recovery returned excluded durable jobs".to_owned(),
            ));
        }
        Ok(snapshot)
    }

    /// Issues one finite fenced claim for a retained maintenance trigger
    /// (issue #1694 W3).
    ///
    /// The request mirrors the Kernel ledger's closed claim-issuance fields;
    /// the Kernel dispatch serving [`MAINTENANCE_TRIGGER_CLAIM_OPERATION`]
    /// binds the live session and issues the generation/session/revision
    /// bound claim (STITCH: dispatch owner). The returned claim is validated
    /// and must answer this trigger under this delivery identity: an exact
    /// retry returns the live claim, a competing claim is refused by the
    /// owner rather than returned here.
    pub(crate) fn claim_maintenance_trigger(
        &self,
        state_fence: &StateFence,
        trigger_id: &str,
        daemon_fence: &StateFence,
        daemon_session: &str,
        delivery_id: &str,
        claim_deadline_unix_ms: u64,
        current_fence: &StateFence,
        now_unix_ms: u64,
    ) -> Result<MaintenanceTriggerClaim, KernelPortError> {
        let _span = tracing::info_span!("eliotd.maintenance_trigger_claim").entered();
        if *state_fence != self.snapshot.state_fence() {
            return Err(KernelPortError::Contract(
                "maintenance trigger claim fence does not match the admitted snapshot".to_owned(),
            ));
        }
        let value = self.request_blocking(
            MAINTENANCE_TRIGGER_CLAIM_OPERATION,
            serde_json::json!({
                "state_fence": state_fence,
                "trigger_id": trigger_id,
                "daemon_fence": daemon_fence,
                "daemon_session": daemon_session,
                "delivery_id": delivery_id,
                "claim_deadline_unix_ms": claim_deadline_unix_ms,
                "current_fence": current_fence,
                "now_unix_ms": now_unix_ms,
            }),
        )?;
        let value = kind_value(&value, MAINTENANCE_TRIGGER_CLAIM_OPERATION)?;
        let claim: MaintenanceTriggerClaim = serde_json::from_value(value)
            .map_err(|error| KernelPortError::Contract(error.to_string()))?;
        claim
            .validate()
            .map_err(|error| KernelPortError::Contract(error.to_string()))?;
        if claim.trigger_id != trigger_id || claim.delivery_id != delivery_id {
            return Err(KernelPortError::Contract(
                "Kernel maintenance trigger claim answers a different trigger or delivery"
                    .to_owned(),
            ));
        }
        Ok(claim)
    }

    /// Reads one bounded pending-trigger page with stable continuation
    /// (issue #1694 W3).
    ///
    /// A reconnect resumes from its cursor; an empty gapless page is refused
    /// by validation rather than read as a certified-complete set.
    pub(crate) fn pending_maintenance_trigger_page(
        &self,
        state_fence: &StateFence,
        continuation: Option<&str>,
        now_unix_ms: u64,
    ) -> Result<MaintenanceTriggerPage, KernelPortError> {
        let _span = tracing::info_span!("eliotd.maintenance_trigger_page").entered();
        if *state_fence != self.snapshot.state_fence() {
            return Err(KernelPortError::Contract(
                "maintenance trigger page fence does not match the admitted snapshot".to_owned(),
            ));
        }
        let value = self.request_blocking(
            MAINTENANCE_TRIGGER_PAGE_OPERATION,
            serde_json::json!({
                "state_fence": state_fence,
                "continuation": continuation,
                "now_unix_ms": now_unix_ms,
            }),
        )?;
        let value = kind_value(&value, MAINTENANCE_TRIGGER_PAGE_OPERATION)?;
        let page: MaintenanceTriggerPage = serde_json::from_value(value)
            .map_err(|error| KernelPortError::Contract(error.to_string()))?;
        page.validate()
            .map_err(|error| KernelPortError::Contract(error.to_string()))?;
        Ok(page)
    }

    /// Replays one retained trigger after a pre-commit crash (issue #1694 W5).
    ///
    /// Returns the exact retained record; the caller re-presents it to the
    /// evaluator under the same identity instead of minting a new trigger. A
    /// committed row replays by receipt through
    /// [`Self::recover_maintenance_trigger_commit`], never here.
    pub(crate) fn replay_maintenance_trigger(
        &self,
        state_fence: &StateFence,
        trigger_id: &str,
    ) -> Result<MaintenanceTriggerRecord, KernelPortError> {
        let _span = tracing::info_span!("eliotd.maintenance_trigger_replay").entered();
        if *state_fence != self.snapshot.state_fence() {
            return Err(KernelPortError::Contract(
                "maintenance trigger replay fence does not match the admitted snapshot".to_owned(),
            ));
        }
        let value = self.request_blocking(
            MAINTENANCE_TRIGGER_REPLAY_OPERATION,
            serde_json::json!({
                "state_fence": state_fence,
                "trigger_id": trigger_id,
            }),
        )?;
        let value = kind_value(&value, MAINTENANCE_TRIGGER_REPLAY_OPERATION)?;
        let record: MaintenanceTriggerRecord = serde_json::from_value(value)
            .map_err(|error| KernelPortError::Contract(error.to_string()))?;
        record
            .validate()
            .map_err(|error| KernelPortError::Contract(error.to_string()))?;
        if record.trigger_id != trigger_id {
            return Err(KernelPortError::Contract(
                "Kernel maintenance trigger replay answers a different trigger".to_owned(),
            ));
        }
        Ok(record)
    }

    /// Reuses one committed decision receipt after a post-commit crash
    /// (issue #1694 W5).
    ///
    /// The caller acknowledges this exact receipt without another job,
    /// recommendation, or wake. Receipt absence is not proof of non-commit:
    /// the owner reports the absence and the row stays open.
    pub(crate) fn recover_maintenance_trigger_commit(
        &self,
        state_fence: &StateFence,
        trigger_id: &str,
    ) -> Result<MaintenanceTriggerDecisionReceipt, KernelPortError> {
        let _span = tracing::info_span!("eliotd.maintenance_trigger_recover").entered();
        if *state_fence != self.snapshot.state_fence() {
            return Err(KernelPortError::Contract(
                "maintenance trigger recover fence does not match the admitted snapshot".to_owned(),
            ));
        }
        let value = self.request_blocking(
            MAINTENANCE_TRIGGER_RECOVER_OPERATION,
            serde_json::json!({
                "state_fence": state_fence,
                "trigger_id": trigger_id,
            }),
        )?;
        let value = kind_value(&value, MAINTENANCE_TRIGGER_RECOVER_OPERATION)?;
        let receipt: MaintenanceTriggerDecisionReceipt = serde_json::from_value(value)
            .map_err(|error| KernelPortError::Contract(error.to_string()))?;
        receipt
            .validate()
            .map_err(|error| KernelPortError::Contract(error.to_string()))?;
        if receipt.trigger_id != trigger_id {
            return Err(KernelPortError::Contract(
                "Kernel maintenance trigger recovery answers a different trigger".to_owned(),
            ));
        }
        Ok(receipt)
    }

    /// Records one committed decision receipt into the Kernel delivery ledger
    /// (issue #1694 W4/W5).
    ///
    /// The owner re-reads the exact canonical Store receipt, requires
    /// `Committed` status, and re-proves the bound digest before recording;
    /// the echoed receipt must equal the presented one byte for byte, which
    /// makes a same-receipt retry an idempotent reuse rather than a competing
    /// decision.
    pub(crate) fn record_maintenance_trigger_decision(
        &self,
        state_fence: &StateFence,
        trigger_id: &str,
        receipt: &MaintenanceTriggerDecisionReceipt,
    ) -> Result<MaintenanceTriggerDecisionReceipt, KernelPortError> {
        let _span = tracing::info_span!("eliotd.maintenance_trigger_record").entered();
        if *state_fence != self.snapshot.state_fence() {
            return Err(KernelPortError::Contract(
                "maintenance trigger record fence does not match the admitted snapshot".to_owned(),
            ));
        }
        receipt
            .validate()
            .map_err(|error| KernelPortError::Contract(error.to_string()))?;
        let value = self.request_blocking(
            MAINTENANCE_TRIGGER_RECORD_OPERATION,
            serde_json::json!({
                "state_fence": state_fence,
                "trigger_id": trigger_id,
                "receipt": receipt,
            }),
        )?;
        let value = kind_value(&value, MAINTENANCE_TRIGGER_RECORD_OPERATION)?;
        let echoed: MaintenanceTriggerDecisionReceipt = serde_json::from_value(value)
            .map_err(|error| KernelPortError::Contract(error.to_string()))?;
        echoed
            .validate()
            .map_err(|error| KernelPortError::Contract(error.to_string()))?;
        if echoed != *receipt {
            return Err(KernelPortError::Contract(
                "Kernel maintenance trigger record echo differs from the presented receipt"
                    .to_owned(),
            ));
        }
        Ok(echoed)
    }

    /// Acknowledges one delivery against its exact committed decision receipt
    /// (issue #1694 W5).
    ///
    /// The ack echoes the live claim exactly and embeds the committed receipt
    /// byte for byte; the echoed ack must equal the presented one. A stale
    /// consumer cannot ack after revocation: the owner refuses it rather
    /// than returning a mismatched echo.
    pub(crate) fn acknowledge_maintenance_trigger(
        &self,
        state_fence: &StateFence,
        current_fence: &StateFence,
        ack: &MaintenanceTriggerAck,
        now_unix_ms: u64,
    ) -> Result<MaintenanceTriggerAck, KernelPortError> {
        let _span = tracing::info_span!("eliotd.maintenance_trigger_acknowledge").entered();
        if *state_fence != self.snapshot.state_fence() {
            return Err(KernelPortError::Contract(
                "maintenance trigger acknowledge fence does not match the admitted snapshot"
                    .to_owned(),
            ));
        }
        ack.validate()
            .map_err(|error| KernelPortError::Contract(error.to_string()))?;
        let value = self.request_blocking(
            MAINTENANCE_TRIGGER_ACKNOWLEDGE_OPERATION,
            serde_json::json!({
                "state_fence": state_fence,
                "current_fence": current_fence,
                "ack": ack,
                "now_unix_ms": now_unix_ms,
            }),
        )?;
        let value = kind_value(&value, MAINTENANCE_TRIGGER_ACKNOWLEDGE_OPERATION)?;
        let echoed: MaintenanceTriggerAck = serde_json::from_value(value)
            .map_err(|error| KernelPortError::Contract(error.to_string()))?;
        echoed
            .validate()
            .map_err(|error| KernelPortError::Contract(error.to_string()))?;
        if echoed != *ack {
            return Err(KernelPortError::Contract(
                "Kernel maintenance trigger ack echo differs from the presented ack".to_owned(),
            ));
        }
        Ok(echoed)
    }

    /// Marks one lost or ambiguous commit as reconciling (issue #1694 W5).
    ///
    /// The owner keeps the trigger open with an `AmbiguousCommit` gap record;
    /// receipt absence during an outage is not proof of non-commit. The reply
    /// echoes the affected trigger identity and its post-transition revision
    /// so the caller can prove which row moved.
    pub(crate) fn mark_maintenance_trigger_ambiguous(
        &self,
        state_fence: &StateFence,
        trigger_id: &str,
        now_unix_ms: u64,
    ) -> Result<u64, KernelPortError> {
        let _span = tracing::info_span!("eliotd.maintenance_trigger_ambiguous").entered();
        if *state_fence != self.snapshot.state_fence() {
            return Err(KernelPortError::Contract(
                "maintenance trigger ambiguous fence does not match the admitted snapshot"
                    .to_owned(),
            ));
        }
        let value = self.request_blocking(
            MAINTENANCE_TRIGGER_AMBIGUOUS_OPERATION,
            serde_json::json!({
                "state_fence": state_fence,
                "trigger_id": trigger_id,
                "now_unix_ms": now_unix_ms,
            }),
        )?;
        let value = kind_value(&value, MAINTENANCE_TRIGGER_AMBIGUOUS_OPERATION)?;
        let revision = value
            .get("revision")
            .and_then(serde_json::Value::as_u64)
            .filter(|revision| *revision != 0)
            .ok_or_else(|| {
                KernelPortError::Contract(
                    "Kernel maintenance trigger ambiguous reply carries no post-transition revision"
                        .to_owned(),
                )
            })?;
        if value.get("trigger_id").and_then(serde_json::Value::as_str) != Some(trigger_id) {
            return Err(KernelPortError::Contract(
                "Kernel maintenance trigger ambiguous reply answers a different trigger".to_owned(),
            ));
        }
        Ok(revision)
    }

    /// Records one visible recovery gap for trigger damage (issue #1694 W7).
    ///
    /// Missing keys, corrupt payloads, inaccessible sources, and incomplete
    /// enumeration produce this record — never a plaintext fallback and never
    /// silent deletion. The echoed gap must name this trigger under the
    /// presented kind.
    pub(crate) fn record_maintenance_trigger_gap(
        &self,
        state_fence: &StateFence,
        trigger_id: &str,
        kind: MaintenanceTriggerGapKind,
        detail: &str,
        now_unix_ms: u64,
    ) -> Result<MaintenanceTriggerGap, KernelPortError> {
        let _span = tracing::info_span!("eliotd.maintenance_trigger_gap").entered();
        if *state_fence != self.snapshot.state_fence() {
            return Err(KernelPortError::Contract(
                "maintenance trigger gap fence does not match the admitted snapshot".to_owned(),
            ));
        }
        let value = self.request_blocking(
            MAINTENANCE_TRIGGER_GAP_OPERATION,
            serde_json::json!({
                "state_fence": state_fence,
                "trigger_id": trigger_id,
                "kind": kind,
                "detail": detail,
                "now_unix_ms": now_unix_ms,
            }),
        )?;
        let value = kind_value(&value, MAINTENANCE_TRIGGER_GAP_OPERATION)?;
        let gap: MaintenanceTriggerGap = serde_json::from_value(value)
            .map_err(|error| KernelPortError::Contract(error.to_string()))?;
        gap.validate()
            .map_err(|error| KernelPortError::Contract(error.to_string()))?;
        if gap.trigger_id.as_deref() != Some(trigger_id) || gap.kind != kind {
            return Err(KernelPortError::Contract(
                "Kernel maintenance trigger gap answers a different trigger or kind".to_owned(),
            ));
        }
        Ok(gap)
    }

    /// Records terminal expiry for a past-window trigger (issue #1694 W7).
    ///
    /// Expired eligibility blocks stale execution but never deletes the row,
    /// its record, or its evidence locators. The echoed disposition must name
    /// this trigger with the expiry class and no successor.
    pub(crate) fn expire_maintenance_trigger(
        &self,
        state_fence: &StateFence,
        trigger_id: &str,
        reason: &str,
        now_unix_ms: u64,
    ) -> Result<MaintenanceTriggerTerminalDisposition, KernelPortError> {
        let _span = tracing::info_span!("eliotd.maintenance_trigger_expire").entered();
        if *state_fence != self.snapshot.state_fence() {
            return Err(KernelPortError::Contract(
                "maintenance trigger expire fence does not match the admitted snapshot".to_owned(),
            ));
        }
        let value = self.request_blocking(
            MAINTENANCE_TRIGGER_EXPIRE_OPERATION,
            serde_json::json!({
                "state_fence": state_fence,
                "trigger_id": trigger_id,
                "reason": reason,
                "now_unix_ms": now_unix_ms,
            }),
        )?;
        let value = kind_value(&value, MAINTENANCE_TRIGGER_EXPIRE_OPERATION)?;
        let disposition: MaintenanceTriggerTerminalDisposition = serde_json::from_value(value)
            .map_err(|error| KernelPortError::Contract(error.to_string()))?;
        disposition
            .validate()
            .map_err(|error| KernelPortError::Contract(error.to_string()))?;
        if disposition.trigger_id != trigger_id
            || disposition.kind != MaintenanceTriggerTerminalKind::Expired
        {
            return Err(KernelPortError::Contract(
                "Kernel maintenance trigger expiry answers a different trigger or class".to_owned(),
            ));
        }
        Ok(disposition)
    }
}

/// Authenticated daemon-to-Kernel operation names for the retained
/// maintenance-trigger delivery protocol (issue #1694).
///
/// The Kernel dispatch serving each name binds the live session, runs the
/// matching Kernel delivery-gateway entry, and replies with
/// `{ "kind": <name>, "value": <typed echo> }` through the existing typed
/// application envelope. Names are fixed wire text shared with that
/// dispatch (STITCH: dispatch owner implements the server half).
pub(crate) const MAINTENANCE_TRIGGER_CLAIM_OPERATION: &str = "maintenance_trigger_claim";
pub(crate) const MAINTENANCE_TRIGGER_PAGE_OPERATION: &str = "maintenance_trigger_pending_page";
pub(crate) const MAINTENANCE_TRIGGER_REPLAY_OPERATION: &str = "maintenance_trigger_replay";
pub(crate) const MAINTENANCE_TRIGGER_RECOVER_OPERATION: &str = "maintenance_trigger_recover_commit";
pub(crate) const MAINTENANCE_TRIGGER_RECORD_OPERATION: &str = "maintenance_trigger_record_decision";
pub(crate) const MAINTENANCE_TRIGGER_ACKNOWLEDGE_OPERATION: &str =
    "maintenance_trigger_acknowledge";
pub(crate) const MAINTENANCE_TRIGGER_AMBIGUOUS_OPERATION: &str =
    "maintenance_trigger_mark_ambiguous";
pub(crate) const MAINTENANCE_TRIGGER_GAP_OPERATION: &str = "maintenance_trigger_record_gap";
pub(crate) const MAINTENANCE_TRIGGER_EXPIRE_OPERATION: &str = "maintenance_trigger_expire";
