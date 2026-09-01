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
use eliot_protocol::RequestIdentity;
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
        request
            .validate(
                &self.snapshot.state_fence(),
                &self.snapshot.protected_snapshot_digest,
            )
            .map_err(|error| KernelPortError::Contract(error.to_string()))?;
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
}
