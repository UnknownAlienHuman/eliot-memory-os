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

use eliot_contracts::{
    ClockReading, ProductId, RequestId, RequestMetadata, SessionId, SourceId, StateFence,
    canonical_json_bytes, sha256_hex,
};
use eliot_governor::{
    GovernorGenesisRequest, KernelNamedReadReply, KernelNamedReadRequest, KernelPortError,
    KernelRecoveryPort, OWNER_SNAPSHOT_SCHEMA,
};
use eliot_maintenance::MaintenanceJob;
use eliot_protocol::RequestIdentity;
use eliot_protocol::TaskControllerAction;
use eliot_receipts::RequestBinding;
use eliot_store_api::{
    CONTRACT_VERSION, RecoveryRecord, RecoveryRecordKey, ScopeRevisionView, StoreFailure,
    StoreFailureDisposition, StoreGenesisRequest, StoreRecoveryRequest, StoreRecoverySnapshot,
    StoreWorkScopeOwnerRequest, StoreWorkScopeOwnerResponse, WriteReceipt,
    validate_genesis_receipt_envelope,
};

use super::{
    DaemonKernelClient, SERVICE_NAME, TaskControllerClaimedInvocation, WireOutcome,
    kernel_port_error, kind_value, unix_ms, unix_ms_i64,
};

const OWNER_RECOVERY_NAMESPACE: &str = "owner";
const JOB_RECOVERY_NAMESPACE: &str = "job";

/// Result boundary for the initial owner publisher. Store refusals retain the
/// complete validated StoreFailure contract; Kernel/transport failures remain
/// the existing neutral KernelPortError variants.
#[derive(Debug)]
pub(super) enum WorkScopeOwnerWriteFailure {
    Store {
        failure: StoreFailure,
        expected: RecoveryRecord,
    },
    Kernel {
        error: KernelPortError,
        expected: Option<RecoveryRecord>,
    },
}

impl From<KernelPortError> for WorkScopeOwnerWriteFailure {
    fn from(error: KernelPortError) -> Self {
        Self::Kernel {
            error,
            expected: None,
        }
    }
}

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

/// Uses the existing daemon owner-publisher RequestMeta shape while binding
/// the operation identity and task/session/fence/deadline to the exact
/// authenticated Task Controller claim. Product/Source identify the daemon
/// publisher here; they do not grant WorkScope source or privacy authority.
fn task_controller_owner_request_identity(
    client: &DaemonKernelClient,
    claimed: &TaskControllerClaimedInvocation,
) -> Result<RequestIdentity, KernelPortError> {
    let attempt = &claimed.attempt;
    let identity = &claimed.envelope.identity;
    let request_id = RequestId::new(identity.request_id.as_str().to_owned())
        .map_err(|error| KernelPortError::Contract(error.to_string()))?;
    let session_id = SessionId::new(attempt.session_id.clone())
        .map_err(|error| KernelPortError::Contract(error.to_string()))?;
    let now = unix_ms_i64();
    let fence = attempt.state_fence.clone();
    let metadata = RequestMetadata {
        request_id,
        session_id: Some(session_id),
        task_id: Some(attempt.task_id.clone()),
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
    let request_identity = RequestIdentity {
        request: RequestBinding {
            metadata,
            state_fence: fence,
        },
        idempotency_key: identity.idempotency_key.clone(),
        deadline_unix_ms: identity.deadline_unix_ms,
        cancellation_id: identity.cancellation_id.clone(),
    };
    request_identity
        .validate()
        .map_err(|error| KernelPortError::Contract(error.to_string()))?;
    if request_identity.request.state_fence != client.snapshot.state_fence()
        || request_identity.request.metadata.task_id.as_ref() != Some(&claimed.invocation.task_id)
        || request_identity
            .request
            .metadata
            .session_id
            .as_ref()
            .map(SessionId::as_str)
            != Some(attempt.session_id.as_str())
        || request_identity.deadline_unix_ms != identity.deadline_unix_ms
        || identity.session_id.as_deref() != Some(attempt.session_id.as_str())
        || identity.task_id.as_deref() != Some(claimed.invocation.task_id.as_str())
        || identity.work_scope_id.as_deref() != Some(attempt.scope_id.as_str())
        || attempt.operation_id != claimed.operation_id
        || attempt.state_fence != claimed.envelope.state_fence
    {
        return Err(KernelPortError::Contract(
            "WorkScope owner publisher identity does not bind the exact claim".to_owned(),
        ));
    }
    Ok(request_identity)
}

impl DaemonKernelClient {
    /// Serializes and durably admits one Governor-created WorkScope snapshot
    /// at the next revision established by a same-fence Store owner read.
    pub(super) async fn persist_work_scope_binding_snapshot(
        &self,
        claimed: &TaskControllerClaimedInvocation,
        snapshot: &eliot_governor::WorkScopeBindingSnapshot,
        expected_owner_revision: u64,
    ) -> Result<RecoveryRecord, WorkScopeOwnerWriteFailure> {
        snapshot
            .validate()
            .map_err(|error| KernelPortError::Contract(error.to_string()))?;
        let next_revision = expected_owner_revision.checked_add(1).ok_or_else(|| {
            KernelPortError::Contract("WorkScope owner revision overflow".to_owned())
        })?;
        if expected_owner_revision == 0
            || snapshot.owner_revision != next_revision
            || snapshot.state_fence != self.snapshot.state_fence()
        {
            return Err(KernelPortError::Contract(
                "WorkScope snapshot does not bind the exact next owner revision and fence"
                    .to_owned(),
            ));
        }
        let payload = canonical_json_bytes(snapshot)
            .map_err(|error| KernelPortError::Contract(error.to_string()))?;
        if payload.is_empty() || payload.len() > eliot_governor::MAX_OWNER_SNAPSHOT_BYTES {
            return Err(KernelPortError::Contract(
                "WorkScope owner snapshot exceeds the recovery payload bound".to_owned(),
            ));
        }
        let owner_record = RecoveryRecord {
            namespace: OWNER_RECOVERY_NAMESPACE.to_owned(),
            key: "work_scope".to_owned(),
            state_fence: snapshot.state_fence.clone(),
            revision: next_revision,
            schema: OWNER_SNAPSHOT_SCHEMA.to_owned(),
            value_digest: sha256_hex(&payload),
            payload,
        };
        let request = StoreWorkScopeOwnerRequest {
            contract_version: CONTRACT_VERSION,
            operation_id: claimed.operation_id.clone(),
            idempotency_key: claimed.envelope.identity.idempotency_key.clone(),
            state_fence: snapshot.state_fence.clone(),
            protected_snapshot_digest: self.snapshot.protected_snapshot_digest.clone(),
            expected_owner_revision,
            owner_record,
            canonical_request_hash: String::new(),
        }
        .with_computed_digest()
        .map_err(|error| KernelPortError::Contract(error.to_string()))?;
        self.write_work_scope_owner(claimed, request).await
    }

    /// Reads the retained WorkScope owner through the authenticated Kernel
    /// recovery route and requires the seeded owner row to be present.
    pub(super) async fn read_work_scope_owner(
        &self,
        state_fence: &StateFence,
        protected_snapshot_digest: &str,
    ) -> Result<RecoveryRecord, KernelPortError> {
        if self.snapshot.state_fence() != *state_fence
            || self.snapshot.protected_snapshot_digest != protected_snapshot_digest
        {
            return Err(KernelPortError::Contract(
                "WorkScope owner read does not match the admitted Kernel snapshot".to_owned(),
            ));
        }
        let key = RecoveryRecordKey::new(OWNER_RECOVERY_NAMESPACE, "work_scope")
            .map_err(|error| KernelPortError::Contract(error.to_string()))?;
        let request = StoreRecoveryRequest {
            contract_version: CONTRACT_VERSION,
            state_fence: state_fence.clone(),
            records: vec![key.clone()],
            include_receipts: false,
            include_jobs: false,
        };
        request
            .validate()
            .map_err(|error| KernelPortError::Contract(error.to_string()))?;
        let value = self
            .transact_async("store_recovery", serde_json::json!({ "request": request }))
            .await
            .map_err(kernel_port_error)?;
        let value = kind_value(&value, "store_recovery")?;
        let snapshot: StoreRecoverySnapshot = serde_json::from_value(value)
            .map_err(|error| KernelPortError::Contract(error.to_string()))?;
        snapshot
            .validate()
            .map_err(|error| KernelPortError::Contract(error.to_string()))?;
        if snapshot.state_fence != *state_fence
            || !snapshot.receipts.is_empty()
            || !snapshot.job_records.is_empty()
            || snapshot.owner_records.len() != 1
        {
            return Err(KernelPortError::Contract(
                "WorkScope owner recovery read has invalid cardinality or fence".to_owned(),
            ));
        }
        let record = snapshot.owner_records.into_iter().next().ok_or_else(|| {
            KernelPortError::Contract("seeded WorkScope owner row is absent".to_owned())
        })?;
        record
            .validate_for_fence(state_fence)
            .map_err(|error| KernelPortError::Contract(error.to_string()))?;
        if record.record_key() != key || record.state_fence != *state_fence || record.revision == 0
        {
            return Err(KernelPortError::Contract(
                "WorkScope owner recovery read returned an invalid named row".to_owned(),
            ));
        }
        Ok(record)
    }

    /// Publishes one initial WorkScope owner record through Kernel's existing
    /// authenticated Store route. Kernel supplies the authenticated request
    /// metadata to Store and returns only after its exact same-fence named
    /// readback; this daemon check binds that returned row to our bytes.
    pub(super) async fn write_work_scope_owner(
        &self,
        claimed: &TaskControllerClaimedInvocation,
        request: StoreWorkScopeOwnerRequest,
    ) -> Result<RecoveryRecord, WorkScopeOwnerWriteFailure> {
        if request.state_fence != self.snapshot.state_fence()
            || request.protected_snapshot_digest != self.snapshot.protected_snapshot_digest
        {
            return Err(KernelPortError::Contract(
                "WorkScope owner write does not match the admitted Kernel snapshot".to_owned(),
            ));
        }
        let identity = task_controller_owner_request_identity(self, claimed)?;
        request
            .validate_for_context(&identity.request.metadata)
            .map_err(|error| KernelPortError::Contract(error.to_string()))?;
        if request.operation_id != claimed.operation_id
            || request.idempotency_key != claimed.envelope.identity.idempotency_key
        {
            return Err(KernelPortError::Contract(
                "WorkScope owner CAS does not preserve the exact original operation identity"
                    .to_owned(),
            )
            .into());
        }
        let expected = request.owner_record.clone();
        let attempt = &claimed.attempt;
        let original_operation_id = claimed.operation_id.as_str();
        let original_request_sha256 = claimed.envelope.envelope_sha256.as_str();
        if claimed.invocation.action != TaskControllerAction::BindScope
            || original_operation_id != attempt.operation_id
            || original_request_sha256.len() != 64
        {
            return Err(KernelPortError::Contract(
                "WorkScope owner write does not bind the claimed Task Controller operation"
                    .to_owned(),
            ));
        }
        let payload = serde_json::json!({
            "attempt": attempt,
            "operation_id": original_operation_id,
            "request_sha256": original_request_sha256,
            "request": request.clone(),
        });
        let outcome = self
            .transact_async_with_identity_outcome("store_work_scope_owner", payload, identity)
            .await
            .map_err(kernel_port_error)
            .map_err(|error| WorkScopeOwnerWriteFailure::Kernel {
                error,
                expected: Some(expected.clone()),
            })?;
        let value = match outcome {
            WireOutcome::Known { value, .. } => value,
            WireOutcome::Error {
                code,
                reason,
                value,
                failure,
            } if code == "STORE_FAILURE" => {
                if value.as_ref()
                    != Some(&serde_json::json!({
                        "kind": "store_work_scope_owner",
                        "value": null,
                    }))
                {
                    return Err(WorkScopeOwnerWriteFailure::Kernel {
                        error: KernelPortError::Contract(
                            "Kernel Store failure has an invalid operation value envelope"
                                .to_owned(),
                        ),
                        expected: Some(expected.clone()),
                    });
                }
                let failure = failure.ok_or_else(|| WorkScopeOwnerWriteFailure::Kernel {
                    error: KernelPortError::Contract(
                        "Kernel Store failure omitted its typed failure contract".to_owned(),
                    ),
                    expected: Some(expected.clone()),
                })?;
                failure
                    .validate()
                    .map_err(|error| WorkScopeOwnerWriteFailure::Kernel {
                        error: KernelPortError::Contract(error.to_string()),
                        expected: Some(expected.clone()),
                    })?;
                if failure.request_id.as_ref() != Some(&claimed.envelope.identity.request_id)
                    || failure.operation_id.as_ref() != Some(&claimed.operation_id)
                    || failure.idempotency_key_ref_or_digest.as_deref()
                        != Some(claimed.envelope.identity.idempotency_key.as_str())
                    || failure.state_fence_ref_or_exact_safe_projection.as_ref()
                        != Some(&claimed.attempt.state_fence)
                {
                    return Err(WorkScopeOwnerWriteFailure::Kernel {
                        error: KernelPortError::Contract(
                            "Kernel Store failure does not preserve the exact original request identity"
                                .to_owned(),
                        ),
                        expected: Some(expected.clone()),
                    });
                }
                let _ = reason;
                return Err(WorkScopeOwnerWriteFailure::Store {
                    failure,
                    expected: expected.clone(),
                });
            }
            WireOutcome::Error {
                code,
                reason,
                failure: Some(_),
                ..
            } => {
                return Err(WorkScopeOwnerWriteFailure::Kernel {
                    error: KernelPortError::Contract(format!(
                        "Kernel attached a typed Store failure to non-Store error {code}: {reason}"
                    )),
                    expected: Some(expected.clone()),
                });
            }
            WireOutcome::Error { code, reason, .. } => {
                let error = if code == "KERNEL_GATEWAY_REFUSAL" {
                    KernelPortError::NotAdmitted(reason)
                } else {
                    KernelPortError::Contract(format!("{code}: {reason}"))
                };
                return Err(WorkScopeOwnerWriteFailure::Kernel {
                    error,
                    expected: Some(expected.clone()),
                });
            }
            WireOutcome::Partial { reason, .. } | WireOutcome::Unknown { reason } => {
                return Err(WorkScopeOwnerWriteFailure::Kernel {
                    error: KernelPortError::Unknown(reason),
                    expected: Some(expected.clone()),
                });
            }
            WireOutcome::AcceptedPending { .. } => {
                return Err(WorkScopeOwnerWriteFailure::Kernel {
                    error: KernelPortError::Unknown(
                        "Kernel returned ACCEPTED_PENDING to an exact owner publisher".to_owned(),
                    ),
                    expected: Some(expected.clone()),
                });
            }
        };
        let value = kind_value(&value, "store_work_scope_owner")?;
        let record: RecoveryRecord = serde_json::from_value(value)
            .map_err(|error| KernelPortError::Contract(error.to_string()))?;
        record
            .validate_for_fence(&self.snapshot.state_fence())
            .map_err(|error| KernelPortError::Contract(error.to_string()))?;
        if record != expected
            || record.namespace != OWNER_RECOVERY_NAMESPACE
            || record.key != "work_scope"
            || record.state_fence != self.snapshot.state_fence()
        {
            return Err(KernelPortError::Contract(
                "Kernel WorkScope owner write did not return the exact durable readback".to_owned(),
            ));
        }
        StoreWorkScopeOwnerResponse {
            record: record.clone(),
        }
        .validate_for_request(&request)
        .map_err(|error| KernelPortError::Contract(error.to_string()))?;
        Ok(record)
    }

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
