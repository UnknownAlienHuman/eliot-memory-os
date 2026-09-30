//! Read-only Kernel port adapters for `eliotd`.
//!
//! Architecture: A2.3 (contract -> ports -> adapters layering) and A13.2
//! (Kernel failure-domain and operational ownership).
//! Implementation: I1.8 (exact ownership and read path), I10.17 (adapter
//! subsystem), B.1 (Kernel <-> Daemon boundary), and P.3 (Kernel control
//! boundary).
//! This is the read-only application-facing Kernel port boundary: it observes
//! typed Kernel state and exchanges Kernel-owned durable jobs; durable-job
//! saving is not a local semantic or canonical write. It owns no transport,
//! lifecycle, local Store, or semantic authority. The one exception is the
//! #1694 W4 decision-commit caller at the bottom of this file: it carries a
//! Governor-built trigger decision to the Governor composition, which submits
//! it through Governor PreparedTransition → Kernel → named Store transaction;
//! the caller adds no policy, no transition planning, and no receipt
//! interpretation of its own.

use eliot_contracts::{
    ClockReading, ProductId, RequestId, RequestMetadata, SourceId, StateFence,
    canonical_json_bytes, sha256_hex,
};
use eliot_governor::{
    CompositionError, GovernorComposition, KernelDurableJobPort, KernelGenerationPort,
    KernelGenerationSnapshot, KernelGenerationSnapshotProvider, KernelPortError,
    KernelServiceObservationPort, KernelServiceRecovery, MaintenanceTriggerDecisionCommit,
};
use eliot_maintenance::MaintenanceJob;
use eliot_protocol::RequestIdentity;
use eliot_receipts::RequestBinding;
use eliot_store_api::{OrderingHeadExpectation, RevisionHeadExpectation, WriteReceipt};
use tracing::Instrument as _;

use super::{DaemonKernelClient, SERVICE_NAME, unix_ms};

pub(crate) fn kind_value(
    value: &serde_json::Value,
    expected_kind: &str,
) -> Result<serde_json::Value, KernelPortError> {
    let object = value.as_object().ok_or_else(|| {
        KernelPortError::Contract("Kernel typed application value is not an object".to_owned())
    })?;
    if object.get("kind").and_then(serde_json::Value::as_str) != Some(expected_kind) {
        return Err(KernelPortError::Contract(format!(
            "Kernel returned unexpected application kind; expected {expected_kind}"
        )));
    }
    object.get("value").cloned().ok_or_else(|| {
        KernelPortError::Contract("Kernel typed value is missing payload".to_owned())
    })
}

impl KernelGenerationSnapshotProvider for DaemonKernelClient {
    fn snapshot(&self) -> &KernelGenerationSnapshot {
        &self.snapshot
    }
}

impl KernelServiceObservationPort for DaemonKernelClient {
    fn services(
        &self,
        state_fence: &StateFence,
        protected_snapshot_digest: &str,
    ) -> Result<Vec<KernelServiceRecovery>, KernelPortError> {
        // #740: request/result span over the observation boundary.
        let _span = tracing::info_span!("eliotd.kernel_services").entered();
        let value = self.request_blocking(
            "services",
            serde_json::json!({
                "state_fence": state_fence,
                "protected_snapshot_digest": protected_snapshot_digest,
            }),
        )?;
        let value = kind_value(&value, "services")?;
        serde_json::from_value(value).map_err(|error| KernelPortError::Contract(error.to_string()))
    }
}

impl KernelDurableJobPort for DaemonKernelClient {
    fn load_durable_job(
        &self,
        job_id: &str,
        state_fence: &StateFence,
    ) -> Result<Option<MaintenanceJob>, KernelPortError> {
        // #740: request/result span over the durable-job read boundary.
        let _span = tracing::info_span!(
            "eliotd.kernel_durable_read",
            job = %super::diagnostics::sanitize_identity(job_id)
        )
        .entered();
        let value = self.request_blocking(
            "load_durable_job",
            serde_json::json!({ "job_id": job_id, "state_fence": state_fence }),
        )?;
        let value = kind_value(&value, "durable_job")?;
        serde_json::from_value(value).map_err(|error| KernelPortError::Contract(error.to_string()))
    }

    fn save_durable_job(&self, job: &MaintenanceJob) -> Result<(), KernelPortError> {
        // #740: request/result span over the durable-job save boundary.
        let _span = tracing::info_span!("eliotd.kernel_durable_save").entered();
        let value = self.request_blocking("save_durable_job", serde_json::json!({ "job": job }))?;
        // #1694 W4: a transport acknowledgement is not proof of a canonical
        // decision commit. Require the Kernel-owned durable-job receipt to
        // carry the exact persisted job and bind it to the submitted trigger,
        // job identity and State Fence before reporting the save.
        let persisted: MaintenanceJob = serde_json::from_value(kind_value(&value, "durable_job")?)
            .map_err(|error| KernelPortError::Contract(error.to_string()))?;
        persisted
            .validate()
            .map_err(|error| KernelPortError::Contract(error.to_string()))?;
        if persisted.job_id != job.job_id
            || persisted.trigger_id != job.trigger_id
            || persisted.state_fence != job.state_fence
        {
            return Err(KernelPortError::Contract(
                "Kernel durable-job receipt does not bind the submitted trigger, job identity and fence"
                    .to_owned(),
            ));
        }
        Ok(())
    }
}

/// Derives the deterministic request identity for exact retries of one
/// trigger-revision decision commit in this authenticated daemon session.
///
/// Mirrors `maintenance_trigger_claim_request_identity`: the digest binds the
/// operation, the daemon connection, the live fence, and the exact
/// trigger/revision/hash being committed, so a lost commit response replays
/// under the same identity (convergent Store idempotency) instead of minting
/// a competing decision. A replacement daemon session passes a different
/// connection reference and must pass the normal Kernel checks.
pub(super) fn maintenance_trigger_decision_commit_identity(
    fence: &StateFence,
    connection_ref: &str,
    commit: &MaintenanceTriggerDecisionCommit,
    applicable_until_unix_ms: u64,
) -> Result<RequestIdentity, KernelPortError> {
    fence
        .validate()
        .map_err(|error| KernelPortError::Contract(error.to_string()))?;
    if connection_ref.trim().is_empty() || connection_ref.chars().any(char::is_control) {
        return Err(KernelPortError::Contract(
            "maintenance decision commit connection reference is blank".to_owned(),
        ));
    }
    if commit.trigger_id.trim().is_empty() || commit.operation_hash.trim().is_empty() {
        return Err(KernelPortError::Contract(
            "maintenance decision commit carries no trigger identity and hash".to_owned(),
        ));
    }
    if commit.trigger_revision == 0 {
        return Err(KernelPortError::Contract(
            "maintenance decision commit trigger revision must be positive".to_owned(),
        ));
    }
    if applicable_until_unix_ms <= unix_ms() {
        return Err(KernelPortError::Contract(
            "maintenance trigger decision is no longer applicable for a commit".to_owned(),
        ));
    }
    let identity_material = serde_json::json!({
        "operation": "maintenance_trigger_decision_commit",
        "connection_ref": connection_ref,
        "state_fence": fence,
        "trigger_id": commit.trigger_id,
        "trigger_revision": commit.trigger_revision,
        "operation_hash": commit.operation_hash,
    });
    let canonical = canonical_json_bytes(&identity_material)
        .map_err(|error| KernelPortError::Contract(error.to_string()))?;
    let digest = sha256_hex(&canonical);
    let request_id = RequestId::new(format!(
        "{SERVICE_NAME}:maintenance_trigger_decision_commit:{digest}"
    ))
    .map_err(|error| KernelPortError::Contract(error.to_string()))?;
    let idempotency_key = format!("{SERVICE_NAME}:maintenance_trigger_decision_commit:{digest}");
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
            valid_time_ms: None,
            known_time_ms: None,
            transaction_sequence: None,
            monotonic_ns: None,
        },
    };
    let identity = RequestIdentity {
        request: RequestBinding {
            metadata,
            state_fence: fence.clone(),
        },
        idempotency_key,
        deadline_unix_ms: applicable_until_unix_ms,
        cancellation_id: format!(
            "{SERVICE_NAME}:maintenance_trigger_decision_commit:{digest}:cancel"
        ),
    };
    identity
        .validate()
        .map_err(|error| KernelPortError::Contract(error.to_string()))?;
    Ok(identity)
}

/// Commits one Governor-built trigger decision through Governor
/// `PreparedTransition` → Kernel → named Store transaction and returns the
/// exact canonical receipt the trigger ack requires (#1694 W4).
///
/// The exact-retry [`RequestIdentity`] is derived here from the live fence,
/// the authenticated daemon connection reference, the commit, and the
/// applicability deadline — never accepted from a caller — so a lost commit
/// response replays under the same derived identity (convergent Store
/// idempotency) instead of minting a competing decision (#1694 W5: the retry
/// identity is preserved by derivation, not by trusting the retrier).
///
/// STITCH: adopted by the eliotd daemon commit lane. The #1688 decision
/// joined with the current #1692 policy evidence through
/// [`MaintenanceTriggerDecisionCommit::for_decision`] is committed here; the
/// trigger is acked only on the returned receipt. A transport
/// acknowledgement (`Ok(())`) or an arbitrary receipt ID is never
/// sufficient: the Governor commit validates the exact canonical receipt
/// before returning. Failures stay typed as [`CompositionError`]; this seam
/// adds no second decision owner.
pub(crate) async fn commit_maintenance_trigger_decision(
    composition: &GovernorComposition<dyn KernelGenerationPort>,
    fence: &StateFence,
    connection_ref: &str,
    commit: MaintenanceTriggerDecisionCommit,
    applicable_until_unix_ms: u64,
    proof_refs: Vec<String>,
    expected_revision_heads: Vec<RevisionHeadExpectation>,
    expected_ordering_heads: Vec<OrderingHeadExpectation>,
) -> Result<WriteReceipt, CompositionError> {
    // #740: commitment span over the decision-commit boundary
    // (`Send`-safe instrumentation; no entered guard crosses an await).
    let span = tracing::info_span!(
        "eliotd.maintenance_decision_commit",
        trigger = %super::diagnostics::sanitize_identity(&commit.trigger_id)
    );
    async move {
        let identity = maintenance_trigger_decision_commit_identity(
            fence,
            connection_ref,
            &commit,
            applicable_until_unix_ms,
        )
        .map_err(|error| CompositionError::Owner(error.to_string()))?;
        composition
            .commit_maintenance_trigger_decision(
                &identity,
                &commit,
                proof_refs,
                expected_revision_heads,
                expected_ordering_heads,
            )
            .await
    }
    .instrument(span)
    .await
}
