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
//! lifecycle, local Store, or semantic authority. The async durable-job
//! read-back below exists for the #1694 W4 decision-commit binding, which
//! proves a referenced job durable through the owning read path instead of
//! accepting the save transport acknowledgement; it adds no policy and no
//! receipt interpretation of its own.

use eliot_contracts::StateFence;
use eliot_governor::{
    KernelDurableJobPort, KernelGenerationSnapshot, KernelGenerationSnapshotProvider,
    KernelPortError, KernelServiceObservationPort, KernelServiceRecovery,
};
use eliot_maintenance::MaintenanceJob;

use super::{DaemonKernelClient, kernel_port_error};

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
        decode_durable_job(value)
    }

    fn save_durable_job(&self, job: &MaintenanceJob) -> Result<(), KernelPortError> {
        // #740: request/result span over the durable-job save boundary.
        let _span = tracing::info_span!("eliotd.kernel_durable_save").entered();
        let _ = self.request_blocking("save_durable_job", serde_json::json!({ "job": job }))?;
        Ok(())
    }
}

impl DaemonKernelClient {
    /// Reads one durable job back through the owning async transport path.
    ///
    /// Byte-identical route and decode to
    /// [`KernelDurableJobPort::load_durable_job`]: the same
    /// `"load_durable_job"` operation under the caller's fence and the same
    /// `"durable_job"` kind decode. The sync port method cannot serve the
    /// async #1694 W4 decision-commit binding, which must not block the
    /// executor on the sync bridge; this is that same read without the
    /// bridge. Transport refusal stays a [`KernelPortError`]; absence stays
    /// `Ok(None)` and never becomes a fabricated job.
    pub(super) async fn load_durable_job_async(
        &self,
        job_id: &str,
        state_fence: &StateFence,
    ) -> Result<Option<MaintenanceJob>, KernelPortError> {
        let value = self
            .transact_async(
                "load_durable_job",
                serde_json::json!({ "job_id": job_id, "state_fence": state_fence }),
            )
            .await
            .map_err(kernel_port_error)?;
        decode_durable_job(value)
    }
}

/// Decodes one `"durable_job"` kind response into the optional retained job.
///
/// Shared by the sync port read and the async #1694 W4 read-back so the two
/// paths can never drift into different decoders: a malformed payload stays
/// a typed contract refusal, and absence stays `Ok(None)`.
fn decode_durable_job(
    value: serde_json::Value,
) -> Result<Option<MaintenanceJob>, KernelPortError> {
    let value = kind_value(&value, "durable_job")?;
    serde_json::from_value(value).map_err(|error| KernelPortError::Contract(error.to_string()))
}
