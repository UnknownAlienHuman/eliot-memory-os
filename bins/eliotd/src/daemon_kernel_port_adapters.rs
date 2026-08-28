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
//! lifecycle, local Store, or semantic authority.

use eliot_contracts::StateFence;
use eliot_governor::{
    KernelDurableJobPort, KernelGenerationSnapshot, KernelGenerationSnapshotProvider,
    KernelPortError, KernelServiceObservationPort, KernelServiceRecovery,
};
use eliot_maintenance::MaintenanceJob;

use super::DaemonKernelClient;

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
        let value = self.request_blocking(
            "load_durable_job",
            serde_json::json!({ "job_id": job_id, "state_fence": state_fence }),
        )?;
        let value = kind_value(&value, "durable_job")?;
        serde_json::from_value(value).map_err(|error| KernelPortError::Contract(error.to_string()))
    }

    fn save_durable_job(&self, job: &MaintenanceJob) -> Result<(), KernelPortError> {
        let _ = self.request_blocking("save_durable_job", serde_json::json!({ "job": job }))?;
        Ok(())
    }
}
