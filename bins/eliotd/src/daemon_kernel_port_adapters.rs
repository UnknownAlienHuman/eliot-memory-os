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
use eliot_maintenance::{MaintenanceJob, prove_job_intent_durable};

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

/// Decodes one Kernel-owned durable job revision through the single closed
/// `durable_job` kind and validates it.
///
/// Both the save reply and the owning load path serve the owner's own
/// committed bytes under this kind, so both decode here instead of each
/// carrying a second decoder. A wrong kind, undecodable bytes, or a revision
/// the maintenance owner refuses is a contract refusal, never a substituted
/// or defaulted job.
fn decode_committed_job(value: &serde_json::Value) -> Result<MaintenanceJob, KernelPortError> {
    let value = kind_value(value, "durable_job")?;
    let job: MaintenanceJob = serde_json::from_value(value)
        .map_err(|error| KernelPortError::Contract(error.to_string()))?;
    job.validate()
        .map_err(|error| KernelPortError::Contract(error.to_string()))?;
    Ok(job)
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
        Ok(Some(decode_committed_job(&value)?))
    }

    fn save_durable_job(&self, job: &MaintenanceJob) -> Result<(), KernelPortError> {
        // #740: request/result span over the durable-job save boundary.
        let _span = tracing::info_span!("eliotd.kernel_durable_save").entered();
        // The intent is validated before it travels: a malformed revision is
        // the caller's defect, not a commit the owner could have recorded.
        job.validate()
            .map_err(|error| KernelPortError::Contract(error.to_string()))?;
        let value = self.request_blocking("save_durable_job", serde_json::json!({ "job": job }))?;
        // Transport acknowledgement is not commit proof (issue #1694 W4): the
        // reply must carry the owner's own committed bytes binding this exact
        // job and trigger identity, or the save is refused and the trigger
        // stays retained and unacknowledged.
        let committed = decode_committed_job(&value)?;
        prove_job_intent_durable(job, &committed)
            .map_err(|error| KernelPortError::Contract(error.to_string()))?;
        // The save acknowledgement alone still proves nothing durable: close
        // the commit through the owning load path and require the retained
        // revision to bind the same intent. An absent or substituted read-back
        // leaves the outcome explicitly incomplete for receipt reconciliation,
        // never a success.
        let retained = self
            .load_durable_job(&job.job_id, &job.state_fence)?
            .ok_or_else(|| {
                KernelPortError::Contract(
                    "Kernel durable-job save has no retained revision for the saved job identity"
                        .to_owned(),
                )
            })?;
        prove_job_intent_durable(job, &retained)
            .map_err(|error| KernelPortError::Contract(error.to_string()))?;
        Ok(())
    }
}

impl DaemonKernelClient {
    /// Reads one durable job back through the owning async transport path.
    ///
    /// Byte-identical route and decode to
    /// [`KernelDurableJobPort::load_durable_job`]: the same
    /// `"load_durable_job"` operation under the caller's fence and the same
    /// single `"durable_job"` kind decode. The sync port method cannot serve
    /// the async #1694 W4 decision-commit binding, which must not block the
    /// executor on the sync bridge; this is that same read without the
    /// bridge. A wrong kind, undecodable bytes, or a revision the maintenance
    /// owner refuses is the transport's own contract refusal, and a read the
    /// exchange cannot complete stays that refusal too: the commit binds
    /// nothing and the trigger stays retained instead of binding a phantom
    /// intent. This adds no policy and no receipt interpretation of its own.
    ///
    /// # Errors
    ///
    /// Returns [`KernelPortError`] when the authenticated exchange refuses or
    /// cannot complete the read, or when the committed bytes do not decode.
    pub(super) async fn load_durable_job_async(
        &self,
        job_id: &str,
        state_fence: &StateFence,
    ) -> Result<MaintenanceJob, KernelPortError> {
        // #740: request/result span over the durable-job read boundary.
        let _span = tracing::info_span!(
            "eliotd.kernel_durable_read",
            job = %super::diagnostics::sanitize_identity(job_id)
        )
        .entered();
        let value = self
            .transact_async(
                "load_durable_job",
                serde_json::json!({ "job_id": job_id, "state_fence": state_fence }),
            )
            .await
            .map_err(kernel_port_error)?;
        decode_committed_job(&value)
    }
}
