//! Kernel port adapters for `eliotd`.
//!
//! Architecture: A2.3 (contract -> ports -> adapters layering) and A13.2
//! (Kernel failure-domain and operational ownership).
//! Implementation: I1.8 (exact ownership and read path), I10.17 (adapter
//! subsystem), B.1 (Kernel <-> Daemon boundary), and P.3 (Kernel control
//! boundary).
//! This is the application-facing Kernel port boundary: it observes typed
//! Kernel state, exchanges Kernel-owned durable jobs, and records the canonical
//! second-phase closure link through the Kernel that owns ORS. Durable-job
//! saving is not a local semantic or canonical write, and the closure link
//! grants no authority: it only makes an already fenced closure's canonical
//! reconciliation durable. It owns no transport, lifecycle, local Store, or
//! semantic authority.

use eliot_contracts::StateFence;
use eliot_governor::{
    GrantClosureCanonicalLinkPort, GrantClosureSecondPhaseLink, KernelDurableJobPort,
    KernelGenerationSnapshot, KernelGenerationSnapshotProvider, KernelPortError,
    KernelPortFuture, KernelServiceObservationPort, KernelServiceRecovery,
};
use eliot_maintenance::{MaintenanceJob, prove_job_intent_durable};
use eliot_receipts::{GrantClosureReceipt, ReceiptIdentity};

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

/// Authenticated P-07 write route recording the canonical second-phase
/// receipt link against one committed closure first phase (issue #686).
const LINK_GRANT_CLOSURE_RECEIPT_OPERATION: &str = "link_grant_closure_canonical_receipt";
/// Typed receipt kind answered by the canonical second-phase link arm.
const GRANT_CLOSURE_LINK_KIND: &str = "grant_closure_canonical_receipt_link";
/// Typed refusal kind answered by the same arm. A refusal is never an absent
/// link read as "canonical reconciliation completed".
const GRANT_CLOSURE_LINK_REFUSAL_KIND: &str = "grant_closure_canonical_receipt_link_refused";

/// The two facts the link proof reads out of the Kernel's durable row
/// projection.
///
/// The Kernel serves its whole `GrantClosureProjection`, which also carries the
/// ORS lifecycle phase, the monotonic operation order and the store-issued
/// row receipt. Those are operational evidence no Governor proof and no caller
/// reads — the in-process ORS adapter drops them for the same reason — so this
/// decode selects the two store-neutral facts by name and lets the remaining
/// operational fields go unread rather than re-declaring the projection here.
#[derive(serde::Deserialize)]
struct GrantClosureLinkReadback {
    /// The ORIGINAL committed first-phase closure row, exactly as ORS holds it.
    commit: GrantClosureReceipt,
    /// The durable canonical second-phase link, absent until one is recorded.
    second_phase: Option<ReceiptIdentity>,
}

/// The one production [`GrantClosureCanonicalLinkPort`] implementation in the
/// daemon composition root (issue #686).
///
/// The Kernel owns ORS inside the Kernel process, so this process has no ORS
/// handle and must never gain one: the link travels over the already-connected
/// authenticated front door to the Kernel route that records it against the one
/// durable store holding the immutable first-phase row. This is the transport
/// realization the port's own contract asks for — every type in its signature
/// is reachable from a daemon dependency set that holds no in-process ORS.
///
/// The call is the same `transact_async` exchange the closure-receipt read
/// uses, awaited rather than blocked: the drive that reaches this port runs
/// inside the daemon's pollable runtime, so a blocking round trip here would
/// either stall health and shutdown or build a nested runtime, which panics.
///
/// Nothing is invented here. `operation_id` is the ORIGINAL recorded
/// first-phase identity the caller presents, `canonical_receipt` is the exact
/// Store-issued identity the canonical commit returned, and the returned link
/// carries the owner's own committed read-back. The Kernel's own service
/// validates the committed first phase and the link before it answers; this
/// adapter re-proves the same three facts on the served bytes so it never takes
/// the far side's word for them, and refuses a refusal rather than reading it as
/// a completed link.
impl GrantClosureCanonicalLinkPort for DaemonKernelClient {
    fn link_grant_closure_canonical_receipt<'a>(
        &'a self,
        operation_id: &'a str,
        canonical_receipt: &'a ReceiptIdentity,
    ) -> KernelPortFuture<'a, GrantClosureSecondPhaseLink> {
        Box::pin(async move {
            let state_fence = self.snapshot.state_fence();
            let value = self
                .transact_async(
                    LINK_GRANT_CLOSURE_RECEIPT_OPERATION,
                    serde_json::json!({
                        "state_fence": state_fence,
                        "closure_operation_id": operation_id,
                        "canonical_receipt": canonical_receipt,
                    }),
                )
                .await
                .map_err(|error| {
                    KernelPortError::Unknown(format!(
                        "canonical second-phase link outcome is unestablished at the Kernel \
                         transport for {operation_id}: {error}"
                    ))
                })?;
            let object = value.as_object().ok_or_else(|| {
                KernelPortError::Contract(
                    "canonical second-phase link reply is not a typed object".to_owned(),
                )
            })?;
            match object.get("kind").and_then(serde_json::Value::as_str) {
                Some(GRANT_CLOSURE_LINK_KIND) => {}
                Some(GRANT_CLOSURE_LINK_REFUSAL_KIND) => {
                    let reason = object
                        .get("value")
                        .and_then(|value| value.get("reason"))
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or("unspecified durable refusal");
                    return Err(KernelPortError::Contract(format!(
                        "Kernel refused the canonical second-phase link for {operation_id}: {reason}"
                    )));
                }
                other => {
                    return Err(KernelPortError::Contract(format!(
                        "canonical second-phase link returned an unexpected kind: {other:?}"
                    )));
                }
            }
            let readback: GrantClosureLinkReadback =
                serde_json::from_value(kind_value(&value, GRANT_CLOSURE_LINK_KIND)?).map_err(
                    |error| {
                        KernelPortError::Contract(format!(
                            "canonical second-phase link read-back does not decode: {error}"
                        ))
                    },
                )?;
            // The ORIGINAL recorded first-phase bytes revalidate under their own
            // receipt contract. Nothing is recomputed as a substitute for
            // validating the value the owner actually committed.
            readback.commit.validate().map_err(|error| {
                KernelPortError::Contract(format!(
                    "canonical second-phase link read-back first phase fails its own receipt \
                     contract: {error}"
                ))
            })?;
            let Some(second_phase) = readback.second_phase else {
                return Err(KernelPortError::Contract(
                    "canonical second-phase link read-back carries no durable link".to_owned(),
                ));
            };
            if readback.commit.operation_id != operation_id
                || &second_phase != canonical_receipt
                || readback
                    .commit
                    .canonical_receipt
                    .as_ref()
                    .is_some_and(|first_phase| first_phase != canonical_receipt)
            {
                return Err(KernelPortError::Contract(
                    "canonical closure receipt link read-back disagrees".to_owned(),
                ));
            }
            Ok(GrantClosureSecondPhaseLink::new(readback.commit, second_phase))
        })
    }
}
