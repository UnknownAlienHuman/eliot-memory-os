//! Authenticated readiness journal append mechanism.
//!
//! Architecture: `docs/architecture/ELIOT_ARCHITECTURE.md` handles `A2.2`,
//! `A2.3`, and `A12.3`, plus Decision Anchors
//! `docs/architecture/A16-01-decision-anchors.md` `ARCH-AUTH-01`, `ARCH-SEC-02`,
//! and `ARCH-RES-01`. Implementation:
//! `docs/architecture/ELIOT_IMPLEMENTATION.md` handles `I1.8`, `I1.9`, `I2.15`,
//! and `I2.23`. Normative precedence remains in `docs/ARCHITECTURE_CONTRACT.md`.
//!
//! This child owns only the extracted mechanism for constructing and appending
//! already-authorized authenticated readiness journal records. It owns no
//! readiness authority, lifecycle, SCM/process, canonical/semantic, or write
//! authority; those boundaries remain with the existing Host composition and
//! journal owners.

use super::super::HostError;
#[cfg(windows)]
use super::super::watchdog_publication::supervision_publication_identity;
#[cfg(windows)]
use super::super::{
    AuthenticatedKernelReadiness, PublishedSupervisionIdentity, fresh_identity, operation,
};
use eliot_host_state::{
    AppendReceipt, HostStateJournalService, JournalBackend, JournalError,
    KernelReadinessObservationRecord, ReadinessApprovedContour,
};
#[cfg(windows)]
use eliot_host_state::{HostStateRecord, NonceState, record_checksum};
#[cfg(windows)]
use eliot_platform::PlatformHandle;
#[cfg(windows)]
use eliot_runtime_contracts::{
    KernelActivationState, LeaseState, ServiceProcessRecord, ServiceProcessState,
    SupervisionLeasePredecessorIdentity, WatchdogAdmissionTemplate,
};

// F-LOG-HOST-6 (#981) readiness-append observation helpers.
//
// Through the #889 facade only
// (`crate::host_diagnostics::observe_entrypoint_with_detail`); the Event Log
// seam stays typed-Unavailable
// (`crate::windows_event_log::event_log_sink_status`), never implemented here
// (#984 still open).
//
// Observation-only contract: every helper projects facts already produced by
// the semantic owner. Arguments are static literals only — never evidence
// refs, digests, or arbitrary error text — so bounding limits size, not
// sensitivity (I15.4). Appended evidence and granted readiness stay
// distinct: this child observes the evidence funnel; the readiness grant
// stays with the gate owner (I1.10). These primitives own no terminal: a
// single terminal per failed readiness operation is enforced by the
// outermost owner boundary, while these phases correlate by stage order
// only. Sink outcome never alters result/order/cleanup.
fn host_readiness_append_observe(detail: &str) {
    let _ = crate::windows_event_log::event_log_sink_status();
    crate::host_diagnostics::observe_entrypoint_with_detail(
        crate::host_diagnostics::EntrypointStage::Startup,
        detail,
    );
}

fn append_reconciled_readiness<B: JournalBackend>(
    journal: &HostStateJournalService<B>,
    observation: KernelReadinessObservationRecord,
    expected: &ReadinessApprovedContour,
) -> Result<AppendReceipt, HostError> {
    host_readiness_append_observe("host.readiness append requested");
    match journal.append_readiness_observation(observation.clone(), expected) {
        Ok(receipt) => {
            host_readiness_append_observe("host.readiness append durable observed");
            Ok(receipt)
        }
        Err(JournalError::OutcomeUnknown { transaction_id }) => {
            host_readiness_append_observe("host.readiness append outcome unknown observed");
            if super::reconcile_unknown_outcome(journal, &transaction_id)? {
                journal
                    .append_readiness_observation(observation, expected)
                    .map_err(HostError::Journal)
            } else {
                // Unreachable today: the choke fails closed instead of returning
                // `Ok(false)`. Retained fail-closed so semantics stay identical
                // if the policy ever evolves.
                Err(HostError::Journal(JournalError::OutcomeUnknown {
                    transaction_id,
                }))
            }
        }
        Err(error) => {
            host_readiness_append_observe("host.readiness append rejected observed");
            Err(HostError::Journal(error))
        }
    }
}

/// Binds the exact admitted watchdog supervision branch behind one readiness
/// proof into the persisted observation evidence: the content-addressed
/// `Watchdog` publication digest joined to the admitted lease identity, the
/// canonical `ORS` receipt digest, and the admitted watchdog epoch.
///
/// Single-snapshot boundary: the ONLY lease input is the Kernel-renewed
/// supervision snapshot (production passes `proof.supervision_lease`). The
/// publication identity is derived from that same snapshot via
/// `supervision_publication_identity` — there is no independent
/// caller-supplied identity alongside, so a foreign or stale branch cannot be
/// mixed into the ref. The provisioned admission template is durable Phase-B
/// authority, not identity, and its scope (installation plus lease scope) is
/// cross-checked against the snapshot payload scope; any mismatch fails
/// closed. The snapshot itself is authenticated (`validate`), must be
/// `Active`/`Active`, and must carry a nonzero watchdog epoch; anything else
/// fails closed instead of persisting a readiness observation that would
/// read as independently supervised (I1.5, Windows-only path).
///
/// Publication exactness against the `ORS` head is verified at publish time by
/// `verify_exact_current_watchdog_publication`, head currency by
/// `require_exact_supervision_head`, and epoch equality by the Kernel
/// `ProbeReady` watchdog-branch gate.
#[cfg(windows)]
pub(crate) fn watchdog_branch_evidence_ref(
    template: &WatchdogAdmissionTemplate,
    admitted_lease: &eliot_ors::SupervisionLeaseSnapshot,
) -> Result<(PlatformHandle, PublishedSupervisionIdentity), HostError> {
    admitted_lease
        .validate()
        .map_err(|error| HostError::RecoveryRequired(error.to_string()))?;
    if admitted_lease.record.state != LeaseState::Active
        || admitted_lease.record.projection != eliot_ors::SupervisionLeaseProjection::Active
    {
        return Err(HostError::RecoveryRequired(
            "Kernel supervision snapshot is not an admitted Active watchdog branch".to_owned(),
        ));
    }
    if template.installation_id != admitted_lease.record.artifact.payload.installation_id
        || template.supervision_lease_scope_id != admitted_lease.record.artifact.payload.scope_ref
    {
        return Err(HostError::RecoveryRequired(
            "provisioned Watchdog admission scope does not match the admitted supervision lease"
                .to_owned(),
        ));
    }
    let watchdog_epoch = admitted_lease.record.binding.watchdog_epoch.value();
    if watchdog_epoch == 0 {
        return Err(HostError::RecoveryRequired(
            "Kernel supervision snapshot carries no admitted watchdog epoch".to_owned(),
        ));
    }
    let supervision = supervision_publication_identity(template, admitted_lease)?;
    PlatformHandle::new(format!(
        "watchdog-branch:{}:lease:{}:receipt:{}:epoch:{watchdog_epoch}",
        supervision.publication_digest.as_str(),
        admitted_lease.record.lease_id.as_str(),
        admitted_lease.receipt.receipt_sha256,
    ))
    .map_err(|error| HostError::Platform(error.to_string()))
    .map(|evidence_ref| (evidence_ref, supervision))
}

#[cfg(windows)]
pub(crate) fn append_authenticated_kernel_readiness<B: JournalBackend>(
    journal: &HostStateJournalService<B>,
    proof: &AuthenticatedKernelReadiness,
    approved_kernel_artifact: &PlatformHandle,
    approved_config: &PlatformHandle,
    watchdog_template: &WatchdogAdmissionTemplate,
) -> Result<(AppendReceipt, PublishedSupervisionIdentity), HostError> {
    host_readiness_append_observe("host.readiness authenticated requested");
    let snapshot = journal.snapshot()?;
    let active = snapshot.kernel.as_ref().ok_or_else(|| {
        HostError::ProcessContour("readiness admission has no active Kernel record".to_owned())
    })?;
    let active_process = active.process.as_ref().ok_or_else(|| {
        HostError::ProcessContour("active Kernel process binding is absent".to_owned())
    })?;
    let active_job = active.candidate_job_binding.as_ref().ok_or_else(|| {
        HostError::ProcessContour("active Kernel Job binding is absent".to_owned())
    })?;
    let candidate = &proof.request.candidate;
    let job = &candidate.job_binding;
    if active.state != KernelActivationState::Active
        || active.one_time_nonce.state() != NonceState::Consumed
        || candidate.installation_id != snapshot.host.installation
        || candidate.host_epoch.value() != snapshot.host.epoch.current.sequence.get()
        || active.activation_identity != candidate.activation_id
        || active.approved_artifact_hash != *approved_kernel_artifact
        || candidate.artifact_hash != *approved_kernel_artifact
        || candidate.config_hash != *approved_config
        || active.active_pipe_identity.as_ref() != Some(&candidate.pipe_identity)
        || active_process.authority_epoch.value() != candidate.kernel_epoch.sequence.get()
        || active_process.process_id != proof.ready.process.process_id.as_str()
        || active_job.job_name.as_str() != job.job.name
        || active_job.root_pid != job.root.process.process_id
        || active_job.root_start_time_100ns != job.root.process.start_time_100ns
        || active_job.root_image_path.as_str() != job.root.process.image_path
        || active_job.root_volume_serial_number != job.root.executable.volume_serial_number
        || active_job.root_file_index != job.root.executable.file_index
    {
        host_readiness_append_observe("host.readiness contour mismatch observed");
        return Err(HostError::ProcessContour(
            "Kernel readiness proof is not bound to the active journal contour".to_owned(),
        ));
    }
    let active_checksum = record_checksum(&HostStateRecord::Kernel(active.clone()))?;
    let response_digest = PlatformHandle::new(proof.response.payload_digest.clone())
        .map_err(|error| HostError::Platform(error.to_string()))?;
    let mut evidence_refs = proof.ready.evidence_refs.clone();
    evidence_refs.push(proof.peer_evidence.clone());
    evidence_refs.push(
        PlatformHandle::new(format!("kernel-response:{}", response_digest.as_str()))
            .map_err(|error| HostError::Platform(error.to_string()))?,
    );
    // Single-snapshot boundary: the supervision identity below is derived
    // from the same Kernel-renewed snapshot (proof.supervision_lease) that the
    // ProbeReady gate admitted — never a caller-supplied identity.
    let (watchdog_branch_ref, supervision) =
        watchdog_branch_evidence_ref(watchdog_template, &proof.supervision_lease)?;
    evidence_refs.extend(supervision.evidence_refs()?);
    evidence_refs.push(watchdog_branch_ref);
    let expected = ReadinessApprovedContour {
        config_digest: approved_config.clone(),
        store_fence: proof.store_fence.clone(),
    };
    let receipt = append_reconciled_readiness(
        journal,
        KernelReadinessObservationRecord {
            fence: active.fence.clone(),
            operation: operation("kernel-readiness-observation")?,
            active_kernel_record_checksum: PlatformHandle::new(active_checksum)
                .map_err(|error| HostError::Platform(error.to_string()))?,
            probe_request_digest: PlatformHandle::new(proof.request.payload_digest.clone())
                .map_err(|error| HostError::Platform(error.to_string()))?,
            ready_receipt_digest: response_digest,
            kernel_process: ServiceProcessRecord {
                process_id: proof.ready.process.process_id.as_str().to_owned(),
                owner: active_process.owner.clone(),
                state: ServiceProcessState::Ready,
                health: proof.ready.health,
                authority_epoch: eliot_contracts::AuthorityEpoch::new(
                    candidate.kernel_epoch.sequence.get(),
                )
                .map_err(|error| HostError::ProcessContour(error.to_string()))?,
            },
            kernel_job: active_job.clone(),
            config_digest: approved_config.clone(),
            authority_epoch: candidate.kernel_epoch.sequence.get(),
            store_fence: proof.store_fence.clone(),
            observed_at: fresh_identity("kernel-readiness-observed-at")?,
            evidence_refs,
            active_supervision_lease: Some(SupervisionLeasePredecessorIdentity {
                supervision_lease_id: supervision.lease_id.as_str().to_owned(),
                ors_receipt_sha256: supervision.ors_receipt_digest.as_str().to_owned(),
            }),
        },
        &expected,
    )?;
    host_readiness_append_observe("host.readiness evidence appended");
    Ok((receipt, supervision))
}
