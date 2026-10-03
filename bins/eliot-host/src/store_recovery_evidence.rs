use std::path::Path;

use serde::{Deserialize, Serialize};

use super::{
    HostError, HostRuntimeControlOperation, HostRuntimeControlRequest, PlatformHandle,
    StoreRebindHandoff, StoreRecoveryPendingIdentity, read_bounded_runtime_restart_file,
    sha256_json, store_recovery_inner_binding_path, store_recovery_termination_path,
    valid_sha256_text,
};

#[cfg(windows)]
use crate::journal_append::{
    HostJournalDisposition, HostJournalObservation, observe_host_journal_boundary,
};

// F-LOG-HOST-6 (#981) recovery-evidence observation helper.
//
// The per-file seam of the family's shared closed vocabulary: it names the Store
// recovery evidence boundary set and delegates to the one shared emitter.
//
// Observation-only contract: every record projects the exact identity the
// evidence owner already read — the requested mutation digest, the read
// evidence's own operation, request, mutation and request digests, and the
// durable Host epoch and lineage it is bound to — and never its bytes, image
// path, or error text, so bounding limits size, not sensitivity (I15.4). An
// absent evidence file is now observed as the exact incomplete fact it is,
// still returning `Ok(None)`: absence is never a synthesized binding, and a
// later read of the same mutation can no longer be read as the first. These
// primitives own no terminal, and the live Event Log disposition is observed
// through the facade's canonical bounded helper rather than a discarded probe.
#[cfg(windows)]
fn host_recovery_observe(observation: &HostJournalObservation) {
    observe_host_journal_boundary(observation);
}

#[cfg(windows)]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct StoreRecoveryTerminationEvidence {
    pub(super) wire: String,
    pub(super) operation: HostRuntimeControlOperation,
    pub(super) request_id: String,
    pub(super) mutation_digest: String,
    pub(super) request_digest: String,
    pub(super) host_epoch: u64,
    pub(super) host_lineage: String,
    pub(super) process_id: u32,
    pub(super) process_start_time_100ns: u64,
    pub(super) process_image_path: String,
    pub(super) job_name: String,
    pub(super) job_empty: bool,
    pub(super) root_reaped: bool,
    pub(super) restart_attempt: u8,
}

#[cfg(windows)]
impl StoreRecoveryTerminationEvidence {
    pub(super) fn validate_for_digest(
        &self,
        expected_mutation_digest: &str,
    ) -> Result<(), HostError> {
        if self.wire != "eliot.host.runtime-control.v2"
            || self.operation != HostRuntimeControlOperation::RecoverStore
            || self.request_id.trim().is_empty()
            || self.request_id.chars().any(char::is_control)
            || !valid_sha256_text(&self.mutation_digest)
            || !valid_sha256_text(&self.request_digest)
            || self.mutation_digest != expected_mutation_digest
            || self.host_epoch == 0
            || self.host_lineage.trim().is_empty()
            || self.host_lineage.chars().any(char::is_control)
            || self.process_id == 0
            || self.process_start_time_100ns == 0
            || self.process_image_path.trim().is_empty()
            || self.process_image_path.chars().any(char::is_control)
            || self.job_name.trim().is_empty()
            || self.job_name.chars().any(char::is_control)
            || !self.job_empty
            || !self.root_reaped
            || self.restart_attempt != 1
        {
            host_recovery_observe(
                &HostJournalObservation::new(
                    "host.recovery termination incomplete observed",
                    HostJournalDisposition::EvidenceIncomplete,
                )
                .with_operation(self.request_id.as_str())
                .with_mutation(self.mutation_digest.as_str())
                .with_request_digest(self.request_digest.as_str())
                .with_host_epoch(self.host_epoch)
                .with_host_lineage(self.host_lineage.as_str()),
            );
            return Err(HostError::RecoveryRequired(
                "Store termination evidence is not complete or is not bound to the mutation"
                    .to_owned(),
            ));
        }
        let request_id = PlatformHandle::new(self.request_id.clone()).map_err(|error| {
            HostError::RecoveryRequired(format!(
                "Store termination request identity is malformed: {error}"
            ))
        })?;
        let mutation_digest =
            PlatformHandle::new(self.mutation_digest.clone()).map_err(|error| {
                HostError::RecoveryRequired(format!(
                    "Store termination mutation identity is malformed: {error}"
                ))
            })?;
        let expected_request = HostRuntimeControlRequest::new_with_mutation_digest(
            HostRuntimeControlOperation::RecoverStore,
            request_id,
            mutation_digest,
        )
        .map_err(|error| {
            HostError::RecoveryRequired(format!(
                "Store termination request identity is malformed: {error}"
            ))
        })?;
        if expected_request.request_digest.as_str() != self.request_digest {
            host_recovery_observe(
                &HostJournalObservation::new(
                    "host.recovery termination digest mismatch observed",
                    HostJournalDisposition::EvidenceMismatched,
                )
                .with_operation(self.request_id.as_str())
                .with_mutation(self.mutation_digest.as_str())
                .with_request_digest(self.request_digest.as_str()),
            );
            return Err(HostError::RecoveryRequired(
                "Store termination request digest does not match its mutation identity".to_owned(),
            ));
        }
        Ok(())
    }

    pub(super) fn validate_for_pending(
        &self,
        pending: &StoreRecoveryPendingIdentity,
    ) -> Result<(), HostError> {
        self.validate_for_digest(&pending.mutation_digest)?;
        if self.wire != pending.wire
            || self.operation != pending.operation
            || self.request_id != pending.request_id
            || self.mutation_digest != pending.mutation_digest
            || self.request_digest != pending.request_digest
            || self.host_epoch != pending.host_epoch
            || self.host_lineage != pending.host_lineage
        {
            host_recovery_observe(
                &HostJournalObservation::new(
                    "host.recovery termination cross-bind mismatch observed",
                    HostJournalDisposition::EvidenceMismatched,
                )
                .with_operation(self.request_id.as_str())
                .with_mutation(self.mutation_digest.as_str())
                .with_request_digest(self.request_digest.as_str())
                .with_host_epoch(self.host_epoch)
                .with_host_lineage(self.host_lineage.as_str())
                .with_recovery_binding(pending.mutation_digest.as_str()),
            );
            return Err(HostError::RecoveryRequired(
                "Store termination evidence is not cross-bound to the exact recovery intent"
                    .to_owned(),
            ));
        }
        Ok(())
    }
}

#[cfg(windows)]
pub(super) fn read_store_recovery_termination_evidence(
    host_state_root: &Path,
    mutation_digest: &str,
) -> Result<Option<StoreRecoveryTerminationEvidence>, HostError> {
    const MAX_TERMINATION_BYTES: u64 = 16 * 1024;
    if !valid_sha256_text(mutation_digest) {
        return Err(HostError::RecoveryRequired(
            "Store termination path is not bound to a lowercase sha256 mutation".to_owned(),
        ));
    }
    let path = store_recovery_termination_path(host_state_root, mutation_digest);
    let metadata = match std::fs::metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            host_recovery_observe(
                &HostJournalObservation::new(
                    "host.recovery termination absent observed",
                    HostJournalDisposition::EvidenceAbsent,
                )
                .with_mutation(mutation_digest),
            );
            return Ok(None);
        }
        Err(error) => {
            host_recovery_observe(
                &HostJournalObservation::new(
                    "host.recovery termination inspect failed observed",
                    HostJournalDisposition::EvidenceUnreadable,
                )
                .with_mutation(mutation_digest),
            );
            return Err(HostError::RecoveryRequired(format!(
                "Store termination evidence cannot be inspected: {error}"
            )));
        }
    };
    if !metadata.is_file() || metadata.len() > MAX_TERMINATION_BYTES {
        host_recovery_observe(
            &HostJournalObservation::new(
                "host.recovery termination too large observed",
                HostJournalDisposition::EvidenceUnusable,
            )
            .with_mutation(mutation_digest),
        );
        return Err(HostError::RecoveryRequired(
            "Store termination evidence is malformed or too large".to_owned(),
        ));
    }
    let bytes = read_bounded_runtime_restart_file(
        &path,
        MAX_TERMINATION_BYTES,
        "Store termination evidence",
    )?;
    let evidence =
        serde_json::from_slice::<StoreRecoveryTerminationEvidence>(&bytes).map_err(|error| {
            host_recovery_observe(
                &HostJournalObservation::new(
                    "host.recovery termination malformed observed",
                    HostJournalDisposition::EvidenceUnusable,
                )
                .with_mutation(mutation_digest),
            );
            HostError::RecoveryRequired(format!("Store termination evidence is malformed: {error}"))
        })?;
    evidence.validate_for_digest(mutation_digest)?;
    host_recovery_observe(
        &HostJournalObservation::new(
            "host.recovery termination observed",
            HostJournalDisposition::EvidenceValidated,
        )
        .with_mutation(evidence.mutation_digest.as_str())
        .with_request_digest(evidence.request_digest.as_str())
        .with_operation(evidence.request_id.as_str())
        .with_host_epoch(evidence.host_epoch)
        .with_host_lineage(evidence.host_lineage.as_str()),
    );
    Ok(Some(evidence))
}

#[cfg(windows)]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct StoreRecoveryInnerBinding {
    pub(super) wire: String,
    pub(super) operation: HostRuntimeControlOperation,
    pub(super) request_id: String,
    pub(super) external_control_mutation_digest: String,
    pub(super) external_control_request_digest: String,
    pub(super) host_epoch: u64,
    pub(super) host_lineage: String,
    pub(super) terminated_store_evidence_digest: String,
    pub(super) store_rebind_operation_id: String,
    pub(super) store_rebind_request_digest: String,
    pub(super) handoff: StoreRebindHandoff,
}

#[cfg(windows)]
impl StoreRecoveryInnerBinding {
    pub(super) fn validate_for_pending(
        &self,
        pending: &StoreRecoveryPendingIdentity,
        termination: &StoreRecoveryTerminationEvidence,
    ) -> Result<(), HostError> {
        pending.recover_request()?;
        termination.validate_for_pending(pending)?;
        self.handoff
            .validate_canonical_digest()
            .map_err(|error| HostError::RecoveryRequired(error.to_string()))?;
        let termination_digest = sha256_json(termination)?;
        if self.wire != pending.wire
            || self.operation != HostRuntimeControlOperation::RecoverStore
            || self.request_id != pending.request_id
            || self.external_control_mutation_digest != pending.mutation_digest
            || self.external_control_request_digest != pending.request_digest
            || self.host_epoch != pending.host_epoch
            || self.host_lineage != pending.host_lineage
            || self.terminated_store_evidence_digest != termination_digest
            || self.store_rebind_operation_id.trim().is_empty()
            || self.store_rebind_operation_id.chars().any(char::is_control)
            || !valid_sha256_text(&self.store_rebind_request_digest)
            || self.handoff.operation_id.as_str() != self.store_rebind_operation_id
            || self.handoff.request_digest != self.store_rebind_request_digest
        {
            host_recovery_observe(
                &HostJournalObservation::new(
                    "host.recovery inner cross-bind mismatch observed",
                    HostJournalDisposition::EvidenceMismatched,
                )
                .with_operation(self.request_id.as_str())
                .with_mutation(self.external_control_mutation_digest.as_str())
                .with_request_digest(self.external_control_request_digest.as_str())
                .with_host_epoch(self.host_epoch)
                .with_host_lineage(self.host_lineage.as_str())
                .with_recovery_binding(pending.mutation_digest.as_str()),
            );
            return Err(HostError::RecoveryRequired(
                "Store recovery inner binding is not canonical or cross-bound".to_owned(),
            ));
        }
        Ok(())
    }
}

#[cfg(windows)]
pub(super) fn read_store_recovery_inner_binding(
    host_state_root: &Path,
    mutation_digest: &str,
) -> Result<Option<StoreRecoveryInnerBinding>, HostError> {
    const MAX_INNER_BINDING_BYTES: u64 = 16 * 1024;
    if !valid_sha256_text(mutation_digest) {
        return Err(HostError::RecoveryRequired(
            "Store recovery inner-binding path is not a lowercase sha256 mutation".to_owned(),
        ));
    }
    let path = store_recovery_inner_binding_path(host_state_root, mutation_digest);
    let metadata = match std::fs::metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            host_recovery_observe(
                &HostJournalObservation::new(
                    "host.recovery inner absent observed",
                    HostJournalDisposition::EvidenceAbsent,
                )
                .with_mutation(mutation_digest),
            );
            return Ok(None);
        }
        Err(error) => {
            host_recovery_observe(
                &HostJournalObservation::new(
                    "host.recovery inner inspect failed observed",
                    HostJournalDisposition::EvidenceUnreadable,
                )
                .with_mutation(mutation_digest),
            );
            return Err(HostError::RecoveryRequired(format!(
                "Store recovery inner binding cannot be inspected: {error}"
            )));
        }
    };
    if !metadata.is_file() || metadata.len() > MAX_INNER_BINDING_BYTES {
        host_recovery_observe(
            &HostJournalObservation::new(
                "host.recovery inner too large observed",
                HostJournalDisposition::EvidenceUnusable,
            )
            .with_mutation(mutation_digest),
        );
        return Err(HostError::RecoveryRequired(
            "Store recovery inner binding is malformed or too large".to_owned(),
        ));
    }
    let bytes = read_bounded_runtime_restart_file(
        &path,
        MAX_INNER_BINDING_BYTES,
        "Store recovery inner binding",
    )?;
    let binding = serde_json::from_slice::<StoreRecoveryInnerBinding>(&bytes).map_err(|error| {
        host_recovery_observe(
            &HostJournalObservation::new(
                "host.recovery inner malformed observed",
                HostJournalDisposition::EvidenceUnusable,
            )
            .with_mutation(mutation_digest),
        );
        HostError::RecoveryRequired(format!(
            "Store recovery inner binding is malformed: {error}"
        ))
    })?;
    // This reader proves only that the requested mutation's inner binding is
    // present, file-shaped, within bounds and decodable. It performs no
    // cross-binding validation: `StoreRecoveryInnerBinding::validate_for_pending`
    // is the fence owner's decision and is deliberately not called here. So the
    // one fact this read already holds is whether the evidence names the
    // requested mutation at all; anything else stays reported as unmatched
    // rather than as validated evidence. Both operands of that comparison are
    // therefore bound: `mutation` carries the digest the evidence itself names
    // and `recovery` the requested mutation this read is about, so the verdict
    // below is readable from the record itself on either arm. The inner rebind
    // operation identity this binding also carries is reported by the fence
    // owner's own validation records instead of duplicated here.
    host_recovery_observe(
        &HostJournalObservation::new(
            "host.recovery inner observed",
            if binding.external_control_mutation_digest == mutation_digest {
                HostJournalDisposition::EvidenceValidated
            } else {
                HostJournalDisposition::EvidenceMismatched
            },
        )
        .with_operation(binding.request_id.as_str())
        .with_mutation(binding.external_control_mutation_digest.as_str())
        .with_request_digest(binding.external_control_request_digest.as_str())
        .with_host_epoch(binding.host_epoch)
        .with_host_lineage(binding.host_lineage.as_str())
        .with_recovery_binding(mutation_digest),
    );
    Ok(Some(binding))
}
