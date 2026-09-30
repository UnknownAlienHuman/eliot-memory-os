//! Composition-local retention for authenticated Host module journal rows.
//!
//! These complete rows remain evidence only. The owner grants no execution,
//! generation, or candidate authority; it prevents evidence from one exact
//! candidate contour from being read back under another.

use super::{
    HostKernelCandidateBinding, KernelServiceError, ModuleBuildProvenanceRecord,
    ResourceGeneration, StateFence,
};
use eliot_platform::PlatformHandle;
use std::collections::BTreeMap;

#[derive(Clone, Debug, Eq, PartialEq)]
struct ProvenanceScope {
    installation_id: PlatformHandle,
    candidate: HostKernelCandidateBinding,
    generation: ResourceGeneration,
    state_fence: StateFence,
}

#[derive(Default)]
pub(super) struct ModuleBuildProvenanceOwner {
    scope: Option<ProvenanceScope>,
    records: Option<BTreeMap<String, ModuleBuildProvenanceRecord>>,
}

impl ModuleBuildProvenanceOwner {
    /// Moves the owner to one authenticated scope, dropping all rows on any
    /// installation, candidate, generation, or complete-fence change.
    pub(super) fn observe_scope(
        &mut self,
        candidate: &HostKernelCandidateBinding,
        generation: ResourceGeneration,
        state_fence: &StateFence,
    ) -> Result<(), KernelServiceError> {
        validate_scope(candidate, generation, state_fence)?;
        let next = ProvenanceScope {
            installation_id: candidate.installation_id.clone(),
            candidate: candidate.clone(),
            generation,
            state_fence: state_fence.clone(),
        };
        if self.scope.as_ref() != Some(&next) {
            self.scope = Some(next);
            self.records = None;
        }
        Ok(())
    }

    /// Admits a complete, unique set of canonical Host journal rows for the
    /// currently authenticated scope. A conflicting same-scope re-admission
    /// is rejected instead of silently replacing retained evidence.
    pub(super) fn admit_rows(
        &mut self,
        candidate: &HostKernelCandidateBinding,
        generation: ResourceGeneration,
        state_fence: &StateFence,
        rows: &[ModuleBuildProvenanceRecord],
    ) -> Result<(), KernelServiceError> {
        self.observe_scope(candidate, generation, state_fence)?;
        if rows.is_empty() {
            return Err(invalid_provenance(
                "a present provenance handoff must contain at least one row",
            ));
        }
        let expected_fence_digest = serde_json::to_vec(state_fence)
            .map(|bytes| eliot_contracts::sha256_hex(&bytes))
            .map_err(|_| invalid_provenance("cannot bind rows to the active state fence"))?;
        let mut admitted = BTreeMap::new();
        for row in rows {
            row.validate().map_err(|_| {
                invalid_provenance("row violates the canonical Host journal contract")
            })?;
            validate_row_scope(row, candidate, &expected_fence_digest)?;
            if admitted
                .insert(row.module_id.as_str().to_owned(), row.clone())
                .is_some()
            {
                return Err(invalid_provenance(
                    "a provenance handoff cannot repeat a module identity",
                ));
            }
        }
        if self
            .records
            .as_ref()
            .is_some_and(|current| current != &admitted)
        {
            return Err(invalid_provenance(
                "same-scope provenance re-admission conflicts with retained journal rows",
            ));
        }
        self.records = Some(admitted);
        Ok(())
    }

    /// Drops retained rows if the active Kernel generation or full fence has
    /// moved. It deliberately does not create a new candidate scope.
    pub(super) fn revoke_if_fence_moved(
        &mut self,
        generation: ResourceGeneration,
        state_fence: &StateFence,
    ) {
        let still_current = self.scope.as_ref().is_some_and(|scope| {
            scope.generation == generation && scope.state_fence == *state_fence
        });
        if !still_current {
            self.scope = None;
            self.records = None;
        }
    }

    /// Returns one complete row only when every scope key still matches.
    pub(super) fn readback(
        &self,
        candidate: &HostKernelCandidateBinding,
        generation: ResourceGeneration,
        state_fence: &StateFence,
        module_id: &str,
    ) -> Result<Option<ModuleBuildProvenanceRecord>, KernelServiceError> {
        validate_scope(candidate, generation, state_fence)?;
        let expected = ProvenanceScope {
            installation_id: candidate.installation_id.clone(),
            candidate: candidate.clone(),
            generation,
            state_fence: state_fence.clone(),
        };
        if self.scope.as_ref() != Some(&expected) {
            return Ok(None);
        }
        Ok(self
            .records
            .as_ref()
            .and_then(|records| records.get(module_id))
            .cloned())
    }
}

fn validate_scope(
    candidate: &HostKernelCandidateBinding,
    generation: ResourceGeneration,
    state_fence: &StateFence,
) -> Result<(), KernelServiceError> {
    if state_fence.resource_generation != generation
        || !candidate
            .kernel_epoch
            .is_same_authority(&state_fence.authority_epoch)
    {
        return Err(invalid_provenance(
            "candidate, resource generation, and Kernel state fence must match exactly",
        ));
    }
    Ok(())
}

fn validate_row_scope(
    row: &ModuleBuildProvenanceRecord,
    candidate: &HostKernelCandidateBinding,
    expected_fence_digest: &str,
) -> Result<(), KernelServiceError> {
    if row.fence.host.installation != candidate.installation_id
        || row.fence.host.epoch.current.lineage_id.as_str()
            != candidate
                .supervision_incarnation
                .host_epoch
                .lineage_id
                .as_str()
        || row.fence.host.epoch.current.sequence.get() != candidate.host_epoch.value()
        || row.fence.activation_id != candidate.activation_id
        || row.fence.activation_generation.current.lineage_id.as_str()
            != candidate
                .supervision_incarnation
                .activation_generation
                .lineage_id
                .as_str()
        || row.fence.activation_generation.current.sequence.get()
            != candidate
                .supervision_incarnation
                .activation_generation
                .sequence
        || row.state_fence_digest.as_str() != expected_fence_digest
    {
        return Err(invalid_provenance(
            "row installation, activation, lineage, or state fence differs from the active scope",
        ));
    }
    Ok(())
}

fn invalid_provenance(reason: &'static str) -> KernelServiceError {
    KernelServiceError::InvalidField {
        field: "startup_evidence.module_build_provenance",
        reason,
    }
}
