//! Governor-side validation for an accepted Module Catalog generation.
//!
//! The caller supplies the exact Module Registry owner readback that followed
//! the catalog write. This module validates both owner revision domains and
//! the accepted generation's binding to the admitted manifest. It does not
//! issue candidate provenance: that must come from the Host and Kernel owners
//! before a `GenerationAdmission` is constructed.

use eliot_contracts::StateFence;
use eliot_module_registry::{
    DesiredModuleState, GenerationAdmission, ModuleCatalogEntry, ModuleCatalogSnapshot, ModuleError,
};
use thiserror::Error;

/// The Module Catalog snapshot and the outer owner revision read together
/// from the canonical owner record.
///
/// `owner_revision` is the Store-arbitrated owner revision. The snapshot's
/// `catalog_revision` is Governor semantic state. They are separate revision
/// domains; each is checked against its own expected value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModuleCatalogOwnerReadback {
    /// Outer owner revision returned by the canonical Store read.
    pub owner_revision: u64,
    /// Governor-owned semantic catalog snapshot from that same read.
    pub snapshot: ModuleCatalogSnapshot,
}

impl ModuleCatalogOwnerReadback {
    /// Checks the exact outer/inner owner revisions and current State Fence.
    pub fn validate_current(
        &self,
        expected_owner_revision: u64,
        expected_catalog_revision: u64,
        expected_state_fence: &StateFence,
    ) -> Result<(), ModuleRegistryAdmissionError> {
        if expected_owner_revision == 0 || self.owner_revision != expected_owner_revision {
            return Err(ModuleRegistryAdmissionError::OwnerRevisionMismatch {
                expected: expected_owner_revision,
                observed: self.owner_revision,
            });
        }
        self.snapshot.validate()?;
        if expected_catalog_revision == 0
            || self.snapshot.catalog_revision != expected_catalog_revision
        {
            return Err(ModuleRegistryAdmissionError::CatalogRevisionMismatch {
                expected: expected_catalog_revision,
                catalog_revision: self.snapshot.catalog_revision,
            });
        }
        if self.snapshot.state_fence != *expected_state_fence {
            return Err(ModuleRegistryAdmissionError::StateFenceMismatch);
        }
        Ok(())
    }

    /// Requires that the exact generation admission appears in the current
    /// owner readback and still matches the enabled manifest at that revision.
    pub fn require_generation_admission(
        &self,
        expected_owner_revision: u64,
        expected_catalog_revision: u64,
        expected_state_fence: &StateFence,
        expected_admission: &GenerationAdmission,
    ) -> Result<&ModuleCatalogEntry, ModuleRegistryAdmissionError> {
        self.validate_current(
            expected_owner_revision,
            expected_catalog_revision,
            expected_state_fence,
        )?;
        expected_admission.validate()?;
        if expected_admission.state_fence != *expected_state_fence {
            return Err(ModuleRegistryAdmissionError::AdmissionRevisionMismatch);
        }

        let entry = self
            .snapshot
            .entries
            .iter()
            .find(|entry| entry.module_id == expected_admission.candidate.module_id)
            .ok_or(ModuleRegistryAdmissionError::ModuleNotFound)?;
        if entry.desired_state != DesiredModuleState::Enabled {
            return Err(ModuleRegistryAdmissionError::ModuleNotEnabled);
        }
        // An unrelated catalog mutation can advance the owner snapshot while
        // this module's exact accepted admission remains current. Snapshot
        // validation already proves that this entry/admission revision is not
        // ahead of the catalog revision; exact receipt equality below prevents
        // an older or replaced candidate from being mistaken for this one.
        if entry.accepted_generation.as_ref() != Some(expected_admission) {
            return Err(ModuleRegistryAdmissionError::AdmissionNotReadBack);
        }

        let candidate = &expected_admission.candidate;
        let execution = &expected_admission.execution;
        let capability_profile_digest =
            entry.manifest.capability_profile_digest(&entry.module_id)?;
        // The Kernel execution projection currently carries only a digest of
        // an admitted versioned policy; there is no wire identity for a
        // withheld/no-automatic-restart disposition. Refuse execution until
        // that representation is added instead of accepting an arbitrary
        // caller-supplied digest.
        let restart_policy_digest = entry
            .restart_policy_disposition
            .policy_digest()
            .ok_or(ModuleRegistryAdmissionError::RestartPolicyNotAdmitted)?;
        if candidate.module_id != entry.module_id
            || candidate.artifact_digest != entry.manifest.artifact_digest
            || candidate.config_digest != entry.manifest.config_digest
            || candidate.protocol_digest != entry.manifest.protocol_digest
            || candidate.capability_profile_digest != capability_profile_digest
            || execution.artifact_digest != entry.manifest.artifact_digest
            || execution.config_digest != entry.manifest.config_digest
            || execution.protocol_digest != entry.manifest.protocol_digest
            || execution.command_ref != entry.manifest.command_ref
            || execution.health_contract_ref != entry.manifest.health_contract_ref
            || execution.effect_ceiling != entry.manifest.effect_ceiling
            || execution.restart_authorization != entry.manifest.restart_authorization
            || execution.restart_policy_digest != restart_policy_digest
        {
            return Err(ModuleRegistryAdmissionError::ManifestBindingMismatch);
        }

        Ok(entry)
    }
}

/// A typed refusal while validating the current Module Catalog owner readback.
#[derive(Debug, Error)]
pub enum ModuleRegistryAdmissionError {
    /// The Store owner revision differs from the exact expected readback.
    #[error("Module Catalog owner revision mismatch: expected {expected}, observed {observed}")]
    OwnerRevisionMismatch { expected: u64, observed: u64 },
    /// Store owner revision and Governor catalog revision disagree.
    #[error("Module Catalog revision mismatch: expected {expected}, observed {catalog_revision}")]
    CatalogRevisionMismatch {
        expected: u64,
        catalog_revision: u64,
    },
    /// The catalog snapshot belongs to a different State Fence.
    #[error("Module Catalog readback State Fence mismatch")]
    StateFenceMismatch,
    /// The accepted generation does not name the exact current revision/fence.
    #[error("generation admission does not name the current catalog revision and State Fence")]
    AdmissionRevisionMismatch,
    /// The current catalog has no entry for this module.
    #[error("Module Catalog readback omitted the admitted module")]
    ModuleNotFound,
    /// A disabled, quarantined or removed module cannot be admitted to run.
    #[error("Module Catalog module is not enabled")]
    ModuleNotEnabled,
    /// The exact accepted admission is absent from the current readback.
    #[error("Module Catalog did not read back the exact accepted generation")]
    AdmissionNotReadBack,
    /// The accepted execution projection differs from the current manifest.
    #[error("accepted Kernel execution projection does not match the current Module Manifest")]
    ManifestBindingMismatch,
    /// A withheld policy has no typed Kernel execution identity to bind.
    #[error("Module Catalog withheld the declared restart policy")]
    RestartPolicyNotAdmitted,
    /// The underlying catalog or generation admission failed its own validation.
    #[error(transparent)]
    Module(#[from] ModuleError),
}
