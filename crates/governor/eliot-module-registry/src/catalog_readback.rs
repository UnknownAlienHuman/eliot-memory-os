//! Current owner-readback validation for an accepted Module Catalog generation.
//!
//! This is the shared owner seam consumed by Governor and by downstream
//! mechanisms that need to bind current provider state to an approved module
//! lifecycle. A value returned by [`ModuleCatalogOwnerReadback::verify_generation_admission`]
//! is a verified projection of one owner readback, not a source of authority
//! by itself; production callers must obtain the readback from the canonical
//! catalog owner at the current fence.

use eliot_contracts::StateFence;
use thiserror::Error;

use crate::{
    DesiredModuleState, GenerationAdmission, GenerationId, ModuleCatalogEntry,
    ModuleCatalogSnapshot, ModuleError, ModuleId,
};

/// The Module Catalog snapshot and outer owner revision returned by one
/// canonical owner read.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModuleCatalogOwnerReadback {
    /// Store-arbitrated outer owner revision.
    pub owner_revision: u64,
    /// Governor-owned semantic catalog snapshot from that same read.
    pub snapshot: ModuleCatalogSnapshot,
}

/// A generation admission proved to remain present in the exact current
/// enabled catalog entry.
///
/// Fields are private so consumers cannot construct a verified lifecycle
/// projection from a runtime activation number or a caller-supplied scalar.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedModuleCatalogGeneration {
    owner_revision: u64,
    catalog_revision: u64,
    catalog_digest: String,
    state_fence: StateFence,
    module_id: ModuleId,
    generation_id: GenerationId,
    artifact_digest: String,
    config_digest: String,
    protocol_digest: String,
    manifest_digest: String,
    admission_receipt: String,
}

impl VerifiedModuleCatalogGeneration {
    /// Exact Store owner revision that supplied this accepted lifecycle row.
    #[must_use]
    pub const fn owner_revision(&self) -> u64 {
        self.owner_revision
    }

    /// Exact Governor semantic catalog revision from the same readback.
    #[must_use]
    pub const fn catalog_revision(&self) -> u64 {
        self.catalog_revision
    }

    /// Catalog digest read back with the accepted generation.
    #[must_use]
    pub fn catalog_digest(&self) -> &str {
        &self.catalog_digest
    }

    /// State Fence that owns the verified catalog snapshot.
    #[must_use]
    pub const fn state_fence(&self) -> &StateFence {
        &self.state_fence
    }

    /// Exact accepted module identity.
    #[must_use]
    pub fn module_id(&self) -> &ModuleId {
        &self.module_id
    }

    /// Immutable accepted generation identity from the catalog admission.
    #[must_use]
    pub fn generation_id(&self) -> &GenerationId {
        &self.generation_id
    }

    /// Admitted artifact digest.
    #[must_use]
    pub fn artifact_digest(&self) -> &str {
        &self.artifact_digest
    }

    /// Admitted configuration digest.
    #[must_use]
    pub fn config_digest(&self) -> &str {
        &self.config_digest
    }

    /// Admitted protocol digest.
    #[must_use]
    pub fn protocol_digest(&self) -> &str {
        &self.protocol_digest
    }

    /// Current module-manifest identity in the owner snapshot.
    #[must_use]
    pub fn manifest_digest(&self) -> &str {
        &self.manifest_digest
    }

    /// Exact accepted catalog receipt reference.
    #[must_use]
    pub fn admission_receipt(&self) -> &str {
        &self.admission_receipt
    }

    /// Provider-registry generation domain: the catalog semantic revision
    /// authenticated by this readback. It is intentionally separate from the
    /// runtime activation generation and the profile-registry generation.
    #[must_use]
    pub const fn provider_registry_generation(&self) -> u64 {
        self.catalog_revision
    }
}

impl ModuleCatalogOwnerReadback {
    /// Checks the exact outer/inner owner revisions and State Fence.
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
        if entry.accepted_generation.as_ref() != Some(expected_admission) {
            return Err(ModuleRegistryAdmissionError::AdmissionNotReadBack);
        }

        let candidate = &expected_admission.candidate;
        let execution = &expected_admission.execution;
        let capability_profile_digest =
            entry.manifest.capability_profile_digest(&entry.module_id)?;
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

    /// Returns a private-field lifecycle projection only after the exact
    /// accepted generation has passed the shared owner-readback validator.
    pub fn verify_generation_admission(
        &self,
        expected_owner_revision: u64,
        expected_catalog_revision: u64,
        expected_state_fence: &StateFence,
        expected_admission: &GenerationAdmission,
    ) -> Result<VerifiedModuleCatalogGeneration, ModuleRegistryAdmissionError> {
        let entry = self.require_generation_admission(
            expected_owner_revision,
            expected_catalog_revision,
            expected_state_fence,
            expected_admission,
        )?;
        Ok(VerifiedModuleCatalogGeneration {
            owner_revision: self.owner_revision,
            catalog_revision: self.snapshot.catalog_revision,
            catalog_digest: self.snapshot.catalog_digest.clone(),
            state_fence: self.snapshot.state_fence.clone(),
            module_id: entry.module_id.clone(),
            generation_id: expected_admission.execution.generation_id.clone(),
            artifact_digest: entry.manifest.artifact_digest.clone(),
            config_digest: entry.manifest.config_digest.clone(),
            protocol_digest: entry.manifest.protocol_digest.clone(),
            manifest_digest: entry.manifest.manifest_digest.clone(),
            admission_receipt: expected_admission.admission_receipt.to_string(),
        })
    }
}

/// Typed refusal from current Module Catalog owner-readback validation.
#[derive(Debug, Error)]
pub enum ModuleRegistryAdmissionError {
    /// Store owner revision differs from the exact expected readback.
    #[error("Module Catalog owner revision mismatch: expected {expected}, observed {observed}")]
    OwnerRevisionMismatch { expected: u64, observed: u64 },
    /// Store owner revision and Governor catalog revision disagree.
    #[error("Module Catalog revision mismatch: expected {expected}, observed {catalog_revision}")]
    CatalogRevisionMismatch {
        expected: u64,
        catalog_revision: u64,
    },
    /// Catalog snapshot belongs to a different State Fence.
    #[error("Module Catalog readback State Fence mismatch")]
    StateFenceMismatch,
    /// Generation admission does not name the current revision and fence.
    #[error("generation admission does not name the current catalog revision and State Fence")]
    AdmissionRevisionMismatch,
    /// Current catalog has no entry for the admitted module.
    #[error("Module Catalog readback omitted the admitted module")]
    ModuleNotFound,
    /// Disabled, quarantined or removed modules cannot execute.
    #[error("Module Catalog module is not enabled")]
    ModuleNotEnabled,
    /// Exact accepted admission is absent from the current readback.
    #[error("Module Catalog did not read back the exact accepted generation")]
    AdmissionNotReadBack,
    /// Accepted execution projection differs from the current manifest.
    #[error("accepted Kernel execution projection does not match the current Module Manifest")]
    ManifestBindingMismatch,
    /// Withheld restart policy has no typed Kernel execution identity.
    #[error("Module Catalog withheld the declared restart policy")]
    RestartPolicyNotAdmitted,
    /// Underlying catalog or generation admission failed validation.
    #[error(transparent)]
    Module(#[from] ModuleError),
}
