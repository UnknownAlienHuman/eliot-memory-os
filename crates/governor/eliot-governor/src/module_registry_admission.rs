//! Governor-side validation and accept path for an accepted Module Catalog
//! generation.
//!
//! The caller supplies the exact Module Registry owner readback that followed
//! the catalog write. This module validates both owner revision domains and
//! the accepted generation's binding to the admitted manifest. It does not
//! issue candidate provenance: that must come from the Host and Kernel owners
//! before a `GenerationAdmission` is constructed.
//!
//! It is also the composition point that carries an accepted generation across
//! into the Generation Registry: [`accept_candidate_generation_into_generation_registry`]
//! builds the admission from owner facts, and
//! [`admit_accepted_generation_into_generation_registry`] runs the one accept
//! chain. This crate depends on the Module Catalog owner contract and on the
//! Generation Registry owner crate, and it wires one into the other; it never
//! constructs, holds or opens a recovery store, and it decides nothing the
//! catalog owner has not already decided.

use eliot_contracts::{OperationId, ResourceGeneration, StateFence};
use eliot_module_registry::{
    CatalogAdmissionReceipt, CatalogAdmissionReceiptReadback, CatalogMutation, CatalogReceiptId,
    DesiredModuleState, GenerationAdmission, GenerationCandidateReceipt, GenerationId,
    KernelExecutionManifest, ModuleCatalog, ModuleCatalogChange, ModuleCatalogEntry,
    ModuleCatalogSnapshot, ModuleError, ModuleId, admitted_authority_epoch,
    admitted_effect_ceiling, admitted_execution_projection, admitted_restart_authorization,
    sealed_facts_of, sealed_projection_refusal,
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
    /// The canonical Module Catalog admission receipt that same owner read
    /// returned, or absent when that read returned no receipt row.
    ///
    /// The snapshot alone cannot carry it: an admission receipt records the
    /// operation identity and idempotency key of the accepting write, and the
    /// Module Catalog snapshot states no operation identity at all. This is the
    /// owner read's own row rather than a value this crate derives, so
    /// `read_admission_receipt` returns the recorded row and never an invented
    /// one; absence is absence, not a receipt with a gap in it.
    pub admission_receipt: Option<CatalogAdmissionReceipt>,
}

impl CatalogAdmissionReceiptReadback for ModuleCatalogOwnerReadback {
    /// Reads the canonical admission receipt the owner recorded for
    /// `operation_id`.
    ///
    /// The row is returned verbatim, field for field, because the accept chain
    /// compares every one of its fields against the offered admission and a
    /// row this function rebuilt would be compared against itself. An operation
    /// this owner recorded no receipt for has none, so absence is `Ok(None)`;
    /// the caller refuses that as an admission this owner never issued.
    fn read_admission_receipt(
        &self,
        operation_id: &OperationId,
    ) -> Result<Option<CatalogAdmissionReceipt>, ModuleError> {
        let Some(receipt) = self.admission_receipt.as_ref() else {
            return Ok(None);
        };
        // A receipt recorded under a different operation identity is not this
        // operation's receipt, so it is absence here rather than a row whose
        // identity happens to differ.
        if receipt.operation_id != *operation_id {
            return Ok(None);
        }
        Ok(Some(receipt.clone()))
    }
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

/// The admitted generation projection Kernel persists into the Generation
/// Registry for one accepted Governor generation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdmittedGenerationProjection {
    /// The admitted identity, revisions, sealed projection and admitted bounds.
    pub admission: eliot_ors::AdmittedModuleGeneration,
    /// The technical execution projection the manifest is copied with.
    pub projection: eliot_ors::KernelExecutionProjection,
    /// The recorded Generation Registry manifest digest the ORS store returned.
    pub manifest_sha256: String,
}

/// The Governor accept path: one chain, in this order, from a canonical owner
/// receipt to an exact Generation Registry copy.
///
/// The order is fixed and each step is the only construction path for its own
/// record:
///
/// 1. the canonical Module Catalog receipt is read back through
///    [`CatalogAdmissionReceiptReadback`];
/// 2. [`ModuleCatalog::apply`] verifies it and produces the one canonical seal
///    through `eliot_module_registry::seal_generation_admission`;
/// 3. the receipt is persisted with
///    `eliot_ors::RedbRecoveryStore::persist_governor_admission_receipt`;
/// 4. the manifest is built by `eliot_ors::KernelExecutionManifest::admit`
///    inside
///    `eliot_ors::RedbRecoveryStore::persist_admitted_kernel_execution_manifest`;
/// 5. that store call is what writes the row.
///
/// The seal binds the admitted bounds as well as the identities, and this chain
/// restates them rather than re-deciding them. Step 2 states the module's
/// admitted restart authorization class and effect ceiling from the accepted
/// catalog entry's own manifest and the admitted route scope set from that same
/// entry's owner execution projection, and all three are inside the seal's
/// canonical owner digest. The record this function builds carries exactly those
/// three values, so a record cannot name a class, a ceiling or a scope set its
/// seal does not carry: it is not handed a scope list of its own, the set is not
/// mapped a second time here, and it is neither sorted, deduped, widened nor
/// narrowed. A record stating any other bound is refused by the sealed
/// projection's own validation before the store call in step 4 opens its
/// transaction.
///
/// An accepted generation therefore produces its exact Generation Registry copy
/// on this path and on no other. Every one of the five receipt discriminators
/// is refused at step 2, inside [`ModuleCatalog::apply`], before step 3 opens
/// its transaction and therefore before any ORS mutation is reachable: an
/// invented non-blank receipt text is refused as
/// [`ModuleError::AdmissionReceiptNotIssued`] because step 1 returns no
/// canonical row for an operation this owner never admitted under; a receipt
/// recorded for another module, generation or Generation Registry counter is
/// refused as [`ModuleError::AdmissionReceiptGenerationMismatch`]; a receipt
/// that carries this generation's text identity under a different accepted
/// manifest digest is refused as
/// [`ModuleError::AdmissionReceiptManifestDigestMismatch`]; a receipt naming a
/// different Module Catalog receipt id is refused as
/// [`ModuleError::AdmissionReceiptMismatch`]; and a receipt accepted at another
/// catalog revision or under another State Fence is refused as
/// [`ModuleError::AdmissionReceiptRevisionMismatch`]. Each is a distinct
/// refusal, none of them is reachable past step 2, and none is reported as
/// another.
///
/// The Generation Registry owner store is an explicit parameter. This crate
/// never constructs a `RedbRecoveryStore`, never holds one open and never
/// opens a recovery transaction itself: it hands the owner store to the two
/// persistence calls that own those transactions, so this composition cannot
/// become a second writer of Generation Registry rows, and the accept path
/// cannot exist without a composition root that already has the owner store.
///
/// The recorded [`AdmittedGenerationProjection::manifest_sha256`] is returned
/// rather than dropped, so a caller cannot read an unrecorded manifest as a
/// persisted one.
///
/// Compatibility: the Module Catalog `GenerationAdmission` record carries the
/// Generation Registry's own generation counter as a required field. The only
/// code path that ever set a catalog entry's accepted generation is the
/// `AcceptGeneration` arm of the catalog's own mutation application, and that
/// arm is reachable only from a `ModuleCatalogChange` whose mutation is
/// `CatalogMutation::AcceptGeneration`; before
/// [`accept_candidate_generation_into_generation_registry`] there was no
/// producer of that mutation anywhere in the tree, so no catalog entry ever held
/// an accepted generation and no snapshot this owner persisted before this
/// change can carry one. The required field therefore has no older row to fail
/// against, and no migration exists or is needed.
///
/// Both halves of what that producer is worth are stated here rather than one of
/// them. It exists, and it is the only producer of `AcceptGeneration` in the
/// tree, so `GenerationAdmission` and `CatalogMutation::AcceptGeneration` do have
/// a producer now and this chain is not unreachable code by absence. It also has
/// no in-tree caller: the only references to it in this tree are its own
/// definition and the `eliot_governor` re-export, and the two owner-store calls
/// below are reached only from it. A function nothing calls is not yet a
/// production producer, so no composition root, and therefore no running system,
/// issues this admission today; the Generation Registry row this chain would
/// write does not exist in any live store yet, and nothing here claims
/// otherwise.
pub fn admit_accepted_generation_into_generation_registry(
    catalog: &mut ModuleCatalog,
    change: &ModuleCatalogChange,
    readback: &dyn CatalogAdmissionReceiptReadback,
    ors: &eliot_ors::RedbRecoveryStore,
    issued_at_ms: i64,
) -> Result<AdmittedGenerationProjection, ModuleError> {
    // 1 + 2: the owner receipt readback and the one canonical seal.
    let applied = catalog.apply(change, readback)?;
    let seal = applied
        .admission_seal
        .clone()
        .ok_or(ModuleError::AdmissionReceiptUnverified)?;
    let Some(entry) = catalog.desired(&change.module_id) else {
        return Err(ModuleError::NotFound);
    };
    let Some(admission) = entry.accepted_generation.as_ref() else {
        return Err(ModuleError::AdmissionReceiptUnverified);
    };
    let projection = admitted_execution_projection(entry)?;
    // 3: the canonical receipt row, issued from the same sealed facts the seal
    // carries, so receipt and seal share one version and one digest function
    // instead of a second mapping that could drift from this one.
    let receipt = eliot_ors::GovernorAdmissionReceipt::issue(&sealed_facts_of(&seal), issued_at_ms)
        .map_err(sealed_projection_refusal)?;
    ors.persist_governor_admission_receipt(&receipt)
        .map_err(sealed_projection_refusal)?;
    let ors_admission = eliot_ors::AdmittedModuleGeneration {
        module_id: seal.module_id().to_owned(),
        generation: seal.generation(),
        authority_epoch: admitted_authority_epoch(admission)?,
        catalog_revision: seal.catalog_revision(),
        policy_revision: seal.policy_revision(),
        governor_admission_seal: seal,
        restart_authorization_class: admitted_restart_authorization(
            entry.manifest.restart_authorization,
        ),
        admitted_effect_ceiling: admitted_effect_ceiling(entry.manifest.effect_ceiling),
        admitted_allowed_scopes: projection.allowed_scopes.clone(),
    };
    // 4 + 5: the manifest is built by the owner store's own constructor and
    // written by the owner store, which re-verifies the sealed projection before
    // it opens its transaction. The digest it returns is the recorded manifest
    // identity.
    let manifest_sha256 = ors
        .persist_admitted_kernel_execution_manifest(&ors_admission, &projection)
        .map_err(sealed_projection_refusal)?;
    Ok(AdmittedGenerationProjection {
        admission: ors_admission,
        projection,
        manifest_sha256,
    })
}

/// The owner-issued facts this composition point cannot produce for itself.
///
/// Every value is copied from the owner that states it. Nothing here is
/// defaulted, derived from another field or invented, and an admission that
/// cannot state one of them cannot be built through
/// [`accept_candidate_generation_into_generation_registry`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CandidateGenerationAdmission {
    /// The catalog module this admission accepts a generation for.
    pub module_id: ModuleId,
    /// The owner text generation identity the operational owner staged.
    ///
    /// It is the Module Catalog's own identity spelling; it is never parsed
    /// into the Generation Registry's numeric counter.
    pub generation_id: GenerationId,
    /// The Generation Registry generation counter its owner issued for this
    /// candidate.
    ///
    /// This composition point records that counter, it never mints it: the
    /// counter belongs to the registry that issued it.
    pub registry_generation: ResourceGeneration,
    /// The Module Catalog admission receipt id the canonical owner issued.
    pub admission_receipt: CatalogReceiptId,
    /// Digest of the independently owner-issued build/source provenance row.
    pub build_provenance_digest: String,
    /// Digest of the build/source owner's own fence.
    pub source_fence_digest: String,
}

/// Accepts one candidate generation into the Module Catalog and copies it into
/// the Generation Registry, in one chain.
///
/// This is the producer that makes the accept path reachable: it builds the
/// [`GenerationAdmission`] the Module Catalog owner requires, wraps it in
/// [`CatalogMutation::AcceptGeneration`] inside the
/// [`ModuleCatalogChange`] that admission intent produces, and calls
/// [`admit_accepted_generation_into_generation_registry`]. It is the only
/// producer of that mutation in the tree, and it has no in-tree caller yet, so
/// the chain it reaches is written but not yet entered by a running system.
///
/// Every admission fact comes from a value this function is given or already
/// holds. The artifact, config and protocol digests, the command, the health
/// contract reference, the effect ceiling and the restart authorization class
/// are the catalog entry's own manifest fields, so the candidate receipt and
/// the accepted execution projection are two statements of one manifest rather
/// than two independent claims. The capability profile digest is the catalog
/// manifest's own projection. The admitted catalog revision is the revision
/// this transition produces, which is the catalog's current revision plus the
/// one it is about to write, and the admitting State Fence is the catalog's own
/// current fence. The restart policy digest is the catalog entry's own
/// disposition; an entry whose policy was withheld states no digest and is
/// refused as [`ModuleRegistryAdmissionError::RestartPolicyNotAdmitted`]
/// rather than admitted under a default.
///
/// What this function cannot state is taken as [`CandidateGenerationAdmission`]
/// instead of being guessed: the module and generation identities, the
/// Generation Registry's own generation counter, the Module Catalog admission
/// receipt id, and the build/source owner's provenance digest and fence digest.
/// No `Default` is involved and no digest is fabricated: a missing one of these
/// is a missing value at the call site, not a refusal this function invents.
///
/// The owner stores are reached only through the accept chain, which takes the
/// Generation Registry owner store as a parameter and never opens one here.
pub fn accept_candidate_generation_into_generation_registry(
    catalog: &mut ModuleCatalog,
    readback: &dyn CatalogAdmissionReceiptReadback,
    ors: &eliot_ors::RedbRecoveryStore,
    operation_id: OperationId,
    idempotency_key: &str,
    candidate: &CandidateGenerationAdmission,
    issued_at_ms: i64,
) -> Result<AdmittedGenerationProjection, ModuleRegistryAdmissionError> {
    let entry = catalog
        .desired(&candidate.module_id)
        .ok_or(ModuleRegistryAdmissionError::ModuleNotFound)?
        .clone();
    let manifest = &entry.manifest;
    if entry.desired_state != DesiredModuleState::Enabled {
        return Err(ModuleRegistryAdmissionError::ModuleNotEnabled);
    }
    let capability_profile_digest = manifest.capability_profile_digest(&candidate.module_id)?;
    let restart_policy_digest = entry
        .restart_policy_disposition
        .policy_digest()
        .ok_or(ModuleRegistryAdmissionError::RestartPolicyNotAdmitted)?
        .to_owned();
    // The admission is accepted at the revision this transition writes, so both
    // the accepted execution projection and the admission state that revision.
    let accepted_catalog_revision = catalog.revision() + 1;
    let execution = KernelExecutionManifest::new(
        candidate.module_id.clone(),
        candidate.generation_id.clone(),
        manifest.artifact_digest.clone(),
        manifest.config_digest.clone(),
        manifest.protocol_digest.clone(),
        manifest.command_ref.clone(),
        manifest.health_contract_ref.clone(),
        manifest.effect_ceiling,
        manifest.restart_authorization,
        restart_policy_digest,
        accepted_catalog_revision,
        candidate.admission_receipt.clone(),
    )?;
    let candidate_receipt = GenerationCandidateReceipt::new(
        candidate.generation_id.clone(),
        candidate.module_id.clone(),
        manifest.artifact_digest.clone(),
        manifest.config_digest.clone(),
        manifest.protocol_digest.clone(),
        candidate.build_provenance_digest.clone(),
        capability_profile_digest,
        candidate.source_fence_digest.clone(),
    )?;
    let state_fence = catalog.state_fence().clone();
    let admission = GenerationAdmission {
        candidate: candidate_receipt,
        execution,
        catalog_revision: accepted_catalog_revision,
        state_fence: state_fence.clone(),
        registry_generation: candidate.registry_generation,
        admission_receipt: candidate.admission_receipt.clone(),
    };
    let change = ModuleCatalogChange {
        operation_id,
        idempotency_key: idempotency_key.to_owned(),
        module_id: candidate.module_id.clone(),
        expected_catalog_revision: catalog.revision(),
        state_fence,
        mutation: CatalogMutation::AcceptGeneration { admission },
        // No approval reference is recorded here: the canonical owner receipt
        // read back through `readback` is the approval evidence for this
        // acceptance, and an invented reference would only repeat it.
        approval_refs: Vec::new(),
    };
    admit_accepted_generation_into_generation_registry(
        catalog,
        &change,
        readback,
        ors,
        issued_at_ms,
    )
    .map_err(ModuleRegistryAdmissionError::from)
}
