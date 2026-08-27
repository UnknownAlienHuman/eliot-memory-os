//! Durable installation registry store: explicit-path redb owner for approved generations and Host operational projection.
//!
//! Architecture: A2.3 (explicit installation state), A12.3 (Host supervision boundary), A13.8/A13.12 (durable activation projection), ARCH-AUTH-01 (authority-bound activation), ARCH-SEC-02 (no path-inferred authority), ARCH-RES-03 (durable Host recovery projection).
//! Implementation: I3.15 (redb registry store owner), I2.2 (explicit protected `ProgramData` path), I2.23 (CAS/revision transaction), I15.3/I15.8 (typed approval and fence validation).
//!
//! This is the sole redb owner for the installation registry. It owns durable bytes and atomic CAS only; it does not mint canonical memory, Kernel authority, or Governor semantics, does not synthesize defaults, does not infer migration, and does not retry unowned operations. All production mutations are narrow transaction-bound operations with expected revision and exact typed approval. Validated projections are operational only.

use std::path::{Path, PathBuf};

use eliot_platform::PlatformHandle;
use eliot_platform_windows::{
    HostOwnerEpochCapability, ProtectedPathLease, ProtectedRootLease, ProtectedRuntimePathLease,
    require_protected_program_data_path,
};
use redb::{Database, TableDefinition};

#[cfg(test)]
use crate::InstallationTransactionStore;
use crate::approved_generation_registry::PendingActivationTerminalDisposition;
use crate::{
    ActivationCommitFence, ActivationCommitReceipt, ActivePhaseBRebind, ActivePhaseBRebindIntent,
    ActivePhaseBRebindReceipt, ActivePhaseBRebindRecovery, AgentBridgeStagePrepared,
    HostPhaseBMaterializationIntent, HostPhaseBMaterializationReceipt,
    HostPhaseBPreparedMaterialization, HostPhaseBPreparedReceipt, InstallationActivationApproval,
    InstallationError, PendingActivation, WindowsPathIdentity, activation_terminal_digest,
    candidate_manifest_digest, valid_installation_key, validate_approval_against_manifest,
};

pub(super) const REGISTRY_TABLE: TableDefinition<&str, &[u8]> =
    TableDefinition::new("eliot_approved_generations_v2");
pub(super) const LEGACY_REGISTRY_TABLE: TableDefinition<&str, &[u8]> =
    TableDefinition::new("eliot_approved_generations_v1");
pub(super) const REGISTRY_RELATIVE_PATH: &str = "Eliot/host/installation-registry.redb";
pub(super) const INSTALLATION_REGISTRY_FILE_NAME: &str = "installation-registry.redb";

/// Durable redb owner for approved generations and LKG activation state.
///
/// There is no public raw `save` operation.  Every production mutation must
/// use a narrow transaction-bound operation with an expected revision and an
/// exact typed approval.
///
/// ```compile_fail
/// use eliot_installation::{ApprovedGenerationRegistry, RedbInstallationRegistry};
/// fn raw_save(store: &RedbInstallationRegistry, registry: &ApprovedGenerationRegistry) {
///     store.save(registry);
/// }
/// ```
pub struct RedbInstallationRegistry {
    pub(super) database: Database,
    _path_lease: RegistryPathLease,
}

enum RegistryPathLease {
    Legacy {
        _lease: ProtectedPathLease,
    },
    InstallationHost {
        _root: ProtectedRootLease,
        _file: ProtectedRuntimePathLease,
    },
    #[cfg(any(test, feature = "test-support"))]
    Test,
}

impl RedbInstallationRegistry {
    #[cfg(test)]
    pub(super) fn from_database_for_test(database: Database) -> Self {
        Self {
            database,
            _path_lease: RegistryPathLease::Test,
        }
    }

    /// Opens a physical registry below a caller-owned temporary test root.
    ///
    /// This is available only through the non-default `test-support` feature.
    /// It deliberately does not relax the production [`Self::open`] or
    /// [`Self::open_at`] ProgramData/root-lease policies; the Host test uses
    /// this path only to exercise the real redb CAS and rebind callsite without
    /// requiring an elevated service token.
    #[cfg(feature = "test-support")]
    pub fn open_test_support(path: impl AsRef<Path>) -> Result<Self, InstallationError> {
        let path = path.as_ref();
        if !path.is_absolute() {
            return Err(InstallationError::Platform(
                "test registry path must be absolute".to_owned(),
            ));
        }
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|error| InstallationError::Platform(error.to_string()))?;
        }
        let database = Database::create(path)
            .map_err(|error| InstallationError::Platform(error.to_string()))?;
        Ok(Self {
            database,
            _path_lease: RegistryPathLease::Test,
        })
    }

    /// Opens or creates the registry database.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, InstallationError> {
        let path = path.as_ref();
        require_protected_program_data_path(path, REGISTRY_RELATIVE_PATH)
            .map_err(|error| InstallationError::Platform(error.to_string()))?;
        let path_lease = ProtectedPathLease::open_or_create(REGISTRY_RELATIVE_PATH)
            .map_err(|error| InstallationError::Platform(error.to_string()))?;
        if path_lease.path() != path {
            return Err(InstallationError::Platform(
                "registry path is not the exact protected ProgramData path".to_owned(),
            ));
        }
        let database = Database::create(path_lease.path())
            .map_err(|error| InstallationError::Platform(error.to_string()))?;
        path_lease
            .verify_path_identity()
            .map_err(|error| InstallationError::Platform(error.to_string()))?;
        Ok(Self {
            database,
            _path_lease: RegistryPathLease::Legacy { _lease: path_lease },
        })
    }

    /// Opens or creates the registry below one retained per-installation
    /// Host root.
    ///
    /// The caller transfers ownership of the retained root lease to this
    /// database owner. The registry file is a fixed direct child of that
    /// canonical root; no arbitrary path, legacy system-data location, or
    /// ACL-rewriting lease is accepted. The runtime-file lease proves the
    /// installer-provisioned BA+LS+SY ACL and retains the no-follow contour
    /// for redb's path-based reopen.
    #[allow(
        clippy::needless_pass_by_value,
        reason = "the registry owner must retain the caller-provided Host root lease"
    )]
    pub fn open_at(host_root: ProtectedRootLease) -> Result<Self, InstallationError> {
        let path = installation_registry_path(&host_root)?;
        let file = ProtectedRuntimePathLease::open_or_create_absolute(&path)
            .map_err(|error| InstallationError::Platform(error.to_string()))?;
        if file.path() != path {
            return Err(InstallationError::Platform(
                "installation registry path is not the retained canonical Host child".to_owned(),
            ));
        }
        let database = Database::create(file.path())
            .map_err(|error| InstallationError::Platform(error.to_string()))?;
        file.verify_path_identity()
            .map_err(|error| InstallationError::Platform(error.to_string()))?;
        Ok(Self {
            database,
            _path_lease: RegistryPathLease::InstallationHost {
                _root: host_root,
                _file: file,
            },
        })
    }

    /// Opens an existing registry below one retained per-installation Host
    /// root without creating a file or database.
    ///
    /// The returned owner retains both the caller-provided Host root and the
    /// installer-provisioned runtime-file lease while callers validate and
    /// load its durable projection. None means only that the fixed registry
    /// child is absent.
    #[allow(
        clippy::needless_pass_by_value,
        reason = "the registry owner must retain the caller-provided Host root lease"
    )]
    pub fn open_existing_at(
        host_root: ProtectedRootLease,
    ) -> Result<Option<Self>, InstallationError> {
        let path = installation_registry_path(&host_root)?;
        match std::fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.is_file() => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Ok(_) | Err(_) => {
                return Err(InstallationError::Platform(
                    "installation registry path is not an existing regular file".to_owned(),
                ));
            }
        }
        let file = ProtectedRuntimePathLease::open_existing_absolute(&path)
            .map_err(|error| InstallationError::Platform(error.to_string()))?;
        if file.path() != path {
            return Err(InstallationError::Platform(
                "installation registry path is not the retained canonical Host child".to_owned(),
            ));
        }
        file.verify_path_identity()
            .map_err(|error| InstallationError::Platform(error.to_string()))?;
        let database = Database::open(file.path())
            .map_err(|error| InstallationError::Platform(error.to_string()))?;
        file.verify_path_identity()
            .map_err(|error| InstallationError::Platform(error.to_string()))?;
        Ok(Some(Self {
            database,
            _path_lease: RegistryPathLease::InstallationHost {
                _root: host_root,
                _file: file,
            },
        }))
    }

    /// Seeds one physically persisted active generation for a production-bound
    /// Host recovery test. The helper is feature-gated and constructs the
    /// same typed approval/fence projection that the installer transaction
    /// path commits; every subsequent Phase-B mutation goes through the real
    /// Host-owner CAS methods.
    #[cfg(feature = "test-support")]
    pub fn seed_active_generation_for_test_support(
        &self,
        host: &HostOwnerEpochCapability,
        manifest: &crate::CandidateManifest,
        transaction_id: &PlatformHandle,
        plan_digest: &PlatformHandle,
        commit_fence: &ActivationCommitFence,
    ) -> Result<(), InstallationError> {
        let _guard = host
            .live_guard()
            .map_err(|error| InstallationError::Platform(error.to_string()))?;
        manifest.validate()?;
        let manifest_digest = candidate_manifest_digest(manifest)?;
        let approval_ref = PlatformHandle::new(eliot_contracts::sha256_hex(
            format!(
                "eliot.test-support.activation-approval.v1\0{}\0{}\0{}",
                transaction_id.as_str(),
                plan_digest.as_str(),
                manifest_digest.as_str(),
            )
            .as_bytes(),
        ))
        .map_err(|error| InstallationError::InvalidField {
            field: "test_support.approval_ref".to_owned(),
            reason: error.to_string(),
        })?;
        let runtime = &manifest.runtime_launch;
        let approval = InstallationActivationApproval::from_verified_parts(
            approval_ref,
            transaction_id.clone(),
            plan_digest.clone(),
            manifest.generation.clone(),
            manifest_digest,
            runtime.descriptor_digest.clone(),
            PlatformHandle::new("owner:test-support").map_err(|error| {
                InstallationError::InvalidField {
                    field: "test_support.required_owner".to_owned(),
                    reason: error.to_string(),
                }
            })?,
            manifest.signature_ref.clone(),
            runtime.authority_descriptor_path.clone(),
            runtime.authority_descriptor_digest.clone(),
            runtime.authority_generation,
            runtime.authority_state_fence.clone(),
        );
        approval.validate()?;
        validate_approval_against_manifest(&approval, manifest, "test_support")?;
        commit_fence.validate_against_manifest(manifest)?;
        let expected_revision = self.load()?.revision();
        self.mutate_atomic(expected_revision, |registry| {
            registry.stage_pending_activation_unchecked(manifest.clone(), approval, &[])?;
            registry.commit_pending_activation_unchecked(
                transaction_id,
                plan_digest,
                &manifest.generation,
                commit_fence,
            )
        })
    }

    /// Reads one exact committed activation terminal without mutating the
    /// registry. The returned opaque receipt can only be produced from this
    /// read path and binds the transaction, plan, generation, candidate
    /// manifest, commit fence, registry revision and terminal digest.
    pub fn read_committed_activation_receipt(
        &self,
        transaction_id: &PlatformHandle,
        plan_digest: &PlatformHandle,
        generation: &PlatformHandle,
    ) -> Result<ActivationCommitReceipt, InstallationError> {
        let registry = self.load()?;
        let terminal = registry.last_terminal_activation.as_ref().ok_or_else(|| {
            InstallationError::IncompleteObservation(
                "no committed terminal activation exists".to_owned(),
            )
        })?;
        if terminal.disposition != PendingActivationTerminalDisposition::Committed {
            return Err(InstallationError::IncompleteObservation(
                "last terminal activation is not committed".to_owned(),
            ));
        }
        if terminal.transaction_id != *transaction_id
            || terminal.plan_digest != *plan_digest
            || terminal.generation != *generation
        {
            return Err(InstallationError::IdentityConflict);
        }
        if registry.active_generation.as_ref() != Some(generation) {
            return Err(InstallationError::IncompleteObservation(
                "committed terminal is not the active registry generation".to_owned(),
            ));
        }
        let manifest = registry
            .generations
            .iter()
            .find(|item| item.manifest.generation == *generation)
            .ok_or_else(|| {
                InstallationError::IncompleteObservation(
                    "committed terminal generation is not approved".to_owned(),
                )
            })?;
        let commit_fence = terminal.commit_fence.clone().ok_or_else(|| {
            InstallationError::IncompleteObservation(
                "committed terminal is missing its activation fence".to_owned(),
            )
        })?;
        commit_fence.validate_against_manifest(&manifest.manifest)?;
        let receipt = ActivationCommitReceipt {
            transaction_id: terminal.transaction_id.clone(),
            plan_digest: terminal.plan_digest.clone(),
            generation: terminal.generation.clone(),
            candidate_manifest_digest: candidate_manifest_digest(&manifest.manifest)?,
            commit_fence,
            registry_revision: registry.revision,
            terminal_digest: activation_terminal_digest(terminal)?,
        };
        receipt.commit_fence.validate()?;
        crate::sha256_handle(
            &receipt.terminal_digest,
            "activation_commit_receipt.terminal_digest",
        )?;
        Ok(receipt)
    }

    /// Loads the sealed transaction and atomically stages its exact pending
    /// activation plus installer-owned SCM approvals.
    ///
    /// `approval` must have been issued by the independent authority after
    /// static verification.  This crate deliberately exposes no constructor
    /// or deserializer for that value; until the authority lane supplies the
    /// sealed receipt, initial staging is unavailable and fails closed at the
    /// caller's boundary.
    ///
    /// `expected_revision` is checked against the registry snapshot inside the
    /// same redb write transaction that commits the projection.  An exact retry
    /// is a no-op and does not advance the revision.
    #[cfg(test)]
    pub fn stage_pending_activation_from_transaction_store<S: InstallationTransactionStore>(
        &self,
        transaction_store: &S,
        transaction_id: &PlatformHandle,
        approval: InstallationActivationApproval,
        expected_revision: u64,
    ) -> Result<(), InstallationError> {
        let transaction = transaction_store.load(transaction_id)?.ok_or_else(|| {
            InstallationError::TransactionNotFound {
                transaction_id: transaction_id.as_str().to_owned(),
            }
        })?;
        if transaction.transaction_id != *transaction_id {
            return Err(InstallationError::IdentityConflict);
        }
        if approval.transaction_id != *transaction_id {
            return Err(InstallationError::IdentityConflict);
        }
        approval.validate_against(&transaction)?;
        self.mutate_atomic(expected_revision, |registry| {
            registry.stage_pending_activation_from_transaction_with_approval(&transaction, approval)
        })
    }

    /// Stages the first-install pending projection after the durable root,
    /// package, and service-registration prefix has applied.  This is the
    /// installation transaction's own bootstrap approval; it contains no
    /// caller-supplied signature or dynamic authority bytes.  The Host remains
    /// fenced until its authenticated epoch and Phase-B handoff complete.
    #[cfg(test)]
    pub fn stage_pending_activation_from_transaction_store_bootstrap<
        S: InstallationTransactionStore,
    >(
        &self,
        transaction_store: &S,
        transaction_id: &PlatformHandle,
        expected_revision: u64,
    ) -> Result<(), InstallationError> {
        let transaction = transaction_store.load(transaction_id)?.ok_or_else(|| {
            InstallationError::TransactionNotFound {
                transaction_id: transaction_id.as_str().to_owned(),
            }
        })?;
        if transaction.transaction_id != *transaction_id {
            return Err(InstallationError::IdentityConflict);
        }
        transaction.require_bootstrap_effects_ready()?;
        let manifest_digest = candidate_manifest_digest(&transaction.candidate_manifest)?;
        let approval_ref = PlatformHandle::new(eliot_contracts::sha256_hex(
            format!(
                "eliot.first-install.bootstrap-approval.v1\0{}\0{}\0{}",
                transaction.transaction_id.as_str(),
                transaction.installer_plan_digest.as_str(),
                manifest_digest.as_str(),
            )
            .as_bytes(),
        ))
        .map_err(|error| InstallationError::InvalidField {
            field: "bootstrap_approval.approval_ref".to_owned(),
            reason: error.to_string(),
        })?;
        let runtime = &transaction.candidate_manifest.runtime_launch;
        let approval = InstallationActivationApproval::from_verified_parts(
            approval_ref,
            transaction.transaction_id.clone(),
            transaction.installer_plan_digest.clone(),
            transaction.candidate_manifest.generation.clone(),
            manifest_digest,
            runtime.descriptor_digest.clone(),
            transaction.request.required_owner.clone(),
            transaction.candidate_manifest.signature_ref.clone(),
            runtime.authority_descriptor_path.clone(),
            runtime.authority_descriptor_digest.clone(),
            runtime.authority_generation,
            runtime.authority_state_fence.clone(),
        );
        approval.validate_against(&transaction)?;
        self.mutate_atomic(expected_revision, |registry| {
            registry.stage_pending_activation_from_transaction_with_approval(&transaction, approval)
        })
    }

    /// Atomically claims one exact pending activation for the live Host owner.
    ///
    /// The registry snapshot, expected revision and complete typed approval
    /// binding are checked inside one redb write transaction.  The returned
    /// pending record is the exact durable value that Host must launch.
    pub fn claim_pending_activation(
        &self,
        host: &HostOwnerEpochCapability,
        expected_revision: u64,
        approval: &InstallationActivationApproval,
    ) -> Result<PendingActivation, InstallationError> {
        let _guard = host
            .live_guard()
            .map_err(|error| InstallationError::Platform(error.to_string()))?;
        approval.validate()?;
        let approval = approval.clone();
        self.mutate_atomic(expected_revision, |registry| {
            let pending = registry.pending_activation.as_ref().ok_or_else(|| {
                InstallationError::IncompleteObservation("no pending activation exists".to_owned())
            })?;
            if pending.approval != approval {
                return Err(InstallationError::IdentityConflict);
            }
            registry.claim_pending_activation_unchecked(
                &approval.transaction_id,
                &approval.installer_plan_digest,
                &approval.generation,
            )
        })
    }

    /// Atomically records the secret-free Host Phase-B receipt for one exact
    /// pending approval. The receipt is a query/reconcile projection only;
    /// it cannot activate or otherwise advance the pending generation.
    pub fn record_pending_phase_b_receipt(
        &self,
        host: &HostOwnerEpochCapability,
        expected_revision: u64,
        approval: &InstallationActivationApproval,
        receipt: &HostPhaseBMaterializationReceipt,
    ) -> Result<HostPhaseBMaterializationReceipt, InstallationError> {
        let _guard = host
            .live_guard()
            .map_err(|error| InstallationError::Platform(error.to_string()))?;
        approval.validate()?;
        receipt.validate()?;
        let approval = approval.clone();
        let receipt = receipt.clone();
        self.mutate_atomic(expected_revision, |registry| {
            let pending = registry.pending_activation.as_ref().ok_or_else(|| {
                InstallationError::IncompleteObservation("no pending activation exists".to_owned())
            })?;
            if pending.approval != approval
                || receipt.transaction_id != pending.transaction_id
                || receipt.candidate_manifest_digest != pending.manifest_digest
                || pending.phase_b_prepared.is_none()
            {
                return Err(InstallationError::IdentityConflict);
            }
            registry.record_pending_phase_b_receipt_unchecked(&receipt)
        })
    }

    /// Atomically records the prepared Phase-B receipt. This is a distinct
    /// durable state and cannot satisfy the final receipt field.
    pub fn record_pending_phase_b_prepared_receipt(
        &self,
        host: &HostOwnerEpochCapability,
        expected_revision: u64,
        approval: &InstallationActivationApproval,
        receipt: &HostPhaseBPreparedReceipt,
    ) -> Result<HostPhaseBPreparedReceipt, InstallationError> {
        let _guard = host
            .live_guard()
            .map_err(|error| InstallationError::Platform(error.to_string()))?;
        approval.validate()?;
        receipt.validate()?;
        let approval = approval.clone();
        let receipt = receipt.clone();
        self.mutate_atomic(expected_revision, |registry| {
            let pending = registry.pending_activation.as_ref().ok_or_else(|| {
                InstallationError::IncompleteObservation("no pending activation exists".to_owned())
            })?;
            if pending.approval != approval
                || receipt.transaction_id != pending.transaction_id
                || receipt.candidate_manifest_digest != pending.manifest_digest
                || pending.phase_b_prepared.is_none()
                || pending.phase_b_receipt.is_some()
            {
                return Err(InstallationError::IdentityConflict);
            }
            registry.record_pending_phase_b_prepared_receipt_unchecked(&receipt)
        })
    }

    /// Atomically records the exact secret-free Phase-B intent before Host
    /// materializes any destination. The intent is a projection of the sole
    /// installation transaction and is never an activation approval.
    pub fn record_pending_phase_b_intent(
        &self,
        host: &HostOwnerEpochCapability,
        expected_revision: u64,
        approval: &InstallationActivationApproval,
        intent: &HostPhaseBMaterializationIntent,
    ) -> Result<HostPhaseBMaterializationIntent, InstallationError> {
        let _guard = host
            .live_guard()
            .map_err(|error| InstallationError::Platform(error.to_string()))?;
        approval.validate()?;
        intent.validate()?;
        let approval = approval.clone();
        let intent = intent.clone();
        self.mutate_atomic(expected_revision, |registry| {
            let pending = registry.pending_activation.as_ref().ok_or_else(|| {
                InstallationError::IncompleteObservation("no pending activation exists".to_owned())
            })?;
            if pending.approval != approval
                || intent.transaction_id != pending.transaction_id
                || intent.installation_plan_digest != pending.plan_digest
                || intent.candidate_manifest_digest != pending.manifest_digest
            {
                return Err(InstallationError::IdentityConflict);
            }
            registry.record_pending_phase_b_intent_unchecked(&intent)
        })
    }

    /// Clears one exact Phase-B intent after Host has durably restored every
    /// destination to its pre-publication state. A receipt, once recorded,
    /// can never be cleared through this recovery seam.
    pub fn clear_pending_phase_b_intent(
        &self,
        host: &HostOwnerEpochCapability,
        expected_revision: u64,
        approval: &InstallationActivationApproval,
        intent: &HostPhaseBMaterializationIntent,
    ) -> Result<(), InstallationError> {
        let _guard = host
            .live_guard()
            .map_err(|error| InstallationError::Platform(error.to_string()))?;
        approval.validate()?;
        intent.validate()?;
        let approval = approval.clone();
        let intent = intent.clone();
        self.mutate_atomic(expected_revision, |registry| {
            let pending = registry.pending_activation.as_ref().ok_or_else(|| {
                InstallationError::IncompleteObservation("no pending activation exists".to_owned())
            })?;
            if pending.approval != approval
                || pending.phase_b_intent.as_ref() != Some(&intent)
                || pending.phase_b_receipt.is_some()
            {
                return Err(InstallationError::IdentityConflict);
            }
            registry.clear_pending_phase_b_intent_unchecked(&intent)
        })
    }

    /// Atomically records the Host-owned Phase-B preparation before any live
    /// destination publication. The preparation is query-only evidence and
    /// cannot activate a pending generation.
    pub fn record_pending_phase_b_prepared(
        &self,
        host: &HostOwnerEpochCapability,
        expected_revision: u64,
        approval: &InstallationActivationApproval,
        prepared: &HostPhaseBPreparedMaterialization,
    ) -> Result<HostPhaseBPreparedMaterialization, InstallationError> {
        let _guard = host
            .live_guard()
            .map_err(|error| InstallationError::Platform(error.to_string()))?;
        approval.validate()?;
        prepared.validate()?;
        let approval = approval.clone();
        let prepared = prepared.clone();
        self.mutate_atomic(expected_revision, |registry| {
            let pending = registry.pending_activation.as_ref().ok_or_else(|| {
                InstallationError::IncompleteObservation("no pending activation exists".to_owned())
            })?;
            if pending.approval != approval
                || pending.phase_b_intent.as_ref().is_none_or(|intent| {
                    intent.effect_id != prepared.effect_id
                        || intent.credential_effect_id != prepared.credential_effect_id
                        || intent.request_digest != prepared.request_digest
                        || intent.credential_receipt_digest != prepared.credential_receipt_digest
                })
                || prepared.transaction_id != pending.transaction_id
                || prepared.manifest_digest != pending.manifest_digest
                || pending.phase_b_receipt.is_some()
            {
                return Err(InstallationError::IdentityConflict);
            }
            registry.record_pending_phase_b_prepared_unchecked(&prepared)
        })
    }

    /// Atomically records the exact auxiliary Agent Bridge stage proof after
    /// `CREATE_NEW` and before publication. This is the durable recovery carrier
    /// for a crash or lost response in that interval; it never adopts bytes.
    pub fn record_pending_phase_b_agent_bridge_stage_prepared(
        &self,
        host: &HostOwnerEpochCapability,
        expected_revision: u64,
        approval: &InstallationActivationApproval,
        stage: &AgentBridgeStagePrepared,
    ) -> Result<AgentBridgeStagePrepared, InstallationError> {
        let _guard = host
            .live_guard()
            .map_err(|error| InstallationError::Platform(error.to_string()))?;
        approval.validate()?;
        stage.validate()?;
        let approval = approval.clone();
        let stage = stage.clone();
        self.mutate_atomic(expected_revision, |registry| {
            let pending = registry.pending_activation.as_ref().ok_or_else(|| {
                InstallationError::IncompleteObservation("no pending activation exists".to_owned())
            })?;
            if pending.approval != approval {
                return Err(InstallationError::IdentityConflict);
            }
            let intent = pending.phase_b_intent.as_ref().ok_or_else(|| {
                InstallationError::IncompleteObservation(
                    "Agent Bridge stage proof requires a pending Phase-B intent".to_owned(),
                )
            })?;
            stage.validate_against_phase_b(intent, pending)?;
            registry.record_pending_phase_b_agent_bridge_stage_prepared_unchecked(&stage)
        })
    }

    /// Clears one exact stage proof only during rollback, before a prepared or
    /// final Phase-B receipt exists. Final receipts retain the same proof.
    pub fn clear_pending_phase_b_agent_bridge_stage_prepared(
        &self,
        host: &HostOwnerEpochCapability,
        expected_revision: u64,
        approval: &InstallationActivationApproval,
        stage: &AgentBridgeStagePrepared,
    ) -> Result<(), InstallationError> {
        let _guard = host
            .live_guard()
            .map_err(|error| InstallationError::Platform(error.to_string()))?;
        approval.validate()?;
        stage.validate()?;
        let approval = approval.clone();
        let stage = stage.clone();
        self.mutate_atomic(expected_revision, |registry| {
            let pending = registry.pending_activation.as_ref().ok_or_else(|| {
                InstallationError::IncompleteObservation("no pending activation exists".to_owned())
            })?;
            if pending.approval != approval {
                return Err(InstallationError::IdentityConflict);
            }
            registry.clear_pending_phase_b_agent_bridge_stage_prepared_unchecked(&stage)
        })
    }

    /// Clears one exact preparation after query-only rollback has restored all
    /// destinations. A Phase-B receipt, once recorded, can never be cleared.
    pub fn clear_pending_phase_b_prepared(
        &self,
        host: &HostOwnerEpochCapability,
        expected_revision: u64,
        approval: &InstallationActivationApproval,
        prepared: &HostPhaseBPreparedMaterialization,
    ) -> Result<(), InstallationError> {
        let _guard = host
            .live_guard()
            .map_err(|error| InstallationError::Platform(error.to_string()))?;
        approval.validate()?;
        prepared.validate()?;
        let approval = approval.clone();
        let prepared = prepared.clone();
        self.mutate_atomic(expected_revision, |registry| {
            let pending = registry.pending_activation.as_ref().ok_or_else(|| {
                InstallationError::IncompleteObservation("no pending activation exists".to_owned())
            })?;
            if pending.approval != approval
                || pending.phase_b_prepared.as_ref() != Some(&prepared)
                || pending.phase_b_receipt.is_some()
            {
                return Err(InstallationError::IdentityConflict);
            }
            registry.clear_pending_phase_b_prepared_unchecked(&prepared)
        })
    }

    /// Atomically records the Host-owned `ActiveVerified` rebind intent before
    /// any authority/config/bootstrap/eliotd destination mutation.
    pub fn record_active_phase_b_rebind_intent(
        &self,
        host: &HostOwnerEpochCapability,
        expected_revision: u64,
        intent: &ActivePhaseBRebindIntent,
    ) -> Result<ActivePhaseBRebindIntent, InstallationError> {
        let _guard = host
            .live_guard()
            .map_err(|error| InstallationError::Platform(error.to_string()))?;
        intent.validate()?;
        let intent = intent.clone();
        self.mutate_atomic(expected_revision, |registry| {
            registry.record_active_phase_b_rebind_intent_unchecked(&intent)
        })
    }

    /// Atomically records `ActiveVerified` rebind preparation before the first
    /// destination write.
    pub fn record_active_phase_b_rebind_prepared(
        &self,
        host: &HostOwnerEpochCapability,
        expected_revision: u64,
        prepared: &HostPhaseBPreparedMaterialization,
    ) -> Result<HostPhaseBPreparedMaterialization, InstallationError> {
        let _guard = host
            .live_guard()
            .map_err(|error| InstallationError::Platform(error.to_string()))?;
        prepared.validate()?;
        let prepared = prepared.clone();
        self.mutate_atomic(expected_revision, |registry| {
            registry.record_active_phase_b_rebind_prepared_unchecked(&prepared)
        })
    }

    /// Atomically records the exact no-follow readback receipt for the current
    /// Host owner and epoch.
    pub fn record_active_phase_b_rebind_receipt(
        &self,
        host: &HostOwnerEpochCapability,
        expected_revision: u64,
        receipt: &ActivePhaseBRebindReceipt,
    ) -> Result<ActivePhaseBRebindReceipt, InstallationError> {
        let _guard = host
            .live_guard()
            .map_err(|error| InstallationError::Platform(error.to_string()))?;
        receipt.validate()?;
        let receipt = receipt.clone();
        self.mutate_atomic(expected_revision, |registry| {
            registry.record_active_phase_b_rebind_receipt_unchecked(&receipt)
        })
    }

    /// Atomically records the fresh-owner CAS that retires one completed
    /// `ActiveVerified` rebind attempt and installs the exact intent it
    /// authorizes. The completed receipt remains in the registry's forensic
    /// recovery history; no durable intermediate can carry a recovery chain
    /// whose final transition does not authorize the current intent.
    pub fn record_active_phase_b_rebind_recovery_and_intent(
        &self,
        host: &HostOwnerEpochCapability,
        expected_revision: u64,
        recovery: &ActivePhaseBRebindRecovery,
        intent: &ActivePhaseBRebindIntent,
    ) -> Result<ActivePhaseBRebind, InstallationError> {
        let _guard = host
            .live_guard()
            .map_err(|error| InstallationError::Platform(error.to_string()))?;
        recovery.validate()?;
        intent.validate()?;
        let recovery = recovery.clone();
        let intent = intent.clone();
        self.mutate_atomic(expected_revision, |registry| {
            registry.record_active_phase_b_rebind_recovery_and_intent_unchecked(&recovery, &intent)
        })
    }

    /// Atomically records a Host recovery disposition for one exact approval.
    pub fn mark_pending_recovery(
        &self,
        host: &HostOwnerEpochCapability,
        expected_revision: u64,
        approval: &InstallationActivationApproval,
        reason: impl Into<String>,
    ) -> Result<(), InstallationError> {
        let _guard = host
            .live_guard()
            .map_err(|error| InstallationError::Platform(error.to_string()))?;
        approval.validate()?;
        let approval = approval.clone();
        let reason = reason.into();
        self.mutate_atomic(expected_revision, |registry| {
            let pending = registry.pending_activation.as_ref().ok_or_else(|| {
                InstallationError::IncompleteObservation("no pending activation exists".to_owned())
            })?;
            if pending.approval != approval {
                return Err(InstallationError::IdentityConflict);
            }
            registry.mark_pending_recovery_unchecked(
                &approval.transaction_id,
                &approval.installer_plan_digest,
                reason,
            )
        })
    }

    /// Atomically commits one exact Host-proven healthy pending approval.
    pub fn commit_pending_activation(
        &self,
        host: &HostOwnerEpochCapability,
        expected_revision: u64,
        approval: &InstallationActivationApproval,
        commit_fence: &ActivationCommitFence,
    ) -> Result<(), InstallationError> {
        let _guard = host
            .live_guard()
            .map_err(|error| InstallationError::Platform(error.to_string()))?;
        approval.validate()?;
        commit_fence.validate()?;
        let approval = approval.clone();
        let commit_fence = commit_fence.clone();
        self.mutate_atomic(expected_revision, |registry| {
            if let Some(pending) = registry.pending_activation.as_ref()
                && pending.approval != approval
            {
                return Err(InstallationError::IdentityConflict);
            }
            registry.commit_pending_activation_unchecked(
                &approval.transaction_id,
                &approval.installer_plan_digest,
                &approval.generation,
                &commit_fence,
            )
        })
    }

    /// Atomically aborts one exact first-install pending approval.
    pub fn abort_pending_activation(
        &self,
        host: &HostOwnerEpochCapability,
        expected_revision: u64,
        approval: &InstallationActivationApproval,
    ) -> Result<(), InstallationError> {
        let _guard = host
            .live_guard()
            .map_err(|error| InstallationError::Platform(error.to_string()))?;
        approval.validate()?;
        let approval = approval.clone();
        self.mutate_atomic(expected_revision, |registry| {
            if let Some(pending) = registry.pending_activation.as_ref()
                && pending.approval != approval
            {
                return Err(InstallationError::IdentityConflict);
            }
            registry.abort_pending_activation_unchecked(
                &approval.transaction_id,
                &approval.installer_plan_digest,
            )
        })
    }
}

pub(super) fn installation_registry_path(
    host_root: &ProtectedRootLease,
) -> Result<PathBuf, InstallationError> {
    host_root
        .verify_stable_identity()
        .map_err(|error| InstallationError::Platform(error.to_string()))?;
    let canonical_root = host_root
        .canonical_path()
        .map_err(|error| InstallationError::Platform(error.to_string()))?;
    validate_installation_host_root(&canonical_root)?;
    Ok(canonical_root.join(INSTALLATION_REGISTRY_FILE_NAME))
}

pub(super) fn validate_installation_host_root(path: &Path) -> Result<(), InstallationError> {
    let identity = WindowsPathIdentity::parse_root(
        &path.to_string_lossy(),
        "installation_registry.host_root",
    )?;
    let Some(key) = identity
        .components
        .get(identity.components.len().saturating_sub(2))
    else {
        return Err(InstallationError::InvalidField {
            field: "installation_registry.host_root".to_owned(),
            reason: "retained root must be an installation Host root".to_owned(),
        });
    };
    if !valid_installation_key(key) || !identity.ends_with(&["eliot", "installations", key, "host"])
    {
        return Err(InstallationError::InvalidField {
            field: "installation_registry.host_root".to_owned(),
            reason: "retained root must end in Eliot/installations/<sha256-key>/host".to_owned(),
        });
    }
    Ok(())
}

#[cfg(test)]
pub(super) fn classify_registry_table(
    database: &impl redb::ReadableDatabase,
) -> Result<bool, InstallationError> {
    crate::redb_state::classify_registry_table(database)
}
