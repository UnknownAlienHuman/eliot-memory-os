//! Durable installation registry store: explicit-path redb owner for approved generations and Host operational projection.
//!
//! Architecture: A2.3 (explicit installation state), A12.3 (Host supervision boundary), A13.8/A13.12 (durable activation projection), ARCH-AUTH-01 (authority-bound activation), ARCH-SEC-02 (no path-inferred authority), ARCH-RES-03 (durable Host recovery projection).
//! Implementation: I3.15 (redb registry store owner), I2.2 (explicit protected `ProgramData` path), I2.23 (CAS/revision transaction), I15.3/I15.8 (typed approval and fence validation).
//!
//! This is the sole redb owner for the installation registry. It owns durable bytes and atomic CAS only; it does not mint canonical memory, Kernel authority, or Governor semantics, does not synthesize defaults, does not infer migration, and does not retry unowned operations. All production mutations are narrow transaction-bound operations with expected revision and exact typed approval. Validated projections are operational only.
//!
//! Handle lifetime and owner model (A13.9:14, s37/#1339).
//!
//! redb 4.1.0 takes one exclusive OS file lock for `Database::create`/`open`
//! and a shared lock for `ReadOnlyDatabase::open`, so exactly one writer may
//! hold this file at a time, in or across processes. A13.9 therefore requires
//! that no transaction, exclusive owner, or global lock is held during an
//! unbounded wait. This crate discharges that with one owner model: **every
//! handle is scoped to one bounded read or one bounded write, and the handle
//! is dropped before any polling, SCM, convergence, or external effect wait.**
//! redb cannot offer a shared reader/writer open or a snapshot model, so no
//! long-lived registry owner is admitted.
//!
//! Complete inventory of the production opens, by lifetime and mode:
//!
//! | Owner | Symbol | Mode | Lifetime |
//! |---|---|---|---|
//! | installer staging | `open_at` | exclusive writer | bounded stage/load projection, dropped before the SCM start + convergence wait |
//! | installer terminal reconcile | `reconcile_host_activation_terminal` → `inspect_existing_at` | shared reader | one bounded read of the committed terminal |
//! | installer owner-aware rollback | `WindowsInstallationCoordinator::rollback_with_activation_owner` → `open_existing_at` | exclusive writer | one bounded abort phase, dropped before the transaction CAS and the external rollback effects |
//! | Host CAS / readback | `eliot-host::open_registry_store_at` → `open_existing_at` | exclusive writer | one bounded CAS or load per call |
//! | Watchdog polls | `inspect_existing_at` | shared reader | one bounded poll, 250ms/2s cadence |
//!
//! Two consequences are load-bearing. First, the Host is **not** a
//! process-lifetime exclusive owner: `HostComposition` retains only the
//! canonical `registry_host_root` plus a revision-keyed, rebuildable
//! `ApprovedGenerationRegistry` projection and re-opens one short-lived handle
//! per CAS/readback, so no Host writer survives a wait and the Watchdog
//! reader is never starved by it. Second, because no side retains the writer,
//! `DatabaseAlreadyOpen` between two short-lived sides is transient
//! contention rather than a dead owner: the single typed retry helpers
//! (`redb_state::{open_registry_reader_with_retry,
//! open_registry_writer_with_retry, open_registry_writer_create_with_retry}`)
//! retry only that variant with bounded backoff, so readers converge inside
//! their readiness window and a writer retries then fails typed with its cause
//! preserved. No retry extends or bypasses an approval or State Fence.

use std::path::{Path, PathBuf};

use eliot_platform::PlatformHandle;
use eliot_platform_windows::{
    HostOwnerEpochCapability, ProtectedPathLease, ProtectedRootLease, ProtectedRuntimePathLease,
    UserOwnedPathLease, UserOwnedRootLease, require_protected_program_data_path,
};
use redb::{Database, TableDefinition};

#[cfg(test)]
use crate::InstallationTransactionStore;
use crate::approved_generation_registry::PendingActivationTerminalDisposition;
#[cfg(any(test, feature = "test-support"))]
use crate::approved_generation_registry::{
    TestSupportRegistryFixtureContour, test_support_activation_fixture,
};
#[cfg(feature = "test-support")]
use crate::validate_approval_against_manifest;
use crate::{
    ActivationCommitFence, ActivationCommitReceipt, ActivePhaseBRebind, ActivePhaseBRebindIntent,
    ActivePhaseBRebindReceipt, ActivePhaseBRebindRecovery, AgentBridgeStagePrepared,
    ApprovedGeneration, ApprovedGenerationRegistry, CommittedCutoverActivation,
    HostPhaseBMaterializationIntent, HostPhaseBMaterializationReceipt,
    HostPhaseBPreparedMaterialization, HostPhaseBPreparedReceipt, InstallationActivationApproval,
    InstallationError, PendingActivation, PendingActivationAbortReceipt,
    PreparedDestinationAdmission, PreparedDestinationMaterialisation, WindowsPathIdentity,
    activation_terminal_digest, candidate_manifest_digest, valid_installation_key,
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
    path_lease: RegistryPathLease,
}

enum RegistryPathLease {
    Legacy {
        _lease: ProtectedPathLease,
    },
    InstallationHost {
        root: ProtectedRootLease,
        _file: ProtectedRuntimePathLease,
    },
    UserOwnedHost {
        root: UserOwnedRootLease,
        _file: UserOwnedPathLease,
    },
    #[cfg(any(test, feature = "test-support"))]
    Test,
}

impl ApprovedGenerationRegistry {
    /// Derives one exact committed activation receipt from an already
    /// validated registry projection.
    ///
    /// This is deliberately a pure read over the projection. Callers that
    /// need the durable bytes should obtain the projection through
    /// [`RedbInstallationRegistry::inspect_existing_at`], which keeps the
    /// redb handle read-only and short-lived. The returned receipt remains
    /// bound to the transaction, plan, generation, manifest, commit fence,
    /// registry revision, and terminal digest; it never grants mutation
    /// authority or freshness beyond that snapshot.
    pub fn read_committed_activation_receipt(
        &self,
        transaction_id: &PlatformHandle,
        plan_digest: &PlatformHandle,
        generation: &PlatformHandle,
    ) -> Result<ActivationCommitReceipt, InstallationError> {
        let terminal = self.last_terminal_activation.as_ref().ok_or_else(|| {
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
        if self.active_generation.as_ref() != Some(generation) {
            return Err(InstallationError::IncompleteObservation(
                "committed terminal is not the active registry generation".to_owned(),
            ));
        }
        let manifest = self
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
            registry_revision: self.revision,
            terminal_digest: activation_terminal_digest(terminal)?,
        };
        receipt.commit_fence.validate()?;
        crate::sha256_handle(
            &receipt.terminal_digest,
            "activation_commit_receipt.terminal_digest",
        )?;
        Ok(receipt)
    }
}

impl RedbInstallationRegistry {
    #[cfg(test)]
    pub(super) fn from_database_for_test(database: Database) -> Self {
        Self {
            database,
            path_lease: RegistryPathLease::Test,
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
            path_lease: RegistryPathLease::Test,
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
            path_lease: RegistryPathLease::Legacy { _lease: path_lease },
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
        // A13.9 short-lived writer: bounded AlreadyOpen retry only
        // (the sole-owner contract in this module's owner-model table). The
        // installer drops this handle before any SCM start or convergence wait
        // (`bins/eliot/src/main.rs::drop(registry)`), so contention with the
        // Watchdog poll reader is transient; non-contention errors return
        // immediately with their cause preserved.
        let database = crate::redb_state::open_registry_writer_create_with_retry(file.path())?;
        file.verify_path_identity()
            .map_err(|error| InstallationError::Platform(error.to_string()))?;
        Ok(Self {
            database,
            path_lease: RegistryPathLease::InstallationHost {
                root: host_root,
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
        // A13.9 short-lived owner-aware rollback and Host CAS writer
        // (`WindowsInstallationCoordinator::rollback_with_activation_owner`
        // and `eliot-host::open_registry_store_at`): bounded AlreadyOpen retry
        // only against live Watchdog poll readers; the handle is dropped after
        // one abort phase / one CAS and before any transaction compare-and-save
        // or external rollback effect, and non-contention errors return
        // immediately with cause preserved.
        let database = crate::redb_state::open_registry_writer_with_retry(file.path())?;
        file.verify_path_identity()
            .map_err(|error| InstallationError::Platform(error.to_string()))?;
        Ok(Some(Self {
            database,
            path_lease: RegistryPathLease::InstallationHost {
                root: host_root,
                _file: file,
            },
        }))
    }

    /// Opens or creates the registry below a retained `UserMode` or `PortableDev`
    /// Host root. Current-user no-follow leases own the directory and fixed
    /// registry file for the complete redb handle lifetime.
    #[allow(
        clippy::needless_pass_by_value,
        reason = "the registry owner must retain the caller-provided Host root lease"
    )]
    pub fn open_user_owned_at(
        host_root: UserOwnedRootLease,
        profile: crate::InstallationProfile,
    ) -> Result<Self, InstallationError> {
        let path = installation_registry_path_user_owned(&host_root, profile)?;
        let file = UserOwnedPathLease::open_or_create(&host_root, &path)
            .map_err(|error| InstallationError::Platform(error.to_string()))?;
        if file.path() != path {
            return Err(InstallationError::Platform(
                "UserMode registry path is not the retained canonical Host child".to_owned(),
            ));
        }
        let database = crate::redb_state::open_registry_writer_create_with_retry(file.path())?;
        file.verify_path_identity()
            .map_err(|error| InstallationError::Platform(error.to_string()))?;
        host_root
            .verify_stable_identity()
            .map_err(|error| InstallationError::Platform(error.to_string()))?;
        Ok(Self {
            database,
            path_lease: RegistryPathLease::UserOwnedHost {
                root: host_root,
                _file: file,
            },
        })
    }

    /// Opens the existing registry below one retained current-user Host root
    /// without creating a database or file.
    #[allow(
        clippy::needless_pass_by_value,
        reason = "the registry owner must retain the caller-provided Host root lease"
    )]
    pub fn open_existing_user_owned_at(
        host_root: UserOwnedRootLease,
        profile: crate::InstallationProfile,
    ) -> Result<Option<Self>, InstallationError> {
        let path = installation_registry_path_user_owned(&host_root, profile)?;
        match std::fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.is_file() => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Ok(_) | Err(_) => {
                return Err(InstallationError::Platform(
                    "UserMode registry path is not an existing regular file".to_owned(),
                ));
            }
        }
        let file = UserOwnedPathLease::open_existing(&host_root, &path)
            .map_err(|error| InstallationError::Platform(error.to_string()))?;
        if file.path() != path {
            return Err(InstallationError::Platform(
                "UserMode registry path is not the retained canonical Host child".to_owned(),
            ));
        }
        file.verify_path_identity()
            .map_err(|error| InstallationError::Platform(error.to_string()))?;
        let database = crate::redb_state::open_registry_writer_with_retry(file.path())?;
        file.verify_path_identity()
            .map_err(|error| InstallationError::Platform(error.to_string()))?;
        host_root
            .verify_stable_identity()
            .map_err(|error| InstallationError::Platform(error.to_string()))?;
        Ok(Some(Self {
            database,
            path_lease: RegistryPathLease::UserOwnedHost {
                root: host_root,
                _file: file,
            },
        }))
    }

    fn validate_host_owner_binding_for_identity(
        &self,
        host: &HostOwnerEpochCapability,
        installation_id: &PlatformHandle,
        host_state_root: &PlatformHandle,
    ) -> Result<(), InstallationError> {
        if !host.is_for_installation(installation_id) {
            return Err(InstallationError::IdentityConflict);
        }
        let expected_root = WindowsPathIdentity::parse_root(
            host_state_root.as_str(),
            "installation_registry.owner.host_state_root",
        )?;
        let actual_root = match &self.path_lease {
            RegistryPathLease::InstallationHost { root, .. } => {
                root.verify_stable_identity()
                    .map_err(|error| InstallationError::Platform(error.to_string()))?;
                let canonical_root = root
                    .canonical_path()
                    .map_err(|error| InstallationError::Platform(error.to_string()))?;
                WindowsPathIdentity::parse_root(
                    &canonical_root.to_string_lossy(),
                    "installation_registry.owner.retained_host_state_root",
                )?
            }
            RegistryPathLease::UserOwnedHost { root, .. } => {
                root.verify_stable_identity()
                    .map_err(|error| InstallationError::Platform(error.to_string()))?;
                let canonical_root = root
                    .canonical_path()
                    .map_err(|error| InstallationError::Platform(error.to_string()))?;
                WindowsPathIdentity::parse_root(
                    &canonical_root.to_string_lossy(),
                    "installation_registry.owner.retained_host_state_root",
                )?
            }
            _ => {
                return Err(InstallationError::Platform(
                    "owner-bound abort requires the retained installation Host registry root"
                        .to_owned(),
                ));
            }
        };
        if actual_root != expected_root {
            return Err(InstallationError::IdentityConflict);
        }
        Ok(())
    }

    fn validate_host_owner_binding(
        &self,
        host: &HostOwnerEpochCapability,
        pending: &PendingActivation,
    ) -> Result<(), InstallationError> {
        self.validate_host_owner_binding_for_identity(
            host,
            &pending
                .manifest
                .runtime_launch
                .installation_epoch
                .installation,
            &pending
                .manifest
                .runtime_launch
                .runtime_state_roots
                .host_state_root,
        )
    }

    fn validate_host_owner_binding_for_abort_receipt(
        &self,
        host: &HostOwnerEpochCapability,
        receipt: &PendingActivationAbortReceipt,
    ) -> Result<(), InstallationError> {
        self.validate_host_owner_binding_for_identity(
            host,
            &receipt.installation_id,
            &receipt.host_state_root,
        )
    }

    /// Seeds one physically persisted active generation for a production-bound
    /// Host recovery test. The helper is feature-gated and constructs the
    /// same typed approval/fence projection that the installer transaction
    /// path commits; every subsequent Phase-B mutation goes through the real
    /// Host-owner CAS methods.
    ///
    /// The staged Pending record and every terminal/readback relation derived
    /// from it retain one coherent transaction/plan/manifest/approval/intent
    /// identity: the approval and the activation-intent digest are minted
    /// together by the one installation-owned test-support activation fixture,
    /// so the immediate commit below cannot drop the Pending identity.
    #[cfg(feature = "test-support")]
    pub fn seed_active_generation_for_test_support(
        &self,
        host: &HostOwnerEpochCapability,
        manifest: &crate::CandidateManifest,
        transaction_id: &PlatformHandle,
        plan_digest: &PlatformHandle,
        commit_fence: &ActivationCommitFence,
    ) -> Result<(), InstallationError> {
        self.seed_active_generation_with_service_approvals_for_test_support(
            host,
            manifest,
            transaction_id,
            plan_digest,
            commit_fence,
            &[],
        )
    }

    /// Seeds one physically persisted active generation carrying explicit
    /// installer SCM approvals (issue #958 dispatch fixture).
    ///
    /// A `SystemService` generation is invalid without exactly the Host +
    /// Watchdog approvals; callers that seed a `SystemService` manifest pass
    /// the pair from
    /// [`crate::issue_test_support_service_registration_approvals`]. The
    /// approvals ride the same Pending stage/commit path as the approval-less
    /// seeding above, so the committed row is indistinguishable from an
    /// installer-driven activation except for the domain-separated
    /// test-support effect identity the issuer binds.
    #[cfg(feature = "test-support")]
    pub fn seed_active_generation_with_service_approvals_for_test_support(
        &self,
        host: &HostOwnerEpochCapability,
        manifest: &crate::CandidateManifest,
        transaction_id: &PlatformHandle,
        plan_digest: &PlatformHandle,
        commit_fence: &ActivationCommitFence,
        service_registration_approvals: &[crate::InstallerServiceRegistrationApproval],
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
        let required_owner = PlatformHandle::new("owner:test-support").map_err(|error| {
            InstallationError::InvalidField {
                field: "test_support.required_owner".to_owned(),
                reason: error.to_string(),
            }
        })?;
        let activation_fixture = test_support_activation_fixture(
            transaction_id,
            plan_digest,
            manifest,
            &approval_ref,
            &required_owner,
            TestSupportRegistryFixtureContour::Durable,
        )?;
        validate_approval_against_manifest(&activation_fixture.approval, manifest, "test_support")?;
        commit_fence.validate_against_manifest(manifest)?;
        let expected_revision = self.load()?.revision();
        self.mutate_atomic(expected_revision, |registry| {
            registry.stage_pending_activation_unchecked(
                manifest.clone(),
                &activation_fixture,
                service_registration_approvals,
            )?;
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
        self.load()?
            .read_committed_activation_receipt(transaction_id, plan_digest, generation)
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
    ///
    /// The staged Pending record always carries a real activation-intent
    /// identity: a transaction that still retains its production
    /// `InstallationActivationProjectionIntent` uses that intent through the
    /// existing digest owner, and a fixture transaction without one uses the
    /// single installation-owned activation fixture binding.  Neither path
    /// substitutes the manifest, plan or approval digest.
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
            registry.stage_pending_activation_from_transaction_for_test_support(
                &transaction,
                approval,
                TestSupportRegistryFixtureContour::Durable,
            )
        })
    }

    /// Stages the first-install pending projection after the durable root,
    /// package, and service-registration prefix has applied.  This is the
    /// installation transaction's own bootstrap approval; it contains no
    /// caller-supplied signature or dynamic authority bytes.  The Host remains
    /// fenced until its authenticated epoch and Phase-B handoff complete.
    ///
    /// The bootstrap approval and its activation-intent identity come from one
    /// versioned, domain-separated installation-owned preimage bound to the
    /// exact transaction, plan, candidate manifest and durable registry
    /// fixture contour, so the staged Pending record and the terminal/readback
    /// relations derived from it keep one coherent identity.
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
        let activation_fixture = test_support_activation_fixture(
            &transaction.transaction_id,
            &transaction.installer_plan_digest,
            &transaction.candidate_manifest,
            &approval_ref,
            &transaction.request.required_owner,
            TestSupportRegistryFixtureContour::Durable,
        )?;
        self.mutate_atomic(expected_revision, |registry| {
            registry.stage_pending_activation_from_transaction_for_test_support(
                &transaction,
                activation_fixture.approval,
                TestSupportRegistryFixtureContour::Durable,
            )
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
            self.validate_host_owner_binding(host, pending)?;
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
            self.validate_host_owner_binding(host, pending)?;
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
            self.validate_host_owner_binding(host, pending)?;
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
            self.validate_host_owner_binding(host, pending)?;
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
            self.validate_host_owner_binding(host, pending)?;
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
            self.validate_host_owner_binding(host, pending)?;
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
            self.validate_host_owner_binding(host, pending)?;
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

    /// Atomically records one PREPARED, UNACTIVATED isolated destination
    /// installation together with the proof that its root was actually CREATED
    /// (#958, A2).
    ///
    /// The admission and its materialisation are one fact and are written in one
    /// compare-and-swap, so this authority can never retain a created root
    /// without the admission that admitted it, or an admission whose
    /// `admission_digest` the created root does not carry. The live exclusive
    /// [`HostOwnerEpochCapability`] and the CAS revision fence are required for
    /// exactly the same reason every sibling mutation requires them.
    ///
    /// A repeat of the same pair is idempotent and returns the stored
    /// materialisation, so a repeated or lost-response request resolves the same
    /// verified destination instead of allocating a second one. A changed
    /// same-operation record, or a second operation naming a destination another
    /// operation already holds, is
    /// [`InstallationError::IdentityConflict`].
    ///
    /// # Errors
    ///
    /// [`InstallationError::CompareAndSaveConflict`] when `expected_revision` no
    /// longer matches, [`InstallationError::IdentityConflict`] for a changed or
    /// contended record, [`InstallationError::Duplicate`] when the destination
    /// is this authority's active or already-approved installation, and
    /// [`InstallationError::InvalidField`] when the materialisation does not
    /// realise the admission it was given, or when the created root no longer
    /// carries the identity the materialisation recorded.
    pub fn record_prepared_isolated_destination_creation(
        &self,
        host: &HostOwnerEpochCapability,
        expected_revision: u64,
        admission: &PreparedDestinationAdmission,
        destination_generation: &ApprovedGeneration,
        materialisation: &PreparedDestinationMaterialisation,
        current_purge_ledger_revision: u64,
    ) -> Result<PreparedDestinationMaterialisation, InstallationError> {
        let _guard = host
            .live_guard()
            .map_err(|error| InstallationError::Platform(error.to_string()))?;
        self.validate_host_owner_capability(host)?;
        admission
            .validate()
            .map_err(|error| InstallationError::InvalidField {
                field: "prepared_isolated_destination".to_owned(),
                reason: error.to_string(),
            })?;
        materialisation
            .validate()
            .map_err(|error| InstallationError::InvalidField {
                field: "prepared_destination_materialisation".to_owned(),
                reason: error.to_string(),
            })?;
        // The created root is RE-OBSERVED here, at record time, through a fresh
        // no-follow protected-root lease, and its LIVE identity is compared with
        // the identity the materialisation RECORDED. `destination_root_identity`
        // is the evidence that this operation created the object at the admitted
        // name; without this comparison it was written once and read by nobody, so
        // a root replaced between creation and recording would be retained as if
        // this operation owned it. A root that cannot be re-proved is refused, and
        // nothing is deleted by name: removal stays with the handle-bound
        // publication teardown that can only act on an object it created itself.
        verify_materialised_destination_root(materialisation)?;
        destination_generation
            .validate()
            .map_err(|error| InstallationError::InvalidField {
                field: "prepared_destination.destination_generation".to_owned(),
                reason: error.to_string(),
            })?;
        let admission = admission.clone();
        let destination_generation = destination_generation.clone();
        let materialisation = materialisation.clone();
        self.mutate_atomic(expected_revision, |registry| {
            registry.record_prepared_isolated_destination_creation_unchecked(
                &admission,
                &destination_generation,
                &materialisation,
                current_purge_ledger_revision,
            )
        })
    }

    /// Atomically records one PREPARED, UNACTIVATED isolated destination
    /// installation, with no filesystem effect (#958, A2).
    ///
    /// The destination is allocated and admitted, never approved and never
    /// active: it carries no generation, no activation approval, no epoch and no
    /// SCM grant, so this call activates nothing and stops nothing. It is also
    /// the only way such a destination enters the projection, so an isolated
    /// destination that no call made is by construction not an installation.
    ///
    /// A retained admission says the destination was ADMITTED; it does not say a
    /// root was created. Use
    /// [`Self::record_prepared_isolated_destination_creation`] when the caller
    /// has actually created the root through the installation authority, so the
    /// created object and the admission are recorded as one fact.
    ///
    /// The caller's live exclusive [`HostOwnerEpochCapability`] is required for
    /// the same reason every sibling seam requires it: this is a mutation of the
    /// installation authority's own durable projection, and it must not be
    /// performed by a process that is not the current Host owner. The capability
    /// is checked against the installation this registry belongs to, so an owner
    /// of one installation cannot admit a destination on another's behalf.
    ///
    /// The comparison this seam performs is on CONTENT, not existence: the
    /// incoming record is validated, an operation this projection already holds
    /// is idempotent only when the whole record is byte-equal (so a repeated
    /// request returns the same verified destination), a changed same-operation
    /// input conflicts instead of allocating a second installation, and a
    /// destination already held under another operation is refused outright.
    ///
    /// `current_purge_ledger_revision` is the revision the ORS purge-ledger owner
    /// reports NOW. It is REQUIRED, not optional, because the revision the
    /// admission bound would otherwise be compared only against `0`: a stale and
    /// a current binding would be indistinguishable after admission, while
    /// A13.7 requires the restore to apply the CURRENT privacy purge.
    /// `IsolationEvidence::source_active_generation` is likewise compared against
    /// this projection's own current active generation, so a preparation bound to
    /// a configuration snapshot the source has since moved on from is refused
    /// rather than retained as current.
    ///
    /// # Errors
    ///
    /// Returns [`InstallationError::CompareAndSaveConflict`] when `expected
    /// _revision` no longer matches, [`InstallationError::IdentityConflict`]
    /// for a changed same-operation record, a stale source generation, a
    /// destination another operation holds, or a caller that is not this
    /// installation's owner, [`InstallationError::IncompleteObservation`] when
    /// the live purge-ledger revision disagrees with the bound one, and
    /// [`InstallationError::Duplicate`] when the destination is an installation
    /// identity this authority already holds.
    pub fn record_prepared_isolated_destination(
        &self,
        host: &HostOwnerEpochCapability,
        expected_revision: u64,
        admission: &PreparedDestinationAdmission,
        destination_generation: &ApprovedGeneration,
        current_purge_ledger_revision: u64,
    ) -> Result<PreparedDestinationAdmission, InstallationError> {
        let _guard = host
            .live_guard()
            .map_err(|error| InstallationError::Platform(error.to_string()))?;
        self.validate_host_owner_capability(host)?;
        admission
            .validate()
            .map_err(|error| InstallationError::InvalidField {
                field: "prepared_isolated_destination".to_owned(),
                reason: error.to_string(),
            })?;
        destination_generation
            .validate()
            .map_err(|error| InstallationError::InvalidField {
                field: "prepared_destination.destination_generation".to_owned(),
                reason: error.to_string(),
            })?;
        let admission = admission.clone();
        let destination_generation = destination_generation.clone();
        self.mutate_atomic(expected_revision, |registry| {
            registry.record_prepared_isolated_destination_unchecked(
                &admission,
                &destination_generation,
                current_purge_ledger_revision,
            )
        })
    }

    /// Reads back one retained prepared-destination admission for an operation.
    ///
    /// This is the idempotency read a repeated or lost-response request uses: it
    /// resolves the SAME verified destination this authority already holds rather
    /// than allocating another, and it grants no mutation authority.
    ///
    /// # Errors
    ///
    /// Returns [`InstallationError::IncompleteObservation`] when this authority
    /// retains no admission for that operation, which is the signal to allocate
    /// rather than to reuse.
    pub fn read_prepared_isolated_destination(
        &self,
        host: &HostOwnerEpochCapability,
        operation_id: &PlatformHandle,
    ) -> Result<PreparedDestinationAdmission, InstallationError> {
        let _guard = host
            .live_guard()
            .map_err(|error| InstallationError::Platform(error.to_string()))?;
        self.validate_host_owner_capability(host)?;
        let registry = self.load()?;
        registry
            .prepared_isolated_destination(operation_id)
            .cloned()
            .ok_or_else(|| {
                InstallationError::IncompleteObservation(
                    "this authority retains no prepared isolated destination for that operation"
                        .to_owned(),
                )
            })
    }

    /// Reads back the retained destination [`ApprovedGeneration`] row for an
    /// operation.
    ///
    /// This is the proof readback for the allocated destination installation:
    /// its own installation identity, lineage and allocation fence, through a
    /// real registry read. It grants no mutation authority, and the row is
    /// re-validated on the way out.
    ///
    /// # Errors
    ///
    /// Returns [`InstallationError::IncompleteObservation`] when this authority
    /// retains no destination row for that operation.
    pub fn read_prepared_destination_generation(
        &self,
        host: &HostOwnerEpochCapability,
        operation_id: &PlatformHandle,
    ) -> Result<ApprovedGeneration, InstallationError> {
        let _guard = host
            .live_guard()
            .map_err(|error| InstallationError::Platform(error.to_string()))?;
        self.validate_host_owner_capability(host)?;
        let registry = self.load()?;
        let row = registry
            .prepared_destination_generation(operation_id)
            .cloned()
            .ok_or_else(|| {
                InstallationError::IncompleteObservation(
                    "this authority retains no destination generation row for that operation"
                        .to_owned(),
                )
            })?;
        row.validate()?;
        Ok(row)
    }

    /// Reads back the ADMISSION and the MATERIALISATION of one isolated
    /// destination, as the pair this authority recorded.
    ///
    /// This is the read an import-side consumer uses to learn which root was
    /// created for its operation. It is a pure read of a durable projection: it
    /// grants no mutation authority, and both records are re-validated on the way
    /// out, so a consumer learns the created root only together with the
    /// admission digest that root was recorded against. The created root is
    /// additionally RE-OBSERVED through a fresh no-follow protected-root lease,
    /// so a caller learns the identity of the object this operation created and
    /// not merely the name it once wrote; a root that no longer carries the
    /// recorded identity is refused and preserved, never deleted by name.
    ///
    /// # Errors
    ///
    /// Returns [`InstallationError::IncompleteObservation`] when this authority
    /// retains no admission, or no materialisation, for that operation, and
    /// [`InstallationError::InvalidField`] when the retained pair is not
    /// self-consistent — which the durable projection already refuses, so a
    /// failure here means the bytes on disk changed under a reader.
    ///
    /// An [`InstallationError::InvalidField`] naming `destination_root_identity`
    /// means the created root no longer carries the identity the record asserts,
    /// or cannot be re-proved at all. That is deliberately a DIFFERENT variant
    /// from the [`InstallationError::IncompleteObservation`] this method returns
    /// for a genuinely absent record, because the two mean opposite things to a
    /// caller: absence means "allocate", and a contradicted identity means
    /// "refuse". Collapsing them would let a repeated request answer a
    /// substituted root with a fresh allocation.
    pub fn read_prepared_isolated_destination_creation(
        &self,
        host: &HostOwnerEpochCapability,
        operation_id: &PlatformHandle,
    ) -> Result<
        (
            PreparedDestinationAdmission,
            PreparedDestinationMaterialisation,
        ),
        InstallationError,
    > {
        let (admission, materialisation) = {
            let _guard = host
                .live_guard()
                .map_err(|error| InstallationError::Platform(error.to_string()))?;
            self.validate_host_owner_capability(host)?;
            let registry = self.load()?;
            let admission = registry
                .prepared_isolated_destination(operation_id)
                .cloned()
                .ok_or_else(|| {
                    InstallationError::IncompleteObservation(
                        "this authority retains no prepared isolated destination for that operation"
                            .to_owned(),
                    )
                })?;
            let materialisation = registry
                .prepared_destination_materialisation(operation_id)
                .cloned()
                .ok_or_else(|| {
                    InstallationError::IncompleteObservation(
                        "this authority retains no materialised isolated destination for that \
                         operation"
                            .to_owned(),
                    )
                })?;
            (admission, materialisation)
        };
        admission
            .validate()
            .map_err(|error| InstallationError::InvalidField {
                field: "prepared_isolated_destination".to_owned(),
                reason: error.to_string(),
            })?;
        materialisation
            .validate()
            .map_err(|error| InstallationError::InvalidField {
                field: "prepared_destination_materialisation".to_owned(),
                reason: error.to_string(),
            })?;
        if materialisation.admission_digest != admission.admission_digest
            || materialisation.destination_installation != admission.destination_installation
        {
            return Err(InstallationError::InvalidField {
                field: "prepared_destination_materialisation".to_owned(),
                reason: "the retained materialisation does not realise the retained admission"
                    .to_owned(),
            });
        }
        // The recorded created root is re-observed here too: this read hands a
        // caller the identity of an object it is about to install into, so it
        // must be the object this operation created rather than whatever now
        // carries the recorded name.
        verify_materialised_destination_root(&materialisation)?;
        Ok((admission, materialisation))
    }

    /// Forgets one explicitly owned, never-activated destination during cleanup.
    ///
    /// An operation whose destination has since been activated is refused rather
    /// than forgotten, so cleanup can never orphan an installation this authority
    /// now treats as real. An admission this authority does not hold is refused
    /// for the same reason: cleanup removes only what it owns.
    ///
    /// The filesystem is NOT touched by this call. A destination whose root was
    /// materialised is removed through the installation authority's own
    /// handle-bound publication teardown, never by path name, and only after this
    /// record has been forgotten — a root this authority cannot prove it owns is
    /// preserved.
    pub fn forget_prepared_isolated_destination_creation(
        &self,
        host: &HostOwnerEpochCapability,
        expected_revision: u64,
        admission: &PreparedDestinationAdmission,
        materialisation: &PreparedDestinationMaterialisation,
    ) -> Result<(), InstallationError> {
        let _guard = host
            .live_guard()
            .map_err(|error| InstallationError::Platform(error.to_string()))?;
        self.validate_host_owner_capability(host)?;
        admission
            .validate()
            .map_err(|error| InstallationError::InvalidField {
                field: "prepared_isolated_destination".to_owned(),
                reason: error.to_string(),
            })?;
        materialisation
            .validate()
            .map_err(|error| InstallationError::InvalidField {
                field: "prepared_destination_materialisation".to_owned(),
                reason: error.to_string(),
            })?;
        let admission = admission.clone();
        let materialisation = materialisation.clone();
        self.mutate_atomic(expected_revision, |registry| {
            registry.forget_prepared_isolated_destination_creation_unchecked(
                &admission,
                &materialisation,
            )
        })
    }

    /// Forgets one explicitly owned, never-activated destination during cleanup.
    pub fn forget_prepared_isolated_destination(
        &self,
        host: &HostOwnerEpochCapability,
        expected_revision: u64,
        admission: &PreparedDestinationAdmission,
    ) -> Result<(), InstallationError> {
        let _guard = host
            .live_guard()
            .map_err(|error| InstallationError::Platform(error.to_string()))?;
        self.validate_host_owner_capability(host)?;
        admission
            .validate()
            .map_err(|error| InstallationError::InvalidField {
                field: "prepared_isolated_destination".to_owned(),
                reason: error.to_string(),
            })?;
        let admission = admission.clone();
        self.mutate_atomic(expected_revision, |registry| {
            registry.forget_prepared_isolated_destination_unchecked(&admission)
        })
    }

    /// Proves the caller is the live owner of THIS installation before any
    /// prepared-destination mutation.
    ///
    /// The check is the SAME one every other sibling mutation uses
    /// ([`Self::validate_host_owner_binding_for_identity`]) and it is applied
    /// against the registry's OWN approved/pending generation rather than against
    /// anything a caller supplies. A prepared destination exists exactly when
    /// nothing is active about it, so requiring an active generation here would
    /// refuse the only case this seam exists for; the identity the capability is
    /// compared with is therefore read out of the owner projection instead of
    /// taken from the admission record.
    fn validate_host_owner_capability(
        &self,
        host: &HostOwnerEpochCapability,
    ) -> Result<(), InstallationError> {
        let registry = self.load()?;
        let manifest = registry
            .active()
            .map(|generation| &generation.manifest)
            .or_else(|| {
                registry
                    .pending_activation()
                    .map(|pending| &pending.manifest)
            })
            .ok_or_else(|| {
                InstallationError::IncompleteObservation(
                    "prepared-destination admission requires an approved or pending generation to \
                     establish this installation's own owner identity"
                        .to_owned(),
                )
            })?;
        self.validate_host_owner_binding_for_identity(
            host,
            &manifest.runtime_launch.installation_epoch.installation,
            &manifest.runtime_launch.runtime_state_roots.host_state_root,
        )
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
            self.validate_host_owner_binding(host, pending)?;
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
            self.validate_host_owner_binding(host, pending)?;
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
            self.validate_host_owner_binding(host, pending)?;
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
            if let Some(pending) = registry.pending_activation.as_ref() {
                self.validate_host_owner_binding(host, pending)?;
                if pending.approval != approval {
                    return Err(InstallationError::IdentityConflict);
                }
            }
            registry.commit_pending_activation_unchecked(
                &approval.transaction_id,
                &approval.installer_plan_digest,
                &approval.generation,
                &commit_fence,
            )
        })
    }

    /// Atomically commits one exact installation cutover: flips the active
    /// generation from the expected predecessor to an already-approved
    /// target (#961, M2 port from M2-961-cutover-20260922; no authorship
    /// change, no duplicate owner).
    ///
    /// Unlike [`Self::commit_pending_activation`], cutover carries no
    /// installer approval: the target must already be approved in the
    /// projection (staged by the installer/preparation flow), and the caller
    /// holds the separately-admitted cutover operation plus the Host
    /// retirement barrier. This CAS is the activation linearization point and
    /// the *only* place that records which operation performed it (#2737).
    ///
    /// `active_generation` is a pointer, not attribution. An active pointer
    /// alone cannot attribute an activation to one operation, so the
    /// operation binding is written inside the same closure that performs the
    /// flip and the exact-replay branch below is admitted only when the
    /// recorded binding already names this same operation identity and
    /// canonical request digest. Every other active-pointer-equals-target
    /// case is `IdentityConflict`: a cutover whose response was lost, or a
    /// different operation that selected the same target, must not be
    /// silently treated as this operation's success.
    ///
    /// # Errors
    ///
    /// Returns [`InstallationError`] when the owner capability is not live,
    /// the generation handles are malformed, the binding does not describe
    /// this exact predecessor/target pair, the target is not approved, or the
    /// expected revision/predecessor disagrees with durable state.
    pub fn commit_cutover_activation(
        &self,
        host: &HostOwnerEpochCapability,
        expected_revision: u64,
        expected_predecessor: &PlatformHandle,
        target_generation: &PlatformHandle,
        committed: &CommittedCutoverActivation,
    ) -> Result<(), InstallationError> {
        let _guard = host
            .live_guard()
            .map_err(|error| InstallationError::Platform(error.to_string()))?;
        crate::handle(expected_predecessor, "cutover.expected_predecessor")?;
        crate::handle(target_generation, "cutover.target_generation")?;
        if expected_predecessor == target_generation {
            return Err(InstallationError::InvalidField {
                field: "cutover.target_generation".to_owned(),
                reason: "cutover target must differ from the expected predecessor".to_owned(),
            });
        }
        // A receipt that disagrees with the CAS it claims to describe is an
        // identity conflict, not a malformed field: the caller has bound one
        // operation to a different transition.
        committed.validate()?;
        if committed.expected_predecessor != *expected_predecessor
            || committed.target_generation != *target_generation
        {
            return Err(InstallationError::IdentityConflict);
        }
        let expected_predecessor = expected_predecessor.clone();
        let target_generation = target_generation.clone();
        let committed = committed.clone();
        self.mutate_atomic(expected_revision, |registry| {
            if !registry
                .generations
                .iter()
                .any(|item| item.manifest.generation == target_generation)
            {
                return Err(InstallationError::IncompleteObservation(
                    "cutover target generation is not approved".to_owned(),
                ));
            }
            if registry.active_generation.as_ref() == Some(&target_generation) {
                // Exact replay of an already-committed cutover: the
                // predecessor was consumed by the first commit. Admit it only
                // when the durable operation binding already names this same
                // operation identity and canonical request digest, so a
                // same-pointer-different-operation case cannot be mistaken
                // for this operation's own success (#2737). A registry that
                // has never recorded a binding has no attributable flip and
                // refuses here rather than guessing.
                if registry.committed_cutover_activation() != Some(&committed) {
                    return Err(InstallationError::IdentityConflict);
                }
                return Ok(());
            }
            if registry.active_generation.as_ref() != Some(&expected_predecessor) {
                return Err(InstallationError::IdentityConflict);
            }
            registry.activate(&target_generation)?;
            registry.record_cutover_activation(&committed)
        })
    }

    /// Reads the current CAS revision for one exact pending activation.
    ///
    /// The intent records the registry snapshot used to stage the pending
    /// projection.  Staging itself advances the registry revision, so abort
    /// must use this guarded readback revision rather than replaying the
    /// pre-stage snapshot number.
    pub fn read_exact_pending_activation_revision(
        &self,
        host: &HostOwnerEpochCapability,
        transaction_id: &PlatformHandle,
        plan_digest: &PlatformHandle,
        approval: &InstallationActivationApproval,
        activation_intent_digest: &PlatformHandle,
    ) -> Result<u64, InstallationError> {
        let _guard = host
            .live_guard()
            .map_err(|error| InstallationError::Platform(error.to_string()))?;
        approval.validate()?;
        crate::sha256_handle(
            activation_intent_digest,
            "activation_projection.intent_digest",
        )?;
        let registry = self.load()?;
        let pending = registry.pending_activation().ok_or_else(|| {
            InstallationError::IncompleteObservation(
                "exact pending activation is absent before abort".to_owned(),
            )
        })?;
        self.validate_host_owner_binding(host, pending)?;
        if pending.transaction_id != *transaction_id
            || pending.plan_digest != *plan_digest
            || pending.approval != *approval
            || pending.activation_intent_digest.as_ref() != Some(activation_intent_digest)
        {
            return Err(InstallationError::IdentityConflict);
        }
        Ok(registry.revision())
    }
    /// Reads an exact Host-owner acknowledgement for a first-install abort.
    ///
    /// A prior successful abort may have advanced the registry revision before
    /// the transaction CAS response was observed.  This readback accepts only
    /// the durable `ABORTED` terminal for the exact transaction, plan and
    /// generation; it never treats a missing or different terminal as success.
    pub fn read_exact_aborted_activation_ack(
        &self,
        host: &HostOwnerEpochCapability,
        transaction_id: &PlatformHandle,
        plan_digest: &PlatformHandle,
        generation: &PlatformHandle,
        manifest_digest: &PlatformHandle,
        approval: &InstallationActivationApproval,
        activation_intent_digest: &PlatformHandle,
    ) -> Result<Option<PlatformHandle>, InstallationError> {
        let _guard = host
            .live_guard()
            .map_err(|error| InstallationError::Platform(error.to_string()))?;
        approval.validate()?;
        crate::sha256_handle(
            activation_intent_digest,
            "activation_projection.intent_digest",
        )?;
        crate::sha256_handle(manifest_digest, "pending_activation.manifest_digest")?;
        let registry = self.load()?;
        let receipt = registry
            .aborted_activation_receipts
            .iter()
            .find(|receipt| {
                receipt.transaction_id == *transaction_id
                    && receipt.plan_digest == *plan_digest
                    && receipt.generation == *generation
            })
            .or_else(|| {
                registry
                    .last_terminal_activation
                    .as_ref()
                    .and_then(|terminal| terminal.abort_receipt.as_ref())
                    .filter(|receipt| {
                        receipt.transaction_id == *transaction_id
                            && receipt.plan_digest == *plan_digest
                            && receipt.generation == *generation
                    })
            });
        let Some(receipt) = receipt else {
            return Ok(None);
        };
        receipt.validate()?;
        self.validate_host_owner_binding_for_abort_receipt(host, receipt)?;
        if registry.active_generation.is_some() || registry.last_known_good_generation.is_some() {
            return Err(InstallationError::IncompleteObservation(
                "aborted first-install terminal coexists with active registry state".to_owned(),
            ));
        }
        if !receipt.approval.matches_approval(approval)
            || candidate_manifest_digest(&receipt.manifest)? != *manifest_digest
            || receipt.activation_intent_digest != *activation_intent_digest
        {
            return Err(InstallationError::IdentityConflict);
        }
        if receipt.transaction_id == *transaction_id
            && receipt.plan_digest == *plan_digest
            && receipt.generation == *generation
        {
            let receipt_digest = crate::activation_abort_receipt_digest(receipt)?;
            let evidence = PlatformHandle::new(format!(
                "activation-abort-ack-v2:{}:{}:{}:{}",
                receipt.registry_revision_after,
                receipt.generation.as_str(),
                receipt.registry_snapshot_identity,
                receipt_digest,
            ))
            .map_err(|error| InstallationError::InvalidField {
                field: "activation_projection.abort_evidence".to_owned(),
                reason: error.to_string(),
            })?;
            return Ok(Some(evidence));
        }
        Err(InstallationError::IdentityConflict)
    }
    /// Atomically aborts one exact first-install pending approval.
    pub fn abort_pending_activation_exact(
        &self,
        host: &HostOwnerEpochCapability,
        expected_revision: u64,
        approval: &InstallationActivationApproval,
        activation_intent_digest: &PlatformHandle,
    ) -> Result<(), InstallationError> {
        let _guard = host
            .live_guard()
            .map_err(|error| InstallationError::Platform(error.to_string()))?;
        approval.validate()?;
        crate::sha256_handle(
            activation_intent_digest,
            "activation_projection.intent_digest",
        )?;
        let approval = approval.clone();
        let activation_intent_digest = activation_intent_digest.clone();
        self.mutate_atomic(expected_revision, |registry| {
            if let Some(pending) = registry.pending_activation.as_ref() {
                self.validate_host_owner_binding(host, pending)?;
                if pending.approval != approval
                    || pending.activation_intent_digest.as_ref() != Some(&activation_intent_digest)
                {
                    return Err(InstallationError::IdentityConflict);
                }
            } else if let Some(receipt) =
                registry.aborted_activation_receipts.iter().find(|receipt| {
                    receipt.transaction_id == approval.transaction_id
                        && receipt.plan_digest == approval.installer_plan_digest
                        && receipt.generation == approval.generation
                })
            {
                receipt.validate()?;
                self.validate_host_owner_binding_for_abort_receipt(host, receipt)?;
                if !receipt.approval.matches_approval(&approval)
                    || receipt.activation_intent_digest != activation_intent_digest
                {
                    return Err(InstallationError::IdentityConflict);
                }
            }
            registry.abort_pending_activation_unchecked(
                &approval.transaction_id,
                &approval.installer_plan_digest,
                &approval.generation,
                &activation_intent_digest,
            )
        })
    }

    /// Test-only compatibility seam for registry state-machine fixtures.
    /// Production callers must provide the transaction-owned digest through
    /// [`Self::abort_pending_activation_exact`]; this fixture helper derives
    /// only the already-persisted test projection and cannot authorize a
    /// production transaction.
    #[cfg(test)]
    pub fn abort_pending_activation(
        &self,
        host: &HostOwnerEpochCapability,
        expected_revision: u64,
        approval: &InstallationActivationApproval,
    ) -> Result<(), InstallationError> {
        let registry = self.load()?;
        let activation_intent_digest = registry
            .pending_activation()
            .filter(|pending| pending.approval == *approval)
            .and_then(|pending| pending.activation_intent_digest.clone())
            .or_else(|| {
                registry
                    .aborted_activation_receipts
                    .iter()
                    .find(|receipt| {
                        receipt.transaction_id == approval.transaction_id
                            && receipt.plan_digest == approval.installer_plan_digest
                            && receipt.generation == approval.generation
                    })
                    .map(|receipt| receipt.activation_intent_digest.clone())
            })
            .ok_or_else(|| {
                InstallationError::IncompleteObservation(
                    "exact activation intent digest is required for abort".to_owned(),
                )
            })?;
        self.abort_pending_activation_exact(
            host,
            expected_revision,
            approval,
            &activation_intent_digest,
        )
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

fn installation_registry_path_user_owned(
    host_root: &UserOwnedRootLease,
    profile: crate::InstallationProfile,
) -> Result<PathBuf, InstallationError> {
    host_root
        .verify_stable_identity()
        .map_err(|error| InstallationError::Platform(error.to_string()))?;
    let canonical_root = host_root
        .canonical_path()
        .map_err(|error| InstallationError::Platform(error.to_string()))?;
    match profile {
        crate::InstallationProfile::UserMode => {
            validate_installation_host_root(&canonical_root)?;
        }
        crate::InstallationProfile::PortableDev => {
            if !canonical_root
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.eq_ignore_ascii_case("host"))
            {
                return Err(InstallationError::InvalidField {
                    field: "installation_registry.host_root".to_owned(),
                    reason: "PortableDev registry root must be its explicit Host state child"
                        .to_owned(),
                });
            }
        }
        crate::InstallationProfile::SystemService => {
            return Err(InstallationError::ProfileViolation(
                "SystemService cannot use a current-user registry lease".to_owned(),
            ));
        }
    }
    Ok(canonical_root.join(INSTALLATION_REGISTRY_FILE_NAME))
}

/// Classifies one path as this crate's own Host-root contour and reports
/// whether it is already an installation, a host root, or neither.
///
/// This is the public owner surface the destination-preparation admission needs
/// and that [`Self::inspect_existing_at`] could not supply. Reading the
/// parent's registry does not work for the "preexisting foreign owner" clause:
/// `RedbInstallationRegistry::inspect_existing_at` resolves its path through the
/// crate-private [`validate_installation_host_root`] and therefore returns
/// `InstallationError::InvalidField` for a *vacant* parent, so a caller would
/// have to match an owner error field string to tell "not an installation" from
/// "a fault", and treating the fault reading as absence would admit a parent it
/// could not classify while treating it as absence-free would refuse every
/// legitimate parent. This function makes the distinction the owner actually
/// draws, in the owner, once.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InstallationHostRootClass {
    /// The path is the Host root of an installation this layout owns.
    InstallationHostRoot,
    /// The path is inside the owner-declared installation tree but is not a Host
    /// root, so it is a parent a new installation root may be created under.
    InstallationArea,
    /// The path is a retained directory that is not part of any installation.
    Unowned,
}

impl InstallationHostRootClass {
    /// Whether this class names an installation's own Host root.
    ///
    /// A destination parent that is itself an installation's Host root is a
    /// foreign owner and must never be written into; this predicate is the
    /// one-line decision the caller needs and cannot derive itself.
    #[must_use]
    pub const fn is_installation_host_root(self) -> bool {
        matches!(self, Self::InstallationHostRoot)
    }
}

/// Classifies `path` against the installation owner's DECLARED installation
/// layout, which `declared_installations_root` supplies.
///
/// # Why the declared root, not a component name
///
/// The previous form searched the path for a component spelled `installations`
/// and reported `Unowned` for everything else. That decided the question by a
/// NAME, and it answered it vacuously for the layout that matters: the
/// owner-declared isolated restore area is a *sibling* of `installations`, so
/// every derived destination leaf is lexically guaranteed `Unowned` and the
/// refusal could never fire. Comparing against the owner's own declared
/// installations root makes the answer a property of the LAYOUT: a destination
/// that lands inside `<installations_root>` is refused because it is inside an
/// installation contour, whether or not any component happens to be spelled
/// `installations`.
///
/// The classification is still purely lexical over two already-validated
/// owner-derived paths — it observes no filesystem, so it proves CONTAINMENT
/// and never existence. Existence and reparse freedom remain the protected-root
/// lease's proof and are composed by the caller on top.
///
/// # Errors
///
/// Returns [`InstallationError::InvalidField`] when either path is not a
/// comparable Windows root, because a classification that cannot be computed is
/// never `Unowned`: absence of proof is not proof of absence. `InvalidField`
/// rather than a refusal variant is deliberate — the fault is in the SHAPE of
/// the value handed in, and a caller that receives it can tell it apart from a
/// classification it actually computed.
pub fn classify_installation_host_root(
    path: &Path,
    declared_installations_root: &PlatformHandle,
) -> Result<InstallationHostRootClass, InstallationError> {
    let candidate = WindowsPathIdentity::parse_root(
        &path.to_string_lossy(),
        "installation_registry.classify.candidate",
    )?;
    let declared = WindowsPathIdentity::parse_root(
        declared_installations_root.as_str(),
        "installation_registry.classify.declared_installations_root",
    )?;
    // A candidate the declared installations area does not CONTAIN is outside
    // every installation contour by definition, which is exactly what
    // `Unowned` means. Only a path that cannot be parsed as a comparable
    // Windows root above is a fault: absence of a classification is never
    // `Unowned`, but a classification of "outside the area" is one.
    let Some(relative) = candidate.relative_to(&declared) else {
        return Ok(InstallationHostRootClass::Unowned);
    };
    // The declared installations root itself is the installation AREA: it is the
    // parent every installation root is created under, not any installation's
    // own Host root.
    if relative.is_empty() {
        return Ok(InstallationHostRootClass::InstallationArea);
    }
    let key = relative.first().ok_or_else(|| {
        InstallationError::IncompleteObservation(
            "the candidate path names no installation below the declared installations root"
                .to_owned(),
        )
    })?;
    if !valid_installation_key(key) {
        return Ok(InstallationHostRootClass::Unowned);
    }
    // Exactly `<installations_root>\<key>\host` is an installation Host root.
    // Every other depth below a valid key — the key itself, a wrong leaf, or a
    // deeper path — is the installation's own area, which an unrelated
    // operation may never write into either.
    if relative.len() == 2 && relative[1] == "host" {
        return Ok(InstallationHostRootClass::InstallationHostRoot);
    }
    Ok(InstallationHostRootClass::InstallationArea)
}

/// Re-observes a recorded materialised destination root and compares the LIVE
/// object with what the record said was created.
///
/// `PreparedDestinationMaterialisation::destination_root_identity` is the only
/// evidence that THIS operation created the object at the admitted name. Written
/// once at materialisation time and never read by anybody, it would still be true
/// of a root that has since been replaced, so both the record seam and the
/// readback re-observe the root through a fresh reparse-free
/// [`ProtectedRootLease`] and compare:
///
/// 1. the lease's own retained identity is stable across the observation,
/// 2. the lease resolves back to exactly the recorded
///    `destination_installation_root`, and
/// 3. the lease's identity EQUALS the recorded `destination_root_identity`.
///
/// # Why this never deletes
///
/// The object that would have to be removed is precisely the one whose ownership
/// just failed to be proved, so a failed re-observation reports the uncertainty
/// and preserves the directory. Removal stays with the handle-bound publication
/// teardown, which can only act on an object it created itself.
///
/// # Errors
///
/// [`InstallationError::InvalidField`] naming
/// `destination_root_identity` in every failure case: the record asserts a
/// stable identity for a specific object, and the re-observation either
/// contradicts that assertion or cannot corroborate it, so the record is not
/// valid to write or to hand back. A caller can therefore tell this refusal
/// from [`InstallationError::IncompleteObservation`], which is what
/// [`Self::read_prepared_isolated_destination_creation`] uses for the genuinely
/// ABSENT case of "this authority retains no record for that operation" — a
/// distinction a caller needs, because an absent record means "allocate" while a
/// contradicted record means "refuse".
fn verify_materialised_destination_root(
    materialisation: &PreparedDestinationMaterialisation,
) -> Result<(), InstallationError> {
    fn contradicted(reason: String) -> InstallationError {
        InstallationError::InvalidField {
            field: "prepared_destination_materialisation.destination_root_identity".to_owned(),
            reason,
        }
    }
    let lease = ProtectedRootLease::open_existing(Path::new(
        &materialisation.destination_installation_root,
    ))
    .map_err(|error| {
        contradicted(format!(
            "the recorded isolated destination root could not be re-proved through a no-follow \
             protected-root lease, so its ownership is no longer established: {error}"
        ))
    })?;
    lease.verify_stable_identity().map_err(|error| {
        contradicted(format!(
            "the recorded isolated destination root did not keep the identity it was observed \
             with: {error}"
        ))
    })?;
    let observed_root = lease.canonical_path().map_err(|error| {
        contradicted(format!(
            "the recorded isolated destination root could not be resolved through its retained \
             lease: {error}"
        ))
    })?;
    if !eliot_platform_windows::windows_paths_equal(
        &observed_root,
        Path::new(&materialisation.destination_installation_root),
    ) {
        return Err(contradicted(
            "the recorded isolated destination root no longer resolves to the root this operation \
             created"
                .to_owned(),
        ));
    }
    if lease.identity() != materialisation.destination_root_identity {
        return Err(contradicted(
            "the identity now observed for the recorded isolated destination root is not the \
             identity this operation created"
                .to_owned(),
        ));
    }
    Ok(())
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
    // Both profiled shapes are admitted here: `SystemService` refines
    // `<anchor>\Eliot` directly while `UserMode` refines the I3.1
    // durable-data sibling (`<anchor>\Eliot\data`). Profile separation stays
    // in the lease family that opened the root (a `SystemService` contour
    // cannot arrive on a current-user lease and vice versa); this check only
    // proves "an installation Host root with a valid key", never which
    // profile admitted it.
    let system_shape = identity.ends_with(&["eliot", "installations", key, "host"]);
    let user_shape = identity.ends_with(&["eliot", "data", "installations", key, "host"]);
    if !valid_installation_key(key) || !(system_shape || user_shape) {
        return Err(InstallationError::InvalidField {
            field: "installation_registry.host_root".to_owned(),
            reason: "retained root must end in Eliot/installations/<sha256-key>/host \
                     (system_service) or Eliot/data/installations/<sha256-key>/host (user_mode)"
                .to_owned(),
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
