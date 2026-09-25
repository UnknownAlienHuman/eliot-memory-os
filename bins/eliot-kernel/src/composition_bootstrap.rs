//! Kernel composition construction and bootstrap assembly.
//!
//! Architecture traceability:
//! - `ELIOT_ARCHITECTURE.md` :: A13.2. Kernel и failure domains keeps
//!   construction inside the Kernel lifecycle and failure boundary.
//! - `ELIOT_ARCHITECTURE.md` :: A13.5. Bounded resources и Control Reserve
//!   keeps assembly tied to the existing bounded runtime/control contour.
//! - `ELIOT_IMPLEMENTATION.md` :: I1.11. Startup algorithm preserves explicit
//!   startup ordering and fail-closed admission inputs.
//! - `ELIOT_IMPLEMENTATION.md` :: I14.16. Kernel and Host update keeps
//!   Host-approved bindings explicit across composition updates.
//! - `ELIOT_IMPLEMENTATION.md` :: P.3. Kernel control boundary preserves
//!   the Kernel ownership boundary while lower-layer adapters are assembled.
//!
//! Public construction semantics remain on `KernelComposition`; this ordinary
//! module only houses their implementation.
use super::{
    AgentActivationPendingState, ArtifactId, AuthorityDescriptorContour, AuthorityHandoffBegin,
    AuthorityHandoffRecord, AuthorityHandoffState, AuthorityPreparationError,
    AuthoritySnapshotBinding, BlobStoreController, BoundCanonicalOwner, ContractId,
    DaemonRuntimeState, DaemonRuntimeStatus, DispatchAuthorityId, DispatchSnapshotCodec,
    GenerationRoute, GenerationRouter, GovernorClosureRestore, HealthVector, IpcImplementation,
    KernelBackupCapture, KernelBackupRestore, KernelBuildError, KernelComposition, KernelConfig,
    KernelDispatchKey, KernelError, KernelPathAdmission, KernelService,
    KernelStoreRebindProductionBoundary, KernelSupervisionLeaseAuthority, ModuleGeneration,
    ModuleGenerationState, OperationalRecoveryStore, OrsError, OrsGenerationCoordinator,
    PROTOCOL_VERSION, PreparedAuthorityMaterial, ProcessAuthorityHandoffDescriptor,
    ProcessDispatchAuthorityController, ProcessExecutionAuthorityConfig, ProcessExecutionGateway,
    RedbRecoveryStore, RouteScope, Runtime, RuntimeConfig, SERVICE_NAME, ServerHandshakePolicy,
    StartupCoordinator, StateFence, USER_AUTOMATION_KERNEL_CAPABILITY, UserOwnedPathLease,
    UserOwnedRootLease, WindowsDispatchSnapshotCodec, WindowsPlatform, bind_canonical_owner,
    is_lower_sha256, owner_bundle_digest, sha256_hex, sha256_json, unix_ms,
};
#[cfg(test)]
use super::{CanonicalEvidenceProvider, DispatchValidationPort};
#[cfg(windows)]
use super::{
    DaemonSupervisionProgressState, SupervisionLeaseAuthorityConfig, dispatch_key,
    load_agent_bridge_declaration, observed_session_principal_binding,
};
#[cfg(not(windows))]
use super::{
    SupervisionLeaseAuthorityConfig, dispatch_key, load_agent_bridge_declaration,
    observed_session_principal_binding,
};
use eliot_contracts::ResourceGeneration;
use eliot_platform_windows::ProtectedPathLease;
use std::collections::BTreeMap;
use std::path::Path;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicU64},
};
use std::time::Duration;

use crate::kernel_diagnostics::{
    EntrypointStage, observe_entrypoint, observe_entrypoint_with_detail, observe_terminal_error,
};

/// Exact-owner backup channel clients (issue #962, Writer-D).
///
/// Declared here (rather than in `lib.rs`) so the client-injection turn
/// touches only this composition file: production assembly binds the actual
/// Host/Watchdog owner clients over the canonical pipes, with no new pipe
/// family, no Host/Watchdog implementation dependency, and no behavior
/// change to any other composition path.
#[path = "backup_owner_clients.rs"]
#[allow(
    dead_code,
    reason = "owner-channel surface is exercised per-method across production assembly and the wire test; a single surface-level allow keeps the private-module declaration warning-clean"
)]
mod backup_owner_clients;
pub use backup_owner_clients::{
    HostBackupOwnerClient, OwnerClientError, WatchdogBackupOwnerClient,
};

impl KernelComposition {
    /// Returns a production Host backup owner client bound to the exact
    /// canonical Host pipe. Fails closed when the canonical binding is
    /// unavailable; never substitutes a default.
    pub fn host_backup_owner_client() -> Result<HostBackupOwnerClient, OwnerClientError> {
        HostBackupOwnerClient::production()
    }

    /// Returns a production Watchdog backup owner client bound to the exact
    /// canonical Watchdog pipe. Fails closed; never substitutes a default.
    pub fn watchdog_backup_owner_client() -> Result<WatchdogBackupOwnerClient, OwnerClientError> {
        WatchdogBackupOwnerClient::production()
    }
}

/// Maps one build failure to its stable owner-typed diagnostic code.
///
/// The code is the `KernelBuildError` variant name only; any `String`
/// payload (paths, digests, descriptors,os errors) is never emitted.
fn kernel_build_error_code(error: &KernelBuildError) -> &'static str {
    match error {
        KernelBuildError::Platform(_) => "PLATFORM",
        KernelBuildError::Transport(_) => "TRANSPORT",
        KernelBuildError::Runtime(_) => "RUNTIME",
        KernelBuildError::Ors(_) => "ORS",
        KernelBuildError::Core(_) => "CORE",
        KernelBuildError::Service(_) => "SERVICE",
        KernelBuildError::StoreBootstrapRequired => "STORE_BOOTSTRAP_REQUIRED",
        KernelBuildError::StoreAlreadyConnected => "STORE_ALREADY_CONNECTED",
        KernelBuildError::Principal(_) => "PRINCIPAL",
    }
}

/// Maps one authority-preparation failure to its stable owner-typed phase
/// label. The label is fixed vocabulary; no descriptor/credential/ORS
/// material is emitted.
fn authority_preparation_phase(error: &AuthorityPreparationError) -> &'static str {
    match error {
        AuthorityPreparationError::ProtectedInput => {
            "kernel.composition.authority_protected_input_rejected"
        }
        AuthorityPreparationError::DigestMismatch => "kernel.composition.authority_digest_mismatch",
        AuthorityPreparationError::DescriptorInvalid => {
            "kernel.composition.authority_descriptor_invalid"
        }
        AuthorityPreparationError::DescriptorNotFresh => {
            "kernel.composition.authority_descriptor_not_fresh"
        }
        AuthorityPreparationError::CredentialUnavailable => {
            "kernel.composition.authority_credential_unavailable"
        }
        AuthorityPreparationError::CredentialInvalid => {
            "kernel.composition.authority_credential_invalid"
        }
        AuthorityPreparationError::Replay => "kernel.composition.authority_replay_rejected",
        AuthorityPreparationError::PersistenceUnknown => {
            "kernel.composition.authority_persistence_unknown"
        }
    }
}

impl KernelComposition {
    /// Builds all lower-layer surfaces once and binds them to one runtime.
    ///
    /// The default authority remains fail-closed until Host performs its
    /// authenticated handoff. Test-only adapter construction is available
    /// under the test configuration.
    pub fn new(config: KernelConfig) -> Result<Self, KernelBuildError> {
        // F-LOG-KERNEL-2 (#899): composition-build boundary. One terminal per
        // failed build; phase observations correlate by stage order.
        observe_entrypoint_with_detail(
            EntrypointStage::Composition,
            "kernel.composition.build_started",
        );
        let work_root = config.work_root.clone();
        let platform = Arc::new(WindowsPlatform::new(work_root.clone()).map_err(|error| {
            let mapped = KernelBuildError::Platform(error);
            observe_entrypoint_with_detail(
                EntrypointStage::Composition,
                "kernel.composition.build_failed",
            );
            observe_terminal_error(kernel_build_error_code(&mapped));
            mapped
        })?);
        let ors_path = Self::ors_path_for_config(&config).inspect_err(|error| {
            observe_entrypoint_with_detail(
                EntrypointStage::Composition,
                "kernel.composition.build_failed",
            );
            observe_terminal_error(kernel_build_error_code(error));
        })?;
        let ors = Arc::new(
            RedbRecoveryStore::open(&ors_path)
                .map_err(|error| KernelBuildError::Ors(error.to_string()))
                .inspect_err(|error| {
                    observe_entrypoint_with_detail(
                        EntrypointStage::Composition,
                        "kernel.composition.build_failed",
                    );
                    observe_terminal_error(kernel_build_error_code(error));
                })?,
        );
        Self::assemble(config, ors, None, platform).inspect_err(|error| {
            observe_entrypoint_with_detail(
                EntrypointStage::Composition,
                "kernel.composition.build_failed",
            );
            observe_terminal_error(kernel_build_error_code(error));
        })
    }

    /// Consumes the Host-approved protected authority descriptor before
    /// constructing the process-execution gateway.  The descriptor, secret,
    /// snapshot codec and replay binding remain inside this composition path.
    pub fn new_with_authority_descriptor(
        mut config: KernelConfig,
        path: &Path,
        expected_sha256: &str,
        contour: AuthorityDescriptorContour,
    ) -> Result<Self, KernelBuildError> {
        // F-LOG-KERNEL-2 (#899): descriptor-gated build boundary; single
        // terminal per failed build, phases correlate by stage order.
        observe_entrypoint_with_detail(
            EntrypointStage::Composition,
            "kernel.composition.descriptor_build_started",
        );
        let terminal = |error: KernelBuildError| {
            observe_entrypoint_with_detail(
                EntrypointStage::Composition,
                "kernel.composition.build_failed",
            );
            observe_terminal_error(kernel_build_error_code(&error));
            error
        };
        let work_root = config.work_root.clone();
        let platform = Arc::new(
            WindowsPlatform::new(work_root.clone())
                .map_err(KernelBuildError::Platform)
                .map_err(&terminal)?,
        );
        let ors_path = Self::ors_path_for_config(&config).map_err(&terminal)?;
        let ors = Arc::new(
            RedbRecoveryStore::open(&ors_path)
                .map_err(|error| KernelBuildError::Ors(error.to_string()))
                .map_err(&terminal)?,
        );
        let prepared = Self::prepare_authority_descriptor_material(
            &platform,
            &ors,
            path,
            expected_sha256,
            contour,
        )
        .map_err(|error| {
            observe_entrypoint_with_detail(
                EntrypointStage::Composition,
                authority_preparation_phase(&error),
            );
            KernelBuildError::Service(error.to_string())
        })
        .map_err(&terminal)?;
        #[cfg(windows)]
        if config.require_descriptor_supervision_authority {
            let descriptor_authority = SupervisionLeaseAuthorityConfig {
                authority: prepared.descriptor.supervision_authority.clone(),
            };
            match &config.supervision_lease_authority {
                Some(configured) if configured != &descriptor_authority => {
                    observe_entrypoint_with_detail(
                        EntrypointStage::SupervisionAuthority,
                        "kernel.composition.supervision_authority_mismatch",
                    );
                    return Err(terminal(KernelBuildError::Service(
                        "configured supervision authority does not match the protected handoff descriptor"
                            .to_owned(),
                    )));
                }
                Some(_) => {
                    observe_entrypoint_with_detail(
                        EntrypointStage::SupervisionAuthority,
                        "kernel.composition.supervision_authority_matched",
                    );
                }
                None => {
                    config.supervision_lease_authority = Some(descriptor_authority);
                    observe_entrypoint_with_detail(
                        EntrypointStage::SupervisionAuthority,
                        "kernel.composition.supervision_authority_adopted",
                    );
                }
            }
        }
        let snapshot_binding = AuthoritySnapshotBinding::from_wire(
            prepared.descriptor.snapshot_binding.clone(),
            &prepared.descriptor.authority_id,
        )
        .map_err(|error| KernelBuildError::Core(error.to_string()))
        .map_err(&terminal)?;
        let codec: Arc<dyn DispatchSnapshotCodec> = Arc::new(WindowsDispatchSnapshotCodec::new(
            Arc::clone(&platform),
            prepared.descriptor.dispatch_key.clone(),
        ));
        let authority_id = prepared.descriptor.authority_id.clone();
        let handoff = prepared.handoff.clone();
        let controller = Self::prepare_descriptor_controller(
            authority_id.clone(),
            prepared.key,
            Arc::clone(&ors) as Arc<dyn OperationalRecoveryStore>,
            Arc::clone(&codec),
            &snapshot_binding,
            &prepared.descriptor,
            &handoff,
        )
        .map_err(|error| KernelBuildError::Core(error.to_string()))
        .map_err(&terminal)?;
        Self::consume_authority_handoff(&ors, &handoff)
            .map_err(|error| KernelBuildError::Service(error.to_string()))
            .map_err(&terminal)?;
        Self::assemble_with_process_controller(config, controller, snapshot_binding, ors, platform)
            .map_err(&terminal)
    }

    /// Builds a production composition with an externally supplied process
    /// authority key, opaque snapshot codec and durable replay binding.
    /// Missing bindings are never replaced by a default or in-memory issuer.
    pub fn new_with_process_authority(
        config: KernelConfig,
        authority_config: ProcessExecutionAuthorityConfig,
    ) -> Result<Self, KernelBuildError> {
        // F-LOG-KERNEL-2 (#899): process-authority build boundary.
        observe_entrypoint_with_detail(
            EntrypointStage::Composition,
            "kernel.composition.process_authority_build_started",
        );
        let terminal = |error: KernelBuildError| {
            observe_entrypoint_with_detail(
                EntrypointStage::Composition,
                "kernel.composition.build_failed",
            );
            observe_terminal_error(kernel_build_error_code(&error));
            error
        };
        let work_root = config.work_root.clone();
        let platform = Arc::new(
            WindowsPlatform::new(work_root.clone())
                .map_err(KernelBuildError::Platform)
                .map_err(&terminal)?,
        );
        let ors_path = Self::ors_path_for_config(&config).map_err(&terminal)?;
        let ors = Arc::new(
            RedbRecoveryStore::open(&ors_path)
                .map_err(|error| KernelBuildError::Ors(error.to_string()))
                .map_err(&terminal)?,
        );
        Self::assemble_with_process_authority(config, authority_config, ors, platform)
            .map_err(&terminal)
    }

    /// Initializes one owner-lineage graph revision before the first
    /// revocation-history read. The operation is idempotent for the same
    /// revision and refuses a lower presentation; it does not bind an owner
    /// or grant authority by itself.
    pub fn initialize_p07_owner_revision(
        &self,
        authority_root_ref: &str,
        expected_revision: u64,
        state_fence: &StateFence,
    ) -> Result<u64, KernelBuildError> {
        if expected_revision == 0 || authority_root_ref.trim().is_empty() {
            return Err(KernelBuildError::Core(
                "owner revision initialization requires a root and nonzero revision".to_owned(),
            ));
        }
        state_fence
            .validate()
            .map_err(|error| KernelBuildError::Core(error.to_string()))?;
        let label = eliot_ors::OpaqueLabel::new(authority_root_ref)
            .map_err(|error| KernelBuildError::Core(error.to_string()))?;
        self.p07_ors
            .note_grant_graph_revision(&label, expected_revision)
            .map_err(|error| KernelBuildError::Core(error.to_string()))
    }

    ///
    /// The Governor feed publishes the restore bundle plus the exact
    /// expected graph revision; this method binds the port through the
    /// canonical bootstrap against the retained ORS handle and retains the
    /// binding. A zero or disagreeing revision, an empty admitted root set,
    /// or a stale presentation against the durable watermark fails closed
    /// without installing any owner. Binding requires no retained owner:
    /// rotation goes through refresh or recover, never a silent
    /// replacement. Returns the bound revision.
    pub fn bind_p07_owner(
        &self,
        restore: GovernorClosureRestore,
        expected_revision: u64,
    ) -> Result<u64, KernelBuildError> {
        observe_entrypoint_with_detail(
            EntrypointStage::Composition,
            "kernel.composition.p07_owner_bind_started",
        );
        if self
            .p07_owner
            .lock()
            .map_err(|_| KernelBuildError::Service("P-07 owner lock poisoned".to_owned()))?
            .is_some()
        {
            return Err(KernelBuildError::Service(
                "P-07 owner bind requires no retained owner".to_owned(),
            ));
        }
        let digest = owner_bundle_digest(&restore)
            .map_err(|error| KernelBuildError::Core(error.to_string()))?;
        let store: Arc<dyn OperationalRecoveryStore> =
            Arc::clone(&self.p07_ors) as Arc<dyn OperationalRecoveryStore>;
        let bound = bind_canonical_owner(restore, expected_revision, store)
            .inspect_err(|_| {
                observe_entrypoint_with_detail(
                    EntrypointStage::Composition,
                    "kernel.composition.p07_owner_bind_failed",
                );
            })
            .map_err(|error| KernelBuildError::Core(error.to_string()))?;
        let revision = bound.bound_revision();
        self.p07_owner
            .lock()
            .map_err(|_| KernelBuildError::Service("P-07 owner lock poisoned".to_owned()))?
            .replace(bound);
        self.p07_owner_digest
            .lock()
            .map_err(|_| KernelBuildError::Service("P-07 owner lock poisoned".to_owned()))?
            .replace(digest);
        observe_entrypoint_with_detail(
            EntrypointStage::Composition,
            "kernel.composition.p07_owner_bound",
        );
        Ok(revision)
    }

    /// Refreshes the retained P-07 owner from newer durable Governor state.
    ///
    /// The expected revision must not move backwards; the admitted state
    /// swaps atomically and the durable per-root watermark advances with
    /// the swap. Refuses when no owner is bound — bind first. A
    /// same-revision presentation carrying different bytes refuses as well:
    /// the digest agreement below proves rotation, not silent replacement.
    pub fn refresh_p07_owner(
        &self,
        restore: GovernorClosureRestore,
        expected_revision: u64,
    ) -> Result<u64, KernelBuildError> {
        let store: Arc<dyn OperationalRecoveryStore> =
            Arc::clone(&self.p07_ors) as Arc<dyn OperationalRecoveryStore>;
        let mut guard = self
            .p07_owner
            .lock()
            .map_err(|_| KernelBuildError::Service("P-07 owner lock poisoned".to_owned()))?;
        let Some(bound) = guard.as_mut() else {
            return Err(KernelBuildError::Service(
                "P-07 owner refresh requires a bound owner".to_owned(),
            ));
        };
        let result = (|| {
            let digest = owner_bundle_digest(&restore)
                .map_err(|error| KernelBuildError::Core(error.to_string()))?;
            let retained_digest = self
                .p07_owner_digest
                .lock()
                .map_err(|_| KernelBuildError::Service("P-07 owner lock poisoned".to_owned()))?
                .clone();
            if expected_revision == bound.bound_revision()
                && retained_digest.as_deref() != Some(digest.as_str())
            {
                observe_entrypoint_with_detail(
                    EntrypointStage::Composition,
                    "kernel.composition.p07_owner_digest_conflict",
                );
                return Err(KernelBuildError::Core(
                    "same-revision owner bundle digest disagreement".to_owned(),
                ));
            }
            bound
                .refresh(restore, expected_revision, &store)
                .map_err(|error| KernelBuildError::Core(error.to_string()))?;
            Ok((bound.bound_revision(), digest))
        })();
        match result {
            Ok((revision, digest)) => {
                let mut retained = self.p07_owner_digest.lock().map_err(|_| {
                    KernelBuildError::Service("P-07 owner lock poisoned".to_owned())
                })?;
                *retained = Some(digest);
                Ok(revision)
            }
            Err(error) => {
                *guard = None;
                drop(guard);
                if let Ok(mut retained) = self.p07_owner_digest.lock() {
                    *retained = None;
                }
                Err(error)
            }
        }
    }

    /// Rebinds the P-07 owner after a restart: binds when no owner is
    /// retained, refreshes when one is. Restart rehydration never invents
    /// owner state — the Governor feed re-presents the bundle and the same
    /// exact-revision gates apply as at bind time.
    pub fn recover_p07_owner(
        &self,
        restore: GovernorClosureRestore,
        expected_revision: u64,
    ) -> Result<u64, KernelBuildError> {
        let bound = self
            .p07_owner
            .lock()
            .map_err(|_| KernelBuildError::Service("P-07 owner lock poisoned".to_owned()))?
            .is_some();
        if bound {
            self.refresh_p07_owner(restore, expected_revision)
        } else {
            self.bind_p07_owner(restore, expected_revision)
        }
    }

    /// Returns the bound P-07 owner revision, if an owner is retained.
    #[must_use]
    pub fn p07_owner_revision(&self) -> Option<u64> {
        self.p07_owner
            .lock()
            .ok()
            .and_then(|guard| guard.as_ref().map(BoundCanonicalOwner::bound_revision))
    }

    /// Returns the owner readback triple for reconcile queries: whether an
    /// owner is bound, its exact revision, and the canonical digest of the
    /// bound bundle bytes. The Governor feed compares all three against
    /// what it served before claiming a publish committed.
    #[must_use]
    pub fn p07_owner_readback(&self) -> (bool, Option<u64>, Option<String>) {
        let owner = self.p07_owner.lock().ok();
        let digest = self.p07_owner_digest.lock().ok();
        match (owner, digest) {
            (Some(owner), Some(digest)) => {
                let record = owner.as_ref().map(BoundCanonicalOwner::bound_revision);
                let proof = digest.as_ref().cloned();
                (record.is_some(), record, proof)
            }
            _ => (false, None, None),
        }
    }

    fn assemble_with_process_authority(
        config: KernelConfig,
        authority_config: ProcessExecutionAuthorityConfig,
        ors: Arc<RedbRecoveryStore>,
        platform: Arc<WindowsPlatform>,
    ) -> Result<Self, KernelBuildError> {
        let authority_store: Arc<dyn OperationalRecoveryStore> = ors.clone();
        let controller = Arc::new(Mutex::new(
            ProcessDispatchAuthorityController::restore(
                authority_config.authority_id,
                authority_config.key,
                authority_store,
                authority_config.snapshot_codec,
                &authority_config.snapshot_binding,
            )
            .map_err(|error| KernelBuildError::Core(error.to_string()))?,
        ));
        Self::assemble_with_process_controller(
            config,
            controller,
            authority_config.snapshot_binding,
            ors,
            platform,
        )
    }

    fn assemble_with_process_controller(
        config: KernelConfig,
        controller: Arc<Mutex<ProcessDispatchAuthorityController>>,
        snapshot_binding: AuthoritySnapshotBinding,
        ors: Arc<RedbRecoveryStore>,
        platform: Arc<WindowsPlatform>,
    ) -> Result<Self, KernelBuildError> {
        let path_admission = Arc::new(KernelPathAdmission::new(Arc::clone(&platform)));
        let gateway = Arc::new(ProcessExecutionGateway::new(
            controller,
            Arc::clone(&ors),
            snapshot_binding,
            path_admission,
        ));
        Self::assemble(config, ors, Some(gateway), platform)
    }

    /// Reconciles the durable activation intent and replay snapshot before a
    /// process gateway is constructed.  A Reserved handoff with no snapshot
    /// is the only clean-boot path and is admitted only while its immutable
    /// descriptor is fresh.  An exact snapshot proves that activation had
    /// already reached its durable boundary, so restart recovery is allowed
    /// after the one-shot admission interval has elapsed.
    pub(crate) fn prepare_descriptor_controller(
        authority_id: DispatchAuthorityId,
        key: KernelDispatchKey,
        store: Arc<dyn OperationalRecoveryStore>,
        codec: Arc<dyn DispatchSnapshotCodec>,
        binding: &AuthoritySnapshotBinding,
        descriptor: &ProcessAuthorityHandoffDescriptor,
        handoff: &AuthorityHandoffRecord,
    ) -> eliot_kernel_core::KernelResult<Arc<Mutex<ProcessDispatchAuthorityController>>> {
        // F-LOG-KERNEL-2 (#899): handoff-state phase observations only; the
        // controller remains the single owner of activation/recovery.
        match handoff.state {
            AuthorityHandoffState::Consumed => {
                observe_entrypoint_with_detail(
                    EntrypointStage::Composition,
                    "kernel.composition.handoff_consumed_restore",
                );
                ProcessDispatchAuthorityController::restore(
                    authority_id,
                    key,
                    store,
                    codec,
                    binding,
                )
                .map(|controller| Arc::new(Mutex::new(controller)))
            }
            AuthorityHandoffState::Reserved => {
                if ProcessDispatchAuthorityController::exact_snapshot_present(
                    &authority_id,
                    store.as_ref(),
                    binding,
                )? {
                    observe_entrypoint_with_detail(
                        EntrypointStage::Composition,
                        "kernel.composition.handoff_reserved_replay",
                    );
                    return ProcessDispatchAuthorityController::restore(
                        authority_id,
                        key,
                        store,
                        codec,
                        binding,
                    )
                    .map(|controller| Arc::new(Mutex::new(controller)));
                }
                let now = i64::try_from(unix_ms()).unwrap_or(i64::MAX);
                if !Self::authority_descriptor_is_fresh(descriptor, now) {
                    observe_entrypoint_with_detail(
                        EntrypointStage::Composition,
                        "kernel.composition.handoff_reserved_not_fresh",
                    );
                    return Err(KernelError::RecoveryUnavailable(
                        "fresh authority admission interval is not active".to_owned(),
                    ));
                }
                observe_entrypoint_with_detail(
                    EntrypointStage::Composition,
                    "kernel.composition.handoff_reserved_activate",
                );
                ProcessDispatchAuthorityController::activate_and_persist_initial(
                    authority_id,
                    key,
                    store,
                    codec,
                    binding,
                )
                .map(|controller| Arc::new(Mutex::new(controller)))
            }
            AuthorityHandoffState::Unknown => {
                observe_entrypoint_with_detail(
                    EntrypointStage::Composition,
                    "kernel.composition.handoff_unknown_reconcile",
                );
                Err(KernelError::RecoveryUnavailable(
                    "authority handoff outcome is unknown and requires reconciliation".to_owned(),
                ))
            }
        }
    }

    /// Commits the terminal handoff only after the controller has proven an
    /// exact durable replay snapshot.  An uncertain consume write is
    /// reconciled by rereading ORS; a committed Consumed record is accepted
    /// idempotently, while Reserved/Unknown are left untouched and fail
    /// closed.  In particular, this path never demotes a possible Consumed
    /// record to Unknown.
    pub(crate) fn consume_authority_handoff(
        ors: &RedbRecoveryStore,
        handoff: &AuthorityHandoffRecord,
    ) -> Result<(), AuthorityPreparationError> {
        // F-LOG-KERNEL-2 (#899): handoff-commit phases only; ORS stays the
        // single owner of the terminal Consumed record.
        let now = i64::try_from(unix_ms()).unwrap_or(i64::MAX);
        let consumed = AuthorityHandoffRecord {
            state: AuthorityHandoffState::Consumed,
            consumed_at_ms: Some(now),
            ..handoff.clone()
        };
        if ors.persist_authority_handoff(&consumed).is_ok() {
            observe_entrypoint_with_detail(
                EntrypointStage::Composition,
                "kernel.composition.handoff_consumed",
            );
            return Ok(());
        }
        let observed = ors
            .load_authority_handoff(&consumed.handoff_id)
            .map_err(|_| AuthorityPreparationError::PersistenceUnknown)?
            .ok_or(AuthorityPreparationError::PersistenceUnknown)?;
        if observed.state == AuthorityHandoffState::Consumed
            && Self::same_authority_handoff_identity(&observed, &consumed)
        {
            observe_entrypoint_with_detail(
                EntrypointStage::Composition,
                "kernel.composition.handoff_consumed_replay",
            );
            return Ok(());
        }
        if observed.state == AuthorityHandoffState::Unknown {
            observe_entrypoint_with_detail(
                EntrypointStage::Composition,
                "kernel.composition.handoff_unknown_replay",
            );
            return Err(AuthorityPreparationError::Replay);
        }
        observe_entrypoint_with_detail(
            EntrypointStage::Composition,
            "kernel.composition.handoff_persistence_unknown",
        );
        Err(AuthorityPreparationError::PersistenceUnknown)
    }

    fn same_authority_handoff_identity(
        left: &AuthorityHandoffRecord,
        right: &AuthorityHandoffRecord,
    ) -> bool {
        left.handoff_id == right.handoff_id
            && left.descriptor_digest == right.descriptor_digest
            && left.authority_id == right.authority_id
            && left.snapshot_record_id == right.snapshot_record_id
            && left.snapshot_binding_digest == right.snapshot_binding_digest
            && left.authority_epoch == right.authority_epoch
            && left.generation == right.generation
            && left.state_fence_digest == right.state_fence_digest
            && left.secret_reference_identity_digest == right.secret_reference_identity_digest
            && left.issued_at_ms == right.issued_at_ms
            && left.expires_at_ms == right.expires_at_ms
    }

    fn authority_descriptor_is_fresh(
        descriptor: &ProcessAuthorityHandoffDescriptor,
        now_ms: i64,
    ) -> bool {
        descriptor.issued_at_ms <= now_ms && now_ms < descriptor.expires_at_ms
    }

    /// Reads, validates, and reserves one protected authority descriptor.
    ///
    /// This remains Kernel-private until the live Store-derived validation
    /// context is available in K1C. The descriptor and credential never leave
    /// this process as serialized authority material.
    #[allow(dead_code)]
    pub(crate) fn prepare_authority_descriptor(
        &self,
        path: &Path,
        expected_sha256: &str,
        contour: AuthorityDescriptorContour,
    ) -> Result<PreparedAuthorityMaterial, AuthorityPreparationError> {
        Self::prepare_authority_descriptor_material(
            &self.platform,
            &self.generation_gateway.ors,
            path,
            expected_sha256,
            contour,
        )
    }

    #[allow(
        clippy::too_many_lines,
        reason = "descriptor-preparation phases keep exact freshness/credential/replay checks in one audited gateway"
    )]
    fn prepare_authority_descriptor_material(
        platform: &WindowsPlatform,
        ors: &RedbRecoveryStore,
        path: &Path,
        expected_sha256: &str,
        contour: AuthorityDescriptorContour,
    ) -> Result<PreparedAuthorityMaterial, AuthorityPreparationError> {
        // F-LOG-KERNEL-2 (#899): descriptor-preparation phases only; no
        // descriptor/credential/path/digest material is emitted.
        let reject = |error: AuthorityPreparationError| {
            observe_entrypoint_with_detail(
                EntrypointStage::Composition,
                authority_preparation_phase(&error),
            );
            error
        };
        if !is_lower_sha256(expected_sha256) {
            return Err(reject(AuthorityPreparationError::DigestMismatch));
        }
        let bytes = match contour {
            AuthorityDescriptorContour::PortableCurrentUser { root } => {
                let root_lease = UserOwnedRootLease::open_existing(&root)
                    .map_err(|_| reject(AuthorityPreparationError::ProtectedInput))?;
                let file_lease = UserOwnedPathLease::open_existing(&root_lease, path)
                    .map_err(|_| reject(AuthorityPreparationError::ProtectedInput))?;
                file_lease
                    .verify_stable_identity()
                    .and_then(|()| file_lease.verify_path_identity())
                    .map_err(|_| reject(AuthorityPreparationError::ProtectedInput))?;
                file_lease
                    .read_bounded(1024 * 1024)
                    .map_err(|_| reject(AuthorityPreparationError::ProtectedInput))?
            }
            AuthorityDescriptorContour::ProgramData => {
                let file_lease = ProtectedPathLease::open_existing_absolute(path)
                    .map_err(|_| reject(AuthorityPreparationError::ProtectedInput))?;
                file_lease
                    .verify_stable_identity()
                    .and_then(|()| file_lease.verify_path_identity())
                    .map_err(|_| reject(AuthorityPreparationError::ProtectedInput))?;
                file_lease
                    .read_bounded(1024 * 1024)
                    .map_err(|_| reject(AuthorityPreparationError::ProtectedInput))?
            }
        };
        if sha256_hex(&bytes) != expected_sha256 {
            return Err(reject(AuthorityPreparationError::DigestMismatch));
        }
        let descriptor: ProcessAuthorityHandoffDescriptor = serde_json::from_slice(&bytes)
            .map_err(|_| reject(AuthorityPreparationError::DescriptorInvalid))?;
        descriptor
            .validate_structure()
            .map_err(|_| reject(AuthorityPreparationError::DescriptorInvalid))?;
        let candidate = Self::authority_handoff_candidate(&descriptor).map_err(&reject)?;

        // Inspect the immutable handoff identity before touching Credential
        // Manager. An exact existing handoff is replay evidence and may be
        // recovered after its admission interval; only an absent handoff is
        // required to be fresh before the credential boundary is crossed.
        let existing = ors
            .load_authority_handoff(&candidate.handoff_id)
            .map_err(|_| reject(AuthorityPreparationError::PersistenceUnknown))?;
        if let Some(existing) = &existing {
            if !Self::same_authority_handoff_identity(existing, &candidate) {
                return Err(reject(AuthorityPreparationError::Replay));
            }
            observe_entrypoint_with_detail(
                EntrypointStage::Composition,
                "kernel.composition.authority_handoff_replay",
            );
        } else {
            let now = i64::try_from(unix_ms()).unwrap_or(i64::MAX);
            if !Self::authority_descriptor_is_fresh(&descriptor, now) {
                return Err(reject(AuthorityPreparationError::DescriptorNotFresh));
            }
        }

        let secret = platform
            .read_credential(descriptor.dispatch_key.key.as_str())
            .map_err(|_| reject(AuthorityPreparationError::CredentialUnavailable))?;
        if secret.expose().len() != 32 || secret.expose().iter().all(|byte| *byte == 0) {
            return Err(reject(AuthorityPreparationError::CredentialInvalid));
        }
        let mut key_bytes = [0_u8; 32];
        key_bytes.copy_from_slice(secret.expose());
        let key = KernelDispatchKey::from_secret_bytes(key_bytes)
            .map_err(|_| reject(AuthorityPreparationError::CredentialInvalid))?;

        let outcome = match ors.begin_authority_handoff_fresh(&candidate) {
            Ok(outcome) => outcome,
            Err(OrsError::AuthorityHandoffNotFresh) => {
                return Err(reject(AuthorityPreparationError::DescriptorNotFresh));
            }
            Err(_) => return Err(reject(AuthorityPreparationError::PersistenceUnknown)),
        };
        let handoff = match outcome {
            AuthorityHandoffBegin::Acquired => {
                observe_entrypoint_with_detail(
                    EntrypointStage::Composition,
                    "kernel.composition.authority_handoff_acquired",
                );
                candidate
            }
            AuthorityHandoffBegin::Existing(existing) => match existing.state {
                AuthorityHandoffState::Reserved | AuthorityHandoffState::Consumed => {
                    observe_entrypoint_with_detail(
                        EntrypointStage::Composition,
                        "kernel.composition.authority_handoff_existing",
                    );
                    existing
                }
                AuthorityHandoffState::Unknown => {
                    return Err(reject(AuthorityPreparationError::Replay));
                }
            },
        };
        observe_entrypoint_with_detail(
            EntrypointStage::Composition,
            "kernel.composition.authority_descriptor_prepared",
        );
        Ok(PreparedAuthorityMaterial {
            descriptor,
            key,
            handoff,
        })
    }

    fn authority_handoff_candidate(
        descriptor: &ProcessAuthorityHandoffDescriptor,
    ) -> Result<AuthorityHandoffRecord, AuthorityPreparationError> {
        let handoff_id = eliot_ors::OperationIdentity::new(descriptor.handoff_id.as_str())
            .map_err(|_| AuthorityPreparationError::DescriptorInvalid)?;
        Ok(AuthorityHandoffRecord {
            contract_version: eliot_ors::CONTRACT_VERSION,
            handoff_id,
            descriptor_digest: descriptor.descriptor_sha256.clone(),
            authority_id: eliot_ors::OpaqueLabel::new(descriptor.authority_id.as_str())
                .map_err(|_| AuthorityPreparationError::DescriptorInvalid)?,
            snapshot_record_id: descriptor.snapshot_binding.record_id.clone(),
            snapshot_binding_digest: sha256_json(&descriptor.snapshot_binding)
                .map_err(|_| AuthorityPreparationError::DescriptorInvalid)?,
            authority_epoch: descriptor.state_fence.authority_epoch.sequence.get(),
            generation: descriptor.generation.value(),
            state_fence_digest: sha256_json(&descriptor.state_fence)
                .map_err(|_| AuthorityPreparationError::DescriptorInvalid)?,
            secret_reference_identity_digest: sha256_json(&descriptor.dispatch_key)
                .map_err(|_| AuthorityPreparationError::DescriptorInvalid)?,
            state: AuthorityHandoffState::Reserved,
            issued_at_ms: descriptor.issued_at_ms,
            expires_at_ms: descriptor.expires_at_ms,
            consumed_at_ms: None,
            reconciliation_evidence: None,
        })
    }

    /// Builds the production composition with Host-owned canonical evidence
    /// and the active P-07 dispatch authority adapters.
    #[cfg(test)]
    pub fn new_with_adapters(
        config: KernelConfig,
        _authority: Arc<dyn DispatchValidationPort>,
        evidence: Arc<dyn CanonicalEvidenceProvider>,
    ) -> Result<Self, KernelBuildError> {
        let work_root = config.work_root.clone();
        let platform =
            Arc::new(WindowsPlatform::new(work_root.clone()).map_err(KernelBuildError::Platform)?);
        let ors_path = work_root.join(".eliot").join("kernel-ors.redb");
        let ors = Arc::new(
            RedbRecoveryStore::open_with_evidence(&ors_path, evidence)
                .map_err(|error| KernelBuildError::Ors(error.to_string()))?,
        );
        Self::assemble(config, ors, None, platform)
    }

    /// Keeps ordered generation, authority, and handoff construction in one
    /// composition path so no intermediate partially wired authority escapes.
    #[allow(clippy::too_many_lines)]
    #[allow(clippy::needless_pass_by_value)]
    fn assemble(
        config: KernelConfig,
        ors: Arc<RedbRecoveryStore>,
        process_gateway: Option<Arc<ProcessExecutionGateway>>,
        platform: Arc<WindowsPlatform>,
    ) -> Result<Self, KernelBuildError> {
        // F-LOG-KERNEL-2 (#899): assembly phases only; the public
        // constructors own the single terminal per failed build. Only fixed
        // phase labels plus numeric epoch/generation are emitted, never raw
        // roots/pipes/digests/descriptors/credentials.
        observe_entrypoint_with_detail(
            EntrypointStage::Composition,
            "kernel.composition.assemble_started",
        );
        let work_root = config.work_root.clone();
        let store_bootstrap = config.store_bootstrap.clone();
        let daemon_launch = config.daemon_launch.clone();
        let kernel_artifact_sha256 = config.kernel_artifact_sha256.clone();
        let eliotd_descriptor_artifact_sha256 = config.eliotd_descriptor_artifact_sha256.clone();
        let wasm_host_executable_path = config.wasm_host_executable_path.clone();
        let wasm_host_artifact_sha256 = config.wasm_host_artifact_sha256.clone();
        let doctor_artifact_sha256 = config.doctor_artifact_sha256.clone();
        let testd_artifact_sha256 = config.testd_artifact_sha256.clone();
        let native_worker_artifact_sha256 = config.native_worker_artifact_sha256.clone();
        let eliotd_receipt_binding = config.eliotd_receipt_binding.clone();
        if let Some(binding) = &eliotd_receipt_binding {
            binding.validate().map_err(|error| {
                observe_entrypoint_with_detail(
                    EntrypointStage::Composition,
                    "kernel.composition.dependencies_rejected",
                );
                KernelBuildError::Service(error)
            })?;
        }
        observe_entrypoint_with_detail(
            EntrypointStage::Composition,
            "kernel.composition.dependencies_validated",
        );
        #[cfg(windows)]
        let agent_bridge_admission = config.agent_bridge_admission.clone();
        #[cfg(windows)]
        if let Some(admission) = agent_bridge_admission.as_ref() {
            admission
                .validate()
                .map_err(|error| KernelBuildError::Service(error.to_string()))?;
            // Read and validate the protected declaration during composition,
            // but retain only the inert descriptor until a matching Host
            // candidate reaches Ready. This prevents preactivation exposure.
            let _ = load_agent_bridge_declaration(admission)?;
        }
        #[cfg(windows)]
        if config.require_descriptor_supervision_authority
            && config.supervision_lease_authority.is_none()
        {
            return Err(KernelBuildError::Service(
                "production Kernel requires the installer-provisioned supervision authority from the protected handoff descriptor"
                    .to_owned(),
            ));
        }
        if let Some(launch) = &daemon_launch {
            launch
                .validate()
                .map_err(|error| KernelBuildError::Service(error.to_string()))?;
            if store_bootstrap.as_ref().is_some_and(|requirement| {
                requirement.state_fence.authority_epoch != launch.authority_epoch
                    || requirement.state_fence.resource_generation != launch.generation
            }) {
                return Err(KernelBuildError::Service(
                    "eliotd launch descriptor does not match Store bootstrap fence".to_owned(),
                ));
            }
        }
        if let Some(digest) = &kernel_artifact_sha256
            && !is_lower_sha256(digest)
        {
            return Err(KernelBuildError::Service(
                "Kernel artifact digest must be lowercase SHA-256".to_owned(),
            ));
        }
        if let Some(digest) = &eliotd_descriptor_artifact_sha256
            && !is_lower_sha256(digest)
        {
            return Err(KernelBuildError::Service(
                "eliotd descriptor artifact digest must be lowercase SHA-256".to_owned(),
            ));
        }
        for (digest, label) in [
            (&doctor_artifact_sha256, "Doctor"),
            (&testd_artifact_sha256, "Testd"),
            (&native_worker_artifact_sha256, "native worker"),
            (&wasm_host_artifact_sha256, "WASM host"),
        ] {
            if let Some(digest) = digest
                && !is_lower_sha256(digest)
            {
                return Err(KernelBuildError::Service(format!(
                    "{label} artifact digest must be lowercase SHA-256"
                )));
            }
        }
        if daemon_launch.is_some() && kernel_artifact_sha256.is_none() {
            return Err(KernelBuildError::Service(
                "integrated eliotd launch requires an independent Kernel artifact digest"
                    .to_owned(),
            ));
        }
        // The integrated contour has no environment/default authority. The
        // daemon config digest is carried by the Host-approved launch
        // descriptor and is checked again by eliotd when its retained file is
        // opened. Standalone test compositions intentionally have no approved
        // config hash and therefore cannot admit an integrated daemon.
        let approved_config_hash = daemon_launch
            .as_ref()
            .map(|launch| launch.config_descriptor_sha256.clone());
        #[cfg(windows)]
        let supervision_lease_authority = config
            .supervision_lease_authority
            .clone()
            .map(|authority| {
                KernelSupervisionLeaseAuthority::new(Arc::clone(&ors), work_root.clone(), authority)
            })
            .transpose()?;
        let _ = &platform;
        let ipc = IpcImplementation::new(config.pipe_name)?;
        // An integrated Kernel must construct its active store route from the
        // exact Host-approved bootstrap fence. Falling back to genesis is
        // reserved for the explicitly standalone composition, where no Store
        // authority has been injected.
        //
        // Lineage-aware route seed (Implements #64): the Kernel route table is
        // built from the exact canonical `EpochId` tuple carried by the
        // Host-approved bootstrap fence. There is no scalar `AuthorityEpoch`
        // projection left for the route, so a route minted under another
        // lineage at the same sequence can never be admitted as the active
        // route.
        let (canonical_epoch, generation) = match store_bootstrap.as_ref() {
            None => (
                eliot_contracts::EpochId::new(
                    eliot_contracts::EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000")
                        .map_err(|error| KernelBuildError::Service(error.to_string()))?,
                    std::num::NonZeroU64::MIN,
                )
                .map_err(|error| KernelBuildError::Service(error.to_string()))?,
                ResourceGeneration::genesis(),
            ),
            Some(requirement) => (
                requirement.state_fence.authority_epoch.clone(),
                requirement.state_fence.resource_generation,
            ),
        };
        let mut generations = GenerationRouter::at_epoch(canonical_epoch.clone());
        generations
            .register(
                GenerationRoute::new(
                    RouteScope::new("daemon")
                        .map_err(|error| KernelBuildError::Core(error.to_string()))?,
                    generation,
                    canonical_epoch.clone(),
                )
                .map_err(|error| KernelBuildError::Core(error.to_string()))?,
            )
            .map_err(|error| KernelBuildError::Core(error.to_string()))?;
        // The canonical store bridge has its own route scope.  It starts at
        // the independent genesis generation and is cut over separately from
        // the daemon process route.
        generations
            .register(
                GenerationRoute::new(
                    RouteScope::new("store_bridge")
                        .map_err(|error| KernelBuildError::Core(error.to_string()))?,
                    generation,
                    canonical_epoch.clone(),
                )
                .map_err(|error| KernelBuildError::Core(error.to_string()))?,
            )
            .map_err(|error| KernelBuildError::Core(error.to_string()))?;
        // F-LOG-KERNEL-2 (#899): exact route/generation observation. Only the
        // fixed route names plus the lineage-aware epoch tuple and generation
        // are emitted, never raw bootstrap/launch/descriptor material. The
        // epoch keeps its lineage: a sequence-only spelling would let two
        // unrelated lineages share one observation.
        observe_entrypoint_with_detail(
            EntrypointStage::Composition,
            &format!(
                "kernel.composition.route_registered:daemon:epoch={:?}:generation={}",
                canonical_epoch,
                generation.value()
            ),
        );
        observe_entrypoint_with_detail(
            EntrypointStage::StoreBootstrap,
            &format!(
                "kernel.composition.route_registered:store_bridge:epoch={:?}:generation={}",
                canonical_epoch,
                generation.value()
            ),
        );
        let service = KernelService::new(dispatch_key(&work_root), 4, 128)
            .map_err(|error| KernelBuildError::Service(error.to_string()))?;
        let module_id =
            ContractId::new("eliotd").map_err(|error| KernelBuildError::Core(error.to_string()))?;
        let artifact_id = daemon_launch
            .as_ref()
            .map_or_else(
                || ArtifactId::new("eliot-kernel-standalone"),
                |launch| ArtifactId::new(launch.executable_sha256.clone()),
            )
            .map_err(|error| KernelBuildError::Core(error.to_string()))?;
        let module_generation = ModuleGeneration {
            module_id: module_id.clone(),
            generation,
            artifact_id,
            state: ModuleGenerationState::Starting,
            health: HealthVector::healthy(),
            state_fence: StateFence::new(canonical_epoch.clone(), generation),
        };
        #[cfg(windows)]
        let session_principal_binding = observed_session_principal_binding()?;
        #[cfg(not(windows))]
        let session_principal_binding = "unsupported-non-windows-principal".to_owned();
        // The published front-door config snapshot carries the COMPLETE typed
        // epoch tuple, never a bare sequence counter (Implements #64). A
        // scalar spelling cannot say which lineage authorized the route, so
        // two unrelated lineages at the same sequence would project one
        // indistinguishable snapshot. `EpochId` is the same value shape the
        // sibling projections publish (`health_view::daemon_snapshot` and
        // `generation_recovery::update_handshake_policy`) and the exact shape
        // both readers already require: `eliotd`'s
        // `daemon_kernel_client::KernelSnapshotWire` and the CLI's
        // `KernelConfigSnapshot` both declare
        // `authority_epoch: EpochId` under `deny_unknown_fields`, so a bare
        // number would fail their decode outright. The daemon takes its
        // binding epoch from the launch handshake, never from this key.
        let mut config_snapshot = serde_json::json!({
            "service": SERVICE_NAME,
            "protocol": PROTOCOL_VERSION,
            "generation": generation.value(),
            "authority_epoch": canonical_epoch,
            "artifact_digest": kernel_artifact_sha256
                .as_deref()
                .unwrap_or("eliot-kernel-standalone"),
        });
        if let Some(launch) = daemon_launch.as_ref() {
            config_snapshot["protected_snapshot_digest"] =
                serde_json::Value::String(launch.protected_snapshot_digest.as_str().to_owned());
        }
        let front_door_policy = ServerHandshakePolicy {
            protocol_range: eliot_protocol::ProtocolRange {
                minimum: eliot_protocol::ProtocolVersion::CURRENT,
                maximum: eliot_protocol::ProtocolVersion::CURRENT,
            },
            module_id: module_id.as_str().to_owned(),
            module_generation,
            launch_nonce: daemon_launch.as_ref().map_or_else(
                || format!("kernel-{}", std::process::id()),
                |launch| launch.launch_nonce.as_str().to_owned(),
            ),
            // The regular daemon session and the dedicated Host
            // UserAutomation session share the authenticated front-door
            // policy, but the latter is admitted through its own binder and
            // can only project this exact capability.  Keeping the capability
            // in the server-owned policy prevents the special binder from
            // bypassing live policy while retaining the least-privilege
            // Submit-only check in `front_door_session`/`dreamer_job_dispatch`.
            allowed_capabilities: vec![
                "daemon".to_owned(),
                USER_AUTOMATION_KERNEL_CAPABILITY.to_owned(),
            ],
            allowed_privacy_classes: vec!["PUBLIC".to_owned()],
            allowed_effects: vec!["REVERSIBLE_MUTATION".to_owned()],
            session_principal_binding,
            control_channel: ipc.name().to_owned(),
            heartbeat_ms: 1_000,
            config_snapshot,
            max_frame: u32::try_from(eliot_protocol::MAX_FRAME_BYTES)
                .map_err(|_| KernelBuildError::Core("maximum frame exceeds u32".to_owned()))?,
        };
        let runtime = Runtime::new(
            RuntimeConfig {
                mailbox_capacity: 128,
                control_reserve: 4,
                concurrency: 4,
                control_concurrency_reserve: 1,
                fairness_quantum: 8,
                restart_budget: 3,
                restart_window: Duration::from_mins(1),
                restart_backoff: Duration::from_millis(100),
                shutdown_grace: Duration::from_secs(5),
            },
            None,
        )
        .map_err(KernelBuildError::Runtime)?;
        let generation_gateway = OrsGenerationCoordinator::new(ors.clone());
        let mut startup_coordinator = StartupCoordinator::new();
        let mut service = service;
        service
            .synchronize_authority_epoch(canonical_epoch)
            .map_err(|error| KernelBuildError::Service(error.to_string()))?;
        let mut policy = front_door_policy;
        generation_gateway
            .recover(&mut generations, &mut service, &mut policy)
            .map_err(|error| {
                observe_entrypoint_with_detail(
                    EntrypointStage::Composition,
                    "kernel.composition.generation_recovery_rejected",
                );
                KernelBuildError::Ors(error)
            })?;
        generation_gateway
            .recover_cutover_ownership()
            .map_err(|error| {
                observe_entrypoint_with_detail(
                    EntrypointStage::Composition,
                    "kernel.composition.cutover_ownership_recovery_rejected",
                );
                KernelBuildError::Ors(error)
            })?;
        startup_coordinator
            .record_live_evidence(3)
            .map_err(KernelBuildError::Service)?;
        observe_entrypoint_with_detail(
            EntrypointStage::Composition,
            "kernel.composition.generation_recovered",
        );
        #[cfg(windows)]
        let store_handoff_init = {
            let store_bootstrap_for_recovery = store_bootstrap.clone();
            let recovered = Self::recover_store_rebind_state(
                &ors,
                &mut service,
                store_bootstrap_for_recovery.as_ref(),
            )
            .map_err(|error| {
                observe_entrypoint_with_detail(
                    EntrypointStage::StoreBootstrap,
                    "kernel.composition.store_rebind_recovery_rejected",
                );
                KernelBuildError::Ors(error)
            })?;
            if recovered.is_some() {
                observe_entrypoint_with_detail(
                    EntrypointStage::StoreBootstrap,
                    "kernel.composition.store_rebind_recovered",
                );
            } else {
                observe_entrypoint_with_detail(
                    EntrypointStage::StoreBootstrap,
                    "kernel.composition.store_rebind_absent",
                );
            }
            recovered
        };
        #[cfg(not(windows))]
        let store_handoff_init = None;
        #[cfg(windows)]
        let agent_activation_results = Self::rehydrate_agent_activation_results(&ors)?;
        // Implements #1967: start the ordered I1.11 coordinator at step zero.
        // Composition construction alone does not prove Host-owned startup,
        // Blob manifest, Store readiness, reconciliation, handshake, mirror,
        // capability, front-door, or supervision evidence. Each later step is
        // advanced only by its owning live probe/publication boundary.
        observe_entrypoint_with_detail(
            EntrypointStage::Composition,
            "kernel.composition.startup_sequence_initiated:step=0",
        );
        let startup_coordinator = Mutex::new(startup_coordinator);
        // I1.11 step 4 (#1969): validate the approved Blob Store manifest at
        // startup without starting the blob generation. First demand
        // starts/probes it.
        let blob_store = match config.blob_manifest.clone() {
            None => {
                observe_entrypoint_with_detail(
                    EntrypointStage::StoreBootstrap,
                    "kernel.blob.manifest_absent:large_payload_degraded",
                );
                None
            }
            Some(manifest) => match BlobStoreController::new(manifest) {
                Ok(controller) => Some(controller),
                Err(error) => {
                    observe_entrypoint_with_detail(
                        EntrypointStage::StoreBootstrap,
                        "kernel.blob.manifest_rejected",
                    );
                    return Err(KernelBuildError::Service(error));
                }
            },
        };
        // I1.11 step 4 (#1969): an absent approved manifest degrades only
        // large-payload capture. Record it in the startup coordinator so the
        // step-9 status reports it; inline and unrelated canonical work are
        // unaffected. A rejected manifest fails construction above instead.
        if blob_store.is_none() {
            startup_coordinator
                .lock()
                .map_err(|_| {
                    KernelBuildError::Service("startup coordinator lock poisoned".to_owned())
                })?
                .note_blob_degraded();
        }
        // Issue #960: hold the Kernel-owned production restore adapter on
        // the composition. The adapter binds the work root only; the durable
        // journal is injected per execution by production composition (#962),
        // so no second database is opened here and unrelated Kernel work is
        // unaffected while no restore executes.
        let backup_restore = KernelBackupRestore::bind(work_root.clone());
        // Issue #962 (Writer-D): bind the exact-owner backup channel
        // clients in production assembly. Both constructors bind the
        // actual canonical pipes and fail closed on any fake or
        // mismatched binding, so a missing binding is never replaced by
        // a default. The marker records the injection for diagnostics;
        // no other composition behavior changes.
        HostBackupOwnerClient::production()
            .map_err(|error| KernelBuildError::Service(error.to_string()))?;
        WatchdogBackupOwnerClient::production()
            .map_err(|error| KernelBuildError::Service(error.to_string()))?;
        backup_owner_clients::mark_owner_clients_bound();
        // Issue #959: hold the Kernel-owned cross-owner backup capture
        // coordinator on the composition. It binds the work root only;
        // captures consume already-accepted owner evidence per execution,
        // so no live owner channel is opened here.
        let backup_capture = KernelBackupCapture::bind(work_root.clone());
        // F-LOG-KERNEL-2 (#899): constructed composition is not ready. The
        // service starts Cold, the daemon is NotLaunched, and no Store
        // gateway is claimed; readiness requires separate Host handoffs.
        observe_entrypoint_with_detail(
            EntrypointStage::Composition,
            "kernel.composition.constructed_not_ready",
        );
        observe_entrypoint(EntrypointStage::Composition);
        Ok(Self {
            p07_owner: Mutex::new(None),
            p07_owner_digest: Mutex::new(None),
            p07_ors: Arc::clone(&ors),
            store_rebind_boundary: KernelStoreRebindProductionBoundary,
            work_root,
            runtime,
            platform,
            ipc,
            generation_gateway,
            service: Arc::new(Mutex::new(service)),
            generations: Mutex::new(generations),
            generation_poison: Mutex::new(None),
            front_door_policy: Mutex::new(policy),
            process_gateway,
            store_bootstrap,
            daemon_active_launch: Mutex::new(daemon_launch.clone()),
            daemon_launch,
            eliotd_receipt_binding,
            kernel_artifact_sha256,
            eliotd_descriptor_artifact_sha256,
            wasm_host_executable_path,
            wasm_host_artifact_sha256,
            daemon_runtime: Mutex::new(DaemonRuntimeState {
                status: DaemonRuntimeStatus::NotLaunched,
                receipt: None,
                recovery_fenced: false,
                #[cfg(windows)]
                supervision: None,
                #[cfg(windows)]
                live_ready: None,
                #[cfg(windows)]
                supervision_progress: DaemonSupervisionProgressState::unbound(),
                #[cfg(windows)]
                last_progress_observation: None,
                #[cfg(windows)]
                supervision_expired: false,
            }),
            daemon_status_changed: tokio::sync::Notify::new(),
            #[cfg(windows)]
            daemon_recovery_gate: tokio::sync::Mutex::new(()),
            #[cfg(windows)]
            daemon_recovery_attempts: AtomicU64::new(0),
            #[cfg(windows)]
            store_handoff: Mutex::new(store_handoff_init),
            #[cfg(windows)]
            store_rebind_gate: tokio::sync::Mutex::new(()),
            approved_config_hash,
            canonical_store_claimed: AtomicBool::new(false),
            blob_store: Mutex::new(blob_store),
            backup_restore,
            backup_capture,
            #[cfg(windows)]
            canonical_store_gateway: Mutex::new(None),
            #[cfg(windows)]
            supervision_lease_authority: supervision_lease_authority.map(Arc::new),
            #[cfg(windows)]
            agent_bridge_profile: Mutex::new(None),
            #[cfg(windows)]
            agent_bridge_transition: std::sync::RwLock::new(()),
            #[cfg(windows)]
            agent_bridge_admission,
            #[cfg(windows)]
            agent_bridge_peer_set_revision: AtomicU64::new(0),
            #[cfg(windows)]
            agent_bridge_peer_set_changed: tokio::sync::Notify::new(),
            #[cfg(windows)]
            agent_bridge_connections: Mutex::new(BTreeMap::new()),
            #[cfg(windows)]
            agent_activation_pending: Mutex::new(AgentActivationPendingState::default()),
            #[cfg(windows)]
            agent_activation_changed: tokio::sync::Notify::new(),
            #[cfg(windows)]
            agent_activation_results: Mutex::new(agent_activation_results),
            #[cfg(windows)]
            host_request_connection_index: Mutex::new(BTreeMap::new()),
            #[cfg(windows)]
            local_read_claim_boot_nonce: {
                use std::collections::hash_map::DefaultHasher;
                use std::hash::{Hash, Hasher};
                // Boot-unique, not cryptographic: process identity plus wall
                // time plus a stack address distinguish every composition
                // incarnation, so attempt IDs never repeat across restarts.
                let stack_anchor = 0u8;
                let mut hasher = DefaultHasher::new();
                std::process::id().hash(&mut hasher);
                super::unix_ms().hash(&mut hasher);
                std::ptr::from_ref(&stack_anchor).hash(&mut hasher);
                let nonce = hasher.finish();
                // Zero is reserved as "no boot nonce"; remap without biasing.
                if nonce == 0 { 1 } else { nonce }
            },
            startup_coordinator,
        })
    }
}
