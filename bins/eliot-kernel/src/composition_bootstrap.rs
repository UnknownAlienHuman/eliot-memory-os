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
    AgentActivationPendingState, ArtifactId, AuthorityDescriptorContour, AuthorityEpoch,
    AuthorityHandoffBegin, AuthorityHandoffRecord, AuthorityHandoffState,
    AuthorityPreparationError, AuthoritySnapshotBinding, ContractId, DaemonRuntimeState,
    DaemonRuntimeStatus, DispatchAuthorityId, DispatchSnapshotCodec, GenerationRoute,
    GenerationRouter, HealthVector, IpcImplementation, KernelBuildError, KernelComposition,
    KernelConfig, KernelDispatchKey, KernelError, KernelPathAdmission, KernelService,
    KernelStoreRebindProductionBoundary, KernelSupervisionLeaseAuthority, ModuleGeneration,
    ModuleGenerationState, OperationalRecoveryStore, OrsError, OrsGenerationCoordinator,
    PROTOCOL_VERSION, PreparedAuthorityMaterial, ProcessAuthorityHandoffDescriptor,
    ProcessDispatchAuthorityController, ProcessExecutionAuthorityConfig, ProcessExecutionGateway,
    RedbRecoveryStore, RouteScope, Runtime, RuntimeConfig, SERVICE_NAME, ServerHandshakePolicy,
    StateFence, UserOwnedPathLease, UserOwnedRootLease, WindowsDispatchSnapshotCodec,
    WindowsPlatform, is_lower_sha256, sha256_hex, sha256_json, unix_ms,
};
#[cfg(test)]
use super::{CanonicalEvidenceProvider, DispatchValidationPort};
#[cfg(windows)]
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

impl KernelComposition {
    /// Builds all lower-layer surfaces once and binds them to one runtime.
    ///
    /// The default authority remains fail-closed until Host performs its
    /// authenticated handoff. Test-only adapter construction is available
    /// under the test configuration.
    pub fn new(config: KernelConfig) -> Result<Self, KernelBuildError> {
        let work_root = config.work_root.clone();
        let platform =
            Arc::new(WindowsPlatform::new(work_root.clone()).map_err(KernelBuildError::Platform)?);
        let ors_path = Self::ors_path_for_config(&config)?;
        let ors = Arc::new(
            RedbRecoveryStore::open(&ors_path)
                .map_err(|error| KernelBuildError::Ors(error.to_string()))?,
        );
        Self::assemble(config, ors, None, platform)
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
        let work_root = config.work_root.clone();
        let platform =
            Arc::new(WindowsPlatform::new(work_root.clone()).map_err(KernelBuildError::Platform)?);
        let ors_path = Self::ors_path_for_config(&config)?;
        let ors = Arc::new(
            RedbRecoveryStore::open(&ors_path)
                .map_err(|error| KernelBuildError::Ors(error.to_string()))?,
        );
        let prepared = Self::prepare_authority_descriptor_material(
            &platform,
            &ors,
            path,
            expected_sha256,
            contour,
        )
        .map_err(|error| KernelBuildError::Service(error.to_string()))?;
        #[cfg(windows)]
        if config.require_descriptor_supervision_authority {
            let descriptor_authority = SupervisionLeaseAuthorityConfig {
                authority: prepared.descriptor.supervision_authority.clone(),
            };
            match &config.supervision_lease_authority {
                Some(configured) if configured != &descriptor_authority => {
                    return Err(KernelBuildError::Service(
                        "configured supervision authority does not match the protected handoff descriptor"
                            .to_owned(),
                    ));
                }
                Some(_) => {}
                None => config.supervision_lease_authority = Some(descriptor_authority),
            }
        }
        let snapshot_binding = AuthoritySnapshotBinding::from_wire(
            prepared.descriptor.snapshot_binding.clone(),
            &prepared.descriptor.authority_id,
        )
        .map_err(|error| KernelBuildError::Core(error.to_string()))?;
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
        .map_err(|error| KernelBuildError::Core(error.to_string()))?;
        Self::consume_authority_handoff(&ors, &handoff)
            .map_err(|error| KernelBuildError::Service(error.to_string()))?;
        Self::assemble_with_process_controller(config, controller, snapshot_binding, ors, platform)
    }

    /// Builds a production composition with an externally supplied process
    /// authority key, opaque snapshot codec and durable replay binding.
    /// Missing bindings are never replaced by a default or in-memory issuer.
    pub fn new_with_process_authority(
        config: KernelConfig,
        authority_config: ProcessExecutionAuthorityConfig,
    ) -> Result<Self, KernelBuildError> {
        let work_root = config.work_root.clone();
        let platform =
            Arc::new(WindowsPlatform::new(work_root.clone()).map_err(KernelBuildError::Platform)?);
        let ors_path = Self::ors_path_for_config(&config)?;
        let ors = Arc::new(
            RedbRecoveryStore::open(&ors_path)
                .map_err(|error| KernelBuildError::Ors(error.to_string()))?,
        );
        Self::assemble_with_process_authority(config, authority_config, ors, platform)
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
        match handoff.state {
            AuthorityHandoffState::Consumed => ProcessDispatchAuthorityController::restore(
                authority_id,
                key,
                store,
                codec,
                binding,
            )
            .map(|controller| Arc::new(Mutex::new(controller))),
            AuthorityHandoffState::Reserved => {
                if ProcessDispatchAuthorityController::exact_snapshot_present(
                    &authority_id,
                    store.as_ref(),
                    binding,
                )? {
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
                    return Err(KernelError::RecoveryUnavailable(
                        "fresh authority admission interval is not active".to_owned(),
                    ));
                }
                ProcessDispatchAuthorityController::activate_and_persist_initial(
                    authority_id,
                    key,
                    store,
                    codec,
                    binding,
                )
                .map(|controller| Arc::new(Mutex::new(controller)))
            }
            AuthorityHandoffState::Unknown => Err(KernelError::RecoveryUnavailable(
                "authority handoff outcome is unknown and requires reconciliation".to_owned(),
            )),
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
        let now = i64::try_from(unix_ms()).unwrap_or(i64::MAX);
        let consumed = AuthorityHandoffRecord {
            state: AuthorityHandoffState::Consumed,
            consumed_at_ms: Some(now),
            ..handoff.clone()
        };
        if ors.persist_authority_handoff(&consumed).is_ok() {
            return Ok(());
        }
        let observed = ors
            .load_authority_handoff(&consumed.handoff_id)
            .map_err(|_| AuthorityPreparationError::PersistenceUnknown)?
            .ok_or(AuthorityPreparationError::PersistenceUnknown)?;
        if observed.state == AuthorityHandoffState::Consumed
            && Self::same_authority_handoff_identity(&observed, &consumed)
        {
            return Ok(());
        }
        if observed.state == AuthorityHandoffState::Unknown {
            return Err(AuthorityPreparationError::Replay);
        }
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

    fn prepare_authority_descriptor_material(
        platform: &WindowsPlatform,
        ors: &RedbRecoveryStore,
        path: &Path,
        expected_sha256: &str,
        contour: AuthorityDescriptorContour,
    ) -> Result<PreparedAuthorityMaterial, AuthorityPreparationError> {
        if !is_lower_sha256(expected_sha256) {
            return Err(AuthorityPreparationError::DigestMismatch);
        }
        let bytes = match contour {
            AuthorityDescriptorContour::PortableCurrentUser { root } => {
                let root_lease = UserOwnedRootLease::open_existing(&root)
                    .map_err(|_| AuthorityPreparationError::ProtectedInput)?;
                let file_lease = UserOwnedPathLease::open_existing(&root_lease, path)
                    .map_err(|_| AuthorityPreparationError::ProtectedInput)?;
                file_lease
                    .verify_stable_identity()
                    .and_then(|()| file_lease.verify_path_identity())
                    .map_err(|_| AuthorityPreparationError::ProtectedInput)?;
                file_lease
                    .read_bounded(1024 * 1024)
                    .map_err(|_| AuthorityPreparationError::ProtectedInput)?
            }
            AuthorityDescriptorContour::ProgramData => {
                let file_lease = ProtectedPathLease::open_existing_absolute(path)
                    .map_err(|_| AuthorityPreparationError::ProtectedInput)?;
                file_lease
                    .verify_stable_identity()
                    .and_then(|()| file_lease.verify_path_identity())
                    .map_err(|_| AuthorityPreparationError::ProtectedInput)?;
                file_lease
                    .read_bounded(1024 * 1024)
                    .map_err(|_| AuthorityPreparationError::ProtectedInput)?
            }
        };
        if sha256_hex(&bytes) != expected_sha256 {
            return Err(AuthorityPreparationError::DigestMismatch);
        }
        let descriptor: ProcessAuthorityHandoffDescriptor = serde_json::from_slice(&bytes)
            .map_err(|_| AuthorityPreparationError::DescriptorInvalid)?;
        descriptor
            .validate_structure()
            .map_err(|_| AuthorityPreparationError::DescriptorInvalid)?;
        let candidate = Self::authority_handoff_candidate(&descriptor)?;

        // Inspect the immutable handoff identity before touching Credential
        // Manager. An exact existing handoff is replay evidence and may be
        // recovered after its admission interval; only an absent handoff is
        // required to be fresh before the credential boundary is crossed.
        let existing = ors
            .load_authority_handoff(&candidate.handoff_id)
            .map_err(|_| AuthorityPreparationError::PersistenceUnknown)?;
        if let Some(existing) = &existing {
            if !Self::same_authority_handoff_identity(existing, &candidate) {
                return Err(AuthorityPreparationError::Replay);
            }
        } else {
            let now = i64::try_from(unix_ms()).unwrap_or(i64::MAX);
            if !Self::authority_descriptor_is_fresh(&descriptor, now) {
                return Err(AuthorityPreparationError::DescriptorNotFresh);
            }
        }

        let secret = platform
            .read_credential(descriptor.dispatch_key.key.as_str())
            .map_err(|_| AuthorityPreparationError::CredentialUnavailable)?;
        if secret.expose().len() != 32 || secret.expose().iter().all(|byte| *byte == 0) {
            return Err(AuthorityPreparationError::CredentialInvalid);
        }
        let mut key_bytes = [0_u8; 32];
        key_bytes.copy_from_slice(secret.expose());
        let key = KernelDispatchKey::from_secret_bytes(key_bytes)
            .map_err(|_| AuthorityPreparationError::CredentialInvalid)?;

        let outcome = match ors.begin_authority_handoff_fresh(&candidate) {
            Ok(outcome) => outcome,
            Err(OrsError::AuthorityHandoffNotFresh) => {
                return Err(AuthorityPreparationError::DescriptorNotFresh);
            }
            Err(_) => return Err(AuthorityPreparationError::PersistenceUnknown),
        };
        let handoff = match outcome {
            AuthorityHandoffBegin::Acquired => candidate,
            AuthorityHandoffBegin::Existing(existing) => match existing.state {
                AuthorityHandoffState::Reserved | AuthorityHandoffState::Consumed => existing,
                AuthorityHandoffState::Unknown => return Err(AuthorityPreparationError::Replay),
            },
        };
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
            authority_epoch: descriptor.state_fence.authority_epoch.value(),
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
        let work_root = config.work_root.clone();
        let store_bootstrap = config.store_bootstrap.clone();
        let daemon_launch = config.daemon_launch.clone();
        let kernel_artifact_sha256 = config.kernel_artifact_sha256.clone();
        let eliotd_descriptor_artifact_sha256 = config.eliotd_descriptor_artifact_sha256.clone();
        let eliotd_receipt_binding = config.eliotd_receipt_binding.clone();
        if let Some(binding) = &eliotd_receipt_binding {
            binding.validate().map_err(KernelBuildError::Service)?;
        }
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
        let (authority_epoch, generation) = store_bootstrap.as_ref().map_or(
            (AuthorityEpoch::genesis(), ResourceGeneration::genesis()),
            |requirement| {
                (
                    requirement.state_fence.authority_epoch,
                    requirement.state_fence.resource_generation,
                )
            },
        );
        let mut generations = GenerationRouter::at_epoch(authority_epoch)
            .map_err(|error| KernelBuildError::Core(error.to_string()))?;
        generations
            .register(
                GenerationRoute::new(
                    RouteScope::new("daemon")
                        .map_err(|error| KernelBuildError::Core(error.to_string()))?,
                    generation,
                    authority_epoch,
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
                    authority_epoch,
                )
                .map_err(|error| KernelBuildError::Core(error.to_string()))?,
            )
            .map_err(|error| KernelBuildError::Core(error.to_string()))?;
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
            state_fence: StateFence::new(authority_epoch, generation),
        };
        #[cfg(windows)]
        let session_principal_binding = observed_session_principal_binding()?;
        #[cfg(not(windows))]
        let session_principal_binding = "unsupported-non-windows-principal".to_owned();
        let mut config_snapshot = serde_json::json!({
            "service": SERVICE_NAME,
            "protocol": PROTOCOL_VERSION,
            "generation": generation.value(),
            "authority_epoch": authority_epoch.value(),
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
            allowed_capabilities: vec!["daemon".to_owned()],
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
        let mut service = service;
        service
            .synchronize_authority_epoch(authority_epoch)
            .map_err(|error| KernelBuildError::Service(error.to_string()))?;
        let mut policy = front_door_policy;
        generation_gateway
            .recover(&mut generations, &mut service, &mut policy)
            .map_err(KernelBuildError::Ors)?;
        #[cfg(windows)]
        let store_handoff_init = {
            let store_bootstrap_for_recovery = store_bootstrap.clone();
            Self::recover_store_rebind_state(
                &ors,
                &mut service,
                store_bootstrap_for_recovery.as_ref(),
            )
            .map_err(KernelBuildError::Ors)?
        };
        #[cfg(not(windows))]
        let store_handoff_init = None;
        Ok(Self {
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
            daemon_runtime: Mutex::new(DaemonRuntimeState {
                status: DaemonRuntimeStatus::NotLaunched,
                receipt: None,
                recovery_fenced: false,
                #[cfg(windows)]
                supervision: None,
                #[cfg(windows)]
                live_ready: None,
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
            #[cfg(windows)]
            canonical_store_gateway: Mutex::new(None),
            #[cfg(windows)]
            supervision_lease_authority: supervision_lease_authority.map(Arc::new),
            #[cfg(windows)]
            agent_bridge_profile: Mutex::new(None),
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
        })
    }
}
