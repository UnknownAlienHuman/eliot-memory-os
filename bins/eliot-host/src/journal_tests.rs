use super::*;
use eliot_host_state::{
    BackendError, BackendReconcileState, DurableImage, FaultPoint, MemoryBackend, PreparedAppend,
};
#[cfg(windows)]
use eliot_installation::{InstallationEpoch, RuntimeStateRoots};

#[cfg(windows)]
fn test_supervision_incarnation(
    installation_id: &str,
    activation_id: &str,
    host_lineage: &str,
    kernel_lineage: &str,
) -> SupervisionLeaseIncarnationBinding {
    SupervisionLeaseIncarnationBinding {
        supervision_lease_scope_id: "eliot-supervision-scope:v1:test".to_owned(),
        supervision_lease_id: String::new(),
        scope_ref_digest: String::new(),
        installation_id: installation_id.to_owned(),
        host_epoch: SupervisionJournalEpoch {
            lineage_id: host_lineage.to_owned(),
            sequence: 1,
        },
        activation_id: activation_id.to_owned(),
        activation_generation: SupervisionJournalEpoch {
            lineage_id: "activation-lineage-1".to_owned(),
            sequence: 1,
        },
        kernel_generation: SupervisionJournalEpoch {
            lineage_id: kernel_lineage.to_owned(),
            sequence: 1,
        },
        watchdog_epoch: SupervisionJournalEpoch {
            lineage_id: "watchdog-lineage-1".to_owned(),
            sequence: 1,
        },
        observation_scope: eliot_runtime_contracts::canonical_observation_scope(),
        wake_policy: eliot_runtime_contracts::canonical_wake_policy(),
        predecessor: None,
    }
    .with_derived_ids()
    .unwrap_or_else(|_| unreachable!())
}

struct ImageBackend {
    image: DurableImage,
}

struct UnknownAppendBackend {
    image: DurableImage,
    prepared: Option<PreparedAppend>,
}

impl JournalBackend for UnknownAppendBackend {
    fn load(&mut self) -> Result<DurableImage, BackendError> {
        Ok(self.image.clone())
    }

    fn prepared_appends(&mut self) -> Result<Vec<PreparedAppend>, BackendError> {
        Ok(self.prepared.clone().into_iter().collect())
    }

    fn prepare(&mut self, append: &PreparedAppend) -> Result<(), BackendError> {
        self.prepared = Some(append.clone());
        Ok(())
    }

    fn append_prepared(
        &mut self,
        _transaction_id: &PlatformHandle,
        _bytes: &[u8],
    ) -> Result<(), BackendError> {
        Ok(())
    }

    fn flush(&mut self, _transaction_id: &PlatformHandle) -> Result<(), BackendError> {
        Ok(())
    }

    fn sync(&mut self, _transaction_id: &PlatformHandle) -> Result<(), BackendError> {
        Ok(())
    }

    fn commit(&mut self, _transaction_id: &PlatformHandle) -> Result<(), BackendError> {
        Err(BackendError::Unknown(
            eliot_platform::UnknownReason::Indeterminate,
        ))
    }

    fn reconcile(
        &mut self,
        _transaction_id: &PlatformHandle,
    ) -> Result<BackendReconcileState, BackendError> {
        Ok(if self.prepared.is_some() {
            BackendReconcileState::Prepared
        } else {
            BackendReconcileState::Absent
        })
    }
}

impl JournalBackend for ImageBackend {
    fn load(&mut self) -> Result<DurableImage, BackendError> {
        Ok(self.image.clone())
    }

    fn prepared_appends(&mut self) -> Result<Vec<PreparedAppend>, BackendError> {
        Ok(Vec::new())
    }

    fn prepare(&mut self, _append: &PreparedAppend) -> Result<(), BackendError> {
        Err(BackendError::Unavailable)
    }

    fn append_prepared(
        &mut self,
        _transaction_id: &PlatformHandle,
        _bytes: &[u8],
    ) -> Result<(), BackendError> {
        Err(BackendError::Unavailable)
    }

    fn flush(&mut self, _transaction_id: &PlatformHandle) -> Result<(), BackendError> {
        Err(BackendError::Unavailable)
    }

    fn sync(&mut self, _transaction_id: &PlatformHandle) -> Result<(), BackendError> {
        Err(BackendError::Unavailable)
    }

    fn commit(&mut self, _transaction_id: &PlatformHandle) -> Result<(), BackendError> {
        Err(BackendError::Unavailable)
    }

    fn reconcile(
        &mut self,
        _transaction_id: &PlatformHandle,
    ) -> Result<BackendReconcileState, BackendError> {
        Ok(BackendReconcileState::Absent)
    }
}

fn test_host() -> HostInstallationEpoch {
    fresh_host_epoch(
        PlatformHandle::new("test-installation").unwrap_or_else(|_| unreachable!()),
        None,
    )
    .unwrap_or_else(|_| unreachable!())
}

#[test]
fn production_termination_binding_rejects_root_and_authority_substitution() -> TestResult {
    let job = KernelJobBinding {
        job_name: PlatformHandle::new("eliot-kernel-job")?,
        owner: PlatformHandle::new("Kernel")?,
        root_pid: 42,
        root_start_time_100ns: 10,
        root_image_path: PlatformHandle::new("C:\\eliot\\eliot-kernel.exe")?,
        root_volume_serial_number: 7,
        root_file_index: 11,
    };
    let process = ServiceProcessRecord {
        process_id: "pid:42:start:10".to_owned(),
        owner: "Kernel".to_owned(),
        state: ServiceProcessState::Starting,
        health: HealthVector::healthy(),
        authority_epoch: AuthorityEpoch::new(7)?,
    };
    let matches = |process_id, start_time, image, job_name, expected| {
        exact_termination_binding_matches(&job, expected, process_id, start_time, image, job_name)
    };
    assert!(matches(
        42,
        10,
        "C:\\eliot\\eliot-kernel.exe",
        "eliot-kernel-job",
        &process,
    ));
    assert!(!matches(
        43,
        10,
        "C:\\eliot\\eliot-kernel.exe",
        "eliot-kernel-job",
        &process,
    ));
    assert!(!matches(
        42,
        11,
        "C:\\eliot\\eliot-kernel.exe",
        "eliot-kernel-job",
        &process,
    ));
    assert!(!matches(
        42,
        10,
        "C:\\eliot\\substituted.exe",
        "eliot-kernel-job",
        &process,
    ));
    assert!(!matches(
        42,
        10,
        "C:\\eliot\\eliot-kernel.exe",
        "substituted-job",
        &process,
    ));

    let mut substituted_authority = process.clone();
    substituted_authority.owner = "Store".to_owned();
    assert!(!matches(
        42,
        10,
        "C:\\eliot\\eliot-kernel.exe",
        "eliot-kernel-job",
        &substituted_authority,
    ));
    let mut substituted_process_id = process.clone();
    substituted_process_id.process_id = "pid:99:start:10".to_owned();
    assert!(!matches(
        42,
        10,
        "C:\\eliot\\eliot-kernel.exe",
        "eliot-kernel-job",
        &substituted_process_id,
    ));
    Ok(())
}

#[test]
fn runtime_control_unknown_ref_preserves_request_identity_across_reopen() -> TestResult {
    let request = HostRuntimeControlRequest::new(
        HostRuntimeControlOperation::RestartKernel,
        PlatformHandle::new("reopen-request-17")?,
    )?;
    let pending_ref = runtime_control_unknown_ref("kernel-restart-reconcile", &request);
    assert!(pending_ref.as_str().contains("RestartKernel"));
    assert!(pending_ref.as_str().contains(request.request_id.as_str()));
    assert!(
        pending_ref
            .as_str()
            .contains(request.request_digest.as_str())
    );
    let error_digest = sha256_json(&"injected-failure")?;
    assert!(!pending_ref.as_str().contains(&error_digest));
    Ok(())
}

#[test]
fn store_termination_evidence_requires_complete_single_attempt() -> TestResult {
    let request = HostRuntimeControlRequest::new(
        HostRuntimeControlOperation::RecoverStore,
        PlatformHandle::new("termination-evidence-request")?,
    )?;
    let mut evidence = StoreRecoveryTerminationEvidence {
        wire: "eliot.host.runtime-control.v2".to_owned(),
        operation: HostRuntimeControlOperation::RecoverStore,
        request_id: request.request_id.as_str().to_owned(),
        mutation_digest: request.mutation_digest.as_str().to_owned(),
        request_digest: request.request_digest.as_str().to_owned(),
        host_epoch: 1,
        host_lineage: "termination-lineage".to_owned(),
        process_id: 42,
        process_start_time_100ns: 7,
        process_image_path: r"C:\eliot\store.exe".to_owned(),
        job_name: r"Local\Eliot-Store".to_owned(),
        job_empty: true,
        root_reaped: true,
        restart_attempt: 1,
    };
    assert!(
        evidence
            .validate_for_digest(request.mutation_digest.as_str())
            .is_ok()
    );
    evidence.job_empty = false;
    assert!(
        evidence
            .validate_for_digest(request.mutation_digest.as_str())
            .is_err()
    );
    evidence.job_empty = true;
    evidence.root_reaped = false;
    assert!(
        evidence
            .validate_for_digest(request.mutation_digest.as_str())
            .is_err()
    );
    evidence.root_reaped = true;
    evidence.restart_attempt = 2;
    assert!(
        evidence
            .validate_for_digest(request.mutation_digest.as_str())
            .is_err()
    );
    Ok(())
}

#[cfg(windows)]
struct ReadinessFixture {
    journal: HostStateJournalService<MemoryBackend>,
    candidate: HostKernelCandidateBinding,
    activation: KernelActivationReceipt,
    requirement: HostStoreBootstrapRequirement,
    kernel_artifact: PlatformHandle,
    store_artifact: PlatformHandle,
    config: PlatformHandle,
}

#[cfg(windows)]
#[allow(
    clippy::too_many_lines,
    reason = "the fixture establishes one complete durable activation contour for Host-level request/response/journal tests"
)]
fn active_readiness_fixture() -> Result<ReadinessFixture, TestError> {
    let host = test_host();
    let activation_generation = root_epoch(fresh_identity("readiness-activation-lineage")?);
    let activation_id = fresh_identity("readiness-activation")?;
    let journal = HostStateJournalService::from_backend(MemoryBackend::default(), host.clone())?;
    append_reconciled(
        &journal,
        HostStateRecord::Activation(initial_activation_record(
            &host,
            &activation_id,
            &activation_generation,
            ActivationState::Starting,
            "readiness-starting",
        )?),
    )?;
    let kernel_artifact = PlatformHandle::new("a".repeat(64))?;
    let store_artifact = PlatformHandle::new("b".repeat(64))?;
    let config = PlatformHandle::new("c".repeat(64))?;
    let job_name = PlatformHandle::new("Local\\Eliot-Host-Kernel-readiness")?;
    let image = "C:\\eliot\\eliot-kernel.exe".to_owned();
    let candidate = HostKernelCandidateBinding {
        installation_id: host.installation.clone(),
        host_epoch: AuthorityEpoch::new(host.epoch.current.sequence)?,
        kernel_epoch: AuthorityEpoch::new(2)?,
        activation_id: activation_id.clone(),
        artifact_hash: kernel_artifact.clone(),
        config_hash: config.clone(),
        job_object_id: job_name.clone(),
        pipe_identity: PlatformHandle::new(KERNEL_CONTROL_PIPE)?,
        host_process: HostProcessBinding {
            process_id: 7,
            start_time_100ns: 9,
            image_path: "C:\\eliot\\eliot-host.exe".to_owned(),
        },
        job_binding: HostJobBinding {
            job: eliot_kernel_service::HostJobIdentity {
                name: job_name.as_str().to_owned(),
            },
            root: eliot_kernel_service::HostJobRoot {
                process: HostProcessBinding {
                    process_id: 42,
                    start_time_100ns: 10,
                    image_path: image.clone(),
                },
                executable: eliot_kernel_service::HostFileIdentity {
                    volume_serial_number: 1,
                    file_index: 2,
                },
            },
        },
        supervision_incarnation: test_supervision_incarnation(
            host.installation.as_str(),
            activation_id.as_str(),
            host.epoch.current.lineage.as_str(),
            "readiness-kernel-lineage",
        ),
        restart_budget: RestartBudget::new(1, 1)?,
        agent_bridge_admission: None,
        containment_action: None,
    };
    let durable_job = KernelJobBinding {
        job_name,
        owner: PlatformHandle::new("Kernel")?,
        root_pid: 42,
        root_start_time_100ns: 10,
        root_image_path: PlatformHandle::new(image)?,
        root_volume_serial_number: 1,
        root_file_index: 2,
    };
    let mut driver = DurableKernelActivationDriver::bind_candidate(
        &journal,
        &host,
        &activation_id,
        &activation_generation,
        kernel_artifact.clone(),
        candidate.pipe_identity.clone(),
        durable_job,
        PriorKernelDisposition::NoPriorKernel,
        root_epoch(fresh_identity("readiness-kernel-lineage")?),
        ServiceProcessRecord {
            process_id: "pid:42:start:10".to_owned(),
            owner: "Kernel".to_owned(),
            state: ServiceProcessState::Starting,
            health: HealthVector::healthy(),
            authority_epoch: candidate.kernel_epoch,
        },
    )?;
    driver.handoff_prepared()?;
    driver.prior_disposition_committed()?;
    let permit = driver.issue_nonce(&candidate, ResourceGeneration::genesis())?;
    driver.activating()?;
    let activation = KernelActivationReceipt::issue(&permit);
    let initial_ready = KernelReadyReceipt {
        activation_id: activation_id.clone(),
        activation_operation_id: activation.operation_id.clone(),
        activation_nonce_digest: activation.activation_nonce_digest.clone(),
        process: eliot_kernel_service::ProcessObservation {
            process_id: PlatformHandle::new("pid:42:start:10")?,
            job_object_id: candidate.job_object_id.clone(),
            state: ServiceProcessState::Ready,
            health: HealthVector::healthy(),
            evidence_refs: vec![PlatformHandle::new("initial-process-proof")?],
        },
        health: HealthVector::healthy(),
        evidence_refs: vec![PlatformHandle::new("initial-ready-proof")?],
    };
    driver.active(&candidate, &activation, &initial_ready)?;
    drop(driver);
    let requirement = HostStoreBootstrapRequirement {
        route_identity: PlatformHandle::new(eliot_kernel_service::STORE_ROUTE_IDENTITY)?,
        canonical_pipe_identity: PlatformHandle::new(r"\\.\pipe\eliot\store-readiness")?,
        store_generation: ResourceGeneration::genesis(),
        state_fence: StateFence::new(candidate.kernel_epoch, ResourceGeneration::genesis()),
        launch_nonce: PlatformHandle::new("store-launch-nonce")?,
        connection_id: PlatformHandle::new("store-connection")?,
        expected_peer_sid: PlatformHandle::new("S-1-5-18")?,
        expected_peer_session_id: 0,
        approved_artifact_hash: store_artifact.clone(),
        approved_config_hash: config.clone(),
        timeout_ms: 5_000,
    };
    Ok(ReadinessFixture {
        journal,
        candidate,
        activation,
        requirement,
        kernel_artifact,
        store_artifact,
        config,
    })
}

#[cfg(windows)]
#[allow(
    clippy::too_many_lines,
    reason = "the fixture constructs one complete signed ORS supervision snapshot for production-bound readiness tests"
)]
fn readiness_supervision_snapshot(
    fixture: &ReadinessFixture,
) -> Result<eliot_ors::SupervisionLeaseSnapshot, TestError> {
    use eliot_runtime_contracts::{SupervisionLeaseSigner as _, SupervisionLeaseVerifier as _};

    let now_ms = u64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis())?;
    let issued_at_ms = now_ms.saturating_sub(1_000);
    let binding = eliot_ors::SupervisionLeaseBinding {
        scope_ref: eliot_ors::OperationIdentity::new("scope-readiness")?,
        observation_scope: eliot_runtime_contracts::SupervisionObservationScope {
            targets: vec!["kernel-readiness".to_owned()],
            sensor_profile: "kernel-heartbeat".to_owned(),
            claimed_coverage: vec!["process".to_owned(), "job".to_owned()],
            governance_axis: "runtime-live".to_owned(),
        },
        installation_id: eliot_ors::OperationIdentity::new(
            fixture.candidate.installation_id.as_str(),
        )?,
        host_epoch: fixture.candidate.host_epoch,
        activation_id: eliot_ors::OperationIdentity::new(fixture.candidate.activation_id.as_str())?,
        activation_generation: fixture.activation.generation,
        kernel_epoch: fixture.candidate.kernel_epoch,
        watchdog_epoch: AuthorityEpoch::new(1)?,
        generation_binding: eliot_runtime_contracts::SupervisionGenerationBinding {
            target_id: "kernel-readiness".to_owned(),
            target_generation: fixture.activation.generation,
            module_id: "eliot-kernel".to_owned(),
            module_generation: fixture.activation.generation,
            process_id: "pid:42:start:10".to_owned(),
            process_generation: fixture.activation.generation,
        },
        state_fence: StateFence::new(
            fixture.candidate.kernel_epoch,
            fixture.activation.generation,
        ),
        issued_at_ms,
        expires_at_ms: now_ms.saturating_add(60_000),
        renew_before_ms: now_ms.saturating_add(30_000),
        wake_policy: eliot_runtime_contracts::RegisteredActivityWakePolicy::Disabled,
        state: eliot_runtime_contracts::LeaseState::Active,
        terminal_disposition: None,
        revocation_reason: None,
        revocation_id: None,
        revocation_epoch: None,
    };
    let request = eliot_ors::SupervisionLeasePrepareRequest {
        ticket_id: eliot_ors::OperationIdentity::new(format!(
            "readiness-ticket-{}",
            Uuid::new_v4().simple()
        ))?,
        operation_id: eliot_ors::OperationIdentity::new(format!(
            "readiness-operation-{}",
            Uuid::new_v4().simple()
        ))?,
        lease_id: eliot_ors::OperationIdentity::new("readiness-supervision-lease")?,
        expected_revision: None,
        operation: eliot_ors::SupervisionLeaseOperation::Commit,
        binding,
    };
    let path = std::env::temp_dir().join(format!(
        "eliot-host-readiness-supervision-{}-{}.redb",
        std::process::id(),
        Uuid::new_v4().simple()
    ));
    let store = eliot_ors::RedbRecoveryStore::open(&path)?;
    let stage = store.prepare_supervision_lease(request)?;
    let signer = eliot_runtime_contracts::Ed25519SupervisionLeaseSigner::from_secret_key(
        "readiness-kernel",
        "readiness-key",
        [7; 32],
    )?;
    let envelope = stage.ticket.expected_payload()?.sign(&signer)?;
    let anchor = eliot_runtime_contracts::SupervisionTrustAnchor::new(
        envelope.payload.installation_id.clone(),
        signer.signer_id(),
        signer.key_id(),
        signer.public_key().to_vec(),
    )?;
    let generation = &envelope.payload.generation_binding;
    let context = eliot_runtime_contracts::SupervisionLeaseVerificationContext {
        now_ms,
        lease_id: envelope.payload.lease_id.clone(),
        host_epoch: envelope.payload.host_epoch,
        activation_id: envelope.payload.activation_id.clone(),
        activation_generation: envelope.payload.activation_generation,
        kernel_epoch: envelope.payload.kernel_epoch,
        watchdog_epoch: envelope.payload.watchdog_epoch,
        state_fence: envelope.payload.state_fence.clone(),
        scope_ref: envelope.payload.scope_ref.clone(),
        observation_scope: envelope.payload.observation_scope.clone(),
        target_id: generation.target_id.clone(),
        module_id: generation.module_id.clone(),
        process_id: generation.process_id.clone(),
        target_generation: generation.target_generation,
        module_generation: generation.module_generation,
        process_generation: generation.process_generation,
        public_key_fingerprint: anchor.public_key_fingerprint().to_owned(),
        ors_mirror: envelope.payload.ors_mirror.clone(),
        active_state: eliot_runtime_contracts::SupervisionLeaseActiveStateBinding {
            state: envelope.payload.state,
            revocation_id: envelope.payload.revocation_id.clone(),
            revocation_epoch: envelope.payload.revocation_epoch,
        },
    };
    let verified = anchor.verify(&envelope, &context)?;
    let snapshot = store.commit_supervision_lease(&stage.ticket, &verified)?;
    drop(store);
    let _ = std::fs::remove_file(path);
    Ok(snapshot)
}

#[cfg(windows)]
fn probe_exchange(
    fixture: &ReadinessFixture,
    validation_revision: u64,
) -> Result<
    (
        KernelControlRequest,
        KernelControlResponse,
        KernelReadyReceipt,
    ),
    TestError,
> {
    let request = KernelControlRequest {
        wire_id: eliot_kernel_service::KERNEL_CONTROL_WIRE_ID.to_owned(),
        wire_version: eliot_kernel_service::KERNEL_CONTROL_WIRE_VERSION,
        message_id: fresh_identity("test-kernel-probe")?,
        sequence: 1,
        peer_process_id: 7,
        generation: ResourceGeneration::genesis(),
        candidate: fixture.candidate.clone(),
        command: KernelControlCommand::ProbeReady,
        payload_digest: String::new(),
    }
    .with_computed_digest()?;
    let mut evidence_refs = KernelReadyReceipt::probe_binding_evidence(&request)?;
    evidence_refs.extend([
        PlatformHandle::new(format!("kernel-store-validation:{validation_revision}"))?,
        PlatformHandle::new("kernel-store-health:manifest-ready")?,
    ]);
    let ready = KernelReadyReceipt {
        activation_id: fixture.candidate.activation_id.clone(),
        activation_operation_id: fixture.activation.operation_id.clone(),
        activation_nonce_digest: fixture.activation.activation_nonce_digest.clone(),
        process: eliot_kernel_service::ProcessObservation {
            process_id: PlatformHandle::new("pid:42:start:10")?,
            job_object_id: fixture.candidate.job_object_id.clone(),
            state: ServiceProcessState::Ready,
            health: HealthVector::healthy(),
            evidence_refs: vec![PlatformHandle::new("repeat-process-proof")?],
        },
        health: HealthVector::healthy(),
        evidence_refs,
    };
    let supervision_lease = readiness_supervision_snapshot(fixture)?;
    let response = KernelControlResponse {
        wire_id: eliot_kernel_service::KERNEL_CONTROL_WIRE_ID.to_owned(),
        wire_version: eliot_kernel_service::KERNEL_CONTROL_WIRE_VERSION,
        message_id: request.message_id.clone(),
        request_digest: request.payload_digest.clone(),
        state: KernelServiceState::Ready,
        receipt: Some(ready.clone()),
        activation_receipt: None,
        store_rebind_receipt: None,
        supervision_lease: Some(supervision_lease),
        error: None,
        payload_digest: String::new(),
    }
    .with_computed_digest()?;
    Ok((request, response, ready))
}

#[cfg(windows)]
fn authenticated_proof(
    fixture: &ReadinessFixture,
    validation_revision: u64,
) -> Result<AuthenticatedKernelReadiness, TestError> {
    let (request, response, _ready) = probe_exchange(fixture, validation_revision)?;
    let ready = validate_probe_response(&request, &fixture.activation, &response)?;
    let supervision_lease = response
        .supervision_lease
        .clone()
        .ok_or_else(|| std::io::Error::other("test option invariant"))?;
    let store_fence = validated_store_proof_fence(
        &fixture.requirement,
        &ready,
        &fixture.store_artifact,
        &fixture.config,
        request.generation,
    )?;
    Ok(AuthenticatedKernelReadiness {
        request,
        response,
        ready,
        supervision_lease,
        store_fence,
        peer_evidence: PlatformHandle::new("kernel-peer:test-authenticated")?,
    })
}

#[cfg(windows)]
fn test_published_supervision_identity() -> Result<PublishedSupervisionIdentity, TestError> {
    Ok(PublishedSupervisionIdentity {
        lease_id: PlatformHandle::new("supervision-lease:test-readiness")?,
        ors_receipt_digest: PlatformHandle::new("a".repeat(64))?,
        publication_digest: PlatformHandle::new("b".repeat(64))?,
    })
}

#[cfg(windows)]
fn readiness_contour(fixture: &ReadinessFixture) -> Result<ReadinessContourIdentity, TestError> {
    let state = fixture.journal.snapshot()?;
    let active = state
        .kernel
        .ok_or_else(|| std::io::Error::other("test option invariant"))?;
    let active_kernel_record_checksum =
        PlatformHandle::new(record_checksum(&HostStateRecord::Kernel(active))?)?;
    let supervision = test_published_supervision_identity()?;
    let store_proof_fence = match state.readiness_observations.last() {
        Some(observation)
            if observation.active_kernel_record_checksum == active_kernel_record_checksum
                && supervision.is_bound_by(&observation.evidence_refs)? =>
        {
            Some(observation.store_fence.clone())
        }
        _ => None,
    };
    Ok(ReadinessContourIdentity {
        approved_generation: PlatformHandle::new("approved-generation")?,
        approved_kernel_artifact: fixture.kernel_artifact.clone(),
        approved_store_artifact: fixture.store_artifact.clone(),
        approved_config: fixture.config.clone(),
        active_kernel_record_checksum,
        candidate_binding_digest: PlatformHandle::new(fixture.candidate.compute_digest()?)?,
        store_requirement_digest: PlatformHandle::new(sha256_json(&fixture.requirement)?)?,
        store_proof_fence,
        supervision_lease_id: Some(supervision.lease_id),
        supervision_ors_receipt_digest: Some(supervision.ors_receipt_digest),
        watchdog_publication_digest: Some(supervision.publication_digest),
    })
}

#[cfg(windows)]
#[allow(
    clippy::too_many_lines,
    reason = "the fixture constructs one fully validated split Store launch descriptor for the production liveness boundary"
)]
pub(super) fn liveness_manifest_with_distinct_store_digests()
-> Result<(CandidateManifest, std::path::PathBuf), TestError> {
    fn handle(value: impl Into<String>) -> PlatformHandle {
        PlatformHandle::new(value.into()).unwrap_or_else(|_| unreachable!())
    }

    fn path(root: &Path, name: &str) -> PlatformHandle {
        handle(root.join(name).to_string_lossy().into_owned())
    }

    let root = std::env::temp_dir().join(format!(
        "eliot-host-liveness-store-split-{}",
        Uuid::new_v4()
    ));
    let portable = root.join("portable");
    std::fs::create_dir_all(&portable).unwrap_or_else(|_| unreachable!());
    drop(UserOwnedRootLease::open_existing(&portable)?);
    let portable_handle = handle(portable.to_string_lossy().into_owned());
    let runtime_state_roots = RuntimeStateRoots::derive_portable(portable_handle.clone())?;
    let generation = handle("generation:liveness-store-split");
    let kernel_digest = handle("a".repeat(64));
    let bridge_digest = handle("b".repeat(64));
    let provider_digest = handle("d".repeat(64));
    let config_digest = handle("c".repeat(64));
    let config_path = path(&portable, "generation.json");
    let bootstrap_path = path(&portable, "store-bootstrap.json");
    let authority_path = path(&portable, "authority.json");
    let credential_target = handle("eliot/store/v1/0123456789abcdef0123456789abcdef");
    let bridge_path = path(&portable, "eliot-store-surreal.exe");
    let provider_path = path(&portable, "surreal.exe");
    let host_path = path(&portable, "eliot-host.exe");
    let mut runtime_launch = RuntimeLaunchDescriptor {
        profile: InstallationProfile::PortableDev,
        portable_root: Some(portable_handle.clone()),
        installation_epoch: InstallationEpoch {
            installation: handle("installation:liveness-store-split"),
            lineage_id: handle("lineage:liveness-store-split"),
            sequence: 1,
        },
        generation: generation.clone(),
        authority_generation: ResourceGeneration::genesis(),
        authority_state_fence: StateFence::new(
            AuthorityEpoch::genesis(),
            ResourceGeneration::genesis(),
        ),
        supervision_authority: eliot_installation::SupervisionAuthorityBinding::Provisioned {
            authority: Box::new(test_provisioned_supervision_authority(
                "installation:liveness-store-split",
                generation.as_str(),
                ResourceGeneration::genesis(),
            )),
        },
        authority_descriptor_path: authority_path.clone(),
        authority_descriptor_digest: handle("9".repeat(64)),
        runtime_state_roots: runtime_state_roots.clone(),
        kernel_work_root: runtime_state_roots.kernel_work_root.clone(),
        kernel_artifact_digest: kernel_digest.clone(),
        eliotd_executable_path: path(&portable, "eliotd.exe"),
        eliotd_artifact_digest: handle("e".repeat(64)),
        eliotd_config_path: path(&portable, "eliotd-governor.json"),
        eliotd_config_digest: handle("2".repeat(64)),
        protected_snapshot_digest: handle("a".repeat(64)),
        eliotd_descriptor_path: path(&portable, "eliotd.json"),
        eliotd_descriptor_digest: handle("f".repeat(64)),
        eliotd_launch_nonce: handle(format!("eliotd:{}", "1".repeat(32))),
        store_config_path: config_path.clone(),
        store_credential_target: credential_target,
        store_bridge_executable_path: bridge_path.clone(),
        store_bridge_artifact_digest: bridge_digest.clone(),
        store_bootstrap_descriptor_path: bootstrap_path.clone(),
        store_bootstrap_descriptor_digest: handle("8".repeat(64)),
        canonical_store_executable_path: provider_path.clone(),
        canonical_store_artifact_digest: provider_digest.clone(),
        kernel_arguments: vec![
            handle("--work-root"),
            runtime_state_roots.kernel_work_root.clone(),
            handle("--store-bootstrap"),
            bootstrap_path,
            handle("--store-bootstrap-sha256"),
            handle("8".repeat(64)),
            handle("--authority-descriptor"),
            authority_path,
            handle("--authority-descriptor-sha256"),
            handle("9".repeat(64)),
            handle("--kernel-artifact-sha256"),
            kernel_digest.clone(),
            handle("--eliotd-descriptor"),
            path(&portable, "eliotd.json"),
            handle("--eliotd-descriptor-sha256"),
            handle("f".repeat(64)),
        ],
        store_bridge_arguments: vec![
            handle("--portable-dev-root"),
            portable_handle,
            handle("--config"),
            config_path.clone(),
        ],
        canonical_store_arguments: vec![
            handle("start"),
            handle("--no-banner"),
            handle("--bind"),
            handle("127.0.0.1:8000"),
            handle("--temporary-directory"),
            runtime_state_roots.store_temp_root.clone(),
            handle("--log-file-enabled"),
            handle("--log-file-path"),
            runtime_state_roots.store_work_root.clone(),
            handle("--log-file-name"),
            handle("surrealdb.log"),
            handle(format!(
                "surrealkv://{}",
                runtime_state_roots
                    .store_data_root
                    .as_str()
                    .replace('\\', "/")
            )),
        ],
        host_executable_path: host_path.clone(),
        host_artifact_digest: handle("e".repeat(64)),
        watchdog_executable_path: path(&portable, "eliot-watchdog.exe"),
        watchdog_artifact_digest: handle("7".repeat(64)),
        descriptor_digest: handle("0".repeat(64)),
    };
    runtime_launch = runtime_launch.with_computed_digest()?;
    let manifest = CandidateManifest {
        generation,
        components: vec![handle("component:kernel"), handle("component:store")],
        kernel_artifact_digest: kernel_digest,
        store_bridge_artifact_digest: bridge_digest,
        canonical_store_artifact_digest: provider_digest,
        host_artifact_digest: handle("e".repeat(64)),
        kernel_executable_path: path(&portable, "eliot-kernel.exe"),
        store_bridge_executable_path: bridge_path,
        canonical_store_executable_path: provider_path,
        host_executable_path: host_path,
        config_path,
        dependency_closure_refs: vec![handle("evidence:dependency-closure")],
        license_refs: vec![handle("evidence:licenses")],
        config_digest,
        store_credential_target: handle("eliot/store/v1/0123456789abcdef0123456789abcdef"),
        supervision_key_slot: handle("6".repeat(64)),
        signature_ref: handle("evidence:signature"),
        runtime_state_roots_digest: runtime_state_roots.roots_digest.clone(),
        runtime_launch,
    };
    manifest.validate()?;
    Ok((manifest, root))
}

#[cfg(all(windows, test))]
fn active_startup_prior_binding(
    manifest: &CandidateManifest,
    lineage: &PlatformHandle,
    sequence: u64,
) -> PhaseBLiveBinding {
    let handle = |value: String| PlatformHandle::new(value).unwrap_or_else(|_| unreachable!());
    PhaseBLiveBinding {
        manifest_digest: phase_b_manifest_digest(manifest).unwrap_or_else(|_| unreachable!()),
        authority_descriptor_digest: manifest.runtime_launch.authority_descriptor_digest.clone(),
        store_bootstrap_descriptor_digest: manifest
            .runtime_launch
            .store_bootstrap_descriptor_digest
            .clone(),
        config_file_digest: manifest.config_digest.clone(),
        eliotd_descriptor_digest: manifest.runtime_launch.eliotd_descriptor_digest.clone(),
        semantic_config_hash: handle("1".repeat(64)),
        host_epoch_lineage: lineage.clone(),
        host_epoch_sequence: sequence,
        host_process_nonce_digest: handle("2".repeat(64)),
        receipt_digest: handle("3".repeat(64)),
        effect_id: handle("effect:active-startup-prior".to_owned()),
        credential_receipt_digest: handle("4".repeat(64)),
        request_digest: handle("5".repeat(64)),
        host_owner_epoch: handle("host-owner:active-startup-prior".to_owned()),
        host_process_identity: handle("6".repeat(64)),
        public_receipt_digest: handle("7".repeat(64)),
        provisioned_supervision_authority: test_provisioned_supervision_authority(
            manifest
                .runtime_launch
                .installation_epoch
                .installation
                .as_str(),
            manifest.runtime_launch.generation.as_str(),
            manifest.runtime_launch.authority_generation,
        ),
        agent_bridge: None,
    }
}

#[cfg(windows)]
#[test]
fn phase_b_materialization_reuses_exact_bytes_and_rejects_substitution() -> TestResult {
    let (_manifest, root) = liveness_manifest_with_distinct_store_digests()?;
    let portable = root.join("portable");
    let portable_lease = UserOwnedRootLease::open_existing(&portable)?;
    let destination = portable.join("phase-b-recovery.json");
    let desired = br#"{"host_epoch":1,"nonce":"fresh"}"#;
    let (digest, identity) = phase_b_materialize_file(
        InstallationProfile::PortableDev,
        Some(&portable_lease),
        &destination,
        desired,
        &[],
        "Phase-B recovery fixture",
    )?;
    assert_ne!(identity.file_index, 0);
    assert_ne!(identity.volume_serial_number, 0);
    assert_eq!(std::fs::read(&destination)?, desired);

    let (replayed_digest, replayed_identity) = phase_b_materialize_file(
        InstallationProfile::PortableDev,
        Some(&portable_lease),
        &destination,
        desired,
        &[&digest],
        "Phase-B recovery fixture",
    )?;
    assert_eq!(replayed_digest, digest);
    assert_eq!(replayed_identity, identity);

    std::fs::write(&destination, b"substituted")?;
    let Err(error) = phase_b_materialize_file(
        InstallationProfile::PortableDev,
        Some(&portable_lease),
        &destination,
        desired,
        &[&digest],
        "Phase-B recovery fixture",
    ) else {
        return Err(std::io::Error::other("substituted bytes must not be overwritten").into());
    };
    assert!(error.to_string().contains("neither the immutable template"));
    drop(portable_lease);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[cfg(windows)]
#[test]
fn agent_bridge_profile_leaf_recovery_reconstructs_missing_declaration() -> TestResult {
    let (_manifest, root) = liveness_manifest_with_distinct_store_digests()?;
    let portable = root.join("portable");
    let portable_lease = UserOwnedRootLease::open_existing(&portable)?;
    let profile_path = portable.join("agent-bridge-profile.json");
    let declaration_path = portable.join("agent-bridge-declaration.json");
    let profile = br#"{"profile":"canonical"}"#;
    let declaration = br#"{"module":"agent-bridge"}"#;
    let (profile_digest, _) = phase_b_materialize_file(
        InstallationProfile::PortableDev,
        Some(&portable_lease),
        &profile_path,
        profile,
        &[],
        "Agent Bridge profile",
    )?;
    assert!(!declaration_path.exists());
    phase_b_materialize_file(
        InstallationProfile::PortableDev,
        Some(&portable_lease),
        &declaration_path,
        declaration,
        &[&phase_b_bytes_digest(declaration)?],
        "Agent Bridge declaration",
    )?;
    assert_eq!(
        phase_b_bytes_digest(&std::fs::read(&profile_path)?)?,
        profile_digest
    );
    assert_eq!(std::fs::read(&declaration_path)?, declaration);
    drop(portable_lease);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[cfg(windows)]
#[test]
fn agent_bridge_declaration_leaf_recovery_reconstructs_missing_profile() -> TestResult {
    let (_manifest, root) = liveness_manifest_with_distinct_store_digests()?;
    let portable = root.join("portable");
    let portable_lease = UserOwnedRootLease::open_existing(&portable)?;
    let profile_path = portable.join("agent-bridge-profile.json");
    let declaration_path = portable.join("agent-bridge-declaration.json");
    let profile = br#"{"profile":"canonical"}"#;
    let declaration = br#"{"module":"agent-bridge"}"#;
    let (declaration_digest, _) = phase_b_materialize_file(
        InstallationProfile::PortableDev,
        Some(&portable_lease),
        &declaration_path,
        declaration,
        &[],
        "Agent Bridge declaration",
    )?;
    assert!(!profile_path.exists());
    phase_b_materialize_file(
        InstallationProfile::PortableDev,
        Some(&portable_lease),
        &profile_path,
        profile,
        &[&phase_b_bytes_digest(profile)?],
        "Agent Bridge profile",
    )?;
    assert_eq!(
        phase_b_bytes_digest(&std::fs::read(&declaration_path)?)?,
        declaration_digest
    );
    assert_eq!(std::fs::read(&profile_path)?, profile);
    drop(portable_lease);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[cfg(windows)]
#[test]
fn agent_bridge_pair_foreign_profile_or_declaration_fails_closed() -> TestResult {
    let (_manifest, root) = liveness_manifest_with_distinct_store_digests()?;
    let portable = root.join("portable");
    let portable_lease = UserOwnedRootLease::open_existing(&portable)?;
    let profile_path = portable.join("agent-bridge-profile.json");
    let declaration_path = portable.join("agent-bridge-declaration.json");
    let profile = br#"{"profile":"canonical"}"#;
    let declaration = br#"{"module":"agent-bridge"}"#;
    let profile_digest = phase_b_bytes_digest(profile)?;
    let declaration_digest = phase_b_bytes_digest(declaration)?;
    std::fs::write(&profile_path, b"foreign-profile")?;
    let profile_result = phase_b_materialize_file(
        InstallationProfile::PortableDev,
        Some(&portable_lease),
        &profile_path,
        profile,
        &[&profile_digest],
        "Agent Bridge profile",
    );
    assert!(profile_result.is_err());
    std::fs::write(&declaration_path, b"foreign-declaration")?;
    let declaration_result = phase_b_materialize_file(
        InstallationProfile::PortableDev,
        Some(&portable_lease),
        &declaration_path,
        declaration,
        &[&declaration_digest],
        "Agent Bridge declaration",
    );
    assert!(declaration_result.is_err());
    let cross_leaf_path = portable.join("agent-bridge-cross-leaf.json");
    std::fs::write(&cross_leaf_path, declaration)?;
    let cross_leaf_result = phase_b_materialize_file(
        InstallationProfile::PortableDev,
        Some(&portable_lease),
        &cross_leaf_path,
        profile,
        &[&profile_digest],
        "Agent Bridge profile",
    );
    assert!(cross_leaf_result.is_err());
    drop(portable_lease);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[cfg(windows)]
#[test]
fn agent_bridge_response_loss_rehydrate_is_idempotent_and_exact() -> TestResult {
    let (_manifest, root) = liveness_manifest_with_distinct_store_digests()?;
    let portable = root.join("portable");
    let portable_lease = UserOwnedRootLease::open_existing(&portable)?;
    let destination = portable.join("agent-bridge-profile.json");
    let desired = br#"{"profile":"canonical"}"#;
    let (first_digest, first_identity) = phase_b_materialize_file(
        InstallationProfile::PortableDev,
        Some(&portable_lease),
        &destination,
        desired,
        &[],
        "Agent Bridge profile",
    )?;
    let (retry_digest, retry_identity) = phase_b_materialize_file(
        InstallationProfile::PortableDev,
        Some(&portable_lease),
        &destination,
        desired,
        &[&first_digest],
        "Agent Bridge profile",
    )?;
    assert_eq!(retry_digest, first_digest);
    assert_eq!(retry_identity, first_identity);
    drop(portable_lease);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[cfg(windows)]
#[test]
fn agent_bridge_generation_replacement_rollback_restores_exact_pair() -> TestResult {
    let (_manifest, root) = liveness_manifest_with_distinct_store_digests()?;
    let portable = root.join("portable");
    let portable_lease = UserOwnedRootLease::open_existing(&portable)?;
    let profile_path = portable.join("agent-bridge-profile.json");
    let declaration_path = portable.join("agent-bridge-declaration.json");
    let old_profile = br#"{"profile":"old"}"#;
    let old_declaration = br#"{"module":"old"}"#;
    let new_profile = br#"{"profile":"new"}"#;
    let new_declaration = br#"{"module":"new"}"#;
    let (old_profile_digest, _) = phase_b_materialize_file(
        InstallationProfile::PortableDev,
        Some(&portable_lease),
        &profile_path,
        old_profile,
        &[],
        "Agent Bridge profile",
    )?;
    let (old_declaration_digest, _) = phase_b_materialize_file(
        InstallationProfile::PortableDev,
        Some(&portable_lease),
        &declaration_path,
        old_declaration,
        &[],
        "Agent Bridge declaration",
    )?;
    phase_b_materialize_file_with_rollback(
        InstallationProfile::PortableDev,
        Some(&portable_lease),
        &profile_path,
        new_profile,
        &[&old_profile_digest],
        "Agent Bridge profile",
    )?;
    phase_b_materialize_file_with_rollback(
        InstallationProfile::PortableDev,
        Some(&portable_lease),
        &declaration_path,
        new_declaration,
        &[&old_declaration_digest],
        "Agent Bridge declaration",
    )?;
    phase_b_restore_or_remove(
        InstallationProfile::PortableDev,
        Some(&portable_lease),
        &profile_path,
        "Agent Bridge profile",
        None,
    )?;
    phase_b_restore_or_remove(
        InstallationProfile::PortableDev,
        Some(&portable_lease),
        &declaration_path,
        "Agent Bridge declaration",
        None,
    )?;
    assert_eq!(std::fs::read(&profile_path)?, old_profile);
    assert_eq!(std::fs::read(&declaration_path)?, old_declaration);
    drop(portable_lease);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[cfg(windows)]
#[test]
fn phase_b_retains_immutable_template_across_live_replacement() -> TestResult {
    let (_manifest, root) = liveness_manifest_with_distinct_store_digests()?;
    let portable = root.join("portable");
    let portable_lease = UserOwnedRootLease::open_existing(&portable)?;
    let destination = portable.join("generation.json");
    let template = br#"{"runtime_launch":{"phase":"template"}}"#;
    std::fs::write(&destination, template)?;
    let template_digest = PlatformHandle::new(format!("{:x}", Sha256::digest(template)))?;
    assert_eq!(
        phase_b_template_bytes(
            InstallationProfile::PortableDev,
            Some(&portable_lease),
            &destination,
            &template_digest,
            "Store config",
        )?,
        template
    );

    let live = br#"{"runtime_launch":{"phase":"live"}}"#;
    phase_b_materialize_file(
        InstallationProfile::PortableDev,
        Some(&portable_lease),
        &destination,
        live,
        &[&template_digest],
        "Store config",
    )?;
    assert_eq!(
        phase_b_template_bytes(
            InstallationProfile::PortableDev,
            Some(&portable_lease),
            &destination,
            &template_digest,
            "Store config",
        )?,
        template
    );

    let retained_path = phase_b_template_path(&destination, "Store config")?;
    std::fs::write(&retained_path, b"substituted-template")?;
    assert!(
        phase_b_template_bytes(
            InstallationProfile::PortableDev,
            Some(&portable_lease),
            &destination,
            &template_digest,
            "Store config",
        )
        .is_err()
    );
    drop(portable_lease);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[cfg(windows)]
#[test]
fn phase_b_live_epoch_and_manifest_digest_are_observed_not_synthesized() -> TestResult {
    let host = test_host();
    let live = phase_b_live_installation_epoch(&host);
    assert_eq!(live.installation, host.installation);
    assert_eq!(live.lineage_id, host.epoch.current.lineage);
    assert_eq!(live.sequence, host.epoch.current.sequence);

    let (manifest, root) = liveness_manifest_with_distinct_store_digests()?;
    let expected = manifest.compute_digest()?;
    assert_eq!(phase_b_manifest_digest(&manifest)?, expected);
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[cfg(windows)]
#[test]
fn approved_host_artifact_path_and_digest_fail_closed() -> TestResult {
    let (mut manifest, root) = liveness_manifest_with_distinct_store_digests()?;
    let approved_path = PathBuf::from(manifest.host_executable_path.as_str());
    let approved_bytes = b"approved-host-fixture";
    std::fs::write(&approved_path, approved_bytes)?;
    let approved_digest = PlatformHandle::new(format!("{:x}", Sha256::digest(approved_bytes)))?;
    manifest.host_artifact_digest = approved_digest.clone();
    manifest.runtime_launch.host_artifact_digest = approved_digest;
    manifest.runtime_launch.descriptor_digest =
        PlatformHandle::new(manifest.runtime_launch.compute_digest()?)?;
    manifest.validate()?;

    verify_host_artifact_at(&manifest, &approved_path)?;

    let substituted_path = approved_path.with_file_name("substituted-host.exe");
    std::fs::write(&substituted_path, approved_bytes)?;
    assert!(verify_host_artifact_at(&manifest, &substituted_path).is_err());

    std::fs::write(&approved_path, b"tampered-host-fixture")?;
    assert!(verify_host_artifact_at(&manifest, &approved_path).is_err());

    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[cfg(windows)]
#[allow(
    clippy::too_many_lines,
    reason = "the fixture keeps the full Phase-B descriptor/config/bootstrap binding explicit"
)]
fn materialize_descriptor_bound_host_fixture(
    manifest: &mut CandidateManifest,
    host: &HostInstallationEpoch,
    descriptor_generation: ResourceGeneration,
) -> Result<(), TestError> {
    fn write_digest(path: &Path, bytes: &[u8]) -> Result<PlatformHandle, TestError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, bytes)?;
        Ok(PlatformHandle::new(format!("{:x}", Sha256::digest(bytes)))?)
    }

    let launch = &mut manifest.runtime_launch;
    for directory in [
        launch.runtime_state_roots.kernel_work_root.as_str(),
        launch.runtime_state_roots.store_work_root.as_str(),
    ] {
        std::fs::create_dir_all(directory)?;
    }
    let kernel_digest = write_digest(
        Path::new(manifest.kernel_executable_path.as_str()),
        b"kernel-fixture",
    )?;
    let store_digest = write_digest(
        Path::new(manifest.store_bridge_executable_path.as_str()),
        b"store-fixture",
    )?;
    let eliotd_digest = write_digest(
        Path::new(launch.eliotd_executable_path.as_str()),
        b"eliotd-fixture",
    )?;
    let eliotd_config_digest = write_digest(
        Path::new(launch.eliotd_config_path.as_str()),
        b"governor-config-fixture",
    )?;
    manifest.kernel_artifact_digest = kernel_digest.clone();
    manifest.store_bridge_artifact_digest = store_digest.clone();
    launch.kernel_artifact_digest = kernel_digest.clone();
    launch.store_bridge_artifact_digest = store_digest.clone();
    launch.eliotd_artifact_digest = eliotd_digest.clone();
    launch.eliotd_config_digest = eliotd_config_digest.clone();
    launch.kernel_arguments[11] = kernel_digest;

    // The persisted Phase-B config intentionally carries the explicit
    // pending bootstrap marker to avoid a self-referential semantic hash.
    // Host's in-memory live launch overlays the exact published bootstrap
    // digest before process admission.
    let pending_marker = PlatformHandle::new(PHASE_B_PENDING_MARKER)?;
    launch.store_bootstrap_descriptor_digest = pending_marker.clone();
    launch.kernel_arguments[5] = pending_marker;

    let nonce = host.host_process_nonce().as_handle().clone();
    let config_without_hash = serde_json::json!({
        "store_pipe": r"\\.\pipe\eliot\store",
        "launch_nonce": nonce.as_str(),
        "expected_client_sid": "S-1-5-19",
        "expected_client_session_id": 0,
        "approved_artifact_hash": store_digest.as_str(),
        "approved_config_hash": STORE_SEMANTIC_CONFIG_HASH_PENDING,
        "endpoint": "ws://127.0.0.1:8000/rpc",
        "provider_bind_address": "127.0.0.1:8000",
        "namespace": "eliot",
        "database": "runtime",
        "username": "root",
        "connect_timeout_ms": 5_000,
        "query_timeout_ms": 5_000,
        "schema_generation": "schema:test",
        "blob_root": launch.runtime_state_roots.store_data_root.as_str(),
        "instance_id": "host-descriptor-test-store",
        "credential_ref": launch.store_credential_target.as_str(),
        "runtime_launch": launch,
    });
    let semantic_config_hash =
        semantic_store_config_hash_from_json(&serde_json::to_vec(&config_without_hash)?)?;
    let mut config = config_without_hash;
    config["approved_config_hash"] =
        serde_json::Value::String(semantic_config_hash.as_str().to_owned());
    let config_bytes = serde_json::to_vec(&config)?;
    let store_config_digest =
        write_digest(Path::new(manifest.config_path.as_str()), &config_bytes)?;
    manifest.config_digest = store_config_digest;

    let requirement = HostStoreBootstrapRequirement {
        route_identity: PlatformHandle::new(eliot_kernel_service::STORE_ROUTE_IDENTITY)?,
        canonical_pipe_identity: PlatformHandle::new(r"\\.\pipe\eliot\store")?,
        store_generation: launch.authority_generation,
        state_fence: launch.authority_state_fence.clone(),
        launch_nonce: nonce,
        connection_id: PlatformHandle::new("host-descriptor-test-store")?,
        expected_peer_sid: PlatformHandle::new("S-1-5-19")?,
        expected_peer_session_id: 0,
        approved_artifact_hash: store_digest,
        approved_config_hash: semantic_config_hash,
        timeout_ms: 5_000,
    };
    let bootstrap_bytes = serde_json::to_vec(&requirement)?;
    let bootstrap_digest = write_digest(
        Path::new(launch.store_bootstrap_descriptor_path.as_str()),
        &bootstrap_bytes,
    )?;
    launch.store_bootstrap_descriptor_digest = bootstrap_digest.clone();
    launch.kernel_arguments[5] = bootstrap_digest;

    let eliotd_nonce = launch.eliotd_launch_nonce.clone();
    let descriptor = EliotdLaunchDescriptor {
        wire_id: "eliot.kernel.eliotd-launch".to_owned(),
        wire_version: EliotdLaunchDescriptor::CONTRACT_VERSION,
        executable: launch.eliotd_executable_path.clone(),
        executable_sha256: eliotd_digest.as_str().to_owned(),
        arguments: vec![
            PlatformHandle::new("--config-descriptor")?,
            launch.eliotd_config_path.clone(),
            PlatformHandle::new("--config-descriptor-sha256")?,
            eliotd_config_digest,
            PlatformHandle::new("--launch-nonce")?,
            eliotd_nonce.clone(),
            PlatformHandle::new("--executable-sha256")?,
            eliotd_digest,
        ],
        working_directory: launch.kernel_work_root.clone(),
        config_descriptor: launch.eliotd_config_path.clone(),
        config_descriptor_sha256: launch.eliotd_config_digest.as_str().to_owned(),
        protected_snapshot_digest: launch.protected_snapshot_digest.as_str().to_owned(),
        launch_nonce: eliotd_nonce,
        authority_epoch: launch.authority_state_fence.authority_epoch,
        generation: descriptor_generation,
        descriptor_sha256: String::new(),
    }
    .with_computed_digest()?;
    let descriptor_bytes = serde_json::to_vec(&descriptor)?;
    let descriptor_digest = write_digest(
        Path::new(launch.eliotd_descriptor_path.as_str()),
        &descriptor_bytes,
    )?;
    launch.eliotd_descriptor_digest = descriptor_digest.clone();
    launch.kernel_arguments[15] = descriptor_digest;
    launch.descriptor_digest = PlatformHandle::new(launch.compute_digest()?)?;
    Ok(())
}

#[cfg(windows)]
#[test]
fn production_initial_and_relaunch_reject_descriptor_generation_substitution() -> TestResult {
    let host = test_host();
    let (mut manifest, root) = liveness_manifest_with_distinct_store_digests()?;
    let substituted_generation =
        ResourceGeneration::new(manifest.runtime_launch.authority_generation.value() + 1)?;
    materialize_descriptor_bound_host_fixture(&mut manifest, &host, substituted_generation)?;
    let descriptor_bytes = std::fs::read(manifest.runtime_launch.eliotd_descriptor_path.as_str())?;
    let mut substituted_descriptor: EliotdLaunchDescriptor =
        serde_json::from_slice(&descriptor_bytes)?;
    substituted_descriptor.protected_snapshot_digest = "b".repeat(64);
    let substituted_bytes = serde_json::to_vec(&substituted_descriptor.with_computed_digest()?)?;
    let substituted_digest =
        PlatformHandle::new(format!("{:x}", Sha256::digest(&substituted_bytes)))?;
    assert!(
        validate_eliotd_launch_descriptor_bytes(
            &substituted_bytes,
            &substituted_digest,
            &manifest.runtime_launch,
        )
        .is_err()
    );
    let config_path = PathBuf::from(manifest.config_path.as_str());
    let mut initial = HostJobBranches::new(&host)?;
    let Err(initial_error) = initial.start_approved(
        Path::new(manifest.kernel_executable_path.as_str()),
        Path::new(manifest.store_bridge_executable_path.as_str()),
        &manifest.generation,
        &manifest.config_digest,
        &config_path,
        &manifest.kernel_executable_path,
        &manifest.store_bridge_executable_path,
        &manifest.config_path,
        &manifest.kernel_artifact_digest,
        &manifest.store_bridge_artifact_digest,
        &host,
        &manifest.runtime_launch,
    ) else {
        return Err(
            std::io::Error::other("initial descriptor generation substitution must fail").into(),
        );
    };
    assert!(
        initial_error
            .to_string()
            .contains("eliotd launch descriptor"),
        "unexpected initial validation error: {initial_error}"
    );
    assert!(initial.kernel.is_none());
    assert!(initial.store.is_none());

    let mut relaunch = HostJobBranches::new(&host)?;
    let portable_root = PathBuf::from(
        manifest
            .runtime_launch
            .portable_root
            .as_ref()
            .ok_or_else(|| std::io::Error::other("test option invariant"))?
            .as_str(),
    );
    let portable_lease = UserOwnedRootLease::open_existing(&portable_root)?;
    relaunch.kernel_executable = Some(PathBuf::from(manifest.kernel_executable_path.as_str()));
    relaunch.kernel_lease = Some(open_launch_lease(
        manifest.runtime_launch.profile,
        Some(&portable_lease),
        Path::new(manifest.kernel_executable_path.as_str()),
    )?);
    relaunch.config_lease = Some(open_launch_lease(
        manifest.runtime_launch.profile,
        Some(&portable_lease),
        &config_path,
    )?);
    relaunch.config_pin = Some(PinnedRuntimeFile::open(&config_path)?);
    relaunch.eliotd_config_lease = Some(open_launch_lease(
        manifest.runtime_launch.profile,
        Some(&portable_lease),
        Path::new(manifest.runtime_launch.eliotd_config_path.as_str()),
    )?);
    relaunch.eliotd_descriptor_lease = Some(open_launch_lease(
        manifest.runtime_launch.profile,
        Some(&portable_lease),
        Path::new(manifest.runtime_launch.eliotd_descriptor_path.as_str()),
    )?);
    relaunch.portable_root = Some(portable_lease);
    relaunch.launch = Some(manifest.runtime_launch.clone());
    let Err(relaunch_error) = relaunch.relaunch_kernel(
        &manifest.generation,
        &manifest.config_digest,
        &config_path,
        &manifest.kernel_artifact_digest,
        &manifest.kernel_executable_path,
        &manifest.config_path,
        &host,
    ) else {
        panic!("relaunch descriptor generation substitution must fail");
    };
    assert!(
        relaunch_error
            .to_string()
            .contains("eliotd launch descriptor"),
        "unexpected relaunch validation error: {relaunch_error}"
    );
    assert!(relaunch.kernel.is_none());
    let _ = std::fs::remove_dir_all(root);
    Ok(())
}

#[cfg(windows)]
#[test]
fn host_launch_options_bind_exact_manifest_and_require_registry_evidence() -> TestResult {
    let (manifest, root) = liveness_manifest_with_distinct_store_digests()?;
    let options = HostLaunchOptions {
        config_descriptor_path: PathBuf::from(
            manifest.runtime_launch.authority_descriptor_path.as_str(),
        ),
        config_descriptor_digest: manifest.runtime_launch.authority_descriptor_digest.clone(),
        installation: manifest
            .runtime_launch
            .installation_epoch
            .installation
            .clone(),
        transaction_plan_generation: manifest.runtime_launch.authority_generation.value(),
        host_state_root: PathBuf::from(
            manifest
                .runtime_launch
                .runtime_state_roots
                .host_state_root
                .as_str(),
        ),
        registration_nonce: Some(PlatformHandle::new("e".repeat(64))?),
    };
    assert!(HostComposition::validate_launch_options_for_manifest(&options, &manifest).is_ok());

    let mut pending_manifest = manifest.clone();
    pending_manifest.runtime_launch.authority_descriptor_digest =
        PlatformHandle::new(PHASE_B_PENDING_MARKER).unwrap_or_else(|_| unreachable!());
    let mut pending_options = options.clone();
    pending_options.config_descriptor_digest =
        PlatformHandle::new(eliot_installation::PHASE_B_PENDING_SCM_DIGEST)
            .unwrap_or_else(|_| unreachable!());
    assert!(
        HostComposition::validate_launch_options_for_manifest(&pending_options, &pending_manifest,)
            .is_ok()
    );
    let mut runtime_selector_manifest = pending_manifest.clone();
    runtime_selector_manifest
        .runtime_launch
        .authority_descriptor_digest =
        PlatformHandle::new(eliot_installation::PHASE_B_PENDING_SCM_DIGEST)
            .unwrap_or_else(|_| unreachable!());
    assert!(
        HostComposition::validate_launch_options_for_manifest(
            &pending_options,
            &runtime_selector_manifest,
        )
        .is_err()
    );

    let mut substituted = options.clone();
    substituted.config_descriptor_digest =
        PlatformHandle::new("f".repeat(64)).unwrap_or_else(|_| unreachable!());
    assert!(
        HostComposition::validate_launch_options_for_manifest(&substituted, &manifest).is_err()
    );
    let mut nonce_substitution = options.clone();
    nonce_substitution.config_descriptor_digest = nonce_substitution
        .registration_nonce
        .clone()
        .unwrap_or_else(|| unreachable!());
    assert!(
        HostComposition::validate_launch_options_for_manifest(&nonce_substitution, &manifest,)
            .is_err()
    );
    let mut wrong_root = options.clone();
    wrong_root.host_state_root = wrong_root.host_state_root.with_file_name("wrong-host");
    assert!(HostComposition::validate_launch_options_for_manifest(&wrong_root, &manifest).is_err());
    let mut wrong_installation = options.clone();
    wrong_installation.installation =
        PlatformHandle::new("installation-substitution").unwrap_or_else(|_| unreachable!());
    assert!(
        HostComposition::validate_launch_options_for_manifest(&wrong_installation, &manifest,)
            .is_err()
    );
    assert!(
        HostComposition::validate_launch_options_for_registry(
            &options,
            &ApprovedGenerationRegistry::new(),
            None,
        )
        .is_err()
    );
    let _ = std::fs::remove_dir_all(root);
    Ok(())
}

#[cfg(windows)]
#[test]
fn production_start_and_relaunch_store_cwd_use_canonical_store_root() -> TestResult {
    let (manifest, root) = liveness_manifest_with_distinct_store_digests()?;
    for directory in [
        manifest
            .runtime_launch
            .runtime_state_roots
            .kernel_work_root
            .as_str(),
        manifest
            .runtime_launch
            .runtime_state_roots
            .store_work_root
            .as_str(),
    ] {
        std::fs::create_dir_all(directory)?;
    }
    let portable_root = manifest
        .runtime_launch
        .portable_root
        .as_ref()
        .ok_or_else(|| std::io::Error::other("portable root missing"))
        .map(|path| PathBuf::from(path.as_str()))?;
    let lease = UserOwnedRootLease::open_existing(&portable_root)?;
    let config_path = portable_root.join("generation.json");
    std::fs::write(&config_path, b"fixture")?;
    let start = HostJobBranches::approved_working_directories(
        &manifest.runtime_launch,
        Some(&lease),
        &config_path,
    )?;
    let relaunch = HostJobBranches::approved_working_directories(
        &manifest.runtime_launch,
        Some(&lease),
        &config_path,
    )?;
    assert_eq!(start, relaunch);
    assert_ne!(start.0, start.1);
    assert_eq!(
        start.1,
        std::fs::canonicalize(
            manifest
                .runtime_launch
                .runtime_state_roots
                .store_work_root
                .as_str(),
        )?
    );
    drop(lease);
    let _ = std::fs::remove_dir_all(root);
    Ok(())
}

#[cfg(windows)]
#[test]
fn host_controller_liveness_tick_uses_bridge_digest_not_provider_digest() -> TestResult {
    let (manifest, root) = liveness_manifest_with_distinct_store_digests()?;
    assert_ne!(
        manifest.store_bridge_artifact_digest,
        manifest.canonical_store_artifact_digest
    );
    let now = std::time::Instant::now();
    let exact = ReadinessContourIdentity {
        approved_generation: manifest.generation.clone(),
        approved_kernel_artifact: manifest.kernel_artifact_digest.clone(),
        approved_store_artifact: manifest.store_bridge_artifact_digest.clone(),
        approved_config: manifest.config_digest.clone(),
        active_kernel_record_checksum: PlatformHandle::new("kernel-record")
            .unwrap_or_else(|_| unreachable!()),
        candidate_binding_digest: PlatformHandle::new("candidate-binding")
            .unwrap_or_else(|_| unreachable!()),
        store_requirement_digest: PlatformHandle::new("store-requirement")
            .unwrap_or_else(|_| unreachable!()),
        store_proof_fence: Some(
            PlatformHandle::new("store-proof").unwrap_or_else(|_| unreachable!()),
        ),
        supervision_lease_id: Some(
            PlatformHandle::new("supervision-lease:test-liveness")
                .unwrap_or_else(|_| unreachable!()),
        ),
        supervision_ors_receipt_digest: Some(
            PlatformHandle::new("a".repeat(64)).unwrap_or_else(|_| unreachable!()),
        ),
        watchdog_publication_digest: Some(
            PlatformHandle::new("b".repeat(64)).unwrap_or_else(|_| unreachable!()),
        ),
    };
    let mut gate = HostReadinessGate::default();
    assert!(gate.grant(exact.clone(), now));
    let mut selected_store = None;
    let tick = descriptor_bound_liveness_tick(
        &mut gate,
        HostBranchDisposition::LiveAwaitingReadiness,
        Some(&manifest),
        |generation, kernel, store, config| {
            assert_eq!(generation, &manifest.generation);
            assert_eq!(kernel, &manifest.kernel_artifact_digest);
            assert_eq!(config, &manifest.config_digest);
            selected_store = Some(store.clone());
            Ok(exact)
        },
        now + std::time::Duration::from_millis(1),
    );
    assert_eq!(tick, HostLivenessTick::HealthyLeasePreserved);
    assert_eq!(
        selected_store.as_ref(),
        Some(&manifest.store_bridge_artifact_digest)
    );
    assert_ne!(
        selected_store.as_ref(),
        Some(&manifest.canonical_store_artifact_digest)
    );
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[cfg(windows)]
#[test]
fn ready_repeat_appends_fresh_proofs_without_mutating_activation_authority() -> TestResult {
    let fixture = active_readiness_fixture()?;
    let before = fixture
        .journal
        .snapshot()?
        .kernel
        .ok_or_else(|| std::io::Error::other("test option invariant"))?;
    let first = authenticated_proof(&fixture, 7)?;
    let first_disposition = append_authenticated_kernel_readiness(
        &fixture.journal,
        &first,
        &fixture.kernel_artifact,
        &fixture.config,
        &test_published_supervision_identity()?,
    )
    .map(|_| HostBranchDisposition::Healthy)?;
    let second = authenticated_proof(&fixture, 8)?;
    let second_disposition = append_authenticated_kernel_readiness(
        &fixture.journal,
        &second,
        &fixture.kernel_artifact,
        &fixture.config,
        &test_published_supervision_identity()?,
    )
    .map(|_| HostBranchDisposition::Healthy)?;
    let state = fixture.journal.snapshot()?;
    let after = state
        .kernel
        .ok_or_else(|| std::io::Error::other("test option invariant"))?;
    assert_eq!(first_disposition, HostBranchDisposition::Healthy);
    assert_eq!(second_disposition, HostBranchDisposition::Healthy);
    assert_eq!(state.readiness_observations.len(), 2);
    assert_ne!(first.request.payload_digest, second.request.payload_digest);
    assert!(matches!(
        first.request.command,
        KernelControlCommand::ProbeReady
    ));
    assert!(matches!(
        second.request.command,
        KernelControlCommand::ProbeReady
    ));
    assert_eq!(after.one_time_nonce, before.one_time_nonce);
    assert_eq!(after.kernel_generation, before.kernel_generation);
    assert_eq!(
        after
            .process
            .ok_or_else(|| std::io::Error::other("test option invariant"))?
            .authority_epoch,
        before
            .process
            .ok_or_else(|| std::io::Error::other("test option invariant"))?
            .authority_epoch
    );
    Ok(())
}

#[cfg(windows)]
#[test]
fn readiness_lease_separates_cheap_polling_from_expired_repeat() -> TestResult {
    assert_eq!(
        ReadinessCadence::default().0,
        std::time::Duration::from_secs(5)
    );
    assert!(ReadinessCadence::bounded(std::time::Duration::from_millis(249)).is_err());
    assert!(ReadinessCadence::bounded(std::time::Duration::from_secs(61)).is_err());

    let fixture = active_readiness_fixture()?;
    let contour = readiness_contour(&fixture)?;
    let mut gate = HostReadinessGate::with_cadence(ReadinessCadence::default());
    let now = std::time::Instant::now();
    let probes = std::cell::Cell::new(0_u8);
    let admit = |revision| -> Result<ReadinessContourIdentity, HostError> {
        probes.set(probes.get() + 1);
        let proof = authenticated_proof(&fixture, revision)
            .map_err(|error| HostError::Platform(error.to_string()))?;
        append_authenticated_kernel_readiness(
            &fixture.journal,
            &proof,
            &fixture.kernel_artifact,
            &fixture.config,
            &test_published_supervision_identity()
                .map_err(|error| HostError::Platform(error.to_string()))?,
        )?;
        readiness_contour(&fixture).map_err(|error| HostError::Platform(error.to_string()))
    };

    let first =
        reconcile_authenticated_readiness(&mut gate, Ok(contour.clone()), now, || admit(20));
    assert_eq!(first, HostBranchDisposition::Healthy);
    assert_eq!(probes.get(), 1);
    let journaled_contour = readiness_contour(&fixture)?;

    let cheap = classify_liveness_tick(
        &mut gate,
        HostBranchDisposition::LiveAwaitingReadiness,
        Some(Ok(journaled_contour.clone())),
        now + std::time::Duration::from_millis(250),
    );
    assert_eq!(cheap, HostLivenessTick::HealthyLeasePreserved);
    assert_eq!(probes.get(), 1);

    let before_expiry = classify_liveness_tick(
        &mut gate,
        HostBranchDisposition::LiveAwaitingReadiness,
        Some(Ok(journaled_contour.clone())),
        (now + DEFAULT_READINESS_CADENCE)
            .checked_sub(std::time::Duration::from_millis(1))
            .ok_or_else(|| std::io::Error::other("test instant underflow"))?,
    );
    assert_eq!(before_expiry, HostLivenessTick::HealthyLeasePreserved);

    let expired_tick = classify_liveness_tick(
        &mut gate,
        HostBranchDisposition::LiveAwaitingReadiness,
        Some(Ok(journaled_contour.clone())),
        now + DEFAULT_READINESS_CADENCE,
    );
    assert_eq!(expired_tick, HostLivenessTick::FullReconcileDue);
    let expired = reconcile_authenticated_readiness(
        &mut gate,
        Ok(journaled_contour),
        now + DEFAULT_READINESS_CADENCE,
        || admit(21),
    );
    assert_eq!(expired, HostBranchDisposition::Healthy);
    assert_eq!(probes.get(), 2);
    assert_eq!(fixture.journal.snapshot()?.readiness_observations.len(), 2);
    Ok(())
}

#[cfg(windows)]
#[test]
fn production_fast_path_invalidates_every_exact_contour_field() -> TestResult {
    let fixture = active_readiness_fixture()?;
    let mut exact = readiness_contour(&fixture)?;
    exact.store_proof_fence = Some(PlatformHandle::new("store-proof-exact")?);
    let changed = |label: &str| -> Result<PlatformHandle, TestError> {
        Ok(PlatformHandle::new(format!("changed-{label}"))?)
    };
    let mut variants = Vec::new();

    let mut contour = exact.clone();
    contour.approved_generation = changed("generation")?;
    variants.push(("approved_generation", contour));
    let mut contour = exact.clone();
    contour.approved_kernel_artifact = changed("kernel-artifact")?;
    variants.push(("approved_kernel_artifact", contour));
    let mut contour = exact.clone();
    contour.approved_store_artifact = changed("store-artifact")?;
    variants.push(("approved_store_artifact", contour));
    let mut contour = exact.clone();
    contour.approved_config = changed("config")?;
    variants.push(("approved_config", contour));
    let mut contour = exact.clone();
    contour.active_kernel_record_checksum = changed("kernel-checksum")?;
    variants.push(("active_kernel_record_checksum", contour));
    let mut contour = exact.clone();
    contour.candidate_binding_digest = changed("candidate-binding")?;
    variants.push(("candidate_binding_digest", contour));
    let mut contour = exact.clone();
    contour.store_requirement_digest = changed("store-requirement")?;
    variants.push(("store_requirement_digest", contour));
    let mut contour = exact.clone();
    contour.store_proof_fence = Some(changed("store-proof")?);
    variants.push(("store_proof_fence", contour));
    let mut contour = exact.clone();
    contour.supervision_lease_id = Some(changed("supervision-lease")?);
    variants.push(("supervision_lease_id", contour));
    let mut contour = exact.clone();
    contour.supervision_ors_receipt_digest = Some(changed("supervision-ors-receipt")?);
    variants.push(("supervision_ors_receipt_digest", contour));
    let mut contour = exact.clone();
    contour.watchdog_publication_digest = Some(changed("watchdog-publication")?);
    variants.push(("watchdog_publication_digest", contour));

    let now = std::time::Instant::now();
    for (field, current) in variants {
        let mut gate = HostReadinessGate::default();
        assert!(gate.grant(exact.clone(), now));
        assert_eq!(
            classify_liveness_tick(
                &mut gate,
                HostBranchDisposition::LiveAwaitingReadiness,
                Some(Ok(current)),
                now + std::time::Duration::from_millis(250),
            ),
            HostLivenessTick::FullReconcileDue,
            "{field} mismatch preserved an inexact lease"
        );
    }

    let mut exact_gate = HostReadinessGate::default();
    assert!(exact_gate.grant(exact.clone(), now));
    assert_eq!(
        classify_liveness_tick(
            &mut exact_gate,
            HostBranchDisposition::LiveAwaitingReadiness,
            Some(Ok(exact.clone())),
            now + std::time::Duration::from_millis(250),
        ),
        HostLivenessTick::HealthyLeasePreserved
    );

    let mut renewed = exact.clone();
    renewed.supervision_ors_receipt_digest = Some(changed("renewed-supervision-ors-receipt")?);
    renewed.watchdog_publication_digest = Some(changed("renewed-watchdog-publication")?);
    assert_ne!(renewed, exact);
    assert!(renewed.same_probe_input_contour(&exact));
    let mut foreign_incarnation = renewed;
    foreign_incarnation.supervision_lease_id = Some(changed("foreign-supervision-lease")?);
    assert!(!foreign_incarnation.same_probe_input_contour(&exact));

    let mut missing_gate = HostReadinessGate::default();
    missing_gate.fail(None, ReadinessFailureKind::ContourUnavailable, now);
    assert_eq!(
        classify_liveness_tick(
            &mut missing_gate,
            HostBranchDisposition::LiveAwaitingReadiness,
            Some(Err(HostError::ProcessContour(
                "retained Store proof is missing".to_owned(),
            ))),
            now + std::time::Duration::from_millis(250),
        ),
        HostLivenessTick::ReadinessRetryPending
    );
    Ok(())
}

#[cfg(windows)]
#[test]
fn production_readiness_supervision_fence_rejects_substitution_and_post_publish_renewal()
-> TestResult {
    let fixture = active_readiness_fixture()?;
    let proof = authenticated_proof(&fixture, 44)?;
    let exact = test_published_supervision_identity()?;
    append_authenticated_kernel_readiness(
        &fixture.journal,
        &proof,
        &fixture.kernel_artifact,
        &fixture.config,
        &exact,
    )?;
    let observation = fixture
        .journal
        .snapshot()?
        .readiness_observations
        .pop()
        .ok_or_else(|| std::io::Error::other("test option invariant"))?;
    assert!(readiness_supervision_fence_matches(
        &exact,
        true,
        &observation.evidence_refs,
    ));
    assert!(!readiness_supervision_fence_matches(
        &exact,
        false,
        &observation.evidence_refs,
    ));
    let mut substituted = exact.clone();
    substituted.publication_digest = PlatformHandle::new("c".repeat(64))?;
    assert!(!readiness_supervision_fence_matches(
        &substituted,
        true,
        &observation.evidence_refs,
    ));
    let mut renewed = proof.supervision_lease.clone();
    renewed.receipt.receipt_sha256 = "d".repeat(64);
    assert!(require_exact_supervision_head(&proof.supervision_lease, || Ok(renewed)).is_err());
    Ok(())
}

#[cfg(windows)]
#[test]
fn degraded_recovery_becomes_healthy_only_after_journaled_probe() -> TestResult {
    let fixture = active_readiness_fixture()?;
    let contour = readiness_contour(&fixture)?;
    let mut gate = HostReadinessGate::default();
    let degraded = HostBranchDisposition::KernelDegraded;
    gate.branch_degraded();
    assert_ne!(degraded, HostBranchDisposition::Healthy);
    let proof = authenticated_proof(&fixture, 9)?;
    let request_digest = proof.request.payload_digest.clone();
    let response_digest = proof.response.payload_digest.clone();
    let recovered = reconcile_authenticated_readiness(
        &mut gate,
        Ok(contour),
        std::time::Instant::now(),
        || {
            append_authenticated_kernel_readiness(
                &fixture.journal,
                &proof,
                &fixture.kernel_artifact,
                &fixture.config,
                &test_published_supervision_identity()
                    .map_err(|error| HostError::Platform(error.to_string()))?,
            )?;
            readiness_contour(&fixture).map_err(|error| HostError::Platform(error.to_string()))
        },
    );
    assert_eq!(recovered, HostBranchDisposition::Healthy);
    let state = fixture.journal.snapshot()?;
    assert_eq!(state.readiness_observations.len(), 1);
    assert_eq!(
        state.readiness_observations[0]
            .probe_request_digest
            .as_str(),
        request_digest
    );
    assert_eq!(
        state.readiness_observations[0]
            .ready_receipt_digest
            .as_str(),
        response_digest
    );
    Ok(())
}

#[cfg(windows)]
#[test]
fn stale_store_snapshot_and_response_substitution_never_become_healthy() -> TestResult {
    let fixture = active_readiness_fixture()?;
    let (request, response, ready) = probe_exchange(&fixture, 0)?;
    validate_probe_response(&request, &fixture.activation, &response)?;
    let stale_result = validated_store_proof_fence(
        &fixture.requirement,
        &ready,
        &fixture.store_artifact,
        &fixture.config,
        request.generation,
    );
    assert!(stale_result.is_err());

    let (request, mut substituted, _) = probe_exchange(&fixture, 10)?;
    substituted.request_digest = "d".repeat(64);
    substituted = substituted.with_computed_digest()?;
    assert!(validate_probe_response(&request, &fixture.activation, &substituted).is_err());
    let snapshot = fixture.journal.snapshot()?;
    assert!(snapshot.readiness_observations.is_empty());
    assert_eq!(
        snapshot
            .kernel
            .ok_or_else(|| std::io::Error::other("test option invariant"))?
            .state,
        KernelActivationState::Active
    );
    Ok(())
}

#[cfg(windows)]
#[test]
fn unknown_readiness_journal_outcome_remains_non_healthy() -> TestResult {
    let fixture = active_readiness_fixture()?;
    let proof = authenticated_proof(&fixture, 11)?;
    let host = fixture.journal.snapshot()?.host;
    let backend = fixture.journal.into_backend()?;
    let journal = HostStateJournalService::from_backend(
        UnknownAppendBackend {
            image: backend.durable_image().clone(),
            prepared: None,
        },
        host,
    )?;
    let outcome = append_authenticated_kernel_readiness(
        &journal,
        &proof,
        &fixture.kernel_artifact,
        &fixture.config,
        &test_published_supervision_identity()?,
    );
    assert!(matches!(
        outcome,
        Err(HostError::Journal(JournalError::OutcomeUnknown { .. }))
    ));
    assert!(journal.snapshot()?.readiness_observations.is_empty());
    Ok(())
}

#[cfg(windows)]
#[test]
#[allow(
    clippy::too_many_lines,
    reason = "the regression spells out HostComposition::stop journal transitions before replay"
)]
fn activation_reopen_starts_a_fresh_child_after_historical_active() -> TestResult {
    let fixture = active_readiness_fixture()?;
    let proof = authenticated_proof(&fixture, 17)?;
    append_authenticated_kernel_readiness(
        &fixture.journal,
        &proof,
        &fixture.kernel_artifact,
        &fixture.config,
        &test_published_supervision_identity()?,
    )?;
    let snapshot = fixture.journal.snapshot()?;
    let control_ready = transition_activation_record(
        snapshot
            .activation
            .as_ref()
            .ok_or_else(|| std::io::Error::other("test option invariant"))?,
        ActivationState::ControlReady,
        "pending-reopen-control-ready",
    )?;
    append_reconciled(&fixture.journal, HostStateRecord::Activation(control_ready))?;
    let ready_snapshot = fixture.journal.snapshot()?;
    let active = transition_activation_record(
        ready_snapshot
            .activation
            .as_ref()
            .ok_or_else(|| std::io::Error::other("test option invariant"))?,
        ActivationState::Active,
        "pending-reopen-active",
    )?;
    append_reconciled(&fixture.journal, HostStateRecord::Activation(active))?;

    // Exercise the same durable reducer sequence as HostComposition::stop
    // before writing the clean marker.  The process termination itself is
    // a Windows Job Object effect and is intentionally not fabricated in
    // this in-memory journal fixture; all journal-owned fences remain
    // production-shaped and are validated by the reducer.
    let historical = fixture.journal.snapshot()?;
    let historical_activation = historical
        .activation
        .as_ref()
        .ok_or_else(|| std::io::Error::other("test option invariant"))?
        .clone();
    let drain_generation = historical_activation.fence.activation_generation.clone();
    append_reconciled(
        &fixture.journal,
        HostStateRecord::Drain(DrainRecord {
            fence: historical_activation.fence.clone(),
            operation: operation("host-drain-request-test")?,
            drain_generation: drain_generation.clone(),
            state: DrainState::Requested,
            evidence_refs: vec![PlatformHandle::new("scm-stop-request-test")?],
        }),
    )?;
    append_reconciled(
        &fixture.journal,
        HostStateRecord::Drain(DrainRecord {
            fence: historical_activation.fence.clone(),
            operation: operation("host-drain-start-test")?,
            drain_generation: drain_generation.clone(),
            state: DrainState::Draining,
            evidence_refs: vec![PlatformHandle::new("host-admission-closed-test")?],
        }),
    )?;
    let draining = transition_activation_record(
        &fixture
            .journal
            .snapshot()?
            .activation
            .ok_or_else(|| std::io::Error::other("test option invariant"))?,
        ActivationState::Draining,
        "host-draining-test",
    )?;
    append_reconciled(&fixture.journal, HostStateRecord::Activation(draining))?;
    append_reconciled(
        &fixture.journal,
        HostStateRecord::DrainCommit(DrainCommitRecord {
            fence: historical_activation.fence.clone(),
            operation: operation("host-drain-commit-test")?,
            drain_generation,
            last_admission_closed_at: PlatformHandle::new("host-admission-closed-at-test")?,
            lease_and_pending_operation_snapshot: Vec::new(),
            authority_epochs_fenced: vec![historical_activation.lineage.kernel_epoch.clone()],
            processes_modules_and_store_branches_to_stop: vec![
                PlatformHandle::new("canonical-store-branch-test")?,
                PlatformHandle::new("kernel-branch-test")?,
            ],
            wake_during_drain_disposition: WakeDisposition::QueueNextGeneration,
            irreversible_stage: PlatformHandle::new("authority-fenced-test")?,
            recovery_owner: PlatformHandle::new("host-composition-test")?,
            committed_at: PlatformHandle::new("host-drain-committed-at-test")?,
        }),
    )?;
    let stopped_clean = transition_activation_record(
        &fixture
            .journal
            .snapshot()?
            .activation
            .ok_or_else(|| std::io::Error::other("test option invariant"))?,
        ActivationState::StoppedClean,
        "host-stopped-clean-test",
    )?;
    append_reconciled(&fixture.journal, HostStateRecord::Activation(stopped_clean))?;

    let historical = fixture.journal.snapshot()?;
    let historical_activation = historical
        .activation
        .as_ref()
        .ok_or_else(|| std::io::Error::other("test option invariant"))?;
    append_clean_marker(
        &fixture.journal,
        &historical.host,
        &historical_activation.activation_id,
        &historical_activation.fence.activation_generation,
    )?;

    // Drive the same persisted replay/reopen path used by production Host
    // (with an in-memory durable backend so the test never touches the
    // machine-wide protected ProgramData journal).  The historical Active
    // record is deliberately not accepted as a live contour: a Host-owned
    // kill-on-close Job has already terminated its children by the time a
    // new Host process reaches this path.
    let durable = fixture.journal.snapshot()?;
    let last_host = durable.host;
    let installation = last_host.installation.clone();
    let prior_generation = durable
        .activation
        .as_ref()
        .ok_or_else(|| std::io::Error::other("activation record missing"))?
        .fence
        .activation_generation
        .clone();
    let (
        reopened,
        reopened_host,
        reopened_generation,
        store_recovery_fenced,
        active_rebind_recovery,
    ) = reopen_existing_epoch(fixture.journal, &last_host, &installation, None, None, &[])?;
    assert!(!store_recovery_fenced.is_fenced());
    assert_eq!(active_rebind_recovery, ActivePhaseBRebindRecoveryKind::None);
    assert_ne!(reopened_host, last_host);
    assert_eq!(
        reopened_host.epoch.parent,
        Some(last_host.epoch.current.clone())
    );
    assert_eq!(reopened_generation, prior_generation.direct_child()?);
    let recovered = reopened.snapshot()?;
    assert!(recovered.activation.is_none());
    assert!(recovered.prior_kernel.is_some());
    Ok(())
}

#[cfg(windows)]
#[test]
fn production_reopen_fails_closed_on_unknown_prepared_append() -> TestResult {
    let fixture = active_readiness_fixture()?;
    let host = fixture.journal.snapshot()?.host;
    let activation = fixture
        .journal
        .snapshot()?
        .activation
        .ok_or_else(|| std::io::Error::other("test option invariant"))?;
    let backend = fixture.journal.into_backend()?;
    let mut faulted_backend = backend;
    faulted_backend.inject_fault(FaultPoint::CommitBeforeUnknown);
    let journal = HostStateJournalService::from_backend(faulted_backend, host.clone())?;
    let draining = transition_activation_record(
        &activation,
        ActivationState::ControlReady,
        "faulted-reopen-control-ready",
    )?;
    let append_result = append_reconciled(&journal, HostStateRecord::Activation(draining));
    assert!(
        matches!(
            &append_result,
            Err(HostError::Journal(JournalError::OutcomeUnknown { .. }))
        ),
        "unexpected fault result: {append_result:?}"
    );
    assert!(matches!(
        reopen_existing_epoch(journal, &host, &host.installation, None, None, &[],),
        Err(HostError::Journal(JournalError::OutcomeUnknown { .. }))
    ));
    Ok(())
}

#[cfg(windows)]
#[test]
fn unclean_reopen_allows_durable_active_rebind_retry_before_clean_marker() -> TestResult {
    let fixture = active_readiness_fixture()?;
    let durable = fixture.journal.snapshot()?;
    let last_host = durable.host;
    let installation = last_host.installation.clone();
    let handle =
        |value: &str| -> Result<PlatformHandle, TestError> { Ok(PlatformHandle::new(value)?) };
    let static_template = eliot_installation::HostPhaseBStaticTemplate {
        wire: handle("eliot.host.phase-b-template.v1")?,
        authority_id: handle("authority")?,
        record_id: handle("record")?,
        revision_policy_binding: handle("revision")?,
        contour_refs: vec![handle("contour")?],
    };
    let rebind = eliot_installation::ActivePhaseBRebind {
        intent: ActivePhaseBRebindIntent {
            wire: handle(ActivePhaseBRebindIntent::WIRE)?,
            transaction_id: handle("transaction")?,
            plan_digest: handle("plan")?,
            effect_id: handle("effect")?,
            manifest_digest: handle("manifest")?,
            prior_terminal_digest: handle("terminal")?,
            prior_phase_b_receipt_digest: handle("receipt")?,
            prior_host_epoch_lineage: handle("prior-lineage")?,
            prior_host_epoch_sequence: 1,
            prior_host_process_nonce_digest: handle(&"0".repeat(64))?,
            prior_host_owner_epoch: handle("prior-owner")?,
            prior_host_process_identity: handle(&"1".repeat(64))?,
            host_owner_epoch: handle("current-owner")?,
            host_process_identity: handle(&"2".repeat(64))?,
            host_process_nonce_digest: handle(&"3".repeat(64))?,
            host_epoch_lineage: handle("current-lineage")?,
            host_epoch_sequence: 2,
            activation_generation_lineage: handle("activation-lineage")?,
            activation_generation_sequence: 2,
            static_template,
            static_template_digest: handle("static-digest")?,
            request_digest: handle("request")?,
        },
        prepared: None,
        receipt: None,
        recovery_history: Vec::new(),
    };
    let (_, reopened_host, _, _, recovery_kind) = reopen_existing_epoch(
        fixture.journal,
        &last_host,
        &installation,
        None,
        Some(&rebind),
        &[],
    )?;
    assert_eq!(recovery_kind, ActivePhaseBRebindRecoveryKind::IntentOnly);
    assert_ne!(reopened_host, last_host);
    assert_eq!(
        reopened_host.epoch.parent,
        Some(last_host.epoch.current.clone())
    );
    Ok(())
}

#[cfg(windows)]
#[test]
fn production_host_journal_crash_retry_substitution_and_reset_negatives() -> TestResult {
    let production_path = std::env::temp_dir()
        .join(format!(
            "eliot-host-prod-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ))
        .join(HOST_JOURNAL_FILE_NAME);
    assert!(
        production_path
            .to_string_lossy()
            .contains(HOST_JOURNAL_FILE_NAME)
    );
    assert!(!HOST_JOURNAL_FILE_NAME.is_empty());
    let handle =
        |value: &str| -> Result<PlatformHandle, TestError> { Ok(PlatformHandle::new(value)?) };
    let static_template = eliot_installation::HostPhaseBStaticTemplate {
        wire: handle("eliot.host.phase-b-template.v1")?,
        authority_id: handle("authority")?,
        record_id: handle("record")?,
        revision_policy_binding: handle("revision")?,
        contour_refs: vec![handle("contour")?],
    };
    let prior = eliot_installation::PhaseBLiveBinding {
        manifest_digest: handle(&"f".repeat(64))?,
        authority_descriptor_digest: handle(&"a".repeat(64))?,
        store_bootstrap_descriptor_digest: handle(&"b".repeat(64))?,
        config_file_digest: handle(&"c".repeat(64))?,
        eliotd_descriptor_digest: handle(&"d".repeat(64))?,
        semantic_config_hash: handle(&"0".repeat(64))?,
        host_epoch_lineage: handle("prior-lineage")?,
        host_epoch_sequence: 1,
        host_process_nonce_digest: handle(&"0".repeat(64))?,
        receipt_digest: handle(&"1".repeat(64))?,
        effect_id: handle("effect")?,
        credential_receipt_digest: handle(&"2".repeat(64))?,
        request_digest: handle(&"3".repeat(64))?,
        host_owner_epoch: handle("prior-owner")?,
        host_process_identity: handle(&"4".repeat(64))?,
        public_receipt_digest: handle(&"e".repeat(64))?,
        provisioned_supervision_authority: test_provisioned_supervision_authority(
            "installation",
            "candidate",
            ResourceGeneration::genesis(),
        ),
        agent_bridge: None,
    };
    let fresh_intent = ActivePhaseBRebindIntent::new(
        handle(&"b".repeat(64))?,
        handle(&"c".repeat(64))?,
        handle("effect")?,
        handle(&"f".repeat(64))?,
        handle(&"a".repeat(64))?,
        &prior,
        handle("current-owner")?,
        handle(&"2".repeat(64))?,
        handle(&"3".repeat(64))?,
        handle("current-lineage")?,
        2,
        handle("activation-lineage")?,
        2,
        static_template.clone(),
    )?;
    assert!(fresh_intent.validate().is_ok());
    let stale_intent = ActivePhaseBRebindIntent::new(
        handle(&"b".repeat(64))?,
        handle(&"c".repeat(64))?,
        handle("effect")?,
        handle(&"f".repeat(64))?,
        handle(&"a".repeat(64))?,
        &prior,
        handle("current-owner")?,
        handle(&"2".repeat(64))?,
        handle(&"3".repeat(64))?,
        handle("current-lineage")?,
        1,
        handle("activation-lineage")?,
        2,
        static_template.clone(),
    );
    assert!(stale_intent.is_err());
    let reused = ActivePhaseBRebindIntent::new(
        handle(&"b".repeat(64))?,
        handle(&"c".repeat(64))?,
        handle("effect")?,
        handle(&"f".repeat(64))?,
        handle(&"a".repeat(64))?,
        &prior,
        handle("prior-owner")?,
        handle(&"2".repeat(64))?,
        handle(&"3".repeat(64))?,
        handle("current-lineage")?,
        2,
        handle("activation-lineage")?,
        2,
        static_template,
    );
    assert!(reused.is_err());
    let _ = production_path;
    Ok(())
}

#[cfg(windows)]
#[test]
fn host_owner_epoch_digest_is_bound_to_exact_direct_child_sequence() -> TestResult {
    let handle =
        |value: &str| -> Result<PlatformHandle, TestError> { Ok(PlatformHandle::new(value)?) };
    let installation = handle("owner-digest-sequence-installation")?;
    let parent = fresh_host_epoch(installation, None)?;
    let child = child_host_epoch(&parent)?;
    assert_eq!(parent.epoch.current.lineage, child.epoch.current.lineage);
    assert_eq!(parent.epoch.current.sequence, 1);
    assert_eq!(child.epoch.current.sequence, 2);
    assert_ne!(
        host_owner_epoch_digest(&parent)?,
        host_owner_epoch_digest(&child)?,
        "owner proof must not collapse same-lineage parent and direct child"
    );
    let mut overflow = parent;
    overflow.epoch.current.sequence = u64::MAX;
    assert!(
        child_host_epoch(&overflow).is_err(),
        "direct-child owner epoch minting must fail closed on sequence overflow"
    );
    Ok(())
}

#[test]
fn host_composition_production_field_is_the_redb_journal_service() {
    fn production_journal(
        composition: &HostComposition,
    ) -> &HostStateJournalService<RedbJournalBackend> {
        &composition.journal
    }
    let typed_reachability: fn(&HostComposition) -> &HostStateJournalService<RedbJournalBackend> =
        production_journal;
    assert_eq!(
        std::any::type_name_of_val(&typed_reachability),
        std::any::type_name::<fn(&HostComposition) -> &HostStateJournalService<RedbJournalBackend>>(
        )
    );
}

#[test]
fn open_activation_clean_stop_and_child_reopen_replay() -> TestResult {
    let host = test_host();
    let generation = root_epoch(fresh_identity("test-activation-lineage")?);
    let activation_id = fresh_identity("test-activation")?;
    let journal = HostStateJournalService::from_backend(MemoryBackend::default(), host.clone())
        .unwrap_or_else(|_| unreachable!());
    append_reconciled(
        &journal,
        HostStateRecord::Activation(initial_activation_record(
            &host,
            &activation_id,
            &generation,
            ActivationState::Stopped,
            "test-open",
        )?),
    )?;
    append_clean_marker(&journal, &host, &activation_id, &generation)?;
    let backend = journal.into_backend()?;

    let child = child_host_epoch(&host)?;
    let reopened = HostStateJournalService::from_backend(backend, child.clone())?;
    assert_eq!(reopened.snapshot()?.retained_epochs.len(), 1);
    let child_generation = generation.direct_child()?;
    let child_activation = fresh_identity("test-child-activation")?;
    append_reconciled(
        &reopened,
        HostStateRecord::Activation(initial_activation_record(
            &child,
            &child_activation,
            &child_generation,
            ActivationState::Stopped,
            "test-child-open",
        )?),
    )?;
    assert_eq!(reopened.snapshot()?.sequence, 1);
    assert!(reopened.snapshot()?.clean_marker.is_none());
    Ok(())
}

#[test]
fn unknown_commit_is_reconciled_by_transaction_identity() -> TestResult {
    let host = test_host();
    let generation = root_epoch(fresh_identity("unknown-lineage")?);
    let activation_id = fresh_identity("unknown-activation")?;
    let journal = HostStateJournalService::from_backend(
        MemoryBackend::with_fault(FaultPoint::CommitAfterUnknown),
        host.clone(),
    )?;
    append_reconciled(
        &journal,
        HostStateRecord::Activation(initial_activation_record(
            &host,
            &activation_id,
            &generation,
            ActivationState::Stopped,
            "unknown-open",
        )?),
    )?;
    assert_eq!(journal.snapshot()?.sequence, 1);
    Ok(())
}

#[test]
fn torn_current_epoch_fails_closed() -> TestResult {
    let host = test_host();
    let generation = root_epoch(fresh_identity("torn-lineage")?);
    let activation_id = fresh_identity("torn-activation")?;
    let journal = HostStateJournalService::from_backend(MemoryBackend::default(), host.clone())?;
    append_reconciled(
        &journal,
        HostStateRecord::Activation(initial_activation_record(
            &host,
            &activation_id,
            &generation,
            ActivationState::Stopped,
            "torn-open",
        )?),
    )?;
    let backend = journal.into_backend()?;
    let mut image = backend.durable_image().clone();
    image.epochs[0].bytes.pop();
    assert!(matches!(
        HostStateJournalService::from_backend(ImageBackend { image }, host),
        Err(JournalError::Torn { .. })
    ));
    Ok(())
}

#[test]
fn activation_failure_nonce_discriminator_revokes_only_pre_active_issuance() {
    let nonce = || {
        eliot_platform::KernelActivationNonce::new(
            PlatformHandle::new("a".repeat(64)).unwrap_or_else(|_| unreachable!()),
        )
        .unwrap_or_else(|_| unreachable!())
    };
    let unissued = OneTimeNonceState::unissued();
    assert_eq!(
        nonce_after_activation_failure(&unissued)
            .unwrap_or_else(|_| unreachable!())
            .state(),
        NonceState::Unissued
    );
    let issued = OneTimeNonceState::issued(nonce());
    assert_eq!(
        nonce_after_activation_failure(&issued)
            .unwrap_or_else(|_| unreachable!())
            .state(),
        NonceState::Revoked
    );
    let consumed = OneTimeNonceState::issued(nonce())
        .consume()
        .unwrap_or_else(|_| unreachable!());
    assert_eq!(
        nonce_after_activation_failure(&consumed)
            .unwrap_or_else(|_| unreachable!())
            .state(),
        NonceState::Consumed
    );
}

#[cfg(windows)]
#[test]
#[allow(
    clippy::too_many_lines,
    reason = "the regression constructs a real Active+Consumed record and drives stale, unknown, and recovered readiness admissions"
)]
fn reconciled_active_readiness_failure_preserves_contour_then_recovers() -> TestResult {
    let host = test_host();
    let activation_generation = root_epoch(fresh_identity("reconcile-activation-lineage")?);
    let activation_id = fresh_identity("reconcile-activation")?;
    let journal = HostStateJournalService::from_backend(MemoryBackend::default(), host.clone())?;
    append_reconciled(
        &journal,
        HostStateRecord::Activation(initial_activation_record(
            &host,
            &activation_id,
            &activation_generation,
            ActivationState::Starting,
            "reconcile-starting",
        )?),
    )?;

    let job_name = PlatformHandle::new("Local\\Eliot-Host-Kernel-reconcile")?;
    let kernel_image = "C:\\eliot\\eliot-kernel.exe".to_owned();
    let candidate = HostKernelCandidateBinding {
        installation_id: host.installation.clone(),
        host_epoch: AuthorityEpoch::new(host.epoch.current.sequence)?,
        kernel_epoch: AuthorityEpoch::new(2)?,
        activation_id: activation_id.clone(),
        artifact_hash: PlatformHandle::new("a".repeat(64))?,
        config_hash: PlatformHandle::new("c".repeat(64))?,
        job_object_id: job_name.clone(),
        pipe_identity: PlatformHandle::new(KERNEL_CONTROL_PIPE)?,
        host_process: HostProcessBinding {
            process_id: 7,
            start_time_100ns: 9,
            image_path: "C:\\eliot\\eliot-host.exe".to_owned(),
        },
        job_binding: HostJobBinding {
            job: eliot_kernel_service::HostJobIdentity {
                name: job_name.as_str().to_owned(),
            },
            root: eliot_kernel_service::HostJobRoot {
                process: HostProcessBinding {
                    process_id: 42,
                    start_time_100ns: 10,
                    image_path: kernel_image.clone(),
                },
                executable: eliot_kernel_service::HostFileIdentity {
                    volume_serial_number: 1,
                    file_index: 2,
                },
            },
        },
        supervision_incarnation: test_supervision_incarnation(
            host.installation.as_str(),
            activation_id.as_str(),
            host.epoch.current.lineage.as_str(),
            "reconcile-kernel-lineage",
        ),
        restart_budget: RestartBudget::new(1, 1)?,
        agent_bridge_admission: None,
        containment_action: None,
    };
    let durable_job = KernelJobBinding {
        job_name: job_name.clone(),
        owner: PlatformHandle::new("Kernel")?,
        root_pid: 42,
        root_start_time_100ns: 10,
        root_image_path: PlatformHandle::new(kernel_image.clone())?,
        root_volume_serial_number: 1,
        root_file_index: 2,
    };
    let kernel_generation = root_epoch(fresh_identity("reconcile-kernel-lineage")?);
    let mut driver = DurableKernelActivationDriver::bind_candidate(
        &journal,
        &host,
        &activation_id,
        &activation_generation,
        candidate.artifact_hash.clone(),
        candidate.pipe_identity.clone(),
        durable_job,
        PriorKernelDisposition::NoPriorKernel,
        kernel_generation,
        ServiceProcessRecord {
            process_id: "pid:42:start:10".to_owned(),
            owner: "Kernel".to_owned(),
            state: ServiceProcessState::Starting,
            health: HealthVector::healthy(),
            authority_epoch: candidate.kernel_epoch,
        },
    )?;
    driver.handoff_prepared()?;
    driver.prior_disposition_committed()?;
    let permit = driver.issue_nonce(&candidate, ResourceGeneration::genesis())?;
    driver.activating()?;
    let activation_receipt = KernelActivationReceipt::issue(&permit);
    let ready = KernelReadyReceipt {
        activation_id: activation_id.clone(),
        activation_operation_id: activation_receipt.operation_id.clone(),
        activation_nonce_digest: activation_receipt.activation_nonce_digest.clone(),
        process: eliot_kernel_service::ProcessObservation {
            process_id: PlatformHandle::new("pid:42:start:10")?,
            job_object_id: job_name,
            state: ServiceProcessState::Ready,
            health: HealthVector::healthy(),
            evidence_refs: vec![PlatformHandle::new("reconcile-process-evidence")?],
        },
        health: HealthVector::healthy(),
        evidence_refs: vec![PlatformHandle::new("reconcile-ready-evidence")?],
    };
    driver.active(&candidate, &activation_receipt, &ready)?;
    drop(driver);
    let active = journal
        .snapshot()?
        .kernel
        .ok_or_else(|| std::io::Error::other("test option invariant"))?;
    assert_eq!(active.state, KernelActivationState::Active);
    assert_eq!(active.one_time_nonce.state(), NonceState::Consumed);

    let kernel_artifact = candidate.artifact_hash.clone();
    let store_artifact = PlatformHandle::new("b".repeat(64))?;
    let config = candidate.config_hash.clone();
    let requirement = HostStoreBootstrapRequirement {
        route_identity: PlatformHandle::new(eliot_kernel_service::STORE_ROUTE_IDENTITY)?,
        canonical_pipe_identity: PlatformHandle::new(r"\\.\pipe\eliot\store-readiness")?,
        store_generation: ResourceGeneration::genesis(),
        state_fence: StateFence::new(candidate.kernel_epoch, ResourceGeneration::genesis()),
        launch_nonce: PlatformHandle::new("reconcile-store-launch")?,
        connection_id: PlatformHandle::new("reconcile-store-connection")?,
        expected_peer_sid: PlatformHandle::new("S-1-5-18")?,
        expected_peer_session_id: 0,
        approved_artifact_hash: store_artifact.clone(),
        approved_config_hash: config.clone(),
        timeout_ms: 5_000,
    };
    let fixture = ReadinessFixture {
        journal,
        candidate,
        activation: activation_receipt,
        requirement,
        kernel_artifact,
        store_artifact,
        config,
    };
    let contour = readiness_contour(&fixture)?;
    let mut gate = HostReadinessGate::with_cadence(ReadinessCadence::default());
    let now = std::time::Instant::now();
    let probes = std::cell::Cell::new(0_u8);

    let stale = reconcile_authenticated_readiness(&mut gate, Ok(contour.clone()), now, || {
        probes.set(probes.get() + 1);
        let (request, response, ready) =
            probe_exchange(&fixture, 0).map_err(|error| HostError::Platform(error.to_string()))?;
        validate_probe_response(&request, &fixture.activation, &response)?;
        let store_proof_fence = validated_store_proof_fence(
            &fixture.requirement,
            &ready,
            &fixture.store_artifact,
            &fixture.config,
            request.generation,
        )?;
        Ok(ReadinessContourIdentity {
            store_proof_fence: Some(store_proof_fence),
            ..contour.clone()
        })
    });
    assert_eq!(stale, HostBranchDisposition::ReadinessDegraded);
    assert_eq!(
        gate.last_failure(),
        Some(ReadinessFailureKind::ProbeRejected)
    );
    assert_eq!(probes.get(), 1);

    let throttled = reconcile_authenticated_readiness(
        &mut gate,
        Ok(contour.clone()),
        now + std::time::Duration::from_millis(250),
        || panic!("250ms liveness poll must not repeat authoritative readiness"),
    );
    assert_eq!(throttled, HostBranchDisposition::ReadinessDegraded);

    let unknown = reconcile_authenticated_readiness(
        &mut gate,
        Ok(contour.clone()),
        now + DEFAULT_READINESS_CADENCE,
        || {
            probes.set(probes.get() + 1);
            Err(HostError::Journal(JournalError::OutcomeUnknown {
                transaction_id: fresh_identity("readiness-unknown")?,
            }))
        },
    );
    assert_eq!(unknown, HostBranchDisposition::ReadinessDegraded);
    assert_eq!(
        gate.last_failure(),
        Some(ReadinessFailureKind::JournalOutcomeUnknown)
    );
    let retained = fixture
        .journal
        .snapshot()?
        .kernel
        .ok_or_else(|| std::io::Error::other("test option invariant"))?;
    assert_eq!(retained.state, KernelActivationState::Active);
    assert_eq!(retained.one_time_nonce.state(), NonceState::Consumed);
    assert!(
        fixture
            .journal
            .snapshot()?
            .readiness_observations
            .is_empty()
    );

    let recovered = reconcile_authenticated_readiness(
        &mut gate,
        Ok(contour),
        now + DEFAULT_READINESS_CADENCE + DEFAULT_READINESS_CADENCE,
        || {
            probes.set(probes.get() + 1);
            let proof = authenticated_proof(&fixture, 12)
                .map_err(|error| HostError::Platform(error.to_string()))?;
            append_authenticated_kernel_readiness(
                &fixture.journal,
                &proof,
                &fixture.kernel_artifact,
                &fixture.config,
                &test_published_supervision_identity()
                    .map_err(|error| HostError::Platform(error.to_string()))?,
            )?;
            readiness_contour(&fixture).map_err(|error| HostError::Platform(error.to_string()))
        },
    );
    assert_eq!(recovered, HostBranchDisposition::Healthy);
    assert_eq!(probes.get(), 3);
    let recovered_state = fixture.journal.snapshot()?;
    let recovered_kernel = recovered_state
        .kernel
        .ok_or_else(|| std::io::Error::other("test option invariant"))?;
    assert_eq!(recovered_kernel.state, KernelActivationState::Active);
    assert_eq!(
        recovered_kernel.one_time_nonce.state(),
        NonceState::Consumed
    );
    assert_eq!(recovered_state.readiness_observations.len(), 1);
    Ok(())
}

#[cfg(windows)]
#[test]
fn store_rebind_disposition_uses_exact_operation_and_request_identity() -> TestResult {
    let host = test_host();
    let activation_generation = root_epoch(fresh_identity("store-rebind-disposition")?);
    let activation_id = fresh_identity("store-rebind-disposition-activation")?;
    let journal = HostStateJournalService::from_backend(MemoryBackend::default(), host.clone())?;
    append_reconciled(
        &journal,
        HostStateRecord::Activation(initial_activation_record(
            &host,
            &activation_id,
            &activation_generation,
            ActivationState::Starting,
            "store-rebind-disposition-starting",
        )?),
    )?;
    let make_pending =
        |operation_id: &str, request_digest: &str| -> Result<StoreRebindRecord, TestError> {
            Ok(StoreRebindRecord {
                fence: record_fence(&host, &activation_id, &activation_generation),
                operation: operation(&format!("store-rebind:{operation_id}"))?,
                state: StoreRebindState::Pending,
                operation_id: PlatformHandle::new(operation_id)?,
                request_digest: PlatformHandle::new(request_digest)?,
                requirement: PlatformHandle::new("a".repeat(64))?,
                candidate_binding_digest: PlatformHandle::new("b".repeat(64))?,
                store_fence: PlatformHandle::new("c".repeat(64))?,
                process_id: 42,
                process_start_time_100ns: 7,
                process_image_path: PlatformHandle::new(r"C:\eliot\store.exe")?,
                job_name: PlatformHandle::new(r"Local\Eliot-Host-Store-disposition")?,
                generation: 1,
                authority_epoch: 1,
                receipt_request_digest: None,
                receipt_store_fence: None,
            })
        };
    let first = make_pending("store-rebind-first", &"d".repeat(64))?;
    let second = make_pending("store-rebind-second", &"e".repeat(64))?;
    append_reconciled(&journal, HostStateRecord::StoreRebind(first))?;
    append_reconciled(&journal, HostStateRecord::StoreRebind(second.clone()))?;

    persist_store_rebind_disposition(
        &journal,
        &second.operation_id,
        second.request_digest.as_str(),
        StoreRebindState::Unknown,
    )?;
    let state = journal.snapshot()?;
    assert_eq!(
        state
            .store_rebinds
            .iter()
            .find(|record| record.operation_id == second.operation_id)
            .ok_or_else(|| { std::io::Error::other("second rebind missing") })?
            .state,
        StoreRebindState::Unknown
    );
    assert_eq!(
        state
            .store_rebinds
            .iter()
            .find(|record| record.operation_id.as_str() == "store-rebind-first")
            .ok_or_else(|| { std::io::Error::other("first rebind missing") })?
            .state,
        StoreRebindState::Pending
    );

    let third = make_pending("store-rebind-third", &"f".repeat(64))?;
    append_reconciled(&journal, HostStateRecord::StoreRebind(third.clone()))?;
    let mut substituted_receipt = StoreRebindReceipt {
        operation_id: third.operation_id.clone(),
        request_digest: third.request_digest.as_str().to_owned(),
        requirement_digest: third.requirement.as_str().to_owned(),
        process_binding: StoreProcessBinding {
            process: HostProcessBinding {
                process_id: third.process_id,
                start_time_100ns: third.process_start_time_100ns,
                image_path: third.process_image_path.as_str().to_owned(),
            },
            job: third.job_name.clone(),
        },
        candidate_binding_digest: third.candidate_binding_digest.as_str().to_owned(),
        generation: ResourceGeneration::new(third.generation)?,
        authority_epoch: AuthorityEpoch::new(third.authority_epoch)?,
        store_fence: third.store_fence.as_str().to_owned(),
    };
    substituted_receipt.process_binding.process.process_id += 1;
    assert!(
        append_store_rebind_terminal(
            &journal,
            third,
            StoreRebindState::Committed,
            Some(&substituted_receipt),
        )
        .is_err()
    );
    Ok(())
}

#[cfg(windows)]
#[test]
fn durable_runtime_restart_physical_reopen_reconciles_exact_receipt_without_resend_and_pending_unknown()
-> TestResult {
    let root = std::env::temp_dir().join(format!(
        "eliot-host-runtime-restart-{}",
        uuid::Uuid::new_v4().simple()
    ));
    std::fs::create_dir_all(&root)?;
    let completed_mutation_digest = "aa".repeat(32);
    let pending_mutation_digest = "bb".repeat(32);
    let completed_request = HostRuntimeControlRequest::new_with_mutation_digest(
        HostRuntimeControlOperation::RestartKernel,
        PlatformHandle::new("completed-restart")?,
        PlatformHandle::new(completed_mutation_digest.clone())?,
    )?;
    let mut receipt = HostKernelRestartReceipt {
        mutation_digest: PlatformHandle::new(completed_mutation_digest.clone())?,
        request_digest: completed_request.request_digest.clone(),
        old_kernel_generation: PlatformHandle::new("a".repeat(64))?,
        new_kernel_generation: PlatformHandle::new("b".repeat(64))?,
        store_fence: PlatformHandle::new("c".repeat(64))?,
        activation_receipt_digest: PlatformHandle::new("d".repeat(64))?,
        ready_receipt_digest: PlatformHandle::new("e".repeat(64))?,
        receipt_digest: PlatformHandle::new("0".repeat(64))?,
    };
    receipt.receipt_digest = receipt.computed_digest()?;
    assert!(receipt.validate().is_ok());
    persist_runtime_restart_receipt(&root, &receipt)?;
    assert!(!has_runtime_restart_pending(
        &root,
        &completed_mutation_digest
    )?);
    let host = test_host();
    let pending_request = HostRuntimeControlRequest::new_with_mutation_digest(
        HostRuntimeControlOperation::RestartKernel,
        PlatformHandle::new("pending-restart")?,
        PlatformHandle::new(pending_mutation_digest.clone())?,
    )?;
    assert_eq!(
        persist_runtime_restart_pending(&root, &pending_request, &host)?,
        RuntimeRestartPendingPublication::Created
    );
    assert!(has_runtime_restart_pending(
        &root,
        &pending_mutation_digest
    )?);
    let stray_pending_path = runtime_restart_pending_path(&root, &completed_mutation_digest);
    assert!(
        !stray_pending_path.exists(),
        "completed receipt must delete pending"
    );
    let reopened = load_durable_runtime_restarts(&root)?;
    assert_eq!(
        reopened.len(),
        1,
        "receipt filter must not load pending as receipt"
    );
    let loaded = reopened
        .get(&completed_mutation_digest)
        .ok_or_else(|| std::io::Error::other("completed restart receipt missing"))?;
    assert_eq!(loaded.receipt_digest, receipt.receipt_digest);
    assert_eq!(loaded.mutation_digest.as_str(), completed_mutation_digest);
    let mut executor_calls = 0usize;
    let reconciled = if let Some(existing) = reopened.get(&completed_mutation_digest).cloned() {
        existing
    } else {
        executor_calls += 1;
        receipt.clone()
    };
    assert_eq!(executor_calls, 0);
    assert_eq!(reconciled.receipt_digest, receipt.receipt_digest);
    assert!(!reopened.contains_key(&pending_mutation_digest));
    let pending_is_unknown = has_runtime_restart_pending(&root, &pending_mutation_digest)?
        && !reopened.contains_key(&pending_mutation_digest);
    assert!(pending_is_unknown, "pending-only must remain Unknown");
    let pending_reconcile = if reopened.contains_key(&pending_mutation_digest) {
        "Restarted"
    } else if has_runtime_restart_pending(&root, &pending_mutation_digest)? {
        "Unknown"
    } else {
        "Missing"
    };
    assert_eq!(pending_reconcile, "Unknown");
    let fake_receipt_bytes = serde_json::to_vec(&receipt)?;
    let wrong_name_path = runtime_restart_receipt_path(&root, "cc".repeat(32).as_str());
    std::fs::write(wrong_name_path, &fake_receipt_bytes)?;
    assert!(load_durable_runtime_restarts(&root).is_err());
    let _ = std::fs::remove_dir_all(&root);
    Ok(())
}

#[cfg(windows)]
#[test]
fn durable_runtime_restart_pending_is_no_replace_and_exactly_bound() -> TestResult {
    let root = std::env::temp_dir().join(format!(
        "eliot-host-runtime-restart-pending-{}",
        uuid::Uuid::new_v4().simple()
    ));
    std::fs::create_dir_all(&root)?;
    let host = test_host();
    let mutation_digest = PlatformHandle::new("d1".repeat(32))?;
    let request = HostRuntimeControlRequest::new_with_mutation_digest(
        HostRuntimeControlOperation::RestartKernel,
        PlatformHandle::new("pending-exact")?,
        mutation_digest.clone(),
    )?;
    assert_eq!(
        persist_runtime_restart_pending(&root, &request, &host)?,
        RuntimeRestartPendingPublication::Created
    );
    let path = runtime_restart_pending_path(&root, mutation_digest.as_str());
    let before = std::fs::read(&path)?;
    assert_eq!(
        persist_runtime_restart_pending(&root, &request, &host)?,
        RuntimeRestartPendingPublication::Replay
    );
    assert_eq!(std::fs::read(&path)?, before);
    assert!(
        std::fs::read_dir(runtime_restart_store_dir(&root))?
            .flatten()
            .all(
                |entry| !entry.file_name().to_string_lossy().contains(".pending.")
                    || entry.path() == path
            )
    );

    std::fs::write(&path, br"{malformed")?;
    let malformed_before = std::fs::read(&path)?;
    let malformed = persist_runtime_restart_pending(&root, &request, &host);
    assert!(matches!(malformed, Err(HostError::RecoveryRequired(_))));
    assert_eq!(std::fs::read(&path)?, malformed_before);

    std::fs::remove_file(&path)?;
    assert_eq!(
        persist_runtime_restart_pending(&root, &request, &host)?,
        RuntimeRestartPendingPublication::Created
    );
    let exact_before_conflict = std::fs::read(&path)?;

    let conflict_request = HostRuntimeControlRequest::new_with_mutation_digest(
        HostRuntimeControlOperation::RestartKernel,
        PlatformHandle::new("pending-conflict")?,
        mutation_digest,
    )?;
    let conflict = persist_runtime_restart_pending(&root, &conflict_request, &host);
    assert!(matches!(conflict, Err(HostError::RecoveryRequired(_))));
    assert_eq!(std::fs::read(&path)?, exact_before_conflict);
    let _ = std::fs::remove_dir_all(&root);
    Ok(())
}

#[cfg(windows)]
#[test]
fn durable_runtime_restart_pending_rejects_unknown_fields_digest_flip_query_and_zero_epoch()
-> TestResult {
    let root = std::env::temp_dir().join(format!(
        "eliot-host-runtime-restart-pending-shape-{}",
        uuid::Uuid::new_v4().simple()
    ));
    std::fs::create_dir_all(&root)?;
    let host = test_host();
    let mutation_digest = PlatformHandle::new("e1".repeat(32))?;
    let request = HostRuntimeControlRequest::new_with_mutation_digest(
        HostRuntimeControlOperation::RestartKernel,
        PlatformHandle::new("pending-shape")?,
        mutation_digest.clone(),
    )?;
    assert_eq!(
        persist_runtime_restart_pending(&root, &request, &host)?,
        RuntimeRestartPendingPublication::Created
    );
    let path = runtime_restart_pending_path(&root, mutation_digest.as_str());
    let original_bytes = std::fs::read(&path)?;
    let original = serde_json::from_slice::<serde_json::Value>(&original_bytes)?;

    let mut unknown_field = original.clone();
    unknown_field["unexpected"] = serde_json::Value::Bool(true);
    let mut operation_flip = original.clone();
    operation_flip["operation"] = serde_json::Value::String("RECONCILE_KERNEL_RESTART".to_owned());
    let mut digest_flip = original.clone();
    digest_flip["request_digest"] = serde_json::Value::String("0".repeat(64));
    let mut epoch_zero = original.clone();
    epoch_zero["host_epoch"] = serde_json::Value::Number(0.into());
    let mut mutation_flip = original;
    mutation_flip["mutation_digest"] = serde_json::Value::String("f".repeat(64));

    for candidate in [
        unknown_field,
        operation_flip,
        digest_flip,
        epoch_zero,
        mutation_flip,
    ] {
        let bytes = serde_json::to_vec(&candidate)?;
        std::fs::write(&path, &bytes)?;
        let result = persist_runtime_restart_pending(&root, &request, &host);
        assert!(matches!(result, Err(HostError::RecoveryRequired(_))));
        assert_eq!(std::fs::read(&path)?, bytes);
        std::fs::write(&path, &original_bytes)?;
    }

    let reconcile = HostRuntimeControlRequest::new_reconcile(
        PlatformHandle::new("pending-query")?,
        mutation_digest,
    )?;
    let result = persist_runtime_restart_pending(&root, &reconcile, &host);
    assert!(matches!(result, Err(HostError::RecoveryRequired(_))));
    assert_eq!(std::fs::read(&path)?, original_bytes);
    let _ = std::fs::remove_dir_all(&root);
    Ok(())
}

#[cfg(windows)]
#[test]
fn durable_runtime_restart_receipt_loader_is_fail_closed_before_adoption_or_restart() -> TestResult
{
    let root = std::env::temp_dir().join(format!(
        "eliot-host-runtime-restart-loader-{}",
        uuid::Uuid::new_v4().simple()
    ));
    std::fs::create_dir_all(&root)?;
    let mutation_digest = "a1".repeat(32);
    let request = HostRuntimeControlRequest::new_with_mutation_digest(
        HostRuntimeControlOperation::RestartKernel,
        PlatformHandle::new("loader-restart")?,
        PlatformHandle::new(mutation_digest.clone())?,
    )?;
    let mut receipt = HostKernelRestartReceipt {
        mutation_digest: request.mutation_digest.clone(),
        request_digest: request.request_digest.clone(),
        old_kernel_generation: PlatformHandle::new("b".repeat(64))?,
        new_kernel_generation: PlatformHandle::new("c".repeat(64))?,
        store_fence: PlatformHandle::new("d".repeat(64))?,
        activation_receipt_digest: PlatformHandle::new("e".repeat(64))?,
        ready_receipt_digest: PlatformHandle::new("f".repeat(64))?,
        receipt_digest: PlatformHandle::new("0".repeat(64))?,
    };
    receipt.receipt_digest = receipt.computed_digest()?;
    persist_runtime_restart_receipt(&root, &receipt)?;
    let exact_path = runtime_restart_receipt_path(&root, &mutation_digest);
    let exact_bytes = std::fs::read(&exact_path)?;
    let mut physical_restart_calls = 0usize;
    let adopt_or_restart = |calls: &mut usize| {
        let loaded = load_durable_runtime_restarts(&root);
        if let Ok(records) = loaded
            && !records.contains_key(&mutation_digest)
        {
            *calls += 1;
        }
    };
    adopt_or_restart(&mut physical_restart_calls);
    assert_eq!(physical_restart_calls, 0, "valid receipt is adopted");

    std::fs::write(&exact_path, br"{malformed")?;
    assert!(load_durable_runtime_restarts(&root).is_err());
    adopt_or_restart(&mut physical_restart_calls);
    assert_eq!(
        physical_restart_calls, 0,
        "malformed receipt fences admission"
    );
    std::fs::write(&exact_path, &exact_bytes)?;

    let wrong_name = runtime_restart_store_dir(&root).join("not-a-digest.receipt.json");
    std::fs::write(&wrong_name, &exact_bytes)?;
    assert!(load_durable_runtime_restarts(&root).is_err());
    adopt_or_restart(&mut physical_restart_calls);
    assert_eq!(
        physical_restart_calls, 0,
        "wrong-name receipt fences admission"
    );
    std::fs::remove_file(&wrong_name)?;

    let duplicate_name = runtime_restart_receipt_path(&root, &"b2".repeat(32));
    std::fs::write(&duplicate_name, &exact_bytes)?;
    assert!(load_durable_runtime_restarts(&root).is_err());
    adopt_or_restart(&mut physical_restart_calls);
    assert_eq!(
        physical_restart_calls, 0,
        "conflicting duplicate fences admission"
    );
    let _ = std::fs::remove_dir_all(&root);
    Ok(())
}

#[cfg(all(windows, test))]
#[test]
#[allow(
    clippy::too_many_lines,
    reason = "the regression drives the real redb reopen path with exact outer, termination, and inner durable records"
)]
fn store_recovery_committed_inner_crash_reopens_as_fenced_unknown_without_child_epoch() -> TestResult
{
    let root = std::env::temp_dir().join(format!(
        "eliot-host-store-recovery-open-{}",
        uuid::Uuid::new_v4().simple()
    ));
    std::fs::create_dir_all(&root)?;
    let journal_path = root.join(HOST_JOURNAL_FILE_NAME);
    let host = fresh_host_epoch(
        PlatformHandle::new("store-recovery-physical-installation")?,
        None,
    )?;
    let activation_generation = root_epoch(fresh_identity("store-recovery-physical-generation")?);
    let activation_id = fresh_identity("store-recovery-physical-activation")?;
    let backend = RedbJournalBackend::open_unprotected_for_test(&journal_path)?;
    let journal = HostStateJournalService::from_backend(backend, host.clone())?;
    append_reconciled(
        &journal,
        HostStateRecord::Activation(initial_activation_record(
            &host,
            &activation_id,
            &activation_generation,
            ActivationState::Starting,
            "store-recovery-physical-starting",
        )?),
    )?;

    let mutation_digest = PlatformHandle::new("a7".repeat(32))?;
    let request = HostRuntimeControlRequest::new_with_mutation_digest(
        HostRuntimeControlOperation::RecoverStore,
        PlatformHandle::new("store-recovery-physical-request")?,
        mutation_digest.clone(),
    )?;
    assert_eq!(
        persist_store_recovery_pending(&root, &request, &host)?,
        StoreRecoveryPendingPublication::Created
    );
    let termination = StoreRecoveryTerminationEvidence {
        wire: request.wire.as_str().to_owned(),
        operation: request.operation.clone(),
        request_id: request.request_id.as_str().to_owned(),
        mutation_digest: request.mutation_digest.as_str().to_owned(),
        request_digest: request.request_digest.as_str().to_owned(),
        host_epoch: host.epoch.current.sequence,
        host_lineage: host.epoch.current.lineage.as_str().to_owned(),
        process_id: 4_101,
        process_start_time_100ns: 41_010,
        process_image_path: r"C:\Eliot\store-old.exe".to_owned(),
        job_name: r"Local\Eliot-Store-old".to_owned(),
        job_empty: true,
        root_reaped: true,
        restart_attempt: 1,
    };
    termination.validate_for_digest(mutation_digest.as_str())?;
    std::fs::write(
        store_recovery_termination_path(&root, mutation_digest.as_str()),
        serde_json::to_vec(&termination)?,
    )?;

    let generation = ResourceGeneration::genesis();
    let authority_epoch = AuthorityEpoch::genesis();
    let requirement = HostStoreBootstrapRequirement {
        route_identity: PlatformHandle::new(eliot_kernel_service::STORE_ROUTE_IDENTITY)?,
        canonical_pipe_identity: PlatformHandle::new(r"\\.\pipe\eliot\store")?,
        store_generation: generation,
        state_fence: StateFence::new(authority_epoch, generation),
        launch_nonce: PlatformHandle::new("store-recovery-physical-nonce")?,
        connection_id: PlatformHandle::new("store-recovery-physical-connection")?,
        expected_peer_sid: PlatformHandle::new("S-1-5-18")?,
        expected_peer_session_id: 0,
        approved_artifact_hash: PlatformHandle::new("b".repeat(64))?,
        approved_config_hash: PlatformHandle::new("c".repeat(64))?,
        timeout_ms: 5_000,
    };
    let process_binding = StoreProcessBinding {
        process: HostProcessBinding {
            process_id: 4_202,
            start_time_100ns: 42_020,
            image_path: r"C:\Eliot\store-new.exe".to_owned(),
        },
        job: PlatformHandle::new(r"Local\Eliot-Store-new")?,
    };
    let mut handoff = StoreRebindHandoff {
        operation_id: PlatformHandle::new("store-recovery-physical-inner")?,
        request_digest: "0".repeat(64),
        requirement: requirement.clone(),
        process_binding: process_binding.clone(),
        candidate_binding_digest: "d".repeat(64),
        generation,
        authority_epoch,
        store_fence: "e".repeat(64),
    };
    handoff.request_digest = handoff.canonical_request_digest()?;
    handoff.validate_canonical_digest()?;
    persist_store_recovery_inner_binding(&root, &request, &host, &handoff)?;
    assert_eq!(
        persist_store_recovery_pending(&root, &request, &host)?,
        StoreRecoveryPendingPublication::Replay
    );
    persist_store_recovery_inner_binding(&root, &request, &host, &handoff)?;
    let pending_inner = StoreRebindRecord {
        fence: record_fence(&host, &activation_id, &activation_generation),
        operation: operation("store-recovery-physical-inner-pending")?,
        state: StoreRebindState::Pending,
        operation_id: handoff.operation_id.clone(),
        request_digest: PlatformHandle::new(handoff.request_digest.clone())?,
        requirement: PlatformHandle::new(sha256_json(&requirement)?)?,
        candidate_binding_digest: PlatformHandle::new(handoff.candidate_binding_digest.clone())?,
        store_fence: PlatformHandle::new(handoff.store_fence.clone())?,
        process_id: process_binding.process.process_id,
        process_start_time_100ns: process_binding.process.start_time_100ns,
        process_image_path: PlatformHandle::new(process_binding.process.image_path.clone())?,
        job_name: process_binding.job.clone(),
        generation: generation.value(),
        authority_epoch: authority_epoch.value(),
        receipt_request_digest: None,
        receipt_store_fence: None,
    };
    append_reconciled(
        &journal,
        HostStateRecord::StoreRebind(pending_inner.clone()),
    )?;
    let mut committed_inner = pending_inner;
    committed_inner.operation = operation("store-recovery-physical-inner-commit")?;
    committed_inner.state = StoreRebindState::Committed;
    committed_inner.receipt_request_digest = Some(committed_inner.request_digest.clone());
    committed_inner.receipt_store_fence = Some(committed_inner.store_fence.clone());
    append_reconciled(
        &journal,
        HostStateRecord::StoreRebind(committed_inner.clone()),
    )?;

    let fences = load_durable_store_recoveries(&root)?;
    assert_eq!(fences.len(), 1);
    let physical_snapshot = journal.snapshot()?;
    fences[0].validate_for_reopen(&host, &physical_snapshot)?;
    let mut substituted = fences[0].clone();
    substituted
        .inner
        .as_mut()
        .ok_or_else(|| std::io::Error::other("test option invariant"))?
        .request_digest = "f".repeat(64);
    assert!(
        substituted
            .validate_for_reopen(&host, &physical_snapshot)
            .is_err()
    );
    drop(journal);

    let reopened_backend = RedbJournalBackend::open_unprotected_for_test(&journal_path)?;
    let (reopened, reopened_host, _, _, startup_fenced, active_rebind_recovery) =
        open_production_epoch_from_backend(
            reopened_backend,
            host.installation.clone(),
            None,
            None,
            &fences,
        )?;
    assert!(startup_fenced.is_fenced());
    assert_eq!(active_rebind_recovery, ActivePhaseBRebindRecoveryKind::None);
    assert_eq!(
        reopened_host.epoch.current, host.epoch.current,
        "fenced startup must retain the exact pre-crash host identity"
    );
    assert_eq!(
        reopened_host.epoch.parent, host.epoch.parent,
        "fenced startup must not create a child host epoch"
    );
    let reopened_state = reopened.snapshot()?;
    assert_eq!(
        reopened_state
            .activation
            .as_ref()
            .map(|record| record.state),
        Some(ActivationState::Starting),
        "fenced startup retains the exact pre-crash activation until reconciliation"
    );
    assert!(reopened_state.readiness_observations.is_empty());
    assert_eq!(
        reopened_state.store_rebinds, physical_snapshot.store_rebinds,
        "fenced startup must not append a second Store rebind record"
    );
    drop(reopened);
    let _ = std::fs::remove_dir_all(&root);
    Ok(())
}

#[cfg(all(windows, test))]
#[test]
#[allow(
    clippy::too_many_lines,
    reason = "the feature-gated regression carries physical redb epoch/rebind recovery through the production Host composition"
)]
fn production_bound_active_phase_b_receipt_recovery_uses_physical_cas() -> TestResult {
    let (mut manifest, root) = liveness_manifest_with_distinct_store_digests()?;
    let portable = root.join("portable");
    let portable_lease = UserOwnedRootLease::open_existing(&portable)?;
    let installation = manifest
        .runtime_launch
        .installation_epoch
        .installation
        .clone();
    let journal_path = portable.join("host-state-journal.redb");
    let registry_path = portable.join("installation-registry.redb");

    let (root_journal, root_host, root_activation_generation, root_activation_id, root_kind) =
        open_test_support_epoch(&journal_path, installation.clone(), None, None)?;
    assert_eq!(root_kind, ActivePhaseBRebindRecoveryKind::None);
    append_clean_marker(
        &root_journal,
        &root_host,
        &root_activation_id,
        &root_activation_generation,
    )?;
    drop(root_journal);

    let (first_journal, first_host, first_activation_generation, first_activation_id, first_kind) =
        open_test_support_epoch(&journal_path, installation.clone(), None, None)?;
    assert_eq!(first_kind, ActivePhaseBRebindRecoveryKind::None);
    assert_eq!(
        first_host.epoch.parent,
        Some(root_host.epoch.current.clone())
    );
    let descriptor_generation = manifest.runtime_launch.authority_generation;
    materialize_descriptor_bound_host_fixture(&mut manifest, &first_host, descriptor_generation)?;

    // Keep the candidate in its real Phase-A state. Host's first
    // publication is the only operation allowed to turn these markers
    // into physical Phase-B authority bytes.
    let pending_phase_b = PlatformHandle::new(PHASE_B_PENDING_MARKER)?;
    let supervision_lease_scope_id =
        PlatformHandle::new(manifest.runtime_launch.supervision_lease_scope_id())?;
    manifest.runtime_launch.authority_descriptor_digest = pending_phase_b.clone();
    manifest.runtime_launch.store_bootstrap_descriptor_digest = pending_phase_b.clone();
    manifest.runtime_launch.supervision_authority =
        eliot_installation::SupervisionAuthorityBinding::Pending {
            supervision_lease_scope_id,
        };
    manifest.runtime_launch.kernel_arguments[5] = pending_phase_b.clone();
    manifest.runtime_launch.kernel_arguments[9] = pending_phase_b;
    manifest.runtime_launch.descriptor_digest =
        PlatformHandle::new(manifest.runtime_launch.compute_digest()?)?;
    let config_path = Path::new(manifest.config_path.as_str());
    let mut config = serde_json::from_slice::<serde_json::Value>(&std::fs::read(config_path)?)?;
    config["runtime_launch"] = serde_json::to_value(&manifest.runtime_launch)?;
    config["approved_config_hash"] =
        serde_json::Value::String(STORE_SEMANTIC_CONFIG_HASH_PENDING.to_owned());
    let semantic_config_hash = semantic_store_config_hash_from_json(&serde_json::to_vec(&config)?)?;
    config["approved_config_hash"] =
        serde_json::Value::String(semantic_config_hash.as_str().to_owned());
    let config_bytes = serde_json::to_vec(&config)?;
    manifest.config_digest = PlatformHandle::new(format!("{:x}", Sha256::digest(&config_bytes)))?;
    std::fs::write(config_path, config_bytes)?;
    std::fs::remove_file(Path::new(
        manifest
            .runtime_launch
            .store_bootstrap_descriptor_path
            .as_str(),
    ))?;
    manifest.validate()?;

    let handle = |value: String| PlatformHandle::new(value).unwrap_or_else(|_| unreachable!());
    let mut prior = active_startup_prior_binding(
        &manifest,
        &first_host.epoch.current.lineage,
        first_host.epoch.current.sequence - 1,
    );
    prior.authority_descriptor_digest = handle("9".repeat(64));
    prior.store_bootstrap_descriptor_digest = handle("8".repeat(64));
    let commit_fence = ActivationCommitFence {
        generation: manifest.generation.clone(),
        config_digest: manifest.config_digest.clone(),
        materialized_config_digest: prior.config_file_digest.clone(),
        phase_b_live_binding: Some(prior.clone()),
        authority_generation: manifest.runtime_launch.authority_generation,
        authority_state_fence: manifest.runtime_launch.authority_state_fence.clone(),
        active_kernel_record_checksum: handle("a".repeat(64)),
        probe_request_digest: handle("b".repeat(64)),
        ready_receipt_digest: handle("c".repeat(64)),
        store_proof_fence: handle("store-proof:physical-test".to_owned()),
        candidate_binding_digest: handle("d".repeat(64)),
        store_requirement_digest: handle("e".repeat(64)),
        readiness_sequence: 1,
        readiness_journal_checksum: handle("f".repeat(64)),
    };
    let transaction_id = handle("transaction:physical-phase-b".to_owned());
    let plan_digest = handle("8".repeat(64));
    let owner_lease = HostOwnerLease::acquire(&installation)?;
    let registry_store = RedbInstallationRegistry::open_test_support(&registry_path)?;
    registry_store.seed_active_generation_for_test_support(
        &owner_lease.activation_capability(),
        &manifest,
        &transaction_id,
        &plan_digest,
        &commit_fence,
    )?;
    let registry = registry_store.load()?;
    let launch_options = HostLaunchOptions {
        config_descriptor_path: PathBuf::from(
            manifest.runtime_launch.authority_descriptor_path.as_str(),
        ),
        config_descriptor_digest: phase_b_scm_selector(
            &manifest.runtime_launch.authority_descriptor_digest,
        )?,
        installation: installation.clone(),
        transaction_plan_generation: manifest.runtime_launch.authority_generation.value(),
        host_state_root: PathBuf::from(
            manifest
                .runtime_launch
                .runtime_state_roots
                .host_state_root
                .as_str(),
        ),
        registration_nonce: None,
    };
    assert_eq!(
        HostComposition::production_store_rebind_discriminator(),
        HOST_STORE_REBIND_PRODUCTION_DISCRIMINATOR
    );
    let build_composition = |journal: ProductionHostStateJournal,
                             registry_store: RedbInstallationRegistry,
                             registry: ApprovedGenerationRegistry,
                             launch_options: HostLaunchOptions,
                             host: HostInstallationEpoch,
                             activation_generation: EpochTransition,
                             activation_id: PlatformHandle,
                             owner_lease: HostOwnerLease|
     -> Result<HostComposition, WindowsAdapterError> {
        let jobs = HostJobBranches::new_test_support(&host)?;
        Ok(HostComposition {
            store_rebind_boundary: HostStoreRebindProductionBoundary,
            runtime_control_boundary: HostRuntimeControlProductionBoundary,
            journal,
            registry_store,
            registry,
            launch_options,
            host,
            activation_generation,
            activation_id,
            running: true,
            jobs,
            readiness_gate: HostReadinessGate::with_cadence(ReadinessCadence::default()),
            phase_b: None,
            runtime_restarts: std::collections::HashMap::new(),
            runtime_control_queue: std::sync::Arc::new(std::sync::Mutex::new(
                std::collections::VecDeque::new(),
            )),
            store_recovery_startup_fence: StoreRecoveryStartupFence::Clear,
            active_phase_b_rebind_recovery: ActivePhaseBRebindRecoveryKind::None,
            owner_lease,
            pending_record: None,
            durable_finalized: false,
            owner_released: false,
            shutdown_failed: false,
        })
    };
    let mut first = build_composition(
        first_journal,
        registry_store,
        registry,
        launch_options.clone(),
        first_host.clone(),
        first_activation_generation,
        first_activation_id,
        owner_lease,
    )?;
    let first_active = first
        .registry
        .active()
        .cloned()
        .ok_or_else(|| std::io::Error::other("test option invariant"))?;
    first.rebind_active_phase_b(&first_active, ActivePhaseBRebindRecoveryKind::None)?;
    assert!(first.jobs.kernel.is_none());
    assert!(first.jobs.store.is_none());
    let first_rebind = first
        .registry
        .active_phase_b_rebind()
        .cloned()
        .ok_or_else(|| std::io::Error::other("test option invariant"))?;
    let first_receipt = first_rebind
        .receipt
        .clone()
        .ok_or_else(|| std::io::Error::other("test option invariant"))?;
    assert!(
        ActivePhaseBRebindRecovery::new(
            &first_rebind,
            first_receipt.host_owner_epoch.clone(),
            first_receipt.host_process_identity.clone(),
            first_receipt.host_process_nonce_digest.clone(),
            first_receipt.host_epoch_lineage.clone(),
            first_receipt.host_epoch_sequence + 1,
        )
        .is_err(),
        "the old owner/nonce/process cannot authorize a direct-child recovery"
    );
    drop(first);

    // The journal's destination bytes are not an adoption authority when
    // the registry lifecycle is not supplied to reopen.
    let destination_only = open_test_support_epoch(&journal_path, installation.clone(), None, None);
    assert!(matches!(
        destination_only,
        Err(HostError::OwnerLeaseRecovery(_))
    ));

    let registry_after_store = RedbInstallationRegistry::open_test_support(&registry_path)?;
    let registry_after = registry_after_store.load()?;
    let active_rebind_after_crash = registry_after
        .active_phase_b_rebind()
        .cloned()
        .ok_or_else(|| std::io::Error::other("test option invariant"))?;
    drop(registry_after_store);
    let (
        second_journal,
        second_host,
        second_activation_generation,
        second_activation_id,
        second_kind,
    ) = open_test_support_epoch(
        &journal_path,
        installation.clone(),
        None,
        Some(&active_rebind_after_crash),
    )?;
    assert_eq!(
        second_kind,
        ActivePhaseBRebindRecoveryKind::CompletedReceipt
    );
    assert_eq!(
        second_host.epoch.parent,
        Some(first_host.epoch.current.clone())
    );
    let recovery_owner_lease = HostOwnerLease::acquire(&installation)?;
    let recovery_registry_store = RedbInstallationRegistry::open_test_support(&registry_path)?;
    let recovery_registry = recovery_registry_store.load()?;
    let mut second = build_composition(
        second_journal,
        recovery_registry_store,
        recovery_registry,
        launch_options,
        second_host,
        second_activation_generation,
        second_activation_id,
        recovery_owner_lease,
    )?;
    let second_active = second
        .registry
        .active()
        .cloned()
        .ok_or_else(|| std::io::Error::other("test option invariant"))?;
    second.rebind_active_phase_b(&second_active, second_kind)?;
    assert!(second.jobs.kernel.is_none());
    assert!(second.jobs.store.is_none());
    let current_rebind = second
        .registry
        .active_phase_b_rebind()
        .cloned()
        .ok_or_else(|| std::io::Error::other("test option invariant"))?;
    assert_eq!(current_rebind.recovery_history.len(), 1);
    assert_eq!(
        current_rebind.recovery_history[0].prior_receipt,
        first_receipt
    );
    let current_receipt = current_rebind
        .receipt
        .clone()
        .ok_or_else(|| std::io::Error::other("test option invariant"))?;
    assert_ne!(
        current_receipt.host_owner_epoch,
        first_receipt.host_owner_epoch
    );
    assert_ne!(
        current_receipt.host_process_identity,
        first_receipt.host_process_identity
    );
    assert_ne!(
        current_receipt.host_process_nonce_digest,
        first_receipt.host_process_nonce_digest
    );
    let file_digest = |path: &Path| -> std::io::Result<String> {
        Ok(format!("{:x}", Sha256::digest(std::fs::read(path)?)))
    };
    assert_eq!(
        file_digest(Path::new(
            manifest.runtime_launch.authority_descriptor_path.as_str(),
        ))?,
        current_receipt.authority_descriptor_digest.as_str()
    );
    assert_eq!(
        file_digest(Path::new(manifest.config_path.as_str()))?,
        current_receipt.config_file_digest.as_str()
    );
    assert_eq!(
        file_digest(Path::new(
            manifest
                .runtime_launch
                .store_bootstrap_descriptor_path
                .as_str(),
        ))?,
        current_receipt.store_bootstrap_descriptor_digest.as_str()
    );
    assert_eq!(
        file_digest(Path::new(
            manifest.runtime_launch.eliotd_descriptor_path.as_str(),
        ))?,
        current_receipt.eliotd_descriptor_digest.as_str()
    );

    let before = [
        std::fs::read(Path::new(
            manifest.runtime_launch.authority_descriptor_path.as_str(),
        ))?,
        std::fs::read(Path::new(manifest.config_path.as_str()))?,
        std::fs::read(Path::new(
            manifest
                .runtime_launch
                .store_bootstrap_descriptor_path
                .as_str(),
        ))?,
        std::fs::read(Path::new(
            manifest.runtime_launch.eliotd_descriptor_path.as_str(),
        ))?,
    ];
    second.rebind_active_phase_b(&second_active, ActivePhaseBRebindRecoveryKind::None)?;
    let retry_receipt = second
        .registry
        .active_phase_b_rebind()
        .and_then(|rebind| rebind.receipt.as_ref())
        .ok_or_else(|| std::io::Error::other("retry receipt missing"))?;
    assert_eq!(retry_receipt.receipt_digest, current_receipt.receipt_digest);
    let after = [
        std::fs::read(Path::new(
            manifest.runtime_launch.authority_descriptor_path.as_str(),
        ))?,
        std::fs::read(Path::new(manifest.config_path.as_str()))?,
        std::fs::read(Path::new(
            manifest
                .runtime_launch
                .store_bootstrap_descriptor_path
                .as_str(),
        ))?,
        std::fs::read(Path::new(
            manifest.runtime_launch.eliotd_descriptor_path.as_str(),
        ))?,
    ];
    assert_eq!(before, after);
    drop(second);
    drop(portable_lease);
    std::fs::remove_dir_all(root)?;
    Ok(())
}
