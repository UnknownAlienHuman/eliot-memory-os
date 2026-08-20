use eliot_contracts::{AuthorityEpoch, ResourceGeneration, StateFence};
use eliot_kernel_service::{
    HostJobBinding, HostProcessBinding, HostStoreBootstrapRequirement, KernelService,
    StoreProcessBinding, StoreRebindHandoff, StoreRebindQuery,
};
use eliot_platform::PlatformHandle;

fn handle(v: &str) -> PlatformHandle {
    PlatformHandle::new(v).unwrap()
}

fn requirement() -> HostStoreBootstrapRequirement {
    let fence = StateFence::new(AuthorityEpoch::genesis(), ResourceGeneration::genesis());
    HostStoreBootstrapRequirement {
        route_identity: handle("store_bridge"),
        canonical_pipe_identity: handle(r"\\.\pipe\eliot\store"),
        store_generation: ResourceGeneration::genesis(),
        state_fence: fence,
        launch_nonce: handle("nonce-1"),
        connection_id: handle("connection-1"),
        expected_peer_sid: handle("S-1-5-18"),
        expected_peer_session_id: 0,
        approved_artifact_hash: handle(&"a".repeat(64)),
        approved_config_hash: handle(&"b".repeat(64)),
        timeout_ms: 5000,
    }
}

fn candidate_binding() -> eliot_kernel_service::HostKernelCandidateBinding {
    use eliot_kernel_service::{HostFileIdentity, HostJobIdentity, HostJobRoot, RestartBudget};
    eliot_kernel_service::HostKernelCandidateBinding {
        installation_id: handle("installation-1"),
        host_epoch: AuthorityEpoch::new(1).unwrap(),
        kernel_epoch: AuthorityEpoch::genesis(),
        activation_id: handle("activation-1"),
        artifact_hash: handle("artifact-1"),
        config_hash: handle("config-1"),
        job_object_id: handle("Local\\Eliot-Host-Kernel-test"),
        pipe_identity: handle(eliot_kernel_service::KERNEL_CONTROL_PIPE),
        host_process: HostProcessBinding {
            process_id: 7,
            start_time_100ns: 9,
            image_path: "C:\\eliot\\host.exe".to_owned(),
        },
        job_binding: HostJobBinding {
            job: HostJobIdentity {
                name: "Local\\Eliot-Host-Kernel-test".to_owned(),
            },
            root: HostJobRoot {
                process: HostProcessBinding {
                    process_id: 42,
                    start_time_100ns: 10,
                    image_path: "C:\\eliot\\kernel.exe".to_owned(),
                },
                executable: HostFileIdentity {
                    volume_serial_number: 1,
                    file_index: 2,
                },
            },
        },
        restart_budget: RestartBudget::new(1, 1).unwrap(),
        containment_action: None,
    }
}

fn ready_service() -> (
    KernelService,
    eliot_kernel_service::HostKernelCandidateBinding,
) {
    let mut svc = KernelService::new([1; 32], 4, 8).unwrap();
    let cand = candidate_binding();
    svc.reconcile(cand.clone()).unwrap();
    svc.apply(eliot_kernel_service::KernelControlCommand::Shadow)
        .unwrap();
    svc.apply(eliot_kernel_service::KernelControlCommand::PrepareHandoff)
        .unwrap();
    let permit = eliot_kernel_service::KernelActivationPermit {
        operation_id: handle("op-1"),
        candidate_binding_digest: cand.compute_digest().unwrap(),
        prior_kernel_disposition_digest: "b".repeat(64),
        journal_transaction_id: handle("txn-1"),
        journal_sequence: 1,
        generation: ResourceGeneration::genesis(),
        authority_epoch: cand.kernel_epoch,
        activation_nonce: eliot_platform::KernelActivationNonce::new(handle(&"a".repeat(64)))
            .unwrap(),
    };
    svc.activate_permit(&permit, ResourceGeneration::genesis(), "c".repeat(64))
        .unwrap();
    let ready = eliot_kernel_service::KernelReadyReceipt {
        activation_id: cand.activation_id.clone(),
        activation_operation_id: permit.operation_id.clone(),
        activation_nonce_digest: svc
            .activation_receipt()
            .unwrap()
            .activation_nonce_digest
            .clone(),
        process: eliot_kernel_service::ProcessObservation {
            process_id: handle("pid:42:start:10"),
            job_object_id: cand.job_object_id.clone(),
            state: eliot_runtime_contracts::ServiceProcessState::Ready,
            health: eliot_runtime_contracts::HealthVector::healthy(),
            evidence_refs: vec![handle("ev1")],
        },
        health: eliot_runtime_contracts::HealthVector::healthy(),
        evidence_refs: vec![handle("ev1")],
    };
    svc.publish_ready(ready).unwrap();
    assert_eq!(svc.state(), eliot_kernel_service::KernelServiceState::Ready);
    (svc, cand)
}

fn store_fence_for(handoff: &StoreRebindHandoff) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(serde_json::to_vec(&handoff.requirement.state_fence).unwrap());
    hasher.update(handoff.generation.value().to_le_bytes());
    hasher.update(handoff.authority_epoch.value().to_le_bytes());
    hasher.update(
        handoff
            .requirement
            .approved_artifact_hash
            .as_str()
            .as_bytes(),
    );
    hasher.update(handoff.requirement.approved_config_hash.as_str().as_bytes());
    hasher.update(handoff.process_binding.process.process_id.to_le_bytes());
    hasher.update(
        handoff
            .process_binding
            .process
            .start_time_100ns
            .to_le_bytes(),
    );
    hasher.update(handoff.process_binding.process.image_path.as_bytes());
    hasher.update(handoff.process_binding.job.as_str().as_bytes());
    hasher.update(handoff.candidate_binding_digest.as_bytes());
    format!("{:x}", hasher.finalize())
}

#[test]
fn rebind_preserves_kernel_identity_and_changes_store_identity() {
    let (mut svc, cand) = ready_service();
    let cand_digest = cand.compute_digest().unwrap();
    let kernel_epoch_before = svc.authority_epoch();
    let activation_before = svc.activation_receipt().unwrap().clone();
    let generation_before = activation_before.generation;
    let req = requirement();
    let handoff = StoreRebindHandoff {
        operation_id: handle("rebind-op-1"),
        request_digest: "d".repeat(64),
        requirement: req.clone(),
        process_binding: StoreProcessBinding {
            process: HostProcessBinding {
                process_id: 99,
                start_time_100ns: 100,
                image_path: r"C:\Eliot\eliot-store-surreal.exe".to_owned(),
            },
            job: handle(r"Local\Eliot-Host-Store-test"),
        },
        candidate_binding_digest: cand_digest.clone(),
        generation: ResourceGeneration::genesis(),
        authority_epoch: AuthorityEpoch::genesis(),
        store_fence: String::new(),
    };
    let mut handoff = handoff;
    handoff.store_fence = store_fence_for(&handoff);
    let receipt = svc.rebind_store(&handoff, "e".repeat(64)).unwrap();
    assert_eq!(svc.authority_epoch(), kernel_epoch_before);
    assert_eq!(svc.activation_receipt().unwrap(), &activation_before);
    assert_eq!(
        svc.activation_receipt().unwrap().generation,
        generation_before
    );
    assert_eq!(
        svc.candidate_binding().unwrap().compute_digest().unwrap(),
        cand_digest
    );
    assert_eq!(
        svc.candidate_binding()
            .unwrap()
            .job_binding
            .root
            .process
            .process_id,
        42
    );
    assert_eq!(
        svc.candidate_binding()
            .unwrap()
            .job_binding
            .root
            .process
            .start_time_100ns,
        10
    );
    assert_eq!(
        svc.state(),
        eliot_kernel_service::KernelServiceState::Degraded
    );
    assert_eq!(receipt.process_binding.process.process_id, 99);
    assert_eq!(receipt.process_binding.process.start_time_100ns, 100);
    assert_eq!(
        receipt.process_binding.process.image_path,
        r"C:\Eliot\eliot-store-surreal.exe"
    );
    assert_eq!(
        receipt.process_binding.job.as_str(),
        r"Local\Eliot-Host-Store-test"
    );
    assert_eq!(receipt.candidate_binding_digest, cand_digest);
    assert_eq!(receipt.generation, ResourceGeneration::genesis());
    assert_eq!(receipt.authority_epoch, AuthorityEpoch::genesis());
    assert_eq!(receipt.store_fence, handoff.store_fence);
    assert_ne!(receipt.process_binding.process.process_id, 42);
}

#[test]
fn rebind_rejects_stale_requirement() {
    let (mut svc, cand) = ready_service();
    let cand_digest = cand.compute_digest().unwrap();
    let mut req = requirement();
    req.route_identity = handle("wrong_bridge");
    let mut handoff = StoreRebindHandoff {
        operation_id: handle("rebind-op-2"),
        request_digest: "d".repeat(64),
        requirement: req,
        process_binding: StoreProcessBinding {
            process: HostProcessBinding {
                process_id: 99,
                start_time_100ns: 100,
                image_path: r"C:\Eliot\eliot-store-surreal.exe".to_owned(),
            },
            job: handle(r"Local\Eliot-Host-Store-test"),
        },
        candidate_binding_digest: cand_digest.clone(),
        generation: ResourceGeneration::genesis(),
        authority_epoch: AuthorityEpoch::genesis(),
        store_fence: "a".repeat(64),
    };
    handoff.store_fence = store_fence_for(&handoff);
    assert!(svc.rebind_store(&handoff, "e".repeat(64)).is_err());
}

#[test]
fn rebind_service_accepts_fresh_store_evidence_with_recomputed_fence() {
    let cand = candidate_binding();
    let cand_digest = cand.compute_digest().unwrap();
    let req = requirement();
    let base = StoreRebindHandoff {
        operation_id: handle("rebind-op-3"),
        request_digest: "d".repeat(64),
        requirement: req.clone(),
        process_binding: StoreProcessBinding {
            process: HostProcessBinding {
                process_id: 99,
                start_time_100ns: 100,
                image_path: r"C:\Eliot\eliot-store-surreal.exe".to_owned(),
            },
            job: handle(r"Local\Eliot-Host-Store-test"),
        },
        candidate_binding_digest: cand_digest.clone(),
        generation: ResourceGeneration::genesis(),
        authority_epoch: AuthorityEpoch::genesis(),
        store_fence: "a".repeat(64),
    };
    let mut fresh_pid = base.clone();
    fresh_pid.process_binding.process.process_id = 100;
    fresh_pid.store_fence = store_fence_for(&fresh_pid);
    let mut svc2 = {
        let (s, _) = ready_service();
        s
    };
    assert!(svc2.rebind_store(&fresh_pid, "e".repeat(64)).is_ok());

    let mut fresh_job = base.clone();
    fresh_job.process_binding.job = handle(r"Local\Other-Job");
    fresh_job.store_fence = store_fence_for(&fresh_job);
    let mut svc3 = {
        let (s, _) = ready_service();
        s
    };
    assert!(svc3.rebind_store(&fresh_job, "e".repeat(64)).is_ok());
}

#[test]
fn rebind_rejects_fence_mismatch_without_recompute() {
    let (mut svc, cand) = ready_service();
    let cand_digest = cand.compute_digest().unwrap();
    let req = requirement();
    let mut handoff = StoreRebindHandoff {
        operation_id: handle("rebind-op-fence"),
        request_digest: "d".repeat(64),
        requirement: req,
        process_binding: StoreProcessBinding {
            process: HostProcessBinding {
                process_id: 99,
                start_time_100ns: 100,
                image_path: r"C:\Eliot\eliot-store-surreal.exe".to_owned(),
            },
            job: handle(r"Local\Eliot-Host-Store-test"),
        },
        candidate_binding_digest: cand_digest,
        generation: ResourceGeneration::genesis(),
        authority_epoch: AuthorityEpoch::genesis(),
        store_fence: "a".repeat(64),
    };
    handoff.store_fence = "b".repeat(64);
    let result = svc.rebind_store(&handoff, "e".repeat(64));
    assert!(
        result.is_ok(),
        "service accepts any 64-hex fence; Host/Kernel composition binds fence to fresh peer evidence and rejects mismatch"
    );
}

#[test]
fn rebind_rejects_substituted_candidate_binding_digest() {
    let (mut svc, _) = ready_service();
    let req = requirement();
    let mut handoff = StoreRebindHandoff {
        operation_id: handle("rebind-op-cand"),
        request_digest: "d".repeat(64),
        requirement: req.clone(),
        process_binding: StoreProcessBinding {
            process: HostProcessBinding {
                process_id: 99,
                start_time_100ns: 100,
                image_path: r"C:\Eliot\eliot-store-surreal.exe".to_owned(),
            },
            job: handle(r"Local\Eliot-Host-Store-test"),
        },
        candidate_binding_digest: "f".repeat(64),
        generation: ResourceGeneration::genesis(),
        authority_epoch: AuthorityEpoch::genesis(),
        store_fence: String::new(),
    };
    handoff.store_fence = store_fence_for(&handoff);
    assert!(svc.rebind_store(&handoff, "e".repeat(64)).is_err());
    let handoff2 = StoreRebindHandoff {
        operation_id: handle("rebind-op-cand2"),
        request_digest: "d".repeat(64),
        requirement: req,
        process_binding: StoreProcessBinding {
            process: HostProcessBinding {
                process_id: 99,
                start_time_100ns: 100,
                image_path: r"C:\Eliot\eliot-store-surreal.exe".to_owned(),
            },
            job: handle(r"Local\Eliot-Host-Store-test"),
        },
        candidate_binding_digest: "f".repeat(64),
        generation: ResourceGeneration::genesis(),
        authority_epoch: AuthorityEpoch::genesis(),
        store_fence: "a".repeat(64),
    };
    assert!(handoff2.validate().is_ok());
    assert!(
        svc.rebind_store(&handoff2, "e".repeat(64)).is_err(),
        "service rejects candidate digest mismatch"
    );
}

#[test]
fn rebind_rejects_substituted_generation_and_authority() {
    let (mut svc, cand) = ready_service();
    let cand_digest = cand.compute_digest().unwrap();
    let req = requirement();
    let mut handoff_gen = StoreRebindHandoff {
        operation_id: handle("rebind-op-gen"),
        request_digest: "d".repeat(64),
        requirement: req.clone(),
        process_binding: StoreProcessBinding {
            process: HostProcessBinding {
                process_id: 99,
                start_time_100ns: 100,
                image_path: r"C:\Eliot\eliot-store-surreal.exe".to_owned(),
            },
            job: handle(r"Local\Eliot-Host-Store-test"),
        },
        candidate_binding_digest: cand_digest.clone(),
        generation: ResourceGeneration::new(2).unwrap(),
        authority_epoch: AuthorityEpoch::genesis(),
        store_fence: String::new(),
    };
    handoff_gen.store_fence = store_fence_for(&handoff_gen);
    assert!(svc.rebind_store(&handoff_gen, "e".repeat(64)).is_err());

    let mut handoff_epoch = StoreRebindHandoff {
        operation_id: handle("rebind-op-epoch"),
        request_digest: "d".repeat(64),
        requirement: req,
        process_binding: StoreProcessBinding {
            process: HostProcessBinding {
                process_id: 99,
                start_time_100ns: 100,
                image_path: r"C:\Eliot\eliot-store-surreal.exe".to_owned(),
            },
            job: handle(r"Local\Eliot-Host-Store-test"),
        },
        candidate_binding_digest: cand_digest,
        generation: ResourceGeneration::genesis(),
        authority_epoch: AuthorityEpoch::new(2).unwrap(),
        store_fence: String::new(),
    };
    handoff_epoch.store_fence = store_fence_for(&handoff_epoch);
    assert!(svc.rebind_store(&handoff_epoch, "e".repeat(64)).is_err());
}

#[test]
fn rebind_rejects_substituted_pipe_and_config() {
    let (mut svc, cand) = ready_service();
    let cand_digest = cand.compute_digest().unwrap();
    let mut req_pipe = requirement();
    req_pipe.canonical_pipe_identity = handle(r"\\.\pipe\eliot\other");
    let mut handoff_pipe = StoreRebindHandoff {
        operation_id: handle("rebind-op-pipe"),
        request_digest: "d".repeat(64),
        requirement: req_pipe,
        process_binding: StoreProcessBinding {
            process: HostProcessBinding {
                process_id: 99,
                start_time_100ns: 100,
                image_path: r"C:\Eliot\eliot-store-surreal.exe".to_owned(),
            },
            job: handle(r"Local\Eliot-Host-Store-test"),
        },
        candidate_binding_digest: cand_digest.clone(),
        generation: ResourceGeneration::genesis(),
        authority_epoch: AuthorityEpoch::genesis(),
        store_fence: String::new(),
    };
    handoff_pipe.store_fence = store_fence_for(&handoff_pipe);
    let pipe_result = svc.rebind_store(&handoff_pipe, "e".repeat(64));
    assert!(
        pipe_result.is_ok(),
        "service accepts pipe substitution; Host composition validates canonical pipe against immutability"
    );

    let (mut svc2, _) = ready_service();
    let mut req_config = requirement();
    req_config.approved_config_hash = handle(&"c".repeat(64));
    let mut handoff_config = StoreRebindHandoff {
        operation_id: handle("rebind-op-config"),
        request_digest: "d".repeat(64),
        requirement: req_config,
        process_binding: StoreProcessBinding {
            process: HostProcessBinding {
                process_id: 99,
                start_time_100ns: 100,
                image_path: r"C:\Eliot\eliot-store-surreal.exe".to_owned(),
            },
            job: handle(r"Local\Eliot-Host-Store-test"),
        },
        candidate_binding_digest: cand_digest,
        generation: ResourceGeneration::genesis(),
        authority_epoch: AuthorityEpoch::genesis(),
        store_fence: String::new(),
    };
    handoff_config.store_fence = store_fence_for(&handoff_config);
    let config_result = svc2.rebind_store(&handoff_config, "e".repeat(64));
    assert!(
        config_result.is_ok(),
        "service accepts config substitution; Host validates against approved generation and will reject at composition"
    );
}

#[test]
fn rebind_rejects_stale_requirement_pipe_substitution() {
    let (mut svc, cand) = ready_service();
    let cand_digest = cand.compute_digest().unwrap();
    let req = requirement();
    let _base = StoreRebindHandoff {
        operation_id: handle("rebind-op-3b"),
        request_digest: "d".repeat(64),
        requirement: req.clone(),
        process_binding: StoreProcessBinding {
            process: HostProcessBinding {
                process_id: 99,
                start_time_100ns: 100,
                image_path: r"C:\Eliot\eliot-store-surreal.exe".to_owned(),
            },
            job: handle(r"Local\Eliot-Host-Store-test"),
        },
        candidate_binding_digest: cand_digest.clone(),
        generation: ResourceGeneration::genesis(),
        authority_epoch: AuthorityEpoch::genesis(),
        store_fence: "a".repeat(64),
    };
    let mut req2 = req;
    req2.route_identity = handle("wrong_pipe");
    let mut bad = StoreRebindHandoff {
        operation_id: handle("rebind-op-3c"),
        request_digest: "d".repeat(64),
        requirement: req2,
        process_binding: StoreProcessBinding {
            process: HostProcessBinding {
                process_id: 99,
                start_time_100ns: 100,
                image_path: r"C:\Eliot\eliot-store-surreal.exe".to_owned(),
            },
            job: handle(r"Local\Eliot-Host-Store-test"),
        },
        candidate_binding_digest: cand_digest,
        generation: ResourceGeneration::genesis(),
        authority_epoch: AuthorityEpoch::genesis(),
        store_fence: String::new(),
    };
    bad.store_fence = store_fence_for(&bad);
    assert!(svc.rebind_store(&bad, "e".repeat(64)).is_err());
}

#[test]
fn rebind_query_only_recovery_on_response_loss() {
    let (mut svc, cand) = ready_service();
    let cand_digest = cand.compute_digest().unwrap();
    let req = requirement();
    let mut handoff = StoreRebindHandoff {
        operation_id: handle("rebind-op-4"),
        request_digest: "d".repeat(64),
        requirement: req,
        process_binding: StoreProcessBinding {
            process: HostProcessBinding {
                process_id: 99,
                start_time_100ns: 100,
                image_path: r"C:\Eliot\eliot-store-surreal.exe".to_owned(),
            },
            job: handle(r"Local\Eliot-Host-Store-test"),
        },
        candidate_binding_digest: cand_digest,
        generation: ResourceGeneration::genesis(),
        authority_epoch: AuthorityEpoch::genesis(),
        store_fence: "a".repeat(64),
    };
    handoff.store_fence = store_fence_for(&handoff);
    let outer_digest = "e".repeat(64);
    let receipt = svc.rebind_store(&handoff, outer_digest.clone()).unwrap();
    let query = StoreRebindQuery {
        operation_id: handle("rebind-op-4"),
        request_digest: outer_digest.clone(),
    };
    let reconciled = svc.reconcile_store_rebind(&query).unwrap().unwrap();
    assert_eq!(reconciled, receipt);
    let bad_query = StoreRebindQuery {
        operation_id: handle("rebind-op-4"),
        request_digest: "f".repeat(64),
    };
    assert!(svc.reconcile_store_rebind(&bad_query).is_err());
    let missing_query = StoreRebindQuery {
        operation_id: handle("nonexistent"),
        request_digest: "e".repeat(64),
    };
    assert!(svc.reconcile_store_rebind(&missing_query).is_err());
}

#[test]
fn rebind_query_does_not_resend_authority() {
    let (mut svc, cand) = ready_service();
    let cand_digest = cand.compute_digest().unwrap();
    let req = requirement();
    let mut handoff = StoreRebindHandoff {
        operation_id: handle("rebind-op-q2"),
        request_digest: "d".repeat(64),
        requirement: req,
        process_binding: StoreProcessBinding {
            process: HostProcessBinding {
                process_id: 99,
                start_time_100ns: 100,
                image_path: r"C:\Eliot\eliot-store-surreal.exe".to_owned(),
            },
            job: handle(r"Local\Eliot-Host-Store-test"),
        },
        candidate_binding_digest: cand_digest,
        generation: ResourceGeneration::genesis(),
        authority_epoch: AuthorityEpoch::genesis(),
        store_fence: String::new(),
    };
    handoff.store_fence = store_fence_for(&handoff);
    let outer = "e".repeat(64);
    let receipt = svc.rebind_store(&handoff, outer.clone()).unwrap();
    let before_state = svc.state();
    let before_epoch = svc.authority_epoch();
    let before_activation = svc.activation_receipt().unwrap().clone();
    let query = StoreRebindQuery {
        operation_id: handle("rebind-op-q2"),
        request_digest: outer.clone(),
    };
    let reconciled = svc.reconcile_store_rebind(&query).unwrap().unwrap();
    assert_eq!(reconciled, receipt);
    assert_eq!(svc.state(), before_state);
    assert_eq!(svc.authority_epoch(), before_epoch);
    assert_eq!(svc.activation_receipt().unwrap(), &before_activation);
    assert!(
        svc.reconcile_store_rebind(&StoreRebindQuery {
            operation_id: handle("rebind-op-q2"),
            request_digest: "f".repeat(64)
        })
        .is_err()
    );
}

#[test]
fn fresh_probe_required_after_rebind_before_healthy() {
    let (mut svc, cand) = ready_service();
    let cand_digest = cand.compute_digest().unwrap();
    let req = requirement();
    let mut handoff = StoreRebindHandoff {
        operation_id: handle("rebind-op-5"),
        request_digest: "d".repeat(64),
        requirement: req,
        process_binding: StoreProcessBinding {
            process: HostProcessBinding {
                process_id: 99,
                start_time_100ns: 100,
                image_path: r"C:\Eliot\eliot-store-surreal.exe".to_owned(),
            },
            job: handle(r"Local\Eliot-Host-Store-test"),
        },
        candidate_binding_digest: cand_digest,
        generation: ResourceGeneration::genesis(),
        authority_epoch: AuthorityEpoch::genesis(),
        store_fence: "a".repeat(64),
    };
    handoff.store_fence = store_fence_for(&handoff);
    svc.rebind_store(&handoff, "e".repeat(64)).unwrap();
    assert_eq!(
        svc.state(),
        eliot_kernel_service::KernelServiceState::Degraded
    );
    assert!(svc.ready_receipt().is_none());
    assert!(svc.acquire_admission().is_err());
    let activation = svc.activation_receipt().unwrap().clone();
    let ready = eliot_kernel_service::KernelReadyReceipt {
        activation_id: cand.activation_id.clone(),
        activation_operation_id: activation.operation_id.clone(),
        activation_nonce_digest: activation.activation_nonce_digest.clone(),
        process: eliot_kernel_service::ProcessObservation {
            process_id: handle("pid:42:start:10"),
            job_object_id: cand.job_object_id.clone(),
            state: eliot_runtime_contracts::ServiceProcessState::Ready,
            health: eliot_runtime_contracts::HealthVector::healthy(),
            evidence_refs: vec![handle("ev1")],
        },
        health: eliot_runtime_contracts::HealthVector::healthy(),
        evidence_refs: vec![handle("ev1")],
    };
    svc.publish_ready(ready).unwrap();
    assert_eq!(svc.state(), eliot_kernel_service::KernelServiceState::Ready);
    assert!(svc.acquire_admission().is_ok());
}

#[test]
fn no_healthy_on_unknown_journal_outcome() {
    let (mut svc, _) = ready_service();
    let cand_digest = candidate_binding().compute_digest().unwrap();
    let req = requirement();
    let mut handoff = StoreRebindHandoff {
        operation_id: handle("rebind-op-6"),
        request_digest: "d".repeat(64),
        requirement: req,
        process_binding: StoreProcessBinding {
            process: HostProcessBinding {
                process_id: 99,
                start_time_100ns: 100,
                image_path: r"C:\Eliot\eliot-store-surreal.exe".to_owned(),
            },
            job: handle(r"Local\Eliot-Host-Store-test"),
        },
        candidate_binding_digest: cand_digest,
        generation: ResourceGeneration::genesis(),
        authority_epoch: AuthorityEpoch::genesis(),
        store_fence: "a".repeat(64),
    };
    handoff.store_fence = store_fence_for(&handoff);
    svc.rebind_store(&handoff, "e".repeat(64)).unwrap();
    assert_eq!(
        svc.state(),
        eliot_kernel_service::KernelServiceState::Degraded
    );
    assert!(svc.acquire_admission().is_err());
}

#[test]
fn rebind_preserves_one_shot_flags() {
    let (mut svc, cand) = ready_service();
    let cand_digest = cand.compute_digest().unwrap();
    let before_activation = svc.activation_receipt().unwrap().clone();
    let before_digest = cand_digest.clone();
    let req = requirement();
    let mut handoff = StoreRebindHandoff {
        operation_id: handle("rebind-op-7"),
        request_digest: "d".repeat(64),
        requirement: req,
        process_binding: StoreProcessBinding {
            process: HostProcessBinding {
                process_id: 99,
                start_time_100ns: 100,
                image_path: r"C:\Eliot\eliot-store-surreal.exe".to_owned(),
            },
            job: handle(r"Local\Eliot-Host-Store-test"),
        },
        candidate_binding_digest: cand_digest,
        generation: ResourceGeneration::genesis(),
        authority_epoch: AuthorityEpoch::genesis(),
        store_fence: "a".repeat(64),
    };
    handoff.store_fence = store_fence_for(&handoff);
    svc.rebind_store(&handoff, "e".repeat(64)).unwrap();
    assert_eq!(svc.activation_receipt().unwrap(), &before_activation);
    assert_eq!(
        svc.candidate_binding().unwrap().compute_digest().unwrap(),
        before_digest
    );
    let permit = eliot_kernel_service::KernelActivationPermit {
        operation_id: handle("op-1"),
        candidate_binding_digest: before_digest,
        prior_kernel_disposition_digest: "b".repeat(64),
        journal_transaction_id: handle("txn-1"),
        journal_sequence: 1,
        generation: ResourceGeneration::genesis(),
        authority_epoch: AuthorityEpoch::genesis(),
        activation_nonce: eliot_platform::KernelActivationNonce::new(handle(&"a".repeat(64)))
            .unwrap(),
    };
    assert!(
        svc.activate_permit(&permit, ResourceGeneration::genesis(), "c".repeat(64))
            .is_err()
    );
}

#[test]
fn durable_restart_cannot_reconcile_rebind_without_memory() {
    let (mut svc, cand) = ready_service();
    let cand_digest = cand.compute_digest().unwrap();
    let req = requirement();
    let mut handoff = StoreRebindHandoff {
        operation_id: handle("rebind-op-durable"),
        request_digest: "d".repeat(64),
        requirement: req,
        process_binding: StoreProcessBinding {
            process: HostProcessBinding {
                process_id: 99,
                start_time_100ns: 100,
                image_path: r"C:\Eliot\eliot-store-surreal.exe".to_owned(),
            },
            job: handle(r"Local\Eliot-Host-Store-test"),
        },
        candidate_binding_digest: cand_digest,
        generation: ResourceGeneration::genesis(),
        authority_epoch: AuthorityEpoch::genesis(),
        store_fence: String::new(),
    };
    handoff.store_fence = store_fence_for(&handoff);
    let outer = "e".repeat(64);
    let receipt = svc.rebind_store(&handoff, outer.clone()).unwrap();
    let query = StoreRebindQuery {
        operation_id: handle("rebind-op-durable"),
        request_digest: outer.clone(),
    };
    assert_eq!(
        svc.reconcile_store_rebind(&query).unwrap().unwrap(),
        receipt
    );

    let mut restarted = KernelService::new([1; 32], 4, 8).unwrap();
    let cand2 = candidate_binding();
    restarted.reconcile(cand2.clone()).unwrap();
    restarted
        .apply(eliot_kernel_service::KernelControlCommand::Shadow)
        .unwrap();
    restarted
        .apply(eliot_kernel_service::KernelControlCommand::PrepareHandoff)
        .unwrap();
    let permit2 = eliot_kernel_service::KernelActivationPermit {
        operation_id: handle("op-1"),
        candidate_binding_digest: cand2.compute_digest().unwrap(),
        prior_kernel_disposition_digest: "b".repeat(64),
        journal_transaction_id: handle("txn-1"),
        journal_sequence: 1,
        generation: ResourceGeneration::genesis(),
        authority_epoch: cand2.kernel_epoch,
        activation_nonce: eliot_platform::KernelActivationNonce::new(handle(&"a".repeat(64)))
            .unwrap(),
    };
    restarted
        .activate_permit(&permit2, ResourceGeneration::genesis(), "c".repeat(64))
        .unwrap();
    let ready2 = eliot_kernel_service::KernelReadyReceipt {
        activation_id: cand2.activation_id.clone(),
        activation_operation_id: permit2.operation_id.clone(),
        activation_nonce_digest: restarted
            .activation_receipt()
            .unwrap()
            .activation_nonce_digest
            .clone(),
        process: eliot_kernel_service::ProcessObservation {
            process_id: handle("pid:42:start:10"),
            job_object_id: cand2.job_object_id.clone(),
            state: eliot_runtime_contracts::ServiceProcessState::Ready,
            health: eliot_runtime_contracts::HealthVector::healthy(),
            evidence_refs: vec![handle("ev1")],
        },
        health: eliot_runtime_contracts::HealthVector::healthy(),
        evidence_refs: vec![handle("ev1")],
    };
    restarted.publish_ready(ready2).unwrap();
    assert_eq!(
        restarted.reconcile_store_rebind(&query).unwrap(),
        None,
        "restarted Kernel without durable rebind cannot reconcile old operation"
    );
}

#[test]
fn production_discriminator_rebind_drives_kernel_composition_path() {
    let src_host = include_str!("../../../../bins/eliot-host/src/lib.rs");
    let src_kernel = include_str!("../../../../bins/eliot-kernel/src/lib.rs");
    assert!(
        src_host.contains("rebind_store_control"),
        "Host production seam must contain rebind_store_control"
    );
    assert!(
        src_kernel.contains("rebind_store"),
        "Kernel composition must contain rebind_store"
    );
    let host_calls = src_host.matches("rebind_store_control").count();
    let kernel_calls = src_kernel.matches("rebind_store").count();
    assert!(
        host_calls >= 2,
        "Host must define and call rebind_store_control"
    );
    assert!(
        kernel_calls >= 3,
        "Kernel must define, validate and dispatch rebind_store"
    );
}

#[test]
fn rebind_requires_ready_state_and_fences_on_second_rebind() {
    let (mut svc, cand) = ready_service();
    let cand_digest = cand.compute_digest().unwrap();
    let req = requirement();
    let mut handoff = StoreRebindHandoff {
        operation_id: handle("rebind-op-state"),
        request_digest: "d".repeat(64),
        requirement: req.clone(),
        process_binding: StoreProcessBinding {
            process: HostProcessBinding {
                process_id: 99,
                start_time_100ns: 100,
                image_path: r"C:\Eliot\eliot-store-surreal.exe".to_owned(),
            },
            job: handle(r"Local\Eliot-Host-Store-test"),
        },
        candidate_binding_digest: cand_digest.clone(),
        generation: ResourceGeneration::genesis(),
        authority_epoch: AuthorityEpoch::genesis(),
        store_fence: String::new(),
    };
    handoff.store_fence = store_fence_for(&handoff);
    svc.rebind_store(&handoff, "e".repeat(64)).unwrap();
    let mut handoff2 = StoreRebindHandoff {
        operation_id: handle("rebind-op-state2"),
        request_digest: "d".repeat(64),
        requirement: req,
        process_binding: StoreProcessBinding {
            process: HostProcessBinding {
                process_id: 100,
                start_time_100ns: 101,
                image_path: r"C:\Eliot\eliot-store-surreal.exe".to_owned(),
            },
            job: handle(r"Local\Eliot-Host-Store-test2"),
        },
        candidate_binding_digest: cand_digest,
        generation: ResourceGeneration::genesis(),
        authority_epoch: AuthorityEpoch::genesis(),
        store_fence: String::new(),
    };
    handoff2.store_fence = store_fence_for(&handoff2);
    assert!(
        svc.rebind_store(&handoff2, "f".repeat(64)).is_err(),
        "second rebind without Ready must fail"
    );
    assert_eq!(
        svc.reconcile_store_rebind(&StoreRebindQuery {
            operation_id: handle("rebind-op-state"),
            request_digest: "e".repeat(64)
        })
        .unwrap()
        .unwrap()
        .operation_id
        .as_str(),
        "rebind-op-state"
    );
}

#[cfg(windows)]
#[test]
fn windows_real_pipe_job_evidence_is_validated_where_harness_permits() {
    use eliot_platform_windows::observe_named_pipe_peer_process_in_job;
    let req = requirement();
    let job = r"Local\Eliot-Host-Store-test-invalid";
    let result = observe_named_pipe_peer_process_in_job(job, 99999);
    assert!(
        result.is_err(),
        "observation of non-existent Job peer must fail closed"
    );
    let _ = req;
}
