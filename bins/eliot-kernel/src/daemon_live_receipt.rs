//! Kernel daemon live receipt closure.
//!
//! Architecture: A8.1, A13.2, A13.3, ARCH-WDG-01, ARCH-RES-01, ARCH-RES-04
//! Implementation: I1.5, I8.1, I8.2, I8.3, I8.4, I14.10, I14.15, I2.2, I2.23
//! Ordinary module topology: I2.2 When capability becomes separate crate; I2.23 Capability-family topology — ordinary single-file extraction (<10k LOC) owning only `KernelComposition` live-receipt closure plus inseparable receipt-only helpers with zero external users.
//! Forbidden authority: must not self-author readiness without authenticated evidence, semantic oracle, or alternate authority; this module remains evidence-gated, renewal-gated, and supervision-checked.

use super::{
    DaemonRuntimeStatus, DaemonSupervisionContour, EliotdLaunchDescriptor, Generation,
    HostKernelCandidateBinding, KernelComposition, KernelControlRequest, KernelReadyReceipt,
    KernelServiceError, PeerIdentity, ProcessStartReceipt, RequestId, Session,
    eliotd_launch_attempt_identity, eliotd_operation_id, observe_named_pipe_peer_process,
    probe_ready_state_admitted, sha256_json, unix_ms,
};
#[cfg(windows)]
use super::{
    EliotdLiveReadyEvidence, EliotdLiveReceipt, EliotdLiveReceiptDisposition, HealthVector,
    ProcessObservation, ProtectedRootLease, ProtectedRuntimePathLease, PublicationOutcome,
    PublicationPrecondition, SupervisionLeaseSnapshot, classify_eliotd_live_receipt_transition,
    publish_atomic_owned_runtime_receipt, windows_paths_equal,
};
use sha2::{Digest as _, Sha256};
use std::path::Path;

impl KernelComposition {
    #[cfg(windows)]
    pub(crate) fn eliotd_live_ready_evidence(
        session: &Session,
        request_id: &RequestId,
        payload: &serde_json::Value,
    ) -> Result<EliotdLiveReadyEvidence, KernelServiceError> {
        Ok(EliotdLiveReadyEvidence {
            request_id: request_id.as_str().to_owned(),
            request_payload_sha256: sha256_json(payload)
                .map_err(|_| KernelServiceError::ReadinessNotProven)?,
            connection_id: session.connection_id.clone(),
            session_epoch: session.session_epoch,
            authority_epoch: session.authority_epoch,
            generation: session.module_generation.generation.value(),
            launch_nonce_sha256: format!("{:x}", Sha256::digest(session.launch_nonce.as_bytes())),
        })
    }

    #[cfg(windows)]
    #[allow(clippy::too_many_lines)]
    pub(crate) fn publish_eliotd_live_receipt(
        &self,
        launch: &EliotdLaunchDescriptor,
        process: &ProcessStartReceipt,
        ready: &EliotdLiveReadyEvidence,
        supervision_contour: &DaemonSupervisionContour,
        supervision_successor: Option<&SupervisionLeaseSnapshot>,
    ) -> Result<EliotdLiveReceipt, KernelServiceError> {
        let runtime_binding = self
            .eliotd_receipt_binding
            .as_ref()
            .ok_or(KernelServiceError::ReadinessNotProven)?;
        runtime_binding
            .validate()
            .map_err(|_| KernelServiceError::ReadinessNotProven)?;
        let receipt_root = runtime_binding.receipt_root();
        if !receipt_root.is_absolute() {
            return Err(KernelServiceError::ReadinessNotProven);
        }
        let root_lease = ProtectedRootLease::open_existing(receipt_root)
            .map_err(|_| KernelServiceError::ReadinessNotProven)?;
        let canonical_root = root_lease
            .canonical_path()
            .map_err(|_| KernelServiceError::ReadinessNotProven)?;
        if !windows_paths_equal(&canonical_root, receipt_root)
            || root_lease.verify_stable_identity().is_err()
        {
            return Err(KernelServiceError::ReadinessNotProven);
        }
        let kernel_artifact = self
            .kernel_artifact_sha256
            .as_deref()
            .ok_or(KernelServiceError::ReadinessNotProven)?;
        let descriptor_artifact = self
            .eliotd_descriptor_artifact_sha256
            .as_deref()
            .ok_or(KernelServiceError::ReadinessNotProven)?;
        let supervision_authority = self
            .supervision_lease_authority
            .as_ref()
            .ok_or(KernelServiceError::ReadinessNotProven)?;
        if let Some(expected_successor) = supervision_successor {
            let observed = supervision_authority
                .current_snapshot(&supervision_contour.incarnation.supervision_lease_id)
                .map_err(|_| KernelServiceError::ReadinessNotProven)?;
            if observed.as_ref() != Some(expected_successor) {
                return Err(KernelServiceError::ReadinessNotProven);
            }
            supervision_authority
                .verify_active_snapshot(
                    expected_successor,
                    &supervision_contour.incarnation.supervision_lease_id,
                    unix_ms(),
                )
                .map_err(|_| KernelServiceError::ReadinessNotProven)?;
        }
        let (supervision, supervision_issued_at_ms) = supervision_authority
            .current_eliotd_live_projection(
                &supervision_contour.incarnation.supervision_lease_id,
                launch.generation.value(),
                launch.authority_epoch.value(),
            )
            .map_err(|_| KernelServiceError::ReadinessNotProven)?;
        let receipt = EliotdLiveReceipt::new(
            canonical_root.to_string_lossy(),
            sha256_json(&root_lease.identity())
                .map_err(|_| KernelServiceError::ReadinessNotProven)?,
            runtime_binding.runtime_state_roots_digest(),
            runtime_binding.installation_id(),
            runtime_binding.approved_generation(),
            launch.generation.value(),
            launch.authority_epoch.value(),
            launch.config_descriptor_sha256.as_str(),
            descriptor_artifact,
            kernel_artifact,
            process.clone(),
            supervision.clone(),
            ready.clone(),
            supervision_issued_at_ms,
        )
        .map_err(|_| KernelServiceError::ReadinessNotProven)?;
        receipt
            .validate()
            .map_err(|_| KernelServiceError::ReadinessNotProven)?;
        let bytes = eliot_contracts::canonical_json_bytes(&receipt)
            .map_err(|_| KernelServiceError::ReadinessNotProven)?;
        let path = canonical_root.join("eliotd-receipt.json");

        let existing = match ProtectedRuntimePathLease::open_existing_absolute(&path) {
            Ok(lease) => {
                if lease.verify_stable_identity().is_err() || lease.verify_path_identity().is_err()
                {
                    return Err(KernelServiceError::ReadinessNotProven);
                }
                let old_bytes = lease
                    .read_bounded(1024 * 1024)
                    .map_err(|_| KernelServiceError::ReadinessNotProven)?;
                let old: EliotdLiveReceipt = serde_json::from_slice(&old_bytes)
                    .map_err(|_| KernelServiceError::ReadinessNotProven)?;
                old.validate()
                    .map_err(|_| KernelServiceError::ReadinessNotProven)?;
                if eliot_contracts::canonical_json_bytes(&old)
                    .map_err(|_| KernelServiceError::ReadinessNotProven)?
                    != old_bytes
                {
                    return Err(KernelServiceError::ReadinessNotProven);
                }
                if !windows_paths_equal(Path::new(&old.receipt_root), &canonical_root)
                    || old.receipt_root_identity_sha256
                        != sha256_json(&root_lease.identity())
                            .map_err(|_| KernelServiceError::ReadinessNotProven)?
                {
                    return Err(KernelServiceError::ReadinessNotProven);
                }
                let same_active_contour = old.runtime_state_roots_digest
                    == receipt.runtime_state_roots_digest
                    && old.installation_id == receipt.installation_id
                    && old.approved_generation == receipt.approved_generation
                    && old.generation == receipt.generation
                    && old.authority_epoch == receipt.authority_epoch
                    && old.config_descriptor_sha256 == receipt.config_descriptor_sha256
                    && old.descriptor_sha256 == receipt.descriptor_sha256
                    && old.kernel_artifact_sha256 == receipt.kernel_artifact_sha256
                    && old.supervision.lease_id == receipt.supervision.lease_id
                    && old.supervision.public_key_fingerprint
                        == receipt.supervision.public_key_fingerprint;
                let exact_predecessor = supervision_contour
                    .incarnation
                    .predecessor
                    .as_ref()
                    .is_some_and(|predecessor| {
                        predecessor.supervision_lease_id == old.supervision.lease_id
                            && predecessor.ors_receipt_sha256 == old.supervision.receipt_sha256
                            && old.installation_id == receipt.installation_id
                            && old.supervision.public_key_fingerprint
                                == receipt.supervision.public_key_fingerprint
                    });
                if !same_active_contour && !exact_predecessor {
                    return Err(KernelServiceError::ReadinessNotProven);
                }
                if old.runtime_state_roots_digest != receipt.runtime_state_roots_digest
                    || old.installation_id != receipt.installation_id
                {
                    return Err(KernelServiceError::ReadinessNotProven);
                }
                Some((
                    old_bytes.clone(),
                    PublicationPrecondition::from_bytes(lease.identity(), &old_bytes),
                ))
            }
            Err(_) => match std::fs::symlink_metadata(&path) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
                _ => return Err(KernelServiceError::ReadinessNotProven),
            },
        };

        let status_is_ready = self
            .daemon_runtime
            .lock()
            .map_err(|_| KernelServiceError::Platform("daemon runtime lock poisoned".to_owned()))?
            .status
            == DaemonRuntimeStatus::Ready;
        let successor_evidence = supervision_successor.map(Into::into);
        let existing_disposition = if let Some((old_bytes, _)) = &existing {
            let old: EliotdLiveReceipt = serde_json::from_slice(old_bytes)
                .map_err(|_| KernelServiceError::ReadinessNotProven)?;
            Some(classify_eliotd_live_receipt_transition(
                &old,
                &receipt,
                status_is_ready,
                supervision_contour.incarnation.predecessor.as_ref(),
                successor_evidence.as_ref(),
            )?)
        } else if status_is_ready {
            return Err(KernelServiceError::ReadinessNotProven);
        } else {
            None
        };
        let reconciled_existing =
            existing_disposition == Some(EliotdLiveReceiptDisposition::ExactReplay);

        let published_identity = if reconciled_existing {
            None
        } else {
            let expected_existing = existing.as_ref().map(|(_, fence)| fence);
            let outcome = publish_atomic_owned_runtime_receipt(&path, &bytes, expected_existing)
                .map_err(|_| KernelServiceError::ReadinessNotProven)?;
            match outcome {
                PublicationOutcome::Published(receipt) => Some(receipt.identity),
                PublicationOutcome::Unknown(_) => {
                    return Err(KernelServiceError::ReadinessNotProven);
                }
            }
        };
        let lease = ProtectedRuntimePathLease::open_existing_absolute(&path)
            .map_err(|_| KernelServiceError::ReadinessNotProven)?;
        if published_identity
            .as_ref()
            .is_some_and(|identity| lease.identity() != *identity)
            || lease.verify_stable_identity().is_err()
            || lease.verify_path_identity().is_err()
        {
            return Err(KernelServiceError::ReadinessNotProven);
        }
        let readback = lease
            .read_bounded(1024 * 1024)
            .map_err(|_| KernelServiceError::ReadinessNotProven)?;
        if readback != bytes {
            return Err(KernelServiceError::ReadinessNotProven);
        }
        if root_lease.verify_stable_identity().is_err()
            || lease.verify_stable_identity().is_err()
            || lease.verify_path_identity().is_err()
        {
            return Err(KernelServiceError::ReadinessNotProven);
        }
        let post_root = root_lease
            .canonical_path()
            .map_err(|_| KernelServiceError::ReadinessNotProven)?;
        if !windows_paths_equal(&post_root, &canonical_root)
            || root_lease.verify_stable_identity().is_err()
        {
            return Err(KernelServiceError::ReadinessNotProven);
        }
        let (post_supervision, post_issued_at_ms) = supervision_authority
            .current_eliotd_live_projection(
                &supervision_contour.incarnation.supervision_lease_id,
                launch.generation.value(),
                launch.authority_epoch.value(),
            )
            .map_err(|_| KernelServiceError::ReadinessNotProven)?;
        if post_supervision != supervision || post_issued_at_ms != supervision_issued_at_ms {
            return Err(KernelServiceError::ReadinessNotProven);
        }
        Ok(receipt)
    }

    #[cfg(windows)]
    pub(crate) fn verify_published_eliotd_live_receipt(
        &self,
        expected: &EliotdLiveReceipt,
    ) -> Result<(), KernelServiceError> {
        expected
            .validate()
            .map_err(|_| KernelServiceError::ReadinessNotProven)?;
        let runtime_binding = self
            .eliotd_receipt_binding
            .as_ref()
            .ok_or(KernelServiceError::ReadinessNotProven)?;
        runtime_binding
            .validate()
            .map_err(|_| KernelServiceError::ReadinessNotProven)?;
        let root_lease = ProtectedRootLease::open_existing(runtime_binding.receipt_root())
            .map_err(|_| KernelServiceError::ReadinessNotProven)?;
        let canonical_root = root_lease
            .canonical_path()
            .map_err(|_| KernelServiceError::ReadinessNotProven)?;
        if !windows_paths_equal(&canonical_root, runtime_binding.receipt_root())
            || !windows_paths_equal(Path::new(&expected.receipt_root), &canonical_root)
            || expected.receipt_root_identity_sha256
                != sha256_json(&root_lease.identity())
                    .map_err(|_| KernelServiceError::ReadinessNotProven)?
        {
            return Err(KernelServiceError::ReadinessNotProven);
        }
        let path = canonical_root.join("eliotd-receipt.json");
        let lease = ProtectedRuntimePathLease::open_existing_absolute(&path)
            .map_err(|_| KernelServiceError::ReadinessNotProven)?;
        if root_lease.verify_stable_identity().is_err()
            || lease.verify_stable_identity().is_err()
            || lease.verify_path_identity().is_err()
        {
            return Err(KernelServiceError::ReadinessNotProven);
        }
        let observed = lease
            .read_bounded(1024 * 1024)
            .map_err(|_| KernelServiceError::ReadinessNotProven)?;
        let expected_bytes = eliot_contracts::canonical_json_bytes(expected)
            .map_err(|_| KernelServiceError::ReadinessNotProven)?;
        if observed != expected_bytes
            || root_lease.verify_stable_identity().is_err()
            || lease.verify_stable_identity().is_err()
            || lease.verify_path_identity().is_err()
        {
            return Err(KernelServiceError::ReadinessNotProven);
        }
        Ok(())
    }

    #[cfg(windows)]
    pub(crate) async fn validated_authenticated_daemon_ready_inputs(
        &self,
    ) -> Result<(EliotdLaunchDescriptor, ProcessStartReceipt), KernelServiceError> {
        let launch = self
            .active_daemon_launch()?
            .ok_or(KernelServiceError::ReadinessNotProven)?;
        let receipt = self
            .daemon_runtime
            .lock()
            .map_err(|_| KernelServiceError::Platform("daemon runtime lock poisoned".to_owned()))?
            .receipt
            .clone()
            .ok_or(KernelServiceError::ReadinessNotProven)?;
        self.validate_daemon_process_readiness(&launch, &receipt)
            .await?;
        Ok((launch, receipt))
    }

    #[cfg(windows)]
    pub(crate) async fn validate_daemon_process_readiness(
        &self,
        launch: &EliotdLaunchDescriptor,
        receipt: &ProcessStartReceipt,
    ) -> Result<(), KernelServiceError> {
        let Some(gateway) = self.process_gateway.as_ref() else {
            let _ = self
                .mark_daemon_failed("eliotd physical process authority is unavailable".to_owned());
            return Err(KernelServiceError::ReadinessNotProven);
        };
        if gateway
            .inspect_exact_running_receipt(receipt)
            .await
            .is_err()
        {
            let _ = self
                .mark_daemon_failed("eliotd physical process is not freshly Running".to_owned());
            return Err(KernelServiceError::ReadinessNotProven);
        }

        let generation = Generation::new(launch.generation.value()).map_err(|_| {
            let _ = self.mark_daemon_failed("eliotd launch generation is invalid".to_owned());
            KernelServiceError::ReadinessNotProven
        })?;
        let kernel_process = observe_named_pipe_peer_process(std::process::id()).map_err(|_| {
            let _ = self.mark_daemon_failed(
                "Kernel physical identity is unavailable for eliotd readiness".to_owned(),
            );
            KernelServiceError::ReadinessNotProven
        })?;
        let launch_identity = eliotd_launch_attempt_identity(
            launch,
            kernel_process.process_id(),
            kernel_process.start_time_100ns(),
            kernel_process.image_path(),
        )
        .map_err(|_| {
            let _ = self.mark_daemon_failed("eliotd launch attempt identity is invalid".to_owned());
            KernelServiceError::ReadinessNotProven
        })?;
        let expected_operation =
            eliotd_operation_id(generation, &launch_identity).map_err(|_| {
                let _ = self
                    .mark_daemon_failed("eliotd launch operation identity is invalid".to_owned());
                KernelServiceError::ReadinessNotProven
            })?;
        let physical = receipt.identity().physical();
        if receipt.operation_id() != &expected_operation
            || receipt.accepted_generation().get() != launch.generation.value()
            || receipt.binding().state_fence().authority_epoch() != launch.authority_epoch.value()
            || receipt.binding().state_fence().generation() != generation
            || receipt.identity().executable_sha256() != launch.executable_sha256
            || !physical
                .image_path()
                .eq_ignore_ascii_case(launch.executable.as_str())
        {
            let _ = self.mark_daemon_failed(
                "eliotd physical process binding does not match the approved launch contour"
                    .to_owned(),
            );
            return Err(KernelServiceError::ReadinessNotProven);
        }
        Ok(())
    }

    #[cfg(windows)]
    #[allow(
        clippy::too_many_lines,
        reason = "ordered live process, Job, authority, configuration, and Store proof remains explicit"
    )]
    pub(crate) async fn self_authored_ready_receipt(
        &self,
        request: &KernelControlRequest,
        peer: &PeerIdentity,
    ) -> Result<KernelReadyReceipt, KernelServiceError> {
        let candidate: &HostKernelCandidateBinding = &request.candidate;
        let observed_peer = peer.process_binding().ok_or(KernelServiceError::Platform(
            "authenticated Host process binding is unavailable".to_owned(),
        ))?;
        if observed_peer.process_id() != candidate.host_process.process_id
            || observed_peer.start_time_100ns() != candidate.host_process.start_time_100ns
            || observed_peer.image_path() != candidate.host_process.image_path
        {
            return Err(KernelServiceError::HandshakeMismatch {
                field: "host_process",
            });
        }
        let binding: eliot_platform_windows::RecoverableJobBinding =
            serde_json::from_value(serde_json::to_value(&candidate.job_binding).map_err(|_| {
                KernelServiceError::Platform("Kernel Job binding cannot be encoded".to_owned())
            })?)
            .map_err(|_| {
                KernelServiceError::Platform("Kernel Job binding is malformed".to_owned())
            })?;
        if binding.job_identity().name() != candidate.job_object_id.as_str() {
            return Err(KernelServiceError::HandshakeMismatch {
                field: "job_object_id",
            });
        }
        let job = eliot_platform_windows::RecoverableJobObject::open(binding)
            .map_err(|error| KernelServiceError::Platform(error.to_string()))?;
        let current = self
            .platform
            .process_identity(std::process::id())
            .map_err(|error| KernelServiceError::Platform(error.to_string()))?;
        let root = job.binding().root().process();
        if root != &current
            || !job
                .live_processes()
                .map_err(|error| KernelServiceError::Platform(error.to_string()))?
                .iter()
                .any(|process| process.process() == &current)
        {
            return Err(KernelServiceError::ReadinessNotProven);
        }
        if !self
            .process_gateway
            .as_ref()
            .is_some_and(|gateway| gateway.readiness_configuration_valid())
        {
            return Err(KernelServiceError::ReadinessNotProven);
        }
        if self.approved_config_hash.as_deref() != Some(candidate.config_hash.as_str()) {
            return Err(KernelServiceError::HandshakeMismatch {
                field: "config_hash",
            });
        }
        {
            let service = self
                .service
                .lock()
                .map_err(|_| KernelServiceError::Platform("service lock poisoned".to_owned()))?;
            if !probe_ready_state_admitted(service.state())
                || service.candidate_binding() != Some(candidate)
                || service.authority_epoch() != candidate.kernel_epoch
            {
                return Err(KernelServiceError::ReadinessNotProven);
            }
            if let Some(receipt) = service.store_rebind_receipt() {
                let handoff = self
                    .store_handoff
                    .lock()
                    .map_err(|_| {
                        KernelServiceError::Platform("store handoff lock poisoned".to_owned())
                    })?
                    .clone()
                    .ok_or(KernelServiceError::ReadinessNotProven)?;
                if handoff.process_binding != receipt.process_binding {
                    return Err(KernelServiceError::ReadinessNotProven);
                }
                let expected_digest = serde_json::to_vec(&handoff.requirement)
                    .map(|b| format!("{:x}", Sha256::digest(b)))
                    .map_err(|_| {
                        KernelServiceError::Platform("store requirement digest failed".to_owned())
                    })?;
                if receipt.requirement_digest != expected_digest
                    || receipt.candidate_binding_digest
                        != candidate.compute_digest().map_err(|_| {
                            KernelServiceError::Platform("candidate digest failed".to_owned())
                        })?
                    || receipt.generation != request.generation
                    || receipt.authority_epoch != candidate.kernel_epoch
                {
                    return Err(KernelServiceError::ReadinessNotProven);
                }
                let ors_records = self
                    .generation_gateway
                    .ors
                    .load_all_store_rebinds()
                    .map_err(|_| KernelServiceError::Platform("ORS load failed".to_owned()))?;
                let committed: Vec<_> = ors_records
                    .iter()
                    .filter(|r| r.state == eliot_ors::StoreRebindReplayState::Committed)
                    .collect();
                let lineage_zeros = committed
                    .iter()
                    .filter(|r| {
                        r.commit_order == 0
                            && r.requirement_digest == receipt.requirement_digest
                            && r.generation == receipt.generation.value()
                            && r.authority_epoch == receipt.authority_epoch.value()
                    })
                    .count();
                if lineage_zeros > 1 {
                    return Err(KernelServiceError::ReadinessNotProven);
                }
                let latest = committed.into_iter().max_by_key(|r| {
                    (
                        r.commit_order,
                        r.operation_id.as_str().to_owned(),
                        r.request_digest.clone(),
                    )
                });
                match latest {
                    Some(latest)
                        if latest.operation_id.as_str() == receipt.operation_id.as_str()
                            && latest.request_digest == receipt.request_digest
                            && latest.store_fence == receipt.store_fence =>
                    {
                        if latest.commit_order == 0 {
                            let total_legacy = ors_records
                                .iter()
                                .filter(|r| {
                                    r.state == eliot_ors::StoreRebindReplayState::Committed
                                        && r.commit_order == 0
                                })
                                .count();
                            if total_legacy > 1 {
                                return Err(KernelServiceError::ReadinessNotProven);
                            }
                        }
                    }
                    _ => return Err(KernelServiceError::ReadinessNotProven),
                }
            } else {
                let ors_has_committed = self
                    .generation_gateway
                    .ors
                    .load_all_store_rebinds()
                    .map_err(|_| KernelServiceError::Platform("ORS load failed".to_owned()))?
                    .iter()
                    .any(|r| r.state == eliot_ors::StoreRebindReplayState::Committed);
                if ors_has_committed {
                    return Err(KernelServiceError::ReadinessNotProven);
                }
            }
        }
        let gateway = self
            .canonical_store_gateway
            .lock()
            .map_err(|_| KernelServiceError::Platform("store gateway lock poisoned".to_owned()))?
            .clone()
            .ok_or(KernelServiceError::ReadinessNotProven)?;
        let health = gateway
            .health()
            .await
            .map_err(KernelServiceError::Platform)?;
        if health.status != eliot_store_api::StoreHealthStatus::Ready {
            return Err(KernelServiceError::ReadinessNotProven);
        }
        let snapshot = gateway
            .validation_snapshot()
            .await
            .map_err(KernelServiceError::Platform)?;
        snapshot
            .validate()
            .map_err(|error| KernelServiceError::Platform(error.to_string()))?;
        if snapshot.state_fence.authority_epoch != candidate.kernel_epoch
            || snapshot.state_fence.resource_generation != request.generation
        {
            return Err(KernelServiceError::HandshakeMismatch {
                field: "store_state_fence",
            });
        }
        let daemon_evidence = if self.active_daemon_launch()?.is_some() {
            let daemon_receipt = self.ensure_daemon_ready_for_probe().await?;
            let launch = self
                .active_daemon_launch()?
                .ok_or(KernelServiceError::ReadinessNotProven)?;
            self.validate_daemon_process_readiness(&launch, &daemon_receipt)
                .await?;
            Some(
                eliot_platform::PlatformHandle::new(format!(
                    "eliotd-ready:{}:{}",
                    daemon_receipt.identity().pid(),
                    launch.descriptor_sha256.as_str(),
                ))
                .map_err(|error| KernelServiceError::Platform(error.to_string()))?,
            )
        } else {
            None
        };
        let process_id = eliot_platform::PlatformHandle::new(format!(
            "pid:{}:start:{}",
            current.process_id, current.start_time_100ns
        ))
        .map_err(|error| KernelServiceError::Platform(error.to_string()))?;
        let process = ProcessObservation {
            process_id,
            job_object_id: candidate.job_object_id.clone(),
            state: eliot_runtime_contracts::ServiceProcessState::Ready,
            health: HealthVector::healthy(),
            evidence_refs: vec![
                eliot_platform::PlatformHandle::new(format!(
                    "kernel-process:{}:{}",
                    current.process_id, current.start_time_100ns
                ))
                .map_err(|error| KernelServiceError::Platform(error.to_string()))?,
                eliot_platform::PlatformHandle::new(format!(
                    "kernel-job:{}:{}",
                    candidate.job_object_id.as_str(),
                    job.active_process_count()
                        .map_err(|error| KernelServiceError::Platform(error.to_string()))?
                ))
                .map_err(|error| KernelServiceError::Platform(error.to_string()))?,
            ],
        };
        let mut evidence_refs = KernelReadyReceipt::probe_binding_evidence(request)?;
        evidence_refs.extend([
            eliot_platform::PlatformHandle::new(format!(
                "kernel-store-validation:{}",
                snapshot.validation_revision
            ))
            .map_err(|error| KernelServiceError::Platform(error.to_string()))?,
            eliot_platform::PlatformHandle::new(format!(
                "kernel-store-health:{}",
                health.manifest_digest.as_str()
            ))
            .map_err(|error| KernelServiceError::Platform(error.to_string()))?,
        ]);
        if let Some(daemon_evidence) = daemon_evidence {
            evidence_refs.push(daemon_evidence);
        }
        let activation = self
            .service
            .lock()
            .map_err(|_| KernelServiceError::Platform("service lock poisoned".to_owned()))?
            .activation_receipt()
            .cloned()
            .ok_or(KernelServiceError::ReadinessNotProven)?;
        let receipt = KernelReadyReceipt {
            activation_id: candidate.activation_id.clone(),
            activation_operation_id: activation.operation_id.clone(),
            activation_nonce_digest: activation.activation_nonce_digest.clone(),
            process,
            health: HealthVector::healthy(),
            evidence_refs,
        };
        receipt.validate_for_probe(request, &activation)?;
        Ok(receipt)
    }
}
