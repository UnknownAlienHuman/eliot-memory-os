//! Host-owned I1.11 startup evidence producers (steps 1, 2, and 4), Windows only.
//!
//! Architecture: I1.11 (startup algorithm), I1.5 (no supervised claim without
//! fresh observation), A0.3 (fail closed where a silent gap could become hidden
//! authority). This child binds live Host probes into the shared
//! [`HostStartupEvidence`] carrier; it owns no Kernel admission, no step
//! cursor, and no canonical authority. Marking steps is the Kernel consumer's
//! exclusive authority.
//!
//! Closed per-probe semantics: every digest below names bytes the Host actually
//! read and validated at send time. A missing Blob probe is `None` (step 4
//! stays unmarked); it is never a fabricated digest. A present-but-invalid
//! Blob manifest fails the whole payload closed (tamper direction): proceeding
//! past blob tamper could later fabricate a canonical `BlobRef` (I1.11 step 4).
//! The caller passes the registry-selected ACTIVE manifest (`registry.active()`);
//! the producer digests it and cross-checks the candidate artifact against it,
//! so a foreign manifest can never bind.

use std::path::{Path, PathBuf};

use eliot_contracts::{EpochId, ResourceGeneration, StateFence};
use eliot_host_state::{HostStateJournalService, JournalBackend};
use eliot_installation::CandidateManifest;
use eliot_kernel_service::{HostKernelCandidateBinding, HostStartupEvidence};
use eliot_platform::PlatformHandle;
use sha2::{Digest as _, Sha256};

use super::HostError;
use super::watchdog_heartbeat::HeartbeatTransportDescriptor;

/// Upper bound for one Blob manifest read, matching the transport file
/// discipline: manifests are small descriptors, never payload stores.
const BLOB_MANIFEST_LIMIT: u64 = 4096;
/// Canonical Blob manifest file below the store data root.
const BLOB_MANIFEST_FILE: &str = "manifest.json";
/// Canonical Blob root below the store data root (planner convention).
const BLOB_ROOT_DIR: &str = "blob";

/// Builds the closed startup evidence from live Host probes.
///
/// The caller passes the registry-selected ACTIVE manifest; selection itself
/// stays at the call site (`registry.active()`), while this producer digests
/// it and pins the candidate artifact to it. The journal snapshot is taken
/// fresh here (not reused from an earlier start phase) so the checksum names
/// the current head. The SCM incarnation comes from the bound heartbeat
/// descriptor (SCM-verified at bind) revalidated live against the OS; a dead
/// or substituted writer fails closed instead of producing stale evidence.
///
/// # Errors
///
/// Returns an error for an unreadable journal, a missing activation head
/// checksum, no usable active manifest, a candidate artifact that does not
/// match the registry-selected manifest, an unbound/absent descriptor, a dead
/// or substituted watchdog incarnation, a tampered Blob manifest, or evidence
/// that fails its own wire validation.
pub(super) fn build_host_startup_evidence<B: JournalBackend>(
    journal: &HostStateJournalService<B>,
    active_manifest: &CandidateManifest,
    candidate: &HostKernelCandidateBinding,
    generation: ResourceGeneration,
    kernel_authority_epoch: EpochId,
    host_state_root: &Path,
    store_data_root: &Path,
) -> Result<HostStartupEvidence, HostError> {
    // Step 1a: the journal's own head checksum. The producer runs after
    // activation appends, so a missing checksum is corruption, never genesis.
    let journal_state = journal
        .snapshot()
        .map_err(|error| HostError::ProcessContour(error.to_string()))?;
    let head_checksum = journal_state.last_checksum.ok_or_else(|| {
        HostError::RecoveryRequired(
            "Host journal has no head checksum for startup evidence".to_owned(),
        )
    })?;
    let host_record_checksum = PlatformHandle::new(head_checksum)
        .map_err(|error| HostError::ProcessContour(error.to_string()))?;
    // Step 1b: the registry-selected manifest, digested plus pinned to the
    // candidate artifact. A foreign manifest fails here, never downstream.
    active_manifest
        .validate()
        .map_err(|error| HostError::ProcessContour(error.to_string()))?;
    if candidate.artifact_hash.as_str() != active_manifest.kernel_artifact_digest.as_str() {
        return Err(HostError::ProcessContour(
            "startup candidate artifact is not the registry-selected Kernel artifact".to_owned(),
        ));
    }
    let artifact_registry_digest = active_manifest
        .compute_digest()
        .map_err(|error| HostError::ProcessContour(error.to_string()))?;
    // Step 1c: the SCM-verified watchdog incarnation, live-revalidated with
    // real artifact identity (never a path-string hash).
    let scm_watchdog_observation_digest = observe_scm_watchdog_incarnation(
        host_state_root,
        &active_manifest.runtime_launch.watchdog_artifact_digest,
    )?;
    // Step 4: the Blob manifest probe. Absent file means demand-start has not
    // produced a manifest yet (None, step 4 unmarkable); a present file must
    // survive contour, bounds, and parse before its bytes become evidence.
    let blob_manifest_digest = read_blob_manifest_digest(store_data_root)?;
    let state_fence = StateFence::new(kernel_authority_epoch, generation);
    let candidate_digest = candidate
        .compute_digest()
        .map_err(|error| HostError::ProcessContour(error.to_string()))?;
    let evidence = HostStartupEvidence {
        candidate_digest,
        state_fence,
        host_record_checksum: host_record_checksum.clone(),
        artifact_registry_digest: artifact_registry_digest.clone(),
        scm_watchdog_observation_digest: scm_watchdog_observation_digest.clone(),
        blob_manifest_digest: blob_manifest_digest.clone(),
        evidence_refs: startup_evidence_refs(
            &host_record_checksum,
            &artifact_registry_digest,
            &scm_watchdog_observation_digest,
            blob_manifest_digest.as_ref(),
        )?,
    };
    // Prove what we send passes the shared wire contract.
    evidence
        .validate()
        .map_err(|error| HostError::ProcessContour(error.to_string()))?;
    Ok(evidence)
}

/// Revalidates the SCM-verified watchdog incarnation live and digests its real
/// artifact identity.
///
/// The bound descriptor names the incarnation SCM verified Running at bind
/// time. This gate additionally requires the same PID/start pair from the OS
/// right now, a live process, and image BYTES whose digest equals the approved
/// watchdog artifact digest: a swapped image at the same path fails closed.
/// Path-string hashes are not identity proof (they survive an image swap), so
/// the path is never hashed here — only the protected file bytes are.
///
/// The digest names the exact live incarnation
/// (`host-scm-watchdog:{pid}:{start}:{image}`) so the Kernel consumer can
/// parse it and cross-check it against Host-observed heartbeat peer evidence.
fn observe_scm_watchdog_incarnation(
    host_state_root: &Path,
    approved_watchdog_artifact: &PlatformHandle,
) -> Result<PlatformHandle, HostError> {
    let descriptor = HeartbeatTransportDescriptor::load(host_state_root)
        .map_err(|error| HostError::ProcessContour(error.to_string()))?
        .ok_or_else(|| {
            HostError::RecoveryRequired(
                "no bound heartbeat descriptor backs the SCM watchdog observation".to_owned(),
            )
        })?;
    if !descriptor.is_bound() {
        return Err(HostError::RecoveryRequired(
            "heartbeat descriptor carries no verified watchdog incarnation".to_owned(),
        ));
    }
    let live_start = eliot_windows_ipc::process_creation_ticks(descriptor.watchdog_incarnation_pid)
        .map_err(|error| {
            HostError::RecoveryRequired(format!("watchdog incarnation is unknown: {error}"))
        })?;
    if live_start != descriptor.watchdog_incarnation_start_100ns {
        return Err(HostError::RecoveryRequired(
            "watchdog incarnation changed since SCM verification".to_owned(),
        ));
    }
    let alive = eliot_windows_ipc::process_is_alive(descriptor.watchdog_incarnation_pid).map_err(
        |error| HostError::RecoveryRequired(format!("watchdog liveness is unknown: {error}")),
    )?;
    if !alive {
        return Err(HostError::RecoveryRequired(
            "SCM-verified watchdog process has exited".to_owned(),
        ));
    }
    let image = eliot_windows_ipc::process_image_path(descriptor.watchdog_incarnation_pid)
        .map_err(|error| {
            HostError::RecoveryRequired(format!("watchdog image is unknown: {error}"))
        })?;
    // Real artifact identity: hash the protected file bytes once and require
    // equality with the approved digest. The bytes hashed are exactly the
    // bytes read; a swapped image changes the digest and fails closed here.
    let image_bytes = std::fs::read(&image).map_err(|error| {
        HostError::RecoveryRequired(format!("watchdog image is unreadable: {error}"))
    })?;
    let image_digest = format!("{:x}", Sha256::digest(&image_bytes));
    if image_digest != approved_watchdog_artifact.as_str() {
        return Err(HostError::RecoveryRequired(
            "watchdog image does not match the approved artifact".to_owned(),
        ));
    }
    PlatformHandle::new(format!(
        "host-scm-watchdog:{}:{}:{image_digest}",
        descriptor.watchdog_incarnation_pid, descriptor.watchdog_incarnation_start_100ns
    ))
    .map_err(|error| HostError::ProcessContour(error.to_string()))
}

/// Reads and validates the Blob manifest, returning its evidence digest.
///
/// Absent file: demand-start has not produced a manifest yet, so there is no
/// step-4 evidence (`None`); no demand is invented to justify a manifest.
/// Present file: must carry the Host-owner contour, fit the manifest bound,
/// and conform to the declared `eliot-types::BlobManifest` field contract
/// (`manifest_id`, `generated_at`, `blob_root`, `blobs`, `total_bytes`,
/// `checksum_algorithm`); the digest covers the validated raw bytes. Contour
/// violation, oversize, or schema-nonconformant bytes fail closed (tamper
/// direction), never degrade to `None`. Plain parseable JSON that does not
/// conform is not a validated canonical manifest.
fn read_blob_manifest_digest(store_data_root: &Path) -> Result<Option<PlatformHandle>, HostError> {
    let path: PathBuf = store_data_root.join(BLOB_ROOT_DIR).join(BLOB_MANIFEST_FILE);
    let bytes = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(HostError::RecoveryRequired(format!(
                "Blob manifest is unreadable: {error}"
            )));
        }
    };
    eliot_windows_ipc::verify_file_owner_and_dacl(&path).map_err(|error| {
        HostError::RecoveryRequired(format!("Blob manifest contour is not intact: {error}"))
    })?;
    if bytes.len() as u64 > BLOB_MANIFEST_LIMIT {
        return Err(HostError::RecoveryRequired(
            "Blob manifest exceeds its bounded size".to_owned(),
        ));
    }
    let value: serde_json::Value = serde_json::from_slice(&bytes)
        .map_err(|_| HostError::RecoveryRequired("Blob manifest is not valid JSON".to_owned()))?;
    if !blob_manifest_conforms(&value) {
        return Err(HostError::RecoveryRequired(
            "Blob manifest does not conform to the declared BlobManifest contract".to_owned(),
        ));
    }
    let digest = format!("{:x}", Sha256::digest(&bytes));
    PlatformHandle::new(format!("host-blob-manifest:{digest}"))
        .map(Option::Some)
        .map_err(|error| HostError::ProcessContour(error.to_string()))
}

/// Checks conformance to the declared `eliot-types::BlobManifest` field
/// contract without taking a new crate dependency: the structural field set
/// is checked here (presence plus JSON kinds); any contract change there must
/// update this check. Structural conformance keeps the dependency surface
/// unchanged; it does not enroll a second Blob owner.
fn blob_manifest_conforms(value: &serde_json::Value) -> bool {
    let Some(object) = value.as_object() else {
        return false;
    };
    let text_field = |name: &str| object.get(name).is_some_and(serde_json::Value::is_string);
    text_field("manifest_id")
        && text_field("generated_at")
        && text_field("blob_root")
        && object.get("blobs").is_some_and(serde_json::Value::is_array)
        && object
            .get("total_bytes")
            .is_some_and(serde_json::Value::is_u64)
        && text_field("checksum_algorithm")
}

/// Closed per-probe evidence refs. Absent probes contribute no ref: the gap
/// stays visible as missing evidence rather than a marker value.
fn startup_evidence_refs(
    journal: &PlatformHandle,
    registry: &PlatformHandle,
    scm: &PlatformHandle,
    blob: Option<&PlatformHandle>,
) -> Result<Vec<PlatformHandle>, HostError> {
    let mut refs = Vec::with_capacity(4);
    for (prefix, handle) in [
        ("host-startup-journal", journal),
        ("host-startup-registry", registry),
        ("host-startup-scm", scm),
    ] {
        refs.push(
            PlatformHandle::new(format!("{prefix}:{}", handle.as_str()))
                .map_err(|error| HostError::ProcessContour(error.to_string()))?,
        );
    }
    if let Some(digest) = blob {
        refs.push(
            PlatformHandle::new(format!("host-startup-blob:{}", digest.as_str()))
                .map_err(|error| HostError::ProcessContour(error.to_string()))?,
        );
    }
    Ok(refs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use eliot_host_state::MemoryBackend;
    use eliot_installation::{
        InstallationEpoch, InstallationProfile, RuntimeLaunchDescriptor, RuntimeStateRoots,
        SupervisionAuthorityBinding,
    };
    use eliot_kernel_service::{
        HostFileIdentity, HostJobBinding, HostJobIdentity, HostJobRoot, HostProcessBinding,
        RestartBudget,
    };
    use eliot_runtime_contracts::{
        RegisteredActivityWakePolicy, SupervisionJournalEpoch, SupervisionLeaseIncarnationBinding,
        SupervisionObservationScope,
    };

    static EVIDENCE_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

    fn handle(value: &str) -> PlatformHandle {
        PlatformHandle::new(value).unwrap_or_else(|_| panic!("test handle must build"))
    }

    fn hex_handle(byte: &str) -> PlatformHandle {
        handle(byte.repeat(64).as_str())
    }

    fn evidence_dir() -> PathBuf {
        let n = EVIDENCE_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        std::env::temp_dir().join(format!("eliot-host-evidence-{}-{n}", std::process::id()))
    }

    fn test_epoch(sequence: u64) -> EpochId {
        EpochId::new(
            eliot_contracts::EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000")
                .unwrap_or_else(|_| panic!("lineage must parse")),
            std::num::NonZeroU64::new(sequence).unwrap_or_else(|| panic!("sequence must fit")),
        )
        .unwrap_or_else(|_| panic!("epoch must build"))
    }

    fn test_host_epoch() -> eliot_host_state::HostInstallationEpoch {
        eliot_host_state::HostInstallationEpoch {
            installation: handle("test-installation-1967"),
            epoch: eliot_contracts::EpochTransition::genesis(
                eliot_contracts::EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000")
                    .unwrap_or_else(|_| panic!("lineage must parse")),
            ),
            nonce: handle("test-host-nonce-1967"),
            recovery: None,
        }
    }

    fn test_journal() -> HostStateJournalService<MemoryBackend> {
        HostStateJournalService::from_backend(MemoryBackend::default(), test_host_epoch())
            .unwrap_or_else(|_| panic!("test journal must open"))
    }

    fn append_clean_marker(
        journal: &HostStateJournalService<MemoryBackend>,
        host: &eliot_host_state::HostInstallationEpoch,
    ) {
        use eliot_host_state::{
            ActivationState, CleanMarker, EliotActivationRecord, HostKernelStoreLineage,
            HostStateRecord, IdempotencyIdentity, JournalManifest, LifecycleTimestamps,
            ReadinessEvidence, RecordFence,
        };
        let generation = eliot_contracts::EpochTransition::genesis(
            eliot_contracts::EpochLineageId::new("660e8400-e29b-41d4-a716-446655440000")
                .unwrap_or_else(|_| panic!("lineage must parse")),
        );
        let fence = RecordFence {
            host: host.clone(),
            activation_id: handle("activation-evidence-1"),
            activation_generation: generation.clone(),
        };
        // A Stopped activation first: the clean-marker reducer only accepts
        // the genesis-without-runtime-contour shape.
        let activation = HostStateRecord::Activation(EliotActivationRecord {
            fence: fence.clone(),
            operation: IdempotencyIdentity {
                operation_id: handle("operation-evidence-genesis"),
                idempotency_key: handle("idempotency-evidence-genesis"),
            },
            activation_id: handle("activation-evidence-1"),
            trigger_class: handle("observable-use"),
            trigger_evidence: vec![handle("trigger-evidence")],
            requester_principal_session_or_scheduler: handle("principal-session"),
            requested_capabilities: vec![handle("kernel-control")],
            candidate_scope: handle("installation-scope"),
            state: ActivationState::Stopped,
            drain_generation: None,
            lineage: HostKernelStoreLineage {
                host_epoch: host.epoch.current.clone(),
                kernel_epoch: test_epoch(1),
                watchdog_epoch: test_epoch(1),
                store_generation: test_epoch(1),
            },
            readiness: ReadinessEvidence {
                supervision_ready: false,
                control_ready: false,
                evidence_refs: vec![handle("readiness-evidence")],
            },
            governance_profile: handle("governed-profile"),
            runtime_lease_refs: vec![],
            supervision_lease_refs: vec![],
            wake_intent_refs: vec![],
            drain_commit_ref: None,
            wake_during_drain_disposition: None,
            boot_session_evidence: vec![handle("boot-session-evidence")],
            power_transition_evidence: vec![],
            timestamps: LifecycleTimestamps {
                started_at: Some(handle("t-started")),
                ready_at: None,
                draining_at: None,
                stopped_at: Some(handle("t-stopped")),
            },
            failure_and_recovery_directive: None,
        });
        journal
            .append(activation)
            .unwrap_or_else(|_| panic!("genesis activation must append"));
        // The marker covers the exact current head: sequence and checksum of
        // the activation just appended.
        let head = journal
            .snapshot()
            .unwrap_or_else(|_| panic!("journal must snapshot"))
            .last_checksum
            .unwrap_or_else(|| panic!("activation must leave a head checksum"));
        let record = HostStateRecord::CleanMarker(CleanMarker {
            fence,
            operation: IdempotencyIdentity {
                operation_id: handle("operation-evidence-1"),
                idempotency_key: handle("idempotency-evidence-1"),
            },
            manifest: JournalManifest {
                schema_version: eliot_host_state::JOURNAL_VERSION,
                last_sequence: 1,
                last_checksum: handle(head.as_str()),
            },
            shutdown_evidence_refs: vec![handle("host-owner-release-fenced")],
        });
        journal
            .append(record)
            .unwrap_or_else(|_| panic!("clean marker must append"));
    }

    fn test_roots(dir: &Path) -> RuntimeStateRoots {
        std::fs::create_dir_all(dir).unwrap_or_else(|_| panic!("test roots must build"));
        // Provision the user-owned contour first: the portable derivation
        // opens a read lease that requires it.
        drop(
            eliot_platform_windows::UserOwnedRootLease::open_existing(dir)
                .unwrap_or_else(|_| panic!("portable root must provision")),
        );
        RuntimeStateRoots::derive_portable(handle(dir.to_string_lossy().as_ref()))
            .unwrap_or_else(|_| panic!("portable roots must derive"))
    }

    fn test_launch(dir: &Path, roots: &RuntimeStateRoots) -> RuntimeLaunchDescriptor {
        let path = |name: &str| handle(dir.join(name).to_string_lossy().as_ref());
        let installation_epoch = InstallationEpoch {
            installation: handle("test-installation-1967"),
            lineage_id: handle("lineage-test-1967"),
            sequence: 1,
        };
        RuntimeLaunchDescriptor {
            profile: InstallationProfile::PortableDev,
            portable_root: Some(roots.installation_root.clone()),
            installation_epoch,
            generation: handle("generation-evidence-1"),
            authority_generation: ResourceGeneration::new(7)
                .unwrap_or_else(|_| panic!("generation")),
            authority_state_fence: StateFence::new(
                test_epoch(7),
                ResourceGeneration::new(7).unwrap_or_else(|_| panic!("generation")),
            ),
            authority_descriptor_path: path("authority.json"),
            // Phase-A pair: pending markers with Pending authority (the
            // producer only reads the watchdog artifact digest below; the
            // launch contour itself is installer-admitted, not re-proven here).
            authority_descriptor_digest: handle(eliot_installation::PHASE_B_PENDING_MARKER),
            supervision_authority: SupervisionAuthorityBinding::Pending {
                supervision_lease_scope_id: handle("test-supervision-scope"),
            },
            runtime_state_roots: roots.clone(),
            kernel_work_root: roots.kernel_work_root.clone(),
            kernel_artifact_digest: hex_handle("4"),
            eliotd_executable_path: path("eliotd.exe"),
            eliotd_artifact_digest: hex_handle("e"),
            eliotd_config_path: path("eliotd-governor.json"),
            eliotd_config_digest: hex_handle("2"),
            protected_snapshot_digest: hex_handle("a"),
            eliotd_descriptor_path: path("eliotd.json"),
            eliotd_descriptor_digest: hex_handle("f"),
            eliotd_launch_nonce: handle("eliotd:11111111111111111111111111111111"),
            store_config_path: handle(dir.join("generation.json").to_string_lossy().as_ref()),
            store_credential_target: handle("eliot/store/v1/0123456789abcdef0123456789abcdef"),
            store_bridge_executable_path: path("eliot-store-surreal.exe"),
            store_bridge_artifact_digest: hex_handle("1"),
            store_bootstrap_descriptor_path: path("store-bootstrap.json"),
            store_bootstrap_descriptor_digest: handle(eliot_installation::PHASE_B_PENDING_MARKER),
            canonical_store_executable_path: path("surreal.exe"),
            canonical_store_artifact_digest: hex_handle("5"),
            kernel_arguments: vec![
                handle("--work-root"),
                roots.kernel_work_root.clone(),
                handle("--store-bootstrap"),
                path("store-bootstrap.json"),
                handle("--store-bootstrap-sha256"),
                handle(eliot_installation::PHASE_B_PENDING_MARKER),
                handle("--authority-descriptor"),
                path("authority.json"),
                handle("--authority-descriptor-sha256"),
                handle(eliot_installation::PHASE_B_PENDING_MARKER),
                handle("--kernel-artifact-sha256"),
                hex_handle("4"),
                handle("--doctor-artifact-sha256"),
                hex_handle("b"),
                handle("--testd-artifact-sha256"),
                hex_handle("c"),
                handle("--native-worker-artifact-sha256"),
                hex_handle("d"),
                handle("--eliotd-descriptor"),
                path("eliotd.json"),
                handle("--eliotd-descriptor-sha256"),
                hex_handle("f"),
            ],
            store_bridge_arguments: vec![
                handle("--portable-dev-root"),
                handle(roots.installation_root.as_str()),
                handle("--config"),
                handle(dir.join("generation.json").to_string_lossy().as_ref()),
            ],
            canonical_store_arguments: vec![
                handle("start"),
                handle("--no-banner"),
                handle("--bind"),
                handle("127.0.0.1:8000"),
                handle("--temporary-directory"),
                roots.store_temp_root.clone(),
                handle("--log-file-enabled"),
                handle("--log-file-path"),
                roots.store_work_root.clone(),
                handle("--log-file-name"),
                handle("surrealdb.log"),
                handle(
                    format!(
                        "surrealkv://{}",
                        roots.store_data_root.as_str().replace('\\', "/")
                    )
                    .as_str(),
                ),
            ],
            host_executable_path: path("eliot-host.exe"),
            host_artifact_digest: hex_handle("e"),
            watchdog_executable_path: path("eliot-watchdog.exe"),
            // The approved digest names the exact bytes of this test binary:
            // the fixture watchdog IS this process, so artifact identity holds.
            watchdog_artifact_digest: own_image_approved(),
            doctor_executable_path: path("eliot-doctor.exe"),
            doctor_artifact_digest: hex_handle("b"),
            testd_executable_path: path("eliot-testd.exe"),
            testd_artifact_digest: hex_handle("c"),
            native_worker_executable_path: path("eliot-native-worker.exe"),
            native_worker_artifact_digest: hex_handle("d"),
            wasm_host_executable_path: path("eliot-wasm-host.exe"),
            wasm_host_artifact_digest: hex_handle("f"),
            descriptor_digest: hex_handle("0"),
        }
        .with_computed_digest()
        .unwrap_or_else(|_| panic!("launch must seal"))
        .with_computed_digest()
        .unwrap_or_else(|_| panic!("launch must seal"))
    }

    fn test_manifest(dir: &Path) -> eliot_installation::CandidateManifest {
        let portable = dir.join("portable");
        let roots = test_roots(&portable);
        let launch = test_launch(dir, &roots);
        let manifest = eliot_installation::CandidateManifest {
            generation: handle("generation-evidence-1"),
            components: vec![handle("component:kernel"), handle("component:store")],
            kernel_artifact_digest: hex_handle("4"),
            store_bridge_artifact_digest: hex_handle("1"),
            canonical_store_artifact_digest: hex_handle("5"),
            host_artifact_digest: hex_handle("e"),
            doctor_artifact_digest: hex_handle("b"),
            testd_artifact_digest: hex_handle("c"),
            native_worker_artifact_digest: hex_handle("d"),
            wasm_host_artifact_digest: hex_handle("f"),
            kernel_executable_path: handle(dir.join("eliot-kernel.exe").to_string_lossy().as_ref()),
            store_bridge_executable_path: handle(
                dir.join("eliot-store-surreal.exe")
                    .to_string_lossy()
                    .as_ref(),
            ),
            canonical_store_executable_path: handle(
                dir.join("surreal.exe").to_string_lossy().as_ref(),
            ),
            host_executable_path: handle(dir.join("eliot-host.exe").to_string_lossy().as_ref()),
            doctor_executable_path: handle(dir.join("eliot-doctor.exe").to_string_lossy().as_ref()),
            testd_executable_path: handle(dir.join("eliot-testd.exe").to_string_lossy().as_ref()),
            native_worker_executable_path: handle(
                dir.join("eliot-native-worker.exe")
                    .to_string_lossy()
                    .as_ref(),
            ),
            wasm_host_executable_path: handle(
                dir.join("eliot-wasm-host.exe").to_string_lossy().as_ref(),
            ),
            config_path: handle(dir.join("generation.json").to_string_lossy().as_ref()),
            dependency_closure_refs: vec![handle("evidence:dependency-closure")],
            license_refs: vec![handle("evidence:licenses")],
            config_digest: hex_handle("2"),
            store_credential_target: handle("eliot/store/v1/0123456789abcdef0123456789abcdef"),
            supervision_key_slot: hex_handle("6"),
            signature_ref: handle("evidence:signature"),
            runtime_state_roots_digest: roots.roots_digest.clone(),
            runtime_launch: launch,
        };
        manifest
            .validate()
            .unwrap_or_else(|_| panic!("manifest must validate"));
        manifest
    }

    fn test_candidate(
        kernel_artifact: &PlatformHandle,
        kernel_epoch: EpochId,
    ) -> HostKernelCandidateBinding {
        HostKernelCandidateBinding {
            installation_id: handle("test-installation-1967"),
            host_epoch: eliot_contracts::AuthorityEpoch::new(1)
                .unwrap_or_else(|_| panic!("host epoch")),
            kernel_epoch,
            activation_id: handle("activation-evidence-1"),
            artifact_hash: kernel_artifact.clone(),
            config_hash: hex_handle("2"),
            job_object_id: handle("Local\\Eliot-Host-Kernel-evidence"),
            pipe_identity: handle("\\\\.\\pipe\\eliot\\kernel\\evidence"),
            host_process: HostProcessBinding {
                process_id: std::process::id(),
                start_time_100ns: 1,
                image_path: "C:\\eliot\\host.exe".to_owned(),
            },
            job_binding: HostJobBinding {
                job: HostJobIdentity {
                    name: "Local\\Eliot-Host-Kernel-evidence".to_owned(),
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
            supervision_incarnation: SupervisionLeaseIncarnationBinding {
                supervision_lease_scope_id: "eliot-supervision-scope:v1:test".to_owned(),
                supervision_lease_id: String::new(),
                scope_ref_digest: String::new(),
                installation_id: "test-installation-1967".to_owned(),
                host_epoch: SupervisionJournalEpoch {
                    lineage_id: "host-lineage-1".to_owned(),
                    sequence: 1,
                },
                activation_id: "activation-evidence-1".to_owned(),
                activation_generation: SupervisionJournalEpoch {
                    lineage_id: "activation-lineage-1".to_owned(),
                    sequence: 1,
                },
                kernel_generation: SupervisionJournalEpoch {
                    lineage_id: "kernel-lineage-1".to_owned(),
                    sequence: 1,
                },
                watchdog_epoch: SupervisionJournalEpoch {
                    lineage_id: "watchdog-lineage-1".to_owned(),
                    sequence: 1,
                },
                observation_scope: SupervisionObservationScope {
                    targets: vec!["eliot-kernel".to_owned()],
                    sensor_profile: "eliot-runtime-live-v3".to_owned(),
                    claimed_coverage: vec!["process".to_owned(), "job".to_owned()],
                    governance_axis: "runtime-live-v3".to_owned(),
                },
                wake_policy: RegisteredActivityWakePolicy::Disabled,
                predecessor: None,
            }
            .with_derived_ids()
            .unwrap_or_else(|_| panic!("sealed supervision incarnation")),
            restart_budget: RestartBudget::new(1, 1).unwrap_or_else(|_| panic!("budget")),
            agent_bridge_admission: None,
            containment_action: None,
        }
    }

    fn self_incarnation() -> (u32, u64) {
        let pid = std::process::id();
        let start = eliot_windows_ipc::process_creation_ticks(pid)
            .unwrap_or_else(|_| panic!("own creation ticks must query"));
        (pid, start)
    }

    fn own_image_approved() -> PlatformHandle {
        let exe = std::env::current_exe().unwrap_or_else(|_| panic!("test image must resolve"));
        let bytes = std::fs::read(&exe).unwrap_or_else(|_| panic!("test image must read"));
        let digest = format!("{:x}", Sha256::digest(&bytes));
        // The approved digest names the exact bytes just read: a swapped image
        // changes the digest, so this binding is real artifact identity.
        handle(digest.as_str())
    }

    fn bind_self_descriptor(dir: &Path) -> HeartbeatTransportDescriptor {
        let mut descriptor = HeartbeatTransportDescriptor::issue("test-installation-1967", 7)
            .unwrap_or_else(|_| panic!("descriptor must issue"));
        let (pid, start) = self_incarnation();
        descriptor.watchdog_incarnation_pid = pid;
        descriptor.watchdog_incarnation_start_100ns = start;
        descriptor
            .publish(dir)
            .unwrap_or_else(|_| panic!("descriptor must publish"));
        descriptor
    }

    struct EvidenceSetup {
        dir: PathBuf,
        journal: HostStateJournalService<MemoryBackend>,
        manifest: eliot_installation::CandidateManifest,
        candidate: HostKernelCandidateBinding,
        generation: ResourceGeneration,
        epoch: EpochId,
    }

    fn evidence_setup() -> EvidenceSetup {
        let dir = evidence_dir();
        std::fs::create_dir_all(&dir).unwrap_or_else(|_| panic!("evidence dir must build"));
        std::fs::create_dir_all(dir.join("portable"))
            .unwrap_or_else(|_| panic!("portable dir must build"));
        let host = test_host_epoch();
        let journal = test_journal_with_host(&host);
        append_clean_marker(&journal, &host);
        let manifest = test_manifest(&dir);
        let epoch = test_epoch(11);
        let generation = ResourceGeneration::new(7).unwrap_or_else(|_| panic!("generation"));
        let candidate = test_candidate(&manifest.kernel_artifact_digest, epoch.clone());
        bind_self_descriptor(&dir);
        EvidenceSetup {
            dir,
            journal,
            manifest,
            candidate,
            generation,
            epoch,
        }
    }

    fn test_journal_with_host(
        host: &eliot_host_state::HostInstallationEpoch,
    ) -> HostStateJournalService<MemoryBackend> {
        HostStateJournalService::from_backend(MemoryBackend::default(), host.clone())
            .unwrap_or_else(|_| panic!("test journal must open"))
    }

    fn build_evidence(setup: &EvidenceSetup) -> Result<HostStartupEvidence, HostError> {
        build_host_startup_evidence(
            &setup.journal,
            &setup.manifest,
            &setup.candidate,
            setup.generation,
            setup.epoch.clone(),
            &setup.dir,
            &setup.dir,
        )
    }

    #[test]
    fn producer_binds_real_probes_and_self_validates() {
        let setup = evidence_setup();
        let evidence = build_evidence(&setup).unwrap_or_else(|_| panic!("evidence must build"));
        // Candidate, fence, and journal bindings are exact.
        assert_eq!(
            evidence.candidate_digest,
            setup
                .candidate
                .compute_digest()
                .unwrap_or_else(|_| panic!("candidate digest must compute"))
        );
        assert!(
            evidence
                .state_fence
                .authority_epoch
                .is_same_authority(&setup.epoch)
        );
        assert_eq!(evidence.state_fence.resource_generation, setup.generation);
        let head = setup
            .journal
            .snapshot()
            .unwrap_or_else(|_| panic!("journal must snapshot"))
            .last_checksum
            .unwrap_or_else(|| panic!("journal must carry a head checksum"));
        assert_eq!(evidence.host_record_checksum.as_str(), head);
        assert_eq!(
            evidence.artifact_registry_digest.as_str(),
            setup
                .manifest
                .compute_digest()
                .unwrap_or_else(|_| panic!("manifest digest must compute"))
                .as_str()
        );
        // The SCM digest names this live process with its real image bytes.
        let (pid, start) = self_incarnation();
        assert!(
            evidence
                .scm_watchdog_observation_digest
                .as_str()
                .starts_with(&format!("host-scm-watchdog:{pid}:{start}:"))
        );
        // No Blob demand exists in the temp root: step 4 stays unmarked with
        // no ref, and the remaining three refs ride the record.
        assert!(evidence.blob_manifest_digest.is_none());
        assert_eq!(evidence.evidence_refs.len(), 3);
        evidence
            .validate()
            .unwrap_or_else(|_| panic!("built evidence must pass wire validation"));
        let _ = std::fs::remove_dir_all(&setup.dir);
    }

    #[test]
    fn producer_rejects_empty_journal_head() {
        let dir = evidence_dir();
        std::fs::create_dir_all(&dir).unwrap_or_else(|_| panic!("evidence dir must build"));
        let host = test_host_epoch();
        let journal = test_journal_with_host(&host);
        let manifest = test_manifest(&dir);
        let epoch = test_epoch(11);
        let candidate = test_candidate(&manifest.kernel_artifact_digest, epoch.clone());
        bind_self_descriptor(&dir);
        let error = build_host_startup_evidence(
            &journal,
            &manifest,
            &candidate,
            ResourceGeneration::new(7).unwrap_or_else(|_| panic!("generation")),
            epoch,
            &dir,
            &dir,
        )
        .unwrap_err();
        assert!(
            format!("{error:?}").contains("head checksum"),
            "missing journal checksum must fail closed, got: {error:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn producer_rejects_foreign_candidate_artifact() {
        let setup = evidence_setup();
        let mut foreign = setup.candidate.clone();
        foreign.artifact_hash = hex_handle("f");
        let error = build_host_startup_evidence(
            &setup.journal,
            &setup.manifest,
            &foreign,
            setup.generation,
            setup.epoch.clone(),
            &setup.dir,
            &setup.dir,
        )
        .unwrap_err();
        assert!(
            format!("{error:?}").contains("not the registry-selected Kernel artifact"),
            "wrong candidate artifact must fail closed, got: {error:?}"
        );
        let _ = std::fs::remove_dir_all(&setup.dir);
    }

    #[test]
    fn producer_rejects_stale_watchdog_incarnation() {
        let dir = evidence_dir();
        std::fs::create_dir_all(&dir).unwrap_or_else(|_| panic!("evidence dir must build"));
        let host = test_host_epoch();
        let journal = test_journal_with_host(&host);
        append_clean_marker(&journal, &host);
        let manifest = test_manifest(&dir);
        let epoch = test_epoch(11);
        let candidate = test_candidate(&manifest.kernel_artifact_digest, epoch.clone());
        // Bind a provably dead incarnation: the liveness revalidation must fail.
        let mut child = std::process::Command::new("cmd")
            .args(["/C", "exit 0"])
            .spawn()
            .unwrap_or_else(|_| panic!("probe process must spawn"));
        let dead_pid = child.id();
        let dead_start = eliot_windows_ipc::process_creation_ticks(dead_pid)
            .unwrap_or_else(|_| panic!("probe incarnation must query"));
        child
            .wait()
            .unwrap_or_else(|_| panic!("probe process must exit"));
        let mut stale = HeartbeatTransportDescriptor::issue("test-installation-1967", 7)
            .unwrap_or_else(|_| panic!("descriptor must issue"));
        stale.watchdog_incarnation_pid = dead_pid;
        stale.watchdog_incarnation_start_100ns = dead_start;
        stale
            .publish(&dir)
            .unwrap_or_else(|_| panic!("stale descriptor must publish"));
        let error = build_host_startup_evidence(
            &journal,
            &manifest,
            &candidate,
            ResourceGeneration::new(7).unwrap_or_else(|_| panic!("generation")),
            epoch,
            &dir,
            &dir,
        )
        .unwrap_err();
        assert!(
            format!("{error:?}").contains("incarnation") || format!("{error:?}").contains("exited"),
            "stale watchdog incarnation must fail closed, got: {error:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn producer_rejects_substituted_watchdog_image() {
        let setup = evidence_setup();
        // Approve a digest that is not this process's image bytes: the
        // artifact binding must fail even though PID/start are live.
        let error = observe_scm_watchdog_incarnation(&setup.dir, &hex_handle("0")).unwrap_err();
        assert!(
            format!("{error:?}").contains("approved artifact"),
            "substituted image must fail closed, got: {error:?}"
        );
        let _ = std::fs::remove_dir_all(&setup.dir);
    }

    #[test]
    fn producer_reports_absent_blob_without_fabrication() {
        let setup = evidence_setup();
        let evidence = build_evidence(&setup).unwrap_or_else(|_| panic!("evidence must build"));
        assert!(evidence.blob_manifest_digest.is_none());
        assert!(
            evidence
                .evidence_refs
                .iter()
                .all(|handle| !handle.as_str().starts_with("host-startup-blob:"))
        );
    }

    #[test]
    fn producer_binds_validated_blob_manifest_bytes() {
        let setup = evidence_setup();
        let blob_dir = setup.dir.join("blob");
        std::fs::create_dir_all(&blob_dir).unwrap_or_else(|_| panic!("blob dir must build"));
        let manifest_path = blob_dir.join("manifest.json");
        let manifest_bytes = serde_json::to_vec(&serde_json::json!({
            "manifest_id": "blob-manifest-evidence-1",
            "generated_at": "2026-09-21T00:00:00Z",
            "blob_root": blob_dir.to_string_lossy(),
            "blobs": [],
            "total_bytes": 0,
            "checksum_algorithm": "sha256",
        }))
        .unwrap_or_else(|_| panic!("blob manifest must encode"));
        std::fs::write(&manifest_path, &manifest_bytes)
            .unwrap_or_else(|_| panic!("blob manifest must write"));
        eliot_windows_ipc::restrict_file_to_current_user_and_system(&manifest_path)
            .unwrap_or_else(|_| panic!("blob manifest must carry the contour"));
        let evidence = build_evidence(&setup).unwrap_or_else(|_| panic!("evidence must build"));
        let expected = format!("{:x}", Sha256::digest(&manifest_bytes));
        assert_eq!(
            evidence.blob_manifest_digest,
            Some(
                PlatformHandle::new(format!("host-blob-manifest:{expected}"))
                    .unwrap_or_else(|_| panic!("blob digest handle must build"))
            )
        );
        assert!(
            evidence
                .evidence_refs
                .iter()
                .any(|handle| handle.as_str().starts_with("host-startup-blob:"))
        );
        let _ = std::fs::remove_dir_all(&setup.dir);
    }

    #[test]
    fn producer_rejects_tampered_blob_manifest() {
        for (name, bytes, contour) in [
            ("raw", b"stale lock bytes".as_slice(), false),
            ("nonconforming", br#"{"wrong": "shape"}"#.as_slice(), true),
        ] {
            let setup = evidence_setup();
            let blob_dir = setup.dir.join("blob");
            std::fs::create_dir_all(&blob_dir).unwrap_or_else(|_| panic!("blob dir must build"));
            let manifest_path = blob_dir.join("manifest.json");
            std::fs::write(&manifest_path, bytes)
                .unwrap_or_else(|_| panic!("{name} manifest must write"));
            if contour {
                eliot_windows_ipc::restrict_file_to_current_user_and_system(&manifest_path)
                    .unwrap_or_else(|_| panic!("{name} manifest must carry the contour"));
            }
            let error = build_evidence(&setup).unwrap_err();
            assert!(
                format!("{error:?}").contains("Blob manifest"),
                "{name} blob manifest must fail closed, got: {error:?}"
            );
            let _ = std::fs::remove_dir_all(&setup.dir);
        }
    }
}
