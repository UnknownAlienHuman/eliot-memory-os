//! Eliotd live observation — Kernel-owned live proof.
//!
//! Architecture A13.2 (Kernel/failure-domain health/unavailable guarantees, module lifecycle):
//! eliotd live is proven only via Kernel-owned observation and never inferred
//! from service registration or file presence alone; unavailable health is the
//! default when evidence is missing or stale.
//! Implementation I16.1 (reports/projections are not truth):
//! this module projects `daemon_ready` and related live bindings as
//! read-only reports/projections, not truth; readiness is validated strictly.

use std::path::{Path, PathBuf};
use std::time::Instant;

use eliot_contracts::sha256_hex;
use serde::{Deserialize, Serialize};

use super::ComponentState;

pub(super) fn eliotd_live_gap() -> String {
    "Kernel-owned eliotd live proof requires current ProcessStartReceipt PID/start/image/executor Job, generation/config/descriptor, authenticated daemon_ready and current supervision authority".to_owned()
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct EliotdLiveSnapshot {
    pub process_id: u32,
    pub start_time_100ns: u64,
    pub image_path: String,
    pub executor_job_name: String,
    pub generation: String,
    pub config_digest: String,
    pub descriptor_digest: String,
    pub daemon_ready: bool,
    pub supervision_epoch: u64,
    pub observed_at_unix_ms: u64,
    pub ready_binding_digest: String,
}

pub trait EliotdLiveObserver {
    fn observe_eliotd_live(&self, deadline: Instant) -> Result<Option<EliotdLiveSnapshot>, String>;
}

#[allow(clippy::too_many_lines, clippy::needless_return)]
#[allow(clippy::similar_names)]
pub(super) fn inspect_eliotd_live(
    host_state: Option<&eliot_host_state::HostState>,
    manifest: Option<&eliot_installation::CandidateManifest>,
    observer: Option<&dyn EliotdLiveObserver>,
    deadline: Instant,
) -> ComponentState {
    if Instant::now() >= deadline {
        return super::unknown_component(
            "eliotd",
            "deadline exceeded before eliotd inspection".to_owned(),
        );
    }
    let Some(host_state) = host_state else {
        return super::unknown_component(
            "eliotd",
            "no HostState for eliotd; Host journal is not validated".to_owned(),
        );
    };
    let Some(kernel) = host_state.kernel.as_ref() else {
        return super::unknown_component(
            "eliotd",
            "no active Kernel record for eliotd; Kernel not Active Consumed".to_owned(),
        );
    };
    if kernel.state != eliot_runtime_contracts::KernelActivationState::Active
        || kernel.one_time_nonce.state() != eliot_host_state::NonceState::Consumed
        || host_state.prior_kernel_unknown
    {
        return super::unknown_component(
            "eliotd",
            format!(
                "Kernel not Active Consumed for eliotd: state {:?} nonce {:?} prior_unknown {}",
                kernel.state,
                kernel.one_time_nonce.state(),
                host_state.prior_kernel_unknown
            ),
        );
    }
    if host_state.readiness_observations.is_empty() {
        return super::unknown_component(
            "eliotd",
            "no KernelReadinessObservationRecord for eliotd freshness".to_owned(),
        );
    }
    let Some(last_observed) = host_state.readiness_observations.last() else {
        return super::unknown_component(
            "eliotd",
            "no KernelReadinessObservationRecord for eliotd freshness".to_owned(),
        );
    };
    let active_checksum = match eliot_host_state::record_checksum(
        &eliot_host_state::HostStateRecord::Kernel(kernel.clone()),
    ) {
        Ok(c) => c,
        Err(e) => {
            return super::unknown_component(
                "eliotd",
                format!("active Kernel checksum failed: {e}"),
            );
        }
    };
    if last_observed
        .validate_against(kernel, &active_checksum)
        .is_err()
    {
        return super::unknown_component(
            "eliotd",
            "readiness observation is not bound to the exact active Kernel checksum/process/Job/authority".to_owned(),
        );
    }
    let now_ms_for_eliotd = match super::current_unix_ms() {
        Ok(v) => v,
        Err(e) => {
            return super::unknown_component("eliotd", format!("current time unavailable: {e}"));
        }
    };
    if let Err(e) =
        super::is_fresh_observed_at(last_observed.observed_at.as_str(), now_ms_for_eliotd)
    {
        return super::unknown_component("eliotd", format!("eliotd readiness not fresh: {e}"));
    }
    let Some(manifest) = manifest else {
        return super::unknown_component(
            "eliotd",
            "active approved manifest is unavailable; eliotd contour is not selected".to_owned(),
        );
    };
    let Some(observer) = observer else {
        return super::unknown_component(
            "eliotd",
            "Kernel-owned EliotdLiveObserver unavailable; no default observer is used; eliotd live proof requires Kernel-owned observation".to_owned(),
        );
    };
    let snapshot = match observer.observe_eliotd_live(deadline) {
        Ok(Some(s)) => s,
        Ok(None) => {
            return super::unknown_component(
                "eliotd",
                "Kernel observer returned no eliotd snapshot; eliotd is not live".to_owned(),
            );
        }
        Err(e) => {
            return super::unknown_component("eliotd", format!("Kernel observer failed: {e}"));
        }
    };
    if Instant::now() >= deadline {
        return super::unknown_component(
            "eliotd",
            "deadline exceeded after eliotd observation".to_owned(),
        );
    }
    if snapshot.process_id == 0 || snapshot.start_time_100ns == 0 {
        return super::unknown_component("eliotd", "eliotd PID or start time is zero".to_owned());
    }
    if snapshot.image_path.trim().is_empty() || snapshot.executor_job_name.trim().is_empty() {
        return super::unknown_component(
            "eliotd",
            "eliotd image_path or Job is empty/whitespace".to_owned(),
        );
    }
    if !eliot_platform_windows::windows_paths_equal(
        Path::new(&snapshot.image_path),
        Path::new(manifest.runtime_launch.eliotd_executable_path.as_str()),
    ) {
        return super::unknown_component(
            "eliotd",
            format!(
                "eliotd image_path {} does not equal current manifest eliotd_executable_path {}",
                snapshot.image_path,
                manifest.runtime_launch.eliotd_executable_path.as_str()
            ),
        );
    }
    if snapshot.config_digest != manifest.runtime_launch.eliotd_config_digest.as_str() {
        return super::unknown_component(
            "eliotd",
            format!(
                "eliotd config_digest {} does not equal manifest {}",
                snapshot.config_digest,
                manifest.runtime_launch.eliotd_config_digest.as_str()
            ),
        );
    }
    if snapshot.generation != manifest.generation.as_str() {
        return super::unknown_component(
            "eliotd",
            format!(
                "eliotd generation {} does not equal manifest generation {}",
                snapshot.generation,
                manifest.generation.as_str()
            ),
        );
    }
    if snapshot.descriptor_digest != manifest.runtime_launch.eliotd_descriptor_digest.as_str() {
        return super::unknown_component(
            "eliotd",
            format!(
                "eliotd descriptor_digest {} does not equal manifest descriptor {}",
                snapshot.descriptor_digest,
                manifest.runtime_launch.eliotd_descriptor_digest.as_str()
            ),
        );
    }
    if !snapshot.daemon_ready {
        return super::unknown_component(
            "eliotd",
            "eliotd daemon_ready is false; not ready".to_owned(),
        );
    }
    if snapshot.supervision_epoch
        != manifest
            .runtime_launch
            .authority_state_fence
            .authority_epoch
            .value()
    {
        return super::unknown_component(
            "eliotd",
            format!(
                "eliotd supervision_epoch {} does not equal manifest authority_state_fence epoch {}",
                snapshot.supervision_epoch,
                manifest
                    .runtime_launch
                    .authority_state_fence
                    .authority_epoch
                    .value()
            ),
        );
    }
    if snapshot.observed_at_unix_ms == 0 {
        return super::unknown_component("eliotd", "eliotd observed_at is zero".to_owned());
    }
    let now_ms = match super::current_unix_ms() {
        Ok(v) => v,
        Err(e) => {
            return super::unknown_component("eliotd", format!("current time unavailable: {e}"));
        }
    };
    if snapshot.observed_at_unix_ms > now_ms.saturating_add(5_000) {
        return super::unknown_component(
            "eliotd",
            format!(
                "eliotd observed_at {} is in the future vs now {now_ms}",
                snapshot.observed_at_unix_ms
            ),
        );
    }
    if now_ms.saturating_sub(snapshot.observed_at_unix_ms) > 60_000 {
        return super::unknown_component(
            "eliotd",
            format!(
                "eliotd observed_at {} is stale vs now {now_ms}",
                snapshot.observed_at_unix_ms
            ),
        );
    }
    let expected_binding = sha256_hex(
        format!(
            "ready:{}:{}:{}",
            snapshot.process_id, snapshot.start_time_100ns, snapshot.observed_at_unix_ms
        )
        .as_bytes(),
    );
    if snapshot.ready_binding_digest != expected_binding {
        return super::unknown_component(
            "eliotd",
            format!(
                "eliotd ready_binding_digest {} does not equal expected binding {}",
                snapshot.ready_binding_digest, expected_binding
            ),
        );
    }
    return super::ComponentState::Healthy;
}

pub struct ProductionEliotdLiveObserver {
    host_state_root: PathBuf,
}

impl ProductionEliotdLiveObserver {
    /// Selects the exact manifest-owned Host state root for observation.
    pub fn for_root(host_state_root: &Path) -> Self {
        Self {
            host_state_root: host_state_root.to_path_buf(),
        }
    }
}

impl EliotdLiveObserver for ProductionEliotdLiveObserver {
    #[allow(clippy::needless_return, clippy::too_many_lines)]
    fn observe_eliotd_live(&self, deadline: Instant) -> Result<Option<EliotdLiveSnapshot>, String> {
        if Instant::now() >= deadline {
            return Err("deadline exceeded before eliotd observation".to_owned());
        }
        if Instant::now() >= deadline {
            return Err("deadline exceeded before eliotd registry read".to_owned());
        }
        let retained = match eliot_platform_windows::ProtectedRootLease::open_existing(
            &self.host_state_root,
        ) {
            Ok(l) => l,
            Err(_) => return Ok(None),
        };
        let canonical = match retained.canonical_path() {
            Ok(p) => p,
            Err(_) => return Ok(None),
        };
        if !eliot_platform_windows::windows_paths_equal(&canonical, &self.host_state_root) {
            return Ok(None);
        }
        if retained.verify_stable_identity().is_err() {
            return Ok(None);
        }
        let registry_lease =
            match eliot_platform_windows::ProtectedRootLease::open_existing(&canonical) {
                Ok(l) => l,
                Err(_) => return Ok(None),
            };
        let registry =
            match eliot_installation::RedbInstallationRegistry::inspect_existing_at(registry_lease)
            {
                Ok(Some(r)) => r,
                _ => return Ok(None),
            };
        if registry.validate().is_err() {
            return Ok(None);
        }
        let manifest = match registry.active() {
            Some(g) => g.manifest.clone(),
            None => return Ok(None),
        };
        if Instant::now() >= deadline {
            return Err("deadline exceeded before eliotd descriptor lease".to_owned());
        }
        let descriptor_path = Path::new(manifest.runtime_launch.eliotd_descriptor_path.as_str());
        if !descriptor_path.is_absolute() {
            return Ok(None);
        }
        let expected_descriptor_digest = manifest.runtime_launch.eliotd_descriptor_digest.as_str();
        if !super::is_sha256_hex(expected_descriptor_digest) {
            return Ok(None);
        }
        #[cfg(windows)]
        let _descriptor_bytes = {
            let portable_opt = manifest
                .runtime_launch
                .portable_root
                .as_ref()
                .map(|h| Path::new(h.as_str()).to_path_buf());
            let bytes_opt: Option<Vec<u8>> = if let Some(portable) = portable_opt {
                let portable_path = portable;
                if descriptor_path.starts_with(&portable_path) {
                    match eliot_platform_windows::UserOwnedRootLease::open_existing(&portable_path)
                    {
                        Ok(root_lease) => {
                            match eliot_platform_windows::UserOwnedPathLease::open_existing(
                                &root_lease,
                                descriptor_path,
                            ) {
                                Ok(file_lease) => {
                                    if file_lease.verify_stable_identity().is_err()
                                        || file_lease.verify_path_identity().is_err()
                                    {
                                        return Ok(None);
                                    }
                                    match file_lease.read_bounded(1024 * 1024) {
                                        Ok(b) => {
                                            if file_lease.verify_stable_identity().is_err() {
                                                return Ok(None);
                                            }
                                            if sha256_hex(&b) != expected_descriptor_digest {
                                                return Ok(None);
                                            }
                                            Some(b)
                                        }
                                        Err(_) => return Ok(None),
                                    }
                                }
                                Err(_) => return Ok(None),
                            }
                        }
                        Err(_) => return Ok(None),
                    }
                } else {
                    match eliot_platform_windows::ProtectedRuntimePathLease::open_existing_absolute(
                        descriptor_path,
                    ) {
                        Ok(lease) => {
                            if lease.verify_stable_identity().is_err()
                                || lease.verify_path_identity().is_err()
                            {
                                return Ok(None);
                            }
                            match lease.read_bounded(1024 * 1024) {
                                Ok(b) => {
                                    if lease.verify_stable_identity().is_err() {
                                        return Ok(None);
                                    }
                                    if sha256_hex(&b) != expected_descriptor_digest {
                                        return Ok(None);
                                    }
                                    Some(b)
                                }
                                Err(_) => return Ok(None),
                            }
                        }
                        Err(_) => return Ok(None),
                    }
                }
            } else {
                match eliot_platform_windows::ProtectedRuntimePathLease::open_existing_absolute(
                    descriptor_path,
                ) {
                    Ok(lease) => {
                        if lease.verify_stable_identity().is_err()
                            || lease.verify_path_identity().is_err()
                        {
                            return Ok(None);
                        }
                        match lease.read_bounded(1024 * 1024) {
                            Ok(b) => {
                                if lease.verify_stable_identity().is_err() {
                                    return Ok(None);
                                }
                                if sha256_hex(&b) != expected_descriptor_digest {
                                    return Ok(None);
                                }
                                Some(b)
                            }
                            Err(_) => return Ok(None),
                        }
                    }
                    Err(_) => return Ok(None),
                }
            };
            match bytes_opt {
                Some(b) => b,
                None => return Ok(None),
            }
        };
        #[cfg(not(windows))]
        {
            let bytes = match std::fs::read(descriptor_path) {
                Ok(b) => b,
                Err(_) => return Ok(None),
            };
            if sha256_hex(&bytes) != expected_descriptor_digest {
                return Ok(None);
            }
            let _ = bytes;
        }
        if retained.verify_stable_identity().is_err() {
            return Ok(None);
        }
        if Instant::now() >= deadline {
            return Err("deadline exceeded before eliotd receipt lease".to_owned());
        }
        let receipt_path = canonical.join("eliotd-receipt.json");
        #[cfg(windows)]
        let receipt_bytes = {
            let lease =
                match eliot_platform_windows::ProtectedRuntimePathLease::open_existing_absolute(
                    &receipt_path,
                ) {
                    Ok(l) => l,
                    Err(_) => return Ok(None),
                };
            if lease.verify_stable_identity().is_err() || lease.verify_path_identity().is_err() {
                return Ok(None);
            }
            let bytes = match lease.read_bounded(1024 * 1024) {
                Ok(b) => b,
                Err(_) => return Ok(None),
            };
            if lease.verify_stable_identity().is_err() {
                return Ok(None);
            }
            bytes
        };
        #[cfg(not(windows))]
        let receipt_bytes = {
            match std::fs::read(&receipt_path) {
                Ok(b) => b,
                Err(_) => return Ok(None),
            }
        };
        #[cfg(windows)]
        let live_receipt: eliot_process::EliotdLiveReceipt =
            match serde_json::from_slice(&receipt_bytes) {
                Ok(r) => r,
                Err(_) => return Ok(None),
            };
        #[cfg(windows)]
        {
            let canonical_receipt_bytes = match eliot_contracts::canonical_json_bytes(&live_receipt)
            {
                Ok(bytes) => bytes,
                Err(_) => return Ok(None),
            };
            if canonical_receipt_bytes != receipt_bytes
                || live_receipt.validate().is_err()
                || !eliot_platform_windows::windows_paths_equal(
                    Path::new(&live_receipt.receipt_root),
                    &canonical,
                )
                || !eliot_platform_windows::windows_paths_equal(
                    Path::new(
                        manifest
                            .runtime_launch
                            .runtime_state_roots
                            .host_state_root
                            .as_str(),
                    ),
                    &canonical,
                )
                || live_receipt.generation != manifest.runtime_launch.authority_generation.value()
                || live_receipt.runtime_state_roots_digest
                    != manifest.runtime_state_roots_digest.as_str()
                || live_receipt.runtime_state_roots_digest
                    != manifest
                        .runtime_launch
                        .runtime_state_roots
                        .roots_digest
                        .as_str()
                || live_receipt.installation_id
                    != manifest
                        .runtime_launch
                        .installation_epoch
                        .installation
                        .as_str()
                || live_receipt.approved_generation != manifest.generation.as_str()
                || live_receipt.authority_epoch
                    != manifest
                        .runtime_launch
                        .authority_state_fence
                        .authority_epoch
                        .value()
                || live_receipt.config_descriptor_sha256
                    != manifest.runtime_launch.eliotd_config_digest.as_str()
                || live_receipt.descriptor_sha256 != expected_descriptor_digest
                || live_receipt.kernel_artifact_sha256
                    != manifest.runtime_launch.kernel_artifact_digest.as_str()
                || live_receipt.kernel_artifact_sha256 != manifest.kernel_artifact_digest.as_str()
                || live_receipt.receipt_root_identity_sha256
                    != sha256_hex(&match serde_json::to_vec(&retained.identity()) {
                        Ok(bytes) => bytes,
                        Err(_) => return Ok(None),
                    })
                || !super::eliotd_live_receipt_ors_matches(
                    &manifest,
                    &live_receipt,
                    &canonical,
                    deadline,
                )
            {
                return Ok(None);
            }
        }
        let receipt: eliot_process::ProcessStartReceipt = {
            #[cfg(windows)]
            {
                live_receipt.process.clone()
            }
            #[cfg(not(windows))]
            {
                match serde_json::from_slice(&receipt_bytes) {
                    Ok(receipt) => receipt,
                    Err(_) => return Ok(None),
                }
            }
        };
        if receipt.validate().is_err() {
            return Ok(None);
        }
        let now_ms = match super::current_unix_ms() {
            Ok(v) => v,
            Err(_) => return Ok(None),
        };
        #[cfg(windows)]
        if live_receipt.published_at_unix_ms == 0
            || live_receipt.published_at_unix_ms > now_ms.saturating_add(5_000)
            || now_ms.saturating_sub(live_receipt.published_at_unix_ms) > 60_000
        {
            return Ok(None);
        }
        let resumed = receipt.identity().resumed_at_unix_ms();
        if resumed == 0
            || resumed > now_ms.saturating_add(5_000)
            || now_ms.saturating_sub(resumed) > 60_000
        {
            return Ok(None);
        }
        let physical = receipt.identity().physical();
        let pid = physical.process_id();
        let start = physical.start_time_100ns();
        let image = physical.image_path().to_owned();
        let job = physical.executor_job_name().to_owned();
        if pid == 0 || start == 0 || image.trim().is_empty() || job.trim().is_empty() {
            return Ok(None);
        }
        if !eliot_platform_windows::windows_paths_equal(
            Path::new(&image),
            Path::new(manifest.runtime_launch.eliotd_executable_path.as_str()),
        ) {
            return Ok(None);
        }
        if receipt.accepted_generation().get()
            != manifest.runtime_launch.authority_generation.value()
        {
            return Ok(None);
        }
        if receipt.binding().state_fence().authority_epoch()
            != manifest
                .runtime_launch
                .authority_state_fence
                .authority_epoch
                .value()
        {
            return Ok(None);
        }
        let observed_at = now_ms;
        #[cfg(windows)]
        {
            if Instant::now() >= deadline {
                return Err("deadline exceeded before eliotd Job observation".to_owned());
            }
            let binding =
                match eliot_platform_windows::observe_named_pipe_peer_process_in_job(&job, pid) {
                    Ok(b) => b,
                    Err(_) => return Ok(None),
                };
            let id = binding.process_binding().identity();
            if id.process_id != pid
                || id.start_time_100ns != start
                || !eliot_platform_windows::windows_paths_equal(
                    Path::new(&id.image_path),
                    Path::new(&image),
                )
                || binding.job_name() != job
            {
                return Ok(None);
            }
            if retained.verify_stable_identity().is_err() {
                return Ok(None);
            }
        }
        #[cfg(not(windows))]
        {
            let live_path = canonical.join("eliotd-live-process.json");
            if !live_path.exists() {
                return Ok(None);
            }
            let live_bytes = match std::fs::read(&live_path) {
                Ok(b) => b,
                Err(_) => return Ok(None),
            };
            let live: serde_json::Value = match serde_json::from_slice(&live_bytes) {
                Ok(v) => v,
                Err(_) => return Ok(None),
            };
            let live_pid = live.get("process_id").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
            let live_start = live
                .get("start_time_100ns")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            let live_image = live
                .get("image_path")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let live_job = live
                .get("executor_job_name")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if live_pid != pid
                || live_start != start
                || !eliot_platform_windows::windows_paths_equal(
                    Path::new(live_image),
                    Path::new(&image),
                )
                || live_job != job
            {
                return Ok(None);
            }
        }
        if retained.verify_stable_identity().is_err() {
            return Ok(None);
        }
        let ready_binding = sha256_hex(format!("ready:{pid}:{start}:{observed_at}").as_bytes());
        let snapshot = EliotdLiveSnapshot {
            process_id: pid,
            start_time_100ns: start,
            image_path: image.clone(),
            executor_job_name: job.clone(),
            generation: manifest.generation.as_str().to_owned(),
            config_digest: manifest
                .runtime_launch
                .eliotd_config_digest
                .as_str()
                .to_owned(),
            descriptor_digest: expected_descriptor_digest.to_owned(),
            daemon_ready: true,
            supervision_epoch: manifest
                .runtime_launch
                .authority_state_fence
                .authority_epoch
                .value(),
            observed_at_unix_ms: observed_at,
            ready_binding_digest: ready_binding,
        };
        if snapshot.supervision_epoch == 0 || snapshot.observed_at_unix_ms == 0 {
            return Ok(None);
        }
        Ok(Some(snapshot))
    }
}
