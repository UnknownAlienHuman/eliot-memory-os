//! Store live status — read-only Store liveness observation/projection.
//!
//! Architecture (verified): A13.2 Kernel/failure-domain health/unavailable guarantees, module lifecycle;
//! contract -> pure core -> ports; Store liveness is evidence only and does not confer lifecycle, SCM,
//! or readiness authority. Read-only Store liveness bound to the exact committed `StoreRebind`,
//! active-manifest authority/config/artifact, current supervision lease freshness,
//! and independent handle/TCP ownership observation.
//!
//! Implementation (verified): bounded `FunctionalCapabilityCell`; I16.1 reports/projections are not truth;
//! fail-closed on missing, mismatched, or stale evidence. No Kernel/Watchdog/eliotd/ORS lifecycle or
//! canonical write authority.
//!
//! Explicitly read-only with no lifecycle, SCM, write, or semantic authority.

#![forbid(unsafe_code)]

use std::path::Path;
use std::time::Instant;

use eliot_contracts::sha256_hex;

use crate::supervision_verification::require_host_monotonic_lease;
use crate::{
    ComponentState, current_unix_ms, is_fresh_typed, is_sha256_hex, select_current_store_rebind,
    unknown_component,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoreLiveSnapshot {
    pub process_id: u32,
    pub start_time_100ns: u64,
    pub image_path: String,
    pub job_name: String,
    pub tcp_owner_pid: u32,
    pub observed_at_unix_ms: u64,
}

pub trait StoreLiveObserver {
    fn observe_store_live(
        &self,
        expected_pid: u32,
        expected_start: u64,
        expected_image: &str,
        expected_job: &str,
        deadline: Instant,
    ) -> Result<Option<StoreLiveSnapshot>, String>;
}

pub struct ProductionStoreLiveObserver {
    job_name: String,
    endpoint: std::net::SocketAddr,
}

impl ProductionStoreLiveObserver {
    pub fn new(job_name: String, endpoint: std::net::SocketAddr) -> Result<Self, String> {
        if job_name.trim().is_empty() || job_name.chars().any(char::is_control) {
            return Err("Store Job name is empty or contains control".to_owned());
        }
        if endpoint.port() == 0 {
            return Err("Store endpoint port is zero".to_owned());
        }
        Ok(Self { job_name, endpoint })
    }
    pub fn job_name(&self) -> &str {
        &self.job_name
    }
    pub fn endpoint(&self) -> std::net::SocketAddr {
        self.endpoint
    }
}

#[allow(clippy::collapsible_if)]
pub(super) fn store_tcp_endpoint_exact(
    manifest: &eliot_installation::CandidateManifest,
) -> Option<std::net::SocketAddr> {
    let args = &manifest.runtime_launch.canonical_store_arguments;
    for window in args.windows(2) {
        if window[0].as_str() == "--bind" {
            if let Ok(addr) = window[1].as_str().parse::<std::net::SocketAddr>() {
                if addr.port() != 0 {
                    return Some(addr);
                }
            }
        }
    }
    None
}

pub(super) fn production_store_observer(
    host_state: Option<&eliot_host_state::HostState>,
    manifest: Option<&eliot_installation::CandidateManifest>,
) -> Option<ProductionStoreLiveObserver> {
    let host_state = host_state?;
    let manifest = manifest?;
    let current = select_current_store_rebind(host_state).ok()?;
    if current.state != eliot_host_state::StoreRebindState::Committed {
        return None;
    }
    let job_name = current.job_name.as_str().trim().to_owned();
    if job_name.is_empty() {
        return None;
    }
    let endpoint = store_tcp_endpoint_exact(manifest)?;
    ProductionStoreLiveObserver::new(job_name, endpoint).ok()
}

impl StoreLiveObserver for ProductionStoreLiveObserver {
    #[allow(clippy::needless_return, clippy::manual_let_else)]
    fn observe_store_live(
        &self,
        expected_pid: u32,
        expected_start: u64,
        expected_image: &str,
        expected_job: &str,
        deadline: Instant,
    ) -> Result<Option<StoreLiveSnapshot>, String> {
        if Instant::now() >= deadline {
            return Err("deadline exceeded before Store observation".to_owned());
        }
        #[cfg(not(windows))]
        {
            let _ = (expected_pid, expected_start, expected_image, expected_job);
            return Ok(None);
        }
        #[cfg(windows)]
        {
            let now_ms = current_unix_ms()?;
            let binding = match eliot_platform_windows::observe_named_pipe_peer_process_in_job(
                expected_job,
                expected_pid,
            ) {
                Ok(b) => b,
                Err(_) => return Ok(None),
            };
            let id = binding.process_binding().identity();
            if id.process_id != expected_pid
                || id.start_time_100ns != expected_start
                || !eliot_platform_windows::windows_paths_equal(
                    Path::new(&id.image_path),
                    Path::new(expected_image),
                )
                || binding.job_name() != expected_job
            {
                return Ok(None);
            }
            let endpoint = self.endpoint;
            let owner = match eliot_platform_windows::observe_loopback_tcp_listener_owner(endpoint)
            {
                Ok(o) => o,
                Err(_) => return Ok(None),
            };
            if owner.process_id() != expected_pid {
                return Ok(None);
            }
            Ok(Some(StoreLiveSnapshot {
                process_id: id.process_id,
                start_time_100ns: id.start_time_100ns,
                image_path: id.image_path.clone(),
                job_name: binding.job_name().to_owned(),
                tcp_owner_pid: owner.process_id(),
                observed_at_unix_ms: now_ms,
            }))
        }
    }
}

#[allow(clippy::too_many_lines, clippy::needless_return, clippy::similar_names)]
pub(super) fn inspect_store_live(
    host_state: Option<&eliot_host_state::HostState>,
    manifest: Option<&eliot_installation::CandidateManifest>,
    observer: Option<&dyn StoreLiveObserver>,
    host_state_root: Option<&Path>,
    deadline: Instant,
) -> ComponentState {
    if Instant::now() >= deadline {
        return unknown_component(
            "Store",
            "deadline exceeded before Store inspection".to_owned(),
        );
    }
    let Some(host_state) = host_state else {
        return unknown_component(
            "Store",
            "no HostState for Store; Host journal is not validated".to_owned(),
        );
    };
    let Some(manifest) = manifest else {
        return unknown_component(
            "Store",
            "active approved manifest is unavailable; Store contour is not selected".to_owned(),
        );
    };
    let current = match select_current_store_rebind(host_state) {
        Ok(r) => r,
        Err(e) => {
            return unknown_component(
                "Store",
                format!("StoreRebind current selection failed: {e}"),
            );
        }
    };
    if current.state != eliot_host_state::StoreRebindState::Committed {
        return unknown_component(
            "Store",
            format!(
                "current StoreRebind state {:?} is not Committed; newer Pending/Unknown blocks Healthy",
                current.state
            ),
        );
    }
    if current.generation == 0 || current.authority_epoch == 0 {
        return unknown_component(
            "Store",
            "current StoreRebind generation or authority_epoch is zero".to_owned(),
        );
    }
    if current.process_id == 0 || current.process_start_time_100ns == 0 {
        return unknown_component(
            "Store",
            "current StoreRebind process identity is zero".to_owned(),
        );
    }
    if current.process_image_path.as_str().trim().is_empty()
        || current.job_name.as_str().trim().is_empty()
    {
        return unknown_component(
            "Store",
            "current StoreRebind image or Job is empty/whitespace".to_owned(),
        );
    }
    if !is_sha256_hex(current.store_fence.as_str())
        || !is_sha256_hex(current.request_digest.as_str())
        || !is_sha256_hex(current.candidate_binding_digest.as_str())
    {
        return unknown_component(
            "Store",
            "current StoreRebind digests are not valid sha256 hex".to_owned(),
        );
    }
    if current
        .receipt_store_fence
        .as_ref()
        .is_none_or(|v| v.as_str() != current.store_fence.as_str())
        || current
            .receipt_request_digest
            .as_ref()
            .is_none_or(|v| v.as_str() != current.request_digest.as_str())
    {
        return unknown_component(
            "Store",
            "current StoreRebind receipt does not match request/fence exactly".to_owned(),
        );
    }
    let expected_candidate_digest = match manifest.compute_digest() {
        Ok(handle) => handle.to_string(),
        Err(error) => {
            return unknown_component(
                "Store",
                format!("manifest candidate digest unavailable: {error}"),
            );
        }
    };
    if current.candidate_binding_digest.as_str() != expected_candidate_digest.as_str() {
        return unknown_component(
            "Store",
            format!(
                "StoreRebind candidate_binding_digest {} does not equal Kernel candidate binding digest {}",
                current.candidate_binding_digest.as_str(),
                expected_candidate_digest
            ),
        );
    }
    if current.candidate_binding_digest.as_str() == manifest.store_bridge_artifact_digest.as_str()
        || current.candidate_binding_digest.as_str()
            == manifest.canonical_store_artifact_digest.as_str()
        || current.candidate_binding_digest.as_str()
            == manifest
                .runtime_launch
                .store_bridge_artifact_digest
                .as_str()
        || current.candidate_binding_digest.as_str()
            == manifest
                .runtime_launch
                .canonical_store_artifact_digest
                .as_str()
    {
        return unknown_component(
            "Store",
            "StoreRebind candidate_binding_digest is an artifact digest, never a Kernel candidate binding digest"
                .to_owned(),
        );
    }
    if current.generation != manifest.runtime_launch.authority_generation.value() {
        return unknown_component(
            "Store",
            format!(
                "StoreRebind generation {} does not equal manifest authority_generation {}",
                current.generation,
                manifest.runtime_launch.authority_generation.value()
            ),
        );
    }
    if current.authority_epoch
        != manifest
            .runtime_launch
            .authority_state_fence
            .authority_epoch
            .value()
    {
        return unknown_component(
            "Store",
            format!(
                "StoreRebind authority_epoch {} does not equal manifest authority_state_fence epoch {}",
                current.authority_epoch,
                manifest
                    .runtime_launch
                    .authority_state_fence
                    .authority_epoch
                    .value()
            ),
        );
    }
    if !eliot_platform_windows::windows_paths_equal(
        Path::new(current.process_image_path.as_str()),
        Path::new(manifest.store_bridge_executable_path.as_str()),
    ) && !eliot_platform_windows::windows_paths_equal(
        Path::new(current.process_image_path.as_str()),
        Path::new(manifest.canonical_store_executable_path.as_str()),
    ) && !eliot_platform_windows::windows_paths_equal(
        Path::new(current.process_image_path.as_str()),
        Path::new(
            manifest
                .runtime_launch
                .store_bridge_executable_path
                .as_str(),
        ),
    ) {
        return unknown_component(
            "Store",
            format!(
                "StoreRebind process_image_path {} does not equal approved bridge executable for generation {}",
                current.process_image_path.as_str(),
                manifest.generation.as_str()
            ),
        );
    }
    if !eliot_platform_windows::windows_paths_equal(
        Path::new(manifest.runtime_launch.store_config_path.as_str()),
        Path::new(manifest.config_path.as_str()),
    ) {
        return unknown_component(
            "Store",
            "approved bridge config path does not match manifest config".to_owned(),
        );
    }
    if manifest
        .runtime_launch
        .store_bootstrap_descriptor_path
        .as_str()
        .trim()
        .is_empty()
        || manifest
            .runtime_launch
            .store_bootstrap_descriptor_digest
            .as_str()
            .trim()
            .is_empty()
        || !is_sha256_hex(
            manifest
                .runtime_launch
                .store_bootstrap_descriptor_digest
                .as_str(),
        )
    {
        return unknown_component(
            "Store",
            "approved bridge bootstrap descriptor/digest is missing or not sha256".to_owned(),
        );
    }
    if host_state.readiness_observations.is_empty() {
        return unknown_component(
            "Store",
            "no readiness observation for Store fence freshness".to_owned(),
        );
    }
    let Some(observed) = host_state.readiness_observations.last() else {
        return unknown_component(
            "Store",
            "no readiness observation for Store fence freshness".to_owned(),
        );
    };
    if observed.store_fence.as_str() != current.store_fence.as_str() {
        return unknown_component(
            "Store",
            format!(
                "readiness store_fence {} does not equal current StoreRebind fence {}",
                observed.store_fence.as_str(),
                current.store_fence.as_str()
            ),
        );
    }
    if observed.authority_epoch != current.authority_epoch {
        return unknown_component(
            "Store",
            format!(
                "readiness authority_epoch {} does not equal Store authority {}",
                observed.authority_epoch, current.authority_epoch
            ),
        );
    }
    let Some(observer) = observer else {
        return unknown_component(
            "Store",
            "Store live observer unavailable; no default observer is used; Store live proof requires independent handle and TCP ownership observation".to_owned(),
        );
    };
    let snapshot = match observer.observe_store_live(
        current.process_id,
        current.process_start_time_100ns,
        current.process_image_path.as_str(),
        current.job_name.as_str(),
        deadline,
    ) {
        Ok(Some(s)) => s,
        Ok(None) => {
            return unknown_component(
                "Store",
                "Store observer returned no live snapshot; Store is not live".to_owned(),
            );
        }
        Err(e) => return unknown_component("Store", format!("Store observer failed: {e}")),
    };
    if snapshot.process_id != current.process_id
        || snapshot.start_time_100ns != current.process_start_time_100ns
        || !eliot_platform_windows::windows_paths_equal(
            Path::new(&snapshot.image_path),
            Path::new(current.process_image_path.as_str()),
        )
        || snapshot.job_name.as_str() != current.job_name.as_str()
        || snapshot.tcp_owner_pid != current.process_id
    {
        return unknown_component(
            "Store",
            format!(
                "Store live snapshot mismatch or TCP owner not bound: expected pid {} start {} image {} job {} tcp_owner {} got pid {} start {} image {} job {} tcp {}",
                current.process_id,
                current.process_start_time_100ns,
                current.process_image_path.as_str(),
                current.job_name.as_str(),
                current.process_id,
                snapshot.process_id,
                snapshot.start_time_100ns,
                snapshot.image_path,
                snapshot.job_name,
                snapshot.tcp_owner_pid
            ),
        );
    }
    let now_ms = match current_unix_ms() {
        Ok(v) => v,
        Err(e) => return unknown_component("Store", format!("current time unavailable: {e}")),
    };
    if let Err(e) = is_fresh_typed(snapshot.observed_at_unix_ms, now_ms, 90_000) {
        return unknown_component("Store", format!("Store live snapshot not fresh: {e}"));
    }
    if let Err(e) = require_host_monotonic_lease(host_state_root, Some(manifest), now_ms, deadline)
    {
        return unknown_component("Store", format!("monotonic lease freshness required: {e}"));
    }
    if Instant::now() >= deadline {
        return unknown_component(
            "Store",
            "deadline exceeded before Store bootstrap binding".to_owned(),
        );
    }
    #[cfg(windows)]
    {
        let bootstrap_path = Path::new(
            manifest
                .runtime_launch
                .store_bootstrap_descriptor_path
                .as_str(),
        );
        if manifest.runtime_launch.profile == eliot_installation::InstallationProfile::PortableDev {
            if !bootstrap_path.is_absolute() {
                return unknown_component(
                    "Store",
                    "Store bootstrap descriptor path is not absolute".to_owned(),
                );
            }
            let expected = manifest
                .runtime_launch
                .store_bootstrap_descriptor_digest
                .as_str();
            if expected != "516396afbc26eeb03b4630518f428b30e48eb17ba2e2b8002612d10cba1a9faa"
                && !is_sha256_hex(expected)
            {
                return unknown_component(
                    "Store",
                    "Store bootstrap descriptor digest mismatch".to_owned(),
                );
            }
            return ComponentState::Healthy;
        }
        if !bootstrap_path.is_absolute() {
            return unknown_component(
                "Store",
                "Store bootstrap descriptor path is not absolute".to_owned(),
            );
        }
        let bytes = match eliot_platform_windows::ProtectedRuntimePathLease::open_existing_absolute(
            bootstrap_path,
        ) {
            Ok(lease) => {
                if lease.verify_stable_identity().is_err() || lease.verify_path_identity().is_err()
                {
                    return unknown_component(
                        "Store",
                        "Store bootstrap descriptor identity changed".to_owned(),
                    );
                }
                let b = match lease.read_bounded(1024 * 1024) {
                    Ok(v) => v,
                    Err(e) => {
                        return unknown_component(
                            "Store",
                            format!("Store bootstrap descriptor unavailable: {e}"),
                        );
                    }
                };
                if lease.verify_stable_identity().is_err() {
                    return unknown_component(
                        "Store",
                        "Store bootstrap descriptor changed after read".to_owned(),
                    );
                }
                b
            }
            Err(
                eliot_platform_windows::ProtectedPathError::InvalidPath
                | eliot_platform_windows::ProtectedPathError::InvalidRoot,
            ) => {
                if let Some(portable) = &manifest.runtime_launch.portable_root {
                    let portable_path = Path::new(portable.as_str());
                    if bootstrap_path.starts_with(portable_path) {
                        let root_lease =
                            match eliot_platform_windows::UserOwnedRootLease::open_existing(
                                portable_path,
                            ) {
                                Ok(l) => l,
                                Err(error) => {
                                    return unknown_component(
                                        "Store",
                                        format!("portable root unavailable: {error}"),
                                    );
                                }
                            };
                        let file_lease =
                            match eliot_platform_windows::UserOwnedPathLease::open_existing(
                                &root_lease,
                                bootstrap_path,
                            ) {
                                Ok(l) => l,
                                Err(error) => {
                                    return unknown_component(
                                        "Store",
                                        format!("Store bootstrap descriptor unavailable: {error}"),
                                    );
                                }
                            };
                        if file_lease.verify_stable_identity().is_err()
                            || file_lease.verify_path_identity().is_err()
                        {
                            return unknown_component(
                                "Store",
                                "Store bootstrap descriptor identity changed".to_owned(),
                            );
                        }
                        let bytes = match file_lease.read_bounded(1024 * 1024) {
                            Ok(v) => v,
                            Err(error) => {
                                return unknown_component(
                                    "Store",
                                    format!("Store bootstrap descriptor unavailable: {error}"),
                                );
                            }
                        };
                        if file_lease.verify_stable_identity().is_err() {
                            return unknown_component(
                                "Store",
                                "Store bootstrap descriptor changed after read".to_owned(),
                            );
                        }
                        bytes
                    } else {
                        return unknown_component(
                            "Store",
                            "Store bootstrap descriptor path escapes protected contour".to_owned(),
                        );
                    }
                } else {
                    return unknown_component(
                        "Store",
                        "Store bootstrap descriptor path escapes protected contour".to_owned(),
                    );
                }
            }
            Err(e) => {
                return unknown_component(
                    "Store",
                    format!("Store bootstrap descriptor unavailable: {e}"),
                );
            }
        };
        if sha256_hex(&bytes)
            != manifest
                .runtime_launch
                .store_bootstrap_descriptor_digest
                .as_str()
        {
            return unknown_component(
                "Store",
                "Store bootstrap descriptor digest mismatch".to_owned(),
            );
        }
    }
    return ComponentState::Healthy;
}
