//! Service registration status observation and projection.
//!
//! Architecture (verified): A2.3, A11.3, A11.4, A13.10, ARCH-MOD-02, ARCH-OBS-01.
//! Read-only service-registration observation and projection bound to the
//! exact installer-owned SCM approval and active manifest. No lifecycle, no
//! SCM mutation/admission, no Kernel/Store/eliotd/ORS/Host journal/canonical/
//! readiness authority, no retry/cache/default/mint/state ownership.
//!
//! Implementation (verified): I1.8, I1.9, I1.10, I3.4, I14.20.
//! Coherent production observation/projection closure for
//! `ServiceRegistrationState` — `canonical_service_name`,
//! `expected_service_image`, `approved_service_registration_request`,
//! `unknown_service_registration`, `project_service_runtime_identity`,
//! `project_matching_service_registration`,
//! `project_service_registration_inspection`,
//! `inspect_approved_service_registration`, `service_gap_for` and strictly
//! coupled `ServiceRegistrationState`/`ServiceRuntimeIdentity`/helpers.
//! Fail-closed on missing or mismatched evidence.
//!
//! Topology: I2.2, I2.23 — separate service-registration topology; not
//! conflated with readiness or canonical lifecycle.

#![forbid(unsafe_code)]

use std::path::Path;
use std::time::Instant;

use eliot_installation::{ApprovedGenerationRegistry, CandidateManifest, InstallerServiceRole};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ServiceRegistrationState {
    pub registration: String,
    pub state: String,
    /// Kept for wire compatibility with the first Runtime Live projection.
    /// It is intentionally never populated from a configured image path:
    /// configured SCM data is not a live process observation.
    pub observed_process: Option<String>,
    /// Handle-bound process identity observed by SCM, when the canonical
    /// registration and live process can be read back together.
    #[serde(default)]
    pub observed_runtime: Option<ServiceRuntimeIdentity>,
    pub gap: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceRuntimeIdentity {
    pub process_id: u32,
    pub start_time_100ns: u64,
    pub image_path: String,
    pub runtime_identity_digest: String,
}

fn service_gap(name: &str) -> String {
    format!(
        "authoritative {name} observation unavailable; no typed read-only {name} health adapter exists; SCM Running does not prove readiness"
    )
}

fn canonical_service_name(role: InstallerServiceRole) -> &'static str {
    match role {
        InstallerServiceRole::Host => eliot_platform_windows::ELIOT_HOST_SERVICE_NAME,
        InstallerServiceRole::Watchdog => eliot_platform_windows::ELIOT_WATCHDOG_SERVICE_NAME,
    }
}

fn expected_service_image(manifest: &CandidateManifest, role: InstallerServiceRole) -> &str {
    match role {
        InstallerServiceRole::Host => manifest.runtime_launch.host_executable_path.as_str(),
        InstallerServiceRole::Watchdog => manifest.runtime_launch.watchdog_executable_path.as_str(),
    }
}

fn approved_service_registration_request(
    registry: &ApprovedGenerationRegistry,
    manifest: &CandidateManifest,
    role: InstallerServiceRole,
) -> Result<eliot_platform_windows::ServiceRegistrationRequest, String> {
    let approval = registry
        .service_registration_approval(&manifest.generation, role)
        .ok_or_else(|| {
            format!(
                "active manifest has no installer-owned {} SCM approval",
                canonical_service_name(role)
            )
        })?;
    let request = approval.service_registration_request().map_err(|error| {
        format!(
            "active {} SCM approval is invalid: {error}",
            canonical_service_name(role)
        )
    })?;
    if request.service_name() != canonical_service_name(role) {
        return Err(format!(
            "active {} SCM approval selected a non-canonical service name",
            canonical_service_name(role)
        ));
    }
    if !eliot_platform_windows::windows_paths_equal(
        request.binary_path(),
        Path::new(expected_service_image(manifest, role)),
    ) {
        return Err(format!(
            "active {} SCM approval image differs from the approved manifest",
            canonical_service_name(role)
        ));
    }
    let Some(bootstrap) = request.bootstrap() else {
        return Err(format!(
            "active {} SCM approval has no typed bootstrap",
            canonical_service_name(role)
        ));
    };
    let runtime = &manifest.runtime_launch;
    let bootstrap_root = bootstrap.host_state_root().ok_or_else(|| {
        format!(
            "active {} SCM approval has no Host state-root binding",
            canonical_service_name(role)
        )
    })?;
    if !eliot_platform_windows::windows_paths_equal(
        bootstrap_root,
        Path::new(runtime.runtime_state_roots.host_state_root.as_str()),
    ) || !eliot_platform_windows::windows_paths_equal(
        bootstrap.config_descriptor_path(),
        Path::new(runtime.authority_descriptor_path.as_str()),
    ) || bootstrap.config_descriptor_digest() != runtime.authority_descriptor_digest.as_str()
        || bootstrap.installation_id() != runtime.installation_epoch.installation.as_str()
        || bootstrap.transaction_plan_generation() != runtime.authority_generation.value()
    {
        return Err(format!(
            "active {} SCM approval bootstrap differs from the approved manifest",
            canonical_service_name(role)
        ));
    }
    Ok(request)
}

fn unknown_service_registration(name: &str, gap: impl Into<String>) -> ServiceRegistrationState {
    ServiceRegistrationState {
        registration: "Unknown".to_owned(),
        state: "Unknown".to_owned(),
        observed_process: None,
        observed_runtime: None,
        gap: gap.into().replace("{name}", name),
    }
}

fn project_service_runtime_identity(
    observation: &eliot_platform_windows::ServiceRuntimeObservation,
) -> Option<ServiceRuntimeIdentity> {
    let process = observation.process()?;
    let runtime_identity_digest = observation.runtime_identity_digest()?;
    Some(ServiceRuntimeIdentity {
        process_id: process.process_id,
        start_time_100ns: process.start_time_100ns,
        image_path: process.image_path.clone(),
        runtime_identity_digest,
    })
}

fn project_matching_service_registration(
    observation: &eliot_platform_windows::ServiceRuntimeObservation,
) -> ServiceRegistrationState {
    let name = observation.service_name().to_owned();
    let state = format!("{:?}", observation.state());
    let observed_runtime = project_service_runtime_identity(observation);
    let gap = if observation.is_running() {
        format!(
            "SCM {name} Running and handle-bound process identity observed; Running/liveness alone does not prove semantic readiness"
        )
    } else if observed_runtime.is_some() {
        format!(
            "SCM {name} {state} with handle-bound process identity; service semantic readiness remains unproven"
        )
    } else {
        format!(
            "SCM {name} {state} observed without a live process identity; service semantic readiness remains unproven"
        )
    };
    ServiceRegistrationState {
        registration: "Matching".to_owned(),
        state,
        observed_process: None,
        observed_runtime,
        gap,
    }
}

pub(crate) fn project_service_registration_inspection(
    name: &str,
    inspection: eliot_platform_windows::ServiceRegistrationRuntimeInspection,
) -> ServiceRegistrationState {
    match inspection {
        eliot_platform_windows::ServiceRegistrationRuntimeInspection::Matching { observation } => {
            project_matching_service_registration(&observation)
        }
        eliot_platform_windows::ServiceRegistrationRuntimeInspection::Absent => {
            ServiceRegistrationState {
                registration: "Absent".to_owned(),
                state: "Absent".to_owned(),
                observed_process: None,
                observed_runtime: None,
                gap: format!("service {name} is not registered in SCM"),
            }
        }
        eliot_platform_windows::ServiceRegistrationRuntimeInspection::Mismatched => {
            ServiceRegistrationState {
                registration: "Mismatched".to_owned(),
                state: "Unknown".to_owned(),
                observed_process: None,
                observed_runtime: None,
                gap: format!(
                    "SCM {name} registration or live image differs from the exact approved request"
                ),
            }
        }
        eliot_platform_windows::ServiceRegistrationRuntimeInspection::Unknown => {
            unknown_service_registration(
                name,
                "authoritative SCM {name} configuration or live process observation is indeterminate",
            )
        }
    }
}

pub(crate) fn inspect_approved_service_registration(
    registry: Option<&ApprovedGenerationRegistry>,
    manifest: Option<&CandidateManifest>,
    role: InstallerServiceRole,
    canonical_root: &Path,
    deadline: Instant,
) -> ServiceRegistrationState {
    let name = canonical_service_name(role);
    if Instant::now() >= deadline {
        return unknown_service_registration(
            name,
            "deadline exceeded before SCM {name} inspection",
        );
    }
    let Some(registry) = registry else {
        return unknown_service_registration(
            name,
            "active approved registry is unavailable; SCM {name} request cannot be reconstructed",
        );
    };
    let Some(manifest) = manifest else {
        return unknown_service_registration(
            name,
            "active approved manifest is unavailable; SCM {name} request cannot be reconstructed",
        );
    };
    let request = match approved_service_registration_request(registry, manifest, role) {
        Ok(request) => request,
        Err(gap) => return unknown_service_registration(name, gap),
    };
    if Instant::now() >= deadline {
        return unknown_service_registration(name, "deadline exceeded before SCM {name} readback");
    }
    let platform = match eliot_platform_windows::WindowsPlatform::new(canonical_root) {
        Ok(platform) => platform,
        Err(error) => {
            return unknown_service_registration(
                name,
                format!("SCM {name} read-only adapter root unavailable: {error}"),
            );
        }
    };
    project_service_registration_inspection(
        name,
        platform.inspect_service_registration_runtime(&request),
    )
}

pub fn service_gap_for(name: &str) -> String {
    service_gap(name)
}
