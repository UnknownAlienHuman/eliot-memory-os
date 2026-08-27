//! Service registration projection for the independent Watchdog.
//!
//! Architecture: A8 Watchdog (ELIOT_ARCHITECTURE.A8.-Watchdog), Watchdog и Doctor (ELIOT_ARCHITECTURE.Watchdog-и-Doctor)
//! Implementation: I8 Watchdog implementation contract (ELIOT_IMPLEMENTATION.I8.-Watchdog-implementation-contract), I8.1 Process and authority (ELIOT_IMPLEMENTATION.I8.1.-Process-and-authority), B.5 Watchdog (ELIOT_IMPLEMENTATION.B.5.-Watchdog), P.11 Dreamer, Watchdog and Doctor boundaries (ELIOT_IMPLEMENTATION.P.11.-Dreamer,-Watchdog-and-Doctor-boundaries)
//!
//! This module is a read-only, fail-closed projection over installer-approved
//! service registrations. It performs exact deterministic checks against the
//! approved generation and never mutates SCM registration, performs semantic
//! admission, or drives Host lifecycle. Any substitution fails closed.

use std::path::Path;

use eliot_installation::{
    ApprovedGenerationRegistry, CandidateManifest, InstallerServiceRegistrationApproval,
    InstallerServiceRole, phase_b_scm_selector,
};
use eliot_platform_windows::{
    ServiceBootstrapArguments, ServiceRegistrationRequest, windows_paths_equal,
};

use crate::{ApprovedHostRegistration, SERVICE_NAME, SpoolError};

pub(crate) fn service_approval_matches_manifest(
    approval: &InstallerServiceRegistrationApproval,
    request: &ServiceRegistrationRequest,
    manifest: &CandidateManifest,
    role: InstallerServiceRole,
) -> bool {
    let launch = &manifest.runtime_launch;
    let Some(bootstrap) = request.bootstrap() else {
        return false;
    };
    let Some(host_state_root) = bootstrap.host_state_root() else {
        return false;
    };
    let expected_image = match role {
        InstallerServiceRole::Host => launch.host_executable_path.as_str(),
        InstallerServiceRole::Watchdog => launch.watchdog_executable_path.as_str(),
    };
    let expected_descriptor_digest = phase_b_scm_selector(&launch.authority_descriptor_digest).ok();
    approval.generation() == &manifest.generation
        && approval.role() == role
        && request.service_name()
            == match role {
                InstallerServiceRole::Host => eliot_platform_windows::ELIOT_HOST_SERVICE_NAME,
                InstallerServiceRole::Watchdog => SERVICE_NAME,
            }
        && windows_paths_equal(
            bootstrap.config_descriptor_path(),
            Path::new(launch.authority_descriptor_path.as_str()),
        )
        && expected_descriptor_digest
            .as_ref()
            .is_some_and(|expected| bootstrap.config_descriptor_digest() == expected.as_str())
        && bootstrap.installation_id() == launch.installation_epoch.installation.as_str()
        && bootstrap.transaction_plan_generation() == launch.authority_generation.value()
        && windows_paths_equal(
            host_state_root,
            Path::new(launch.runtime_state_roots.host_state_root.as_str()),
        )
        && windows_paths_equal(request.binary_path(), Path::new(expected_image))
}

pub(crate) fn approved_service_registration(
    registry: &ApprovedGenerationRegistry,
    manifest: &CandidateManifest,
    role: InstallerServiceRole,
) -> Result<
    (
        InstallerServiceRegistrationApproval,
        ServiceRegistrationRequest,
    ),
    SpoolError,
> {
    let approval = registry
        .service_registration_approval(&manifest.generation, role)
        .ok_or_else(|| {
            SpoolError::InvalidLease("installer SCM registration approval is missing".to_owned())
        })?;
    let request = approval.service_registration_request().map_err(|_| {
        SpoolError::InvalidLease("installer SCM registration approval is invalid".to_owned())
    })?;
    if !service_approval_matches_manifest(approval, &request, manifest, role) {
        return Err(SpoolError::InvalidLease(
            "installer SCM registration approval does not bind the selected generation".to_owned(),
        ));
    }
    Ok((approval.clone(), request))
}

pub(crate) fn load_approved_service_registrations(
    registry: &ApprovedGenerationRegistry,
    manifest: &CandidateManifest,
    bootstrap: &ServiceBootstrapArguments,
) -> Result<(ApprovedHostRegistration, ServiceRegistrationRequest), SpoolError> {
    let (host_approval, _) =
        approved_service_registration(registry, manifest, InstallerServiceRole::Host)?;
    let (_, watchdog_request) =
        approved_service_registration(registry, manifest, InstallerServiceRole::Watchdog)?;
    if watchdog_request.bootstrap() != Some(bootstrap) {
        return Err(SpoolError::InvalidLease(
            "Watchdog SCM bootstrap does not match the installer approval".to_owned(),
        ));
    }
    let approved_host_registration = ApprovedHostRegistration::from_approval(&host_approval)?;
    Ok((approved_host_registration, watchdog_request))
}

pub(crate) fn read_approved_service_registration(
    bootstrap: &ServiceBootstrapArguments,
    role: InstallerServiceRole,
) -> Result<
    (
        CandidateManifest,
        InstallerServiceRegistrationApproval,
        ServiceRegistrationRequest,
    ),
    SpoolError,
> {
    let (registry, manifest) = crate::read_registry_for_bootstrap(bootstrap)?;
    let (approval, request) = approved_service_registration(&registry, &manifest, role)?;
    Ok((manifest, approval, request))
}

pub(crate) fn validate_bound_service_registrations(
    registry: &ApprovedGenerationRegistry,
    manifest: &CandidateManifest,
    expected_host_request: &ServiceRegistrationRequest,
    expected_watchdog_request: &ServiceRegistrationRequest,
    bootstrap: &ServiceBootstrapArguments,
) -> Result<(), SpoolError> {
    let (_, host_request) =
        approved_service_registration(registry, manifest, InstallerServiceRole::Host)?;
    let (_, watchdog_request) =
        approved_service_registration(registry, manifest, InstallerServiceRole::Watchdog)?;
    if host_request != *expected_host_request
        || watchdog_request != *expected_watchdog_request
        || watchdog_request.bootstrap() != Some(bootstrap)
    {
        return Err(SpoolError::InvalidLease(
            "installer SCM registration approval changed after watchdog binding".to_owned(),
        ));
    }
    Ok(())
}
