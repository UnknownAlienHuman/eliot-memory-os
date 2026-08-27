//! Runtime manifest selection for the independent watchdog.
//!
//! Architecture: A8, ARCH-WDG-01, ARCH-WDG-02, A13.2, ARCH-AUTH-01, ARCH-SEC-02, ARCH-RES-01
//! Implementation: I1.2, I1.4, I1.5, I8, B.5, I14.16
//!
//! Watchdog observes and validates the installer-approved lineage only. It owns
//! no semantic or Host lifecycle authority; selection is an exact, fail-closed
//! read of the approved generation, pending activation, and service registration
//! contour derived from the SCM bootstrap.

use std::path::{Path, PathBuf};

use eliot_installation::{
    ApprovedGenerationRegistry, CandidateManifest, PendingActivationState,
    RedbInstallationRegistry, phase_b_scm_selector,
};
use eliot_platform_windows::{ProtectedRootLease, ServiceBootstrapArguments, windows_paths_equal};

use crate::SpoolError;

pub(crate) fn select_runtime_manifest(
    registry: &ApprovedGenerationRegistry,
    bootstrap: &ServiceBootstrapArguments,
) -> Result<CandidateManifest, SpoolError> {
    let matching_generations = registry
        .generations()
        .iter()
        .filter(|generation| manifest_matches_bootstrap(&generation.manifest, bootstrap))
        .collect::<Vec<_>>();
    if matching_generations.len() > 1 {
        return Err(SpoolError::InvalidLease(
            "multiple approved generations match the SCM bootstrap".to_owned(),
        ));
    }
    let active_match = registry
        .active()
        .filter(|active| manifest_matches_bootstrap(&active.manifest, bootstrap));
    if let Some(pending) = registry.pending_activation() {
        if !matches!(pending.state, PendingActivationState::Pending) {
            return Err(SpoolError::InvalidLease(
                "pending activation is recovery-required".to_owned(),
            ));
        }
        let pending_match = manifest_matches_bootstrap(&pending.manifest, bootstrap);
        match (active_match, pending_match) {
            (Some(active), false) => {
                let Some(matching) = matching_generations.first() else {
                    return Err(SpoolError::InvalidLease(
                        "active generation has no approved projection".to_owned(),
                    ));
                };
                if matching.manifest != active.manifest {
                    return Err(SpoolError::InvalidLease(
                        "active generation projection was substituted".to_owned(),
                    ));
                }
                Ok(active.manifest.clone())
            }
            (None, true) => {
                let Some(matching) = matching_generations.first() else {
                    return Err(SpoolError::InvalidLease(
                        "pending activation has no approved generation projection".to_owned(),
                    ));
                };
                if matching.manifest != pending.manifest {
                    return Err(SpoolError::InvalidLease(
                        "pending activation projection was substituted".to_owned(),
                    ));
                }
                Ok(pending.manifest.clone())
            }
            (Some(_), true) => Err(SpoolError::InvalidLease(
                "active and pending generations both match the SCM bootstrap".to_owned(),
            )),
            (None, false) => Err(SpoolError::InvalidLease(
                "pending activation does not match the SCM bootstrap".to_owned(),
            )),
        }
    } else {
        let Some(active) = active_match.or_else(|| registry.active()) else {
            return Err(SpoolError::InvalidLease(
                "no active or matching pending approved generation".to_owned(),
            ));
        };
        if !manifest_matches_bootstrap(&active.manifest, bootstrap) {
            return Err(SpoolError::InvalidLease(
                "active approved generation does not match the SCM bootstrap".to_owned(),
            ));
        }
        let Some(matching) = matching_generations.first() else {
            return Err(SpoolError::InvalidLease(
                "active approved generation has no approved projection".to_owned(),
            ));
        };
        if matching.manifest != active.manifest {
            return Err(SpoolError::InvalidLease(
                "active approved generation projection was substituted".to_owned(),
            ));
        }
        Ok(active.manifest.clone())
    }
}

pub(crate) fn manifest_matches_bootstrap(
    manifest: &CandidateManifest,
    bootstrap: &ServiceBootstrapArguments,
) -> bool {
    let launch = &manifest.runtime_launch;
    let expected_descriptor_digest = phase_b_scm_selector(&launch.authority_descriptor_digest).ok();
    bootstrap.host_state_root().is_some_and(|host_state_root| {
        windows_paths_equal(
            host_state_root,
            Path::new(launch.runtime_state_roots.host_state_root.as_str()),
        )
    }) && bootstrap.config_descriptor_path() == Path::new(launch.authority_descriptor_path.as_str())
        && expected_descriptor_digest
            .as_ref()
            .is_some_and(|expected| bootstrap.config_descriptor_digest() == expected.as_str())
        && bootstrap.installation_id() == launch.installation_epoch.installation.as_str()
        && bootstrap.transaction_plan_generation() == launch.authority_generation.value()
}

pub(crate) fn approved_host_artifact_path(
    manifest: &CandidateManifest,
) -> Result<PathBuf, SpoolError> {
    let (path, _) = manifest
        .runtime_launch
        .host_artifact_binding()
        .map_err(|error| SpoolError::InvalidLease(error.to_string()))?;
    Ok(PathBuf::from(path.as_str()))
}

pub(crate) fn read_registry_for_bootstrap(
    bootstrap: &ServiceBootstrapArguments,
) -> Result<(ApprovedGenerationRegistry, CandidateManifest), SpoolError> {
    let host_state_root = bootstrap.host_state_root().ok_or_else(|| {
        SpoolError::InvalidLease(
            "Watchdog SCM bootstrap omitted the installer-approved Host state root".to_owned(),
        )
    })?;
    let registry = RedbInstallationRegistry::inspect_existing_at(
        ProtectedRootLease::open_existing(host_state_root).map_err(|error| {
            SpoolError::InvalidLease(format!("Host state root open failed: {error}"))
        })?,
    )
    .map_err(|error| SpoolError::InvalidLease(error.to_string()))?
    .ok_or_else(|| SpoolError::InvalidLease("installation registry is missing".to_owned()))?;
    let manifest = select_runtime_manifest(&registry, bootstrap)?;
    Ok((registry, manifest))
}
