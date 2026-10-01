//! Host composition adapters for the shared crash reporter.
//!
//! This module copies only the installer-admitted symbol identity and
//! owner-supplied bounded context. It performs no environment, executable, or
//! sibling-symbol lookup of its own.

use eliot_host::HostComposition;
use eliot_installation::{AdmittedSymbolBinding, SymbolExecutableRole};
use eliot_observability_runtime::{
    CrashExecutableRole, CrashReportError, CrashReporterHandle, CrashRuntimeContext,
    RollingLogPolicy, SymbolArtifact,
};

/// Projects the exact admitted Host symbol record into the shared report
/// schema. `None` stays absent so the reporter emits an explicit gap.
pub(crate) fn host_symbol_artifact(
    binding: Option<&AdmittedSymbolBinding>,
) -> Result<Option<SymbolArtifact>, CrashReportError> {
    let Some(binding) = binding else {
        return Ok(None);
    };
    if binding.role != SymbolExecutableRole::Host {
        return Err(CrashReportError::InvalidMetadata(
            "symbol_artifact.role_mismatch",
        ));
    }
    let artifact = SymbolArtifact {
        role: CrashExecutableRole::Host,
        artifact_ref: binding.symbol_artifact_ref.as_str().to_owned(),
        artifact_sha256: binding.symbol_artifact_sha256.as_str().to_owned(),
        executable_sha256: binding.executable_sha256.as_str().to_owned(),
        build_fingerprint: binding.build_fingerprint.as_str().to_owned(),
        build_profile: binding.build_profile.as_str().to_owned(),
        retention_id: binding.retention_id.as_str().to_owned(),
        retention_reference: binding.retention_reference.as_str().to_owned(),
    };
    artifact.validate(&artifact.build_profile)?;
    Ok(Some(artifact))
}

/// Reuses the observability runtime's declared finite rolling bounds for the
/// Host's dedicated incident-evidence surface.
fn incident_retention_policy(report_directory: std::path::PathBuf) -> RollingLogPolicy {
    RollingLogPolicy::declared_bounded(report_directory, "crash-evidence", 0)
}

/// Creates the explicit pre-composition snapshot for Host startup.
#[must_use]
pub(crate) fn unavailable_context() -> CrashRuntimeContext {
    CrashRuntimeContext::unavailable()
}

/// Publishes the Host identities only after its composition has admitted the
/// retained root and active launch descriptor, then attaches the live owner
/// snapshot/update seam.
pub(crate) fn attach_reporter(
    host: &mut HostComposition,
    reporter: &CrashReporterHandle,
) -> Result<(), CrashReportError> {
    let mut incomplete = false;
    let active_launch = host
        .registry()
        .active()
        .map(|active| &active.manifest.runtime_launch);
    if let Some(launch) = active_launch {
        let runtime_profile = match launch.profile {
            eliot_installation::InstallationProfile::SystemService => "system_service",
            eliot_installation::InstallationProfile::UserMode => "user_mode",
            eliot_installation::InstallationProfile::PortableDev => "portable_dev",
        };
        if reporter.update_runtime_profile(runtime_profile).is_err() {
            incomplete = true;
        }
        match host_symbol_artifact(launch.admitted_symbol_binding(SymbolExecutableRole::Host)) {
            Ok(Some(artifact)) => {
                if reporter.update_symbol_artifact(artifact).is_err() {
                    incomplete = true;
                }
            }
            Ok(None) => {}
            Err(_) => incomplete = true,
        }
    }
    if reporter
        .update_retention_policy(incident_retention_policy(host.crash_report_directory()))
        .is_err()
    {
        incomplete = true;
    }
    if incomplete {
        reporter.invalidate_runtime_context();
        Err(CrashReportError::InvalidMetadata(
            "crash_reporter.host_attachment_incomplete",
        ))
    } else if host.attach_crash_reporter(reporter.clone()).is_err() {
        reporter.invalidate_runtime_context();
        Err(CrashReportError::InvalidMetadata(
            "crash_reporter.host_attachment_incomplete",
        ))
    } else {
        Ok(())
    }
}
