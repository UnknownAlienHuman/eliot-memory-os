//! Kernel composition adapters for the shared crash reporter.
//!
//! This module copies only the Host-injected, already admitted Kernel symbol
//! identity and owner-supplied bounded context. It never reads environment
//! values or resolves a PDB path itself.

use std::path::{Path, PathBuf};

use eliot_installation::{AdmittedSymbolBinding, SymbolExecutableRole};
use eliot_observability_runtime::{
    CrashExecutableRole, CrashReportError, CrashRuntimeContext, RollingLogPolicy, SymbolArtifact,
};

/// Projects the exact authenticated Kernel symbol record into the shared
/// report schema. `None` stays absent so the reporter emits an explicit gap.
pub(crate) fn kernel_symbol_artifact(
    binding: Option<&AdmittedSymbolBinding>,
) -> Result<Option<SymbolArtifact>, CrashReportError> {
    let Some(binding) = binding else {
        return Ok(None);
    };
    if binding.role != SymbolExecutableRole::Kernel {
        return Err(CrashReportError::InvalidMetadata(
            "symbol_artifact.role_mismatch",
        ));
    }
    let artifact = SymbolArtifact {
        role: CrashExecutableRole::Kernel,
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

/// Uses the Host-injected receipt root for the non-authoritative crash
/// evidence sidecar.
#[must_use]
pub(crate) fn report_directory(receipt_root: &Path) -> PathBuf {
    receipt_root.join("crash-reports")
}

/// Reuses the exact finite bounds selected for Kernel operational logging,
/// while separating security-incident evidence into its own owned directory
/// and generation name.
pub(crate) fn incident_retention_policy(
    mut operational_policy: RollingLogPolicy,
    receipt_root: &Path,
) -> RollingLogPolicy {
    operational_policy.directory = report_directory(receipt_root);
    operational_policy.file_stem = "crash-evidence".to_owned();
    operational_policy
}

/// Creates the explicit pre-composition snapshot for Kernel startup.
#[must_use]
pub(crate) fn unavailable_context() -> CrashRuntimeContext {
    CrashRuntimeContext::unavailable()
}
