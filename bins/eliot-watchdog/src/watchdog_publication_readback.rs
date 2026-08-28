//! Read-only watchdog publication/lease evidence and independent observation
//! routes.
//!
//! Architecture: A8.1, ARCH-WDG-01.
//! Implementation: I8.1, I8.2.
//!
//! This module observes/reads publication evidence only. Lifecycle authority,
//! semantic authority, and canonical authority remain outside and forbidden
//! to this module.

use std::path::{Path, PathBuf};

use eliot_installation::CandidateManifest;
use eliot_ors::{SupervisionLeaseSnapshot, read_current_supervision_lease_read_only};
use eliot_platform_windows::{
    OwnedDirectoryObservation, ProtectedRuntimePathLease, observe_owned_directory_exact,
    windows_paths_equal,
};
use eliot_runtime_contracts::{
    SignedSupervisionLease, SupervisionLeaseError, SupervisionLeaseVerificationContext,
    SupervisionLeaseVerifier, SupervisionTrustAnchor, VerifiedSupervisionLease,
    WATCHDOG_PUBLICATION_DIRECTORY_PREFIX, WatchdogPublicationBundle,
};

use super::{
    KERNEL_ORS_FILE_NAME, LEASE_FILE_LIMIT, SUPERVISION_LEASE_FILE_NAME, SpoolError,
    WATCHDOG_ADMISSION_FILE_NAME, WATCHDOG_PUBLICATION_FILE_NAME, WatchdogAdmissionConfig,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct ObservedWatchdogPublication {
    pub(super) marker: WatchdogPublicationBundle,
    pub(super) admission: WatchdogAdmissionConfig,
    pub(super) lease: SignedSupervisionLease,
    pub(super) raw: OwnedDirectoryObservation,
}

pub(super) fn observe_watchdog_publication(
    path: &Path,
) -> Result<ObservedWatchdogPublication, SpoolError> {
    let raw = observe_owned_directory_exact(
        path,
        &[
            WATCHDOG_ADMISSION_FILE_NAME,
            SUPERVISION_LEASE_FILE_NAME,
            WATCHDOG_PUBLICATION_FILE_NAME,
        ],
        LEASE_FILE_LIMIT,
    )
    .map_err(|error| SpoolError::InvalidLease(error.to_string()))?;
    let admission_bytes = raw
        .bytes(WATCHDOG_ADMISSION_FILE_NAME)
        .ok_or_else(|| SpoolError::InvalidLease("admission child is absent".to_owned()))?;
    let lease_bytes = raw
        .bytes(SUPERVISION_LEASE_FILE_NAME)
        .ok_or_else(|| SpoolError::InvalidLease("lease child is absent".to_owned()))?;
    let marker_bytes = raw
        .bytes(WATCHDOG_PUBLICATION_FILE_NAME)
        .ok_or_else(|| SpoolError::InvalidLease("publication marker is absent".to_owned()))?;
    let admission: WatchdogAdmissionConfig = serde_json::from_slice(admission_bytes)
        .map_err(|error| SpoolError::InvalidLease(error.to_string()))?;
    let lease: SignedSupervisionLease = serde_json::from_slice(lease_bytes)
        .map_err(|error| SpoolError::InvalidLease(error.to_string()))?;
    let marker: WatchdogPublicationBundle = serde_json::from_slice(marker_bytes)
        .map_err(|error| SpoolError::InvalidLease(error.to_string()))?;
    admission
        .validate()
        .map_err(|error| SpoolError::InvalidLease(error.to_string()))?;
    lease
        .validate()
        .map_err(|error| SpoolError::InvalidLease(error.to_string()))?;
    marker
        .validate()
        .map_err(|error| SpoolError::InvalidLease(error.to_string()))?;
    if admission
        .canonical_bytes()
        .map_err(|error| SpoolError::InvalidLease(error.to_string()))?
        != admission_bytes
        || serde_json::to_vec(&lease)
            .map_err(|error| SpoolError::InvalidLease(error.to_string()))?
            != lease_bytes
        || marker
            .canonical_bytes()
            .map_err(|error| SpoolError::InvalidLease(error.to_string()))?
            != marker_bytes
    {
        return Err(SpoolError::InvalidLease(
            "Watchdog publication children are not canonical".to_owned(),
        ));
    }
    marker
        .verify_bytes(admission_bytes, lease_bytes)
        .map_err(|error| SpoolError::InvalidLease(error.to_string()))?;
    if marker.installation_id != admission.installation_id
        || marker.approved_generation != admission.approved_generation
        || marker.supervision_lease_scope_id != admission.supervision_lease_scope_id
        || marker.supervision_lease_id != lease.payload.lease_id
    {
        return Err(SpoolError::InvalidLease(
            "Watchdog marker is not bound to its admission template".to_owned(),
        ));
    }
    let expected_name = marker
        .directory_name()
        .map_err(|error| SpoolError::InvalidLease(error.to_string()))?;
    if path
        .file_name()
        .and_then(|name| name.to_str())
        .is_none_or(|name| !name.eq_ignore_ascii_case(&expected_name))
    {
        return Err(SpoolError::InvalidLease(
            "Watchdog directory is not keyed by its ORS receipt".to_owned(),
        ));
    }
    Ok(ObservedWatchdogPublication {
        marker,
        admission,
        lease,
        raw,
    })
}

pub(super) fn scan_watchdog_publications(
    host_state_root: &Path,
) -> Result<Vec<ObservedWatchdogPublication>, SpoolError> {
    let mut observed = Vec::new();
    for entry in std::fs::read_dir(host_state_root)? {
        let entry = entry?;
        let name = entry
            .file_name()
            .to_str()
            .map(ToOwned::to_owned)
            .ok_or(SpoolError::InvalidProtectedRoot)?;
        if name
            .to_ascii_lowercase()
            .starts_with(WATCHDOG_PUBLICATION_DIRECTORY_PREFIX)
        {
            observed.push(observe_watchdog_publication(&entry.path())?);
        }
    }
    Ok(observed)
}

pub(super) fn read_manifest_selected_ors_current(
    selected_manifest: &CandidateManifest,
    lease_id: &eliot_ors::OperationIdentity,
) -> Result<Option<SupervisionLeaseSnapshot>, SpoolError> {
    let kernel_ors_path = PathBuf::from(
        selected_manifest
            .runtime_launch
            .runtime_state_roots
            .kernel_ors_root
            .as_str(),
    )
    .join(KERNEL_ORS_FILE_NAME);
    let kernel_ors_lease = ProtectedRuntimePathLease::open_existing_absolute(&kernel_ors_path)
        .map_err(|error| SpoolError::InvalidLease(format!("Kernel ORS open failed: {error}")))?;
    if !windows_paths_equal(kernel_ors_lease.path(), &kernel_ors_path) {
        return Err(SpoolError::InvalidLease(
            "Kernel ORS path is not the manifest-selected path".to_owned(),
        ));
    }
    kernel_ors_lease
        .verify_stable_identity()
        .map_err(|error| SpoolError::InvalidLease(format!("Kernel ORS changed: {error}")))?;
    kernel_ors_lease
        .verify_path_identity()
        .map_err(|error| SpoolError::InvalidLease(format!("Kernel ORS path changed: {error}")))?;
    read_current_supervision_lease_read_only(kernel_ors_lease.path(), lease_id)
        .map_err(|error| SpoolError::InvalidLease(format!("Kernel ORS read failed: {error}")))
}

pub(super) fn verify_against_durable_current(
    trust_anchor: &SupervisionTrustAnchor,
    context: &SupervisionLeaseVerificationContext,
    envelope: &SignedSupervisionLease,
    durable_current: Option<SupervisionLeaseSnapshot>,
) -> Result<VerifiedSupervisionLease, SpoolError> {
    let durable_current = durable_current.ok_or_else(|| {
        SpoolError::LeaseFenced("Kernel ORS has no current supervision lease".to_owned())
    })?;
    if durable_current.record.artifact != *envelope {
        return Err(SpoolError::LeaseFenced(
            "signed supervision lease is not the exact durable Kernel ORS artifact".to_owned(),
        ));
    }
    validate_payload_bindings(context, &envelope.payload)
        .map_err(|error| map_lease_verification_error(&error))?;
    let mut context = context.clone();
    context.ors_mirror = durable_current.record.artifact.payload.ors_mirror.clone();
    context
        .validate()
        .map_err(|error| map_lease_verification_error(&error))?;
    let lease = trust_anchor
        .verify(envelope, &context)
        .map_err(|error| map_lease_verification_error(&error))?;
    if lease.payload() != &durable_current.record.artifact.payload {
        return Err(SpoolError::LeaseFenced(
            "verified supervision lease diverged from the durable Kernel ORS artifact".to_owned(),
        ));
    }
    Ok(lease)
}

/// Validates the independently admitted lease contour before replacing the
/// context ORS mirror with the exact durable artifact.  The Store-base
/// runtime-contracts crate predates the shared helper, so this composition
/// root keeps the same comparison local rather than accepting a payload-owned
/// ORS mirror.
fn validate_payload_bindings(
    context: &SupervisionLeaseVerificationContext,
    payload: &eliot_runtime_contracts::SupervisionLease,
) -> Result<(), SupervisionLeaseError> {
    context.validate()?;
    payload
        .validate()
        .map_err(SupervisionLeaseError::InvalidPayload)?;
    if payload.lease_id != context.lease_id {
        return Err(SupervisionLeaseError::LeaseIdentityMismatch);
    }
    if payload.host_epoch != context.host_epoch
        || payload.activation_generation != context.activation_generation
        || payload.activation_id != context.activation_id
        || payload.kernel_epoch != context.kernel_epoch
        || payload.watchdog_epoch != context.watchdog_epoch
        || payload.state_fence != context.state_fence
        || payload.scope_ref != context.scope_ref
        || payload.observation_scope != context.observation_scope
    {
        return Err(SupervisionLeaseError::EpochOrActivationMismatch);
    }
    let binding = &payload.generation_binding;
    if binding.target_id != context.target_id
        || binding.module_id != context.module_id
        || binding.process_id != context.process_id
        || binding.target_generation != context.target_generation
        || binding.module_generation != context.module_generation
        || binding.process_generation != context.process_generation
    {
        return Err(SupervisionLeaseError::GenerationMismatch);
    }
    if payload.state != context.active_state.state
        || payload.revocation_id != context.active_state.revocation_id
        || payload.revocation_epoch != context.active_state.revocation_epoch
    {
        return Err(SupervisionLeaseError::ActiveStateMismatch);
    }
    Ok(())
}

fn map_lease_verification_error(error: &SupervisionLeaseError) -> SpoolError {
    let detail = error.to_string();
    match error {
        SupervisionLeaseError::Expired => SpoolError::LeaseStale(detail),
        SupervisionLeaseError::EpochOrActivationMismatch
        | SupervisionLeaseError::LeaseIdentityMismatch
        | SupervisionLeaseError::GenerationMismatch
        | SupervisionLeaseError::OrsMirrorMismatch
        | SupervisionLeaseError::ActiveStateMismatch
        | SupervisionLeaseError::InactiveLease => SpoolError::LeaseFenced(detail),
        _ => SpoolError::InvalidLease(detail),
    }
}
