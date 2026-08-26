//! Runtime package observation, staging, reconciliation and execution capability.

use std::path::{Path, PathBuf};

use eliot_platform::{PortError, PortOutcome, ProviderError, ProviderErrorCode, UnknownReason};
use eliot_platform_windows::{
    AuthenticodeVerdict, FileIdentity, PackageManifest, PackageStager, PackageStagingError,
    PackageStagingObservation, PackageStagingStage, StagePackageAuthorization,
    StagePackageExpectedFile, StagingReceipt, TrustedSourceBundle,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::{
    CandidateManifest, InstallationCreateDisposition, InstallationEffectAction,
    InstallationEffectDisposition, InstallationEffectExecution, InstallationEffectObservation,
    InstallationEffectRequest, InstallationError, InstallationSecretLifecycle, InstallerEffectPlan,
    PackageArtifactDigest, PlatformHandle, candidate_manifest_digest, handle, platform_error,
    same_windows_root, sha256_handle, sha256_hex,
};

pub(super) fn package_plan_error(error: &PackageStagingError) -> InstallationError {
    InstallationError::InvalidField {
        field: "installer_effect.package_manifest".to_owned(),
        reason: error.to_string(),
    }
}

pub(super) fn validate_package_relative_text(
    value: &str,
    field: &str,
) -> Result<(), InstallationError> {
    eliot_platform_windows::validate_package_relative_path(Path::new(value))
        .map(|_| ())
        .map_err(|error| InstallationError::InvalidField {
            field: field.to_owned(),
            reason: error.to_string(),
        })
}

pub(super) fn validate_package_binding(
    candidate_manifest: &CandidateManifest,
    transaction_staging_root: &PlatformHandle,
    effects: &[InstallerEffectPlan],
) -> Result<(), InstallationError> {
    let roots = &candidate_manifest.runtime_launch.runtime_state_roots;
    if let Some(expected_staging_root) = roots.expected_staging_root()?
        && !same_windows_root(
            transaction_staging_root.as_str(),
            expected_staging_root.as_str(),
        )?
    {
        return Err(InstallationError::ProfileViolation(
            "SystemService/UserMode staging_root must equal profile_anchor_root\\Eliot\\packages"
                .to_owned(),
        ));
    }
    let expected_manifest_digest = candidate_manifest_digest(candidate_manifest)?;
    let mut package_count = 0_u8;
    for effect in effects {
        let InstallerEffectPlan::StagePackage {
            generation,
            manifest,
            staging_root,
            candidate_manifest_digest: bound_manifest_digest,
            package_manifest_digest: bound_package_manifest_digest,
            ..
        } = effect
        else {
            continue;
        };
        package_count = package_count.saturating_add(1);
        if generation != &candidate_manifest.generation {
            return Err(InstallationError::IdentityConflict);
        }
        if bound_manifest_digest != &expected_manifest_digest {
            return Err(InstallationError::IdentityConflict);
        }
        if !same_windows_root(staging_root.as_str(), transaction_staging_root.as_str())? {
            return Err(InstallationError::IdentityConflict);
        }
        let validated_package_manifest =
            PackageManifest::new(&manifest.generation, manifest.files.clone())
                .map_err(|error| package_plan_error(&error))?;
        sha256_handle(
            bound_package_manifest_digest,
            "installer_effect.package_manifest_digest",
        )?;
        if bound_package_manifest_digest.as_str() != validated_package_manifest.canonical_digest() {
            return Err(InstallationError::IdentityConflict);
        }
    }
    if package_count > 1 {
        return Err(InstallationError::Duplicate {
            kind: "package staging effect".to_owned(),
            identity: candidate_manifest.generation.as_str().to_owned(),
        });
    }
    let service_requires_package = effects.iter().any(|effect| {
        matches!(
            effect,
            InstallerEffectPlan::RegisterService { .. }
                | InstallerEffectPlan::StartService { .. }
                | InstallerEffectPlan::ProvisionStoreCredential { .. }
        )
    });
    if service_requires_package && package_count == 0 {
        return Err(InstallationError::IncompleteObservation(
            "service effects require one package/static-verification effect".to_owned(),
        ));
    }
    let package_index = effects
        .iter()
        .position(|effect| matches!(effect, InstallerEffectPlan::StagePackage { .. }));
    if let Some(package_index) = package_index
        && effects[..package_index].iter().any(|effect| {
            matches!(
                effect,
                InstallerEffectPlan::RegisterService { .. }
                    | InstallerEffectPlan::StartService { .. }
                    | InstallerEffectPlan::ProvisionStoreCredential { .. }
            )
        })
    {
        return Err(InstallationError::IncompleteObservation(
            "package/static verification must precede service and credential effects".to_owned(),
        ));
    }
    Ok(())
}

pub(super) fn validate_staging_receipt_for_plan(
    effect: &InstallerEffectPlan,
    receipt: &StagingReceipt,
) -> Result<(), InstallationError> {
    let InstallerEffectPlan::StagePackage {
        manifest,
        staging_root,
        expected_file_digests,
        ..
    } = effect
    else {
        return Err(InstallationError::IdentityConflict);
    };
    if receipt.generation != manifest.generation
        || receipt.manifest_sha256 != manifest.canonical_digest()
        || receipt.root_identity.volume_serial_number == 0
        || receipt.root_identity.file_index == 0
    {
        return Err(InstallationError::IdentityConflict);
    }
    let expected_root = Path::new(staging_root.as_str()).join(&manifest.generation);
    if !eliot_platform_windows::windows_paths_equal(&receipt.root_path, &expected_root) {
        return Err(InstallationError::IdentityConflict);
    }
    if receipt.files.len() != manifest.files.len() {
        return Err(InstallationError::IncompleteObservation(
            "package receipt file count differs from its immutable manifest".to_owned(),
        ));
    }
    for spec in &manifest.files {
        let Some(expected) = expected_file_digests
            .iter()
            .find(|item| item.relative_path.eq_ignore_ascii_case(&spec.relative_path))
        else {
            return Err(InstallationError::IdentityConflict);
        };
        let Some(file) = receipt
            .files
            .iter()
            .find(|item| item.relative_path.eq_ignore_ascii_case(&spec.relative_path))
        else {
            return Err(InstallationError::IncompleteObservation(
                "package receipt is missing a manifest file".to_owned(),
            ));
        };
        sha256_handle(
            &expected.sha256,
            "installer_effect.expected_file_digests.sha256",
        )?;
        if file.sha256 != expected.sha256.as_str()
            || file.size != spec.expected_size
            || (spec.executable && (file.pe.is_none() || file.authenticode.is_none()))
            || (!spec.executable && (file.pe.is_some() || file.authenticode.is_some()))
            || file.source_identity.volume_serial_number == 0
            || file.source_identity.file_index == 0
            || file.destination_identity.volume_serial_number == 0
            || file.destination_identity.file_index == 0
        {
            return Err(InstallationError::IdentityConflict);
        }
        if let Some(authenticode) = &file.authenticode
            && authenticode.verdict != AuthenticodeVerdict::Valid
        {
            return Err(InstallationError::IncompleteObservation(
                "package receipt does not contain a valid Authenticode verdict".to_owned(),
            ));
        }
    }
    Ok(())
}

pub(super) fn validate_staging_receipt_for_observation(
    snapshot: &PackageObservationSnapshot,
    receipt: &StagingReceipt,
) -> Result<(), InstallationError> {
    snapshot.validate()?;
    if receipt.generation != snapshot.generation.as_str()
        || receipt.manifest_sha256 != snapshot.manifest_digest.as_str()
        || receipt.files.len() != snapshot.files.len()
    {
        return Err(InstallationError::IdentityConflict);
    }
    let total_bytes = receipt.files.iter().try_fold(0_u64, |total, file| {
        total
            .checked_add(file.size)
            .ok_or(InstallationError::IdentityConflict)
    })?;
    if total_bytes != snapshot.total_bytes {
        return Err(InstallationError::IdentityConflict);
    }
    for observed in &snapshot.files {
        let Some(receipt_file) = receipt.files.iter().find(|file| {
            eliot_platform_windows::ordinal_eq_str(&file.relative_path, &observed.relative_path)
        }) else {
            return Err(InstallationError::IncompleteObservation(
                "package receipt is missing a durably observed source file".to_owned(),
            ));
        };
        if receipt_file.sha256 != observed.sha256.as_str()
            || receipt_file.size != observed.size
            || receipt_file.source_identity != observed.identity
        {
            return Err(InstallationError::IdentityConflict);
        }
    }
    Ok(())
}

/// One immutable source-file fact retained in a durable package observation.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackageObservedFile {
    /// Canonical relative path below the trusted source root.
    pub relative_path: String,
    /// Exact SHA-256 measured from the retained source handle.
    pub sha256: PlatformHandle,
    /// Exact byte length measured from the retained source handle.
    pub size: u64,
    /// Volume/file-object identity measured from the retained source handle.
    pub identity: FileIdentity,
}

/// Complete immutable observation of one trusted package source.
///
/// The snapshot is a durable capability precondition, not merely an evidence
/// digest.  It binds the retained source-root identity and every sorted file
/// fact so a later attempt must re-observe the same source objects before any
/// destination mutation.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackageObservationSnapshot {
    /// Volume/file-object identity of the retained source root.
    pub source_bundle_identity: FileIdentity,
    /// Candidate generation bound to the package manifest.
    pub generation: PlatformHandle,
    /// Canonical package-manifest digest.
    pub manifest_digest: PlatformHandle,
    /// Exact source-file facts in Windows ordinal path order.
    pub files: Vec<PackageObservedFile>,
    /// Aggregate bytes measured from the retained source files.
    pub total_bytes: u64,
    /// SHA-256 over the complete typed observation.
    pub digest: PlatformHandle,
}

impl PackageObservationSnapshot {
    /// Computes the canonical aggregate snapshot digest.
    pub fn compute_digest(
        source_bundle_identity: &FileIdentity,
        generation: &PlatformHandle,
        manifest_digest: &PlatformHandle,
        files: &[PackageObservedFile],
        total_bytes: u64,
    ) -> Result<PlatformHandle, InstallationError> {
        #[derive(Serialize)]
        struct DigestInput<'a> {
            source_bundle_identity: &'a FileIdentity,
            generation: &'a PlatformHandle,
            manifest_digest: &'a PlatformHandle,
            files: &'a [PackageObservedFile],
            total_bytes: u64,
        }
        let bytes = serde_json::to_vec(&DigestInput {
            source_bundle_identity,
            generation,
            manifest_digest,
            files,
            total_bytes,
        })
        .map_err(|error| InstallationError::InvalidField {
            field: "effect.precondition.package_snapshot".to_owned(),
            reason: error.to_string(),
        })?;
        PlatformHandle::new(sha256_hex(&bytes)).map_err(|error| platform_error(&error))
    }

    /// Validates grammar, ordering, identities and the aggregate digest.
    pub fn validate(&self) -> Result<(), InstallationError> {
        if self.source_bundle_identity.volume_serial_number == 0
            || self.source_bundle_identity.file_index == 0
        {
            return Err(InstallationError::InvalidField {
                field: "effect.precondition.package_snapshot.source_bundle_identity".to_owned(),
                reason: "must be non-zero".to_owned(),
            });
        }
        handle(
            &self.generation,
            "effect.precondition.package_snapshot.generation",
        )?;
        sha256_handle(
            &self.manifest_digest,
            "effect.precondition.package_snapshot.manifest_digest",
        )?;
        sha256_handle(&self.digest, "effect.precondition.package_snapshot.digest")?;
        if self.files.len() > 4096 {
            return Err(InstallationError::InvalidField {
                field: "effect.precondition.package_snapshot.files".to_owned(),
                reason: "exceeds bound".to_owned(),
            });
        }
        let mut seen = Vec::with_capacity(self.files.len());
        for file in &self.files {
            validate_package_relative_text(
                &file.relative_path,
                "effect.precondition.package_snapshot.files.relative_path",
            )?;
            sha256_handle(
                &file.sha256,
                "effect.precondition.package_snapshot.files.sha256",
            )?;
            if file.identity.volume_serial_number == 0 || file.identity.file_index == 0 {
                return Err(InstallationError::InvalidField {
                    field: "effect.precondition.package_snapshot.files.identity".to_owned(),
                    reason: "must be non-zero".to_owned(),
                });
            }
            if seen.iter().any(|existing: &String| {
                eliot_platform_windows::ordinal_eq_str(existing, &file.relative_path)
            }) {
                return Err(InstallationError::Duplicate {
                    kind: "package snapshot file".to_owned(),
                    identity: file.relative_path.clone(),
                });
            }
            seen.push(file.relative_path.clone());
        }
        for pair in self.files.windows(2) {
            if eliot_platform_windows::ordinal_cmp_str(
                &pair[0].relative_path,
                &pair[1].relative_path,
            ) != std::cmp::Ordering::Less
            {
                return Err(InstallationError::InvalidField {
                    field: "effect.precondition.package_snapshot.files".to_owned(),
                    reason: "must be sorted ordinal".to_owned(),
                });
            }
        }
        let observed_total_bytes = self.files.iter().try_fold(0_u64, |total, file| {
            total
                .checked_add(file.size)
                .ok_or_else(|| InstallationError::InvalidField {
                    field: "effect.precondition.package_snapshot.total_bytes".to_owned(),
                    reason: "file sizes overflow aggregate".to_owned(),
                })
        })?;
        if observed_total_bytes != self.total_bytes {
            return Err(InstallationError::InvalidField {
                field: "effect.precondition.package_snapshot.total_bytes".to_owned(),
                reason: "does not equal observed file sizes".to_owned(),
            });
        }
        let expected = Self::compute_digest(
            &self.source_bundle_identity,
            &self.generation,
            &self.manifest_digest,
            &self.files,
            self.total_bytes,
        )?;
        if expected != self.digest {
            return Err(InstallationError::InvalidField {
                field: "effect.precondition.package_snapshot.digest".to_owned(),
                reason: "snapshot digest mismatch".to_owned(),
            });
        }
        Ok(())
    }
}

fn package_stager(
    request: &InstallationEffectRequest,
) -> Result<(PackageStager, PackageManifest), PackageStagingError> {
    let InstallerEffectPlan::StagePackage {
        source_bundle,
        source_bundle_identity,
        manifest,
        staging_root,
        ..
    } = &request.plan
    else {
        return Err(PackageStagingError::Io);
    };
    let source = TrustedSourceBundle::open(Path::new(source_bundle.as_str()))?;
    if source.identity() != *source_bundle_identity {
        return Err(PackageStagingError::IdentityMismatch);
    }
    let stager = PackageStager::open(source, Path::new(staging_root.as_str()))?;
    Ok((stager, manifest.clone()))
}

fn stage_package_authorization(
    request: &InstallationEffectRequest,
    installation_root_identity: Option<FileIdentity>,
) -> Result<StagePackageAuthorization, PackageStagingError> {
    let InstallerEffectPlan::StagePackage {
        source_bundle_identity,
        generation,
        manifest,
        staging_root,
        ..
    } = &request.plan
    else {
        return Err(PackageStagingError::Io);
    };
    let snapshot = request
        .precondition
        .package_snapshot
        .as_ref()
        .ok_or(PackageStagingError::IdentityMismatch)?;
    let ownership = request
        .ownership_secret
        .as_ref()
        .ok_or(PackageStagingError::IdentityMismatch)?;
    let marker_nonce = sha256_hex(
        format!(
            "eliot-stage-package-marker-nonce-v1\0{}\0{}\0{}\0{}",
            request.transaction_id.as_str(),
            request.effect_id.as_str(),
            request.plan_digest.as_str(),
            ownership.reference.target.as_str(),
        )
        .as_bytes(),
    );
    let expected_files = snapshot
        .files
        .iter()
        .map(|file| StagePackageExpectedFile {
            relative_path: file.relative_path.clone(),
            source_identity: file.identity,
            size: file.size,
            sha256: file.sha256.as_str().to_owned(),
        })
        .collect();
    let authorization = StagePackageAuthorization {
        transaction_id: request.transaction_id.as_str().to_owned(),
        effect_id: request.effect_id.as_str().to_owned(),
        plan_digest: request.plan_digest.as_str().to_owned(),
        source_bundle_identity: *source_bundle_identity,
        source_snapshot_digest: snapshot.digest.as_str().to_owned(),
        staging_root: PathBuf::from(staging_root.as_str()),
        installation_root_identity,
        generation: generation.as_str().to_owned(),
        manifest_sha256: manifest.canonical_digest(),
        marker_nonce,
        expected_files,
    };
    Ok(authorization)
}

pub(super) fn package_port_error(error: &PackageStagingError) -> PortError {
    let provider = ProviderError {
        code: match error {
            PackageStagingError::UnsupportedPlatform => ProviderErrorCode::Unavailable,
            PackageStagingError::SecurityMismatch => ProviderErrorCode::PermissionDenied,
            _ => ProviderErrorCode::Failed,
        },
        retryable: false,
    };
    PortError::ProviderReference {
        error: provider,
        reference: package_staging_error_reference(error),
    }
}

pub(super) fn package_staging_reference(stage: PackageStagingStage, code: u32) -> PlatformHandle {
    let stage = match stage {
        PackageStagingStage::KnownFolderPath => "known-folder-path",
        PackageStagingStage::CanonicalizePath => "canonicalize-path",
        PackageStagingStage::SymlinkMetadata => "symlink-metadata",
        PackageStagingStage::SetSecurityInfo => "set-security-info",
        PackageStagingStage::GetSecurityInfo => "get-security-info",
        PackageStagingStage::CreateFileW => "create-file-w",
        PackageStagingStage::FileMetadata => "file-metadata",
        PackageStagingStage::FlushFileBuffers => "flush-file-buffers",
        PackageStagingStage::GetFileInformationByHandle => "get-file-information-by-handle",
        PackageStagingStage::GetFinalPathNameByHandleW => "get-final-path-name-by-handle-w",
        PackageStagingStage::DuplicateHandle => "duplicate-handle",
        PackageStagingStage::SetFilePointerEx => "set-file-pointer-ex",
        PackageStagingStage::ReadFile => "read-file",
        PackageStagingStage::WriteFile => "write-file",
    };
    PlatformHandle::new(format!("stage-package-win32-v1:{stage}:{code:08x}"))
        .unwrap_or_else(|_| unreachable!())
}

fn package_staging_error_reference(error: &PackageStagingError) -> PlatformHandle {
    let semantic = match error {
        PackageStagingError::InvalidRelativePath => "invalid-relative-path",
        PackageStagingError::ManifestCollision => "manifest-collision",
        PackageStagingError::BoundExceeded => "bound-exceeded",
        PackageStagingError::RootUnavailable => "root-unavailable",
        PackageStagingError::ReparsePoint => "reparse-point",
        PackageStagingError::WrongEntryKind => "wrong-entry-kind",
        PackageStagingError::IdentityMismatch => "identity-mismatch",
        PackageStagingError::HashMismatch => "hash-mismatch",
        PackageStagingError::SizeMismatch => "size-mismatch",
        PackageStagingError::SecurityMismatch => "security-mismatch",
        PackageStagingError::GenerationExists => "generation-exists",
        PackageStagingError::TreeMismatch => "tree-mismatch",
        PackageStagingError::PartialTree => "partial-tree",
        PackageStagingError::PeParse(_) => "pe-parse",
        PackageStagingError::Authenticode(_) => "authenticode",
        PackageStagingError::AuthenticodeRejected(_) => "authenticode-rejected",
        PackageStagingError::RollbackRefused => "rollback-refused",
        PackageStagingError::UnsupportedPlatform => "unsupported-platform",
        PackageStagingError::Io => "io",
        PackageStagingError::Win32 { stage, code } => {
            return package_staging_reference(*stage, *code);
        }
    };
    PlatformHandle::new(format!("stage-package-error-v1:{semantic}"))
        .unwrap_or_else(|_| unreachable!())
}

fn package_staging_outcome<T>(error: &PackageStagingError) -> PortOutcome<T> {
    match error {
        PackageStagingError::Win32 { stage, code } => {
            PortOutcome::Error(package_port_error(&PackageStagingError::Win32 {
                stage: *stage,
                code: *code,
            }))
        }
        PackageStagingError::UnsupportedPlatform => {
            PortOutcome::Unknown(UnknownReason::Unsupported)
        }
        PackageStagingError::InvalidRelativePath
        | PackageStagingError::ManifestCollision
        | PackageStagingError::BoundExceeded
        | PackageStagingError::RootUnavailable => {
            PortOutcome::Error(PortError::InvalidRequestMetadata)
        }
        _ => PortOutcome::Unknown(UnknownReason::Indeterminate),
    }
}

fn package_pending(error: &PackageStagingError) -> InstallationEffectObservation {
    let pending_ref = package_staging_error_reference(error);
    InstallationEffectObservation::Mismatch { pending_ref }
}

fn package_receipt_binding(
    request: &InstallationEffectRequest,
    receipt: &StagingReceipt,
) -> Result<(PlatformHandle, PlatformHandle, PlatformHandle), PortError> {
    let receipt_digest =
        PlatformHandle::new(receipt.digest()).map_err(|_| PortError::IdentityConflict)?;
    let external_identity = PlatformHandle::new(sha256_hex(
        &serde_json::to_vec(&(
            "package-receipt-external-v1",
            request.transaction_id.as_str(),
            request.effect_id.as_str(),
            request.plan_digest.as_str(),
            receipt_digest.as_str(),
        ))
        .map_err(|_| PortError::InvalidRequestMetadata)?,
    ))
    .map_err(|_| PortError::InvalidRequestMetadata)?;
    let postcondition_digest = PlatformHandle::new(sha256_hex(
        &serde_json::to_vec(&(
            "package-receipt-postcondition-v1",
            request.plan_digest.as_str(),
            receipt_digest.as_str(),
            receipt,
        ))
        .map_err(|_| PortError::InvalidRequestMetadata)?,
    ))
    .map_err(|_| PortError::InvalidRequestMetadata)?;
    Ok((receipt_digest, external_identity, postcondition_digest))
}

fn package_matching_observation(
    request: &InstallationEffectRequest,
    receipt: StagingReceipt,
) -> Result<InstallationEffectObservation, PortError> {
    validate_staging_receipt_for_plan(&request.plan, &receipt)
        .map_err(|_| PortError::IdentityConflict)?;
    if let Some(snapshot) = request.precondition.package_snapshot.as_ref() {
        validate_staging_receipt_for_observation(snapshot, &receipt)
            .map_err(|_| PortError::IdentityConflict)?;
    }
    let (receipt_digest, external_identity, postcondition_digest) =
        package_receipt_binding(request, &receipt)?;
    Ok(InstallationEffectObservation::Matching {
        disposition: InstallationEffectDisposition::CreatedByTransaction,
        external_identity,
        evidence: vec![receipt_digest],
        postcondition_digest,
        service_control_grant: None,
        credential_receipt: None,
        staging_receipt: Some(receipt),
        phase_b_receipt: None,
        service_runtime_lineage: None,
    })
}

fn validate_observed_against_plan(
    observed: &eliot_platform_windows::PackageSourceObservation,
    manifest: &PackageManifest,
    expected: &[PackageArtifactDigest],
) -> Result<(), PackageStagingError> {
    if observed.files.len() != manifest.files.len() || observed.files.len() != expected.len() {
        return Err(PackageStagingError::TreeMismatch);
    }
    let mut observed_sorted = observed.files.clone();
    observed_sorted.sort_by(|left, right| {
        eliot_platform_windows::ordinal_cmp_str(&left.relative_path, &right.relative_path)
    });
    let mut manifest_sorted = manifest.files.clone();
    manifest_sorted.sort_by(|left, right| {
        eliot_platform_windows::ordinal_cmp_str(&left.relative_path, &right.relative_path)
    });
    let mut expected_sorted = expected.to_vec();
    expected_sorted.sort_by(|left, right| {
        eliot_platform_windows::ordinal_cmp_str(&left.relative_path, &right.relative_path)
    });
    for ((observed, spec), expected) in observed_sorted
        .iter()
        .zip(&manifest_sorted)
        .zip(&expected_sorted)
    {
        if !eliot_platform_windows::ordinal_eq_str(&observed.relative_path, &spec.relative_path)
            || !eliot_platform_windows::ordinal_eq_str(
                &observed.relative_path,
                &expected.relative_path,
            )
        {
            return Err(PackageStagingError::TreeMismatch);
        }
        if !observed
            .sha256
            .eq_ignore_ascii_case(expected.sha256.as_str())
        {
            return Err(PackageStagingError::HashMismatch);
        }
        if observed.size != spec.expected_size || observed.size != expected.expected_size {
            return Err(PackageStagingError::SizeMismatch);
        }
        if observed.sha256.len() != 64
            || !observed
                .sha256
                .chars()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return Err(PackageStagingError::HashMismatch);
        }
    }
    Ok(())
}

fn build_package_snapshot(
    source_identity: FileIdentity,
    generation: PlatformHandle,
    manifest_digest: PlatformHandle,
    observed: &eliot_platform_windows::PackageSourceObservation,
) -> Result<PackageObservationSnapshot, PackageStagingError> {
    let mut files = observed
        .files
        .iter()
        .map(|file| {
            Ok(PackageObservedFile {
                relative_path: file.relative_path.clone(),
                sha256: PlatformHandle::new(file.sha256.clone())
                    .map_err(|_| PackageStagingError::HashMismatch)?,
                size: file.size,
                identity: file.identity,
            })
        })
        .collect::<Result<Vec<_>, PackageStagingError>>()?;
    files.sort_by(|left, right| {
        eliot_platform_windows::ordinal_cmp_str(&left.relative_path, &right.relative_path)
    });
    let digest = PackageObservationSnapshot::compute_digest(
        &source_identity,
        &generation,
        &manifest_digest,
        &files,
        observed.total_bytes,
    )
    .map_err(|_| PackageStagingError::Io)?;
    Ok(PackageObservationSnapshot {
        source_bundle_identity: source_identity,
        generation,
        manifest_digest,
        files,
        total_bytes: observed.total_bytes,
        digest,
    })
}

fn package_absent_observation(
    request: &InstallationEffectRequest,
) -> InstallationEffectObservation {
    InstallationEffectObservation::Absent {
        observed_precondition: request.precondition.clone(),
        evidence: vec![
            PlatformHandle::new(sha256_hex(
                format!(
                    "package-absent-v1\0{}\0{}",
                    request.effect_id.as_str(),
                    request.plan_digest.as_str()
                )
                .as_bytes(),
            ))
            .unwrap_or_else(|_| unreachable!()),
        ],
        service_runtime_lineage: None,
    }
}

pub(super) fn package_absent_with_snapshot(
    request: &InstallationEffectRequest,
    snapshot: PackageObservationSnapshot,
) -> Result<InstallationEffectObservation, PackageStagingError> {
    let precondition = request
        .precondition
        .with_package_snapshot(snapshot)
        .map_err(|_| PackageStagingError::Io)?;
    Ok(InstallationEffectObservation::Absent {
        evidence: vec![precondition.digest.clone()],
        observed_precondition: precondition,
        service_runtime_lineage: None,
    })
}

pub(super) fn package_manifest_matches(
    manifest: &PackageManifest,
    generation: &PlatformHandle,
    package_manifest_digest: &PlatformHandle,
) -> bool {
    manifest.generation == generation.as_str()
        && manifest.canonical_digest() == package_manifest_digest.as_str()
}

pub(super) fn inspect_package(
    request: &InstallationEffectRequest,
) -> Result<InstallationEffectObservation, PackageStagingError> {
    let (stager, manifest) = package_stager(request)?;
    let InstallerEffectPlan::StagePackage {
        expected_file_digests,
        generation,
        package_manifest_digest,
        ..
    } = &request.plan
    else {
        return Err(PackageStagingError::Io);
    };
    if !package_manifest_matches(&manifest, generation, package_manifest_digest) {
        return Err(PackageStagingError::IdentityMismatch);
    }
    let observed = stager.source().observe()?;
    validate_observed_against_plan(&observed, &manifest, expected_file_digests)?;
    let manifest_digest = PlatformHandle::new(manifest.canonical_digest())
        .map_err(|_| PackageStagingError::HashMismatch)?;
    let snapshot = build_package_snapshot(
        stager.source().identity(),
        generation.clone(),
        manifest_digest,
        &observed,
    )?;
    if let Some(persisted) = request.precondition.package_snapshot.as_ref()
        && persisted != &snapshot
    {
        return Err(PackageStagingError::HashMismatch);
    }
    let absent = if request.precondition.package_snapshot.is_some() {
        package_absent_observation(request)
    } else {
        package_absent_with_snapshot(request, snapshot.clone())?
    };
    let matching_request = if request.precondition.package_snapshot.is_some() {
        request.clone()
    } else {
        InstallationEffectRequest {
            precondition: request
                .precondition
                .with_package_snapshot(snapshot)
                .map_err(|_| PackageStagingError::Io)?,
            ..request.clone()
        }
    };
    match stager.inspect(&manifest)? {
        PackageStagingObservation::Absent => Ok(absent),
        PackageStagingObservation::Matching(receipt) => {
            package_matching_observation(&matching_request, receipt)
                .map_err(|_| PackageStagingError::IdentityMismatch)
        }
        PackageStagingObservation::Mismatch(error) => Ok(package_pending(&error)),
        PackageStagingObservation::Unknown(error) => Err(error),
    }
}

pub(super) fn reconcile_package(
    request: &InstallationEffectRequest,
    ownership_key: &[u8],
) -> Result<InstallationEffectObservation, PackageStagingError> {
    let InstallerEffectPlan::StagePackage {
        expected_file_digests,
        generation,
        package_manifest_digest,
        manifest,
        staging_root,
        ..
    } = &request.plan
    else {
        return Err(PackageStagingError::Io);
    };
    let persisted = request
        .precondition
        .package_snapshot
        .as_ref()
        .ok_or(PackageStagingError::Io)?;
    if !package_manifest_matches(manifest, generation, package_manifest_digest)
        || persisted.generation != *generation
        || persisted.manifest_digest != *package_manifest_digest
    {
        return Err(PackageStagingError::IdentityMismatch);
    }

    // Once the exact staging receipt is durable, it is the source-independent
    // recovery authority.  Reopen only the retained destination contour; the
    // source bundle may have been removed after publication and must never be
    // required for destination reconciliation.
    if let Some(receipt) = &request.staging_receipt {
        validate_staging_receipt_for_plan(&request.plan, receipt)
            .map_err(|_| PackageStagingError::IdentityMismatch)?;
        validate_staging_receipt_for_observation(persisted, receipt)
            .map_err(|_| PackageStagingError::IdentityMismatch)?;
        return match PackageStager::reconcile_destination_only(
            Path::new(staging_root.as_str()),
            receipt,
        )? {
            PackageStagingObservation::Absent => Ok(package_absent_observation(request)),
            PackageStagingObservation::Matching(receipt) => {
                package_matching_observation(request, receipt)
                    .map_err(|_| PackageStagingError::IdentityMismatch)
            }
            PackageStagingObservation::Mismatch(error) => Ok(package_pending(&error)),
            PackageStagingObservation::Unknown(error) => Err(error),
        };
    }

    // A committed StagePackage intent with an ownership key is recovered from
    // its pre-authorised marker and the destination only.  The source bundle
    // is deliberately not opened here: it may have been removed after the
    // caller published the bundle or after the provider completed the copy.
    if request.ownership_secret.as_ref().is_some_and(|ownership| {
        ownership.create_disposition == InstallationCreateDisposition::Created
            && ownership.lifecycle != InstallationSecretLifecycle::Deleted
    }) {
        let authorization = stage_package_authorization(request, None)?;
        return match PackageStager::reconcile_prepared_destination_only(
            Path::new(staging_root.as_str()),
            manifest,
            &authorization,
            ownership_key,
        )? {
            PackageStagingObservation::Absent => Ok(package_absent_observation(request)),
            PackageStagingObservation::Matching(receipt) => {
                package_matching_observation(request, receipt)
                    .map_err(|_| PackageStagingError::IdentityMismatch)
            }
            PackageStagingObservation::Mismatch(error) => Ok(package_pending(&error)),
            PackageStagingObservation::Unknown(error) => Err(error),
        };
    }

    let (stager, manifest) = package_stager(request)?;
    if persisted.source_bundle_identity != stager.source().identity() {
        return Err(PackageStagingError::IdentityMismatch);
    }
    let observed = stager.source().observe()?;
    validate_observed_against_plan(&observed, &manifest, expected_file_digests)?;
    let fresh = build_package_snapshot(
        stager.source().identity(),
        generation.clone(),
        persisted.manifest_digest.clone(),
        &observed,
    )?;
    if fresh != *persisted {
        return Err(PackageStagingError::HashMismatch);
    }
    // A committed intent without a receipt may only be reobserved when the
    // exact source bundle is still present and matches the durable snapshot.
    // If the source disappeared, package_stager above fails closed and no
    // destination-only adoption path is reachable.
    let observation = stager.inspect(&manifest)?;
    match observation {
        PackageStagingObservation::Absent => Ok(package_absent_observation(request)),
        PackageStagingObservation::Matching(receipt) => {
            package_matching_observation(request, receipt)
                .map_err(|_| PackageStagingError::IdentityMismatch)
        }
        PackageStagingObservation::Mismatch(error) => Ok(package_pending(&error)),
        PackageStagingObservation::Unknown(error) => Err(error),
    }
}

#[expect(
    clippy::too_many_lines,
    reason = "W3-02 will extract the package capability cell"
)]
pub(super) fn execute_package(
    request: &InstallationEffectRequest,
    ownership_key: &[u8],
) -> PortOutcome<InstallationEffectExecution> {
    let Some(snapshot) = request.precondition.package_snapshot.as_ref() else {
        return PortOutcome::Error(PortError::InvalidRequestMetadata);
    };
    let InstallerEffectPlan::StagePackage {
        expected_file_digests: _,
        generation,
        package_manifest_digest,
        manifest,
        staging_root,
        ..
    } = &request.plan
    else {
        return PortOutcome::Error(PortError::InvalidRequestMetadata);
    };
    match request.action {
        InstallationEffectAction::Rollback => {
            let Some(receipt) = request.staging_receipt.as_ref() else {
                return PortOutcome::Error(PortError::InvalidRequestMetadata);
            };
            if validate_staging_receipt_for_plan(&request.plan, receipt).is_err()
                || validate_staging_receipt_for_observation(snapshot, receipt).is_err()
            {
                return PortOutcome::Unknown(UnknownReason::Indeterminate);
            }
            let Ok((_, expected_external_identity, _)) = package_receipt_binding(request, receipt)
            else {
                return PortOutcome::Error(PortError::InvalidRequestMetadata);
            };
            if request.expected_external_identity.as_ref() != Some(&expected_external_identity) {
                return PortOutcome::Unknown(UnknownReason::Indeterminate);
            }
            match PackageStager::rollback_destination_only(
                Path::new(staging_root.as_str()),
                receipt,
            ) {
                Ok(()) => PortOutcome::Known(InstallationEffectExecution {
                    evidence: vec![
                        PlatformHandle::new(sha256_hex(
                            format!("package-rollback-v1\0{}", receipt.digest()).as_bytes(),
                        ))
                        .unwrap_or_else(|_| unreachable!()),
                    ],
                    create_disposition: None,
                    credential_receipt: None,
                    staging_receipt: None,
                    phase_b_receipt: None,
                    service_start_disposition: None,
                    service_runtime_lineage: None,
                }),
                Err(error) => package_staging_outcome(&error),
            }
        }
        InstallationEffectAction::Apply => {
            if ownership_key.is_empty()
                || !package_manifest_matches(manifest, generation, package_manifest_digest)
                || snapshot.generation != *generation
                || snapshot.manifest_digest != *package_manifest_digest
            {
                return PortOutcome::Unknown(UnknownReason::Indeterminate);
            }
            let (stager, _) = match package_stager(request) {
                Ok(value) => value,
                Err(error) => return PortOutcome::Error(package_port_error(&error)),
            };
            if snapshot.source_bundle_identity != stager.source().identity() {
                return PortOutcome::Unknown(UnknownReason::Indeterminate);
            }
            let Ok(authorization) =
                stage_package_authorization(request, Some(stager.installation_root_identity()))
            else {
                return PortOutcome::Unknown(UnknownReason::Indeterminate);
            };
            match stager.stage_authorized(manifest, &authorization, ownership_key) {
                Ok(receipt) => {
                    if validate_staging_receipt_for_plan(&request.plan, &receipt).is_err()
                        || validate_staging_receipt_for_observation(snapshot, &receipt).is_err()
                    {
                        return match PackageStager::rollback_destination_only(
                            Path::new(staging_root.as_str()),
                            &receipt,
                        ) {
                            Ok(()) => PortOutcome::Error(PortError::IdentityConflict),
                            Err(_) => PortOutcome::Unknown(UnknownReason::Indeterminate),
                        };
                    }
                    let Ok(digest) = PlatformHandle::new(receipt.digest()) else {
                        return PortOutcome::Unknown(UnknownReason::Indeterminate);
                    };
                    PortOutcome::Known(InstallationEffectExecution {
                        evidence: vec![digest],
                        create_disposition: None,
                        credential_receipt: None,
                        staging_receipt: Some(receipt),
                        phase_b_receipt: None,
                        service_start_disposition: None,
                        service_runtime_lineage: None,
                    })
                }
                Err(error) => package_staging_outcome(&error),
            }
        }
    }
}
