//! I3.3/I3.15: original installer root ownership readback for a survey probe.
//!
//! A path or a deserialized root receipt cannot construct this retained lease.
//! Its producer loads the sealed installation aggregate and checks the original
//! keyed marker against current native root and marker identities. This grants
//! no process, network, credential or capability admission.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use eliot_platform_windows::{FileIdentity, UserOwnedRootReadLease};

use super::{
    InstallationCreateDisposition, InstallationEffectDisposition,
    InstallationEffectProgressState, InstallationError, InstallationProfile,
    InstallationSecretLifecycle, InstallationSecretProvisionDisposition,
    InstallationSecretScope, InstallationTransaction, InstallationTransactionStore,
    InstallationManagedRootEffectProof, InstallationEffectObservation,
    InstallerEffectPlan, InstallerRootObjectSnapshot, InstallerRootPrimitiveObservation,
    InstallerRootPrimitiveSpec, InstallerRootProfile, PlatformHandle,
    WindowsInstallationCoordinator, WindowsInstallationEffectPort,
    WindowsRootOwnershipReceipt, constant_time_equal, hmac_sha256_hex, sha256_hex,
};

/// A retained, installer-authenticated working area for a read-only probe.
///
/// This value is neither serializable nor caller-constructible. It retains the
/// native directory handle and the original installer root record. The Kernel
/// must retain it until its exact executor operation has reconciled terminally.
pub struct SurveyProbeWorkingArea {
    lease: UserOwnedRootReadLease,
    transaction: InstallationTransaction,
    root_index: usize,
    path: PathBuf,
}

/// Preserves the original root refusal or native partially admitted owner.
/// A native failure may hold a lease that the exact operation must reconcile;
/// converting it to a string would discard that cleanup responsibility.
pub enum SurveyProbeWorkingAreaPathError {
    /// Root verification failed before any executor-owned path effect.
    Root(InstallationError),
    /// Original native path admission failed, possibly retaining cleanup.
    Native(eliot_platform_windows::SurveyProbePathAdmissionError),
}

impl SurveyProbeWorkingArea {
    /// Borrows the original native root only after installer ownership readback.
    /// Evidence sinks must retain their own native handles before the executor
    /// temporarily admits its isolated child directory.
    ///
    /// # Errors
    /// Refuses original root, marker, credential or native identity drift.
    pub fn verified_native_root_read_lease(
        &self,
    ) -> Result<&UserOwnedRootReadLease, InstallationError> {
        self.verify()?;
        Ok(&self.lease)
    }

    /// Returns the original installer receipt for evidence retained in this area.
    /// The reference is measured and store-bound ownership, never a caller path.
    ///
    /// # Errors
    /// Refuses root drift or an area without an original created-root receipt.
    pub fn evidence_area_receipt_ref(&self) -> Result<&PlatformHandle, InstallationError> {
        self.verify()?;
        match &self.transaction.effect_progress[self.root_index].state {
            InstallationEffectProgressState::Applied {
                disposition: InstallationEffectDisposition::CreatedByTransaction,
                external_identity,
                ..
            } => Ok(external_identity),
            _ => Err(InstallationError::IdentityConflict),
        }
    }

    /// Creates the exact executor-owned child under this verified installer root.
    ///
    /// # Errors
    /// Refuses original-root drift or a substituted/foreign executor child.
    pub fn retain_executor_path(
        &self,
        process_path: Arc<eliot_platform_windows::RetainedProcessPathLease>,
        operation_id: &str,
        invocation_digest: &str,
        working_directory: &Path,
    ) -> Result<eliot_platform_windows::RetainedSurveyProbePathLease, SurveyProbeWorkingAreaPathError> {
        self.verify().map_err(SurveyProbeWorkingAreaPathError::Root)?;
        eliot_platform_windows::retain_survey_probe_path_lease(
            &self.lease, process_path, operation_id, invocation_digest, working_directory,
        ).map_err(SurveyProbeWorkingAreaPathError::Native)
    }
    /// Returns the exact durable installation's Kernel working root.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Returns the native identity measured from the retained directory handle.
    #[must_use]
    pub const fn identity(&self) -> FileIdentity {
        self.lease.identity()
    }

    /// Rechecks the retained handle and original marker before dependent use.
    ///
    /// # Errors
    ///
    /// Refuses a replaced root or marker, a changed DACL, a foreign credential
    /// principal, a missing key, or a mismatch with the original durable receipt.
    pub fn verify(&self) -> Result<(), InstallationError> {
        self.lease.verify_stable_identity().map_err(platform_error)?;
        if self.lease.canonical_path().map_err(platform_error)? != self.path {
            return Err(InstallationError::IdentityConflict);
        }
        let observed = read_owned_root(
            &WindowsInstallationEffectPort::new(),
            &self.transaction,
            self.root_index,
        )?;
        if snapshot_identity(&observed) != self.identity() {
            return Err(InstallationError::IdentityConflict);
        }
        Ok(())
    }
}

impl<S: InstallationTransactionStore> WindowsInstallationCoordinator<S> {
    /// Borrows the original sealed journal for current publication readback.
    /// This exposes no mutable store or effect authority.
    pub fn transaction_store(&self) -> &S {
        self.inner.store()
    }

    /// Retains the exact original installer's admitted Kernel working area.
    ///
    /// This read-only producer accepts no caller-selected root or owner bits.
    /// PortableDev is the current managed-tool profile; other profiles require
    /// their own retained protected-root contour and are refused here.
    ///
    /// # Errors
    ///
    /// Refuses incomplete or foreign root effects and current OS readback drift.
    pub fn retain_survey_probe_working_area(
        &self,
        transaction_id: &PlatformHandle,
    ) -> Result<SurveyProbeWorkingArea, InstallationError> {
        let transaction = self.inner.store().load(transaction_id)?.ok_or_else(|| {
            InstallationError::TransactionNotFound {
                transaction_id: transaction_id.as_str().to_owned(),
            }
        })?;
        transaction.validate()?;
        if transaction.transaction_id != *transaction_id
            || transaction.profile != InstallationProfile::PortableDev
        {
            return Err(InstallationError::IdentityConflict);
        }
        let path = PathBuf::from(
            transaction.candidate_manifest.runtime_launch.runtime_state_roots
                .kernel_work_root.as_str(),
        );
        let mut roots = transaction.installer_effects.iter().enumerate().filter_map(
            |(index, plan)| match plan {
                InstallerEffectPlan::CreateRoot { root, .. }
                    if Path::new(root.as_str()) == path => Some(index),
                _ => None,
            },
        );
        let root_index = roots.next().ok_or(InstallationError::IdentityConflict)?;
        if roots.next().is_some() {
            return Err(InstallationError::IdentityConflict);
        }
        let lease = UserOwnedRootReadLease::open_existing(&path).map_err(platform_error)?;
        let observed = read_owned_root(self.inner.port(), &transaction, root_index)?;
        if snapshot_identity(&observed) != lease.identity()
            || lease.canonical_path().map_err(platform_error)? != path
        {
            return Err(InstallationError::IdentityConflict);
        }
        let area = SurveyProbeWorkingArea { lease, transaction, root_index, path };
        area.verify()?;
        Ok(area)
    }
}

fn read_owned_root(
    port: &WindowsInstallationEffectPort,
    transaction: &InstallationTransaction,
    index: usize,
) -> Result<InstallerRootObjectSnapshot, InstallationError> {
    let plan = transaction.installer_effects.get(index)
        .ok_or(InstallationError::IdentityConflict)?;
    let progress = transaction.effect_progress.get(index)
        .ok_or(InstallationError::IdentityConflict)?;
    read_owned_root_record(port, &InstallationManagedRootEffectProof {
        owner_transaction_id: transaction.transaction_id.clone(),
        installer_plan_digest: transaction.installer_plan_digest.clone(),
        original_plan: plan.clone(),
        original_progress: progress.clone(),
    }, &transaction.candidate_manifest.runtime_launch.runtime_state_roots.installation_root,
        transaction.profile, true)
}

pub(super) fn read_owned_root_proof(
    port: &WindowsInstallationEffectPort,
    proof: &InstallationManagedRootEffectProof,
    installation_root: &PlatformHandle,
    profile: InstallationProfile,
) -> Result<InstallerRootObjectSnapshot, InstallationError> {
    read_owned_root_record(port, proof, installation_root, profile, false)
}

fn read_owned_root_record(
    port: &WindowsInstallationEffectPort,
    proof: &InstallationManagedRootEffectProof,
    installation_root: &PlatformHandle,
    profile: InstallationProfile,
    allow_retired_original: bool,
) -> Result<InstallerRootObjectSnapshot, InstallationError> {
    let InstallerEffectPlan::CreateRoot { root, .. } = &proof.original_plan else {
        return Err(InstallationError::IdentityConflict);
    };
    if !allow_retired_original {
        proof.validate(root)?;
    }
    let progress = &proof.original_progress;
    let InstallationEffectProgressState::Applied {
        disposition: InstallationEffectDisposition::CreatedByTransaction,
        external_identity,
        evidence,
        postcondition_digest,
        ..
    } = &progress.state else {
        return Err(InstallationError::IdentityConflict);
    };
    let ownership = progress.ownership_secret.as_ref()
        .ok_or(InstallationError::IdentityConflict)?;
    ownership.validate()?;
    if progress.effect_id != *proof.original_plan.effect_id()
        || ownership.create_disposition != InstallationCreateDisposition::Created
        || ownership.secret_provision_disposition != InstallationSecretProvisionDisposition::Created
        || !(ownership.lifecycle == InstallationSecretLifecycle::Active
            || (allow_retired_original
                && ownership.lifecycle == InstallationSecretLifecycle::Deleted))
        || ownership.reference.scope != InstallationSecretScope::WindowsCredentialManagerCurrentUser
        || port.secret_principal_sid().map_err(platform_error)?
            != ownership.reference.expected_principal_sid
    {
        return Err(InstallationError::IdentityConflict);
    }
    let installation_root = PathBuf::from(installation_root.as_str());
    let spec = InstallerRootPrimitiveSpec {
        root: PathBuf::from(root.as_str()),
        profile_anchor: installation_root.parent()
            .ok_or(InstallationError::IdentityConflict)?.to_path_buf(),
        installation_root,
        profile: match profile {
            InstallationProfile::PortableDev => InstallerRootProfile::PortableDev,
            InstallationProfile::UserMode => InstallerRootProfile::UserMode,
            InstallationProfile::SystemService => InstallerRootProfile::SystemService,
        },
    };
    let InstallerRootPrimitiveObservation::Matching(observed) =
        port.primitive.inspect(&spec).map_err(platform_error)? else {
            return Err(InstallationError::IdentityConflict);
        };
    let marker_name = sha256_hex(format!("{}\0{}\0{}",
        proof.owner_transaction_id.as_str(), proof.original_plan.effect_id().as_str(),
        proof.installer_plan_digest.as_str()).as_bytes());
    let marker = port.primitive.read_protected_file(
        &spec, &spec.root.join(format!(".eliot-install-{marker_name}.receipt")),
        super::RECEIPT_LIMIT,
    ).map_err(platform_error)?;
    let receipt: WindowsRootOwnershipReceipt = serde_json::from_slice(&marker.bytes)
        .map_err(|_| InstallationError::IdentityConflict)?;
    if receipt.version != super::OWNERSHIP_RECEIPT_VERSION
        || receipt.transaction_id != proof.owner_transaction_id.as_str()
        || receipt.effect_id != proof.original_plan.effect_id().as_str()
        || receipt.plan_digest != proof.installer_plan_digest.as_str()
        || receipt.secret_reference != ownership.reference.target.as_str()
        || receipt.root != observed || receipt.marker != marker.object
        || receipt.external_identity().map_err(platform_error)? != *external_identity
    {
        return Err(InstallationError::IdentityConflict);
    }
    // Managed owner records retain their key and require independent MAC
    // verification. A completed core installer may have retired its key;
    // only its sealed store-loaded original record takes that read-only path.
    // The marker, native identities and both ORIGINAL recorded digests must
    // still match. Caller-carried managed proofs cannot take this exception.
    if ownership.lifecycle == InstallationSecretLifecycle::Active {
        let secret = port.read_ownership_secret(&ownership.reference.target).map_err(platform_error)?;
        let payload = receipt.mac_payload().map_err(platform_error)?;
        if !constant_time_equal(receipt.mac.as_bytes(),
            hmac_sha256_hex(secret.expose(), &payload).as_bytes()) {
            return Err(InstallationError::IdentityConflict);
        }
    }
    let InstallationEffectObservation::Matching {
        evidence: observed_evidence, postcondition_digest: observed_postcondition, ..
    } = super::matching_created_for_binding(
        proof.original_plan.effect_id(), &proof.installer_plan_digest,
        &observed, &marker.object, &receipt, external_identity.clone(),
    ).map_err(platform_error)? else {
        return Err(InstallationError::IdentityConflict);
    };
    if observed_evidence != *evidence || observed_postcondition != *postcondition_digest {
        return Err(InstallationError::IdentityConflict);
    }
    Ok(observed)
}

fn snapshot_identity(snapshot: &InstallerRootObjectSnapshot) -> FileIdentity {
    FileIdentity { volume_serial_number: snapshot.volume_serial_number,
        file_index: snapshot.file_index }
}

pub(super) fn managed_root_effects(
    transaction: &InstallationTransaction,
    plan: &InstallerEffectPlan,
) -> Result<Vec<InstallationManagedRootEffectProof>, InstallationError> {
    let InstallerEffectPlan::ManagedEnvironmentChange {
        managed_tools_root, request, recipe, prior_root_effects, ..
    } = plan else { return Ok(Vec::new()); };
    if !super::managed_change_execution::managed_operation_requires_destination_parent(
        recipe.operation,
    ) { return Ok(Vec::new()); }
    let family = Path::new(managed_tools_root.as_str()).join(request.target_family.as_str());
    let mut result = Vec::new();
    for path in [PathBuf::from(managed_tools_root.as_str()), family] {
        let root = PlatformHandle::new(path.to_string_lossy().into_owned())?;
        let current = transaction.installer_effects.iter().zip(&transaction.effect_progress)
            .find(|(effect, _)| matches!(effect,
                InstallerEffectPlan::CreateRoot { root: candidate, .. }
                    if candidate == &root));
        let proof = match current {
            Some((original_plan, original_progress)) if matches!(
                original_progress.state, InstallationEffectProgressState::Applied {
                    disposition: InstallationEffectDisposition::CreatedByTransaction, ..
                }) => InstallationManagedRootEffectProof {
                    owner_transaction_id: transaction.transaction_id.clone(),
                    installer_plan_digest: transaction.installer_plan_digest.clone(),
                    original_plan: original_plan.clone(),
                    original_progress: original_progress.clone(),
                },
            Some((_, progress)) if !matches!(progress.state,
                InstallationEffectProgressState::Applied {
                    disposition: InstallationEffectDisposition::PreexistingMatching, ..
                }) => return Err(InstallationError::IdentityConflict),
            _ => {
                let mut owners = prior_root_effects.iter().filter(|proof| matches!(
                    &proof.original_plan, InstallerEffectPlan::CreateRoot { root: candidate, .. }
                        if candidate == &root));
                let owner = owners.next().ok_or(InstallationError::IdentityConflict)?;
                if owners.next().is_some() { return Err(InstallationError::IdentityConflict); }
                owner.clone()
            }
        };
        proof.validate(&root)?;
        result.push(proof);
    }
    Ok(result)
}

pub(super) fn validate_managed_root_effects(
    request: &super::InstallationEffectRequest,
) -> Result<(), InstallationError> {
    let InstallerEffectPlan::ManagedEnvironmentChange {
        managed_tools_root, request: change, recipe, ..
    } = &request.plan else {
        return if request.managed_root_effects.is_empty() { Ok(()) }
            else { Err(InstallationError::IdentityConflict) };
    };
    if !super::managed_change_execution::managed_operation_requires_destination_parent(
        recipe.operation,
    ) {
        return if request.managed_root_effects.is_empty() { Ok(()) }
            else { Err(InstallationError::IdentityConflict) };
    }
    if request.managed_root_effects.len() != 2 {
        return Err(InstallationError::IdentityConflict);
    }
    let family = Path::new(managed_tools_root.as_str()).join(change.target_family.as_str());
    for (proof, root) in request.managed_root_effects.iter().zip([
        PathBuf::from(managed_tools_root.as_str()), family,
    ]) {
        proof.validate(&PlatformHandle::new(root.to_string_lossy().into_owned())?)?;
    }
    Ok(())
}

pub(super) fn managed_destination_parent_identity(
    port: &WindowsInstallationEffectPort,
    request: &super::InstallationEffectRequest,
) -> Result<Option<FileIdentity>, eliot_platform::PortError> {
    validate_managed_root_effects(request)
        .map_err(|_| eliot_platform::PortError::InvalidRequestMetadata)?;
    let mut parent = None;
    for proof in &request.managed_root_effects {
        let observed = read_owned_root_proof(
            port, proof, &request.installation_root, request.profile,
        ).map_err(|_| eliot_platform::PortError::InvalidRequestMetadata)?;
        parent = Some(snapshot_identity(&observed));
    }
    Ok(parent)
}

fn platform_error(error: impl std::fmt::Display) -> InstallationError {
    InstallationError::Platform(error.to_string())
}
