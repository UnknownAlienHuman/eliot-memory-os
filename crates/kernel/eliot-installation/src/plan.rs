//! Immutable installation-plan contracts and fail-closed plan validation.

use std::collections::BTreeSet;
use std::path::Path;

use eliot_platform_windows::{FileIdentity, PackageManifest, StagingReceipt};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::{
    AgentBridgeSourceMaterializationPlan, CandidateManifest, ELIOT_HOST_SERVICE_NAME,
    ELIOT_WATCHDOG_SERVICE_NAME, HostPhaseBStaticTemplate, InstallationError, InstallationProfile,
    InstallationManagedRootEffectProof, ManagedEnvironmentChangeRequest, ManagedEffectRecipe,
    ManagedResourceProjection, PlatformHandle, RuntimeStateRoots, StoreCredentialProvisionPlan,
    WindowsPathIdentity,
    approved_path, handle, package_plan_error, phase_b_host_state_root_digest,
    phase_b_static_template_for_candidate, phase_b_watchdog_selector_digest, sha256_handle,
    validate_package_relative_text,
};
mod contract_models;

pub use contract_models::{
    InstallerAclPrincipal, InstallerServiceAccount, InstallerServiceRole, PackageArtifactDigest,
    PlannedChange, SupervisionAuthorityProvisionPlan, UserModeSupervisionAuthorityProvisionPlan,
};

/// One immutable installer effect owned by the enclosing
/// [`InstallationTransaction`]. The elevated adapter reports observations
/// through the existing transaction coordinator.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum InstallerEffectPlan {
    /// Create and retain one declared root.
    CreateRoot {
        /// Stable effect identity.
        effect_id: PlatformHandle,
        /// Exact root to create.
        root: PlatformHandle,
    },
    /// Apply and verify one protected ACL.
    ApplyAcl {
        /// Stable effect identity.
        effect_id: PlatformHandle,
        /// Exact root receiving the ACL.
        root: PlatformHandle,
        /// Complete admitted principal set.
        principals: Vec<InstallerAclPrincipal>,
    },
    /// Stage one immutable source bundle into the transaction staging root and
    /// retain the complete static-verification receipt in effect progress.
    StagePackage {
        /// Stable effect identity.
        effect_id: PlatformHandle,
        /// Absolute retained source bundle directory.
        source_bundle: PlatformHandle,
        /// File identity captured when the plan was admitted.
        source_bundle_identity: FileIdentity,
        /// Candidate generation identity from the immutable manifest.
        generation: PlatformHandle,
        /// Exact package manifest used by the bounded stager.
        manifest: PackageManifest,
        /// Destination root for the immutable generation.
        staging_root: PlatformHandle,
        /// Exact selected I3.1 immutable-binaries destination. When present,
        /// this is the final generation directory itself; logical `generation`
        /// remains a separate manifest identity and is never appended to this
        /// path.
        #[serde(default)]
        destination_root: Option<PlatformHandle>,
        /// Expected file bytes bound to the candidate artifact set.
        expected_file_digests: Vec<PackageArtifactDigest>,
        /// Digest of the complete candidate manifest, including runtime argv.
        candidate_manifest_digest: PlatformHandle,
        /// Canonical digest of the exact package manifest.
        package_manifest_digest: PlatformHandle,
    },
    /// Execute one System-Owner-signed, non-privileged portable managed-tool
    /// operation through the existing durable transaction and PackageStager.
    /// The private plan carries the exact catalogue/survey/approval bindings;
    /// the optional projection is an immutable precondition that the redb
    /// owner must compare with its same-store row before committing the effect.
    ManagedEnvironmentChange {
        /// Stable effect identity.
        effect_id: PlatformHandle,
        /// Serialized snapshot of the accepted non-deserializable plan. It is
        /// data only: an accepted live carrier must match it before each
        /// managed effect is driven or reconciled.
        accepted_plan_json: String,
        /// Exact governing request repeated from the transaction header.
        request: ManagedEnvironmentChangeRequest,
        /// Fixed managed-tools root derived from the transaction's retained
        /// profile-governed immutable-binaries binding.
        managed_tools_root: PlatformHandle,
        /// Deserializable signed recipe; its authority still comes from the
        /// accepted-plan byte binding and fresh admission check.
        recipe: Box<ManagedEffectRecipe>,
        /// Exact previous projection derived from the same transaction table.
        prior_resource: Option<Box<ManagedResourceProjection>>,
        /// Original receipts reloaded from each referenced owner transaction.
        /// These are immutable preconditions; the redb owner rechecks them
        /// against their transaction/effect pointers before the effect runs.
        #[serde(default)]
        prior_receipts: Vec<StagingReceipt>,
        /// Original same-installation CreateRoot receipts for managed-tools
        /// or family parents that predate this transaction.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        prior_root_effects: Vec<InstallationManagedRootEffectProof>,
    },
    /// Register one own-process SCM service.
    RegisterService {
        /// Stable effect identity.
        effect_id: PlatformHandle,
        /// Host or Watchdog role.
        role: InstallerServiceRole,
        /// Stable SCM service name.
        service_name: PlatformHandle,
        /// Approved executable path.
        executable_path: PlatformHandle,
        /// Password-free service account.
        account: InstallerServiceAccount,
        /// Whether SCM starts the service automatically.
        automatic_start: bool,
    },
    /// Start one exact registered SCM service after signed pending activation
    /// staging.  This is deliberately distinct from registration and from the
    /// provider-neutral name-only `ServicePort::Start` operation.
    StartService {
        /// Stable effect identity.
        effect_id: PlatformHandle,
        /// Host or Watchdog role.
        role: InstallerServiceRole,
        /// Stable SCM service name.
        service_name: PlatformHandle,
        /// Approved executable path.
        executable_path: PlatformHandle,
        /// Password-free service account.
        account: InstallerServiceAccount,
        /// Whether SCM starts the service automatically.
        automatic_start: bool,
    },
    /// Provision the Store credential inside the exact `LocalService` Host token.
    ProvisionStoreCredential {
        /// Stable effect identity.
        effect_id: PlatformHandle,
        /// Secret-free immutable provision plan.
        provision: StoreCredentialProvisionPlan,
    },
    /// Provision one current-user `UserMode` supervision key after package
    /// publication. The durable coordinator retains the original key receipt
    /// before the provider performs its create-only write.
    ProvisionUserModeSupervisionAuthority {
        /// Stable effect identity.
        effect_id: PlatformHandle,
        /// Secret-free immutable current-user provision plan.
        provision: Box<UserModeSupervisionAuthorityProvisionPlan>,
    },
    /// Publish the Host-owned Phase-B overlay and hand the exact pending
    /// activation to Host after the credential effect has been durably read
    /// back. This is a separate effect so materialization has its own
    /// intent/unknown/reconcile crash windows.
    MaterializePhaseB {
        /// Stable effect identity.
        effect_id: PlatformHandle,
        /// Candidate manifest digest bound by the pending registry record.
        candidate_manifest_digest: PlatformHandle,
        /// Deterministic static authority constraint; Host supplies live data.
        static_template: HostPhaseBStaticTemplate,
        /// Exact retained Host root binding.
        host_state_root_digest: PlatformHandle,
        /// Exact immutable Watchdog selector binding.
        watchdog_selector_digest: PlatformHandle,
        /// Installer-owned service-SID sealed signing-key effect plan.
        supervision_authority: Box<SupervisionAuthorityProvisionPlan>,
        /// Exact bundled credential provision contract repeated for Host
        /// admission; no secret bytes cross this boundary.
        provision: Box<StoreCredentialProvisionPlan>,
        /// Optional immutable external agent-bridge source materialization
        /// contract.  `None` is the legacy transaction shape.
        agent_bridge_source: Option<Box<AgentBridgeSourceMaterializationPlan>>,
    },
}

impl InstallerEffectPlan {
    pub(super) fn effect_id(&self) -> &PlatformHandle {
        match self {
            Self::CreateRoot { effect_id, .. }
            | Self::ApplyAcl { effect_id, .. }
            | Self::StagePackage { effect_id, .. }
            | Self::ManagedEnvironmentChange { effect_id, .. }
            | Self::RegisterService { effect_id, .. }
            | Self::StartService { effect_id, .. }
            | Self::ProvisionStoreCredential { effect_id, .. }
            | Self::ProvisionUserModeSupervisionAuthority { effect_id, .. }
            | Self::MaterializePhaseB { effect_id, .. } => effect_id,
        }
    }

    #[allow(
        clippy::too_many_lines,
        reason = "all immutable installer effect variants share one validation boundary"
    )]
    pub(super) fn validate(&self) -> Result<(), InstallationError> {
        handle(self.effect_id(), "installer_effect.effect_id")?;
        match self {
            Self::CreateRoot { root, .. } => approved_path(root, "installer_effect.root"),
            Self::ApplyAcl {
                root, principals, ..
            } => {
                approved_path(root, "installer_effect.root")?;
                if principals.is_empty() {
                    return Err(InstallationError::InvalidField {
                        field: "installer_effect.principals".to_owned(),
                        reason: "ACL plan must contain explicit principals".to_owned(),
                    });
                }
                let unique = principals.iter().copied().collect::<BTreeSet<_>>();
                if unique.len() != principals.len() {
                    return Err(InstallationError::Duplicate {
                        kind: "installer ACL principal".to_owned(),
                        identity: self.effect_id().as_str().to_owned(),
                    });
                }
                Ok(())
            }
            Self::StagePackage {
                source_bundle,
                source_bundle_identity,
                generation,
                manifest,
                staging_root,
                destination_root,
                expected_file_digests,
                candidate_manifest_digest,
                package_manifest_digest,
                ..
            } => {
                approved_path(source_bundle, "installer_effect.source_bundle")?;
                approved_path(staging_root, "installer_effect.staging_root")?;
                if let Some(destination_root) = destination_root {
                    approved_path(destination_root, "installer_effect.destination_root")?;
                }
                handle(generation, "installer_effect.generation")?;
                if source_bundle_identity.volume_serial_number == 0
                    || source_bundle_identity.file_index == 0
                {
                    return Err(InstallationError::InvalidField {
                        field: "installer_effect.source_bundle_identity".to_owned(),
                        reason: "must contain a non-zero retained file identity".to_owned(),
                    });
                }
                let validated = PackageManifest::new(&manifest.generation, manifest.files.clone())
                    .map_err(|error| package_plan_error(&error))?;
                if validated != *manifest {
                    return Err(InstallationError::IdentityConflict);
                }
                sha256_handle(
                    candidate_manifest_digest,
                    "installer_effect.candidate_manifest_digest",
                )?;
                sha256_handle(
                    package_manifest_digest,
                    "installer_effect.package_manifest_digest",
                )?;
                if package_manifest_digest.as_str() != manifest.canonical_digest() {
                    return Err(InstallationError::IdentityConflict);
                }
                let mut paths = BTreeSet::new();
                for digest in expected_file_digests {
                    validate_package_relative_text(
                        &digest.relative_path,
                        "installer_effect.expected_file_digests.relative_path",
                    )?;
                    if !paths.insert(digest.relative_path.to_ascii_lowercase()) {
                        return Err(InstallationError::Duplicate {
                            kind: "package artifact digest".to_owned(),
                            identity: digest.relative_path.clone(),
                        });
                    }
                    sha256_handle(
                        &digest.sha256,
                        "installer_effect.expected_file_digests.sha256",
                    )?;
                }
                let manifest_paths = manifest
                    .files
                    .iter()
                    .map(|file| file.relative_path.to_ascii_lowercase())
                    .collect::<BTreeSet<_>>();
                if paths != manifest_paths {
                    return Err(InstallationError::IdentityConflict);
                }
                Ok(())
            }
            Self::ManagedEnvironmentChange {
                accepted_plan_json,
                request,
                managed_tools_root,
                recipe,
                prior_resource,
                prior_receipts,
                ..
            } => {
                recipe.validate()?;
                approved_path(managed_tools_root, "installer_effect.managed_tools_root")?;
                recipe.require_supported().map_err(|requirement| {
                    InstallationError::ProfileViolation(format!(
                        "managed effect recipe requires unsupported capability {requirement:?}"
                    ))
                })?;
                request.validate()?;
                let accepted_plan_value: serde_json::Value =
                    serde_json::from_str(accepted_plan_json).map_err(|error| {
                        InstallationError::InvalidField {
                            field: "installer_effect.accepted_plan_json".to_owned(),
                            reason: format!("must be serialized accepted-plan JSON: {error}"),
                        }
                    })?;
                let accepted_request = serde_json::to_value(request).map_err(|error| {
                    InstallationError::InvalidField {
                        field: "installer_effect.request".to_owned(),
                        reason: error.to_string(),
                    }
                })?;
                let accepted_recipe = serde_json::to_value(recipe.as_ref()).map_err(|error| {
                    InstallationError::InvalidField {
                        field: "installer_effect.recipe".to_owned(),
                        reason: error.to_string(),
                    }
                })?;
                if !accepted_plan_value.is_object()
                    || accepted_plan_value.get("request") != Some(&accepted_request)
                    || accepted_plan_value.get("effect_recipe") != Some(&accepted_recipe)
                    || recipe.action != request.action
                    || recipe.target_family != request.target_family
                {
                    return Err(InstallationError::IdentityConflict);
                }
                let prior_required = matches!(
                    recipe.operation,
                    super::ManagedEffectOperation::UpdatePortableGeneration
                        | super::ManagedEffectOperation::RepairPortableGeneration
                        | super::ManagedEffectOperation::RemoveOwnedPortableGeneration
                        | super::ManagedEffectOperation::ReconfigurePortableGeneration
                );
                match (prior_required, prior_resource.as_deref()) {
                    (false, None) => {}
                    (true, Some(prior))
                        if prior.key.family_id == request.target_family
                            && prior.key.exact_candidate == request.exact_candidate
                            && prior.disposition
                                != super::ManagedResourceDisposition::Removed =>
                    {
                        prior.validate()?;
                    }
                    _ => return Err(InstallationError::IdentityConflict),
                }
                let expected_receipts = prior_resource
                    .as_deref()
                    .map_or(&[][..], |prior| prior.owned_generations.as_slice())
                    .iter()
                    .filter_map(|owner| owner.staging_receipt_digest.as_ref())
                    .collect::<Vec<_>>();
                if expected_receipts.len() != prior_receipts.len()
                    || expected_receipts
                        .iter()
                        .zip(prior_receipts)
                        .any(|(expected, receipt)| receipt.digest() != expected.as_str())
                {
                    return Err(InstallationError::IdentityConflict);
                }
                let matching_prior_generation = prior_receipts
                    .iter()
                    .filter(|receipt| {
                        receipt.generation == recipe.package_manifest.generation
                    })
                    .count();
                match recipe.operation {
                    super::ManagedEffectOperation::RepairPortableGeneration
                    | super::ManagedEffectOperation::RemoveOwnedPortableGeneration
                        if matching_prior_generation != 1 =>
                    {
                        return Err(InstallationError::IdentityConflict);
                    }
                    super::ManagedEffectOperation::UpdatePortableGeneration
                    | super::ManagedEffectOperation::ReconfigurePortableGeneration
                        if matching_prior_generation != 0 =>
                    {
                        return Err(InstallationError::IdentityConflict);
                    }
                    _ => {}
                }
                for receipt in prior_receipts {
                    if receipt.root_identity.volume_serial_number == 0
                        || receipt.root_identity.file_index == 0
                        || receipt.files.is_empty()
                    {
                        return Err(InstallationError::IdentityConflict);
                    }
                }
                Ok(())
            }
            Self::RegisterService {
                service_name,
                executable_path,
                automatic_start,
                ..
            }
            | Self::StartService {
                service_name,
                executable_path,
                automatic_start,
                ..
            } => {
                handle(service_name, "installer_effect.service_name")?;
                approved_path(executable_path, "installer_effect.executable_path")?;
                if !automatic_start {
                    return Err(InstallationError::InvalidField {
                        field: "installer_effect.automatic_start".to_owned(),
                        reason: "Runtime Live Host and Watchdog must use automatic start"
                            .to_owned(),
                    });
                }
                Ok(())
            }
            Self::ProvisionStoreCredential { provision, .. } => provision.validate(),
            Self::ProvisionUserModeSupervisionAuthority {
                effect_id,
                provision,
            } => {
                provision.validate()?;
                if provision.effect_id != *effect_id {
                    return Err(InstallationError::IdentityConflict);
                }
                Ok(())
            }
            Self::MaterializePhaseB {
                candidate_manifest_digest,
                static_template,
                host_state_root_digest,
                watchdog_selector_digest,
                supervision_authority,
                provision,
                agent_bridge_source,
                ..
            } => {
                sha256_handle(
                    candidate_manifest_digest,
                    "installer_effect.candidate_manifest_digest",
                )?;
                static_template.validate()?;
                sha256_handle(
                    host_state_root_digest,
                    "installer_effect.host_state_root_digest",
                )?;
                sha256_handle(
                    watchdog_selector_digest,
                    "installer_effect.watchdog_selector_digest",
                )?;
                supervision_authority.validate()?;
                provision.validate()?;
                if let Some(source) = agent_bridge_source {
                    source.validate()?;
                }
                Ok(())
            }
        }
    }
}

pub(super) fn validate_effect_profile(
    profile: InstallationProfile,
    plan: &InstallerEffectPlan,
) -> Result<(), InstallationError> {
    match plan {
        InstallerEffectPlan::CreateRoot { .. } | InstallerEffectPlan::StagePackage { .. } => Ok(()),
        InstallerEffectPlan::ManagedEnvironmentChange { .. }
            if profile == InstallationProfile::PortableDev =>
        {
            Ok(())
        }
        InstallerEffectPlan::ManagedEnvironmentChange { .. } => Err(
            InstallationError::ProfileViolation(
                "managed portable-tool effects require PortableDev".to_owned(),
            ),
        ),
        InstallerEffectPlan::ApplyAcl { principals, .. } => {
            let expected = match profile {
                InstallationProfile::SystemService => [
                    InstallerAclPrincipal::Administrators,
                    InstallerAclPrincipal::LocalService,
                    InstallerAclPrincipal::LocalSystem,
                ]
                .into_iter()
                .collect::<BTreeSet<_>>(),
                InstallationProfile::UserMode | InstallationProfile::PortableDev => [
                    InstallerAclPrincipal::CurrentUser,
                    InstallerAclPrincipal::LocalSystem,
                ]
                .into_iter()
                .collect::<BTreeSet<_>>(),
            };
            if principals.iter().copied().collect::<BTreeSet<_>>() == expected {
                Ok(())
            } else {
                Err(InstallationError::ProfileViolation(
                    "effect request ACL differs from its exact profile".to_owned(),
                ))
            }
        }
        // #1771 AUD4: the privileged profile needs Phase-B for its SCM bootstrap, and
        // `UserMode` needs it for a different reason: its supervision is a
        // current-user launcher plus a Task Scheduler task that may only be
        // registered against a real authority descriptor, and only Host Phase-B
        // publishes one. The second disjunct therefore admits
        // `MaterializePhaseB` for `UserMode` *alone* — never `RegisterService`,
        // `StartService` or `ProvisionStoreCredential`, which stay
        // `SystemService`-only, so no non-service profile reaches SCM or a
        // `LocalService` credential. The marker-until-published discipline is
        // unchanged, no placeholder is admitted, and `PortableDev` still falls
        // through to the `MaterializePhaseB` refusal below.
        InstallerEffectPlan::RegisterService { .. }
        | InstallerEffectPlan::StartService { .. }
        | InstallerEffectPlan::ProvisionStoreCredential { .. }
        | InstallerEffectPlan::MaterializePhaseB { .. }
            if profile == InstallationProfile::SystemService
                || (profile == InstallationProfile::UserMode
                    && matches!(plan, InstallerEffectPlan::MaterializePhaseB { .. })) =>
        {
            Ok(())
        }
        InstallerEffectPlan::RegisterService { .. } | InstallerEffectPlan::StartService { .. } => {
            Err(InstallationError::ProfileViolation(
                "service effect requires SystemService profile".to_owned(),
            ))
        }
        InstallerEffectPlan::ProvisionStoreCredential { .. } => {
            Err(InstallationError::ProfileViolation(
                "Store credential provisioning requires SystemService profile".to_owned(),
            ))
        }
        InstallerEffectPlan::ProvisionUserModeSupervisionAuthority { .. }
            if profile == InstallationProfile::UserMode =>
        {
            Ok(())
        }
        InstallerEffectPlan::ProvisionUserModeSupervisionAuthority { .. } => {
            Err(InstallationError::ProfileViolation(
                "current-user supervision authority provisioning requires UserMode profile"
                    .to_owned(),
            ))
        }
        InstallerEffectPlan::MaterializePhaseB { .. } => Err(InstallationError::ProfileViolation(
            "Phase-B materialization requires SystemService profile".to_owned(),
        )),
    }
}

pub(super) fn validate_phase_b_effect_bindings(
    candidate: &CandidateManifest,
    effects: &[InstallerEffectPlan],
) -> Result<(), InstallationError> {
    let expected_manifest_digest = candidate.compute_digest()?;
    let expected_template = phase_b_static_template_for_candidate(candidate)?;
    let expected_root_digest = phase_b_host_state_root_digest(candidate)?;
    let expected_watchdog_digest = phase_b_watchdog_selector_digest(candidate)?;
    for effect in effects {
        if let InstallerEffectPlan::MaterializePhaseB {
            candidate_manifest_digest,
            static_template,
            host_state_root_digest,
            watchdog_selector_digest,
            supervision_authority,
            ..
        } = effect
            && (candidate_manifest_digest != &expected_manifest_digest
                || static_template != &expected_template
                || host_state_root_digest != &expected_root_digest
                || watchdog_selector_digest != &expected_watchdog_digest
                || supervision_authority.installation_id
                    != candidate.runtime_launch.installation_epoch.installation
                || supervision_authority.candidate_generation != candidate.generation
                || supervision_authority.authority_generation
                    != candidate.runtime_launch.authority_generation
                || supervision_authority.supervision_lease_scope_id.as_str()
                    != candidate.runtime_launch.supervision_lease_scope_id()
                || supervision_authority.kernel_root != candidate.runtime_launch.kernel_work_root)
        {
            return Err(InstallationError::IdentityConflict);
        }
    }
    Ok(())
}

pub(super) fn validate_user_mode_authority_effect_bindings(
    transaction_id: &PlatformHandle,
    candidate: &CandidateManifest,
    roots: &super::InstallationRoots,
    effects: &[InstallerEffectPlan],
) -> Result<(), InstallationError> {
    let mut matched = 0_usize;
    for effect in effects {
        let InstallerEffectPlan::ProvisionUserModeSupervisionAuthority {
            effect_id,
            provision,
        } = effect
        else {
            continue;
        };
        matched += 1;
        if candidate.runtime_launch.profile != InstallationProfile::UserMode
            || provision.transaction_id != *transaction_id
            || provision.effect_id != *effect_id
            || provision.installation_id != candidate.runtime_launch.installation_epoch.installation
            || provision.candidate_generation != candidate.generation
            || provision.authority_generation != candidate.runtime_launch.authority_generation
            || provision.supervision_lease_scope_id.as_str()
                != candidate.runtime_launch.supervision_lease_scope_id()
            || provision.profile_roots != *roots
        {
            return Err(InstallationError::IdentityConflict);
        }
    }
    match (candidate.runtime_launch.profile, matched) {
        (InstallationProfile::UserMode, 1) => Ok(()),
        (InstallationProfile::UserMode, 0) => Err(InstallationError::IncompleteObservation(
            "UserMode candidate is missing its current-user authority effect".to_owned(),
        )),
        (InstallationProfile::UserMode, _) => Err(InstallationError::Duplicate {
            kind: "UserMode supervision authority effect".to_owned(),
            identity: transaction_id.as_str().to_owned(),
        }),
        (_, 0) => Ok(()),
        (_, _) => Err(InstallationError::ProfileViolation(
            "UserMode authority effect is inconsistent with the candidate profile".to_owned(),
        )),
    }
}

pub(super) fn validate_installer_effects(
    profile: InstallationProfile,
    roots: &RuntimeStateRoots,
    store_credential_target: &PlatformHandle,
    planned_changes: &[PlannedChange],
    effects: &[InstallerEffectPlan],
) -> Result<(), InstallationError> {
    validate_installer_effects_impl(
        profile,
        roots,
        None,
        store_credential_target,
        planned_changes,
        effects,
    )
}

pub(super) fn validate_installer_effects_with_managed_root(
    profile: InstallationProfile,
    roots: &RuntimeStateRoots,
    immutable_binaries: &PlatformHandle,
    store_credential_target: &PlatformHandle,
    planned_changes: &[PlannedChange],
    effects: &[InstallerEffectPlan],
) -> Result<(), InstallationError> {
    validate_installer_effects_impl(
        profile,
        roots,
        Some(immutable_binaries),
        store_credential_target,
        planned_changes,
        effects,
    )
}

#[allow(
    clippy::too_many_lines,
    reason = "ordered fail-closed installer validation is kept in one auditable boundary"
)]
fn validate_installer_effects_impl(
    profile: InstallationProfile,
    roots: &RuntimeStateRoots,
    immutable_binaries: Option<&PlatformHandle>,
    store_credential_target: &PlatformHandle,
    planned_changes: &[PlannedChange],
    effects: &[InstallerEffectPlan],
) -> Result<(), InstallationError> {
    if effects.iter().any(|effect| {
        matches!(effect, InstallerEffectPlan::ManagedEnvironmentChange { .. })
    }) {
        let immutable_binaries = immutable_binaries.ok_or_else(|| {
            InstallationError::ProfileViolation(
                "managed portable effects require the retained immutable-binaries root"
                    .to_owned(),
            )
        })?;
        return validate_managed_installer_effects(
            profile,
            roots,
            immutable_binaries,
            planned_changes,
            effects,
        );
    }
    if effects.is_empty() {
        return Err(InstallationError::InvalidField {
            field: "installer_effects".to_owned(),
            reason: "must contain explicit root, ACL and service work".to_owned(),
        });
    }
    let planned_ids = planned_changes
        .iter()
        .map(|change| change.change_id.as_str())
        .collect::<BTreeSet<_>>();
    if planned_ids.len() != planned_changes.len() {
        return Err(InstallationError::Duplicate {
            kind: "planned change".to_owned(),
            identity: "installer plan contains a repeated change identity".to_owned(),
        });
    }
    let mut effect_ids = BTreeSet::new();
    let mut created_roots = BTreeSet::new();
    let mut acl_roots = BTreeSet::new();
    let mut service_roles = BTreeSet::new();
    let mut start_roles = Vec::new();
    let mut start_indices = Vec::new();
    let mut register_indices = Vec::new();
    let mut host_service_image = None;
    let mut credential_host_image = None;
    let mut credential_index = None;
    let mut phase_b_index = None;
    let mut package_index = None;
    let mut user_mode_authority_index = None;
    for (index, effect) in effects.iter().enumerate() {
        effect.validate()?;
        if !effect_ids.insert(effect.effect_id().as_str()) {
            return Err(InstallationError::Duplicate {
                kind: "installer effect".to_owned(),
                identity: effect.effect_id().as_str().to_owned(),
            });
        }
        match effect {
            InstallerEffectPlan::CreateRoot { root, .. } => {
                let root_identity =
                    WindowsPathIdentity::parse_root(root.as_str(), "installer_effect.root")?;
                if !created_roots.insert(root_identity.clone()) {
                    return Err(InstallationError::Duplicate {
                        kind: "installer root effect".to_owned(),
                        identity: root.as_str().to_owned(),
                    });
                }
                if profile != InstallationProfile::PortableDev {
                    let parent = root_identity
                        .components
                        .len()
                        .checked_sub(1)
                        .map(|length| WindowsPathIdentity {
                            prefix: root_identity.prefix.clone(),
                            components: root_identity.components[..length].to_vec(),
                        })
                        .ok_or(InstallationError::InvalidField {
                            field: "installer_effect.root".to_owned(),
                            reason: "root must have one exact parent component".to_owned(),
                        })?;
                    let profile_anchor = WindowsPathIdentity::parse_root(
                        roots.profile_anchor_root.as_str(),
                        "runtime_state_roots.profile_anchor_root",
                    )?;
                    if parent != profile_anchor
                        && (!created_roots.contains(&parent) || !acl_roots.contains(&parent))
                    {
                        return Err(InstallationError::IncompleteObservation(
                            "root and ACL effects must complete each parent before its child"
                                .to_owned(),
                        ));
                    }
                }
            }
            InstallerEffectPlan::ApplyAcl {
                root, principals, ..
            } => {
                let expected_principals = if profile == InstallationProfile::SystemService {
                    [
                        InstallerAclPrincipal::Administrators,
                        InstallerAclPrincipal::LocalService,
                        InstallerAclPrincipal::LocalSystem,
                    ]
                    .into_iter()
                    .collect::<BTreeSet<_>>()
                } else {
                    [
                        InstallerAclPrincipal::CurrentUser,
                        InstallerAclPrincipal::LocalSystem,
                    ]
                    .into_iter()
                    .collect::<BTreeSet<_>>()
                };
                if principals.iter().copied().collect::<BTreeSet<_>>() != expected_principals {
                    return Err(InstallationError::ProfileViolation(
                        "runtime ACL differs from the exact profile principal set".to_owned(),
                    ));
                }
                let root_identity =
                    WindowsPathIdentity::parse_root(root.as_str(), "installer_effect.root")?;
                if !created_roots.contains(&root_identity) {
                    return Err(InstallationError::IncompleteObservation(
                        "ACL effects must follow their exact CreateRoot effect".to_owned(),
                    ));
                }
                if !acl_roots.insert(root_identity) {
                    return Err(InstallationError::Duplicate {
                        kind: "installer ACL effect".to_owned(),
                        identity: root.as_str().to_owned(),
                    });
                }
            }
            InstallerEffectPlan::StagePackage { .. } => {
                if package_index.replace(index).is_some() {
                    return Err(InstallationError::Duplicate {
                        kind: "package staging effect".to_owned(),
                        identity: effect.effect_id().as_str().to_owned(),
                    });
                }
            }
            InstallerEffectPlan::RegisterService {
                role,
                service_name,
                executable_path,
                account,
                ..
            } => {
                if profile != InstallationProfile::SystemService {
                    return Err(InstallationError::ProfileViolation(
                        "SCM effects are admitted only for SystemService".to_owned(),
                    ));
                }
                if *account != InstallerServiceAccount::LocalService {
                    return Err(InstallationError::ProfileViolation(
                        "Host and Watchdog must run as LocalService".to_owned(),
                    ));
                }
                let (expected_name, expected_image) = match role {
                    InstallerServiceRole::Host => (ELIOT_HOST_SERVICE_NAME, "eliot-host.exe"),
                    InstallerServiceRole::Watchdog => {
                        (ELIOT_WATCHDOG_SERVICE_NAME, "eliot-watchdog.exe")
                    }
                };
                let observed_image = executable_path
                    .as_str()
                    .rsplit(['\\', '/'])
                    .next()
                    .unwrap_or_default();
                if service_name.as_str() != expected_name
                    || !observed_image.eq_ignore_ascii_case(expected_image)
                {
                    return Err(InstallationError::ProfileViolation(format!(
                        "{role:?} must register canonical service {expected_name} from {expected_image}"
                    )));
                }
                if !service_roles.insert(*role) {
                    return Err(InstallationError::Duplicate {
                        kind: "installer service role".to_owned(),
                        identity: format!("{role:?}"),
                    });
                }
                if *role == InstallerServiceRole::Host {
                    host_service_image = Some(WindowsPathIdentity::parse_root(
                        executable_path.as_str(),
                        "installer_effect.host_executable",
                    )?);
                }
                register_indices.push(index);
            }
            InstallerEffectPlan::StartService {
                role,
                service_name,
                executable_path,
                account,
                ..
            } => {
                if profile != InstallationProfile::SystemService {
                    return Err(InstallationError::ProfileViolation(
                        "SCM start requires SystemService profile".to_owned(),
                    ));
                }
                if *account != InstallerServiceAccount::LocalService {
                    return Err(InstallationError::ProfileViolation(
                        "Host and Watchdog must run as LocalService".to_owned(),
                    ));
                }
                let (expected_name, expected_image) = match role {
                    InstallerServiceRole::Host => (ELIOT_HOST_SERVICE_NAME, "eliot-host.exe"),
                    InstallerServiceRole::Watchdog => {
                        (ELIOT_WATCHDOG_SERVICE_NAME, "eliot-watchdog.exe")
                    }
                };
                let observed_image = executable_path
                    .as_str()
                    .rsplit(['\\', '/'])
                    .next()
                    .unwrap_or_default();
                if service_name.as_str() != expected_name
                    || !observed_image.eq_ignore_ascii_case(expected_image)
                {
                    return Err(InstallationError::ProfileViolation(format!(
                        "{role:?} must start canonical service {expected_name} from {expected_image}"
                    )));
                }
                start_roles.push(*role);
                start_indices.push(index);
            }
            InstallerEffectPlan::ProvisionStoreCredential { provision, .. } => {
                credential_index = Some(index);
                if provision.target != *store_credential_target {
                    return Err(InstallationError::InvalidField {
                        field: "installer_effect.provision.target".to_owned(),
                        reason: "must exactly equal the candidate runtime launch credential target"
                            .to_owned(),
                    });
                }
                let host_root = WindowsPathIdentity::parse_root(
                    roots.host_state_root.as_str(),
                    "runtime_roots.host_state_root",
                )?;
                let planned_root = WindowsPathIdentity::parse_root(
                    provision.host_state_root.as_str(),
                    "credential.host_state_root",
                )?;
                if profile != InstallationProfile::SystemService || planned_root != host_root {
                    return Err(InstallationError::ProfileViolation(
                        "credential marker must use the exact SystemService host_state_root"
                            .to_owned(),
                    ));
                }
                if credential_host_image
                    .replace(WindowsPathIdentity::parse_root(
                        provision.expected_host_executable.as_str(),
                        "credential.expected_host_executable",
                    )?)
                    .is_some()
                {
                    return Err(InstallationError::Duplicate {
                        kind: "Store credential effect".to_owned(),
                        identity: provision.target.as_str().to_owned(),
                    });
                }
            }
            InstallerEffectPlan::ProvisionUserModeSupervisionAuthority { provision, .. } => {
                if profile != InstallationProfile::UserMode {
                    return Err(InstallationError::ProfileViolation(
                        "current-user authority provisioning is UserMode-only".to_owned(),
                    ));
                }
                if user_mode_authority_index.replace(index).is_some() {
                    return Err(InstallationError::Duplicate {
                        kind: "UserMode supervision authority effect".to_owned(),
                        identity: provision.effect_id.as_str().to_owned(),
                    });
                }
                if package_index.is_none_or(|package| index != package + 1) {
                    return Err(InstallationError::IncompleteObservation(
                        "UserMode authority provisioning must immediately follow package publication"
                            .to_owned(),
                    ));
                }
            }
            InstallerEffectPlan::MaterializePhaseB { .. } => {
                if phase_b_index.replace(index).is_some() {
                    return Err(InstallationError::Duplicate {
                        kind: "Phase-B materialization effect".to_owned(),
                        identity: effect.effect_id().as_str().to_owned(),
                    });
                }
            }
            InstallerEffectPlan::ManagedEnvironmentChange { .. } => {
                return Err(InstallationError::ProfileViolation(
                    "managed portable effects require the retained immutable-binaries root"
                        .to_owned(),
                ));
            }
        }
        if package_index.is_some_and(|package| {
            index > package
                && matches!(
                    effect,
                    InstallerEffectPlan::CreateRoot { .. } | InstallerEffectPlan::ApplyAcl { .. }
                )
        }) {
            return Err(InstallationError::IncompleteObservation(
                "root and ACL effects must precede package staging".to_owned(),
            ));
        }
    }
    if planned_ids != effect_ids {
        return Err(InstallationError::IdentityConflict);
    }
    let required_roots = roots
        .installer_root_hierarchy()?
        .into_iter()
        .map(|(_, root)| WindowsPathIdentity::parse_root(root.as_str(), "required_root"))
        .collect::<Result<BTreeSet<_>, _>>()?;
    if created_roots != required_roots || acl_roots != required_roots {
        return Err(InstallationError::IncompleteObservation(
            "transaction plan must create and ACL exactly the declared root hierarchy".to_owned(),
        ));
    }
    let required_services = [InstallerServiceRole::Host, InstallerServiceRole::Watchdog]
        .into_iter()
        .collect::<BTreeSet<_>>();
    if profile == InstallationProfile::SystemService && service_roles != required_services {
        return Err(InstallationError::IncompleteObservation(
            "SystemService transaction requires exactly Host and Watchdog registrations".to_owned(),
        ));
    }
    if profile == InstallationProfile::SystemService {
        let bootstrap_only = start_roles == vec![InstallerServiceRole::Host];
        let legacy_activation =
            start_roles == vec![InstallerServiceRole::Watchdog, InstallerServiceRole::Host];
        if !bootstrap_only && !legacy_activation {
            return Err(InstallationError::IncompleteObservation(
                "SystemService requires Host bootstrap start or legacy Watchdog then Host activation starts"
                    .to_owned(),
            ));
        }
        if register_indices
            .iter()
            .max()
            .is_some_and(|max| start_indices.iter().min().is_some_and(|min| max >= min))
        {
            return Err(InstallationError::IncompleteObservation(
                "service registration must precede service start".to_owned(),
            ));
        }
        if package_index.is_some_and(|pkg| start_indices.iter().any(|idx| *idx < pkg)) {
            return Err(InstallationError::IncompleteObservation(
                "package staging must precede service start".to_owned(),
            ));
        }
        if bootstrap_only {
            let Some(credential) = credential_index else {
                return Err(InstallationError::IncompleteObservation(
                    "Host bootstrap requires the transaction-owned credential effect".to_owned(),
                ));
            };
            if start_indices.iter().any(|idx| *idx > credential) {
                return Err(InstallationError::IncompleteObservation(
                    "Host bootstrap must precede bundled credential provisioning".to_owned(),
                ));
            }
            let Some(phase_b) = phase_b_index else {
                return Err(InstallationError::IncompleteObservation(
                    "SystemService transaction requires the Host-owned Phase-B effect".to_owned(),
                ));
            };
            if phase_b <= credential_index.unwrap_or(phase_b) {
                return Err(InstallationError::IncompleteObservation(
                    "Phase-B materialization must follow credential provisioning".to_owned(),
                ));
            }
        } else if credential_index
            .is_some_and(|credential| start_indices.iter().any(|idx| idx < &credential))
            && start_roles != vec![InstallerServiceRole::Watchdog, InstallerServiceRole::Host]
        {
            return Err(InstallationError::IncompleteObservation(
                "Store credential provisioning must precede legacy service activation starts"
                    .to_owned(),
            ));
        }
        for effect in effects {
            let InstallerEffectPlan::StartService {
                role,
                service_name,
                executable_path,
                account,
                automatic_start,
                ..
            } = effect
            else {
                continue;
            };
            let Some(InstallerEffectPlan::RegisterService {
                service_name: registered_name,
                executable_path: registered_image,
                account: registered_account,
                automatic_start: registered_automatic_start,
                ..
            }) = effects.iter().find(|candidate| {
                matches!(
                    candidate,
                    InstallerEffectPlan::RegisterService {
                        role: registered_role,
                        ..
                    } if registered_role == role
                )
            })
            else {
                return Err(InstallationError::IncompleteObservation(
                    "every service start requires its exact service registration".to_owned(),
                ));
            };
            if service_name != registered_name
                || executable_path != registered_image
                || account != registered_account
                || automatic_start != registered_automatic_start
            {
                return Err(InstallationError::IdentityConflict);
            }
        }
    } else if !start_roles.is_empty() {
        return Err(InstallationError::ProfileViolation(
            "non-service profiles must not start SCM services".to_owned(),
        ));
    }
    if profile == InstallationProfile::UserMode && user_mode_authority_index.is_none() {
        return Err(InstallationError::IncompleteObservation(
            "UserMode transaction requires its current-user supervision authority effect"
                .to_owned(),
        ));
    }
    if profile != InstallationProfile::UserMode && user_mode_authority_index.is_some() {
        return Err(InstallationError::ProfileViolation(
            "current-user supervision authority effect is admitted only for UserMode".to_owned(),
        ));
    }
    if profile == InstallationProfile::SystemService
        && (credential_host_image.is_none() || credential_host_image != host_service_image)
    {
        return Err(InstallationError::IncompleteObservation(
            "SystemService transaction requires one Store credential effect bound to the exact Host image"
                .to_owned(),
        ));
    }
    if profile != InstallationProfile::SystemService && credential_host_image.is_some() {
        return Err(InstallationError::ProfileViolation(
            "non-service profiles must not provision a LocalService Store credential".to_owned(),
        ));
    }
    if profile != InstallationProfile::SystemService && !service_roles.is_empty() {
        return Err(InstallationError::ProfileViolation(
            "non-service profiles must not register SCM services".to_owned(),
        ));
    }
    Ok(())
}

/// Closes the existing installation effect owner over the one narrow
/// PortableDev managed-package recipe. These transactions may only add the
/// two signed child roots needed by PackageStager; all other effects remain
/// outside this adapter. The package generation itself is not a CreateRoot:
/// PackageStager owns that exact final leaf and its durable receipt.
fn validate_managed_installer_effects(
    profile: InstallationProfile,
    roots: &RuntimeStateRoots,
    immutable_binaries: &PlatformHandle,
    planned_changes: &[PlannedChange],
    effects: &[InstallerEffectPlan],
) -> Result<(), InstallationError> {
    if profile != InstallationProfile::PortableDev
        || roots.profile != InstallationProfile::PortableDev
    {
        return Err(InstallationError::ProfileViolation(
            "managed portable-tool effects require the retained PortableDev contour".to_owned(),
        ));
    }
    if effects.is_empty() || planned_changes.len() != effects.len() {
        return Err(InstallationError::IdentityConflict);
    }
    let managed_indexes = effects
        .iter()
        .enumerate()
        .filter_map(|(index, effect)| {
            matches!(effect, InstallerEffectPlan::ManagedEnvironmentChange { .. })
                .then_some(index)
        })
        .collect::<Vec<_>>();
    if managed_indexes.len() != 1 {
        return Err(InstallationError::InvalidField {
            field: "installer_effects".to_owned(),
            reason: "a managed transaction must contain exactly one signed managed effect"
                .to_owned(),
        });
    }
    let managed_index = managed_indexes[0];
    if managed_index + 1 != effects.len() {
        return Err(InstallationError::IncompleteObservation(
            "managed package effect must follow its exact root creation effects".to_owned(),
        ));
    }
    let InstallerEffectPlan::ManagedEnvironmentChange {
        recipe,
        managed_tools_root,
        prior_root_effects,
        ..
    } = &effects[managed_index]
    else {
        return Err(InstallationError::IdentityConflict);
    };
    let base = Path::new(immutable_binaries.as_str());
    let expected_managed_tools_root = recipe.target_root(base);
    if !eliot_platform_windows::windows_paths_equal(
        Path::new(managed_tools_root.as_str()),
        &expected_managed_tools_root,
    ) {
        return Err(InstallationError::IdentityConflict);
    }
    let stages_package = matches!(
        recipe.operation,
        super::ManagedEffectOperation::InstallPortableGeneration
            | super::ManagedEffectOperation::UpdatePortableGeneration
            | super::ManagedEffectOperation::RepairPortableGeneration
            | super::ManagedEffectOperation::ReconfigurePortableGeneration
    );
    let expected_roots = if stages_package {
        let managed_tools = recipe.target_root(base);
        let family_root = managed_tools.join(recipe.target_family.as_str());
        vec![managed_tools, family_root]
    } else {
        Vec::new()
    };
    let mut created_roots = Vec::new();
    let mut effect_ids = BTreeSet::new();
    for (index, effect) in effects.iter().enumerate() {
        effect.validate()?;
        validate_effect_profile(profile, effect)?;
        if !effect_ids.insert(effect.effect_id().as_str()) {
            return Err(InstallationError::Duplicate {
                kind: "installer effect".to_owned(),
                identity: effect.effect_id().as_str().to_owned(),
            });
        }
        match effect {
            InstallerEffectPlan::CreateRoot { root, .. } if index < managed_index => {
                let actual = WindowsPathIdentity::parse_root(root.as_str(), "installer_effect.root")?;
                created_roots.push(actual);
            }
            InstallerEffectPlan::ManagedEnvironmentChange { .. } if index == managed_index => {}
            _ => {
                return Err(InstallationError::ProfileViolation(
                    "the managed portable adapter accepts only exact root creation and its signed managed effect"
                        .to_owned(),
                ));
            }
        }
    }
    let expected_roots = expected_roots
        .iter()
        .map(|root| WindowsPathIdentity::parse_root(&root.to_string_lossy(), "managed_effect.root"))
        .collect::<Result<Vec<_>, _>>()?;
    if created_roots != expected_roots {
        return Err(InstallationError::IncompleteObservation(
            "managed effects must create managed-tools and its exact signed family parent before staging"
                .to_owned(),
        ));
    }
    let required_prior_root_paths = if stages_package
        || recipe.operation == super::ManagedEffectOperation::RemoveOwnedPortableGeneration
    {
        vec![
            recipe.target_root(base),
            recipe
                .target_root(base)
                .join(recipe.target_family.as_str()),
        ]
    } else {
        Vec::new()
    };
    let mut previous_proof_index = None;
    for proof in prior_root_effects {
        let InstallerEffectPlan::CreateRoot { root, .. } = &proof.original_plan else {
            return Err(InstallationError::IdentityConflict);
        };
        let root_identity = WindowsPathIdentity::parse_root(root.as_str(), "managed_root.root")?;
        let mut proof_index = None;
        for (index, required) in required_prior_root_paths.iter().enumerate() {
            let required_identity = WindowsPathIdentity::parse_root(
                &required.to_string_lossy(),
                "managed_root.root",
            )?;
            if required_identity == root_identity {
                if proof_index.replace(index).is_some() {
                    return Err(InstallationError::IdentityConflict);
                }
            }
        }
        let Some(proof_index) = proof_index else {
            return Err(InstallationError::IdentityConflict);
        };
        if previous_proof_index.is_some_and(|previous| proof_index <= previous) {
            return Err(InstallationError::IdentityConflict);
        }
        previous_proof_index = Some(proof_index);
        proof.validate(root)?;
    }
    let planned_ids = planned_changes
        .iter()
        .map(|change| {
            change.validate()?;
            Ok(change.change_id.as_str())
        })
        .collect::<Result<BTreeSet<_>, InstallationError>>()?;
    if planned_ids.len() != planned_changes.len() || planned_ids != effect_ids {
        return Err(InstallationError::IdentityConflict);
    }
    Ok(())
}
