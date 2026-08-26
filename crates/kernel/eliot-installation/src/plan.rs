//! Immutable installation-plan contracts and fail-closed plan validation.

use std::{collections::BTreeSet, path::Path};

use eliot_platform_windows::{FileIdentity, PackageManifest};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::{
    CandidateManifest, ELIOT_HOST_SERVICE_NAME, ELIOT_WATCHDOG_SERVICE_NAME,
    HostPhaseBStaticTemplate, InstallationError, InstallationProfile, PlatformHandle,
    ResourceGeneration, RuntimeStateRoots, SUPERVISION_AUTHORITY_HOST_SERVICE,
    SUPERVISION_AUTHORITY_SERVICE_SID_TYPE, StoreCredentialProvisionPlan, WindowsPathIdentity,
    approved_path, handle, handles, package_plan_error, phase_b_host_state_root_digest,
    phase_b_static_template_for_candidate, phase_b_watchdog_selector_digest, sha256_handle,
    validate_package_relative_text,
};
/// A planned immutable change to an OS registration, file or plugin surface.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlannedChange {
    /// Stable change identity.
    pub change_id: PlatformHandle,
    /// External object/reference affected by the change.
    pub target: PlatformHandle,
    /// Exact precondition evidence.
    pub precondition_refs: Vec<PlatformHandle>,
    /// Expected postcondition evidence.
    pub postcondition_refs: Vec<PlatformHandle>,
}

impl PlannedChange {
    /// Validates one planned external change.
    pub fn validate(&self) -> Result<(), InstallationError> {
        handle(&self.change_id, "change_id")?;
        handle(&self.target, "change.target")?;
        handles(&self.precondition_refs, "change.precondition_refs", true)?;
        handles(&self.postcondition_refs, "change.postcondition_refs", true)
    }
}

/// Service role owned by the elevated `SystemService` installer.
#[derive(
    Clone, Copy, Debug, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum InstallerServiceRole {
    /// `eliot-host` service.
    Host,
    /// Sibling `eliot-watchdog` service.
    Watchdog,
}

/// Password-free account admitted for Runtime Live service plans.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum InstallerServiceAccount {
    /// Built-in least-privileged `LocalService` identity.
    LocalService,
}

/// Principals admitted by one protected runtime-root ACL plan.
#[derive(
    Clone, Copy, Debug, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum InstallerAclPrincipal {
    /// Built-in Administrators group.
    Administrators,
    /// Built-in `LocalService` identity used by Host and Watchdog.
    LocalService,
    /// Built-in `LocalSystem` identity retained for installer/OS ownership.
    LocalSystem,
    /// Current user, valid only for `UserMode` or `PortableDev`.
    CurrentUser,
}

/// One expected package-file digest bound to a [`InstallerEffectPlan::StagePackage`] effect.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackageArtifactDigest {
    /// Canonical path relative to the package generation root.
    pub relative_path: String,
    /// Exact byte length of the immutable source and staged file.
    pub expected_size: u64,
    /// Expected SHA-256 digest of the immutable source and staged file.
    pub sha256: PlatformHandle,
}

/// Immutable installer plan for one service-SID sealed supervision signer.
///
/// The exact SID text is resolved from the already registered canonical Host
/// service immediately before create and is retained in the resulting public
/// receipt. No private key or ambient path crosses this plan boundary.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SupervisionAuthorityProvisionPlan {
    /// Installation identity pinned into the trust anchor.
    pub installation_id: PlatformHandle,
    /// Exact candidate generation that owns the key.
    pub candidate_generation: PlatformHandle,
    /// Authority lifecycle generation.
    pub authority_generation: ResourceGeneration,
    /// Stable lease identity selected in the Phase-A launch template.
    pub supervision_lease_scope_id: PlatformHandle,
    /// Exact Kernel signer identity.
    pub signer_id: PlatformHandle,
    /// Generation-specific external key identity.
    pub key_id: PlatformHandle,
    /// Approved Kernel work root used as the sole resolution base.
    pub kernel_root: PlatformHandle,
    /// Single canonical file name below `kernel_root`.
    pub sealed_key_relative_path: PlatformHandle,
    /// Canonical SCM service whose SID is the DPAPI-NG principal.
    pub host_service_name: PlatformHandle,
    /// Required SCM service SID type (`UNRESTRICTED`).
    pub service_sid_type: u32,
}

impl SupervisionAuthorityProvisionPlan {
    fn validate(&self) -> Result<(), InstallationError> {
        for (value, field) in [
            (
                &self.installation_id,
                "supervision_authority.installation_id",
            ),
            (
                &self.candidate_generation,
                "supervision_authority.candidate_generation",
            ),
            (
                &self.supervision_lease_scope_id,
                "supervision_authority.supervision_lease_scope_id",
            ),
            (&self.signer_id, "supervision_authority.signer_id"),
            (&self.key_id, "supervision_authority.key_id"),
            (
                &self.host_service_name,
                "supervision_authority.host_service_name",
            ),
        ] {
            handle(value, field)?;
        }
        approved_path(&self.kernel_root, "supervision_authority.kernel_root")?;
        let relative = self.sealed_key_relative_path.as_str();
        handle(
            &self.sealed_key_relative_path,
            "supervision_authority.sealed_key_relative_path",
        )?;
        if Path::new(relative).components().count() != 1
            || relative.contains(['/', '\\', ':'])
            || matches!(relative, "." | "..")
        {
            return Err(InstallationError::InvalidField {
                field: "supervision_authority.sealed_key_relative_path".to_owned(),
                reason: "must be one canonical component below the Kernel root".to_owned(),
            });
        }
        if self.authority_generation.value() == 0
            || self.host_service_name.as_str() != SUPERVISION_AUTHORITY_HOST_SERVICE
            || self.service_sid_type != SUPERVISION_AUTHORITY_SERVICE_SID_TYPE
        {
            return Err(InstallationError::IdentityConflict);
        }
        Ok(())
    }
}

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
        /// Expected file bytes bound to the candidate artifact set.
        expected_file_digests: Vec<PackageArtifactDigest>,
        /// Digest of the complete candidate manifest, including runtime argv.
        candidate_manifest_digest: PlatformHandle,
        /// Canonical digest of the exact package manifest.
        package_manifest_digest: PlatformHandle,
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
    },
}

impl InstallerEffectPlan {
    pub(super) fn effect_id(&self) -> &PlatformHandle {
        match self {
            Self::CreateRoot { effect_id, .. }
            | Self::ApplyAcl { effect_id, .. }
            | Self::StagePackage { effect_id, .. }
            | Self::RegisterService { effect_id, .. }
            | Self::StartService { effect_id, .. }
            | Self::ProvisionStoreCredential { effect_id, .. }
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
                expected_file_digests,
                candidate_manifest_digest,
                package_manifest_digest,
                ..
            } => {
                approved_path(source_bundle, "installer_effect.source_bundle")?;
                approved_path(staging_root, "installer_effect.staging_root")?;
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
            Self::MaterializePhaseB {
                candidate_manifest_digest,
                static_template,
                host_state_root_digest,
                watchdog_selector_digest,
                supervision_authority,
                provision,
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
                provision.validate()
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
        InstallerEffectPlan::RegisterService { .. }
        | InstallerEffectPlan::StartService { .. }
        | InstallerEffectPlan::ProvisionStoreCredential { .. }
        | InstallerEffectPlan::MaterializePhaseB { .. }
            if profile == InstallationProfile::SystemService =>
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

#[allow(
    clippy::too_many_lines,
    reason = "ordered fail-closed installer validation is kept in one auditable boundary"
)]
pub(super) fn validate_installer_effects(
    profile: InstallationProfile,
    roots: &RuntimeStateRoots,
    store_credential_target: &PlatformHandle,
    planned_changes: &[PlannedChange],
    effects: &[InstallerEffectPlan],
) -> Result<(), InstallationError> {
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
            InstallerEffectPlan::MaterializePhaseB { .. } => {
                if phase_b_index.replace(index).is_some() {
                    return Err(InstallationError::Duplicate {
                        kind: "Phase-B materialization effect".to_owned(),
                        identity: effect.effect_id().as_str().to_owned(),
                    });
                }
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
