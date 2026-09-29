//! Immutable installation-plan contracts and fail-closed plan validation.

use std::collections::BTreeSet;

use eliot_platform_windows::{
    FileIdentity, PackageManifest, PortableDevSupervisionAuthorityKeyRequest,
};
use eliot_runtime_contracts::PortableDevSupervisionKeyReference;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::{
    AgentBridgeSourceMaterializationPlan, CandidateManifest, ELIOT_HOST_SERVICE_NAME,
    ELIOT_WATCHDOG_SERVICE_NAME, HostPhaseBStaticTemplate, InstallationError, InstallationProfile,
    PlatformHandle, RuntimeStateRoots, StoreCredentialProvisionPlan, StoreCredentialScope,
    WindowsPathIdentity,
    approved_path, handle, package_plan_error, phase_b_host_state_root_digest,
    phase_b_static_template_for_candidate, phase_b_watchdog_selector_digest, sha256_handle,
    sha256_hex, same_windows_root, validate_package_relative_text,
};
use super::credential_provision::valid_current_user_sid;
use super::profile_supervision::UserModeTaskRegistrationPlan;
mod contract_models;

pub use contract_models::{
    InstallerAclPrincipal, InstallerServiceAccount, InstallerServiceRole, PackageArtifactDigest,
    PlannedChange, SupervisionAuthorityProvisionPlan, UserModeSupervisionAuthorityProvisionPlan,
};

/// Profile-specific Phase-B signing-key provision plan.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(tag = "profile", content = "provision", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PhaseBSupervisionAuthorityProvisionPlan {
    /// Service-SID sealed key provisioned by the elevated SystemService installer.
    SystemService(Box<SupervisionAuthorityProvisionPlan>),
    /// Current-user Credential Manager key provisioned for UserMode.
    UserMode(Box<UserModeSupervisionAuthorityProvisionPlan>),
    /// Disposable repository-local key provisioned for PortableDev.
    PortableDev(Box<PortableDevSupervisionAuthorityKeyRequest>),
}

impl PhaseBSupervisionAuthorityProvisionPlan {
    fn validate(&self) -> Result<(), InstallationError> {
        match self {
            Self::SystemService(provision) => provision.validate(),
            Self::UserMode(provision) => provision.validate(),
            Self::PortableDev(provision) => validate_portable_dev_authority_request(provision),
        }
    }

    const fn profile(&self) -> InstallationProfile {
        match self {
            Self::SystemService(_) => InstallationProfile::SystemService,
            Self::UserMode(_) => InstallationProfile::UserMode,
            Self::PortableDev(_) => InstallationProfile::PortableDev,
        }
    }
}

fn validate_portable_dev_authority_request(
    provision: &PortableDevSupervisionAuthorityKeyRequest,
) -> Result<(), InstallationError> {
    for (value, field) in [
        (&provision.transaction_id, "portable_dev_authority.transaction_id"),
        (&provision.effect_id, "portable_dev_authority.effect_id"),
        (&provision.installation_id, "portable_dev_authority.installation_id"),
        (&provision.candidate_generation, "portable_dev_authority.candidate_generation"),
        (
            &provision.supervision_lease_scope_id,
            "portable_dev_authority.supervision_lease_scope_id",
        ),
        (&provision.signer_id, "portable_dev_authority.signer_id"),
        (&provision.key_id, "portable_dev_authority.key_id"),
    ] {
        if value.trim().is_empty() || value.trim() != value || value.chars().any(char::is_control) {
            return Err(InstallationError::InvalidField {
                field: field.to_owned(),
                reason: "must be non-empty canonical text".to_owned(),
            });
        }
    }
    if provision.authority_generation.value() == 0
        || !provision.repository_root.is_absolute()
        || provision.repository_root.components().any(|component| {
            matches!(component, std::path::Component::CurDir | std::path::Component::ParentDir)
        })
        || provision.repository_root_identity.volume_serial_number == 0
        || provision.repository_root_identity.file_index == 0
        || provision.signer_id != "eliot-kernel"
        || provision.key_id != format!("eliot-supervision-key:v1:{}", provision.candidate_generation)
    {
        return Err(InstallationError::IdentityConflict);
    }
    PortableDevSupervisionKeyReference::new(provision.relative_path.clone()).map_err(|error| {
        InstallationError::InvalidField {
            field: "portable_dev_authority.relative_path".to_owned(),
            reason: error.to_string(),
        }
    })?;
    Ok(())
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
    /// Provision a Store credential in the exact UserMode or PortableDev current-user token.
    ProvisionCurrentUserStoreCredential {
        /// Stable effect identity.
        effect_id: PlatformHandle,
        /// Secret-free immutable provision plan, with the current-user scope.
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
    /// Provision one disposable repository-local PortableDev supervision authority key.
    ProvisionPortableDevSupervisionAuthority {
        /// Stable effect identity.
        effect_id: PlatformHandle,
        /// Exact create-only authority-key request bound to the repository object identity.
        provision: Box<PortableDevSupervisionAuthorityKeyRequest>,
    },
    /// Register the exact current-user Task Scheduler action for one UserMode
    /// candidate. The typed registration template contains no Phase-B digest;
    /// Host must materialize the live descriptor before this effect executes.
    RegisterCurrentUserTask {
        /// Stable effect identity.
        effect_id: PlatformHandle,
        /// Immutable UserMode task registration template.
        registration: Box<UserModeTaskRegistrationPlan>,
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
        supervision_authority: Box<PhaseBSupervisionAuthorityProvisionPlan>,
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
            | Self::RegisterService { effect_id, .. }
            | Self::StartService { effect_id, .. }
            | Self::ProvisionStoreCredential { effect_id, .. }
            | Self::ProvisionCurrentUserStoreCredential { effect_id, .. }
            | Self::ProvisionUserModeSupervisionAuthority { effect_id, .. }
            | Self::ProvisionPortableDevSupervisionAuthority { effect_id, .. }
            | Self::RegisterCurrentUserTask { effect_id, .. }
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
            Self::ProvisionStoreCredential { provision, .. } => {
                provision.validate()?;
                if provision.scope != StoreCredentialScope::LocalService {
                    return Err(InstallationError::ProfileViolation(
                        "LocalService Store effect requires LocalService scope".to_owned(),
                    ));
                }
                Ok(())
            }
            Self::ProvisionCurrentUserStoreCredential { provision, .. } => {
                provision.validate()?;
                if provision.scope != StoreCredentialScope::CurrentUser {
                    return Err(InstallationError::ProfileViolation(
                        "current-user Store effect requires current-user scope".to_owned(),
                    ));
                }
                Ok(())
            }
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
            Self::RegisterCurrentUserTask {
                effect_id,
                registration,
            } => {
                registration.validate()?;
                if registration.effect_id != *effect_id {
                    return Err(InstallationError::IdentityConflict);
                }
                Ok(())
            }
            Self::ProvisionPortableDevSupervisionAuthority {
                effect_id,
                provision,
            } => {
                validate_portable_dev_authority_request(provision)?;
                if provision.effect_id != effect_id.as_str() {
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
                let expected_scope = match supervision_authority.profile() {
                    InstallationProfile::SystemService => StoreCredentialScope::LocalService,
                    InstallationProfile::UserMode | InstallationProfile::PortableDev => {
                        StoreCredentialScope::CurrentUser
                    }
                };
                if provision.scope != expected_scope {
                    return Err(InstallationError::ProfileViolation(
                        "Phase-B authority profile and Store credential scope disagree".to_owned(),
                    ));
                }
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
        InstallerEffectPlan::ProvisionCurrentUserStoreCredential { .. }
            if matches!(profile, InstallationProfile::UserMode | InstallationProfile::PortableDev) =>
        {
            Ok(())
        }
        InstallerEffectPlan::ProvisionCurrentUserStoreCredential { .. } => {
            Err(InstallationError::ProfileViolation(
                "current-user Store credential requires UserMode or PortableDev profile".to_owned(),
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
        InstallerEffectPlan::ProvisionPortableDevSupervisionAuthority { .. }
            if profile == InstallationProfile::PortableDev =>
        {
            Ok(())
        }
        InstallerEffectPlan::ProvisionPortableDevSupervisionAuthority { .. } => {
            Err(InstallationError::ProfileViolation(
                "repository-local supervision authority provisioning requires PortableDev profile"
                    .to_owned(),
            ))
        }
        InstallerEffectPlan::RegisterCurrentUserTask { .. }
            if profile == InstallationProfile::UserMode =>
        {
            Ok(())
        }
        InstallerEffectPlan::RegisterCurrentUserTask { .. } => {
            Err(InstallationError::ProfileViolation(
                "current-user task registration requires UserMode profile".to_owned(),
            ))
        }
        InstallerEffectPlan::MaterializePhaseB {
            supervision_authority,
            ..
        } if supervision_authority.profile() == profile => Ok(()),
        InstallerEffectPlan::MaterializePhaseB { .. } => {
            Err(InstallationError::ProfileViolation(
                "Phase-B materialization authority does not match its selected profile".to_owned(),
            ))
        }
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
                || !phase_b_authority_matches_candidate(supervision_authority, candidate)?)
        {
            return Err(InstallationError::IdentityConflict);
        }
    }
    Ok(())
}

fn phase_b_authority_matches_candidate(
    authority: &PhaseBSupervisionAuthorityProvisionPlan,
    candidate: &CandidateManifest,
) -> Result<bool, InstallationError> {
    let launch = &candidate.runtime_launch;
    let matches_common = |installation_id: &str,
                          generation: &str,
                          authority_generation: eliot_contracts::ResourceGeneration,
                          scope_id: &str| {
        installation_id == launch.installation_epoch.installation.as_str()
            && generation == candidate.generation.as_str()
            && authority_generation == launch.authority_generation
            && scope_id == launch.supervision_lease_scope_id()
    };
    Ok(match authority {
        PhaseBSupervisionAuthorityProvisionPlan::SystemService(provision) => {
            matches_common(
                provision.installation_id.as_str(),
                provision.candidate_generation.as_str(),
                provision.authority_generation,
                provision.supervision_lease_scope_id.as_str(),
            ) && provision.kernel_root == launch.kernel_work_root
        }
        PhaseBSupervisionAuthorityProvisionPlan::UserMode(provision) => {
            matches_common(
                provision.installation_id.as_str(),
                provision.candidate_generation.as_str(),
                provision.authority_generation,
                provision.supervision_lease_scope_id.as_str(),
            ) && provision.profile_roots == launch.profile_governed_roots
        }
        PhaseBSupervisionAuthorityProvisionPlan::PortableDev(provision) => {
            matches_common(
                &provision.installation_id,
                &provision.candidate_generation,
                provision.authority_generation,
                &provision.supervision_lease_scope_id,
            ) && launch.profile == InstallationProfile::PortableDev
                && same_windows_root(
                    &provision.repository_root.to_string_lossy(),
                    launch
                        .profile_governed_roots
                        .runtime_state_roots
                        .profile_anchor_root
                        .as_str(),
                )?
        }
    })
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

pub(super) fn validate_portable_dev_authority_effect_bindings(
    transaction_id: &PlatformHandle,
    candidate: &CandidateManifest,
    effects: &[InstallerEffectPlan],
) -> Result<(), InstallationError> {
    let launch = &candidate.runtime_launch;
    let expected_relative_path = portable_dev_authority_relative_path(candidate);
    let mut matched = 0_usize;
    for effect in effects {
        let InstallerEffectPlan::ProvisionPortableDevSupervisionAuthority {
            effect_id,
            provision,
        } = effect
        else {
            continue;
        };
        matched += 1;
        if launch.profile != InstallationProfile::PortableDev
            || provision.transaction_id != transaction_id.as_str()
            || provision.effect_id != effect_id.as_str()
            || provision.effect_id
                != format!("effect:portable-dev-supervision-authority:{}", candidate.generation)
            || provision.installation_id != launch.installation_epoch.installation.as_str()
            || provision.candidate_generation != candidate.generation.as_str()
            || provision.authority_generation != launch.authority_generation
            || provision.supervision_lease_scope_id != launch.supervision_lease_scope_id()
            || provision.signer_id != "eliot-kernel"
            || provision.key_id != format!("eliot-supervision-key:v1:{}", candidate.generation)
            || provision.relative_path != expected_relative_path
            || !same_windows_root(
                &provision.repository_root.to_string_lossy(),
                launch
                    .profile_governed_roots
                    .runtime_state_roots
                    .profile_anchor_root
                    .as_str(),
            )?
        {
            return Err(InstallationError::IdentityConflict);
        }
    }
    match (launch.profile, matched) {
        (InstallationProfile::PortableDev, 1) => Ok(()),
        (InstallationProfile::PortableDev, 0) => Err(InstallationError::IncompleteObservation(
            "PortableDev candidate is missing its repository-local supervision authority effect"
                .to_owned(),
        )),
        (InstallationProfile::PortableDev, _) => Err(InstallationError::Duplicate {
            kind: "PortableDev supervision authority effect".to_owned(),
            identity: transaction_id.as_str().to_owned(),
        }),
        (_, 0) => Ok(()),
        (_, _) => Err(InstallationError::ProfileViolation(
            "PortableDev authority effect is inconsistent with the candidate profile".to_owned(),
        )),
    }
}

pub(super) fn validate_current_user_store_credential_effect_bindings(
    candidate: &CandidateManifest,
    roots: &super::InstallationRoots,
    store_credential_target: &PlatformHandle,
    effects: &[InstallerEffectPlan],
) -> Result<(), InstallationError> {
    let launch = &candidate.runtime_launch;
    let mut matched = 0_usize;
    for effect in effects {
        let InstallerEffectPlan::ProvisionCurrentUserStoreCredential {
            effect_id,
            provision,
        } = effect
        else {
            continue;
        };
        matched += 1;
        let expected_effect_id = match launch.profile {
            InstallationProfile::UserMode => "effect:user-mode-store-credential",
            InstallationProfile::PortableDev => "effect:portable-dev-store-credential",
            InstallationProfile::SystemService => "",
        };
        let expected_state_root = WindowsPathIdentity::parse_root(
            roots.runtime_state_roots.host_state_root.as_str(),
            "runtime_roots.host_state_root",
        )?;
        let planned_state_root = WindowsPathIdentity::parse_root(
            provision.host_state_root.as_str(),
            "credential.host_state_root",
        )?;
        if !matches!(launch.profile, InstallationProfile::UserMode | InstallationProfile::PortableDev)
            || effect_id.as_str() != expected_effect_id
            || provision.scope != StoreCredentialScope::CurrentUser
            || provision.provider != super::StoreCredentialProvider::WindowsCredentialManager
            || provision.target != *store_credential_target
            || provision.target != candidate.store_credential_target
            || provision.host_state_root.as_str()
                != roots.runtime_state_roots.host_state_root.as_str()
            || expected_state_root != planned_state_root
            || provision.expected_host_executable != candidate.host_executable_path
            || provision.expected_host_executable_sha256 != launch.host_artifact_digest
            || provision.generation != launch.authority_generation
            || provision.config_digest != candidate.config_digest
            || provision.provider_bootstrap_target.is_some()
            || !valid_current_user_sid(provision.expected_principal_sid.as_str())
        {
            return Err(InstallationError::IdentityConflict);
        }
        if launch.profile == InstallationProfile::UserMode {
            let expected_owner = effects.iter().find_map(|candidate_effect| {
                if let InstallerEffectPlan::ProvisionUserModeSupervisionAuthority {
                    provision, ..
                } = candidate_effect
                {
                    Some(&provision.owner_sid)
                } else {
                    None
                }
            });
            if expected_owner != Some(&provision.expected_principal_sid) {
                return Err(InstallationError::IdentityConflict);
            }
        }
    }
    match (launch.profile, matched) {
        (InstallationProfile::UserMode | InstallationProfile::PortableDev, 1) => Ok(()),
        (InstallationProfile::UserMode | InstallationProfile::PortableDev, 0) => {
            Err(InstallationError::IncompleteObservation(
                "current-user profile is missing its exact Store credential effect".to_owned(),
            ))
        }
        (InstallationProfile::UserMode | InstallationProfile::PortableDev, _) => {
            Err(InstallationError::Duplicate {
                kind: "current-user Store credential effect".to_owned(),
                identity: launch.installation_epoch.installation.as_str().to_owned(),
            })
        }
        (_, 0) => Ok(()),
        (_, _) => Err(InstallationError::ProfileViolation(
            "current-user Store credential effect is admitted only for UserMode or PortableDev"
                .to_owned(),
        )),
    }
}

fn portable_dev_authority_relative_path(candidate: &CandidateManifest) -> String {
    let launch = &candidate.runtime_launch;
    let digest = sha256_hex(
        format!(
            "{}\0{}\0{}",
            launch.installation_epoch.installation,
            candidate.generation,
            launch.authority_generation.value()
        )
        .as_bytes(),
    );
    format!(
        "{}.sealed",
        format!(
            "{}supervision-authority-{}",
            eliot_runtime_contracts::PORTABLE_DEV_SUPERVISION_KEY_PREFIX,
            &digest[..32]
        )
    )
}

pub(super) fn validate_user_mode_task_effect_bindings(
    transaction_id: &PlatformHandle,
    candidate: &CandidateManifest,
    roots: &super::InstallationRoots,
    effects: &[InstallerEffectPlan],
) -> Result<(), InstallationError> {
    let expected_manifest_digest = candidate.compute_digest()?;
    let mut matched = 0_usize;
    for effect in effects {
        let InstallerEffectPlan::RegisterCurrentUserTask {
            effect_id,
            registration,
        } = effect
        else {
            continue;
        };
        matched += 1;
        let launch = &candidate.runtime_launch;
        if launch.profile != InstallationProfile::UserMode
            || registration.transaction_id != *transaction_id
            || registration.effect_id != *effect_id
            || registration.installation_id != launch.installation_epoch.installation
            || registration.candidate_generation != candidate.generation
            || registration.candidate_manifest_digest != expected_manifest_digest
            || registration.profile_component != launch.profile_component
            || registration.profile_version != launch.profile_version
            || registration.profile_installation_key != launch.profile_installation_key
            || registration.profile_roots.as_ref() != roots
            || registration.authority_descriptor_path != launch.authority_descriptor_path
            || registration.authority_generation != launch.authority_generation
            || registration.host_executable_path != launch.host_executable_path
            || registration.host_executable_sha256 != launch.host_artifact_digest
            || registration.working_directory.as_str()
                != launch.profile_governed_roots.immutable_binaries
        {
            return Err(InstallationError::IdentityConflict);
        }
    }
    match (candidate.runtime_launch.profile, matched) {
        (InstallationProfile::UserMode, 1) => Ok(()),
        (InstallationProfile::UserMode, 0) => Err(InstallationError::IncompleteObservation(
            "UserMode candidate is missing its current-user task registration effect".to_owned(),
        )),
        (InstallationProfile::UserMode, _) => Err(InstallationError::Duplicate {
            kind: "UserMode current-user task effect".to_owned(),
            identity: transaction_id.as_str().to_owned(),
        }),
        (_, 0) => Ok(()),
        (_, _) => Err(InstallationError::ProfileViolation(
            "UserMode task effect is inconsistent with the candidate profile".to_owned(),
        )),
    }
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
    let mut current_user_credential_index = None;
    let mut phase_b_index = None;
    let mut package_index = None;
    let mut user_mode_authority_index = None;
    let mut portable_dev_authority_index = None;
    let mut user_mode_task_index = None;
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
            InstallerEffectPlan::ProvisionCurrentUserStoreCredential { provision, .. } => {
                if !matches!(profile, InstallationProfile::UserMode | InstallationProfile::PortableDev)
                    || provision.scope != StoreCredentialScope::CurrentUser
                    || provision.target != *store_credential_target
                {
                    return Err(InstallationError::ProfileViolation(
                        "current-user credential effect must match the selected non-service profile and target"
                            .to_owned(),
                    ));
                }
                let host_root = WindowsPathIdentity::parse_root(
                    roots.host_state_root.as_str(),
                    "runtime_roots.host_state_root",
                )?;
                let planned_root = WindowsPathIdentity::parse_root(
                    provision.host_state_root.as_str(),
                    "credential.host_state_root",
                )?;
                if planned_root != host_root {
                    return Err(InstallationError::ProfileViolation(
                        "current-user credential marker must use the exact selected host_state_root"
                            .to_owned(),
                    ));
                }
                if current_user_credential_index.replace(index).is_some() {
                    return Err(InstallationError::Duplicate {
                        kind: "current-user Store credential effect".to_owned(),
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
            InstallerEffectPlan::ProvisionPortableDevSupervisionAuthority { provision, .. } => {
                if profile != InstallationProfile::PortableDev {
                    return Err(InstallationError::ProfileViolation(
                        "repository-local supervision authority provisioning is PortableDev-only"
                            .to_owned(),
                    ));
                }
                if portable_dev_authority_index.replace(index).is_some() {
                    return Err(InstallationError::Duplicate {
                        kind: "PortableDev supervision authority effect".to_owned(),
                        identity: provision.effect_id.clone(),
                    });
                }
                if package_index.is_none_or(|package| index != package + 1) {
                    return Err(InstallationError::IncompleteObservation(
                        "PortableDev authority provisioning must immediately follow package publication"
                            .to_owned(),
                    ));
                }
            }
            InstallerEffectPlan::RegisterCurrentUserTask { registration, .. } => {
                if profile != InstallationProfile::UserMode {
                    return Err(InstallationError::ProfileViolation(
                        "current-user task registration is admitted only for UserMode".to_owned(),
                    ));
                }
                if user_mode_task_index.replace(index).is_some() {
                    return Err(InstallationError::Duplicate {
                        kind: "UserMode current-user task effect".to_owned(),
                        identity: registration.effect_id.as_str().to_owned(),
                    });
                }
                if user_mode_authority_index.is_none_or(|authority| index <= authority)
                    || phase_b_index.is_none_or(|phase_b| index <= phase_b)
                    || index + 1 != effects.len()
                {
                    return Err(InstallationError::IncompleteObservation(
                        "UserMode task registration must follow Phase-B materialization as the final installer effect"
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
    if profile == InstallationProfile::UserMode && user_mode_task_index.is_none() {
        return Err(InstallationError::IncompleteObservation(
            "UserMode transaction requires its current-user task registration effect".to_owned(),
        ));
    }
    if profile == InstallationProfile::UserMode {
        let (Some(authority), Some(credential), Some(phase_b)) = (
            user_mode_authority_index,
            current_user_credential_index,
            phase_b_index,
        ) else {
            return Err(InstallationError::IncompleteObservation(
                "UserMode transaction requires authority, current-user Store credential and Phase-B effects"
                    .to_owned(),
            ));
        };
        if !(authority < credential && credential < phase_b) {
            return Err(InstallationError::IncompleteObservation(
                "UserMode authority, Store credential and Phase-B effects are out of order"
                    .to_owned(),
            ));
        }
    }
    if profile == InstallationProfile::PortableDev {
        let (Some(authority), Some(credential), Some(phase_b)) = (
            portable_dev_authority_index,
            current_user_credential_index,
            phase_b_index,
        ) else {
            return Err(InstallationError::IncompleteObservation(
                "PortableDev transaction requires repository authority, current-user Store credential and Phase-B effects"
                    .to_owned(),
            ));
        };
        if !(authority < credential && credential < phase_b) {
            return Err(InstallationError::IncompleteObservation(
                "PortableDev authority, Store credential and Phase-B effects are out of order"
                    .to_owned(),
            ));
        }
    }
    if profile != InstallationProfile::UserMode && user_mode_task_index.is_some() {
        return Err(InstallationError::ProfileViolation(
            "current-user task registration effect is admitted only for UserMode".to_owned(),
        ));
    }
    if profile != InstallationProfile::UserMode && user_mode_authority_index.is_some() {
        return Err(InstallationError::ProfileViolation(
            "current-user supervision authority effect is admitted only for UserMode".to_owned(),
        ));
    }
    if profile != InstallationProfile::PortableDev && portable_dev_authority_index.is_some() {
        return Err(InstallationError::ProfileViolation(
            "repository-local supervision authority effect is admitted only for PortableDev"
                .to_owned(),
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
    if profile == InstallationProfile::SystemService && current_user_credential_index.is_some() {
        return Err(InstallationError::ProfileViolation(
            "SystemService must not provision a current-user Store credential".to_owned(),
        ));
    }
    if matches!(profile, InstallationProfile::UserMode | InstallationProfile::PortableDev)
        && (credential_index.is_some() || current_user_credential_index.is_none())
    {
        return Err(InstallationError::ProfileViolation(
            "UserMode and PortableDev require current-user Store credentials only".to_owned(),
        ));
    }
    if profile != InstallationProfile::SystemService && !service_roles.is_empty() {
        return Err(InstallationError::ProfileViolation(
            "non-service profiles must not register SCM services".to_owned(),
        ));
    }
    Ok(())
}
