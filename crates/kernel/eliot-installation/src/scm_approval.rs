//! Immutable SCM registration approvals derived from authoritative readback.

use std::path::Path;

use eliot_contracts::sha256_hex;
use eliot_platform_windows::{
    ELIOT_HOST_SERVICE_CONTROL_ACCESS_MASK, ELIOT_HOST_SERVICE_DISPLAY_NAME,
    ELIOT_HOST_SERVICE_NAME, ELIOT_HOST_SERVICE_SID, ELIOT_WATCHDOG_HOST_CONTROL_ACCESS_MASK,
    ELIOT_WATCHDOG_SERVICE_DISPLAY_NAME, ELIOT_WATCHDOG_SERVICE_NAME, SERVICE_EXPECTED_GROUP_SID,
    SERVICE_EXPECTED_OWNER_SID, ServiceAccount, ServiceBootstrapArguments,
    ServiceControlGrantReadback, ServiceRegistrationRequest, ServiceStartMode,
    host_service_security_descriptor_digest, watchdog_service_security_descriptor_digest,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::{
    InstallationError, InstallationServiceBootstrap, InstallerServiceAccount, InstallerServiceRole,
    PlatformHandle, approved_path, handle, sha256_handle,
};
/// Durable installer receipt for one narrow per-service installer-policy SCM
/// control grant: the `EliotHost` self-grant on the canonical `EliotHost`
/// registration, or the `EliotHost` service-SID grant on the canonical
/// `EliotWatchdog` registration. Both carry the deterministic Host SID as
/// principal and the OWNER|GROUP|DACL proof read from one SCM handle. The
/// private service key and SCM mutation handles never cross this projection.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstallerServiceControlGrantReceipt {
    /// Canonical service name whose deterministic SID receives the grant.
    pub(super) principal_service: PlatformHandle,
    /// Exact canonical Host service SID read back from SCM.
    pub(super) principal_sid: PlatformHandle,
    /// Concrete minimal service-object rights mask.
    pub(super) access_mask: u32,
    /// Exact service security-descriptor owner SID observed by SCM.
    pub(super) security_descriptor_owner: PlatformHandle,
    /// Exact service security-descriptor group SID observed by SCM.
    pub(super) security_descriptor_group: PlatformHandle,
    /// Digest of the exact protected service DACL returned by SCM readback.
    pub(super) security_descriptor_digest: PlatformHandle,
}

impl InstallerServiceControlGrantReceipt {
    pub(super) fn from_readback(
        readback: &ServiceControlGrantReadback,
    ) -> Result<Self, InstallationError> {
        readback
            .validate()
            .map_err(|_| InstallationError::IdentityConflict)?;
        let receipt = Self {
            principal_service: PlatformHandle::new(readback.principal_service()).map_err(
                |error| InstallationError::InvalidField {
                    field: "service_control_grant.principal_service".to_owned(),
                    reason: error.to_string(),
                },
            )?,
            principal_sid: PlatformHandle::new(readback.principal_sid()).map_err(|error| {
                InstallationError::InvalidField {
                    field: "service_control_grant.principal_sid".to_owned(),
                    reason: error.to_string(),
                }
            })?,
            access_mask: readback.access_mask(),
            security_descriptor_owner: PlatformHandle::new(readback.security_descriptor_owner())
                .map_err(|error| InstallationError::InvalidField {
                    field: "service_control_grant.security_descriptor_owner".to_owned(),
                    reason: error.to_string(),
                })?,
            security_descriptor_group: PlatformHandle::new(readback.security_descriptor_group())
                .map_err(|error| InstallationError::InvalidField {
                    field: "service_control_grant.security_descriptor_group".to_owned(),
                    reason: error.to_string(),
                })?,
            security_descriptor_digest: PlatformHandle::new(readback.security_descriptor_digest())
                .map_err(|error| InstallationError::InvalidField {
                    field: "service_control_grant.security_descriptor_digest".to_owned(),
                    reason: error.to_string(),
                })?,
        };
        receipt.validate()?;
        Ok(receipt)
    }

    /// Returns the exact service whose SID owns the runtime grant.
    #[must_use]
    pub fn principal_service(&self) -> &PlatformHandle {
        &self.principal_service
    }

    /// Returns the exact OS service SID observed by the installer.
    #[must_use]
    pub fn principal_sid(&self) -> &PlatformHandle {
        &self.principal_sid
    }

    /// Returns the concrete allowed service-object rights.
    #[must_use]
    pub const fn access_mask(&self) -> u32 {
        self.access_mask
    }

    /// Returns the digest of the exact protected SCM security descriptor.
    #[must_use]
    pub fn security_descriptor_digest(&self) -> &PlatformHandle {
        &self.security_descriptor_digest
    }

    /// Returns the exact owner SID observed in the SCM security descriptor.
    #[must_use]
    pub fn security_descriptor_owner(&self) -> &PlatformHandle {
        &self.security_descriptor_owner
    }

    /// Returns the exact group SID observed in the SCM security descriptor.
    #[must_use]
    pub fn security_descriptor_group(&self) -> &PlatformHandle {
        &self.security_descriptor_group
    }

    /// Computes the canonical binding used by the ownership marker and effect
    /// postcondition.
    pub fn canonical_digest(&self) -> Result<PlatformHandle, InstallationError> {
        #[derive(Serialize)]
        struct Shape<'a> {
            schema: &'static str,
            principal_service: &'a PlatformHandle,
            principal_sid: &'a PlatformHandle,
            access_mask: u32,
            security_descriptor_owner: &'a PlatformHandle,
            security_descriptor_group: &'a PlatformHandle,
            security_descriptor_digest: &'a PlatformHandle,
        }
        self.validate()?;
        let bytes = serde_json::to_vec(&Shape {
            schema: "eliot.installer.service-control-grant.v2",
            principal_service: &self.principal_service,
            principal_sid: &self.principal_sid,
            access_mask: self.access_mask,
            security_descriptor_owner: &self.security_descriptor_owner,
            security_descriptor_group: &self.security_descriptor_group,
            security_descriptor_digest: &self.security_descriptor_digest,
        })
        .map_err(|_| InstallationError::IdentityConflict)?;
        PlatformHandle::new(sha256_hex(&bytes)).map_err(|error| InstallationError::InvalidField {
            field: "service_control_grant.digest".to_owned(),
            reason: error.to_string(),
        })
    }

    /// Validates the receipt without touching SCM. Accepts both canonical
    /// per-service installer-policy grants (Host self-grant and
    /// Host-to-Watchdog grant), mirroring
    /// `ServiceControlGrantReadback::validate`.
    pub fn validate(&self) -> Result<(), InstallationError> {
        handle(
            &self.principal_service,
            "service_control_grant.principal_service",
        )?;
        handle(&self.principal_sid, "service_control_grant.principal_sid")?;
        handle(
            &self.security_descriptor_owner,
            "service_control_grant.security_descriptor_owner",
        )?;
        handle(
            &self.security_descriptor_group,
            "service_control_grant.security_descriptor_group",
        )?;
        sha256_handle(
            &self.security_descriptor_digest,
            "service_control_grant.security_descriptor_digest",
        )?;
        if self.principal_service.as_str() != ELIOT_HOST_SERVICE_NAME
            || self.principal_sid.as_str() != ELIOT_HOST_SERVICE_SID
        {
            return Err(InstallationError::IdentityConflict);
        }
        if self.security_descriptor_owner.as_str() != SERVICE_EXPECTED_OWNER_SID
            || self.security_descriptor_group.as_str() != SERVICE_EXPECTED_GROUP_SID
        {
            return Err(InstallationError::IdentityConflict);
        }
        // Watchdog grant path (byte-identical legacy behavior).
        if self.access_mask == ELIOT_WATCHDOG_HOST_CONTROL_ACCESS_MASK
            && watchdog_service_security_descriptor_digest(self.principal_sid.as_str())
                .is_ok_and(|expected| expected == self.security_descriptor_digest.as_str())
        {
            return Ok(());
        }
        // Host self-grant path (per-service generalization; Watchdog path
        // above unchanged).
        if self.access_mask == ELIOT_HOST_SERVICE_CONTROL_ACCESS_MASK
            && host_service_security_descriptor_digest(self.principal_sid.as_str())
                .is_ok_and(|expected| expected == self.security_descriptor_digest.as_str())
        {
            return Ok(());
        }
        Err(InstallationError::IdentityConflict)
    }
}

/// Installer-owned approval for one exact Host or Watchdog SCM registration.
///
/// The approval is a projection of an [`crate::InstallationTransaction`]'s durable
/// service-effect progress.  It is deliberately separate from
/// [`crate::CandidateManifest`] and [`crate::RuntimeLaunchDescriptor`]: the registration
/// nonce is minted only while the installer drives the effect and is retained
/// here only after authoritative SCM readback has produced an `Applied`
/// progress entry.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstallerServiceRegistrationApproval {
    /// Sole transaction which authorized this registration.
    pub(super) transaction_id: PlatformHandle,
    /// Candidate generation bound to the transaction.
    pub(super) generation: PlatformHandle,
    /// Immutable installer effect identity.
    pub(super) effect_id: PlatformHandle,
    /// Host or Watchdog role.
    pub(super) role: InstallerServiceRole,
    /// Canonical SCM service name.
    pub(super) service_name: PlatformHandle,
    /// Exact approved service image path.
    pub(super) executable_path: PlatformHandle,
    /// Exact service account admitted by the effect plan.
    pub(super) account: InstallerServiceAccount,
    /// Exact service start policy admitted by the effect plan.
    pub(super) automatic_start: bool,
    /// Immutable descriptor/installation binding rendered to service argv.
    pub(super) service_bootstrap: InstallationServiceBootstrap,
    /// Unpredictable nonce rendered only for this role's registration.
    pub(super) registration_nonce: PlatformHandle,
    /// Authoritative SCM configuration digest returned by readback.
    pub(super) configuration_digest: PlatformHandle,
    /// Exact installer-policy service DACL grant read back from SCM for
    /// this registration's service. Both Host and Watchdog registrations
    /// carry the grant: a service whose security descriptor is not the
    /// installer policy must never be reported `Applied`. The receipt always
    /// names the Host service SID authorized by the installer policy.
    pub(super) service_control_grant: Option<InstallerServiceControlGrantReceipt>,
}

/// Inputs for one fixture transaction's SCM approval pair. The bundle exists
/// so the per-role approval builder stays a small honest helper instead of
/// one 109-line loop body: the shared bootstrap and naming roots live here,
/// the role-shaped parts in `approval`.
#[cfg(feature = "test-support")]
struct TestSupportApprovalParts<'a> {
    transaction_id: &'a PlatformHandle,
    manifest: &'a crate::CandidateManifest,
    bootstrap: InstallationServiceBootstrap,
}

#[cfg(feature = "test-support")]
impl TestSupportApprovalParts<'_> {
    fn field(value: &str, field: &str) -> Result<PlatformHandle, InstallationError> {
        PlatformHandle::new(value).map_err(|error| InstallationError::InvalidField {
            field: field.to_owned(),
            reason: error.to_string(),
        })
    }

    fn role_tag(role: InstallerServiceRole) -> &'static str {
        match role {
            InstallerServiceRole::Host => "host",
            InstallerServiceRole::Watchdog => "watchdog",
        }
    }

    fn approval(
        &self,
        role: InstallerServiceRole,
        service_name: &'static str,
        executable_path: PlatformHandle,
    ) -> Result<InstallerServiceRegistrationApproval, InstallationError> {
        let role_tag = Self::role_tag(role);
        let service_control_grant = Some(test_support_service_control_grant(role)?);
        let registration_nonce = Self::field(
            sha256_hex(
                format!(
                    "eliot.test-support.scm-registration-nonce.v1\0{}\0{}\0{role_tag}",
                    self.transaction_id.as_str(),
                    self.manifest.generation.as_str(),
                )
                .as_bytes(),
            )
            .as_str(),
            "test_support.registration_nonce",
        )?;
        let bootstrap_arguments = ServiceBootstrapArguments::new(
            Path::new(self.bootstrap.descriptor_path.as_str()).to_path_buf(),
            self.bootstrap.descriptor_digest.as_str(),
            self.bootstrap.installation_id.as_str(),
            self.bootstrap.plan_generation,
            Vec::<String>::new(),
        )
        .and_then(|value| {
            value.with_host_state_root(Path::new(self.bootstrap.host_state_root.as_str()))
        })
        .and_then(|value| value.with_registration_nonce(registration_nonce.as_str()))
        .map_err(|_| InstallationError::InvalidField {
            field: "test_support.service_bootstrap".to_owned(),
            reason: "test-support SCM bootstrap could not be constructed".to_owned(),
        })?;
        let display_name = match role {
            InstallerServiceRole::Host => eliot_platform_windows::ELIOT_HOST_SERVICE_DISPLAY_NAME,
            InstallerServiceRole::Watchdog => {
                eliot_platform_windows::ELIOT_WATCHDOG_SERVICE_DISPLAY_NAME
            }
        };
        let request = ServiceRegistrationRequest::with_bootstrap(
            service_name,
            display_name,
            Path::new(executable_path.as_str()).to_path_buf(),
            ServiceStartMode::Automatic,
            ServiceAccount::LocalService,
            bootstrap_arguments,
        )
        .map_err(|_| InstallationError::InvalidField {
            field: "test_support.service_registration.request".to_owned(),
            reason: "test-support SCM request could not be constructed".to_owned(),
        })?;
        let approval = InstallerServiceRegistrationApproval {
            transaction_id: self.transaction_id.clone(),
            generation: self.manifest.generation.clone(),
            effect_id: Self::field(
                &format!(
                    "test-support:service-effect:{role_tag}:{}",
                    self.transaction_id.as_str(),
                ),
                "test_support.effect_id",
            )?,
            role,
            service_name: Self::field(service_name, "test_support.service_name")?,
            executable_path,
            account: InstallerServiceAccount::LocalService,
            automatic_start: true,
            service_bootstrap: self.bootstrap.clone(),
            registration_nonce,
            configuration_digest: Self::field(
                request.expected_configuration_digest().as_str(),
                "test_support.configuration_digest",
            )?,
            service_control_grant,
        };
        approval.validate()?;
        Ok(approval)
    }
}
impl InstallerServiceRegistrationApproval {
    /// Returns the generation bound to this approval.
    #[must_use]
    pub fn generation(&self) -> &PlatformHandle {
        &self.generation
    }

    /// Returns the role bound to this approval.
    #[must_use]
    pub const fn role(&self) -> InstallerServiceRole {
        self.role
    }

    /// Returns the authoritative SCM configuration digest.
    #[must_use]
    pub fn configuration_digest(&self) -> &PlatformHandle {
        &self.configuration_digest
    }

    /// Returns the authoritative installer-policy service DACL grant read
    /// back from SCM for this registration. Both Host and Watchdog
    /// registrations carry `Some` after authoritative readback.
    #[must_use]
    pub fn service_control_grant(&self) -> Option<&InstallerServiceControlGrantReceipt> {
        self.service_control_grant.as_ref()
    }

    pub(crate) fn registration_nonce(&self) -> &PlatformHandle {
        &self.registration_nonce
    }

    pub(crate) fn service_name_handle(&self) -> &PlatformHandle {
        &self.service_name
    }

    pub(crate) fn executable_path_handle(&self) -> &PlatformHandle {
        &self.executable_path
    }

    /// Validates the durable approval without touching the filesystem or SCM.
    pub fn validate(&self) -> Result<(), InstallationError> {
        handle(&self.transaction_id, "service_registration.transaction_id")?;
        handle(&self.generation, "service_registration.generation")?;
        handle(&self.effect_id, "service_registration.effect_id")?;
        handle(&self.service_name, "service_registration.service_name")?;
        approved_path(
            &self.executable_path,
            "service_registration.executable_path",
        )?;
        self.service_bootstrap.validate()?;
        sha256_handle(
            &self.registration_nonce,
            "service_registration.registration_nonce",
        )?;
        sha256_handle(
            &self.configuration_digest,
            "service_registration.configuration_digest",
        )?;
        let (expected_name, expected_image) = match self.role {
            InstallerServiceRole::Host => (ELIOT_HOST_SERVICE_NAME, "eliot-host.exe"),
            InstallerServiceRole::Watchdog => (ELIOT_WATCHDOG_SERVICE_NAME, "eliot-watchdog.exe"),
        };
        let observed_image = self
            .executable_path
            .as_str()
            .rsplit(['\\', '/'])
            .next()
            .unwrap_or_default();
        if self.service_name.as_str() != expected_name
            || !observed_image.eq_ignore_ascii_case(expected_image)
            || self.account != InstallerServiceAccount::LocalService
            || !self.automatic_start
        {
            return Err(InstallationError::ProfileViolation(
                "service registration approval differs from the canonical Runtime Live service shape"
                .to_owned(),
            ));
        }
        // s38 (#1345): Host and Watchdog registrations both require the
        // exact installer-policy service DACL grant. A Host service whose
        // security descriptor is not the installer policy must never be
        // reported `Applied`, so a Host approval without its grant receipt
        // fails closed exactly like a Watchdog approval without its own.
        match (self.role, &self.service_control_grant) {
            (InstallerServiceRole::Host | InstallerServiceRole::Watchdog, Some(receipt)) => {
                receipt.validate()?;
                let (expected_mask, expected_digest) = match self.role {
                    InstallerServiceRole::Host => (
                        ELIOT_HOST_SERVICE_CONTROL_ACCESS_MASK,
                        host_service_security_descriptor_digest(ELIOT_HOST_SERVICE_SID),
                    ),
                    InstallerServiceRole::Watchdog => (
                        ELIOT_WATCHDOG_HOST_CONTROL_ACCESS_MASK,
                        watchdog_service_security_descriptor_digest(ELIOT_HOST_SERVICE_SID),
                    ),
                };
                if receipt.access_mask() != expected_mask
                    || !expected_digest.is_ok_and(|expected| {
                        expected == receipt.security_descriptor_digest().as_str()
                    })
                {
                    return Err(InstallationError::IdentityConflict);
                }
            }
            (InstallerServiceRole::Host | InstallerServiceRole::Watchdog, None) => {
                return Err(InstallationError::IdentityConflict);
            }
        }
        Ok(())
    }

    /// Reconstructs the exact platform request approved by the installer.
    ///
    /// The returned request is still inert; this helper performs no SCM
    /// mutation.  The platform constructor supplies the final canonical
    /// command line and its configuration digest is checked against the
    /// installer readback before the request is returned.
    pub fn service_registration_request(
        &self,
    ) -> Result<ServiceRegistrationRequest, InstallationError> {
        self.validate()?;
        let bootstrap = ServiceBootstrapArguments::new(
            Path::new(self.service_bootstrap.descriptor_path.as_str()).to_path_buf(),
            self.service_bootstrap.descriptor_digest.as_str(),
            self.service_bootstrap.installation_id.as_str(),
            self.service_bootstrap.plan_generation,
            Vec::<String>::new(),
        )
        .and_then(|value| {
            value.with_host_state_root(Path::new(self.service_bootstrap.host_state_root.as_str()))
        })
        .and_then(|value| value.with_registration_nonce(self.registration_nonce.as_str()))
        .map_err(|_| InstallationError::InvalidField {
            field: "service_registration.service_bootstrap".to_owned(),
            reason: "approved SCM bootstrap could not be reconstructed".to_owned(),
        })?;
        let display_name = match self.role {
            InstallerServiceRole::Host => ELIOT_HOST_SERVICE_DISPLAY_NAME,
            InstallerServiceRole::Watchdog => ELIOT_WATCHDOG_SERVICE_DISPLAY_NAME,
        };
        let request = ServiceRegistrationRequest::with_bootstrap(
            self.service_name.as_str(),
            display_name,
            Path::new(self.executable_path.as_str()).to_path_buf(),
            ServiceStartMode::Automatic,
            ServiceAccount::LocalService,
            bootstrap,
        )
        .map_err(|_| InstallationError::InvalidField {
            field: "service_registration.request".to_owned(),
            reason: "approved SCM request could not be reconstructed".to_owned(),
        })?;
        if request.expected_configuration_digest() != self.configuration_digest.as_str() {
            return Err(InstallationError::IdentityConflict);
        }
        // s38 (#1345): both roles prove the installer-policy service DACL
        // with `Some` grant. The platform flag is still authoritative for the
        // Watchdog grant install/read; for Host it is advisory across the
        // platform generalization (older builds report `false` while newer
        // builds report `true`), so Host requires its own proof under either
        // flag value while Watchdog keeps the exact flag coupling.
        match self.role {
            InstallerServiceRole::Watchdog => {
                if !request.requires_host_service_control_grant()
                    || self.service_control_grant.is_none()
                {
                    return Err(InstallationError::IdentityConflict);
                }
            }
            InstallerServiceRole::Host => {
                if self.service_control_grant.is_none() {
                    return Err(InstallationError::IdentityConflict);
                }
            }
        }
        Ok(request)
    }
}

/// Issues the Host + Watchdog SCM registration approval pair for one
/// `SystemService` test-support seeding (issue #958 dispatch fixture).
///
/// A `SystemService` generation is invalid without exactly the two installer
/// SCM approvals (`ApprovedGenerationRegistry::validate`), and an approval is
/// a projection of authoritative SCM readback the test contour can never
/// perform (no SCM handle exists in the test process). This seam mints that
/// exact projection for one fixture transaction and manifest: the service
/// shape (canonical names, the manifest's own images, `LocalService` account,
/// automatic start), the installer-policy DACL grant receipts (the real
/// platform digest authority over the canonical Host SID) and the canonical
/// SCM configuration digest (the real `ServiceRegistrationRequest` binding
/// over the manifest's bootstrap) are all derived, never canned. Only the
/// installer effect identity and the registration nonces are
/// domain-separated test-support values, bound to the caller's transaction
/// and generation so two fixtures can never share them. No production path
/// calls this function: initial staging stays available only through the
/// transaction-bound activation gate.
#[cfg(feature = "test-support")]
pub fn issue_test_support_service_registration_approvals(
    transaction_id: &PlatformHandle,
    manifest: &crate::CandidateManifest,
) -> Result<Vec<InstallerServiceRegistrationApproval>, InstallationError> {
    if manifest.runtime_launch.profile != crate::InstallationProfile::SystemService {
        return Err(InstallationError::ProfileViolation(
            "test-support SCM approvals require the SystemService profile".to_owned(),
        ));
    }
    let runtime = &manifest.runtime_launch;
    let parts = TestSupportApprovalParts {
        transaction_id,
        manifest,
        bootstrap: InstallationServiceBootstrap {
            descriptor_path: runtime.authority_descriptor_path.clone(),
            descriptor_digest: crate::approved_generation_registry::phase_b_scm_digest(
                &runtime.authority_descriptor_digest,
            )?,
            installation_id: runtime.installation_epoch.installation.clone(),
            plan_generation: runtime.authority_generation.value(),
            host_state_root: runtime.runtime_state_roots.host_state_root.clone(),
        },
    };
    let mut approvals = Vec::with_capacity(2);
    for (role, service_name, executable_path) in [
        (
            InstallerServiceRole::Host,
            eliot_platform_windows::ELIOT_HOST_SERVICE_NAME,
            manifest.host_executable_path.clone(),
        ),
        (
            InstallerServiceRole::Watchdog,
            eliot_platform_windows::ELIOT_WATCHDOG_SERVICE_NAME,
            manifest.runtime_launch.watchdog_executable_path.clone(),
        ),
    ] {
        approvals.push(parts.approval(role, service_name, executable_path)?);
    }
    Ok(approvals)
}

/// Mints the installer-policy DACL grant receipt for one test-support SCM
/// approval: the canonical Host SID principal, the role's concrete access
/// mask and owner/group SIDs, and the digest from the real platform digest
/// authority for that SID. Mirrors the `#[cfg(test)]` grant fixtures without
/// sharing their module.
#[cfg(feature = "test-support")]
fn test_support_service_control_grant(
    role: InstallerServiceRole,
) -> Result<InstallerServiceControlGrantReceipt, InstallationError> {
    let field = |value: &str, field: &str| {
        PlatformHandle::new(value).map_err(|error| InstallationError::InvalidField {
            field: field.to_owned(),
            reason: error.to_string(),
        })
    };
    let principal_sid = eliot_platform_windows::ELIOT_HOST_SERVICE_SID;
    let digest_error =
        |error: eliot_platform_windows::WindowsAdapterError| InstallationError::InvalidField {
            field: "test_support.service_control_grant.digest".to_owned(),
            reason: error.to_string(),
        };
    let (access_mask, security_descriptor_digest) = match role {
        InstallerServiceRole::Host => (
            eliot_platform_windows::ELIOT_HOST_SERVICE_CONTROL_ACCESS_MASK,
            eliot_platform_windows::host_service_security_descriptor_digest(principal_sid)
                .map_err(digest_error)?,
        ),
        InstallerServiceRole::Watchdog => (
            eliot_platform_windows::ELIOT_WATCHDOG_HOST_CONTROL_ACCESS_MASK,
            eliot_platform_windows::watchdog_service_security_descriptor_digest(principal_sid)
                .map_err(digest_error)?,
        ),
    };
    let receipt = InstallerServiceControlGrantReceipt {
        principal_service: field(
            eliot_platform_windows::ELIOT_HOST_SERVICE_NAME,
            "test_support.service_control_grant.principal_service",
        )?,
        principal_sid: field(
            principal_sid,
            "test_support.service_control_grant.principal_sid",
        )?,
        access_mask,
        security_descriptor_owner: field(
            eliot_platform_windows::SERVICE_EXPECTED_OWNER_SID,
            "test_support.service_control_grant.owner",
        )?,
        security_descriptor_group: field(
            eliot_platform_windows::SERVICE_EXPECTED_GROUP_SID,
            "test_support.service_control_grant.group",
        )?,
        security_descriptor_digest: field(
            security_descriptor_digest.as_str(),
            "test_support.service_control_grant.digest",
        )?,
    };
    receipt.validate()?;
    Ok(receipt)
}
