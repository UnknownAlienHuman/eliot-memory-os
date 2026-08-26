//! Immutable SCM registration approvals derived from authoritative readback.

use std::path::Path;

use eliot_contracts::sha256_hex;
use eliot_platform_windows::{
    ELIOT_HOST_SERVICE_DISPLAY_NAME, ELIOT_HOST_SERVICE_NAME,
    ELIOT_WATCHDOG_HOST_CONTROL_ACCESS_MASK, ELIOT_WATCHDOG_SERVICE_DISPLAY_NAME,
    ELIOT_WATCHDOG_SERVICE_NAME, ServiceAccount, ServiceBootstrapArguments,
    ServiceControlGrantReadback, ServiceRegistrationRequest, ServiceStartMode,
    watchdog_service_security_descriptor_digest,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::{
    InstallationError, InstallationServiceBootstrap, InstallerServiceAccount, InstallerServiceRole,
    PlatformHandle, approved_path, handle, sha256_handle,
};
/// Durable installer receipt for the one narrow Host-to-Watchdog SCM control
/// grant. The private service key and SCM mutation handles never cross this
/// projection.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstallerServiceControlGrantReceipt {
    /// Canonical service name whose deterministic SID receives the grant.
    pub(super) principal_service: PlatformHandle,
    /// Exact OS-resolved `S-1-5-80-...` service SID.
    pub(super) principal_sid: PlatformHandle,
    /// Concrete minimal service-object rights mask.
    pub(super) access_mask: u32,
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

    /// Computes the canonical binding used by the ownership marker and effect
    /// postcondition.
    pub fn canonical_digest(&self) -> Result<PlatformHandle, InstallationError> {
        #[derive(Serialize)]
        struct Shape<'a> {
            schema: &'static str,
            principal_service: &'a PlatformHandle,
            principal_sid: &'a PlatformHandle,
            access_mask: u32,
            security_descriptor_digest: &'a PlatformHandle,
        }
        self.validate()?;
        let bytes = serde_json::to_vec(&Shape {
            schema: "eliot.installer.service-control-grant.v1",
            principal_service: &self.principal_service,
            principal_sid: &self.principal_sid,
            access_mask: self.access_mask,
            security_descriptor_digest: &self.security_descriptor_digest,
        })
        .map_err(|_| InstallationError::IdentityConflict)?;
        PlatformHandle::new(sha256_hex(&bytes)).map_err(|error| InstallationError::InvalidField {
            field: "service_control_grant.digest".to_owned(),
            reason: error.to_string(),
        })
    }

    /// Validates the receipt without touching SCM.
    pub fn validate(&self) -> Result<(), InstallationError> {
        handle(
            &self.principal_service,
            "service_control_grant.principal_service",
        )?;
        handle(&self.principal_sid, "service_control_grant.principal_sid")?;
        sha256_handle(
            &self.security_descriptor_digest,
            "service_control_grant.security_descriptor_digest",
        )?;
        let sid_tail = self
            .principal_sid
            .as_str()
            .strip_prefix("S-1-5-80-")
            .map(|tail| tail.split('-').collect::<Vec<_>>());
        if self.principal_service.as_str() != ELIOT_HOST_SERVICE_NAME
            || sid_tail.as_ref().is_none_or(|parts| {
                parts.len() != 5
                    || parts.iter().any(|part| {
                        part.is_empty()
                            || !part.bytes().all(|byte| byte.is_ascii_digit())
                            || part.parse::<u32>().is_err()
                    })
            })
            || self.access_mask != ELIOT_WATCHDOG_HOST_CONTROL_ACCESS_MASK
            || !watchdog_service_security_descriptor_digest(self.principal_sid.as_str())
                .is_ok_and(|expected| expected == self.security_descriptor_digest.as_str())
        {
            return Err(InstallationError::IdentityConflict);
        }
        Ok(())
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
    /// Exact Host service-SID grant required only by the Watchdog service.
    pub(super) service_control_grant: Option<InstallerServiceControlGrantReceipt>,
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

    /// Returns the authoritative Host control grant for the Watchdog
    /// registration. Host registrations deliberately return `None`.
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
        match (self.role, &self.service_control_grant) {
            (InstallerServiceRole::Host, None) => {}
            (InstallerServiceRole::Watchdog, Some(receipt)) => receipt.validate()?,
            (InstallerServiceRole::Host, Some(_)) | (InstallerServiceRole::Watchdog, None) => {
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
        if request.requires_host_service_control_grant() != self.service_control_grant.is_some() {
            return Err(InstallationError::IdentityConflict);
        }
        Ok(request)
    }
}
