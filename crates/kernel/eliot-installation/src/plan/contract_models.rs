//! Architecture `A2.3` (functional/source/runtime/deployment boundaries; Kernel retains
//! lifecycle/fencing depth outside this contract island).
//!
//! Implementation `I2.20` (`FunctionalCapabilityCell`: stateless contracts/primitives
//! island, package membership does not transfer authority).
//!
//! Implementation `I3.15` (installation/update transaction: immutable plan/staging/artifact
//! digests and planned file/ACL/service changes; installer/Host owns execution and durable
//! recovery).
//!
//! Ownership: this child owns immutable plan DTOs and local validation only; parent
//! transaction/effect execution/installation authority remains outside.

use std::path::Path;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::super::{
    InstallationError, PlatformHandle, ResourceGeneration, SUPERVISION_AUTHORITY_HOST_SERVICE,
    SUPERVISION_AUTHORITY_SERVICE_SID_TYPE, approved_path, handle, handles,
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
    pub(super) fn validate(&self) -> Result<(), InstallationError> {
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
