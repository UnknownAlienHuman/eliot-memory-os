//! Typed runtime profile/root topology and retained-lease contract.
//!
//! This installation-owned contract derives explicit profile roots and retains
//! OS adapter leases for validation. It records typed topology and retained
//! observations, not authority or lifecycle decisions.
//!
//! Normative basis: Architecture A2.3, A12.2, A12.3; Implementation I1.2,
//! I2.2, I2.23. This module has no canonical or semantic authority,
//! lifecycle/SCM/process-tree authority, package-staging mutation,
//! credential/wire authority, `SurrealDB` connection/query/migration, daemon
//! authority, or platform implementation authority; it consumes OS adapter
//! leases only.

use std::{collections::BTreeSet, path::Path};

use eliot_platform_windows::{ProtectedPathError, ProtectedRootLease, UserOwnedRootReadLease};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::{
    InstallationError, PlatformHandle, WindowsPathIdentity, current_user_local_app_data_root,
    joined_windows_path, protected_program_data_root, runtime_sha256_handle, same_windows_root,
    sha256_hex, text, valid_installation_key, validate_installation_key,
};

/// The supported installation supervision and path profiles.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InstallationProfile {
    /// Elevated SCM-owned service with the strongest isolation guarantees.
    SystemService,
    /// Per-user installation supervised by the current user.
    UserMode,
    /// Repository-local disposable development profile.
    PortableDev,
}

impl InstallationProfile {
    /// Whether this profile requires administrative installation authority.
    #[must_use]
    pub const fn requires_admin(self) -> bool {
        matches!(self, Self::SystemService)
    }

    /// Whether this profile is permitted to share state with production roots.
    #[must_use]
    pub const fn is_disposable(self) -> bool {
        matches!(self, Self::PortableDev)
    }
}

/// Digest-bound mutable runtime roots for one explicitly selected profile.
///
/// `profile_anchor_root` is supplied by the installer after the Windows adapter
/// proves the corresponding protected `ProgramData`, `LocalAppData`, or retained
/// portable contour. The contract never consults process environment variables
/// and therefore cannot silently select a different profile root.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeStateRoots {
    /// Profile for which these roots were derived.
    pub profile: InstallationProfile,
    /// Explicit OS-validated profile anchor.
    pub profile_anchor_root: PlatformHandle,
    /// Durable root for this exact installation identity.
    pub installation_root: PlatformHandle,
    /// Host journal and supervision state.
    pub host_state_root: PlatformHandle,
    /// Kernel operational-record state (ORS).
    pub kernel_ors_root: PlatformHandle,
    /// Kernel ephemeral work area.
    pub kernel_work_root: PlatformHandle,
    /// Canonical Store database files.
    pub store_data_root: PlatformHandle,
    /// Canonical Store working directory.
    pub store_work_root: PlatformHandle,
    /// Canonical Store temporary files.
    pub store_temp_root: PlatformHandle,
    /// Watchdog state and bounded spool.
    pub watchdog_state_root: PlatformHandle,
    /// SHA-256 of all preceding fields.
    pub roots_digest: PlatformHandle,
}

/// One retained, no-follow root lease exposed by an OS adapter.
///
/// Implementations must keep the underlying directory and ancestor handles
/// alive for the lifetime of the value. Returning path text without a retained
/// lease violates this contract.
pub trait RuntimeRootLease {
    /// Caller-declared path bound to the retained handle.
    fn declared_path(&self) -> &str;
    /// Canonical path obtained from the retained no-follow handle.
    fn canonical_path(&self) -> &str;
    /// Stable same-file identity (for example volume serial plus file index).
    fn file_identity(&self) -> &str;
    /// Whether every retained component was proven non-reparse.
    fn is_reparse_free(&self) -> bool;
}

/// Adapter hook that acquires retained no-follow leases for runtime roots.
pub trait RuntimeRootLeaseProvider {
    /// Concrete guard kept alive through validation and returned to the caller.
    type Lease: RuntimeRootLease;

    /// Retains one existing root without following a reparse point.
    fn retain_root(&mut self, root: &PlatformHandle) -> Result<Self::Lease, InstallationError>;
}

/// Validated lease guards. Dropping this value releases the retained OS leases.
pub struct ValidatedRuntimeRootLeases<L> {
    leases: Vec<L>,
}

/// Real Windows retained root lease used by production composition.
pub enum WindowsRuntimeRootLease {
    /// `SystemService` lease backed by a retained read-only directory contour.
    Protected {
        /// Contract-declared root path.
        declared_path: String,
        /// OS-resolved DOS/UNC root path.
        canonical_path: String,
        /// Stable retained file-object identity.
        file_identity: String,
        /// Retained no-follow protected contour guard.
        lease: ProtectedRootLease,
    },
    /// UserMode/PortableDev retained directory lease.
    UserOwned {
        /// Contract-declared root path.
        declared_path: String,
        /// OS-resolved DOS/UNC root path.
        canonical_path: String,
        /// Stable retained directory-object identity.
        file_identity: String,
        /// Retained current-user directory guard.
        lease: UserOwnedRootReadLease,
    },
}

impl RuntimeRootLease for WindowsRuntimeRootLease {
    fn declared_path(&self) -> &str {
        match self {
            Self::Protected { declared_path, .. } | Self::UserOwned { declared_path, .. } => {
                declared_path
            }
        }
    }

    fn canonical_path(&self) -> &str {
        match self {
            Self::Protected { canonical_path, .. } | Self::UserOwned { canonical_path, .. } => {
                canonical_path
            }
        }
    }

    fn file_identity(&self) -> &str {
        match self {
            Self::Protected { file_identity, .. } | Self::UserOwned { file_identity, .. } => {
                file_identity
            }
        }
    }

    fn is_reparse_free(&self) -> bool {
        match self {
            Self::Protected { lease, .. } => lease.verify_stable_identity().is_ok(),
            Self::UserOwned { lease, .. } => lease.verify_stable_identity().is_ok(),
        }
    }
}

/// Production Windows adapter for the `RuntimeRootLeaseProvider` hook.
pub struct WindowsRuntimeRootLeaseProvider {
    profile: InstallationProfile,
}

impl WindowsRuntimeRootLeaseProvider {
    /// Validates the OS profile anchor before any runtime root is retained.
    pub fn for_roots(roots: &RuntimeStateRoots) -> Result<Self, InstallationError> {
        roots.validate()?;
        roots.validate_profile_anchor_os()?;
        Ok(Self {
            profile: roots.profile,
        })
    }
}

impl RuntimeRootLeaseProvider for WindowsRuntimeRootLeaseProvider {
    type Lease = WindowsRuntimeRootLease;

    fn retain_root(&mut self, root: &PlatformHandle) -> Result<Self::Lease, InstallationError> {
        let declared_path = root.as_str().to_owned();
        let path = Path::new(root.as_str());
        match self.profile {
            InstallationProfile::SystemService => {
                let lease =
                    ProtectedRootLease::open_existing(path).map_err(protected_path_error)?;
                let canonical_path = lease
                    .canonical_path()
                    .map_err(protected_path_error)?
                    .to_string_lossy()
                    .into_owned();
                let identity = lease.identity();
                Ok(WindowsRuntimeRootLease::Protected {
                    declared_path,
                    canonical_path,
                    file_identity: format!(
                        "volume:{}:file:{}",
                        identity.volume_serial_number, identity.file_index
                    ),
                    lease,
                })
            }
            InstallationProfile::UserMode | InstallationProfile::PortableDev => {
                let lease =
                    UserOwnedRootReadLease::open_existing(path).map_err(protected_path_error)?;
                let canonical_path = lease
                    .canonical_path()
                    .map_err(protected_path_error)?
                    .to_string_lossy()
                    .into_owned();
                let identity = lease.identity();
                Ok(WindowsRuntimeRootLease::UserOwned {
                    declared_path,
                    canonical_path,
                    file_identity: format!(
                        "volume:{}:file:{}",
                        identity.volume_serial_number, identity.file_index
                    ),
                    lease,
                })
            }
        }
    }
}

fn protected_path_error(error: ProtectedPathError) -> InstallationError {
    InstallationError::Platform(error.to_string())
}

impl<L> ValidatedRuntimeRootLeases<L> {
    /// Borrows every retained root lease in contract field order.
    #[must_use]
    pub fn leases(&self) -> &[L] {
        &self.leases
    }
}

impl RuntimeStateRoots {
    const ROOT_SUFFIXES: [(&'static str, &'static str); 7] = [
        ("host_state_root", "host"),
        ("kernel_ors_root", "kernel\\state"),
        ("kernel_work_root", "kernel\\work"),
        ("store_data_root", "store\\data"),
        ("store_work_root", "store\\work"),
        ("store_temp_root", "store\\tmp"),
        ("watchdog_state_root", "watchdog"),
    ];

    /// Derives `SystemService` or `UserMode` roots from an explicit OS-validated
    /// profile anchor and a lowercase SHA-256 installation key.
    pub fn derive_profiled(
        profile: InstallationProfile,
        profile_anchor_root: PlatformHandle,
        installation_key: &str,
    ) -> Result<Self, InstallationError> {
        if profile == InstallationProfile::PortableDev {
            return Err(InstallationError::ProfileViolation(
                "portable_dev requires derive_portable with one retained root".to_owned(),
            ));
        }
        Self::validate_profile_anchor_path_os(profile, &profile_anchor_root)?;
        validate_installation_key(installation_key)?;
        let installation_root = PlatformHandle::new(joined_windows_path(
            profile_anchor_root.as_str(),
            &format!("Eliot\\installations\\{installation_key}"),
        ))
        .map_err(|error| InstallationError::InvalidField {
            field: "runtime_state_roots.installation_root".to_owned(),
            reason: error.to_string(),
        })?;
        Self::derived(profile, profile_anchor_root, installation_root)
    }

    /// Derives `PortableDev` roots below one explicit retained disposable root.
    pub fn derive_portable(
        retained_portable_root: PlatformHandle,
    ) -> Result<Self, InstallationError> {
        Self::validate_profile_anchor_path_os(
            InstallationProfile::PortableDev,
            &retained_portable_root,
        )?;
        Self::derived(
            InstallationProfile::PortableDev,
            retained_portable_root.clone(),
            retained_portable_root,
        )
    }

    fn validate_profile_anchor_path_os(
        profile: InstallationProfile,
        anchor: &PlatformHandle,
    ) -> Result<(), InstallationError> {
        let observed = match profile {
            InstallationProfile::SystemService => {
                protected_program_data_root().map_err(protected_path_error)?
            }
            InstallationProfile::UserMode => {
                current_user_local_app_data_root().map_err(protected_path_error)?
            }
            InstallationProfile::PortableDev => {
                let lease = UserOwnedRootReadLease::open_existing(Path::new(anchor.as_str()))
                    .map_err(protected_path_error)?;
                lease.canonical_path().map_err(protected_path_error)?
            }
        };
        if !same_windows_root(anchor.as_str(), &observed.to_string_lossy())? {
            return Err(InstallationError::ProfileViolation(
                "profile anchor does not match the OS-resolved retained contour".to_owned(),
            ));
        }
        Ok(())
    }

    fn validate_profile_anchor_os(&self) -> Result<(), InstallationError> {
        Self::validate_profile_anchor_path_os(self.profile, &self.profile_anchor_root)
    }

    pub(super) fn derived(
        profile: InstallationProfile,
        profile_anchor_root: PlatformHandle,
        installation_root: PlatformHandle,
    ) -> Result<Self, InstallationError> {
        let make = |suffix: &str| {
            PlatformHandle::new(joined_windows_path(installation_root.as_str(), suffix)).map_err(
                |error| InstallationError::InvalidField {
                    field: "runtime_state_roots".to_owned(),
                    reason: error.to_string(),
                },
            )
        };
        let host_state_root = make("host")?;
        let kernel_ors_root = make("kernel\\state")?;
        let kernel_work_root = make("kernel\\work")?;
        let store_data_root = make("store\\data")?;
        let store_work_root = make("store\\work")?;
        let store_temp_root = make("store\\tmp")?;
        let watchdog_state_root = make("watchdog")?;
        let mut roots = Self {
            profile,
            profile_anchor_root,
            installation_root,
            host_state_root,
            kernel_ors_root,
            kernel_work_root,
            store_data_root,
            store_work_root,
            store_temp_root,
            watchdog_state_root,
            roots_digest: PlatformHandle::new("0".repeat(64)).map_err(|error| {
                InstallationError::InvalidField {
                    field: "runtime_state_roots.roots_digest".to_owned(),
                    reason: error.to_string(),
                }
            })?,
        };
        roots.roots_digest =
            PlatformHandle::new(sha256_hex(&roots.unsigned_bytes()?)).map_err(|error| {
                InstallationError::InvalidField {
                    field: "runtime_state_roots.roots_digest".to_owned(),
                    reason: error.to_string(),
                }
            })?;
        roots.validate()?;
        Ok(roots)
    }

    pub(super) fn root_fields(&self) -> [(&'static str, &PlatformHandle); 7] {
        [
            ("host_state_root", &self.host_state_root),
            ("kernel_ors_root", &self.kernel_ors_root),
            ("kernel_work_root", &self.kernel_work_root),
            ("store_data_root", &self.store_data_root),
            ("store_work_root", &self.store_work_root),
            ("store_temp_root", &self.store_temp_root),
            ("watchdog_state_root", &self.watchdog_state_root),
        ]
    }

    fn installer_profile_root(&self) -> Result<PlatformHandle, InstallationError> {
        match self.profile {
            InstallationProfile::SystemService | InstallationProfile::UserMode => {
                PlatformHandle::new(joined_windows_path(
                    self.profile_anchor_root.as_str(),
                    "Eliot",
                ))
                .map_err(|error| InstallationError::InvalidField {
                    field: "runtime_state_roots.profile_root".to_owned(),
                    reason: error.to_string(),
                })
            }
            InstallationProfile::PortableDev => Ok(self.installation_root.clone()),
        }
    }

    pub(super) fn expected_staging_root(
        &self,
    ) -> Result<Option<PlatformHandle>, InstallationError> {
        if self.profile == InstallationProfile::PortableDev {
            return Ok(None);
        }
        let profile_root = self.installer_profile_root()?;
        PlatformHandle::new(joined_windows_path(profile_root.as_str(), "packages"))
            .map(Some)
            .map_err(|error| InstallationError::InvalidField {
                field: "runtime_state_roots.staging_root".to_owned(),
                reason: error.to_string(),
            })
    }

    /// Derives the exact per-installation evidence root used by the live
    /// canary harness. The path is derived from the already validated
    /// installation root and is not an independently serialized authority.
    pub fn canary_evidence_root(&self) -> Result<PlatformHandle, InstallationError> {
        PlatformHandle::new(joined_windows_path(
            self.installation_root.as_str(),
            "canary-evidence",
        ))
        .map_err(|error| InstallationError::InvalidField {
            field: "runtime_state_roots.canary_evidence_root".to_owned(),
            reason: error.to_string(),
        })
    }

    /// Returns the exact one-leaf-at-a-time hierarchy admitted by the
    /// installer. System/User plans include every missing shared and runtime
    /// parent; `PortableDev` intentionally retains its pre-existing contour.
    pub(super) fn installer_root_hierarchy(
        &self,
    ) -> Result<Vec<(&'static str, PlatformHandle)>, InstallationError> {
        let mut hierarchy = Vec::new();
        if self.profile != InstallationProfile::PortableDev {
            let profile_root = self.installer_profile_root()?;
            let packages_root = self.expected_staging_root()?.ok_or_else(|| {
                InstallationError::ProfileViolation(
                    "profiled roots require a deterministic packages root".to_owned(),
                )
            })?;
            let installations_root =
                PlatformHandle::new(joined_windows_path(profile_root.as_str(), "installations"))
                    .map_err(|error| InstallationError::InvalidField {
                        field: "runtime_state_roots.installations_root".to_owned(),
                        reason: error.to_string(),
                    })?;
            hierarchy.push(("profile_root", profile_root));
            hierarchy.push(("packages_root", packages_root));
            hierarchy.push(("installations_root", installations_root));
        }
        hierarchy.push(("installation_root", self.installation_root.clone()));
        if self.profile == InstallationProfile::PortableDev {
            hierarchy.extend(
                self.root_fields()
                    .into_iter()
                    .map(|(field, root)| (field, root.clone())),
            );
        } else {
            hierarchy.push(("canary_evidence_root", self.canary_evidence_root()?));
            let kernel_root = PlatformHandle::new(joined_windows_path(
                self.installation_root.as_str(),
                "kernel",
            ))
            .map_err(|error| InstallationError::InvalidField {
                field: "runtime_state_roots.kernel_root".to_owned(),
                reason: error.to_string(),
            })?;
            let store_root = PlatformHandle::new(joined_windows_path(
                self.installation_root.as_str(),
                "store",
            ))
            .map_err(|error| InstallationError::InvalidField {
                field: "runtime_state_roots.store_root".to_owned(),
                reason: error.to_string(),
            })?;
            hierarchy.push(("host_state_root", self.host_state_root.clone()));
            hierarchy.push(("kernel_root", kernel_root));
            hierarchy.push(("kernel_ors_root", self.kernel_ors_root.clone()));
            hierarchy.push(("kernel_work_root", self.kernel_work_root.clone()));
            hierarchy.push(("store_root", store_root));
            hierarchy.push(("store_data_root", self.store_data_root.clone()));
            hierarchy.push(("store_work_root", self.store_work_root.clone()));
            hierarchy.push(("store_temp_root", self.store_temp_root.clone()));
            hierarchy.push(("watchdog_state_root", self.watchdog_state_root.clone()));
        }
        Ok(hierarchy)
    }

    pub(super) fn reject_mutable_alias(
        &self,
        candidate: &PlatformHandle,
        candidate_field: &str,
    ) -> Result<(), InstallationError> {
        let candidate_path = WindowsPathIdentity::parse_root(candidate.as_str(), candidate_field)?;
        for (root_field, root) in self.root_fields() {
            let mutable_path = WindowsPathIdentity::parse_root(
                root.as_str(),
                &format!("runtime_state_roots.{root_field}"),
            )?;
            if candidate_path.aliases_or_overlaps(&mutable_path) {
                return Err(InstallationError::ProfileViolation(format!(
                    "{candidate_field} aliases mutable runtime root {root_field}"
                )));
            }
        }
        Ok(())
    }

    pub(super) fn unsigned_bytes(&self) -> Result<Vec<u8>, InstallationError> {
        #[derive(Serialize)]
        struct Unsigned<'a> {
            profile: InstallationProfile,
            profile_anchor_root: &'a PlatformHandle,
            installation_root: &'a PlatformHandle,
            host_state_root: &'a PlatformHandle,
            kernel_ors_root: &'a PlatformHandle,
            kernel_work_root: &'a PlatformHandle,
            store_data_root: &'a PlatformHandle,
            store_work_root: &'a PlatformHandle,
            store_temp_root: &'a PlatformHandle,
            watchdog_state_root: &'a PlatformHandle,
        }
        serde_json::to_vec(&Unsigned {
            profile: self.profile,
            profile_anchor_root: &self.profile_anchor_root,
            installation_root: &self.installation_root,
            host_state_root: &self.host_state_root,
            kernel_ors_root: &self.kernel_ors_root,
            kernel_work_root: &self.kernel_work_root,
            store_data_root: &self.store_data_root,
            store_work_root: &self.store_work_root,
            store_temp_root: &self.store_temp_root,
            watchdog_state_root: &self.watchdog_state_root,
        })
        .map_err(|error| InstallationError::InvalidField {
            field: "runtime_state_roots".to_owned(),
            reason: error.to_string(),
        })
    }

    /// Validates profile binding, fixed topology, whole-component separation,
    /// and the roots digest. OS reparse/file identity proof is performed by
    /// [`Self::retain_and_validate`].
    pub fn validate(&self) -> Result<(), InstallationError> {
        let anchor = WindowsPathIdentity::parse_root(
            self.profile_anchor_root.as_str(),
            "runtime_state_roots.profile_anchor_root",
        )?;
        let installation = WindowsPathIdentity::parse_root(
            self.installation_root.as_str(),
            "runtime_state_roots.installation_root",
        )?;
        match self.profile {
            InstallationProfile::SystemService | InstallationProfile::UserMode => {
                if !anchor.contains(&installation) || anchor == installation {
                    return Err(InstallationError::ProfileViolation(
                        "profiled installation root must be below its explicit profile anchor"
                            .to_owned(),
                    ));
                }
                let Some(key) = installation.components.last() else {
                    return Err(InstallationError::ProfileViolation(
                        "profiled installation root is incomplete".to_owned(),
                    ));
                };
                validate_installation_key(key)?;
                if installation.components.len() < 3
                    || !installation.ends_with(&["eliot", "installations", key])
                {
                    return Err(InstallationError::ProfileViolation(
                        "profiled installation root must end in Eliot/installations/<key>"
                            .to_owned(),
                    ));
                }
            }
            InstallationProfile::PortableDev => {
                if anchor != installation {
                    return Err(InstallationError::ProfileViolation(
                        "portable_dev installation root must equal its retained portable root"
                            .to_owned(),
                    ));
                }
                if installation.components.len() >= 3 {
                    let last = installation.components.last().map_or("", String::as_str);
                    if valid_installation_key(last)
                        && installation.ends_with(&["eliot", "installations", last])
                    {
                        return Err(InstallationError::ProfileViolation(
                            "portable_dev must not alias a profiled durable installation root"
                                .to_owned(),
                        ));
                    }
                }
            }
        }

        let fields = self.root_fields();
        let mut parsed = Vec::with_capacity(fields.len());
        for ((field, root), (expected_field, suffix)) in
            fields.iter().zip(Self::ROOT_SUFFIXES.iter())
        {
            debug_assert_eq!(field, expected_field);
            let path = WindowsPathIdentity::parse_root(
                root.as_str(),
                &format!("runtime_state_roots.{field}"),
            )?;
            if !installation.contains(&path) || installation == path {
                return Err(InstallationError::ProfileViolation(format!(
                    "{field} must be below the installation root"
                )));
            }
            let expected = WindowsPathIdentity::parse_root(
                &joined_windows_path(self.installation_root.as_str(), suffix),
                &format!("runtime_state_roots.{field}"),
            )?;
            if path != expected {
                return Err(InstallationError::ProfileViolation(format!(
                    "{field} does not match the fixed runtime root topology"
                )));
            }
            parsed.push((field, path));
        }
        for left in 0..parsed.len() {
            for right in left + 1..parsed.len() {
                if parsed[left].1.aliases_or_overlaps(&parsed[right].1) {
                    return Err(InstallationError::ProfileViolation(format!(
                        "{} and {} alias or overlap by Windows path components",
                        parsed[left].0, parsed[right].0
                    )));
                }
            }
        }
        runtime_sha256_handle(&self.roots_digest, "runtime_state_roots.roots_digest")?;
        if sha256_hex(&self.unsigned_bytes()?) != self.roots_digest.as_str() {
            return Err(InstallationError::InvalidField {
                field: "runtime_state_roots.roots_digest".to_owned(),
                reason: "runtime root digest mismatch".to_owned(),
            });
        }
        Ok(())
    }

    /// Acquires and validates retained no-follow OS leases for all mutable roots.
    /// The returned guards must remain alive across descriptor consumption.
    pub fn retain_and_validate<P>(
        &self,
        provider: &mut P,
    ) -> Result<ValidatedRuntimeRootLeases<P::Lease>, InstallationError>
    where
        P: RuntimeRootLeaseProvider,
    {
        self.validate()?;
        let mut leases = Vec::with_capacity(7);
        let mut identities = BTreeSet::new();
        for (field, root) in self.root_fields() {
            let lease = provider.retain_root(root)?;
            if !lease.is_reparse_free() {
                return Err(InstallationError::ProfileViolation(format!(
                    "{field} retained lease contains a reparse point"
                )));
            }
            if !same_windows_root(lease.declared_path(), root.as_str())?
                || !same_windows_root(lease.canonical_path(), root.as_str())?
            {
                return Err(InstallationError::ProfileViolation(format!(
                    "{field} retained lease does not bind the declared canonical root"
                )));
            }
            text(lease.file_identity(), "runtime_root_lease.file_identity")?;
            if !identities.insert(lease.file_identity().to_owned()) {
                return Err(InstallationError::ProfileViolation(
                    "two runtime roots alias the same retained file object".to_owned(),
                ));
            }
            leases.push(lease);
        }
        Ok(ValidatedRuntimeRootLeases { leases })
    }
}
