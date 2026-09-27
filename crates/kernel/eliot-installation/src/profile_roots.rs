use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::runtime_root_contract::{InstallationProfile, RuntimeStateRoots};
use super::{InstallationError, WindowsPathIdentity, text};

/// Breaking revision of the persisted four-root installation binding.
///
/// Version 1 is the first versioned binding: profile plus immutable, durable,
/// user-configuration and user-cache roots with the digest-bound runtime
/// topology. Older unversioned projections require explicit migration and are
/// never defaulted into this shape.
pub const INSTALLATION_ROOT_BINDING_VERSION: u32 = 1;

/// Installation/package roots plus the typed mutable runtime topology.
///
/// The binding carries the complete I3.1 four-root set: immutable versioned
/// binaries, durable service/installation state, and the separate user
/// configuration and user cache roots the `user_mode` and `portable_dev`
/// profiles require. For `system_service`, whose I3.1 user root is a single
/// `%LocalAppData%\Eliot`, configuration and cache name that same root.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstallationRoots {
    /// Breaking revision of this binding projection.
    pub binding_version: u32,
    /// Immutable, versioned binaries and component artifacts.
    pub immutable_binaries: String,
    /// Durable service/installation state.
    pub durable_data: String,
    /// User configuration root.
    pub user_config: String,
    /// User cache root, persisted separately from configuration.
    pub user_cache: String,
    /// Explicit digest-bound runtime state topology.
    pub runtime_state_roots: RuntimeStateRoots,
}

impl InstallationRoots {
    /// Creates and validates a root set for one profile.
    pub(crate) fn new(
        profile: InstallationProfile,
        immutable_binaries: impl Into<String>,
        durable_data: impl Into<String>,
        user_config: impl Into<String>,
        user_cache: impl Into<String>,
        runtime_state_roots: RuntimeStateRoots,
    ) -> Result<Self, InstallationError> {
        let roots = Self {
            binding_version: INSTALLATION_ROOT_BINDING_VERSION,
            immutable_binaries: immutable_binaries.into(),
            durable_data: durable_data.into(),
            user_config: user_config.into(),
            user_cache: user_cache.into(),
            runtime_state_roots,
        };
        roots.validate(profile)?;
        Ok(roots)
    }

    /// Validates the binding revision, path separation and profile agreement,
    /// and rejects traversal or empty roots.
    pub fn validate(&self, profile: InstallationProfile) -> Result<(), InstallationError> {
        if self.binding_version != INSTALLATION_ROOT_BINDING_VERSION {
            return Err(InstallationError::InvalidField {
                field: "binding_version".to_owned(),
                reason: "installation root binding requires explicit migration".to_owned(),
            });
        }
        let values = [
            (&self.immutable_binaries, "immutable_binaries"),
            (&self.durable_data, "durable_data"),
            (&self.user_config, "user_config"),
            (&self.user_cache, "user_cache"),
        ];
        let mut parsed_roots = Vec::new();
        for (value, field) in values {
            text(value, field)?;
            parsed_roots.push((field, WindowsPathIdentity::parse_root(value, field)?));
        }
        // Immutable, durable and configuration roots must never alias or
        // overlap; the cache root must never alias the immutable or durable
        // roots. Configuration and cache aliasing is governed by the profile
        // below: only `system_service` names one shared user root.
        for left in 0..3 {
            for right in left + 1..3 {
                if parsed_roots[left]
                    .1
                    .aliases_or_overlaps(&parsed_roots[right].1)
                {
                    return Err(InstallationError::ProfileViolation(format!(
                        "{} and {} alias or overlap by Windows path components",
                        parsed_roots[left].0, parsed_roots[right].0
                    )));
                }
            }
        }
        for index in 0..2 {
            if parsed_roots[3]
                .1
                .aliases_or_overlaps(&parsed_roots[index].1)
            {
                return Err(InstallationError::ProfileViolation(format!(
                    "user_cache and {} alias or overlap by Windows path components",
                    parsed_roots[index].0
                )));
            }
        }
        match profile {
            InstallationProfile::SystemService => {
                if parsed_roots[2].1 != parsed_roots[3].1 {
                    return Err(InstallationError::ProfileViolation(
                        "system_service names one shared user configuration and cache root"
                            .to_owned(),
                    ));
                }
            }
            InstallationProfile::UserMode | InstallationProfile::PortableDev => {
                if parsed_roots[2].1.aliases_or_overlaps(&parsed_roots[3].1) {
                    return Err(InstallationError::ProfileViolation(
                        "user configuration and cache roots must be separate".to_owned(),
                    ));
                }
            }
        }
        if !profile.is_disposable()
            && self
                .immutable_binaries
                .eq_ignore_ascii_case(&self.durable_data)
        {
            return Err(InstallationError::ProfileViolation(
                "production binaries may not share the durable data root".to_owned(),
            ));
        }
        self.runtime_state_roots.validate()?;
        if self.runtime_state_roots.profile != profile {
            return Err(InstallationError::ProfileViolation(
                "runtime roots profile must equal the installation profile".to_owned(),
            ));
        }
        self.validate_durable_runtime_join(profile)?;
        Ok(())
    }

    /// Binds the I3.1 durable root to the proved runtime topology.
    ///
    /// `system_service` names the runtime profile root itself as durable
    /// state; `user_mode` refines that contour into per-role children, so each
    /// of its durable, configuration and cache roots must sit strictly below
    /// it. `portable_dev` is explicitly disposable, so profile agreement and
    /// root separation above are its complete join.
    fn validate_durable_runtime_join(
        &self,
        profile: InstallationProfile,
    ) -> Result<(), InstallationError> {
        let profile_root = self.runtime_state_roots.installer_profile_root()?;
        let profile_root = WindowsPathIdentity::parse_root(
            profile_root.as_str(),
            "runtime_state_roots.profile_root",
        )?;
        let durable = WindowsPathIdentity::parse_root(&self.durable_data, "durable_data")?;
        match profile {
            InstallationProfile::SystemService => {
                if durable != profile_root {
                    return Err(InstallationError::ProfileViolation(
                        "durable installation root must equal the runtime profile root".to_owned(),
                    ));
                }
            }
            InstallationProfile::UserMode => {
                let user_config =
                    WindowsPathIdentity::parse_root(&self.user_config, "user_config")?;
                let user_cache = WindowsPathIdentity::parse_root(&self.user_cache, "user_cache")?;
                for (field, root) in [
                    ("durable_data", &durable),
                    ("user_config", &user_config),
                    ("user_cache", &user_cache),
                ] {
                    if !profile_root.contains(root) || profile_root == *root {
                        return Err(InstallationError::ProfileViolation(format!(
                            "{field} must sit strictly below the runtime profile root"
                        )));
                    }
                }
            }
            InstallationProfile::PortableDev => {}
        }
        Ok(())
    }
}
