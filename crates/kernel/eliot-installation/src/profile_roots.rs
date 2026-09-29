use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::runtime_root_contract::{InstallationProfile, RuntimeStateRoots};
use super::{InstallationError, WindowsPathIdentity, text};

/// Breaking revision of the persisted four-root installation binding.
///
/// Version 2 corrects UserMode and PortableDev to the exact I3.1 sibling
/// durable/config/cache roots. Version 1 persisted the wrong mutable layout
/// and therefore requires explicit migration rather than path reinterpretation.
pub const INSTALLATION_ROOT_BINDING_VERSION: u32 = 2;

/// Installation/package roots plus the typed mutable runtime topology.
///
/// The binding carries the complete I3.1 four-role set: immutable versioned
/// binaries, durable service/installation state, and user configuration/cache
/// roles. `user_mode` and `portable_dev` use separate config/cache roots;
/// `system_service` retains the single `%LocalAppData%\Eliot` user root in both
/// role fields, as I3.1 specifies.
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
    /// User cache root. It is separate from configuration for `user_mode` and
    /// `portable_dev`, and equals it for the single `system_service` user root.
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
        // Every role has its own identity. Configuration and cache may be
        // siblings, but neither may alias or contain the other role.
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
            InstallationProfile::SystemService if parsed_roots[2].1 != parsed_roots[3].1 => {
                return Err(InstallationError::ProfileViolation(
                    "system_service must retain one shared user configuration and cache root"
                        .to_owned(),
                ));
            }
            InstallationProfile::UserMode | InstallationProfile::PortableDev
                if parsed_roots[2].1.aliases_or_overlaps(&parsed_roots[3].1) =>
            {
                return Err(InstallationError::ProfileViolation(
                    "user configuration and cache roots must be separate for this profile"
                        .to_owned(),
                ));
            }
            _ => {}
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

    /// Refuses a source bundle that overlaps the selected immutable binaries
    /// root. Source publication must remain separate from the final package
    /// destination so only the planned `StagePackage` effect can write there.
    ///
    /// # Errors
    ///
    /// Returns [`InstallationError::InvalidField`] for a malformed source path
    /// and [`InstallationError::ProfileViolation`] when its Windows path
    /// identity equals, contains, or is contained by the immutable root.
    pub fn validate_source_bundle_root(
        &self,
        source_bundle_root: &str,
    ) -> Result<(), InstallationError> {
        let source = WindowsPathIdentity::parse_root(source_bundle_root, "source_bundle_root")?;
        let immutable =
            WindowsPathIdentity::parse_root(&self.immutable_binaries, "immutable_binaries")?;
        if source.aliases_or_overlaps(&immutable) {
            return Err(InstallationError::ProfileViolation(
                "source bundle root must be disjoint from the final immutable binaries root"
                    .to_owned(),
            ));
        }
        Ok(())
    }

    /// Binds the I3.1 durable root to the proved runtime topology.
    ///
    /// `system_service` names the runtime profile root itself as durable state.
    /// UserMode and PortableDev use the I3.1 sibling data/config/cache layout;
    /// their seven runtime roots are children of the exact durable state root.
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
                let product_root = WindowsPathIdentity::parse_root(
                    &joined_windows_path(
                        self.runtime_state_roots.profile_anchor_root.as_str(),
                        "Eliot",
                    ),
                    "user_mode.product_root",
                )?;
                let expected_config = WindowsPathIdentity::parse_root(
                    &joined_windows_path(product_root.as_str(), "config"),
                    "user_config",
                )?;
                let expected_cache = WindowsPathIdentity::parse_root(
                    &joined_windows_path(product_root.as_str(), "cache"),
                    "user_cache",
                )?;
                if durable != profile_root
                    || user_config != expected_config
                    || user_cache != expected_cache
                {
                    return Err(InstallationError::ProfileViolation(
                        "UserMode must use Eliot\\data with sibling Eliot\\config and Eliot\\cache roots"
                            .to_owned(),
                    ));
                }
            }
            InstallationProfile::PortableDev => {
                let repository = WindowsPathIdentity::parse_root(
                    self.runtime_state_roots.profile_anchor_root.as_str(),
                    "portable_dev.repository_root",
                )?;
                let dev_root = WindowsPathIdentity::parse_root(
                    &joined_windows_path(repository.as_str(), ".eliot-dev"),
                    "portable_dev.dev_root",
                )?;
                let expected_config = WindowsPathIdentity::parse_root(
                    &joined_windows_path(dev_root.as_str(), "config"),
                    "user_config",
                )?;
                let expected_cache = WindowsPathIdentity::parse_root(
                    &joined_windows_path(dev_root.as_str(), "cache"),
                    "user_cache",
                )?;
                if durable != profile_root
                    || user_config != expected_config
                    || user_cache != expected_cache
                {
                    return Err(InstallationError::ProfileViolation(
                        "PortableDev must use sibling .eliot-dev/state, config and cache roots"
                            .to_owned(),
                    ));
                }
            }
        }
        Ok(())
    }
}
