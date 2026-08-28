use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::runtime_root_contract::{InstallationProfile, RuntimeStateRoots};
use super::{InstallationError, WindowsPathIdentity, same_windows_root, text};

/// Installation/package roots plus the typed mutable runtime topology.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstallationRoots {
    /// Immutable, versioned binaries and component artifacts.
    pub immutable_binaries: String,
    /// Durable service/installation state.
    pub durable_data: String,
    /// User configuration and cache.
    pub user_config_cache: String,
    /// Explicit digest-bound runtime state topology.
    pub runtime_state_roots: RuntimeStateRoots,
}

impl InstallationRoots {
    /// Creates and validates a root set for one profile.
    #[allow(dead_code, reason = "retained for crate-local root composition")]
    pub(crate) fn new(
        profile: InstallationProfile,
        immutable_binaries: impl Into<String>,
        durable_data: impl Into<String>,
        user_config_cache: impl Into<String>,
        runtime_state_roots: RuntimeStateRoots,
    ) -> Result<Self, InstallationError> {
        let roots = Self {
            immutable_binaries: immutable_binaries.into(),
            durable_data: durable_data.into(),
            user_config_cache: user_config_cache.into(),
            runtime_state_roots,
        };
        roots.validate(profile)?;
        Ok(roots)
    }

    /// Validates path separation and rejects traversal or empty roots.
    pub fn validate(&self, profile: InstallationProfile) -> Result<(), InstallationError> {
        let values = [
            (&self.immutable_binaries, "immutable_binaries"),
            (&self.durable_data, "durable_data"),
            (&self.user_config_cache, "user_config_cache"),
        ];
        let mut parsed_roots = Vec::new();
        for (value, field) in values {
            text(value, field)?;
            parsed_roots.push((field, WindowsPathIdentity::parse_root(value, field)?));
        }
        for left in 0..parsed_roots.len() {
            for right in left + 1..parsed_roots.len() {
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
        if !same_windows_root(
            &self.durable_data,
            self.runtime_state_roots.installation_root.as_str(),
        )? {
            return Err(InstallationError::ProfileViolation(
                "durable installation root must equal RuntimeStateRoots.installation_root"
                    .to_owned(),
            ));
        }
        Ok(())
    }
}
