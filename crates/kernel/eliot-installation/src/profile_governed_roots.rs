//! Profile-governed root selection (I3.1).
//!
//! I3.1 states that the installation profile "determines both process
//! supervision and writable roots", and publishes one authoritative root table:
//!
//! ```text
//! system_service  %ProgramFiles%\Eliot\<component>\<version>  %ProgramData%\Eliot          %LocalAppData%\Eliot
//! user_mode       %LocalAppData%\Programs\Eliot\<component>\<version>  %LocalAppData%\Eliot\data  %LocalAppData%\Eliot\config|cache
//! portable_dev    <repository>\target\eliot-dev\<generation>  <repository>\.eliot-dev\state  <repository>\.eliot-dev\config|cache
//! ```
//!
//! This module resolves that table from anchors the Windows adapter has already
//! proved, and reports the selection it made. It deliberately does **not** read
//! process environment variables: `RuntimeStateRoots` establishes that the
//! contract "never consults process environment variables and therefore cannot
//! silently select a different profile root", and an anchor this module cannot
//! prove is an error rather than a guess.
//!
//! Normative basis: I3.1. This module resolves paths and refuses two documented
//! combinations. It grants no supervision authority, performs no installation
//! effect, and creates nothing on disk.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::runtime_root_contract::{InstallationProfile, RuntimeStateRoots};
use super::{
    InstallationError, InstallationRoots, PlatformHandle, WindowsPathIdentity, joined_windows_path,
    text,
};

/// Product directory name under every Windows profile anchor (I3.1 table).
const PRODUCT_DIR: &str = "Eliot";
/// Per-user programs directory for the `user_mode` immutable root (I3.1 table).
const USER_PROGRAMS_DIR: &str = "Programs";
/// Repository-local immutable root for the `portable_dev` profile (I3.1 table).
const PORTABLE_BINARIES_DIR: &str = "target\\eliot-dev";
/// Repository-local state root prefix for the `portable_dev` profile (I3.1 table).
const PORTABLE_STATE_DIR: &str = ".eliot-dev";
/// User configuration root name, where I3.1 publishes a `config|cache` pair.
const USER_CONFIG_DIR: &str = "config";
/// User cache root name, where I3.1 publishes a `config|cache` pair.
const USER_CACHE_DIR: &str = "cache";

/// The profile anchors the Windows adapter has proved for one selection.
///
/// An anchor that the selected profile does not use is left `None`; an anchor
/// the selected profile requires is an error when it is absent. Nothing here is
/// discovered, and no anchor is inferred from an environment variable.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProfileRootAnchors {
    /// `%ProgramFiles%` contour, required by `system_service` only.
    pub program_files: Option<PlatformHandle>,
    /// `%ProgramData%` contour, required by `system_service` only.
    pub program_data: Option<PlatformHandle>,
    /// `%LocalAppData%` contour, required by `user_mode` and by every profile's
    /// user configuration and cache roots.
    pub local_app_data: PlatformHandle,
    /// Repository contour, required by `portable_dev` only.
    pub repository_root: Option<PlatformHandle>,
}

/// Returns the anchor a profile requires, or the typed reason it is absent.
fn required_anchor(
    anchor: Option<&PlatformHandle>,
    field: &'static str,
) -> Result<String, InstallationError> {
    match anchor {
        Some(handle) => {
            text(handle.as_str(), field)?;
            Ok(handle.as_str().to_owned())
        }
        None => Err(InstallationError::ProfileViolation(format!(
            "{field} is required by the selected installation profile and was not proved"
        ))),
    }
}

/// The I3.1 root set resolved for one explicitly selected profile.
///
/// `user_cache` is the sibling root of `user_config` where I3.1 publishes the
/// `config|cache` pair for `user_mode` and `portable_dev`. `system_service`
/// retains its single `%LocalAppData%\Eliot` user root in both role fields.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileGovernedRoots {
    /// Profile whose rules produced these roots.
    pub profile: InstallationProfile,
    /// Immutable, versioned binaries and component artifacts.
    pub immutable_binaries: String,
    /// Durable service/installation state.
    pub durable_data: String,
    /// User configuration root.
    pub user_config: String,
    /// User cache root.
    pub user_cache: String,
}

impl ProfileGovernedRoots {
    /// Returns the profile selection that produced these roots.
    #[must_use]
    pub const fn selection(&self) -> InstallationProfile {
        self.profile
    }

    /// Refuses a mutable write target for this profile (I3.1).
    ///
    /// I3.1: "Mutable data is never stored beside immutable versioned binaries,
    /// except inside the explicitly disposable `portable_dev` profile." A target
    /// inside the profile's versioned immutable binaries root is therefore
    /// refused for `system_service` and `user_mode`, and admitted only for the
    /// disposable `portable_dev` profile. The comparison is lexical on
    /// [`WindowsPathIdentity`], the same bounded identity this crate already uses
    /// for root separation, so a traversal or alias cannot slip past it.
    ///
    /// # Errors
    ///
    /// Returns [`InstallationError::InvalidField`] when the target is not a
    /// usable absolute path, and [`InstallationError::ProfileViolation`] when
    /// the target lies inside the versioned immutable binaries root of a profile
    /// that does not permit it.
    pub fn admits_write_target(&self, target: &str) -> Result<(), InstallationError> {
        let target = WindowsPathIdentity::parse_root(target, "write_target")?;
        let binaries =
            WindowsPathIdentity::parse_root(&self.immutable_binaries, "immutable_binaries")?;
        if binaries.contains(&target) && !self.profile.is_disposable() {
            return Err(InstallationError::ProfileViolation(format!(
                "write target lies inside the {} immutable binaries root; mutable data is never stored beside immutable versioned binaries",
                self.profile_name()
            )));
        }
        Ok(())
    }

    /// Stable profile name used in rejection messages.
    fn profile_name(&self) -> &'static str {
        match self.profile {
            InstallationProfile::SystemService => "system_service",
            InstallationProfile::UserMode => "user_mode",
            InstallationProfile::PortableDev => "portable_dev",
        }
    }

    /// Converts the resolved roots into the crate's versioned installation
    /// root binding.
    ///
    /// Path separation, aliasing and profile agreement stay owned by
    /// [`InstallationRoots::validate`]; this function only supplies the roots
    /// the I3.1 table produced. Both the user configuration and the user cache
    /// roots are forwarded separately, so the cache root the I3.1 `config|cache`
    /// pair names survives into downstream use. The caller supplies the
    /// already digest-bound [`RuntimeStateRoots`], because those are proved by
    /// the Windows adapter rather than derived from a profile.
    ///
    /// # Errors
    ///
    /// Returns [`InstallationError`] when the runtime state roots do not belong
    /// to this profile or violate root separation.
    pub fn into_installation_roots(
        self,
        runtime_state_roots: RuntimeStateRoots,
    ) -> Result<InstallationRoots, InstallationError> {
        InstallationRoots::new(
            self.profile,
            self.immutable_binaries,
            self.durable_data,
            self.user_config,
            self.user_cache,
            runtime_state_roots,
        )
    }
}

/// Resolves the I3.1 root table for one explicitly selected profile.
///
/// Every profile reports its selection through the returned
/// [`ProfileGovernedRoots::selection`], and the roots are exactly the row I3.1
/// publishes for that profile. `component` and `version` are required by the two
/// Windows profiles' immutable root; `generation` is required by `portable_dev`,
/// whose immutable root is versioned by generation rather than by release
/// version.
///
/// `user_mode` is resolved without administrative rights: its durable, config
/// and cache roots are derived from the current-user contour, and a root that
/// would place user-mode state under the `system_service` `%ProgramData%` anchor
/// is refused rather than returned, because I3.1 states that code "may not assume
/// `%ProgramData%` or administrative service rights merely because the Windows
/// production profile supports them".
///
/// # Errors
///
/// Returns [`InstallationError::ProfileViolation`] when the profile requires an
/// anchor that was not proved, when a required component/version/generation input
/// is missing, or when a resolved user-mode root would fall under the
/// `%ProgramData%` contour.
pub fn select_profile_roots(
    profile: InstallationProfile,
    component: &str,
    version: &str,
    generation: Option<&str>,
    anchors: &ProfileRootAnchors,
) -> Result<ProfileGovernedRoots, InstallationError> {
    text(component, "component")?;
    text(version, "version")?;
    let local_app_data = required_anchor(Some(&anchors.local_app_data), "local_app_data")?;
    let roots = match profile {
        InstallationProfile::SystemService => {
            let program_files = required_anchor(anchors.program_files.as_ref(), "program_files")?;
            let program_data = required_anchor(anchors.program_data.as_ref(), "program_data")?;
            let user_root = joined_windows_path(&local_app_data, PRODUCT_DIR);
            ProfileGovernedRoots {
                profile,
                immutable_binaries: joined_windows_path(
                    &joined_windows_path(
                        &joined_windows_path(&program_files, PRODUCT_DIR),
                        component,
                    ),
                    version,
                ),
                durable_data: joined_windows_path(&program_data, PRODUCT_DIR),
                user_config: user_root.clone(),
                user_cache: user_root,
            }
        }
        InstallationProfile::UserMode => {
            let user_root = joined_windows_path(&local_app_data, PRODUCT_DIR);
            let data_root = joined_windows_path(&user_root, "data");
            let config_root = joined_windows_path(&user_root, USER_CONFIG_DIR);
            let cache_root = joined_windows_path(&user_root, USER_CACHE_DIR);
            reject_privileged_user_mode_root(profile, anchors, &data_root)?;
            reject_privileged_user_mode_root(profile, anchors, &config_root)?;
            reject_privileged_user_mode_root(profile, anchors, &cache_root)?;
            ProfileGovernedRoots {
                profile,
                immutable_binaries: joined_windows_path(
                    &joined_windows_path(
                        &joined_windows_path(
                            &joined_windows_path(&local_app_data, USER_PROGRAMS_DIR),
                            PRODUCT_DIR,
                        ),
                        component,
                    ),
                    version,
                ),
                durable_data: data_root,
                user_config: config_root,
                user_cache: cache_root,
            }
        }
        InstallationProfile::PortableDev => {
            let repository = required_anchor(anchors.repository_root.as_ref(), "repository_root")?;
            let Some(generation) = generation else {
                return Err(InstallationError::ProfileViolation(
                    "portable_dev resolves its immutable root by generation, which was not supplied"
                        .to_owned(),
                ));
            };
            text(generation, "generation")?;
            let state_root = joined_windows_path(&repository, PORTABLE_STATE_DIR);
            let config_root = joined_windows_path(&repository, ".eliot-dev\\config");
            let cache_root = joined_windows_path(&repository, ".eliot-dev\\cache");
            ProfileGovernedRoots {
                profile,
                immutable_binaries: joined_windows_path(
                    &joined_windows_path(&repository, PORTABLE_BINARIES_DIR),
                    generation,
                ),
                durable_data: state_root,
                user_config: config_root,
                user_cache: cache_root,
            }
        }
    };
    Ok(roots)
}

/// Refuses a `user_mode` root that would sit under the `%ProgramData%` contour.
fn reject_privileged_user_mode_root(
    profile: InstallationProfile,
    anchors: &ProfileRootAnchors,
    candidate: &str,
) -> Result<(), InstallationError> {
    let Some(program_data) = anchors.program_data.as_ref() else {
        return Ok(());
    };
    let program_data = WindowsPathIdentity::parse_root(program_data.as_str(), "program_data")?;
    let candidate = WindowsPathIdentity::parse_root(candidate, "user_mode_root")?;
    if program_data.contains(&candidate) {
        return Err(InstallationError::ProfileViolation(format!(
            "{profile:?} state may not be placed under the system_service ProgramData contour"
        )));
    }
    Ok(())
}
