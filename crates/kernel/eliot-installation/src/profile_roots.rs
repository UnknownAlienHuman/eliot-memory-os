use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use eliot_platform_windows::profile_supervision::{
    ProfileRootPaths, ProfileRootRequest, ProfileSelection, ProfileSelectionReceipt,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::runtime_root_contract::{InstallationProfile, RuntimeStateRoots};
use super::{
    InstallationError, ProfileGovernedRoots, RuntimeLaunchDescriptor, WindowsPathIdentity,
    joined_windows_path, phase_b_scm_selector, sha256_handle, text,
};

/// Builds the platform root request from the exact profile roots retained by a
/// validated runtime launch descriptor.
///
/// During Phase-A the platform receipt carries the fixed pending SCM selector
/// returned by the transaction's selector boundary; raw pending markers never
/// enter the platform request.
pub fn profile_root_request_for_launch(
    launch: &RuntimeLaunchDescriptor,
) -> Result<ProfileRootRequest, InstallationError> {
    launch.validate()?;
    let selection_digest = phase_b_scm_selector(&launch.authority_descriptor_digest)?;
    profile_root_request_for_binding(
        launch,
        selection_digest.as_str(),
        launch.authority_generation.value(),
    )
}

/// Builds the same root request using the exact committed Phase-B live
/// authority binding selected by the registry. This is used after restart,
/// when the immutable launch descriptor still contains its Phase-A selector.
pub fn profile_root_request_for_live_launch(
    launch: &RuntimeLaunchDescriptor,
    live_authority_descriptor_digest: &super::PlatformHandle,
    authority_generation: u64,
) -> Result<ProfileRootRequest, InstallationError> {
    launch.validate()?;
    sha256_handle(
        live_authority_descriptor_digest,
        "profile_root_request.live_authority_descriptor_digest",
    )?;
    if live_authority_descriptor_digest.as_str() == super::PHASE_B_PENDING_SCM_DIGEST
        || authority_generation == 0
    {
        return Err(InstallationError::IncompleteObservation(
            "live profile root selection requires a committed Phase-B authority digest and generation"
                .to_owned(),
        ));
    }
    profile_root_request_for_binding(
        launch,
        live_authority_descriptor_digest.as_str(),
        authority_generation,
    )
}

fn profile_root_request_for_binding(
    launch: &RuntimeLaunchDescriptor,
    authority_descriptor_sha256: &str,
    authority_generation: u64,
) -> Result<ProfileRootRequest, InstallationError> {
    let profile = match launch.profile {
        InstallationProfile::UserMode => ProfileSelection::UserMode,
        InstallationProfile::PortableDev => ProfileSelection::PortableDev,
        InstallationProfile::SystemService => {
            return Err(InstallationError::ProfileViolation(
                "profile root selection receipts are limited to UserMode and PortableDev"
                    .to_owned(),
            ));
        }
    };
    let roots = &launch.profile_governed_roots;
    let runtime = &launch.runtime_state_roots;
    let runtime_state_roots = vec![
        (
            "runtime_state_roots.profile_anchor_root".to_owned(),
            PathBuf::from(runtime.profile_anchor_root.as_str()),
        ),
        (
            "runtime_state_roots.installation_root".to_owned(),
            PathBuf::from(runtime.installation_root.as_str()),
        ),
        (
            "runtime_state_roots.host_state_root".to_owned(),
            PathBuf::from(runtime.host_state_root.as_str()),
        ),
        (
            "runtime_state_roots.kernel_ors_root".to_owned(),
            PathBuf::from(runtime.kernel_ors_root.as_str()),
        ),
        (
            "runtime_state_roots.kernel_work_root".to_owned(),
            PathBuf::from(runtime.kernel_work_root.as_str()),
        ),
        (
            "runtime_state_roots.store_data_root".to_owned(),
            PathBuf::from(runtime.store_data_root.as_str()),
        ),
        (
            "runtime_state_roots.store_work_root".to_owned(),
            PathBuf::from(runtime.store_work_root.as_str()),
        ),
        (
            "runtime_state_roots.store_temp_root".to_owned(),
            PathBuf::from(runtime.store_temp_root.as_str()),
        ),
        (
            "runtime_state_roots.watchdog_state_root".to_owned(),
            PathBuf::from(runtime.watchdog_state_root.as_str()),
        ),
    ];
    Ok(ProfileRootRequest {
        profile,
        installation_id: launch.installation_epoch.installation.as_str().to_owned(),
        installation_key: launch
            .profile_installation_key
            .as_ref()
            .map(|value| value.as_str().to_owned()),
        component: launch.profile_component.as_str().to_owned(),
        version: launch.profile_version.as_str().to_owned(),
        generation: launch.generation.as_str().to_owned(),
        authority_descriptor_path: PathBuf::from(launch.authority_descriptor_path.as_str()),
        authority_descriptor_sha256: authority_descriptor_sha256.to_owned(),
        authority_generation,
        roots: ProfileRootPaths {
            immutable_binaries: PathBuf::from(&roots.immutable_binaries),
            durable_data: PathBuf::from(&roots.durable_data),
            user_config: PathBuf::from(&roots.user_config),
            user_cache: PathBuf::from(&roots.user_cache),
            runtime_state_roots,
        },
        repository_root: launch
            .portable_root
            .as_ref()
            .map(|value| PathBuf::from(value.as_str())),
    })
}

/// Compares the retained root identity across the Phase-B pending-selector
/// transition. The current receipt must still carry every original root
/// object and owner binding; only a fixed pending SCM selector may transition
/// to a live descriptor SHA-256.
pub fn profile_selection_receipts_match_retained_roots(
    original: &ProfileSelectionReceipt,
    current: &ProfileSelectionReceipt,
) -> Result<bool, InstallationError> {
    validate_profile_selection_receipt_shape(original, "original")?;
    validate_profile_selection_receipt_shape(current, "current")?;
    let same_static_binding = original.profile == current.profile
        && original.installation_id == current.installation_id
        && original.installation_key == current.installation_key
        && original.component == current.component
        && original.version == current.version
        && original.generation == current.generation
        && eliot_platform_windows::windows_paths_equal(
            &original.authority_descriptor_path,
            &current.authority_descriptor_path,
        )
        && original.authority_generation == current.authority_generation
        && original.owner_sid == current.owner_sid;
    if !same_static_binding {
        return Ok(false);
    }
    let digest_matches = original.authority_descriptor_sha256
        == current.authority_descriptor_sha256
        || (original.authority_descriptor_sha256 == super::PHASE_B_PENDING_SCM_DIGEST
            && current.authority_descriptor_sha256 != super::PHASE_B_PENDING_SCM_DIGEST);
    if !digest_matches {
        return Ok(false);
    }
    for observation in &original.roots {
        let Some(current_observation) = current
            .roots
            .iter()
            .find(|candidate| candidate.role == observation.role)
        else {
            return Ok(false);
        };
        if observation.identity != current_observation.identity
            || !eliot_platform_windows::windows_paths_equal(
                &observation.canonical_path,
                &current_observation.canonical_path,
            )
        {
            return Ok(false);
        }
    }
    Ok(true)
}

fn validate_profile_selection_receipt_shape(
    receipt: &ProfileSelectionReceipt,
    label: &str,
) -> Result<(), InstallationError> {
    if !matches!(
        receipt.profile,
        ProfileSelection::UserMode | ProfileSelection::PortableDev
    ) {
        return Err(InstallationError::ProfileViolation(
            "retained profile selection must be UserMode or PortableDev".to_owned(),
        ));
    }
    for (value, field) in [
        (&receipt.installation_id, "installation_id"),
        (&receipt.component, "component"),
        (&receipt.version, "version"),
        (&receipt.generation, "generation"),
        (&receipt.owner_sid, "owner_sid"),
    ] {
        text(value, &format!("profile_selection_receipt.{label}.{field}"))?;
    }
    if !receipt.owner_sid.starts_with("S-")
        || receipt.session_id == 0
        || receipt.authority_generation == 0
    {
        return Err(InstallationError::InvalidField {
            field: format!("profile_selection_receipt.{label}"),
            reason: "owner, session, generation, and descriptor path must be live values"
                .to_owned(),
        });
    }
    WindowsPathIdentity::parse_root(
        &receipt.authority_descriptor_path.to_string_lossy(),
        &format!("profile_selection_receipt.{label}.authority_descriptor_path"),
    )?;
    let digest =
        super::PlatformHandle::new(&receipt.authority_descriptor_sha256).map_err(|error| {
            InstallationError::InvalidField {
                field: format!("profile_selection_receipt.{label}.authority_descriptor_sha256"),
                reason: error.to_string(),
            }
        })?;
    sha256_handle(
        &digest,
        &format!("profile_selection_receipt.{label}.authority_descriptor_sha256"),
    )?;

    const ROOT_ROLES: [&str; 13] = [
        "immutable_binaries",
        "durable_data",
        "user_config",
        "user_cache",
        "runtime_state_roots.profile_anchor_root",
        "runtime_state_roots.installation_root",
        "runtime_state_roots.host_state_root",
        "runtime_state_roots.kernel_ors_root",
        "runtime_state_roots.kernel_work_root",
        "runtime_state_roots.store_data_root",
        "runtime_state_roots.store_work_root",
        "runtime_state_roots.store_temp_root",
        "runtime_state_roots.watchdog_state_root",
    ];
    if receipt.roots.len() != ROOT_ROLES.len() {
        return Err(InstallationError::IncompleteObservation(format!(
            "profile-selection receipt {label} does not contain all 13 retained root roles"
        )));
    }
    let mut roles = BTreeSet::new();
    let mut identities = BTreeSet::new();
    for observation in &receipt.roots {
        if !ROOT_ROLES.contains(&observation.role.as_str())
            || !roles.insert(observation.role.as_str())
            || observation.identity.volume_serial_number == 0
            || observation.identity.file_index == 0
            || !identities.insert((
                observation.identity.volume_serial_number,
                observation.identity.file_index,
            ))
        {
            return Err(InstallationError::IncompleteObservation(format!(
                "profile-selection receipt {label} contains an invalid or duplicate root observation"
            )));
        }
        WindowsPathIdentity::parse_root(
            &observation.canonical_path.to_string_lossy(),
            &format!("profile_selection_receipt.{label}.{}", observation.role),
        )?;
    }
    if roles.len() != ROOT_ROLES.len() {
        return Err(InstallationError::IncompleteObservation(format!(
            "profile-selection receipt {label} omits a retained root role"
        )));
    }
    if receipt.authority_descriptor_sha256 == super::PHASE_B_PENDING_SCM_DIGEST
        && receipt.profile != ProfileSelection::UserMode
    {
        return Err(InstallationError::ProfileViolation(
            "the pending Phase-B selector is only valid for the UserMode authority transition"
                .to_owned(),
        ));
    }
    Ok(())
}

/// Breaking revision of the persisted four-root installation binding.
///
/// Version 1 is the first versioned binding: profile plus immutable, durable,
/// user-configuration and user-cache roots with the digest-bound runtime
/// topology. Older unversioned projections require explicit migration and are
/// never defaulted into this shape.
pub const INSTALLATION_ROOT_BINDING_VERSION: u32 = 1;

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

    /// Validates one retained live profile selection against this exact
    /// descriptor-bound four-root and runtime-root set.
    ///
    /// The observations carry the original file-object identities. This
    /// method checks their role and path bindings without deriving or
    /// substituting identities from paths.
    pub(crate) fn validate_profile_selection_receipt(
        &self,
        launch: &RuntimeLaunchDescriptor,
        receipt: &ProfileSelectionReceipt,
    ) -> Result<(), InstallationError> {
        self.validate(launch.profile)?;
        validate_profile_selection_receipt_shape(receipt, "binding")?;
        let expected_profile = match launch.profile {
            InstallationProfile::UserMode => ProfileSelection::UserMode,
            InstallationProfile::PortableDev => ProfileSelection::PortableDev,
            InstallationProfile::SystemService => {
                return Err(InstallationError::ProfileViolation(
                    "profile-selection receipts are limited to UserMode and PortableDev".to_owned(),
                ));
            }
        };
        let expected_installation_key = launch
            .profile_installation_key
            .as_ref()
            .map(super::PlatformHandle::as_str);
        let authority_descriptor_digest =
            super::phase_b_scm_selector(&launch.authority_descriptor_digest)?;
        if receipt.profile != expected_profile
            || receipt.installation_id != launch.installation_epoch.installation.as_str()
            || receipt.installation_key.as_deref() != expected_installation_key
            || receipt.component != launch.profile_component.as_str()
            || receipt.version != launch.profile_version.as_str()
            || receipt.generation != launch.generation.as_str()
            || !eliot_platform_windows::windows_paths_equal(
                &receipt.authority_descriptor_path,
                Path::new(launch.authority_descriptor_path.as_str()),
            )
            || receipt.authority_descriptor_sha256 != authority_descriptor_digest.as_str()
            || receipt.authority_generation != launch.authority_generation.value()
            || !receipt.owner_sid.starts_with("S-")
            || receipt.session_id == 0
        {
            return Err(InstallationError::IdentityConflict);
        }
        sha256_handle(
            &authority_descriptor_digest,
            "profile_selection_receipt.authority_descriptor_sha256",
        )?;

        let runtime = &launch.runtime_state_roots;
        let expected_roots = [
            ("immutable_binaries", self.immutable_binaries.as_str()),
            ("durable_data", self.durable_data.as_str()),
            ("user_config", self.user_config.as_str()),
            ("user_cache", self.user_cache.as_str()),
            (
                "runtime_state_roots.profile_anchor_root",
                runtime.profile_anchor_root.as_str(),
            ),
            (
                "runtime_state_roots.installation_root",
                runtime.installation_root.as_str(),
            ),
            (
                "runtime_state_roots.host_state_root",
                runtime.host_state_root.as_str(),
            ),
            (
                "runtime_state_roots.kernel_ors_root",
                runtime.kernel_ors_root.as_str(),
            ),
            (
                "runtime_state_roots.kernel_work_root",
                runtime.kernel_work_root.as_str(),
            ),
            (
                "runtime_state_roots.store_data_root",
                runtime.store_data_root.as_str(),
            ),
            (
                "runtime_state_roots.store_work_root",
                runtime.store_work_root.as_str(),
            ),
            (
                "runtime_state_roots.store_temp_root",
                runtime.store_temp_root.as_str(),
            ),
            (
                "runtime_state_roots.watchdog_state_root",
                runtime.watchdog_state_root.as_str(),
            ),
        ];
        if receipt.roots.len() != expected_roots.len() {
            return Err(InstallationError::IncompleteObservation(
                "profile-selection receipt does not contain the complete four-root and runtime-root set"
                    .to_owned(),
            ));
        }
        let mut observed_roles = BTreeSet::new();
        for observation in &receipt.roots {
            let Some((_, expected_path)) = expected_roots
                .iter()
                .find(|(role, _)| *role == observation.role)
            else {
                return Err(InstallationError::ProfileViolation(format!(
                    "profile-selection receipt contains unknown root role {}",
                    observation.role
                )));
            };
            if !observed_roles.insert(observation.role.as_str())
                || observation.identity.volume_serial_number == 0
                || observation.identity.file_index == 0
                || !eliot_platform_windows::windows_paths_equal(
                    &observation.canonical_path,
                    Path::new(expected_path),
                )
            {
                return Err(InstallationError::IdentityConflict);
            }
            WindowsPathIdentity::parse_root(
                &observation.canonical_path.to_string_lossy(),
                &format!("profile_selection_receipt.{}", observation.role),
            )?;
        }
        if observed_roles.len() != expected_roots.len() {
            return Err(InstallationError::IncompleteObservation(
                "profile-selection receipt omits a descriptor-bound root role".to_owned(),
            ));
        }
        Ok(())
    }

    /// Admits an additional mutable output against this selected profile's
    /// immutable binaries binding.
    ///
    /// Callers use this for outputs that are not represented by an installation
    /// effect, such as a diagnostic file or transaction-store location. The
    /// binding is validated against its retained runtime profile before the
    /// existing profile-governed write rule is applied.
    pub fn admits_write_target(&self, target: &str) -> Result<(), InstallationError> {
        let profile = self.runtime_state_roots.profile;
        self.validate(profile)?;
        ProfileGovernedRoots {
            profile,
            immutable_binaries: self.immutable_binaries.clone(),
            durable_data: self.durable_data.clone(),
            user_config: self.user_config.clone(),
            user_cache: self.user_cache.clone(),
        }
        .admits_write_target(target)
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
    /// `system_service` and `user_mode` retain the I3.1 durable-data root as
    /// their top-level state contour and refine it into per-installation
    /// runtime directories. `UserMode`'s data, config, and cache roles are
    /// checked against the exact sibling layout derived from its retained
    /// `LocalAppData` anchor. `portable_dev` is explicitly disposable, so
    /// profile agreement and root separation above are its complete join.
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
        let installation = WindowsPathIdentity::parse_root(
            self.runtime_state_roots.installation_root.as_str(),
            "runtime_state_roots.installation_root",
        )?;
        let user_config = WindowsPathIdentity::parse_root(&self.user_config, "user_config")?;
        let user_cache = WindowsPathIdentity::parse_root(&self.user_cache, "user_cache")?;
        let installation_is_below_durable =
            installation != durable && durable.contains(&installation);
        match profile {
            InstallationProfile::SystemService => {
                let expected_durable = WindowsPathIdentity::parse_root(
                    &joined_windows_path(
                        self.runtime_state_roots.profile_anchor_root.as_str(),
                        "Eliot",
                    ),
                    "durable_data",
                )?;
                if durable != expected_durable
                    || durable != profile_root
                    || !installation_is_below_durable
                {
                    return Err(InstallationError::ProfileViolation(
                        "SystemService durable data must equal its I3.1 root and contain the runtime installation root strictly"
                            .to_owned(),
                    ));
                }
            }
            InstallationProfile::UserMode => {
                let user_root = joined_windows_path(
                    self.runtime_state_roots.profile_anchor_root.as_str(),
                    "Eliot",
                );
                let expected_data = WindowsPathIdentity::parse_root(
                    &joined_windows_path(&user_root, "data"),
                    "durable_data",
                )?;
                let expected_config = WindowsPathIdentity::parse_root(
                    &joined_windows_path(&user_root, "config"),
                    "user_config",
                )?;
                let expected_cache = WindowsPathIdentity::parse_root(
                    &joined_windows_path(&user_root, "cache"),
                    "user_cache",
                )?;
                if durable != expected_data
                    || durable != profile_root
                    || user_config != expected_config
                    || user_cache != expected_cache
                    || !installation_is_below_durable
                {
                    return Err(InstallationError::ProfileViolation(
                        "UserMode durable data must equal its I3.1 root, preserve the config/cache siblings, and contain the runtime installation root strictly"
                            .to_owned(),
                    ));
                }
            }
            InstallationProfile::PortableDev => {
                let anchor = WindowsPathIdentity::parse_root(
                    self.runtime_state_roots.profile_anchor_root.as_str(),
                    "runtime_state_roots.profile_anchor_root",
                )?;
                let expected_data = WindowsPathIdentity::parse_root(
                    &joined_windows_path(
                        &joined_windows_path(
                            self.runtime_state_roots.profile_anchor_root.as_str(),
                            ".eliot-dev",
                        ),
                        "state",
                    ),
                    "durable_data",
                )?;
                let expected_config = WindowsPathIdentity::parse_root(
                    &joined_windows_path(
                        self.runtime_state_roots.profile_anchor_root.as_str(),
                        ".eliot-dev\\config",
                    ),
                    "user_config",
                )?;
                let expected_cache = WindowsPathIdentity::parse_root(
                    &joined_windows_path(
                        self.runtime_state_roots.profile_anchor_root.as_str(),
                        ".eliot-dev\\cache",
                    ),
                    "user_cache",
                )?;
                if durable != expected_data
                    || durable != profile_root
                    || installation != durable
                    || user_config != expected_config
                    || user_cache != expected_cache
                    || !anchor.contains(&durable)
                    || anchor == durable
                {
                    return Err(InstallationError::ProfileViolation(
                        "PortableDev must retain its repository anchor, state installation root, and exact config/cache siblings"
                            .to_owned(),
                    ));
                }
            }
        }
        Ok(())
    }
}
