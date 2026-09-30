//! Profile-specific launch composition and runtime proof of absence of
//! service-only authority (I3.1, I1.4).
//!
//! Implementation item 4 of #1771 requires that a profile own the launch
//! adapter it actually needs: `system_service` reuses the existing SCM
//! primitives, `user_mode` needs a current-user launcher/Task Scheduler, and
//! `portable_dev` is repository-local and disposable. This module is that
//! composition boundary. It is deliberately *not* a second authority state
//! machine and *not* a second root registry: it consumes the four I3.1 roots
//! and the digest-bound runtime topology that
//! [`super::ProfileSelectionResolution`] already resolved, and it asks the
//! existing Windows adapter to retain and re-verify those roots.
//!
//! The composition is where `UserMode` proves, at runtime rather than by table
//! lookup, that it depends on no SCM service, no administrative right and no
//! `ProgramData` anchor. The proof is
//! [`super::prove_no_service_profile_authority_dependency`] plus the adapter's
//! own retained-root validation: the adapter opens a live no-follow handle to
//! the current user's `%LocalAppData%` contour and to every one of the four
//! I3.1 role roots plus every runtime root, proves the observed owner SID is
//! the current interactive user rather than a service account, and proves each
//! path is exactly the I3.1 `user_mode` row beneath that contour. A root that
//! would require SCM, administrator rights or the `ProgramData` contour
//! therefore fails *before* any external object is created, which is a refusal
//! rather than a downgrade.
//!
//! What this module deliberately does not do is register anything by itself.
//! Registration, bounded launch, result receipts and cleanup stay in the
//! Windows adapter
//! (`eliot_platform_windows::profile_supervision::{register_current_user_task,
//! run_current_user_task, remove_current_user_task, inspect_current_user_task}`)
//! and in the Host supervisor that consumes the adapter's private switch. This
//! module only composes the exact request those existing owners require and
//! refuses, by name, when a required adapter is not admitted.

use std::path::PathBuf;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use eliot_platform_windows::profile_supervision::{
    ProfileRootPaths, ProfileRootRequest, ProfileSelection, ProfileSelectionReceipt,
};

use super::profile_governed_roots::ProfileGovernedRoots;
use super::runtime_root_contract::{InstallationProfile, RuntimeStateRoots};
use super::{InstallationError, InstallationRoots, ProfileSelectionResolution};

/// The supervision adapter a selected profile composes for its Host launch.
///
/// I3.1 names exactly one supervision per profile. This enum is the typed
/// projection of that column at the composition boundary; it grants no
/// supervision authority and starts nothing.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(tag = "adapter", rename_all = "snake_case", deny_unknown_fields)]
pub enum ProfileLaunchComposition {
    /// `system_service`: reuse the existing SCM registration/start effects.
    ///
    /// I3.1 gives `system_service` SCM demand-start supervision, and the
    /// installer already plans `RegisterService`/`StartService` effects for it.
    /// This composition therefore names the existing SCM adapter rather than
    /// inventing a parallel one.
    ScmServiceRegistration,
    /// `user_mode`: current-user launcher plus Task Scheduler, in the current
    /// user's interactive session, with no service-admin rights.
    CurrentUserLauncherTaskScheduler {
        /// Exact provider-neutral root request the admitted adapter re-proves
        /// against live current-user OS objects before it registers anything.
        ///
        /// The four I3.1 roles and every digest-bound runtime root are carried
        /// separately and by name, so the adapter proves the distinct cache
        /// root rather than a single user root.
        ///
        /// Boxed because this request and the receipt below are the two
        /// multi-root proof structures, and this variant is the only one that
        /// carries either. Boxing them keeps the enum's size set by the
        /// discriminant rather than by this single variant, so the two
        /// profiles that carry no payload do not pay for the one that does.
        /// `Box` is transparent to `Serialize`, `Deserialize` and
        /// `JsonSchema`, so the emitted proof JSON is unchanged.
        roots: Box<ProfileRootRequest>,
        /// Live current-user root selection proof retained for this request,
        /// including the observed owner SID and interactive session that bind
        /// the task to this account rather than to a service account.
        selection: Box<ProfileSelectionReceipt>,
    },
    /// `portable_dev`: repository-local disposable supervision, retained under
    /// the caller-named repository contour.
    RepositoryLocalDisposableSupervision,
}

/// Composes the launch adapter for one already-resolved profile selection.
///
/// This is the read-only composition entry point a plan or status response
/// uses, and it is also the boundary at which a `user_mode` selection proves
/// absence of SCM, administrative and `ProgramData` dependencies: the proof is
/// the adapter's retained current-user root validation, not a table lookup.
/// It creates nothing, registers nothing, and mutates nothing.
///
/// # Errors
///
/// Returns [`InstallationError::ProfileViolation`] when the resolved selection
/// and its retained four-root binding disagree, or when the selection is
/// `user_mode` and the adapter's retained current-user root proof does not
/// establish the exact I3.1 layout beneath the OS-resolved `%LocalAppData%`
/// contour owned by the live current interactive user.
pub fn compose_profile_launch(
    resolution: &ProfileSelectionResolution,
) -> Result<ProfileLaunchComposition, InstallationError> {
    let profile = resolution.governance.profile;
    let roots: &InstallationRoots = &resolution.roots;
    if roots.runtime_state_roots.profile != profile {
        return Err(InstallationError::ProfileViolation(
            "resolved launch composition requires the selection's own profile roots".to_owned(),
        ));
    }
    let governed = ProfileGovernedRoots {
        profile,
        immutable_binaries: resolution.governance.roots.immutable_binaries.clone(),
        durable_data: resolution.governance.roots.durable_data.clone(),
        user_config: resolution.governance.roots.user_config.clone(),
        user_cache: resolution.governance.roots.user_cache.clone(),
    };
    if governed.immutable_binaries != roots.immutable_binaries
        || governed.durable_data != roots.durable_data
        || governed.user_config != roots.user_config
        || governed.user_cache != roots.user_cache
    {
        return Err(InstallationError::ProfileViolation(
            "resolved launch composition roots disagree with the recorded four-root binding"
                .to_owned(),
        ));
    }
    match profile {
        // I3.1: `system_service` supervision is SCM demand-start, which the
        // installer already composes as `RegisterService`/`StartService`
        // effects. Nothing here adds a second service path.
        InstallationProfile::SystemService => Ok(ProfileLaunchComposition::ScmServiceRegistration),
        // I3.1: `portable_dev` is repository-local and explicitly disposable.
        // Its supervision is the retained repository contour under Host Job
        // supervision, not a registration, so no external object is named.
        InstallationProfile::PortableDev => {
            Ok(ProfileLaunchComposition::RepositoryLocalDisposableSupervision)
        }
        InstallationProfile::UserMode => {
            let root_request = user_mode_root_request(&governed, &roots.runtime_state_roots)?;
            // The runtime proof. The adapter retains the OS-resolved
            // current-user `%LocalAppData%` contour and every one of the four
            // I3.1 role roots plus every digest-bound runtime root as live
            // no-follow objects, proves the observed owner is the current
            // interactive user rather than a service account, and proves every
            // path is exactly the I3.1 `user_mode` row. A root that would need
            // SCM, administrator rights or `ProgramData` fails here.
            let selection =
                eliot_platform_windows::profile_supervision::validate_profile_roots(&root_request)
                    .map_err(|error| {
                        InstallationError::ProfileViolation(format!(
                            "user_mode launch composition could not prove current-user root authority: {error}"
                        ))
                    })?;
            Ok(ProfileLaunchComposition::CurrentUserLauncherTaskScheduler {
                roots: Box::new(root_request),
                selection: Box::new(selection),
            })
        }
    }
}

/// Projects the installation-owned four-root binding plus the digest-bound
/// runtime topology into the adapter's provider-neutral root request.
///
/// The installation identity, component, version and generation come from the
/// retained runtime root itself rather than from an ambient environment
/// variable or a caller-supplied string: the installation key is the exact
/// validated key leaf of the retained installation root, and the generation is
/// the immutable-root leaf the profile layout pins.
fn user_mode_root_request(
    governed: &ProfileGovernedRoots,
    runtime_state_roots: &RuntimeStateRoots,
) -> Result<ProfileRootRequest, InstallationError> {
    let installation_key = runtime_state_roots
        .installation_root
        .as_str()
        .rsplit(['\\', '/'])
        .next()
        .filter(|key| super::valid_installation_key(key))
        .ok_or_else(|| {
            InstallationError::ProfileViolation(
                "user_mode installation root does not end in its exact installation key".to_owned(),
            )
        })?
        .to_owned();
    let immutable =
        super::WindowsPathIdentity::parse_root(&governed.immutable_binaries, "immutable_binaries")?;
    // I3.1 pins both the Windows profiles' immutable root to
    // `<anchor>\Programs\Eliot\<component>\<version>` for `user_mode`, so the
    // component and version leaves of the retained immutable root are the
    // exact identities the task must carry. Both are read from the retained
    // root itself, never from an ambient value.
    let component = immutable
        .components
        .get(immutable.components.len().saturating_sub(2))
        .cloned()
        .ok_or_else(|| {
            InstallationError::ProfileViolation(
                "user_mode immutable root does not carry its component leaf".to_owned(),
            )
        })?;
    let version = immutable.components.last().cloned().ok_or_else(|| {
        InstallationError::ProfileViolation(
            "user_mode immutable root does not carry its version leaf".to_owned(),
        )
    })?;
    Ok(ProfileRootRequest {
        profile: ProfileSelection::UserMode,
        installation_id: runtime_state_roots.profile_anchor_root.as_str().to_owned(),
        installation_key: Some(installation_key),
        component,
        version: version.clone(),
        // The task registration marker is per generation, and `portable_dev`
        // versions its immutable root by generation rather than by release
        // version. `user_mode` has no installation key and its immutable root
        // is versioned, so the selected generation is carried by the retained
        // durable-data contour leaf the installation owns.
        generation: runtime_state_roots
            .installation_root
            .as_str()
            .rsplit(['\\', '/'])
            .next()
            .unwrap_or(version.as_str())
            .to_owned(),
        // The task action names one exact authority descriptor beside the
        // approved Host image. Phase A publishes no authority bytes, so the
        // installation owner composes the launch against the recorded
        // descriptor path and a digest derived from the exact immutable
        // identity rather than from ambient state; the adapter re-pins it
        // against the retained object before it registers anything.
        authority_descriptor_path: PathBuf::from(governed.immutable_binaries.as_str())
            .join("authority.json"),
        authority_descriptor_sha256: super::sha256_hex(
            format!(
                "user-mode-authority-descriptor:v1:{}:{}",
                runtime_state_roots.roots_digest.as_str(),
                governed.immutable_binaries
            )
            .as_bytes(),
        ),
        authority_generation: 1,
        roots: profile_root_paths(governed, runtime_state_roots),
        repository_root: None,
    })
}

/// Carries the four I3.1 role roots and every digest-bound runtime root, by
/// role name, into the adapter's provider-neutral projection.
fn profile_root_paths(
    governed: &ProfileGovernedRoots,
    runtime_state_roots: &RuntimeStateRoots,
) -> ProfileRootPaths {
    let runtime = runtime_state_roots;
    let runtime_state_roots = [
        (
            "runtime_state_roots.profile_anchor_root",
            &runtime.profile_anchor_root,
        ),
        (
            "runtime_state_roots.installation_root",
            &runtime.installation_root,
        ),
        (
            "runtime_state_roots.host_state_root",
            &runtime.host_state_root,
        ),
        (
            "runtime_state_roots.kernel_ors_root",
            &runtime.kernel_ors_root,
        ),
        (
            "runtime_state_roots.kernel_work_root",
            &runtime.kernel_work_root,
        ),
        (
            "runtime_state_roots.store_data_root",
            &runtime.store_data_root,
        ),
        (
            "runtime_state_roots.store_work_root",
            &runtime.store_work_root,
        ),
        (
            "runtime_state_roots.store_temp_root",
            &runtime.store_temp_root,
        ),
        (
            "runtime_state_roots.watchdog_state_root",
            &runtime.watchdog_state_root,
        ),
    ]
    .into_iter()
    .map(|(role, path)| (role.to_owned(), PathBuf::from(path.as_str())))
    .collect();
    ProfileRootPaths {
        immutable_binaries: PathBuf::from(governed.immutable_binaries.as_str()),
        durable_data: PathBuf::from(governed.durable_data.as_str()),
        user_config: PathBuf::from(governed.user_config.as_str()),
        user_cache: PathBuf::from(governed.user_cache.as_str()),
        runtime_state_roots,
    }
}
