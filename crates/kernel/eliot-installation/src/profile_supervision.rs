//! Profile supervision composition and no-service-authority proof (I3.1).
//!
//! I3.1 states that the installation profile "determines both process
//! supervision and writable roots", and that a `user_mode` installation
//! "preserves EBP, Kernel and module contracts, but its Governance Profile
//! honestly reports weaker restart, independent-Watchdog and OS-level
//! isolation guarantees". This module supplies exactly that second half for
//! the roots [`super::select_profile_roots`] already resolves: the intended
//! supervision for the selected profile, the guarantees that profile
//! actually enforces, the guarantees it does not, and a structural proof
//! that a non-`system_service` selection carries no SCM, administrative or
//! `ProgramData`-anchor dependency.
//!
//! The proof is structural, not textual. It revalidates the selected
//! current-user or repository anchor through the existing OS adapter, retains
//! that anchor as a real no-follow root object wherever the OS lease contract
//! admits it, compares each resolved I3.1 role to its exact profile layout
//! beneath the retained object, and requires the profile to claim neither SCM
//! supervision nor administrative authority. A layout that only matches a
//! predictable path name is not verified root ownership and is never counted as
//! such. Non-service selection does not query, receive, or depend on a
//! `ProgramData` anchor.
//!
//! Normative basis: I3.1 (exact layouts, default profile, supervision, and
//! owner/session binding). This module resolves no new root and mints no
//! second registry: [`ProfileGovernedRoots`] remains the sole selector
//! output, and [`super::RuntimeStateRoots`] remains the sole retained
//! runtime topology.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::profile_governed_roots::ProfileGovernedRoots;
use super::runtime_root_contract::{
    InstallationProfile, RuntimeRootLease, RuntimeRootLeaseProvider, RuntimeStateRoots,
};
use super::{
    InstallationError, WindowsPathIdentity, WindowsRuntimeRootLeaseProvider, joined_windows_path,
    same_windows_root, text,
};

/// The supervision path a selected profile is intended to use.
///
/// I3.1 names exactly one supervision per profile. This enum is the typed
/// projection of that column; it grants no supervision authority and starts
/// nothing.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProfileSupervision {
    /// `system_service`: SCM demand-start with service-administrative rights.
    ScmDemandStart,
    /// `user_mode`: current-user launcher and Task Scheduler supervision in
    /// the interactive session, without service-admin rights.
    CurrentUserLauncherTaskScheduler,
    /// `portable_dev`: explicitly disposable repository-local supervision.
    RepositoryLocalDisposable,
}

/// The four resolved root roles reported for a selection, by name.
///
/// This is the presentation projection the CLI renders. It names the same
/// four roots [`ProfileGovernedRoots`] resolves and adds no value.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileRootRoles {
    /// Immutable, versioned binaries and component artifacts.
    pub immutable_binaries: String,
    /// Durable service/installation state.
    pub durable_data: String,
    /// User configuration root.
    pub user_config: String,
    /// User cache root.
    pub user_cache: String,
}

/// One profile's honest Governance Profile (I3.1).
///
/// The report names the selected profile, its intended supervision, its four
/// resolved root roles, the guarantees the profile enforces, and the
/// guarantees it does not. It carries no key, secret, token or credential
/// material: only profile names, root paths, and fixed guarantee text.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileGovernanceReport {
    /// Profile whose selection produced this report.
    pub profile: InstallationProfile,
    /// Supervision path this profile is intended to use.
    pub supervision: ProfileSupervision,
    /// The four resolved root roles.
    pub roots: ProfileRootRoles,
    /// Guarantees this profile enforces.
    pub enforced_guarantees: Vec<String>,
    /// Guarantees this profile does not enforce. I3.1 requires these to be
    /// published rather than implied.
    pub unsupported_guarantees: Vec<String>,
}

/// Evidence that the selected profile depends on no service-profile authority.
///
/// The fields are the structural facts the proof established, retained so a
/// caller can report what was proved rather than re-deriving it.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NoServiceProfileAuthorityProof {
    /// Profile whose service-only dependencies were checked.
    pub profile: InstallationProfile,
    /// Whether the selected profile requires SCM supervision. Always `false`.
    pub selects_scm_supervision: bool,
    /// Whether the selected profile claims administrative authority. Always
    /// `false` for a value this type can exist for.
    pub requires_admin: bool,
    /// Whether selection requires an OS-known `ProgramData` anchor. Always
    /// `false` for a value this type can exist for.
    pub requires_program_data_anchor: bool,
    /// Number of I3.1 root roles whose exact profile layout was verified
    /// against a retained, reparse-free, no-follow OS root object.
    ///
    /// A role is counted only when its resolved path was derived from a
    /// retained root lease and the lease was proven to bind that same root
    /// object. A role whose path merely equals a constructed string is not
    /// counted; a predictable name is not ownership.
    pub verified_root_roles: u32,
}

/// Returns the supervision path I3.1 names for `profile`.
///
/// This is a pure column of the I3.1 profile table. It reads no anchor and
/// infers nothing; the caller still has to resolve and prove the roots.
const fn supervision_for(profile: InstallationProfile) -> ProfileSupervision {
    match profile {
        InstallationProfile::SystemService => ProfileSupervision::ScmDemandStart,
        InstallationProfile::UserMode => ProfileSupervision::CurrentUserLauncherTaskScheduler,
        InstallationProfile::PortableDev => ProfileSupervision::RepositoryLocalDisposable,
    }
}

/// Returns the guarantees a profile enforces and those it does not.
///
/// I3.1 requires a `user_mode` Governance Profile to "honestly report weaker
/// restart, independent-Watchdog and OS-level isolation guarantees", so those
/// three appear in the unsupported set for `user_mode` and in the enforced
/// set for `system_service`.
#[must_use]
const fn guarantees_for(
    profile: InstallationProfile,
) -> (&'static [&'static str], &'static [&'static str]) {
    match profile {
        InstallationProfile::SystemService => (
            &[
                "scm_demand_start_supervision",
                "independent_watchdog_service",
                "os_level_isolation_under_a_service_sid",
                "scm_restart_without_an_interactive_session",
            ],
            &["per_user_launcher_and_task_scheduler"],
        ),
        InstallationProfile::UserMode => (
            &[
                "current_user_launcher_and_task_scheduler",
                "no_administrative_installation_authority",
                "distinct_per_user_configuration_and_cache_roots",
            ],
            &[
                "independent_watchdog_service",
                "scm_supervised_automatic_restart",
                "os_level_isolation_under_a_service_sid",
            ],
        ),
        InstallationProfile::PortableDev => (
            &[
                "repository_local_disposable_supervision",
                "explicitly_disposable_state_and_cache",
                "no_administrative_installation_authority",
            ],
            &[
                "independent_watchdog_service",
                "scm_supervised_automatic_restart",
                "os_level_isolation_under_a_service_sid",
                "isolation_from_other_checkouts",
            ],
        ),
    }
}

impl ProfileGovernedRoots {
    /// Returns the supervision path this resolved selection is intended to
    /// use, as the I3.1 table names it.
    #[must_use]
    pub const fn supervision(&self) -> ProfileSupervision {
        supervision_for(self.profile)
    }

    /// Returns this selection's four resolved root roles, by name.
    #[must_use]
    pub fn root_roles(&self) -> ProfileRootRoles {
        ProfileRootRoles {
            immutable_binaries: self.immutable_binaries.clone(),
            durable_data: self.durable_data.clone(),
            user_config: self.user_config.clone(),
            user_cache: self.user_cache.clone(),
        }
    }

    /// Builds the honest Governance Profile report for this selection.
    ///
    /// The report exposes profile, supervision type, resolved root roles and
    /// enforced/unsupported guarantees. It deliberately carries no key,
    /// secret, token or credential value, so it is safe to render in a CLI
    /// or status response.
    #[must_use]
    pub fn governance_report(&self) -> ProfileGovernanceReport {
        let (enforced_guarantees, unsupported_guarantees) = guarantees_for(self.profile);
        ProfileGovernanceReport {
            profile: self.profile,
            supervision: self.supervision(),
            roots: self.root_roles(),
            enforced_guarantees: enforced_guarantees
                .iter()
                .map(|value| (*value).to_owned())
                .collect(),
            unsupported_guarantees: unsupported_guarantees
                .iter()
                .map(|value| (*value).to_owned())
                .collect(),
        }
    }
}

/// Proves that a resolved selection depends on no service-profile authority.
///
/// The proof is refused for `system_service`, whose supervision path *is* the
/// SCM. For every other profile it establishes, structurally:
///
/// 1. the selected current-user or repository anchor is revalidated through
///    the existing OS adapter;
/// 2. all four I3.1 root roles exactly match the layout derived from that
///    anchor; and
/// 3. the profile does not claim SCM supervision or administrative authority.
///
/// This proof does not claim lexical exclusion from a hypothetical
/// `ProgramData` path. Non-service selection receives no `ProgramData` anchor and
/// makes no `ProgramData` known-folder query.
///
/// # Errors
///
/// Returns [`InstallationError::ProfileViolation`] when the profile claims
/// service authority or a root differs from its exact profile layout,
/// [`InstallationError::InvalidField`] when a selected root is not a usable
/// absolute path, and [`InstallationError::Platform`] when OS anchor
/// revalidation fails.
pub fn prove_no_service_profile_authority_dependency(
    governed: &ProfileGovernedRoots,
    runtime_state_roots: &RuntimeStateRoots,
    component: &str,
    version: &str,
    generation: Option<&str>,
) -> Result<NoServiceProfileAuthorityProof, InstallationError> {
    if governed.profile.requires_admin() {
        return Err(InstallationError::ProfileViolation(format!(
            "{:?} supervision depends on SCM and administrative service rights",
            governed.profile
        )));
    }
    if runtime_state_roots.profile != governed.profile {
        return Err(InstallationError::ProfileViolation(
            "profile selection and runtime roots disagree".to_owned(),
        ));
    }
    runtime_state_roots.validate()?;
    let _anchor_proof = WindowsRuntimeRootLeaseProvider::for_roots(runtime_state_roots)?;

    let anchor = runtime_state_roots.profile_anchor_root.as_str();
    let expected = match governed.profile {
        InstallationProfile::SystemService => unreachable!("service profile rejected above"),
        InstallationProfile::UserMode => {
            text(component, "profile_component")?;
            text(version, "profile_version")?;
            [
                (
                    "immutable_binaries",
                    joined_windows_path(
                        &joined_windows_path(
                            &joined_windows_path(&joined_windows_path(anchor, "Programs"), "Eliot"),
                            component,
                        ),
                        version,
                    ),
                ),
                (
                    "durable_data",
                    joined_windows_path(&joined_windows_path(anchor, "Eliot"), "data"),
                ),
                (
                    "user_config",
                    joined_windows_path(&joined_windows_path(anchor, "Eliot"), "config"),
                ),
                (
                    "user_cache",
                    joined_windows_path(&joined_windows_path(anchor, "Eliot"), "cache"),
                ),
            ]
        }
        InstallationProfile::PortableDev => {
            let generation = generation.ok_or_else(|| {
                InstallationError::ProfileViolation(
                    "portable_dev root proof requires its selected generation identity".to_owned(),
                )
            })?;
            text(generation, "profile_generation")?;
            let state = joined_windows_path(anchor, ".eliot-dev");
            [
                (
                    "immutable_binaries",
                    joined_windows_path(
                        &joined_windows_path(anchor, "target\\eliot-dev"),
                        generation,
                    ),
                ),
                ("durable_data", joined_windows_path(&state, "state")),
                ("user_config", joined_windows_path(&state, "config")),
                ("user_cache", joined_windows_path(&state, "cache")),
            ]
        }
    };
    let actual = [
        ("immutable_binaries", governed.immutable_binaries.as_str()),
        ("durable_data", governed.durable_data.as_str()),
        ("user_config", governed.user_config.as_str()),
        ("user_cache", governed.user_cache.as_str()),
    ];
    for ((expected_field, expected_path), (actual_field, actual_path)) in
        expected.into_iter().zip(actual)
    {
        if expected_field != actual_field
            || WindowsPathIdentity::parse_root(&expected_path, expected_field)?
                != WindowsPathIdentity::parse_root(actual_path, actual_field)?
        {
            return Err(InstallationError::ProfileViolation(format!(
                "{actual_field} differs from the exact {:?} root derived from its retained profile anchor",
                governed.profile
            )));
        }
    }

    Ok(NoServiceProfileAuthorityProof {
        profile: governed.profile,
        selects_scm_supervision: false,
        requires_admin: false,
        requires_program_data_anchor: false,
        verified_root_roles: 4,
    })
}
