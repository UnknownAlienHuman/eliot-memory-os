//! Profile supervision composition and unprivileged-selection proof (I3.1).
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
//! `ProgramData` dependency.
//!
//! The proof is structural, not textual. It re-reads the OS-proved
//! `ProgramData` contour through the Windows adapter, compares it with
//! [`WindowsPathIdentity`] component containment against every resolved and
//! every retained root, and requires the selected profile to be one that
//! claims no administrative authority. A profile that merely *says* it is
//! unprivileged is refused; only a layout that is provably outside the
//! service contour passes.
//!
//! Normative basis: I3.1 (exact layouts, default profile, supervision, and
//! owner/session binding). This module resolves no new root and mints no
//! second registry: [`ProfileGovernedRoots`] remains the sole selector
//! output, and [`super::RuntimeStateRoots`] remains the sole retained
//! runtime topology.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::profile_governed_roots::ProfileGovernedRoots;
use super::runtime_root_contract::{InstallationProfile, RuntimeStateRoots};
use super::{InstallationError, PlatformHandle, WindowsPathIdentity, protected_program_data_root};

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

/// Evidence that the selected profile depends on no service-only authority.
///
/// The fields are the structural facts the proof established, retained so a
/// caller can report what was proved rather than re-deriving it.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnprivilegedSelectionProof {
    /// Profile that was proved unprivileged.
    pub profile: InstallationProfile,
    /// Whether the selected profile claims administrative authority. Always
    /// `false` for a value this type can exist for.
    pub requires_admin: bool,
    /// Number of root roles and retained runtime roots compared against the
    /// OS-proved service contours.
    pub compared_roots: u32,
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

/// Proves that a resolved selection depends on no service-only authority.
///
/// The proof is refused for `system_service`, whose supervision path *is* the
/// SCM. For every other profile it establishes, structurally:
///
/// 1. the selected profile claims no administrative installation authority;
/// 2. no resolved root role lies under the OS-proved `ProgramData` contour;
/// 3. no retained runtime root — the profile anchor, the installation root, or
///    any of the fixed runtime root roles — lies under that contour either.
///
/// The `ProgramData` contour is read from the Windows adapter, so a caller
/// cannot satisfy this proof by passing a convenient path.
///
/// # Errors
///
/// Returns [`InstallationError::ProfileViolation`] when the profile claims
/// administrative authority or when any compared root lies inside the service
/// `ProgramData` contour, and [`InstallationError::InvalidField`] when a
/// compared root is not a usable absolute path.
pub fn prove_unprivileged_selection(
    governed: &ProfileGovernedRoots,
    runtime_state_roots: &RuntimeStateRoots,
) -> Result<UnprivilegedSelectionProof, InstallationError> {
    if governed.profile.requires_admin() {
        return Err(InstallationError::ProfileViolation(format!(
            "{:?} supervision depends on SCM and administrative service rights",
            governed.profile
        )));
    }
    let program_data = protected_program_data_root().map_err(|error| {
        InstallationError::Platform(format!("service ProgramData contour is unproved: {error}"))
    })?;
    let program_data_text = program_data.to_string_lossy().into_owned();
    let program_data = WindowsPathIdentity::parse_root(&program_data_text, "program_data")?;

    let mut compared: Vec<(&'static str, PlatformHandle)> = Vec::with_capacity(13);
    for (field, value) in [
        ("immutable_binaries", &governed.immutable_binaries),
        ("durable_data", &governed.durable_data),
        ("user_config", &governed.user_config),
        ("user_cache", &governed.user_cache),
    ] {
        compared.push((
            field,
            PlatformHandle::new((*value).clone()).map_err(|error| {
                InstallationError::InvalidField {
                    field: (*field).to_owned(),
                    reason: error.to_string(),
                }
            })?,
        ));
    }
    compared.push((
        "profile_anchor_root",
        runtime_state_roots.profile_anchor_root.clone(),
    ));
    compared.push((
        "installation_root",
        runtime_state_roots.installation_root.clone(),
    ));
    for (field, root) in runtime_state_roots.root_fields() {
        compared.push((field, root.clone()));
    }

    let mut compared_roots: u32 = 0;
    for (field, candidate) in &compared {
        compared_roots = compared_roots.saturating_add(1);
        let identity = WindowsPathIdentity::parse_root(candidate.as_str(), field)?;
        if program_data.contains(&identity) {
            return Err(InstallationError::ProfileViolation(format!(
                "{field} lies inside the system_service ProgramData contour; {:?} may not depend on it",
                governed.profile
            )));
        }
    }

    Ok(UnprivilegedSelectionProof {
        profile: governed.profile,
        requires_admin: false,
        compared_roots,
    })
}
