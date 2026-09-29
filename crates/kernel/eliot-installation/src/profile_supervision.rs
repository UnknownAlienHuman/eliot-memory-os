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

use std::path::{Path, PathBuf};

use eliot_platform_windows::profile_supervision::{
    CurrentUserTaskRequest, ProfileRootRequest, ProfileSelection as PlatformProfileSelection,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::profile_governed_roots::ProfileGovernedRoots;
use super::runtime_root_contract::{
    InstallationProfile, RuntimeRootLease, RuntimeRootLeaseProvider, RuntimeStateRoots,
};
use super::{
    CandidateManifest, InstallationError, InstallationRoots, PlatformHandle, ResourceGeneration,
    WindowsPathIdentity, WindowsRuntimeRootLeaseProvider, handle, joined_windows_path,
    same_windows_root, sha256_handle, text,
};

/// Phase-A template for one UserMode current-user Task Scheduler registration.
///
/// This plan binds the transaction and immutable candidate. It intentionally
/// carries no Phase-B authority digest: the final task request can be built
/// only from the live descriptor after Host has materialized and read it back.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserModeTaskRegistrationPlan {
    /// Installation transaction that owns this planned task effect.
    pub transaction_id: PlatformHandle,
    /// Stable effect identity included in the task registration receipt.
    pub effect_id: PlatformHandle,
    /// Installation identity from the immutable candidate epoch.
    pub installation_id: PlatformHandle,
    /// Exact immutable candidate generation.
    pub candidate_generation: PlatformHandle,
    /// Digest of the complete immutable candidate manifest.
    pub candidate_manifest_digest: PlatformHandle,
    /// Component identity selected by I3.1.
    pub profile_component: PlatformHandle,
    /// Immutable version identity selected by I3.1.
    pub profile_version: PlatformHandle,
    /// Current-user installation key selected by I3.1.
    pub profile_installation_key: Option<PlatformHandle>,
    /// Exact four-root and digest-bound runtime topology from the candidate.
    pub profile_roots: Box<InstallationRoots>,
    /// Phase-B descriptor path fixed by the candidate; its digest is supplied
    /// only after Host materializes the live descriptor.
    pub authority_descriptor_path: PlatformHandle,
    /// Authority generation selected by the candidate.
    pub authority_generation: ResourceGeneration,
    /// Exact approved Host image path.
    pub host_executable_path: PlatformHandle,
    /// Exact approved Host image SHA-256.
    pub host_executable_sha256: PlatformHandle,
    /// Exact working directory, fixed to the immutable binaries root.
    pub working_directory: PlatformHandle,
}

impl UserModeTaskRegistrationPlan {
    pub(crate) fn for_candidate(
        transaction_id: PlatformHandle,
        effect_id: PlatformHandle,
        candidate: &CandidateManifest,
    ) -> Result<Self, InstallationError> {
        let launch = &candidate.runtime_launch;
        if launch.profile != InstallationProfile::UserMode {
            return Err(InstallationError::ProfileViolation(
                "current-user task registration requires a UserMode candidate".to_owned(),
            ));
        }
        let (host_executable_path, host_executable_sha256) = launch.host_artifact_binding()?;
        let working_directory = PlatformHandle::new(
            launch.profile_governed_roots.immutable_binaries.clone(),
        )
        .map_err(|error| InstallationError::InvalidField {
            field: "user_mode_task.working_directory".to_owned(),
            reason: error.to_string(),
        })?;
        let plan = Self {
            transaction_id,
            effect_id,
            installation_id: launch.installation_epoch.installation.clone(),
            candidate_generation: candidate.generation.clone(),
            candidate_manifest_digest: candidate.compute_digest()?,
            profile_component: launch.profile_component.clone(),
            profile_version: launch.profile_version.clone(),
            profile_installation_key: launch.profile_installation_key.clone(),
            profile_roots: Box::new(launch.profile_governed_roots.clone()),
            authority_descriptor_path: launch.authority_descriptor_path.clone(),
            authority_generation: launch.authority_generation.clone(),
            host_executable_path: host_executable_path.clone(),
            host_executable_sha256: host_executable_sha256.clone(),
            working_directory,
        };
        plan.validate()?;
        Ok(plan)
    }

    /// Validates the immutable plan without inventing a live Phase-B digest.
    pub fn validate(&self) -> Result<(), InstallationError> {
        for (value, field) in [
            (&self.transaction_id, "user_mode_task.transaction_id"),
            (&self.effect_id, "user_mode_task.effect_id"),
            (&self.installation_id, "user_mode_task.installation_id"),
            (
                &self.candidate_generation,
                "user_mode_task.candidate_generation",
            ),
            (
                &self.profile_component,
                "user_mode_task.profile_component",
            ),
            (&self.profile_version, "user_mode_task.profile_version"),
        ] {
            handle(value, field)?;
        }
        sha256_handle(
            &self.candidate_manifest_digest,
            "user_mode_task.candidate_manifest_digest",
        )?;
        sha256_handle(
            &self.host_executable_sha256,
            "user_mode_task.host_executable_sha256",
        )?;
        if self.authority_generation.value() == 0 {
            return Err(InstallationError::InvalidField {
                field: "user_mode_task.authority_generation".to_owned(),
                reason: "must be non-zero".to_owned(),
            });
        }
        self.profile_roots.validate(InstallationProfile::UserMode)?;
        for (value, field) in [
            (
                &self.authority_descriptor_path,
                "user_mode_task.authority_descriptor_path",
            ),
            (
                &self.host_executable_path,
                "user_mode_task.host_executable_path",
            ),
            (
                &self.working_directory,
                "user_mode_task.working_directory",
            ),
        ] {
            handle(value, field)?;
            if !Path::new(value.as_str()).is_absolute() {
                return Err(InstallationError::InvalidField {
                    field: field.to_owned(),
                    reason: "must be an absolute path".to_owned(),
                });
            }
        }
        let expected_host = format!(
            "{}\\eliot-host.exe",
            self.profile_roots.immutable_binaries
        );
        let descriptor_name = Path::new(self.authority_descriptor_path.as_str())
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| InstallationError::InvalidField {
                field: "user_mode_task.authority_descriptor_path".to_owned(),
                reason: "must name the Phase-B descriptor".to_owned(),
            })?;
        let expected_descriptor = format!(
            "{}\\{descriptor_name}",
            self.profile_roots.immutable_binaries
        );
        if !same_windows_root(
            self.working_directory.as_str(),
            &self.profile_roots.immutable_binaries,
        )? || !same_windows_root(self.host_executable_path.as_str(), &expected_host)?
            || !same_windows_root(
                self.authority_descriptor_path.as_str(),
                &expected_descriptor,
            )?
        {
            return Err(InstallationError::IdentityConflict);
        }
        Ok(())
    }
}

/// Binds the immutable UserMode task template to a live, Host-materialized
/// Phase-B root request and the already-admitted Host argv tail.
///
/// The pending Phase-A marker is rejected by `sha256_handle`; the returned
/// platform request is therefore safe to pass to
/// `register_current_user_task` only after the live descriptor exists.
pub fn complete_user_mode_task_request(
    plan: &UserModeTaskRegistrationPlan,
    roots: ProfileRootRequest,
    bootstrap_arguments: Vec<String>,
) -> Result<CurrentUserTaskRequest, InstallationError> {
    plan.validate()?;
    let authority_digest = PlatformHandle::new(roots.authority_descriptor_sha256.clone()).map_err(
        |error| InstallationError::InvalidField {
            field: "user_mode_task.live_authority_digest".to_owned(),
            reason: error.to_string(),
        },
    )?;
    sha256_handle(
        &authority_digest,
        "user_mode_task.live_authority_digest",
    )?;
    if roots.profile != PlatformProfileSelection::UserMode
        || roots.installation_id != plan.installation_id.as_str()
        || roots.installation_key.as_deref() != self_handle_option(&plan.profile_installation_key)
        || roots.component != plan.profile_component.as_str()
        || roots.version != plan.profile_version.as_str()
        || roots.generation != plan.candidate_generation.as_str()
        || roots.authority_generation != plan.authority_generation.value()
        || roots.authority_descriptor_path
            != PathBuf::from(plan.authority_descriptor_path.as_str())
        || roots.repository_root.is_some()
        || bootstrap_arguments.is_empty()
        || !same_request_roots(plan, &roots)?
    {
        return Err(InstallationError::IdentityConflict);
    }
    Ok(CurrentUserTaskRequest {
        transaction_id: plan.transaction_id.as_str().to_owned(),
        effect_id: plan.effect_id.as_str().to_owned(),
        roots,
        executable: PathBuf::from(plan.host_executable_path.as_str()),
        executable_sha256: plan.host_executable_sha256.as_str().to_owned(),
        working_directory: PathBuf::from(plan.working_directory.as_str()),
        bootstrap_arguments,
    })
}

fn self_handle_option(value: &Option<PlatformHandle>) -> Option<&str> {
    value.as_ref().map(PlatformHandle::as_str)
}

fn same_request_roots(
    plan: &UserModeTaskRegistrationPlan,
    request: &ProfileRootRequest,
) -> Result<bool, InstallationError> {
    let expected = &plan.profile_roots;
    for (left, right) in [
        (&expected.immutable_binaries, &request.roots.immutable_binaries),
        (&expected.durable_data, &request.roots.durable_data),
        (&expected.user_config, &request.roots.user_config),
        (&expected.user_cache, &request.roots.user_cache),
    ] {
        let right = right.to_string_lossy();
        if !same_windows_root(left, right.as_ref())? {
            return Ok(false);
        }
    }
    let runtime = &expected.runtime_state_roots;
    let expected_runtime = [
        ("runtime_state_roots.profile_anchor_root", &runtime.profile_anchor_root),
        ("runtime_state_roots.installation_root", &runtime.installation_root),
        ("runtime_state_roots.host_state_root", &runtime.host_state_root),
        ("runtime_state_roots.kernel_ors_root", &runtime.kernel_ors_root),
        ("runtime_state_roots.kernel_work_root", &runtime.kernel_work_root),
        ("runtime_state_roots.store_data_root", &runtime.store_data_root),
        ("runtime_state_roots.store_work_root", &runtime.store_work_root),
        ("runtime_state_roots.store_temp_root", &runtime.store_temp_root),
        ("runtime_state_roots.watchdog_state_root", &runtime.watchdog_state_root),
    ];
    if request.roots.runtime_state_roots.len() != expected_runtime.len() {
        return Ok(false);
    }
    for (role, expected_path) in expected_runtime {
        let Some((_, actual_path)) = request
            .roots
            .runtime_state_roots
            .iter()
            .find(|(actual_role, _)| actual_role == role)
        else {
            return Ok(false);
        };
        let actual_path = actual_path.to_string_lossy();
        if !same_windows_root(expected_path.as_str(), actual_path.as_ref())? {
            return Ok(false);
        }
    }
    Ok(true)
}

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
/// 2. the anchor is *retained* as a live no-follow OS root object wherever the
///    OS lease contract admits it, and the retained lease is proven to bind
///    that same root object rather than merely repeat its name;
/// 3. all four I3.1 root roles exactly match the layout derived from the
///    retained anchor and lie strictly beneath it; and
/// 4. the profile does not claim SCM supervision or administrative authority.
///
/// [`NoServiceProfileAuthorityProof::verified_root_roles`] counts only the roles
/// whose layout was verified against a retained root object. A role derived from
/// a path that no OS lease holds is not counted, because a predictable name is
/// not ownership.
///
/// This proof does not claim lexical exclusion from a hypothetical
/// `ProgramData` path. Non-service selection receives no `ProgramData` anchor and
/// makes no `ProgramData` known-folder query.
///
/// # Errors
///
/// Returns [`InstallationError::ProfileViolation`] when the profile claims
/// service authority, a retained lease does not bind its declared root, or a
/// root differs from its exact profile layout; [`InstallationError::InvalidField`]
/// when a selected root is not a usable absolute path; and
/// [`InstallationError::Platform`] when OS anchor revalidation or retention
/// fails.
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
    let mut anchor_provider = WindowsRuntimeRootLeaseProvider::for_roots(runtime_state_roots)?;

    // The profile anchor is the only root in this selection the OS lease
    // contract admits as a retainable object. `portable_dev` names an already
    // retained current-user directory, so the provider opens and holds a real
    // no-follow handle to it for the whole proof.
    //
    // `user_mode` anchors on the OS-known-folder `LocalAppData` contour, and no
    // lease is retained for it. This is NOT an adapter capability choice and
    // must not be "fixed" by relaxing the user-owned lease precondition. The
    // anchor is the OS folder itself, shared machine-wide across every per-user
    // application, and `UserOwnedRootReadLease::open_existing` requires a
    // protected two-ACE DACL owned by the current SID
    // (`user_owned_leases.rs::verify_user_owned_opened_handle_read_only`). A
    // stock `%LocalAppData%` root is inheritable (`D:AI`) and carries AppContainer
    // capability, `Users` and `BA` ACEs, so it can never satisfy that contract.
    // Provisioning it to satisfy the contract would strip those ACEs from a
    // shared OS folder and break unrelated software, and the read lease
    // structurally never requests `WRITE_DAC`, so it cannot do so itself.
    //
    // The consequence is that `user_mode` reports zero verified root roles. That
    // is the honest number, not a defect to be papered over: the derived
    // per-user roots under the anchor are Eliot-owned and become leaseable via
    // this same unmodified `retain_root` path once an installer effect
    // provisions them. Until then no role is counted, because counting a role
    // against a constructed path string rather than a retained object would
    // claim a verification this code does not perform.
    let retained_anchor = match governed.profile {
        InstallationProfile::SystemService => unreachable!("service profile rejected above"),
        InstallationProfile::PortableDev => {
            Some(anchor_provider.retain_root(&runtime_state_roots.profile_anchor_root)?)
        }
        InstallationProfile::UserMode => None,
    };
    let declared_anchor = runtime_state_roots.profile_anchor_root.as_str();
    if let Some(lease) = &retained_anchor {
        if !lease.is_reparse_free() {
            return Err(InstallationError::ProfileViolation(
                "retained profile anchor contains a reparse point".to_owned(),
            ));
        }
        if !same_windows_root(lease.declared_path(), declared_anchor)?
            || !same_windows_root(lease.canonical_path(), declared_anchor)?
        {
            return Err(InstallationError::ProfileViolation(
                "retained profile anchor lease does not bind the declared profile anchor"
                    .to_owned(),
            ));
        }
        text(
            lease.file_identity(),
            "profile_supervision.anchor_lease.file_identity",
        )?;
    }

    // The layout is derived from the retained lease's OS-resolved canonical
    // path when one exists, so the expected side of every comparison is a value
    // the OS reported about a held object rather than an echo of the caller's
    // own anchor string.
    let anchor = match &retained_anchor {
        Some(lease) => lease.canonical_path(),
        None => declared_anchor,
    };
    let anchor_identity = WindowsPathIdentity::parse_root(anchor, "profile_supervision.anchor")?;
    let expected =
        expected_profile_layout(governed.profile, anchor, component, version, generation)?;
    let actual = [
        ("immutable_binaries", governed.immutable_binaries.as_str()),
        ("durable_data", governed.durable_data.as_str()),
        ("user_config", governed.user_config.as_str()),
        ("user_cache", governed.user_cache.as_str()),
    ];
    // A role counts as verified only when the anchor it was derived from is a
    // retained OS root object. Without a retained lease this loop is still a
    // required refusal check -- a role that is not the exact layout under the
    // selected anchor is refused either way -- but it is a lexical check, and
    // nothing it agrees with is counted.
    let anchor_is_retained = retained_anchor.is_some();
    let mut verified_root_roles = 0_u32;
    for ((expected_field, expected_path), (actual_field, actual_path)) in
        expected.into_iter().zip(actual)
    {
        let expected_identity = WindowsPathIdentity::parse_root(&expected_path, expected_field)?;
        let actual_identity = WindowsPathIdentity::parse_root(actual_path, actual_field)?;
        if expected_field != actual_field || expected_identity != actual_identity {
            return Err(InstallationError::ProfileViolation(format!(
                "{actual_field} differs from the exact {:?} root derived from its retained profile anchor",
                governed.profile
            )));
        }
        // The role must be strictly inside the anchor, so a role can never
        // satisfy its own layout by collapsing onto the anchor itself.
        if expected_identity == anchor_identity || !anchor_identity.contains(&expected_identity) {
            return Err(InstallationError::ProfileViolation(format!(
                "{expected_field} is not strictly below the {:?} profile anchor",
                governed.profile
            )));
        }
        if anchor_is_retained {
            verified_root_roles += 1;
        }
    }

    Ok(NoServiceProfileAuthorityProof {
        profile: governed.profile,
        selects_scm_supervision: false,
        requires_admin: false,
        requires_program_data_anchor: false,
        verified_root_roles,
    })
}

/// Builds the exact I3.1 root layout a profile names beneath `anchor`.
///
/// This is the expected side of the no-service-authority comparison: for each
/// of the four I3.1 roles it returns the path that profile requires, obtained
/// by joining `anchor` with that role's own fixed contour. It is pure layout
/// arithmetic and proves nothing by itself; the caller supplies `anchor` as the
/// OS-reported canonical path of the retained anchor object wherever the OS
/// lease contract admits one, so the paths produced here are anchored to a
/// value the OS reported about a held object rather than to an echo of the
/// caller's own anchor string.
///
/// The `SystemService` arm is unreachable because the caller refuses that
/// profile before any layout is built.
///
/// # Errors
///
/// Returns [`InstallationError::ProfileViolation`] when a `portable_dev`
/// selection carries no generation identity to lay its disposable state roots
/// under, and [`InstallationError::InvalidField`] when the component, version
/// or generation identity is not a usable field value.
fn expected_profile_layout(
    profile: InstallationProfile,
    anchor: &str,
    component: &str,
    version: &str,
    generation: Option<&str>,
) -> Result<[(&'static str, String); 4], InstallationError> {
    Ok(match profile {
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
    })
}
