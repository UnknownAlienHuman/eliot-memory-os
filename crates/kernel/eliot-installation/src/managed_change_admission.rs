//! Private-construction handoff from signed request admission to the existing
//! durable installation transaction.
//!
//! A value of [`AcceptedManagedChange`] can only be created by the production
//! accepted-survey seam. Before each effect, its method re-reads the retained
//! signed configuration bytes, re-matches the exact approval, resolves the
//! current typed recipe, re-runs the ordered survey through the same sealed
//! observation source, and confirms the durable PortableDev root binding.
//! Holding the carrier is not permission to skip that check or to report a
//! successful probe.

use std::path::{Path, PathBuf};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::{
    AcceptedCatalogueContext, AcceptedInstallationSurvey, InstallationError, InstallationProfile,
    InstallationTransactionStore, ManagedChangeAdmissionError, ManagedChangeApproval,
    ManagedEffectRecipe, ManagedEnvironmentChangePlan, PlatformHandle, SurveyObservationSource,
    VerifiedSetupBinding,
    WindowsPathIdentity, revalidate_managed_change_plan, survey_accepted_installation,
};

/// One accepted request and its exact signed plan, carried to the existing
/// transaction owner. Fields are private so a caller cannot pair an arbitrary
/// survey or recipe with an approved plan.
#[derive(Clone, Debug)]
pub struct AcceptedManagedChange {
    accepted_survey: AcceptedInstallationSurvey,
    plan: ManagedEnvironmentChangePlan,
    managed_tools_root: PathBuf,
}

impl AcceptedManagedChange {
    pub(crate) fn new(
        accepted_survey: AcceptedInstallationSurvey,
        plan: ManagedEnvironmentChangePlan,
        managed_tools_root: PathBuf,
    ) -> Self {
        Self {
            accepted_survey,
            plan,
            managed_tools_root,
        }
    }

    /// Returns the exact current accepted catalogue and ordered survey that
    /// were used to compile this request.
    #[must_use]
    pub const fn accepted_survey(&self) -> &AcceptedInstallationSurvey {
        &self.accepted_survey
    }

    /// Returns the immutable plan compiled from the exact approved request.
    #[must_use]
    pub const fn plan(&self) -> &ManagedEnvironmentChangePlan {
        &self.plan
    }

    /// Returns the exact signed portable effect recipe frozen into the plan.
    #[must_use]
    pub const fn recipe(&self) -> &ManagedEffectRecipe {
        self.plan.effect_recipe()
    }

    /// Returns the exact owner-signed approval frozen into the plan.
    #[must_use]
    pub const fn approval(&self) -> &ManagedChangeApproval {
        self.plan.approval()
    }

    /// Returns the selected installation's fixed `managed-tools` child root.
    /// The path was derived from the durable transaction's I3.1 root binding;
    /// no caller-supplied path is retained.
    #[must_use]
    pub fn managed_tools_root(&self) -> &Path {
        &self.managed_tools_root
    }

    /// Re-reads authoritative bytes and current observations immediately
    /// before an effect. This is not a cache hit: the catalogue, approval,
    /// source recipe, survey and root binding must all still equal the original
    /// accepted plan.
    pub(crate) fn revalidate_for_effect(
        &self,
        context: &AcceptedCatalogueContext<'_>,
        source: &dyn SurveyObservationSource,
    ) -> Result<(), ManagedChangeAdmissionError> {
        let _admitted = rederive_accepted_plan(&self.plan, context, source)?;
        let current_root = managed_tools_root(context.authority, context.store, context.transaction_id)?;
        if !same_windows_root(&current_root, &self.managed_tools_root)? {
            return Err(InstallationError::IdentityConflict.into());
        }
        Ok(())
    }
}

/// The exact live values from which one capability advertisement was derived.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequalificationBinding {
    /// Catalogue origin of the live revision.
    pub catalogue_origin: PlatformHandle,
    /// Live accepted catalogue revision.
    pub catalogue_revision: u64,
    /// Exact retained signed configuration publication.
    pub catalogue_publication_ref: PlatformHandle,
    /// Verified catalogue signer.
    pub catalogue_accepted_by: PlatformHandle,
    /// Confirmed setup owner.
    pub confirmed_owner: PlatformHandle,
    /// Admitted installation profile.
    pub profile: InstallationProfile,
    /// Admitted runtime-root topology digest.
    pub runtime_state_roots_digest: PlatformHandle,
    /// Admitted setup revision.
    pub setup_revision: u64,
    /// Signed setup snapshot reference.
    pub configuration_snapshot_ref: PlatformHandle,
    /// Content digest of the live ordered survey.
    pub survey_content_digest: PlatformHandle,
}

/// A freshly surveyed requalification of one completed managed change.
///
/// The owner validates the original completed transaction, then reads the
/// current signed catalogue and surveys its current family. The optional probe
/// is resolved only for a native identity that the current catalogue survey
/// observed; retaining this carrier does not execute that probe.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompletedManagedChangeRequalification {
    result: super::InstallationSurveyProbeResult,
    probe: Option<super::BoundedProbeInvocation>,
}

impl CompletedManagedChangeRequalification {
    /// Returns the current advertisement and the prior/current runtime hashes
    /// proved by the original owner and the live observations.
    #[must_use]
    pub const fn result(&self) -> &super::InstallationSurveyProbeResult {
        &self.result
    }

    /// Returns the bounded probe resolved for the exact current native
    /// identity, when the current signed catalogue admits one.
    #[must_use]
    pub const fn probe(&self) -> Option<&super::BoundedProbeInvocation> {
        self.probe.as_ref()
    }
}

/// Requalifies a completed managed change using its original durable owner and
/// a fresh survey against the current accepted catalogue and approval.
///
/// Package-changing actions bind the current runtime hash to a fresh native
/// readback of one declared executable in the exact Applied package receipt.
/// Registration and reconfiguration can retain the original fingerprint only
/// when the current survey proves that exact original identity, path and hash.
/// The recorded plan is never recompiled or rewritten.
pub fn requalify_completed_managed_change(
    context: &AcceptedCatalogueContext<'_>,
    source: &dyn SurveyObservationSource,
    request: &super::ManagedEnvironmentChangeRequest,
    completed_transaction_id: &PlatformHandle,
) -> Result<CompletedManagedChangeRequalification, ManagedChangeAdmissionError> {
    request.validate()?;
    let transaction = context
        .store
        .load(completed_transaction_id)?
        .ok_or_else(|| InstallationError::TransactionNotFound {
            transaction_id: completed_transaction_id.as_str().to_owned(),
        })?;
    transaction.validate()?;
    if transaction.transaction_id != *completed_transaction_id
        || transaction.stage() != super::InstallationStage::Completed
        || transaction.request != *request
        || transaction.installation_epoch.installation.as_str()
            != context.authority.installation_id()
    {
        return Err(InstallationError::IdentityConflict.into());
    }
    // Confirm the existing transaction still belongs to the current admitted
    // PortableDev root topology. This performs no write or root selection.
    let _ = managed_tools_root(context.authority, context.store, completed_transaction_id)?;

    let managed_effects = transaction
        .installer_effects
        .iter()
        .enumerate()
        .filter_map(|(index, effect)| match effect {
            super::InstallerEffectPlan::ManagedEnvironmentChange {
                effect_id,
                accepted_plan_json,
                request: retained_request,
                recipe,
                ..
            } => Some((index, effect_id, accepted_plan_json, retained_request, recipe)),
            _ => None,
        })
        .collect::<Vec<_>>();
    let [(effect_index, effect_id, accepted_plan_json, retained_request, recipe)] =
        managed_effects.as_slice()
    else {
        return Err(InstallationError::IdentityConflict.into());
    };
    if *retained_request != request || recipe.action != request.action
        || recipe.target_family != request.target_family
    {
        return Err(InstallationError::IdentityConflict.into());
    }
    // Transaction validation checks the retained plan projection against its
    // complete request and exact retained recipe. Recheck the byte-backed
    // projection here before using its original native observation getter.
    let retained_plan =
        super::ManagedEnvironmentChangePlan::from_retained_json(accepted_plan_json)?;
    if retained_plan.request() != request || retained_plan.effect_recipe() != recipe.as_ref() {
        return Err(InstallationError::IdentityConflict.into());
    }
    let progress = transaction
        .effect_progress()
        .get(*effect_index)
        .ok_or(InstallationError::IdentityConflict)?;
    if &progress.effect_id != *effect_id
        || !matches!(
            &progress.state,
            super::InstallationEffectProgressState::Applied { .. }
        )
    {
        return Err(InstallationError::IdentityConflict.into());
    }
    let previous_observation = transaction
        .completed_managed_target_executable_observation(effect_id)?;
    let previous_runtime_hash = previous_observation
        .as_ref()
        .map(|(_, _, sha256)| sha256.as_str().to_owned());

    let live = survey_accepted_installation(context, source)?;
    let accepted = &live.accepted;
    accepted.require_approval(
        request,
        context.authority,
        super::wall_clock_millis(),
    )?;
    let family = live
        .survey
        .families()
        .iter()
        .find(|family| family.family_id == request.target_family)
        .ok_or_else(|| InstallationError::IncompleteObservation(
            "the completed change family was not covered by the live survey".to_owned(),
        ))?;
    let current_family_id = &request.target_family;
    let coverage_gaps = survey_coverage_gaps(family);

    let current_runtime_hash = match request.action {
        super::ManagedEnvironmentAction::Install
        | super::ManagedEnvironmentAction::Update
        | super::ManagedEnvironmentAction::Repair => {
            package_receipt_runtime_hash(progress.staging_receipt.as_ref(), recipe)?
        }
        super::ManagedEnvironmentAction::Register
        | super::ManagedEnvironmentAction::Reconfigure => {
            previous_observation.as_ref().and_then(|(identity, path, sha256)| {
                surveyed_native_match(family, identity, path, sha256.as_str(), None)
                    .then(|| sha256.as_str().to_owned())
            })
        }
        super::ManagedEnvironmentAction::Remove => None,
    };

    let matched_identity = match request.action {
        super::ManagedEnvironmentAction::Install
        | super::ManagedEnvironmentAction::Update
        | super::ManagedEnvironmentAction::Repair => current_runtime_hash
            .as_ref()
            .and_then(|_| progress.staging_receipt.as_ref())
            .and_then(|receipt| receipt_survey_identity(family, receipt, recipe)),
        super::ManagedEnvironmentAction::Register
        | super::ManagedEnvironmentAction::Reconfigure => previous_observation
            .as_ref()
            .and_then(|(identity, path, sha256)| {
                surveyed_native_match(family, identity, path, sha256.as_str(), None)
                    .then(|| identity.clone())
            }),
        super::ManagedEnvironmentAction::Remove => None,
    };
    let probe = if let Some(identity) = matched_identity.as_ref() {
        super::resolve_bounded_probe(accepted.catalogue(), current_family_id, identity)?
    } else {
        None
    };
    let state = match matched_identity.as_ref() {
        Some(_) => candidate_state(probe.as_ref(), coverage_gaps),
        None => {
            let mut missing = coverage_gaps;
            missing.push(MissingQualification::TargetNotObservedInTheLiveSurvey);
            unsupported_state(missing)
        }
    };
    let category = family.category;
    let advertisement = ManagedCapabilityAdvertisement {
        family_id: request.target_family.clone(),
        category,
        target_identity: matched_identity,
        state,
        requalified_against: requalification_binding(accepted, &live.survey, context.authority)?,
    };
    Ok(CompletedManagedChangeRequalification {
        result: super::InstallationSurveyProbeResult {
            advertisement,
            runtime_hash: current_runtime_hash,
            previous_runtime_hash,
        },
        probe,
    })
}

fn package_receipt_runtime_hash(
    receipt: Option<&eliot_platform_windows::StagingReceipt>,
    recipe: &super::ManagedEffectRecipe,
) -> Result<Option<String>, InstallationError> {
    let Some(receipt) = receipt else {
        return Ok(None);
    };
    let mut matching_hashes = Vec::new();
    for executable in &recipe.executable_relative_paths {
        let Some(file) = receipt
            .files
            .iter()
            .find(|file| file.relative_path == executable.as_str())
        else {
            return Err(InstallationError::IdentityConflict);
        };
        let path = receipt.root_path.join(&file.relative_path);
        let observation = eliot_platform_windows::observe_file_version(&path);
        if !matches!(
            &observation.outcome,
            eliot_platform_windows::FileVersionOutcome::Present { .. }
                | eliot_platform_windows::FileVersionOutcome::Absent
        ) || observation.file_identity.as_ref() != Some(&file.destination_identity)
            || observation.sha256.as_deref() != Some(file.sha256.as_str())
        {
            continue;
        }
        matching_hashes.push(file.sha256.clone());
    }
    if matching_hashes.len() == 1 {
        Ok(matching_hashes.into_iter().next())
    } else {
        // Zero means the current readback did not bind. More than one
        // executable identity is ambiguous and must not select one hash.
        Ok(None)
    }
}

fn receipt_survey_identity(
    family: &super::SurveyFamilyReport,
    receipt: &eliot_platform_windows::StagingReceipt,
    recipe: &super::ManagedEffectRecipe,
) -> Option<PlatformHandle> {
    let mut matches = Vec::new();
    for executable in &recipe.executable_relative_paths {
        let Some(file) = receipt
            .files
            .iter()
            .find(|file| file.relative_path == executable.as_str())
        else {
            continue;
        };
        let Ok(expected_path) = PlatformHandle::new(
            receipt
                .root_path
                .join(&file.relative_path)
                .to_string_lossy()
                .into_owned(),
        ) else {
            continue;
        };
        if let Some(identity) = family
            .candidates
            .iter()
            .find(|candidate| {
                candidate.aliases.iter().any(|path| {
                    eliot_platform_windows::windows_paths_equal(
                        Path::new(path.as_str()),
                        Path::new(expected_path.as_str()),
                    )
                })
            })
            .map(|candidate| candidate.observed_identity.clone())
            && surveyed_native_match(
                family,
                &identity,
                &expected_path,
                &file.sha256,
                Some(&file.destination_identity),
            )
        {
            matches.push(identity);
        }
    }
    matches.sort();
    matches.dedup();
    (matches.len() == 1).then(|| matches.remove(0))
}

fn surveyed_native_match(
    family: &super::SurveyFamilyReport,
    identity: &PlatformHandle,
    expected_path: &PlatformHandle,
    expected_sha256: &str,
    expected_file_identity: Option<&eliot_platform_windows::FileIdentity>,
) -> bool {
    let Some(candidate) = family
        .candidates
        .iter()
        .find(|candidate| &candidate.observed_identity == identity)
    else {
        return false;
    };
    let Some(stage) = family
        .stages
        .iter()
        .find(|stage| stage.stage == super::SurveyStage::FileVersionSignatureIdentity)
    else {
        return false;
    };
    let mut matches = stage.observations.iter().filter(|observation| {
        observation.observed_identity.as_ref() == Some(identity)
            && observation.outcome == super::SurveyStageOutcome::Found
            && candidate.aliases.contains(&observation.input)
            && eliot_platform_windows::windows_paths_equal(
                Path::new(observation.input.as_str()),
                Path::new(expected_path.as_str()),
            )
            && observation
                .file_version
                .as_ref()
                .is_some_and(|version| {
                    expected_file_identity.map_or(true, |expected| {
                        version.file_identity.as_ref() == Some(expected)
                    })
                        && version
                        .sha256
                        .as_deref()
                        .is_some_and(|sha256| sha256.eq_ignore_ascii_case(expected_sha256))
                })
    });
    matches.next().is_some() && matches.next().is_none()
}

/// Qualification gaps a live installation survey may report.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MissingQualification {
    /// This identity has no exact accepted bounded probe contract.
    NoBoundedProbeAdmittedForThisIdentity,
    /// A probe contract exists but the admitted Kernel executor has not
    /// produced a result.
    NotProbedByAnAdmittedExecutor,
    /// The exact planned identity is absent from the live survey.
    TargetNotObservedInTheLiveSurvey,
    /// At least one required observation was unreadable.
    LiveSurveyUnreadableInput,
    /// At least one image or version resource was malformed or over bound.
    LiveSurveyInvalidInput,
    /// At least one declared input was not covered.
    LiveSurveyInputNotCovered,
    /// At least one observed input could not be attributed to one identity.
    AmbiguousIdentityInTheLiveSurvey,
    /// At least one required input was denied.
    LiveSurveyDeniedInput,
}

/// Capability facts this installation-owned contour can emit.
///
/// `admitted` and `degraded` are intentionally absent: admission and evidence
/// invalidation belong to the Governor registry, not a filesystem survey.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum ManagedCapabilityStatus {
    /// Complete discovery coverage with no current candidate selected.
    Discovered,
    /// Exact bounded probe contract exists, but no admitted result is present.
    Declared {
        /// Stable probe recipe identity.
        probe_id: PlatformHandle,
    },
    /// The admitted Kernel executor answered the exact bounded invocation.
    Probed {
        /// Stable probe recipe identity.
        probe_id: PlatformHandle,
        /// Bounded, non-secret answer handles retained by the sealed survey.
        answer_refs: Vec<PlatformHandle>,
    },
    /// The exact live survey or probe lacks one or more qualifications.
    Unsupported {
        /// All named gaps, ascending and distinct.
        missing: Vec<MissingQualification>,
    },
}

/// One candidate's live capability qualification, still short of admission.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedCapabilityState {
    /// Current status derived from live evidence.
    pub status: ManagedCapabilityStatus,
    /// Every remaining qualification gap, ascending and distinct.
    pub missing: Vec<MissingQualification>,
}

/// Live requalification result for one exact catalogue family/candidate.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedCapabilityAdvertisement {
    /// Catalogue family.
    pub family_id: PlatformHandle,
    /// Live accepted discovery category.
    pub category: super::IntegrationCategory,
    /// Exact candidate identity, or none for a prospective install.
    pub target_identity: Option<PlatformHandle>,
    /// The current qualified facts and missing requirements.
    pub state: ManagedCapabilityState,
    /// Original plan and live authority bindings checked before derivation.
    pub requalified_against: RequalificationBinding,
}

/// Re-derives a plan's capability advertisement from fresh signed bytes and a
/// fresh ordered metadata survey. The plan only narrows the family and target;
/// it never supplies the current survey answer.
pub fn requalify_managed_capability(
    accepted_change: &AcceptedManagedChange,
    context: &AcceptedCatalogueContext<'_>,
    source: &dyn SurveyObservationSource,
) -> Result<ManagedCapabilityAdvertisement, ManagedChangeAdmissionError> {
    let live = rederive_accepted_plan(&accepted_change.plan, context, source)?;
    let plan = &accepted_change.plan;
    let accepted = live.accepted();
    let survey = live.survey();
    let entry = accepted.catalogue().entry(plan.family_id())?;
    let family = survey
        .families()
        .iter()
        .find(|family| family.family_id == *plan.family_id())
        .ok_or_else(|| InstallationError::IncompleteObservation(
            "the requested family was not covered by the live survey".to_owned(),
        ))?;
    let missing_coverage = survey_coverage_gaps(family);
    let state = match plan.target_identity() {
        None if missing_coverage.is_empty() => ManagedCapabilityState {
            status: ManagedCapabilityStatus::Discovered,
            missing: Vec::new(),
        },
        None => unsupported_state(missing_coverage),
        Some(identity) => {
            let Some(candidate) = family
                .candidates
                .iter()
                .find(|candidate| &candidate.observed_identity == identity)
            else {
                return Ok(ManagedCapabilityAdvertisement {
                    family_id: plan.family_id().clone(),
                    category: family.category,
                    target_identity: Some(identity.clone()),
                    state: unsupported_state(vec![MissingQualification::TargetNotObservedInTheLiveSurvey]),
                    requalified_against: requalification_binding(accepted, survey, context.authority)?,
                });
            };
            candidate_state(plan.target_probe(), missing_coverage)
        }
    };
    Ok(ManagedCapabilityAdvertisement {
        family_id: plan.family_id().clone(),
        category: family.category,
        target_identity: plan.target_identity().cloned(),
        state,
        requalified_against: requalification_binding(accepted, survey, context.authority)?,
    })
}

fn candidate_state(
    probe: Option<&super::BoundedProbeInvocation>,
    mut missing: Vec<MissingQualification>,
) -> ManagedCapabilityState {
    match probe {
        Some(probe) => {
            missing.push(MissingQualification::NotProbedByAnAdmittedExecutor);
            sort_missing(&mut missing);
            ManagedCapabilityState {
                status: ManagedCapabilityStatus::Declared {
                    probe_id: probe.probe_id.clone(),
                },
                missing,
            }
        }
        None => {
            missing.push(MissingQualification::NoBoundedProbeAdmittedForThisIdentity);
            unsupported_state(missing)
        }
    }
}

fn survey_coverage_gaps(family: &super::SurveyFamilyReport) -> Vec<MissingQualification> {
    let mut missing = Vec::new();
    if family.stages.iter().any(|stage| !stage.invalid.is_empty()) {
        missing.push(MissingQualification::LiveSurveyInvalidInput);
    }
    if family.stages.iter().any(|stage| !stage.unreadable.is_empty()) {
        missing.push(MissingQualification::LiveSurveyUnreadableInput);
    }
    if family.stages.iter().any(|stage| !stage.denied.is_empty()) {
        missing.push(MissingQualification::LiveSurveyDeniedInput);
    }
    if family.stages.iter().any(|stage| {
        !stage.not_covered.is_empty()
            || (stage.stage != super::SurveyStage::AdmittedSafeProbe
                && !stage.withheld.is_empty())
    }) {
        missing.push(MissingQualification::LiveSurveyInputNotCovered);
    }
    if family.stages.iter().any(|stage| !stage.ambiguous.is_empty()) {
        missing.push(MissingQualification::AmbiguousIdentityInTheLiveSurvey);
    }
    sort_missing(&mut missing);
    missing
}

fn unsupported_state(mut missing: Vec<MissingQualification>) -> ManagedCapabilityState {
    sort_missing(&mut missing);
    ManagedCapabilityState {
        status: ManagedCapabilityStatus::Unsupported {
            missing: missing.clone(),
        },
        missing,
    }
}

fn sort_missing(missing: &mut Vec<MissingQualification>) {
    missing.sort_unstable();
    missing.dedup();
}

fn requalification_binding(
    accepted: &super::AcceptedIntegrationCatalogue,
    survey: &super::InstallationSurvey,
    authority: &VerifiedSetupBinding,
) -> Result<RequalificationBinding, InstallationError> {
    Ok(RequalificationBinding {
        catalogue_origin: accepted.origin().clone(),
        catalogue_revision: accepted.revision(),
        catalogue_publication_ref: accepted.signed_publication_ref().clone(),
        catalogue_accepted_by: accepted.accepted_by().clone(),
        confirmed_owner: authority.confirmed_owner().clone(),
        profile: authority.profile(),
        runtime_state_roots_digest: authority.runtime_state_roots_digest().clone(),
        setup_revision: authority.setup_revision(),
        configuration_snapshot_ref: authority.configuration_snapshot_ref().clone(),
        survey_content_digest: super::managed_change_plan::survey_content_digest(survey)?,
    })
}

fn rederive_accepted_plan(
    plan: &ManagedEnvironmentChangePlan,
    context: &AcceptedCatalogueContext<'_>,
    source: &dyn SurveyObservationSource,
) -> Result<AcceptedInstallationSurvey, ManagedChangeAdmissionError> {
    let live = survey_accepted_installation(context, source)?;
    let approval = live.accepted.require_approval(
        plan.request(),
        context.authority,
        super::wall_clock_millis(),
    )?;
    revalidate_managed_change_plan(
        plan,
        &live.accepted,
        &live.survey,
        context.authority,
        &approval,
    )?;
    Ok(live)
}

/// Resolve the one fixed managed-tools child from the transaction's persisted
/// profile-root binding. The caller's ambient environment never participates.
pub(crate) fn managed_tools_root(
    authority: &VerifiedSetupBinding,
    store: &super::RedbInstallationTransactionStore,
    transaction_id: &PlatformHandle,
) -> Result<PathBuf, InstallationError> {
    if authority.profile() != InstallationProfile::PortableDev {
        return Err(InstallationError::ProfileViolation(
            "portable managed-tool effects require PortableDev".to_owned(),
        ));
    }
    let transaction = store
        .load(transaction_id)?
        .ok_or_else(|| InstallationError::TransactionNotFound {
            transaction_id: transaction_id.as_str().to_owned(),
        })?;
    transaction.validate()?;
    if transaction.transaction_id != *transaction_id
        || transaction.installation_epoch.installation.as_str() != authority.installation_id()
        || transaction.profile != authority.profile()
    {
        return Err(InstallationError::IdentityConflict);
    }
    let roots = transaction
        .profile_governed_roots
        .as_ref()
        .ok_or_else(|| InstallationError::ProfileViolation(
            "managed tool effect requires the durable I3.1 root binding".to_owned(),
        ))?;
    roots.validate(transaction.profile)?;
    if roots.runtime_state_roots.profile != authority.profile()
        || roots.runtime_state_roots.roots_digest != *authority.runtime_state_roots_digest()
    {
        return Err(InstallationError::IdentityConflict);
    }
    let immutable_binaries = PathBuf::from(&roots.immutable_binaries);
    WindowsPathIdentity::parse_root(
        &roots.immutable_binaries,
        "transaction.profile_governed_roots.immutable_binaries",
    )?;
    Ok(immutable_binaries.join(super::MANAGED_TOOLS_RELATIVE_ROOT))
}

fn same_windows_root(left: &Path, right: &Path) -> Result<bool, InstallationError> {
    let left = left.to_string_lossy();
    let right = right.to_string_lossy();
    let left = WindowsPathIdentity::parse_root(&left, "managed_tools_root")?;
    let right = WindowsPathIdentity::parse_root(&right, "managed_tools_root")?;
    Ok(left == right)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_file_version_resource_remains_an_explicit_qualification_gap() {
        let invalid_input = PlatformHandle::new("C:\\tools\\malformed.exe")
            .expect("test input handle is valid");
        let family = super::super::SurveyFamilyReport {
            family_id: PlatformHandle::new("family:test").expect("test family handle is valid"),
            category: super::super::IntegrationCategory::Toolchain,
            stages: vec![super::super::SurveyStageResult {
                stage: super::super::SurveyStage::FileVersionSignatureIdentity,
                outcome: super::super::SurveyStageOutcome::Invalid,
                inputs: vec![invalid_input.clone()],
                observations: vec![super::super::SurveyInputObservation {
                    input: invalid_input.clone(),
                    outcome: super::super::SurveyStageOutcome::Invalid,
                    observed_identity: None,
                    evidence: None,
                    file_version: None,
                }],
                found: Vec::new(),
                not_found: Vec::new(),
                denied: Vec::new(),
                unreadable: Vec::new(),
                invalid: vec![invalid_input],
                ambiguous: Vec::new(),
                withheld: Vec::new(),
                not_covered: Vec::new(),
                evidence: Vec::new(),
            }],
            candidates: Vec::new(),
        };

        assert_eq!(
            survey_coverage_gaps(&family),
            vec![MissingQualification::LiveSurveyInvalidInput],
        );
    }
}
