//! Side-effect-free compilation of one managed environment change request
//! against the exact survey, catalogue and admitted authority it is planned
//! from.
//!
//! `I3.3` and `I3.3.1` make discovery an observation: a survey reports what was
//! seen, never what is installed, healthy, supported or admitted. This module
//! is the step-4 boundary where a
//! [`ManagedEnvironmentChangeRequest`](super::ManagedEnvironmentChangeRequest)
//! stops being a proposal and becomes a plan bound to those exact observations.
//! `I3.15` keeps it a plan only: nothing here installs, starts, stops,
//! reconfigures or removes anything, and the durable `InstallationTransaction`
//! stays the single effect owner. There is deliberately no effect port in this
//! module for the same reason the survey coordinator has no execution port.
//!
//! Authorization is never inferred from the request. A request's
//! `required_owner` is a caller-supplied field and a catalogue entry's
//! `managed_surfaces` is detection data, so neither is treated as permission
//! here: compilation requires a
//! [`VerifiedSetupBinding`](super::VerifiedSetupBinding) that an independent
//! trust anchor already admitted, and the request's `required_owner` must equal
//! that binding's confirmed owner. A caller cannot mint that value, so this
//! module never proves its own authorization.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::{
    InstallationError, InstallationProfile, InstallationSurvey, IntegrationCategory,
    IntegrationDiscoveryCatalogue, ManagedEnvironmentAction, ManagedEnvironmentChangeRequest,
    PlatformHandle, SurveyFamilyReport, VerifiedSetupBinding, handle,
};

/// One immutable, side-effect-free plan compiled from an exact survey.
///
/// The plan is the frozen denominator of a requested change: it carries the
/// governing request unchanged, the catalogue origin and revision the survey
/// was produced from, the family's discovery category, every identity the
/// survey actually observed for that family, the one current target identity
/// the request resolves to, and the profile, root and trust revisions the
/// admitted authority was verified under. Every one of those bindings is
/// re-checked by [`ManagedEnvironmentChangePlan::validate`] and again against
/// current state by [`revalidate_managed_change_plan`].
///
/// For `Install` the target is by definition not the surveyed installation, so
/// `target_identity` is `None` and the observed identities are what the change
/// is planned against. For every other action the request must name an identity
/// the survey actually observed, because a change to something the survey never
/// saw is not a change to a current installation.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedEnvironmentChangePlan {
    /// The governing request, bound unchanged.
    pub request: ManagedEnvironmentChangeRequest,
    /// Catalogue origin the survey and the plan were produced from.
    pub catalogue_origin: PlatformHandle,
    /// Catalogue revision the survey and the plan were produced from.
    pub catalogue_revision: u64,
    /// Catalogue family this plan changes.
    pub family_id: PlatformHandle,
    /// Discovery category carried by the validated catalogue entry.
    pub category: IntegrationCategory,
    /// Every exact identity the survey observed for this family, ascending.
    pub observed_target_identities: Vec<PlatformHandle>,
    /// The one current target identity this request resolves to, when the
    /// action acts on an observed installation.
    pub target_identity: Option<PlatformHandle>,
    /// System Owner the admitted authority confirmed.
    pub confirmed_owner: PlatformHandle,
    /// Profile the admitted authority was verified under.
    pub profile: InstallationProfile,
    /// Runtime root topology digest the admitted authority was verified under.
    pub runtime_state_roots_digest: PlatformHandle,
    /// Durable setup revision the admitted authority was verified under.
    pub setup_revision: u64,
    /// Signed configuration snapshot the admitted authority was verified
    /// against.
    pub configuration_snapshot_ref: PlatformHandle,
}

impl ManagedEnvironmentChangePlan {
    /// Revalidates every internal binding without touching a survey, a
    /// catalogue or an external effect.
    ///
    /// The request is checked through its own existing `validate()` rather than
    /// a second copy of those rules.
    pub fn validate(&self) -> Result<(), InstallationError> {
        self.request.validate()?;
        for (value, field) in [
            (&self.catalogue_origin, "managed_change_plan.catalogue_origin"),
            (&self.family_id, "managed_change_plan.family_id"),
            (&self.confirmed_owner, "managed_change_plan.confirmed_owner"),
            (
                &self.runtime_state_roots_digest,
                "managed_change_plan.runtime_state_roots_digest",
            ),
            (
                &self.configuration_snapshot_ref,
                "managed_change_plan.configuration_snapshot_ref",
            ),
        ] {
            handle(value, field)?;
        }
        if self.catalogue_revision == 0 {
            return Err(InstallationError::InvalidField {
                field: "managed_change_plan.catalogue_revision".to_owned(),
                reason: "must be non-zero".to_owned(),
            });
        }
        if self.setup_revision == 0 {
            return Err(InstallationError::InvalidField {
                field: "managed_change_plan.setup_revision".to_owned(),
                reason: "must be non-zero".to_owned(),
            });
        }
        if &self.family_id != &self.request.target_family {
            return Err(InstallationError::IdentityConflict);
        }
        if &self.confirmed_owner != &self.request.required_owner {
            return Err(InstallationError::IdentityConflict);
        }
        for pair in self.observed_target_identities.windows(2) {
            if pair[0] >= pair[1] {
                return Err(InstallationError::InvalidField {
                    field: "managed_change_plan.observed_target_identities".to_owned(),
                    reason: "must be sorted ascending and distinct".to_owned(),
                });
            }
        }
        for identity in &self.observed_target_identities {
            handle(identity, "managed_change_plan.observed_target_identities")?;
        }
        // The action decides whether this request names something already
        // surveyed, and the identity is required to be one of the observed
        // identities rather than merely well-formed: a name the survey never
        // resolved to an identity is not a current installation.
        match (&self.request.action, &self.target_identity) {
            (ManagedEnvironmentAction::Install, None) => Ok(()),
            (ManagedEnvironmentAction::Install, Some(_)) => {
                Err(InstallationError::InvalidField {
                    field: "managed_change_plan.target_identity".to_owned(),
                    reason: "an install request resolves no current target identity".to_owned(),
                })
            }
            (_, None) => Err(InstallationError::IncompleteObservation(
                "a non-install request must name a target identity the survey observed".to_owned(),
            )),
            (_, Some(identity)) => {
                if !self.observed_target_identities.contains(identity) {
                    return Err(InstallationError::IncompleteObservation(
                        "the requested target identity was not observed by this survey"
                            .to_owned(),
                    ));
                }
                Ok(())
            }
        }
    }
}

/// Compiles one request against the exact survey, catalogue and admitted
/// authority, without any side effect.
///
/// The catalogue is resolved through its own `entry()`, so the family must
/// exist in the catalogue the survey was produced from, and the survey must
/// cover that family: a request is never compiled against a family the survey
/// did not walk, because "not surveyed" and "not present" are different facts.
/// The request must name the family the admitted authority confirmed, so a
/// caller's own `required_owner` field never stands in for approval.
///
/// # Errors
/// Returns [`InstallationError`] when the request, catalogue, survey or
/// authority is invalid, when the survey does not cover the requested family,
/// or when the request and the admitted authority disagree.
pub fn compile_managed_change_plan(
    request: &ManagedEnvironmentChangeRequest,
    catalogue: &IntegrationDiscoveryCatalogue,
    survey: &InstallationSurvey,
    authority: &VerifiedSetupBinding,
) -> Result<ManagedEnvironmentChangePlan, InstallationError> {
    request.validate()?;
    survey.validate()?;
    if &survey.catalogue_origin != &catalogue.origin
        || survey.catalogue_revision != catalogue.revision
    {
        return Err(InstallationError::IdentityConflict);
    }
    let entry = catalogue.entry(&request.target_family)?;
    let family = surveyed_family(survey, &request.target_family)?;
    if family.category != entry.category {
        return Err(InstallationError::IdentityConflict);
    }
    if &request.required_owner != authority.confirmed_owner() {
        return Err(InstallationError::IdentityConflict);
    }

    let plan = ManagedEnvironmentChangePlan {
        request: request.clone(),
        catalogue_origin: survey.catalogue_origin.clone(),
        catalogue_revision: survey.catalogue_revision,
        family_id: family.family_id.clone(),
        category: family.category,
        observed_target_identities: family
            .candidates
            .iter()
            .map(|candidate| candidate.observed_identity.clone())
            .collect(),
        target_identity: match request.action {
            ManagedEnvironmentAction::Install => None,
            ManagedEnvironmentAction::Update
            | ManagedEnvironmentAction::Repair
            | ManagedEnvironmentAction::Remove
            | ManagedEnvironmentAction::Register
            | ManagedEnvironmentAction::Reconfigure => Some(request.exact_candidate.clone()),
        },
        confirmed_owner: authority.confirmed_owner().clone(),
        profile: authority.profile(),
        runtime_state_roots_digest: authority.runtime_state_roots_digest().clone(),
        setup_revision: authority.setup_revision(),
        configuration_snapshot_ref: authority.configuration_snapshot_ref().clone(),
    };
    plan.validate()?;
    Ok(plan)
}

/// Revalidates a frozen plan against the current survey, catalogue and admitted
/// authority, and refuses it on any drift.
///
/// This is the pre-effect precondition of `I3.3` step 4: a changed catalogue,
/// a changed executable identity, a changed family category or a changed
/// admitted authority makes the plan stale, and a stale plan must not carry an
/// effect. Every comparison is by content with this operation — the current
/// identities are compared to the recorded set, not merely checked for
/// presence — and the survey is revalidated rather than trusted.
///
/// Detecting drift between two dependent effects of a running transaction, and
/// retaining the effects already issued, is `I3.15` step 6 and is not
/// implemented here.
///
/// # Errors
/// Returns [`InstallationError`] when the plan, survey, catalogue or authority
/// is invalid, or when any bound value has changed since planning.
pub fn revalidate_managed_change_plan(
    plan: &ManagedEnvironmentChangePlan,
    catalogue: &IntegrationDiscoveryCatalogue,
    survey: &InstallationSurvey,
    authority: &VerifiedSetupBinding,
) -> Result<(), InstallationError> {
    plan.validate()?;
    survey.validate()?;
    if &survey.catalogue_origin != &plan.catalogue_origin
        || survey.catalogue_revision != plan.catalogue_revision
        || &catalogue.origin != &plan.catalogue_origin
        || catalogue.revision != plan.catalogue_revision
    {
        return Err(InstallationError::IdentityConflict);
    }
    if authority.confirmed_owner() != &plan.confirmed_owner
        || authority.profile() != plan.profile
        || authority.runtime_state_roots_digest() != &plan.runtime_state_roots_digest
        || authority.setup_revision() != plan.setup_revision
        || authority.configuration_snapshot_ref() != &plan.configuration_snapshot_ref
    {
        return Err(InstallationError::IdentityConflict);
    }
    let entry = catalogue.entry(&plan.family_id)?;
    let family = surveyed_family(survey, &plan.family_id)?;
    if family.category != entry.category || family.category != plan.category {
        return Err(InstallationError::IdentityConflict);
    }
    let observed = family
        .candidates
        .iter()
        .map(|candidate| candidate.observed_identity.clone())
        .collect::<Vec<_>>();
    if observed != plan.observed_target_identities {
        return Err(InstallationError::IdentityConflict);
    }
    if let Some(identity) = &plan.target_identity {
        if !observed.contains(identity) {
            return Err(InstallationError::IdentityConflict);
        }
    }
    Ok(())
}

/// Returns the one survey report for `family_id`, or refuses: a family the
/// survey did not walk is not a family with nothing installed.
fn surveyed_family<'a>(
    survey: &'a InstallationSurvey,
    family_id: &PlatformHandle,
) -> Result<&'a SurveyFamilyReport, InstallationError> {
    survey
        .families
        .iter()
        .find(|family| &family.family_id == family_id)
        .ok_or_else(|| {
            InstallationError::IncompleteObservation(
                "the requested family was not covered by this survey".to_owned(),
            )
        })
}
