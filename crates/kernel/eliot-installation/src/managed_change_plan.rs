//! Side-effect-free compilation of one managed environment change request
//! against the exact survey, the exact accepted catalogue revision and the
//! exact admitted approval it is planned from.
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
//!
//! The catalogue is likewise never taken from a bare revision string. A
//! catalogue that merely declares `origin` and `revision` has proved nothing
//! about who accepted it, so compilation requires an
//! [`AcceptedIntegrationCatalogue`](super::AcceptedIntegrationCatalogue),
//! which can only be obtained by verifying the actual retained bytes of the
//! System Owner's signed configuration publication against the
//! installation-pinned trust anchor. The plan records the exact survey content
//! digest, the accepted catalogue revision, and the signed publication
//! reference that admitted it, so a stale survey, a changed catalogue or a
//! changed approval all fail at use time instead of carrying an effect.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::{
    AcceptedIntegrationCatalogue, InstallationError, InstallationProfile, InstallationSurvey,
    ManagedChangeApproval, ManagedEnvironmentAction, ManagedEnvironmentChangeRequest,
    ManagedEffectRecipe, PlatformHandle, SurveyFamilyReport, SurveyStage, SurveyStageOutcome,
    VerifiedSetupBinding, handle, is_lower_sha256, resolve_bounded_probe, sha256_handle,
};

/// The unique native file observation that belongs to one surveyed target.
///
/// `path` is copied from the original identity-stage observation; it is never
/// inferred from the opaque file identity. The separate identity member makes
/// the path and digest inseparable from the exact surveyed installation they
/// describe.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NativeFileObservation {
    /// Exact target identity reported by the native identity stage.
    pub(crate) target_identity: PlatformHandle,
    /// Exact input path inspected by that identity-stage observation.
    pub(crate) path: PlatformHandle,
    /// Lowercase SHA-256 measured from the native file handle.
    pub(crate) sha256: PlatformHandle,
}

impl NativeFileObservation {
    fn validate_for_target(
        &self,
        target_identity: &PlatformHandle,
    ) -> Result<(), InstallationError> {
        handle(
            &self.target_identity,
            "managed_change_plan.target_executable_observation.target_identity",
        )?;
        handle(
            &self.path,
            "managed_change_plan.target_executable_observation.path",
        )?;
        sha256_handle(
            &self.sha256,
            "managed_change_plan.target_executable_observation.sha256",
        )?;
        if &self.target_identity != target_identity {
            return Err(InstallationError::IdentityConflict);
        }
        Ok(())
    }
}

/// One immutable, side-effect-free plan compiled from an exact survey.
///
/// The plan is the frozen denominator of a requested change: it carries the
/// governing request unchanged, the digest of the exact survey content it was
/// compiled from, the accepted catalogue revision and the signed publication
/// reference that admitted that revision, the family's discovery category,
/// every identity the survey actually observed for that family, the one current
/// target identity the request resolves to, and the profile, root and trust
/// revisions the admitted authority was verified under. Every one of those
/// bindings is re-checked by [`ManagedEnvironmentChangePlan::validate`] and
/// again against current state by [`revalidate_managed_change_plan`].
///
/// For `Install` the target is by definition not the surveyed installation, so
/// `target_identity` is `None` and the observed identities are what the change
/// is planned against. For every other action the request must name an identity
/// the survey actually observed, because a change to something the survey never
/// saw is not a change to a current installation.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
pub struct ManagedEnvironmentChangePlan {
    /// The governing request, bound unchanged.
    pub(crate) request: ManagedEnvironmentChangeRequest,
    /// Exact System Owner approval reloaded from the signed configuration
    /// snapshot that admitted the catalogue.
    pub(crate) approval: ManagedChangeApproval,
    /// Exact signed typed package/effect recipe selected for the request.
    pub(crate) effect_recipe: ManagedEffectRecipe,
    /// Lowercase SHA-256 of the canonical exact survey this plan was compiled
    /// from.
    ///
    /// This is bound to the survey's own content, not to a caller-supplied
    /// label, so a survey replaced after planning no longer matches. It is a
    /// content digest of a value the caller still holds; it is not preserved
    /// evidence standing in for unavailable bytes.
    pub(crate) survey_content_digest: PlatformHandle,
    /// Catalogue origin of the accepted revision this plan was compiled from.
    pub(crate) catalogue_origin: PlatformHandle,
    /// Accepted catalogue revision this plan was compiled from.
    pub(crate) catalogue_revision: u64,
    /// Retained signed configuration publication that admitted that revision.
    pub(crate) catalogue_publication_ref: PlatformHandle,
    /// System Owner whose verified signature admitted that revision.
    pub(crate) catalogue_accepted_by: PlatformHandle,
    /// Catalogue family this plan changes.
    pub(crate) family_id: PlatformHandle,
    /// Discovery category carried by the validated catalogue entry.
    pub(crate) category: super::IntegrationCategory,
    /// Every exact identity the survey observed for this family, ascending.
    pub(crate) observed_target_identities: Vec<PlatformHandle>,
    /// The one current target identity this request resolves to, when the
    /// action acts on an observed installation.
    pub(crate) target_identity: Option<PlatformHandle>,
    /// Exact native executable path and digest reported for this target by the
    /// original identity-stage survey. Missing or ambiguous native evidence is
    /// retained as `None`, never replaced by the new package's digest.
    pub(crate) target_executable_observation: Option<NativeFileObservation>,
    /// The bounded, non-secret probe invocation the accepted revision admits for
    /// the exact target identity, frozen into this plan.
    ///
    /// `None` means the accepted revision admits no probe for this identity;
    /// it never means "run something else". The plan stays valid when this is
    /// `None`, because a family need not declare any probe.
    pub(crate) target_probe: Option<super::BoundedProbeInvocation>,
    /// System Owner the admitted authority confirmed.
    pub(crate) confirmed_owner: PlatformHandle,
    /// Profile the admitted authority was verified under.
    pub(crate) profile: InstallationProfile,
    /// Runtime root topology digest the admitted authority was verified under.
    pub(crate) runtime_state_roots_digest: PlatformHandle,
    /// Durable setup revision the admitted authority was verified under.
    pub(crate) setup_revision: u64,
    /// Signed configuration snapshot the admitted authority was verified
    /// against.
    pub(crate) configuration_snapshot_ref: PlatformHandle,
    /// Non-wire brand installed only by the accepted signed-snapshot
    /// compilation path.
    #[serde(skip)]
    #[schemars(skip)]
    compilation_seal: PlanCompilationSeal,
}

#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq)]
struct PlanCompilationSeal;

/// Passive retained fields. Restoring this wire is crate-private and does not
/// issue an accepted catalogue, owner approval, or effect authority.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RetainedManagedChangePlan {
    request: ManagedEnvironmentChangeRequest,
    approval: ManagedChangeApproval,
    effect_recipe: ManagedEffectRecipe,
    survey_content_digest: PlatformHandle,
    catalogue_origin: PlatformHandle,
    catalogue_revision: u64,
    catalogue_publication_ref: PlatformHandle,
    catalogue_accepted_by: PlatformHandle,
    family_id: PlatformHandle,
    category: super::IntegrationCategory,
    observed_target_identities: Vec<PlatformHandle>,
    target_identity: Option<PlatformHandle>,
    #[serde(default)]
    target_executable_observation: Option<NativeFileObservation>,
    target_probe: Option<super::BoundedProbeInvocation>,
    confirmed_owner: PlatformHandle,
    profile: InstallationProfile,
    runtime_state_roots_digest: PlatformHandle,
    setup_revision: u64,
    configuration_snapshot_ref: PlatformHandle,
}

impl ManagedEnvironmentChangePlan {
    /// Restores passive fields from the original validated transaction's
    /// retained bytes. Every field is validated; callers must independently
    /// reopen signed catalogue/approval and current owner bindings before use.
    pub(crate) fn from_retained_json(encoded: &str) -> Result<Self, InstallationError> {
        let wire: RetainedManagedChangePlan = serde_json::from_str(encoded)
            .map_err(|_| InstallationError::IdentityConflict)?;
        let plan = Self {
            request: wire.request,
            approval: wire.approval,
            effect_recipe: wire.effect_recipe,
            survey_content_digest: wire.survey_content_digest,
            catalogue_origin: wire.catalogue_origin,
            catalogue_revision: wire.catalogue_revision,
            catalogue_publication_ref: wire.catalogue_publication_ref,
            catalogue_accepted_by: wire.catalogue_accepted_by,
            family_id: wire.family_id,
            category: wire.category,
            observed_target_identities: wire.observed_target_identities,
            target_identity: wire.target_identity,
            target_executable_observation: wire.target_executable_observation,
            target_probe: wire.target_probe,
            confirmed_owner: wire.confirmed_owner,
            profile: wire.profile,
            runtime_state_roots_digest: wire.runtime_state_roots_digest,
            setup_revision: wire.setup_revision,
            configuration_snapshot_ref: wire.configuration_snapshot_ref,
            compilation_seal: PlanCompilationSeal,
        };
        plan.validate()?;
        Ok(plan)
    }

    /// Returns the exact approved request compiled into this plan.
    #[must_use]
    pub const fn request(&self) -> &ManagedEnvironmentChangeRequest {
        &self.request
    }

    /// Returns the exact owner-signed approval compiled into this plan.
    #[must_use]
    pub const fn approval(&self) -> &ManagedChangeApproval {
        &self.approval
    }

    /// Returns the exact signed portable effect recipe selected at admission.
    #[must_use]
    pub const fn effect_recipe(&self) -> &ManagedEffectRecipe {
        &self.effect_recipe
    }

    /// Returns the selected installation profile.
    #[must_use]
    pub const fn profile(&self) -> InstallationProfile {
        self.profile
    }

    /// Returns the signed catalogue revision.
    #[must_use]
    pub const fn catalogue_revision(&self) -> u64 {
        self.catalogue_revision
    }

    /// Returns the exact target identity, if the action names an observed
    /// candidate.
    #[must_use]
    pub const fn target_identity(&self) -> Option<&PlatformHandle> {
        self.target_identity.as_ref()
    }

    /// Returns the original target identity, native path and SHA-256 together
    /// when the ordered survey observed one unambiguous native file row.
    #[must_use]
    pub const fn target_executable_observation(
        &self,
    ) -> Option<(&PlatformHandle, &PlatformHandle, &PlatformHandle)> {
        match (&self.target_identity, &self.target_executable_observation) {
            (Some(target_identity), Some(observation)) => Some((
                target_identity,
                &observation.path,
                &observation.sha256,
            )),
            _ => None,
        }
    }

    /// Returns the exact bounded probe contract frozen for the target, when
    /// the accepted catalogue declared one for that identity.
    #[must_use]
    pub const fn target_probe(&self) -> Option<&super::BoundedProbeInvocation> {
        self.target_probe.as_ref()
    }

    /// Returns the family identity.
    #[must_use]
    pub const fn family_id(&self) -> &PlatformHandle {
        &self.family_id
    }

    /// Returns the signed configuration publication that admitted catalogue
    /// and approval.
    #[must_use]
    pub const fn catalogue_publication_ref(&self) -> &PlatformHandle {
        &self.catalogue_publication_ref
    }

    /// Returns the exact survey content binding.
    #[must_use]
    pub const fn survey_content_digest(&self) -> &PlatformHandle {
        &self.survey_content_digest
    }

    /// Returns the owner the setup binding verified.
    #[must_use]
    pub const fn confirmed_owner(&self) -> &PlatformHandle {
        &self.confirmed_owner
    }

    /// Returns the setup binding's runtime-root topology digest.
    #[must_use]
    pub const fn runtime_state_roots_digest(&self) -> &PlatformHandle {
        &self.runtime_state_roots_digest
    }

    /// Returns the admitted setup revision.
    #[must_use]
    pub const fn setup_revision(&self) -> u64 {
        self.setup_revision
    }

    /// Returns the signed setup snapshot reference.
    #[must_use]
    pub const fn configuration_snapshot_ref(&self) -> &PlatformHandle {
        &self.configuration_snapshot_ref
    }

    /// Revalidates every internal binding without touching a survey, a
    /// catalogue or an external effect.
    ///
    /// The request is checked through its own existing `validate()` rather than
    /// a second copy of those rules.
    pub fn validate(&self) -> Result<(), InstallationError> {
        let _compilation_seal = self.compilation_seal;
        self.request.validate()?;
        self.approval.validate()?;
        self.effect_recipe.validate()?;
        if self.approval.request != self.request
            || self.effect_recipe.action != self.request.action
            || self.effect_recipe.target_family != self.request.target_family
            || (self.request.action == ManagedEnvironmentAction::Install
                && self.request.exact_candidate != self.effect_recipe.package_version)
        {
            return Err(InstallationError::IdentityConflict);
        }
        if self.profile != InstallationProfile::PortableDev {
            return Err(InstallationError::ProfileViolation(
                "portable managed effects require the selected PortableDev profile".to_owned(),
            ));
        }
        if is_protected_core_family(&self.family_id) {
            return Err(InstallationError::ProfileViolation(
                "active core components require their side-by-side generation owner".to_owned(),
            ));
        }
        self.validate_bound_values()?;
        if self.family_id != self.request.target_family {
            return Err(InstallationError::IdentityConflict);
        }
        if self.confirmed_owner != self.request.required_owner {
            return Err(InstallationError::IdentityConflict);
        }
        // The catalogue acceptance and the installation approval are two
        // different authorities. A plan whose catalogue was accepted by one
        // System Owner and whose installation was approved by another is not a
        // coherent plan, and neither is a plan whose acceptance is not
        // attributable to the retained signed publication it names.
        if self.catalogue_accepted_by != self.confirmed_owner {
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
            (ManagedEnvironmentAction::Install, Some(_)) => Err(InstallationError::InvalidField {
                field: "managed_change_plan.target_identity".to_owned(),
                reason: "an install request resolves no current target identity".to_owned(),
            }),
            (_, None) => Err(InstallationError::IncompleteObservation(
                "a non-install request must name a target identity the survey observed".to_owned(),
            )),
            (_, Some(identity)) => {
                if !self.observed_target_identities.contains(identity) {
                    return Err(InstallationError::IncompleteObservation(
                        "the requested target identity was not observed by this survey".to_owned(),
                    ));
                }
                Ok(())
            }
        }?;
        match (&self.target_identity, &self.target_executable_observation) {
            (None, None) | (Some(_), None) => {}
            (Some(identity), Some(observation)) => observation.validate_for_target(identity)?,
            (None, Some(_)) => return Err(InstallationError::IdentityConflict),
        }
        self.validate_target_probe()
    }

    /// Checks the plan's own bound values: that each is a well-formed handle,
    /// that the survey digest is a real lowercase SHA-256, and that the two
    /// revision counters the plan claims to have been compiled under are
    /// non-zero.
    ///
    /// These checks read nothing but the plan, so a caller can prove a frozen
    /// plan is self-consistent without holding the survey, the catalogue or the
    /// authority it was compiled from. They assert shape only: that a value is
    /// well-formed proves nothing about whether it is the *right* value, which
    /// is what the cross-checks in [`Self::validate`] establish.
    fn validate_bound_values(&self) -> Result<(), InstallationError> {
        for (value, field) in [
            (
                &self.survey_content_digest,
                "managed_change_plan.survey_content_digest",
            ),
            (
                &self.catalogue_origin,
                "managed_change_plan.catalogue_origin",
            ),
            (
                &self.catalogue_publication_ref,
                "managed_change_plan.catalogue_publication_ref",
            ),
            (
                &self.catalogue_accepted_by,
                "managed_change_plan.catalogue_accepted_by",
            ),
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
        if !is_lower_sha256(self.survey_content_digest.as_str()) {
            return Err(InstallationError::InvalidField {
                field: "managed_change_plan.survey_content_digest".to_owned(),
                reason: "must be a lowercase SHA-256 digest".to_owned(),
            });
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
        Ok(())
    }

    /// Checks the frozen probe, when there is one, is the probe this plan
    /// resolved for this family and this exact target identity.
    ///
    /// A frozen probe is only meaningful against the identity it was resolved
    /// for, on the family it was resolved from. A probe that names any other
    /// family, or any other executable identity than the plan's
    /// `target_identity`, is a contract for something other than the change
    /// this plan describes.
    fn validate_target_probe(&self) -> Result<(), InstallationError> {
        let Some(probe) = &self.target_probe else {
            return Ok(());
        };
        handle(&probe.probe_id, "managed_change_plan.target_probe.probe_id")?;
        handle(
            &probe.executable_identity,
            "managed_change_plan.target_probe.executable_identity",
        )?;
        handle(
            &probe.working_area,
            "managed_change_plan.target_probe.working_area",
        )?;
        if probe.family_id != self.family_id
            || self.target_identity.as_ref() != Some(&probe.executable_identity)
        {
            return Err(InstallationError::IdentityConflict);
        }
        Ok(())
    }
}

/// Returns the canonical content digest of one exact survey.
///
/// The digest covers the survey's complete canonical content, so a survey that
/// gained, lost or changed any observation, stage result or candidate is a
/// different digest rather than the same label.
pub(crate) fn survey_content_digest(
    survey: &InstallationSurvey,
) -> Result<PlatformHandle, InstallationError> {
    let bytes =
        super::canonical_json_bytes(survey).map_err(|error| InstallationError::InvalidField {
            field: "survey".to_owned(),
            reason: format!("survey content could not be canonicalized: {error}"),
        })?;
    PlatformHandle::new(super::sha256_hex(&bytes)).map_err(|error| {
        InstallationError::InvalidField {
            field: "managed_change_plan.survey_content_digest".to_owned(),
            reason: error.to_string(),
        }
    })
}

/// Compiles one request against the exact survey, the exact accepted catalogue
/// revision and the exact admitted approval, without any side effect.
///
/// The catalogue is an [`AcceptedIntegrationCatalogue`], so the revision was
/// admitted by verifying the System Owner's actual retained signed
/// configuration bytes against the installation-pinned trust anchor; a bare
/// `IntegrationDiscoveryCatalogue` with a self-declared `revision` string is
/// not accepted here. The survey must come from exactly that revision, and the
/// request must name the family the admitted authority confirmed, so a caller's
/// own `required_owner` field never stands in for approval.
///
/// The request's `exact_candidate` is resolved as an observed survey identity,
/// never as a bare category name: a category is carried only as the validated
/// recipe's category and is never sufficient to select a target.
///
/// # Errors
/// Returns [`InstallationError`] when the request, catalogue, survey or
/// authority is invalid, when the survey does not come from the accepted
/// catalogue revision, when the survey does not cover the requested family, or
/// when the request and the admitted authority disagree.
pub(crate) fn compile_managed_change_plan(
    request: &ManagedEnvironmentChangeRequest,
    accepted: &AcceptedIntegrationCatalogue,
    survey: &InstallationSurvey,
    authority: &VerifiedSetupBinding,
    approval: &ManagedChangeApproval,
    effect_recipe: &ManagedEffectRecipe,
) -> Result<ManagedEnvironmentChangePlan, InstallationError> {
    request.validate()?;
    survey.validate()?;
    let catalogue = accepted.catalogue();
    if survey.catalogue_origin != catalogue.origin
        || survey.catalogue_revision != catalogue.revision
    {
        return Err(InstallationError::IdentityConflict);
    }
    let entry = catalogue.entry(&request.target_family)?;
    effect_recipe.validate()?;
    if effect_recipe.action != request.action
        || effect_recipe.target_family != request.target_family
        || (request.action == ManagedEnvironmentAction::Install
            && request.exact_candidate != effect_recipe.package_version)
        || approval.request != *request
        || approval.catalogue_origin != *accepted.origin()
        || approval.catalogue_revision != accepted.revision()
        || approval.approved_by != *accepted.accepted_by()
        || approval.profile != authority.profile()
        || approval.runtime_state_roots_digest != *authority.runtime_state_roots_digest()
        || approval.setup_revision != authority.setup_revision()
        || approval.snapshot_id.as_str() != authority.snapshot_id()
    {
        return Err(InstallationError::IdentityConflict);
    }
    if entry.managed_effect_for(request.action) != Some(effect_recipe) {
        return Err(InstallationError::IdentityConflict);
    }
    let family = surveyed_family(survey, &request.target_family)?;
    if family.category != entry.category {
        return Err(InstallationError::IdentityConflict);
    }
    if &request.required_owner != authority.confirmed_owner()
        || authority.confirmed_owner() != accepted.accepted_by()
    {
        return Err(InstallationError::IdentityConflict);
    }

    let observed_target_identities = family
        .candidates
        .iter()
        .map(|candidate| candidate.observed_identity.clone())
        .collect::<Vec<_>>();
    let target_identity = match request.action {
        ManagedEnvironmentAction::Install => None,
        ManagedEnvironmentAction::Update
        | ManagedEnvironmentAction::Repair
        | ManagedEnvironmentAction::Remove
        | ManagedEnvironmentAction::Register
        | ManagedEnvironmentAction::Reconfigure => Some(request.exact_candidate.clone()),
    };
    let target_executable_observation =
        target_native_file_observation(family, target_identity.as_ref())?;
    // A probe may only be planned against an identity this exact survey
    // resolved, and only through a bounded contract the accepted revision
    // declares for that exact identity. Freezing the resolved invocation in
    // the plan is what makes the argument contract part of the immutable plan
    // instead of a value an effect executor chooses later; `None` is an
    // ordinary outcome meaning this family admits no probe for this identity,
    // not a fallback to a wider probe.
    let target_probe = match &target_identity {
        Some(identity) => resolve_bounded_probe(catalogue, &request.target_family, identity)?,
        None => None,
    };

    let plan = ManagedEnvironmentChangePlan {
        request: request.clone(),
        approval: approval.clone(),
        effect_recipe: effect_recipe.clone(),
        compilation_seal: PlanCompilationSeal,
        target_probe,
        survey_content_digest: survey_content_digest(survey)?,
        catalogue_origin: survey.catalogue_origin.clone(),
        catalogue_revision: survey.catalogue_revision,
        catalogue_publication_ref: accepted.signed_publication_ref().clone(),
        catalogue_accepted_by: accepted.accepted_by().clone(),
        family_id: family.family_id.clone(),
        category: family.category,
        observed_target_identities,
        target_identity,
        target_executable_observation,
        confirmed_owner: authority.confirmed_owner().clone(),
        profile: authority.profile(),
        runtime_state_roots_digest: authority.runtime_state_roots_digest().clone(),
        setup_revision: authority.setup_revision(),
        configuration_snapshot_ref: authority.configuration_snapshot_ref().clone(),
    };
    plan.validate()?;
    Ok(plan)
}

/// Revalidates a frozen plan against the current survey, the current accepted
/// catalogue revision and the current admitted approval, and refuses it on any
/// drift.
///
/// This is the pre-effect precondition of `I3.3` step 4: a changed catalogue,
/// a changed survey, a changed executable identity, a changed family category
/// or a changed admitted authority makes the plan stale, and a stale plan must
/// not carry an effect. The survey is compared by exact content digest — the
/// plan names the exact survey it was compiled from, not merely "some survey of
/// revision N" — and the survey is revalidated rather than trusted.
///
/// Detecting drift between two dependent effects of a running transaction, and
/// retaining the effects already issued, is `I3.15` step 6 and is not
/// implemented here.
///
/// # Errors
/// Returns [`InstallationError`] when the plan, survey, catalogue or authority
/// is invalid, or when any bound value has changed since planning.
pub(crate) fn revalidate_managed_change_plan(
    plan: &ManagedEnvironmentChangePlan,
    accepted: &AcceptedIntegrationCatalogue,
    survey: &InstallationSurvey,
    authority: &VerifiedSetupBinding,
    approval: &ManagedChangeApproval,
) -> Result<(), InstallationError> {
    plan.validate()?;
    survey.validate()?;
    let catalogue = accepted.catalogue();
    if survey.catalogue_origin != plan.catalogue_origin
        || survey.catalogue_revision != plan.catalogue_revision
        || catalogue.origin != plan.catalogue_origin
        || catalogue.revision != plan.catalogue_revision
    {
        return Err(InstallationError::IdentityConflict);
    }
    // The exact survey this plan was compiled from, by content.
    if survey_content_digest(survey)? != plan.survey_content_digest {
        return Err(InstallationError::IdentityConflict);
    }
    // The exact accepted catalogue publication and the exact approval.
    if accepted.signed_publication_ref() != &plan.catalogue_publication_ref
        || accepted.accepted_by() != &plan.catalogue_accepted_by
        || approval != &plan.approval
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
    if entry.managed_effect_for(plan.request.action) != Some(&plan.effect_recipe) {
        return Err(InstallationError::IdentityConflict);
    }
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
    if let Some(identity) = &plan.target_identity
        && !observed.contains(identity)
    {
        return Err(InstallationError::IdentityConflict);
    }
    let current_target_executable_observation =
        target_native_file_observation(family, plan.target_identity.as_ref())?;
    if current_target_executable_observation != plan.target_executable_observation {
        return Err(InstallationError::IdentityConflict);
    }
    // Re-resolve the probe against the current accepted revision: a contract
    // added, removed or widened since planning changes what may be run, and a
    // changed executable identity means the frozen invocation no longer names
    // what is installed.
    let current_probe = match &plan.target_identity {
        Some(identity) => resolve_bounded_probe(catalogue, &plan.family_id, identity)?,
        None => None,
    };
    if current_probe != plan.target_probe {
        return Err(InstallationError::IdentityConflict);
    }
    Ok(())
}

/// Copies only one exact native file observation from the identity stage.
///
/// An absent row, incomplete metadata, or multiple rows for the same opaque
/// identity remains unknown. The caller never supplies a path or substitutes
/// an expected package digest.
fn target_native_file_observation(
    family: &SurveyFamilyReport,
    target_identity: Option<&PlatformHandle>,
) -> Result<Option<NativeFileObservation>, InstallationError> {
    let Some(target_identity) = target_identity else {
        return Ok(None);
    };
    let Some(candidate) = family
        .candidates
        .iter()
        .find(|candidate| &candidate.observed_identity == target_identity)
    else {
        return Ok(None);
    };
    let identity_stage = family
        .stages
        .iter()
        .find(|stage| stage.stage == SurveyStage::FileVersionSignatureIdentity)
        .ok_or_else(|| {
            InstallationError::IncompleteObservation(
                "managed target survey has no file-identity stage".to_owned(),
            )
        })?;
    let mut observations = identity_stage
        .observations
        .iter()
        .filter(|observation| observation.observed_identity.as_ref() == Some(target_identity));
    let Some(observation) = observations.next() else {
        return Ok(None);
    };
    if observations.next().is_some()
        || observation.outcome != SurveyStageOutcome::Found
        || !candidate.aliases.contains(&observation.input)
    {
        return Ok(None);
    }
    let Some(file_version) = observation.file_version.as_ref() else {
        return Ok(None);
    };
    if !matches!(
        &file_version.outcome,
        eliot_platform_windows::FileVersionOutcome::Present { .. }
            | eliot_platform_windows::FileVersionOutcome::Absent
    ) {
        return Ok(None);
    }
    let Some(file_identity) = file_version.file_identity.as_ref() else {
        return Ok(None);
    };
    if file_identity.volume_serial_number == 0 || file_identity.file_index == 0 {
        return Ok(None);
    }
    let Some(sha256) = file_version.sha256.as_ref() else {
        return Ok(None);
    };
    let sha256 = PlatformHandle::new(sha256.clone()).map_err(|error| {
        InstallationError::InvalidField {
            field: "managed_change_plan.target_executable_observation.sha256".to_owned(),
            reason: error.to_string(),
        }
    })?;
    sha256_handle(
        &sha256,
        "managed_change_plan.target_executable_observation.sha256",
    )?;
    let native = NativeFileObservation {
        target_identity: target_identity.clone(),
        path: observation.input.clone(),
        sha256,
    };
    native.validate_for_target(target_identity)?;
    Ok(Some(native))
}

fn is_protected_core_family(family: &PlatformHandle) -> bool {
    [
        "surrealdb",
        "eliot_store_surreal",
        "eliot-host",
        "eliot_host",
        "eliot-kernel",
        "eliot_kernel",
        "eliot-watchdog",
        "eliot_watchdog",
    ]
    .iter()
    .any(|core| family.as_str().eq_ignore_ascii_case(core))
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
