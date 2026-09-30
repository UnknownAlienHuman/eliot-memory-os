//! Requalification before capability advertisement, and the non-admission of
//! an installed-but-unqualified candidate.
//!
//! `I3.3.1` keeps the discovery catalogue a detection surface: "Package-manager
//! success is installation evidence, not production admission", and a catalogue
//! update "cannot install software, grant credentials or advertise a capability
//! by itself". `I3.4` makes the same point about the evidence: production
//! admission requires matching `probe_passed` or `observed` evidence.
//!
//! The defect this module closes is a *remembered* qualification. A
//! [`ManagedEnvironmentChangePlan`](super::ManagedEnvironmentChangePlan) is a
//! frozen record of a check performed at plan time: it carries the survey
//! content digest, catalogue revision, publication and approval that were true
//! *then*. Reading those bindings and advertising on their strength advertises a
//! stale authority, because a qualification check is a check and not a receipt.
//!
//! So nothing here derives an advertisement from a plan's own fields. The
//! advertisement is derived from the **live** survey and the **live** accepted
//! catalogue, both re-derived through the existing
//! [`survey_accepted_installation`](super::survey_accepted_installation), which
//! reloads the System Owner's actual retained signed publication bytes and
//! re-verifies them against the installation-pinned trust anchor. The frozen
//! plan is admitted only as a *narrowing* — which family, which exact identity
//! — and may never supply the answer. A plan whose bindings no longer hold is
//! refused by the existing
//! [`revalidate_managed_change_plan`](super::revalidate_managed_change_plan),
//! so staleness produces a typed refusal rather than a stale advertisement.
//!
//! The second property is `I3.3.1`'s "Installed-but-unqualified remains
//! non-admitted". Presence is a fact about the filesystem; qualification is a
//! fact about policy, approval and catalogue. A present, executable, healthy
//! binary that was never approved therefore stays non-admitted here, and the
//! refusal names exactly which qualification is missing rather than collapsing
//! to a boolean. `admitted` is deliberately **not** a state this contour emits:
//! admission belongs to the Governor-owned capability registry of `I3.4` and is
//! reached only through submitted capability evidence, which no survey
//! observation can stand in for.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::{
    AcceptedCatalogueContext, AcceptedInstallationSurvey, InstallationError,
    ManagedChangeAdmissionError, ManagedChangeDispatch, ManagedEnvironmentAction,
    ManagedEnvironmentChangePlan, PlatformHandle, SurveyCandidate, SurveyObservationSource,
    SurveyProbeAdmission, handle, resolve_bounded_probe, revalidate_managed_change_plan,
    survey_accepted_installation,
};

/// The exact live values one advertisement was derived from.
///
/// Recorded so a consumer can answer *what was true when this advertisement was
/// made*. Every value is copied from the live accepted catalogue, the live
/// admitted authority and the live survey that
/// [`requalify_managed_capability`] just re-derived — never from the frozen
/// plan — so this struct cannot launder a stored plan into a current claim.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequalificationBinding {
    /// Catalogue origin of the revision the live survey was taken from.
    pub catalogue_origin: PlatformHandle,
    /// Accepted catalogue revision the live survey was taken from.
    pub catalogue_revision: u64,
    /// Retained signed publication that admitted that revision, live.
    pub catalogue_publication_ref: PlatformHandle,
    /// System Owner whose verified signature admitted that revision, live.
    pub catalogue_accepted_by: PlatformHandle,
    /// System Owner the live admitted authority confirmed.
    pub confirmed_owner: PlatformHandle,
    /// Profile the live admitted authority was verified under.
    pub profile: super::InstallationProfile,
    /// Runtime root topology digest the live authority was verified under.
    pub runtime_state_roots_digest: PlatformHandle,
    /// Durable setup revision the live authority was verified under.
    pub setup_revision: u64,
    /// Signed configuration snapshot the live authority was verified against.
    pub configuration_snapshot_ref: PlatformHandle,
    /// Content digest of the live survey this advertisement was derived from.
    pub survey_content_digest: PlatformHandle,
}

/// The exact qualification an advertised candidate is still missing.
///
/// Each variant names one thing the live survey did **not** establish. They are
/// never collapsed into "unavailable": an unproved qualification and an absent
/// installation are different facts, and only the first is a qualification gap.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MissingQualification {
    /// The accepted revision declares no bounded probe for this exact identity.
    ///
    /// A non-empty catalogue `safe_probes` list does not fill this gap: that
    /// list is detection data and is never read as permission to execute.
    NoBoundedProbeAdmittedForThisIdentity,
    /// A bounded probe is admitted for this identity, but no admitted executor
    /// has answered it.
    ///
    /// This is the ordinary state of a present binary. The survey coordinator
    /// runs no process, so nothing has probed it, and an unprobed executable is
    /// not a qualified one.
    NotProbedByAnAdmittedExecutor,
    /// The live survey did not observe the identity the plan names.
    ///
    /// A plan naming an identity the current survey no longer resolves is naming
    /// something that is not a current installation. This is a coverage fact
    /// about the live survey, never an assertion that nothing is installed.
    TargetNotObservedInTheLiveSurvey,
}

/// The closed set of states a surveyed candidate may be advertised in.
///
/// `I3.3.1` requires `discovered`, `declared`, `probed`, `admitted`, `degraded`
/// and `unsupported` to be reflected as distinct facts "rather than forcing them
/// into a single success ladder". Each variant is one such fact.
///
/// `admitted` is intentionally absent, and that is the point rather than an
/// unfinished arm. Admission is owned by the Governor capability registry of
/// `I3.4` and requires submitted capability evidence for an exact runtime and
/// adapter fingerprint. No state reachable from a metadata-only survey may claim
/// it, so an installation that is present, executable and healthy still reports
/// [`Self::Unsupported`] naming
/// [`MissingQualification::NotProbedByAnAdmittedExecutor`] until an admitted
/// executor actually probes it. That is what keeps an installed-but-unqualified
/// candidate non-admitted.
///
/// `degraded` is absent for the mirror reason. A degraded candidate is one whose
/// *previously admitted* evidence no longer holds, and this contour admits no
/// evidence, so it can never hold evidence to invalidate. Reporting `degraded`
/// here would be inferring a lifecycle stage from the absence of a current
/// answer — inferring a fact from the wrong fact, the same defect class as
/// reading admission off installation. `I3.4` degradation is derived by the
/// Governor registry from evidence this contour does not own.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum ManagedCapabilityStatus {
    /// The live survey resolved this exact identity and nothing more.
    ///
    /// `I3.3`: a discovered executable is not started automatically as a
    /// trusted Module. Finding it is the whole of this state.
    Discovered,
    /// The accepted revision declares a bounded probe for this exact identity,
    /// and nothing has run it.
    ///
    /// A declared *contract* to run, not a capability. The name of the probe is
    /// reported so a consumer can show what would be run, with no suggestion
    /// that running it is permitted from here.
    Declared {
        /// Catalogue probe recipe identity that would be invoked.
        probe_id: PlatformHandle,
    },
    /// An admitted executor answered the bounded probe for this exact identity.
    ///
    /// Probe evidence, still not admission: it is one observed property of one
    /// identity, and the `I3.4` registry decides what it means.
    Probed {
        /// Catalogue probe recipe identity that was answered.
        probe_id: PlatformHandle,
        /// Bounded, non-secret answer handles retained, ascending and distinct.
        answer_refs: Vec<PlatformHandle>,
    },
    /// This candidate is not admitted for capability use, and every missing
    /// qualification is named.
    Unsupported {
        /// Every qualification this candidate is still missing, ascending.
        missing: Vec<MissingQualification>,
    },
}

/// One candidate's requalified capability state, with its named gaps.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedCapabilityState {
    /// What is true about this candidate right now.
    pub status: ManagedCapabilityStatus,
    /// Every qualification this candidate is still missing, ascending.
    ///
    /// Empty exactly when `status` is [`ManagedCapabilityStatus::Probed`] or
    /// [`ManagedCapabilityStatus::Discovered`].
    pub missing: Vec<MissingQualification>,
}

/// One candidate's requalified capability advertisement.
///
/// This is what a consumer shows instead of the frozen plan. It always carries
/// the [`RequalificationBinding`] it was derived from, so "what is true now" is
/// answerable without trusting the plan it narrows.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedCapabilityAdvertisement {
    /// Catalogue family this advertisement is about.
    pub family_id: PlatformHandle,
    /// Discovery category carried by the validated live catalogue entry.
    pub category: super::IntegrationCategory,
    /// The exact identity being advertised, when the change acts on one.
    ///
    /// `None` for an `Install` plan, which by definition names no current
    /// installation: a prospective change advertises nothing about a candidate
    /// that does not exist yet.
    pub target_identity: Option<PlatformHandle>,
    /// What is true about this candidate right now.
    pub state: ManagedCapabilityState,
    /// The exact live values this advertisement was derived from.
    pub requalified_against: RequalificationBinding,
}

/// Which existing transaction owner may carry one compiled managed change.
///
/// The decision is a value rather than a side effect so it travels with the
/// compiled plan to whoever receives it: a consumer is told the owner, or is
/// told the named refusal, instead of being left to pick a dispatch contour.
/// Nothing here performs an effect or creates an operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ManagedChangeDispatch {
    /// One admitted owner may carry this change.
    Admitted {
        /// The request this decision belongs to.
        request_id: PlatformHandle,
        /// The single existing owner permitted to carry it.
        owner: ManagedChangeEffectOwner,
    },
    /// No admitted owner exists for this change on this contour.
    Refused {
        /// The request this decision belongs to.
        request_id: PlatformHandle,
        /// The typed refusal naming the action and family.
        refusal: ManagedEffectRoutingRefusal,
    },
}

impl ManagedChangeDispatch {
    /// Pairs one request identity with its routing decision.
    pub(crate) const fn new(
        request_id: PlatformHandle,
        decision: Result<ManagedChangeEffectOwner, ManagedEffectRoutingRefusal>,
    ) -> Self {
        match decision {
            Ok(owner) => Self::Admitted { request_id, owner },
            Err(refusal) => Self::Refused { request_id, refusal },
        }
    }

    /// Returns the request this decision belongs to.
    #[must_use]
    pub const fn request_id(&self) -> &PlatformHandle {
        match self {
            Self::Admitted { request_id, .. } | Self::Refused { request_id, .. } => request_id,
        }
    }

    /// Returns the admitted owner, or the named refusal.
    ///
    /// A refused change is never silently treated as unrouted: the caller gets
    /// the reason, so an action with no owner cannot be mistaken for one that
    /// merely has not been dispatched yet.
    #[must_use]
    pub const fn owner(&self) -> Result<ManagedChangeEffectOwner, &ManagedEffectRoutingRefusal> {
        match self {
            Self::Admitted { owner, .. } => Ok(*owner),
            Self::Refused { refusal, .. } => Err(refusal),
        }
    }
}

/// The one existing transaction owner permitted to carry a managed change.
///
/// `I3.3.1` compiles a request into "the existing `InstallationTransaction`,
/// Module-generation change or configuration transition", and naming the owner
/// explicitly — rather than letting a caller pick one — is what stops this
/// contour from becoming a second effect owner.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ManagedChangeEffectOwner {
    /// The existing durable canary/generation removal operation, which already
    /// persists effect intent before its platform call, proves its
    /// postconditions by authoritative readback, and reconciles a lost response
    /// against that persisted intent rather than repeating the effect.
    CanaryRemoval,
}

/// A managed change that has no admitted effect owner on this contour.
///
/// A refusal, not a deferral and not a fallback. `I3.3.1` requires optional
/// external tool installation to use "a narrow effect adapter", and the
/// `InstallerEffectPlan` vocabulary of the installation transaction holds no
/// such effect. Rather than widening that vocabulary with a generic
/// run-command port, this names the owner the request has to reach.
#[derive(Clone, Debug, Eq, thiserror::Error, PartialEq)]
pub enum ManagedEffectRoutingRefusal {
    /// No admitted effect owner exists for this action on this contour.
    #[error(
        "managed {action:?} of catalogue family {family} has no admitted effect owner; it must \
         be carried by its own owner through the installation, module-generation or configuration \
         path, never by the generic managed-tool path"
    )]
    NoAdmittedEffectOwner {
        /// Requested action that has no admitted owner here.
        action: ManagedEnvironmentAction,
        /// Catalogue family whose change was refused.
        family: PlatformHandle,
    },
}

/// Requalifies one frozen plan against live state and derives the capability
/// advertisement a consumer may show.
///
/// This is the W7 seam, shaped so requalification can be neither skipped nor
/// replaced by a stored answer:
///
/// 1. the accepted catalogue revision is **reloaded** from the System Owner's
///    actual retained signed publication bytes and re-verified against the
///    installation-pinned trust anchor, and the ordered survey is **re-run**,
///    through the existing
///    [`survey_accepted_installation`](super::survey_accepted_installation);
/// 2. the frozen plan is admitted only as a narrowing, and is refused by the
///    existing
///    [`revalidate_managed_change_plan`](super::revalidate_managed_change_plan)
///    when the live survey content digest, catalogue revision, publication,
///    approval, observed identities or resolved probe contract no longer agree;
/// 3. only then is the state derived — from the **live** survey, never from the
///    plan's own bindings.
///
/// Step 3 is what makes this a live re-proof rather than a record read. A stale
/// plan is refused at step 2; a present-but-unprobed candidate is reported at
/// step 3 naming the qualification it lacks. Neither outcome is reachable by
/// holding the plan.
///
/// # Errors
/// Returns [`ManagedChangeAdmissionError`] when no accepted catalogue revision
/// loads for the observed platform, when the live survey or catalogue refuses,
/// or when the frozen plan no longer agrees with live state. In every one of
/// those cases the advertisement is refused; it is never produced from the
/// stored plan.
pub fn requalify_managed_capability(
    frozen_plan: &ManagedEnvironmentChangePlan,
    context: &AcceptedCatalogueContext<'_>,
    source: &dyn SurveyObservationSource,
) -> Result<ManagedCapabilityAdvertisement, ManagedChangeAdmissionError> {
    // Step 1 — live re-proof. Reloads and re-verifies the accepted catalogue
    // publication and re-runs the ordered survey. Nothing below reads a stored
    // qualification.
    let live = survey_accepted_installation(context, source)?;

    // Step 2 — the frozen plan may narrow, never answer. The existing
    // revalidator is the only thing that decides whether the plan is still
    // current, and it is called against the live values. None of its rules are
    // repeated here.
    revalidate_managed_change_plan(frozen_plan, &live.accepted, &live.survey, context.authority)?;

    // Step 3 — derive the state from the live survey.
    let advertisement = derive_advertisement(frozen_plan, &live, context.authority)?;
    validate_advertisement(&advertisement)?;
    Ok(advertisement)
}

/// Derives the requalified advertisement from the live survey.
///
/// The plan contributes only `family_id`, `category` and `target_identity`; every
/// fact about the candidate — whether it was observed, whether a bounded probe
/// is admitted for it, whether an admitted executor answered — is read from
/// `live`.
fn derive_advertisement(
    frozen_plan: &ManagedEnvironmentChangePlan,
    live: &AcceptedInstallationSurvey,
    authority: &super::VerifiedSetupBinding,
) -> Result<ManagedCapabilityAdvertisement, InstallationError> {
    let requalified_against = live_binding(live, authority)?;
    let Some(target_identity) = frozen_plan.target_identity.clone() else {
        // An `Install` plan names no current installation. A prospective change
        // says nothing about a candidate that does not exist yet, so the honest
        // state is `discovered` for the family and no identity is advertised.
        return Ok(ManagedCapabilityAdvertisement {
            family_id: frozen_plan.family_id.clone(),
            category: frozen_plan.category,
            target_identity: None,
            state: ManagedCapabilityState {
                status: ManagedCapabilityStatus::Discovered,
                missing: Vec::new(),
            },
            requalified_against,
        });
    };

    let candidate = live
        .survey
        .families
        .iter()
        .find(|family| family.family_id == frozen_plan.family_id)
        .and_then(|family| {
            family
                .candidates
                .iter()
                .find(|candidate| candidate.observed_identity == target_identity)
        });
    let state = classify_candidate(live, &frozen_plan.family_id, candidate)?;

    Ok(ManagedCapabilityAdvertisement {
        family_id: frozen_plan.family_id.clone(),
        category: frozen_plan.category,
        target_identity: Some(target_identity),
        state,
        requalified_against,
    })
}

/// Classifies one live candidate into the state it is actually in.
///
/// Reads only the live accepted catalogue and the live survey. Presence of the
/// identity gets it no further than `declared`, and `declared` is a contract to
/// run, not a capability.
fn classify_candidate(
    live: &AcceptedInstallationSurvey,
    family_id: &PlatformHandle,
    candidate: Option<&SurveyCandidate>,
) -> Result<ManagedCapabilityState, InstallationError> {
    let Some(candidate) = candidate else {
        return Ok(unsupported(&[
            MissingQualification::TargetNotObservedInTheLiveSurvey,
        ]));
    };

    // The bounded probe contract is resolved from the live accepted catalogue
    // for this exact identity. `resolve_bounded_probe` never reads the
    // catalogue's `safe_probes` strings, so a declared probe name alone cannot
    // produce a contract, and its refusal is propagated rather than flattened
    // into an absence.
    let Some(invocation) = resolve_bounded_probe(
        live.accepted.catalogue(),
        family_id,
        &candidate.observed_identity,
    )?
    else {
        return Ok(unsupported(&[
            MissingQualification::NoBoundedProbeAdmittedForThisIdentity,
        ]));
    };

    if candidate.probe_admission != SurveyProbeAdmission::AnsweredByAdmittedExecutor {
        // Installed, present, runnable — and not qualified. The missing
        // qualification is named rather than reported as a boolean.
        return Ok(ManagedCapabilityState {
            status: ManagedCapabilityStatus::Declared {
                probe_id: invocation.probe_id,
            },
            missing: vec![MissingQualification::NotProbedByAnAdmittedExecutor],
        });
    }

    Ok(ManagedCapabilityState {
        status: ManagedCapabilityStatus::Probed {
            probe_id: invocation.probe_id,
            answer_refs: candidate.probe_answers.clone(),
        },
        missing: Vec::new(),
    })
}

/// Builds the `unsupported` state naming every missing qualification.
fn unsupported(missing: &[MissingQualification]) -> ManagedCapabilityState {
    let mut missing = missing.to_vec();
    missing.sort_unstable();
    missing.dedup();
    ManagedCapabilityState {
        status: ManagedCapabilityStatus::Unsupported {
            missing: missing.clone(),
        },
        missing,
    }
}

/// Copies the binding out of the freshly re-derived live values.
///
/// Every field comes from the live accepted catalogue, the live admitted
/// authority or the live survey content. Nothing is substituted, defaulted or
/// recomputed to make a comparison succeed: an unreadable owner is a typed
/// refusal upstream in `requalify_managed_capability`, never a placeholder here.
fn live_binding(
    live: &AcceptedInstallationSurvey,
    authority: &super::VerifiedSetupBinding,
) -> Result<RequalificationBinding, InstallationError> {
    Ok(RequalificationBinding {
        catalogue_origin: live.survey.catalogue_origin.clone(),
        catalogue_revision: live.survey.catalogue_revision,
        catalogue_publication_ref: live.accepted.signed_publication_ref().clone(),
        catalogue_accepted_by: live.accepted.accepted_by().clone(),
        confirmed_owner: authority.confirmed_owner().clone(),
        profile: authority.profile(),
        runtime_state_roots_digest: authority.runtime_state_roots_digest().clone(),
        setup_revision: authority.setup_revision(),
        configuration_snapshot_ref: authority.configuration_snapshot_ref().clone(),
        survey_content_digest: survey_content_digest(&live.survey)?,
    })
}

/// Returns the canonical content digest of one exact survey.
///
/// The same canonicalisation the existing plan compiler uses, so this digest is
/// directly comparable with
/// [`ManagedEnvironmentChangePlan::survey_content_digest`] rather than being a
/// second, differently-computed notion of survey identity. The comparison is
/// therefore against the original recorded value; no digest is ever recomputed
/// to make a comparison succeed.
///
/// # Errors
/// Returns [`InstallationError::InvalidField`] when the survey cannot be
/// canonicalized. A survey with no computable content binding is not advertised
/// at all: substituting a placeholder here would be reporting a binding nobody
/// proved, and "could not canonicalize" is never "nothing to bind".
fn survey_content_digest(
    survey: &super::InstallationSurvey,
) -> Result<PlatformHandle, InstallationError> {
    let bytes = super::canonical_json_bytes(survey).map_err(|error| {
        InstallationError::InvalidField {
            field: "advertisement.requalified_against.survey_content_digest".to_owned(),
            reason: format!("live survey could not be canonicalized: {error}"),
        }
    })?;
    PlatformHandle::new(super::sha256_hex(&bytes)).map_err(|error| {
        InstallationError::InvalidField {
            field: "advertisement.requalified_against.survey_content_digest".to_owned(),
            reason: error.to_string(),
        }
    })
}

/// Names the one existing transaction owner permitted to carry this change, or
/// refuses.
///
/// `I3.3.1`: "The request is compiled into the existing `InstallationTransaction`,
/// Module-generation change or configuration transition. An agent or Dreamer
/// never runs `winget`, `scoop`, `choco`, `npm`, `uv/pipx`, `cargo install`, an
/// updater or a downloaded installer directly as authority."
///
/// Only `Remove` has an admitted owner on this contour: the existing durable
/// canary/generation removal operation, which persists effect intent before its
/// platform call, proves its postconditions by authoritative readback, and
/// reconciles a lost response against that persisted intent rather than
/// repeating the effect. Every other action is refused by name, because the
/// `InstallerEffectPlan` vocabulary of the installation transaction holds no
/// external-tool effect and adding one would be the generic run-command port
/// `I3.3.1` prohibits.
///
/// A wrong-owner dispatch would have looked like: reading a catalogue recipe's
/// `managed_surfaces` entry, treating that detection string as an install
/// surface, and driving a package manager from this contour — an effect with no
/// persisted intent, no authoritative readback and no recovery, owned by nobody.
///
/// # Errors
/// Returns [`ManagedEffectRoutingRefusal::NoAdmittedEffectOwner`] for every
/// action other than `Remove`.
pub fn route_managed_change_to_effect_owner(
    frozen_plan: &ManagedEnvironmentChangePlan,
) -> Result<ManagedChangeEffectOwner, ManagedEffectRoutingRefusal> {
    match frozen_plan.request.action {
        ManagedEnvironmentAction::Remove => Ok(ManagedChangeEffectOwner::CanaryRemoval),
        action => Err(ManagedEffectRoutingRefusal::NoAdmittedEffectOwner {
            action,
            family: frozen_plan.family_id.clone(),
        }),
    }
}

/// Validates one advertisement's own shape without touching live state.
///
/// A consumer holding only an advertisement — after a restart, say — can prove
/// the value is well-formed and that its state agrees with the qualifications it
/// names, without holding the survey it was derived from.
///
/// # Errors
/// Returns [`InstallationError`] when the advertisement is malformed or its
/// state disagrees with the missing qualifications it carries.
pub fn validate_advertisement(
    advertisement: &ManagedCapabilityAdvertisement,
) -> Result<(), InstallationError> {
    handle(&advertisement.family_id, "advertisement.family_id")?;
    if let Some(target_identity) = &advertisement.target_identity {
        handle(target_identity, "advertisement.target_identity")?;
    }
    let binding = &advertisement.requalified_against;
    for (value, field) in [
        (
            &binding.catalogue_origin,
            "advertisement.requalified_against.catalogue_origin",
        ),
        (
            &binding.catalogue_publication_ref,
            "advertisement.requalified_against.catalogue_publication_ref",
        ),
        (
            &binding.catalogue_accepted_by,
            "advertisement.requalified_against.catalogue_accepted_by",
        ),
        (
            &binding.confirmed_owner,
            "advertisement.requalified_against.confirmed_owner",
        ),
        (
            &binding.runtime_state_roots_digest,
            "advertisement.requalified_against.runtime_state_roots_digest",
        ),
        (
            &binding.configuration_snapshot_ref,
            "advertisement.requalified_against.configuration_snapshot_ref",
        ),
        (
            &binding.survey_content_digest,
            "advertisement.requalified_against.survey_content_digest",
        ),
    ] {
        handle(value, field)?;
    }
    if binding.catalogue_revision == 0 {
        return Err(InstallationError::InvalidField {
            field: "advertisement.requalified_against.catalogue_revision".to_owned(),
            reason: "must be non-zero".to_owned(),
        });
    }
    if binding.setup_revision == 0 {
        return Err(InstallationError::InvalidField {
            field: "advertisement.requalified_against.setup_revision".to_owned(),
            reason: "must be non-zero".to_owned(),
        });
    }
    // The catalogue acceptance and the installation approval are two different
    // authorities. An advertisement whose two owners disagree is incoherent.
    if binding.catalogue_accepted_by != binding.confirmed_owner {
        return Err(InstallationError::IdentityConflict);
    }

    let missing = &advertisement.state.missing;
    for pair in missing.windows(2) {
        if pair[0] >= pair[1] {
            return Err(InstallationError::InvalidField {
                field: "advertisement.state.missing".to_owned(),
                reason: "must be sorted ascending and distinct".to_owned(),
            });
        }
    }
    match &advertisement.state.status {
        ManagedCapabilityStatus::Probed {
            probe_id,
            answer_refs,
        } => {
            handle(probe_id, "advertisement.state.status.probe_id")?;
            for answer in answer_refs {
                handle(answer, "advertisement.state.status.answer_refs")?;
            }
            for pair in answer_refs.windows(2) {
                if pair[0] >= pair[1] {
                    return Err(InstallationError::InvalidField {
                        field: "advertisement.state.status.answer_refs".to_owned(),
                        reason: "must be sorted ascending and distinct".to_owned(),
                    });
                }
            }
            if !missing.is_empty() || answer_refs.is_empty() {
                return Err(InstallationError::IncompleteObservation(
                    "a probed advertisement names no missing qualification and at least one answer"
                        .to_owned(),
                ));
            }
        }
        ManagedCapabilityStatus::Declared { probe_id } => {
            handle(probe_id, "advertisement.state.status.probe_id")?;
            if missing != &[MissingQualification::NotProbedByAnAdmittedExecutor] {
                return Err(InstallationError::IncompleteObservation(
                    "a declared advertisement names the unprobed qualification".to_owned(),
                ));
            }
        }
        ManagedCapabilityStatus::Discovered => {
            // A discovered candidate resolved an identity and nothing more. It
            // carries no missing qualification because none has been evaluated
            // yet, not because none exists.
            if !missing.is_empty() {
                return Err(InstallationError::IncompleteObservation(
                    "a discovered advertisement names no qualification gap".to_owned(),
                ));
            }
        }
        ManagedCapabilityStatus::Unsupported { missing: named } => {
            // The named set and the carried set are the same set, stated once in
            // the status and once alongside it; disagreement means the
            // advertisement was assembled from two different observations.
            if named != missing || missing.is_empty() {
                return Err(InstallationError::IncompleteObservation(
                    "an unsupported advertisement names one non-empty missing set consistently"
                        .to_owned(),
                ));
            }
        }
    }
    Ok(())
}
