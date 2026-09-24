//! Governed local overlay admission at the `SHAPE_VALIDATED` → `LOCAL_ADMITTED` edge.
//!
//! [`admit_local`] enforces the locally checkable admission predicates against
//! the authoritative base view and the exact supplied source deltas: exact
//! view lineage and [`StateFence`] equality, a named parent revision, a
//! nonempty named source delta set with matching digests, a nonempty
//! next discriminator, exact reversibility with a retained rollback path,
//! nonempty evaluator receipts per delta, equal protected-surface digests, and
//! a live expiry deadline.
//!
//! [`admit_local_with_refs`] adds the owner-record predicates via the
//! caller-supplied [`AuthoritativeRefs`]: same user objective and acceptance
//! revision, no authority/privacy widening by string equality against the
//! ceiling (`candidate != ceiling` rejects), and changed-target disjointness
//! from sealed-holdout and evaluator references.
//!
//! This enforcement is partial and local-only. The A-32 contracts carry no
//! objective/acceptance/evaluator/authority/privacy/cost payload, so the
//! owner-record strings and [`StateFence`] in [`AuthoritativeRefs`] are
//! caller-supplied equality assertions checked here but not authenticated or
//! re-derived by this crate. Protected-surface digests in the input are likewise
//! caller assertions, not recomputed policy evidence (see `lib.rs`). In
//! particular, S218b prohibitions that name material outside the A-32 shape
//! (Architecture text, Hard Boundaries, canonical write/finish semantics, the
//! promoting oracle, sealed holdout answers, the stable production generation,
//! provider identity, the promotion decision itself) cannot be proven from the
//! local shape and remain the caller's responsibility to bind into `refs`.

use eliot_contracts::StateFence;
use eliot_learning_contracts::{
    AttemptLearningDeltaCandidate, CampaignHarnessOverlayCandidate, CampaignLearningStateView,
    LearningContractError,
};

use crate::{OverlayError, expiry, freeze, lifecycle};

/// Authoritative owner records supplied by the caller for admission comparison.
///
/// Every string is compared by exact equality; no ordering, prefix, or
/// hierarchy inference exists. For the ceilings, widening is defined as
/// `candidate != ceiling`: any candidate authority/privacy label that is not
/// exactly the ceiling label rejects, whether it names more or simply
/// different authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthoritativeRefs<'a> {
    /// Observed user objective revision on the candidate side.
    pub objective_revision: &'a str,
    /// Observed acceptance revision on the candidate side.
    pub acceptance_revision: &'a str,
    /// Objective revision required by the Task Controller record.
    pub expected_objective_revision: &'a str,
    /// Acceptance revision required by the Governor record.
    pub expected_acceptance_revision: &'a str,
    /// Authority ceiling label from the Governor record.
    pub authority_ceiling: &'a str,
    /// Authority label claimed for the candidate.
    pub candidate_authority: &'a str,
    /// Privacy ceiling label from the Governor record.
    pub privacy_ceiling: &'a str,
    /// Privacy label claimed for the candidate.
    pub candidate_privacy: &'a str,
    /// Sealed-holdout reference strings; no changed target may name one.
    pub sealed_holdout_refs: &'a [String],
    /// Evaluator reference strings; no changed target may name one.
    pub evaluator_refs: &'a [String],
    /// Authoritative [`StateFence`] the candidate fence must equal.
    pub state_fence: &'a StateFence,
}

/// Evidence that a candidate passed local admission at one observation time.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdmissionReceipt {
    /// Admitted overlay candidate identity.
    pub overlay_id: String,
    /// Caller observation time (`observed_at_ms`) the admission was fixed at.
    pub admitted_at_ms: u64,
    /// Digest binding the frozen pre-evaluation fields to the overlay
    /// identity and canonical digest at admission time.
    pub frozen_digest: String,
}

/// Enforce the locally checkable admission predicates without owner records.
///
/// Checks, in order: candidate shape (`validate`, which covers discriminator
/// presence, nonempty admitted deltas/changes, per-change exact inverses,
/// dependency coverage, and protected-digest equality); exact binding, base
/// digest, and [`StateFence`] lineage against `view`; a present parent task
/// revision equal to the candidate parent; a nonempty supplied `deltas` slice
/// whose identities and canonical digests exactly cover the admitted pairs; a
/// nonempty next discriminator; local reversibility via
/// [`CampaignHarnessOverlayCandidate::is_reversible`]; a nonempty
/// `evaluator_receipts` set per delta; unchanged protected-surface digests; and
/// a live expiry deadline against `observed_at_ms`.
///
/// # Errors
///
/// Returns [`OverlayError::Contract`] with `ScopeMismatch`, `Missing`,
/// `MissingOwnerEvidence`, `MissingInverse`, or `DigestMismatch`;
/// [`OverlayError::ProtectedSurfaceChanged`] when a protected digest moved; or
/// [`OverlayError::Expired`] when the deadline has passed at `observed_at_ms`.
pub fn admit_local(
    candidate: &CampaignHarnessOverlayCandidate,
    view: &CampaignLearningStateView,
    deltas: &[AttemptLearningDeltaCandidate],
    observed_at_ms: u64,
) -> Result<AdmissionReceipt, OverlayError> {
    candidate.validate()?;
    if candidate.binding != view.binding || candidate.base_view_digest != view.canonical_digest {
        return Err(OverlayError::Contract(
            LearningContractError::ScopeMismatch {
                field: "overlay.view_lineage",
            },
        ));
    }
    if candidate.binding.state_fence != view.binding.state_fence {
        return Err(OverlayError::Contract(
            LearningContractError::ScopeMismatch {
                field: "overlay.state_fence",
            },
        ));
    }
    match view.binding.state_fence.task_revision {
        Some(parent) if parent == candidate.parent_revision => {}
        Some(_) => {
            return Err(OverlayError::Contract(
                LearningContractError::ScopeMismatch {
                    field: "parent_revision",
                },
            ));
        }
        None => {
            return Err(OverlayError::Contract(LearningContractError::Missing {
                field: "parent_revision",
            }));
        }
    }
    if deltas.is_empty() || candidate.admitted_delta_ids.is_empty() {
        return Err(OverlayError::Contract(LearningContractError::Missing {
            field: "overlay.admitted_delta",
        }));
    }
    for (id, digest) in candidate
        .admitted_delta_ids
        .iter()
        .zip(&candidate.admitted_delta_digests)
    {
        let Some(delta) = deltas.iter().find(|delta| delta.delta_id == *id) else {
            return Err(OverlayError::Contract(
                LearningContractError::ScopeMismatch {
                    field: "overlay.admitted_delta",
                },
            ));
        };
        if digest != &delta.canonical_digest {
            return Err(OverlayError::Contract(
                LearningContractError::DigestMismatch {
                    field: "overlay.admitted_delta_digests",
                },
            ));
        }
    }
    if candidate
        .fixed_before_observation_discriminator
        .as_str()
        .trim()
        .is_empty()
    {
        return Err(OverlayError::Contract(LearningContractError::Missing {
            field: "overlay.discriminator",
        }));
    }
    if !candidate.is_reversible() {
        return Err(OverlayError::Contract(
            LearningContractError::MissingInverse,
        ));
    }
    for delta in deltas {
        if delta.evaluator_receipts.is_empty() {
            return Err(OverlayError::Contract(
                LearningContractError::MissingOwnerEvidence {
                    field: "delta.evaluator_receipts",
                },
            ));
        }
    }
    if candidate.protected_surface_base_digest != candidate.protected_surface_proposed_digest {
        return Err(OverlayError::ProtectedSurfaceChanged);
    }
    expiry::check_candidate_retrievable(candidate, observed_at_ms)?;
    Ok(AdmissionReceipt {
        overlay_id: candidate.overlay_id.as_str().to_owned(),
        admitted_at_ms: observed_at_ms,
        frozen_digest: frozen_digest_of(candidate),
    })
}

/// Enforce local admission plus the authoritative owner-record predicates.
///
/// Runs [`admit_local`] first, then checks `refs`: same objective and
/// acceptance revision (empty observed revisions fail as `Missing`);
/// authority/privacy string equality against the ceilings; candidate fence
/// equality against the authoritative fence; and changed-target disjointness
/// from both the sealed-holdout and evaluator references (any intersection
/// fails as [`OverlayError::ProtectedSurfaceChanged`]).
///
/// # Errors
///
/// Same errors as [`admit_local`], plus [`OverlayError::Contract`] with
/// `ScopeMismatch` for revision, ceiling, or fence drift and `Missing` for an
/// unnamed objective or acceptance revision.
pub fn admit_local_with_refs(
    candidate: &CampaignHarnessOverlayCandidate,
    view: &CampaignLearningStateView,
    deltas: &[AttemptLearningDeltaCandidate],
    refs: &AuthoritativeRefs<'_>,
    observed_at_ms: u64,
) -> Result<AdmissionReceipt, OverlayError> {
    let receipt = admit_local(candidate, view, deltas, observed_at_ms)?;
    if refs.objective_revision.trim().is_empty() {
        return Err(OverlayError::Contract(LearningContractError::Missing {
            field: "admission.objective_revision",
        }));
    }
    if refs.acceptance_revision.trim().is_empty() {
        return Err(OverlayError::Contract(LearningContractError::Missing {
            field: "admission.acceptance_revision",
        }));
    }
    if refs.objective_revision != refs.expected_objective_revision {
        return Err(OverlayError::Contract(
            LearningContractError::ScopeMismatch {
                field: "admission.objective_revision",
            },
        ));
    }
    if refs.acceptance_revision != refs.expected_acceptance_revision {
        return Err(OverlayError::Contract(
            LearningContractError::ScopeMismatch {
                field: "admission.acceptance_revision",
            },
        ));
    }
    if refs.candidate_authority != refs.authority_ceiling {
        return Err(OverlayError::Contract(
            LearningContractError::ScopeMismatch {
                field: "admission.authority",
            },
        ));
    }
    if refs.candidate_privacy != refs.privacy_ceiling {
        return Err(OverlayError::Contract(
            LearningContractError::ScopeMismatch {
                field: "admission.privacy",
            },
        ));
    }
    if candidate.binding.state_fence != *refs.state_fence {
        return Err(OverlayError::Contract(
            LearningContractError::ScopeMismatch {
                field: "admission.state_fence",
            },
        ));
    }
    for change in &candidate.changes {
        let target = change.target.as_str();
        if refs
            .sealed_holdout_refs
            .iter()
            .any(|held| held.as_str() == target)
        {
            return Err(OverlayError::ProtectedSurfaceChanged);
        }
        if refs
            .evaluator_refs
            .iter()
            .any(|evaluator| evaluator.as_str() == target)
        {
            return Err(OverlayError::ProtectedSurfaceChanged);
        }
    }
    lifecycle::transition(
        lifecycle::OverlayLifecycle::ShapeValidated,
        lifecycle::LifecycleEvent::AdmitLocal,
    )?;
    Ok(receipt)
}

/// Inputs for revalidating one overlay revision for a requesting campaign.
///
/// Bundled so the gate keeps a narrow call shape; every field is compared by
/// exact equality and the wall clock (`now_ms`) always comes from the
/// caller, never from requester envelopes.
pub struct RevalidationRequest<'a> {
    /// Admitted overlay revision under test.
    pub candidate: &'a CampaignHarnessOverlayCandidate,
    /// Immutable base view the revision was composed against.
    pub view: &'a CampaignLearningStateView,
    /// Exact source deltas covering the admitted delta identities.
    pub deltas: &'a [AttemptLearningDeltaCandidate],
    /// Authoritative owner records for the admission predicates.
    pub refs: &'a AuthoritativeRefs<'a>,
    /// Campaign requesting delivery (active campaign for same-campaign use).
    pub requesting_campaign_id: &'a str,
    /// Whether the requester binding matches the admitted fence scope.
    pub binding_compatible: bool,
    /// Caller wall-clock observation in Unix milliseconds.
    pub now_ms: u64,
    /// Fresh governed admission for cross-campaign carryover, if any.
    pub cross_task: Option<&'a eliot_learning_contracts::CrossTaskAdmission>,
}

/// Revalidate one admitted overlay revision for delivery to a requesting
/// campaign: expiry/invalidation wall, campaign eligibility with cross-task
/// admission, lifecycle arming, and full local admission.
///
/// Same-campaign delivery requires the exact active campaign and a live
/// revision. Cross-campaign delivery additionally requires a fresh governed
/// [`CrossTaskAdmission`](eliot_learning_contracts::CrossTaskAdmission)
/// revalidating scope, authority, retention, evaluator, and rollback; the
/// overlay bytes are reused but the admission is new. On success the
/// lifecycle advances `LocalAdmitted` to `ActiveForNextAttempt` and a new
/// [`AdmissionReceipt`] is issued.
///
/// # Errors
///
/// Returns [`OverlayError::Expired`] for an invalidated or past-deadline
/// revision, [`OverlayError::Contract`] for campaign/binding drift or a
/// missing/invalid cross-task admission, and the [`admit_local_with_refs`]
/// errors for any predicate the revision no longer satisfies.
pub fn revalidate_for_campaign(
    request: &RevalidationRequest<'_>,
) -> Result<AdmissionReceipt, OverlayError> {
    use eliot_learning_contracts::OverlayEligibility;
    let candidate = request.candidate;
    expiry::check_candidate_retrievable(candidate, request.now_ms)?;
    match eliot_learning_contracts::overlay_eligibility(
        candidate.campaign_id.as_str(),
        request.requesting_campaign_id,
        candidate.invalidated,
        candidate.expires_at_ms,
        request.now_ms,
        request.binding_compatible,
        request.cross_task,
    ) {
        OverlayEligibility::Eligible => {}
        OverlayEligibility::NotEligible { reason } => {
            return Err(eligibility_refusal(reason));
        }
    }
    lifecycle::transition(
        lifecycle::OverlayLifecycle::LocalAdmitted,
        lifecycle::LifecycleEvent::ActivateForNextAttempt,
    )?;
    admit_local_with_refs(
        candidate,
        request.view,
        request.deltas,
        request.refs,
        request.now_ms,
    )
}

/// Build the frozen pre-evaluation bundle carried on one candidate.
fn frozen_bundle_of(candidate: &CampaignHarnessOverlayCandidate) -> freeze::FrozenPreEvaluation {
    freeze::FrozenPreEvaluation {
        intended_mechanism: candidate.intended_mechanism.clone(),
        prediction: candidate.prediction.clone(),
        expected_observable: candidate.expected_observable.clone(),
        possible_regressions: candidate.possible_regressions.clone(),
        confounders: candidate.confounders.clone(),
        preserved_success_constraint: candidate.preserved_success_constraint.clone(),
        next_discriminator_text: candidate.next_discriminator_text.clone(),
        rollback_condition: candidate.rollback_condition.clone(),
    }
}

/// Bind the candidate-carried frozen fields to its identity and seal digest.
fn frozen_digest_of(candidate: &CampaignHarnessOverlayCandidate) -> String {
    freeze::frozen_digest(
        &frozen_bundle_of(candidate),
        candidate.overlay_id.as_str(),
        &candidate.canonical_digest,
    )
}

fn eligibility_refusal(reason: &'static str) -> OverlayError {
    match reason {
        "overlay_expired" | "overlay_invalidated" => OverlayError::Expired,
        _ => OverlayError::Contract(LearningContractError::ScopeMismatch {
            field: "overlay.campaign_eligibility",
        }),
    }
}
