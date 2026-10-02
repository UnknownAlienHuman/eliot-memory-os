//! Governor-owned use-attribution producers and their five owner seams
//! (CC-007, issue #45).
//!
//! [`eliot_learning_contracts::UseAttributionCandidate`] is a candidate-only
//! record whose validation the family already owns, but nine of its fields had
//! no production producer: `subject`, `decision_action_id`, `disposition`,
//! `use_basis`, `eligible_refs`, `non_use`, `competing_contributors`,
//! `evaluator_receipt` and `dimensions`. This module gives each of them an owner
//! at the home the canonical documentation assigns it, and derives the candidate
//! only from those owner records. It never fills a field in itself.
//!
//! # Owner seams
//!
//! | Owner seam | Owner record | Attribution fields it owns |
//! |---|---|---|
//! | delivery/use owner (Context Compiler delivery + observability owners) | [`HarnessActivationReceiptCandidate`] + [`AttributedSubject`] | `subject`, `eligible_refs`, `competing_contributors`, `disposition` |
//! | action/decision owner (Task Controller decision owner) | [`DecisionOwnerRecord`] | `decision_action_id`, `non_use` |
//! | basis owner (acceptance-item-bound verifier route, A5.5) | [`UseBasisOwnerRecord`] | `use_basis` |
//! | outcome/verifier owner | [`LearningAssessmentCandidate`] | `dimensions`, `claim_ceiling` |
//! | evaluator owner (route outside the attributor's failure domain) | [`IndependentObservationReceipt`] | `evaluator_receipt` |
//!
//! Each seam is an independent optional slot in [`UseAttributionOwnerInput`], so
//! an owner that published nothing is named by its own typed
//! [`AttributionRefusal::OwnerAbsent`] rather than being silently defaulted.
//! The five refusals keep the existing
//! [`LearningContractError`](eliot_learning_contracts::LearningContractError)
//! vocabulary for every *content* failure, so no refusal is ever a string verdict
//! or a boolean.
//!
//! # Independence is content, not presence
//!
//! A5.5 is the governing sentence: "As impact increases, the system relies less
//! on the actor's self-report. A Critical result requires an observation or
//! evaluation route outside the actor's failure domain when practical;
//! otherwise, finish remains honestly degraded." A5.5 also forbids the shortcut
//! this module exists to block: "A model evaluator is admissible for a
//! subjective property, but its model name does not make it independent."
//!
//! So independence is decided by comparing content-addressed
//! [`FailureDomain`] descriptors and by requiring the observing route to be a
//! registered owner of a *different* domain from the attributor's. Three
//! separate content bindings keep the attributor from certifying its own use:
//!
//! 1. [`issue_independence_receipt`] refuses to mint a receipt whose observing
//!    route shares the attributor's failure-domain digest or route identity
//!    ([`eliot_learning_contracts::LearningContractError::NonIndependentAssessment`]);
//! 2. the receipt's `receipt_id` is content-addressed over the attributor, the
//!    observing route, the observed action and the observation, and
//!    [`IndependentObservationReceipt::validate`] recomputes it, so a substituted
//!    observation is a
//!    [`eliot_learning_contracts::LearningContractError::DigestMismatch`];
//! 3. the outcome owner's `SOURCE_EVALUATOR_INDEPENDENCE` dimension must carry
//!    *the independent route's own receipt* as its owner receipt, so the
//!    attributor's own dimensioned self-assessment cannot satisfy it.
//!
//! I18.47 supplies the role separation this enforces: an
//! `EvaluationIntegrityReceipt` records "production, measurement and
//! optimization-feedback roles", and `SourceEvaluatorIndependence` stays its own
//! dimension rather than being collapsed into benefit.
//!
//! # Boundary
//!
//! Nothing here promotes, admits or delivers anything. The producer is a pure
//! function of owner records: no clock, no I/O, no live query, no authority
//! beyond the verdict it returns. Retrieval, delivery, observable activation,
//! adherence and outcome stay orthogonal (I12.24 line 256), so the derived
//! `disposition` is corroborated against the delivery owner's own recorded
//! sections and never inferred from presence.

use eliot_contracts::{ArtifactId, canonical_json_bytes, sha256_hex};
use eliot_learning_contracts::identity::validate_digest;
use eliot_learning_contracts::{
    ActivationStatus, AssessmentDimension, AttributedSubject, DeliveryStatus,
    HarnessActivationReceiptCandidate, LearningAssessmentCandidate, LearningContractError,
    LifecycleStage, NonUseDeclaration, SourceDenominator, StageDisposition,
    UseAttributionCandidate, UseBasis, UseDisposition,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Content-addressed descriptor of the failure domain a route operates in.
///
/// A5.5 requires "an observation or evaluation route outside the actor's failure
/// domain". Independence is therefore decided by comparing these descriptors
/// *by content* — two routes share a failure domain exactly when their digests
/// are equal — and never by the presence, absence or name of a route, a process,
/// a model or an evaluator registration.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FailureDomain {
    /// Identity of the service identity this domain belongs to.
    pub domain_id: String,
    /// Canonical digest over every declared part of the domain.
    pub domain_digest: String,
}

impl FailureDomain {
    /// Content-address the declared parts of one failure domain.
    ///
    /// The parts are the owner values that place a route in a domain (its
    /// service identity, executing process, deciding plan route, ...). They are
    /// canonicalized together, so the digest changes when any part changes.
    pub fn seal(parts: &[&str]) -> Result<Self, AttributionRefusal> {
        if parts.is_empty() || parts.iter().any(|part| part.trim().is_empty()) {
            return Err(AttributionRefusal::Owner(LearningContractError::Missing {
                field: "attribution.failure_domain",
            }));
        }
        let bytes = canonical_json_bytes(&parts)
            .map_err(|_| AttributionRefusal::Owner(LearningContractError::Canonicalization))?;
        Ok(Self {
            domain_id: parts[0].to_owned(),
            domain_digest: sha256_hex(&bytes),
        })
    }

    /// Reject an unsealed or malformed domain descriptor.
    fn validate(&self) -> Result<(), AttributionRefusal> {
        if self.domain_id.trim().is_empty() {
            return Err(AttributionRefusal::Owner(LearningContractError::Missing {
                field: "attribution.failure_domain.domain_id",
            }));
        }
        validate_digest(
            &self.domain_digest,
            "attribution.failure_domain.domain_digest",
        )?;
        Ok(())
    }
}

/// The attributing actor: the party whose use claim the attribution makes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AttributorIdentity {
    /// Actor that executed the attempt and would benefit from the use claim.
    pub actor_id: String,
    /// Route that selected and decided the attempt.
    pub route_id: String,
    /// Failure domain the attributor operates in.
    pub failure_domain: FailureDomain,
}

impl AttributorIdentity {
    /// Reject an unattested attributor identity.
    fn validate(&self) -> Result<(), AttributionRefusal> {
        if self.actor_id.trim().is_empty() {
            return Err(AttributionRefusal::Owner(LearningContractError::Missing {
                field: "attribution.attributing_actor",
            }));
        }
        if self.route_id.trim().is_empty() {
            return Err(AttributionRefusal::Owner(LearningContractError::Missing {
                field: "attribution.attributing_route",
            }));
        }
        self.failure_domain.validate()
    }

    /// Whether an observing route is genuinely outside this failure domain.
    ///
    /// The comparison is by content: an equal content-addressed domain digest or
    /// an equal route identity means the observer shares the attributor's
    /// failure domain, and the observation cannot certify this actor's own use.
    fn is_outside(&self, route: &IndependentObservationRoute) -> bool {
        route.failure_domain.domain_digest != self.failure_domain.domain_digest
            && route.failure_domain.domain_id != self.failure_domain.domain_id
            && route.route_id != self.route_id
    }
}

/// An observation route published by an owner outside the attributor's domain.
///
/// A02.03 and A13.02 are the shape this record has to be able to name: Watchdog
/// and the other supervising services "operate outside the shared process
/// failure domain of the main services".
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IndependentObservationRoute {
    /// Identity of the observing route or supervising service.
    pub route_id: String,
    /// Failure domain the observing route operates in.
    pub failure_domain: FailureDomain,
    /// Owner receipt registering this route to observe decisions.
    pub owner_receipt: ArtifactId,
}

/// What an independent route observed about the subject.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum IndependentObservation {
    /// The independent route observed the subject being used in the action.
    SubjectUsedInAction,
    /// The independent route observed the action; the subject was not used in it.
    SubjectNotUsedInAction,
    /// The independent route observed the action; subject use is inconclusive.
    SubjectUseInconclusive,
}

/// Immutable evidence that one decided action was observed outside the
/// attributing actor's failure domain.
///
/// The receipt is observation-only. It never certifies benefit, correctness or
/// improvement (A14.5 ARCH-META-01), and its existence is not proof that the
/// subject was used: what was observed is the closed
/// [`IndependentObservation`] value and nothing more.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct IndependentObservationReceipt {
    /// Content-addressed receipt identity over every other field.
    pub receipt_id: ArtifactId,
    /// Actor whose use claim this observation is independent of.
    pub attributing_actor_id: String,
    /// Content-addressed failure domain the attributor operates in.
    pub attributing_failure_domain: String,
    /// Identity of the independent observing route.
    pub observation_route_id: String,
    /// Content-addressed failure domain the observing route operates in.
    pub observation_failure_domain: String,
    /// Owner receipt that registered the observing route.
    pub route_owner_receipt: ArtifactId,
    /// Exact decided action artifact the independent route observed.
    pub observed_action_id: ArtifactId,
    /// Canonical content digest of the observed action artifact.
    pub observed_action_digest: String,
    /// What the independent route observed about the subject.
    pub observation: IndependentObservation,
}

impl IndependentObservationReceipt {
    /// Canonical content digest over every field except `receipt_id`.
    fn content_digest(&self) -> Result<String, AttributionRefusal> {
        canonical_json_bytes(&(
            self.attributing_actor_id.as_str(),
            self.attributing_failure_domain.as_str(),
            self.observation_route_id.as_str(),
            self.observation_failure_domain.as_str(),
            self.route_owner_receipt.as_str(),
            self.observed_action_id.as_str(),
            self.observed_action_digest.as_str(),
            self.observation,
        ))
        .map(|bytes| sha256_hex(&bytes))
        .map_err(|_| AttributionRefusal::Owner(LearningContractError::Canonicalization))
    }

    /// Revalidate the receipt and recompute its content-addressed identity.
    ///
    /// A substituted observation, a swapped route or a rewritten observed
    /// action all change the recomputed digest and are refused with the existing
    /// [`LearningContractError::DigestMismatch`] instead of being trusted.
    pub fn validate(&self) -> Result<(), AttributionRefusal> {
        if self.attributing_actor_id.trim().is_empty()
            || self.observation_route_id.trim().is_empty()
        {
            return Err(AttributionRefusal::Owner(LearningContractError::Missing {
                field: "attribution.independence.route",
            }));
        }
        validate_digest(
            &self.attributing_failure_domain,
            "attribution.independence.attributing_failure_domain",
        )?;
        validate_digest(
            &self.observation_failure_domain,
            "attribution.independence.observation_failure_domain",
        )?;
        validate_digest(
            &self.observed_action_digest,
            "attribution.independence.observed_action_digest",
        )?;
        if self.route_owner_receipt.as_str().trim().is_empty() {
            return Err(AttributionRefusal::Owner(
                LearningContractError::MissingOwnerEvidence {
                    field: "attribution.independence.route_owner_receipt",
                },
            ));
        }
        if self.observed_action_id.as_str().trim().is_empty() {
            return Err(AttributionRefusal::Owner(LearningContractError::Missing {
                field: "attribution.independence.observed_action_id",
            }));
        }
        let expected = self.expected_receipt_id()?;
        if expected != self.receipt_id {
            return Err(AttributionRefusal::Owner(
                LearningContractError::DigestMismatch {
                    field: "attribution.independence.receipt_id",
                },
            ));
        }
        Ok(())
    }

    /// The receipt identity this content must carry.
    fn expected_receipt_id(&self) -> Result<ArtifactId, AttributionRefusal> {
        let digest = self.content_digest()?;
        ArtifactId::new(format!("independence-receipt:{digest}"))
            .map_err(|_| AttributionRefusal::Owner(LearningContractError::Foundation))
    }
}

/// Mint one independent observation of a decided action.
///
/// This is the producer of the attribution's `evaluator_receipt`. It is
/// fail-closed and refuses rather than degrades:
///
/// - no observing route published (`None`) is
///   [`AttributionRefusal::OwnerAbsent`], which is the A5.5 outcome "finish
///   remains honestly degraded" rather than a pass;
/// - a route that shares the attributor's failure domain, service identity or
///   route identity is refused with
///   [`LearningContractError::NonIndependentAssessment`], so the attributor can
///   never certify its own independence;
/// - the minted `receipt_id` is content-addressed over the attributor, the
///   observing route, the observed action and the observation, so two different
///   observations never share one identity.
pub fn issue_independence_receipt(
    attributor: &AttributorIdentity,
    route: Option<&IndependentObservationRoute>,
    observed_action_id: Option<&ArtifactId>,
    observed_action_digest: Option<&str>,
    observation: Option<IndependentObservation>,
) -> Result<IndependentObservationReceipt, AttributionRefusal> {
    attributor.validate()?;
    let Some(route) = route else {
        return Err(AttributionRefusal::OwnerAbsent {
            field: "attribution.independent_route",
        });
    };
    let Some(observed_action_id) = observed_action_id else {
        return Err(AttributionRefusal::OwnerAbsent {
            field: "attribution.observed_action",
        });
    };
    let Some(observed_action_digest) = observed_action_digest else {
        return Err(AttributionRefusal::OwnerAbsent {
            field: "attribution.observed_action_digest",
        });
    };
    let Some(observation) = observation else {
        return Err(AttributionRefusal::OwnerAbsent {
            field: "attribution.independent_observation",
        });
    };
    route.failure_domain.validate()?;
    if route.route_id.trim().is_empty() {
        return Err(AttributionRefusal::Owner(LearningContractError::Missing {
            field: "attribution.independence.observation_route_id",
        }));
    }
    validate_digest(
        observed_action_digest,
        "attribution.independence.observed_action_digest",
    )?;
    if !attributor.is_outside(route) {
        return Err(AttributionRefusal::Owner(
            LearningContractError::NonIndependentAssessment,
        ));
    }
    let receipt = IndependentObservationReceipt {
        receipt_id: ArtifactId::new("independence-receipt:pending")
            .map_err(|_| AttributionRefusal::Owner(LearningContractError::Foundation))?,
        attributing_actor_id: attributor.actor_id.clone(),
        attributing_failure_domain: attributor.failure_domain.domain_digest.clone(),
        observation_route_id: route.route_id.clone(),
        observation_failure_domain: route.failure_domain.domain_digest.clone(),
        route_owner_receipt: route.owner_receipt.clone(),
        observed_action_id: observed_action_id.clone(),
        observed_action_digest: observed_action_digest.to_owned(),
        observation,
    };
    let receipt = IndependentObservationReceipt {
        receipt_id: receipt.expected_receipt_id()?,
        ..receipt
    };
    receipt.validate()?;
    Ok(receipt)
}

/// Delivery/use owner record: the Context Compiler delivery owner and the
/// observability owner's published receipt, plus the exact subject identity they
/// delivered.
///
/// I12.24 lines 227-254 define this receipt, and line 256 keeps its retrieval,
/// delivery, observable-activation, adherence and outcome sections orthogonal.
/// The attributed subject, the complete eligible denominator and the competing
/// contributors are read from that one owner record rather than reconstructed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeliveredUseOwnerRecord<'a> {
    /// The activation receipt the delivery and observability owners published.
    pub activation: &'a HarnessActivationReceiptCandidate,
    /// The exact delivered subject with its pinned version and record digest.
    pub subject: &'a AttributedSubject,
}

/// Action/decision owner record for one decision opportunity.
///
/// I12.24 line 251 names `downstream_decision_action_artifact_and_verifier_refs`
/// as the decision owner's own downstream handle, and the candidate requires
/// "decision/action identity and WorkScope/StateFence" plus explicit non-use.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DecisionOwnerRecord<'a> {
    /// Identity of the decision/action that consumed or rejected the subject.
    pub decided_action_id: &'a ArtifactId,
    /// Subjects the decision owner explicitly considered and rejected.
    pub non_use: &'a [NonUseDeclaration],
    /// Decision owner receipt binding this record to the attempt.
    pub owner_receipt: &'a ArtifactId,
}

/// Basis owner record: the closed observation route the use claim rests on.
///
/// A5.5 assigns the acceptance binding to the Governor: "The Governor binds the
/// verifier to an acceptance item and checks scope and freshness." A5.5 also
/// rejects retrieval, repetition and model self-judgment as proof, so those
/// bases are refused here rather than at a later gate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UseBasisOwnerRecord<'a> {
    /// The closed basis this owner's observation route supports.
    pub basis: UseBasis,
    /// Acceptance item the verifier route is bound to.
    pub acceptance_item_ref: &'a ArtifactId,
    /// Verifier/oracle route that produced the basis.
    pub basis_route: &'a ArtifactId,
    /// Owner receipt for the basis observation.
    pub owner_receipt: &'a ArtifactId,
    /// Exact subject handles the basis route actually observed.
    ///
    /// Compared by content against the delivery owner's eligible denominator, so
    /// an `eligible_refs` claim the basis route did not support is refused.
    pub observed_subject_refs: &'a [ArtifactId],
}

/// Exact owner evidence presented to one use-attribution derivation.
///
/// Every value is published by its owner and passed through unchanged. The
/// Governor composes them; it never fills one in, and an owner that published
/// nothing leaves its slot `None` so the refusal names that seam.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UseAttributionOwnerInput<'a> {
    /// Durable record whose canonical digest the attribution's lineage names.
    pub source_delta_id: &'a ArtifactId,
    /// Canonical digest of that durable record.
    pub source_delta_digest: &'a str,
    /// The attributing actor the independence receipt must be independent of.
    pub attributor: &'a AttributorIdentity,
    /// Delivery/use owner record.
    pub delivery: Option<&'a DeliveredUseOwnerRecord<'a>>,
    /// Action/decision owner record.
    pub decision: Option<&'a DecisionOwnerRecord<'a>>,
    /// Basis owner record.
    pub basis: Option<&'a UseBasisOwnerRecord<'a>>,
    /// Outcome/verifier owner record.
    pub evaluation: Option<&'a LearningAssessmentCandidate>,
    /// Independence receipt minted outside the attributor's failure domain.
    pub independence: Option<&'a IndependentObservationReceipt>,
}

/// Typed refusals of one use-attribution derivation; every variant names one
/// cause.
///
/// An absent owner and a failed owner record stay distinct, exactly as
/// [`crate::learning_promotion::PromotionRefusal`] keeps an absent boundary
/// distinct from an invalid one, and every content failure travels as the
/// existing typed contract error.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum AttributionRefusal {
    /// No owner published a record for this attribution owner seam, so nothing
    /// was derived. Absence is recorded as absence and never as a pass.
    #[error("no owner record was published for {field}")]
    OwnerAbsent {
        /// The owner seam that published nothing.
        field: &'static str,
    },
    /// An owner's record failed contract validation or a cross-owner content
    /// binding. The typed contract error travels as the source.
    #[error("use attribution refused: {0}")]
    Owner(#[source] LearningContractError),
}

impl From<LearningContractError> for AttributionRefusal {
    fn from(error: LearningContractError) -> Self {
        Self::Owner(error)
    }
}

/// Typed outcome of one use-attribution derivation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AttributionOutcome {
    /// Every owner seam published and the candidate validated in one fence.
    /// The record stays candidate-only: nothing is admitted or promoted here.
    Attributed(Box<UseAttributionCandidate>),
    /// An owner seam was absent or refused. The typed cause is retained so an
    /// honest absent and an invalid record never collapse into one answer.
    Unattributed {
        /// The exact reason the candidate was not derived.
        reason: AttributionRefusal,
    },
}

/// Typed outcome of the independent-observation step for one record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IndependenceOutcome {
    /// An owner outside the attributor's failure domain observed the decided
    /// action and its receipt is retained.
    Observed(Box<IndependentObservationReceipt>),
    /// No independent observation was available, so nothing was minted. This is
    /// the A5.5 honest-degraded outcome, not a pass.
    NotObserved {
        /// The exact reason no receipt was minted.
        reason: AttributionRefusal,
    },
}

/// Derive the candidate-only use attribution from the owner records.
///
/// The evaluation order is fixed and fail-closed: the attributor identity, the
/// source-delta lineage, then the five owner seams in the order the
/// documentation names them, then the cross-owner content bindings. The first
/// failing seam is the recorded refusal, so a consumer always learns which
/// owner is missing rather than only that something is.
///
/// Nothing is asserted by presence: every value is either an owner record, a
/// content-addressed reference inside one, or a set derived from them by
/// content comparison.
#[must_use = "the attribution verdict must be recorded, not discarded"]
pub fn attribute_observed_use(input: &UseAttributionOwnerInput<'_>) -> AttributionOutcome {
    match derive_attribution(input) {
        Ok(candidate) => AttributionOutcome::Attributed(Box::new(candidate)),
        Err(reason) => AttributionOutcome::Unattributed { reason },
    }
}

/// The production seam: derive use attribution for one committed record.
///
/// This is the entry the learning-closure path calls. It mints the independent
/// observation through [`issue_independence_receipt`] and then derives the
/// candidate through [`attribute_observed_use`], recording both verdicts side by
/// side. `independent_route`, `observed_action_id`, `observed_action_digest` and
/// `observation` are the independent owner's published values; a seam where no
/// such owner publishes passes `None` and the receipt names that absence, which
/// is the fail-closed A5.5 outcome rather than a fabricated attribution.
#[allow(
    clippy::too_many_arguments,
    reason = "one slot per attribution owner seam plus the independent-observation inputs"
)]
#[must_use = "both attribution verdicts must be recorded, not discarded"]
pub fn attribute_committed_attempt(
    attributor: &AttributorIdentity,
    source_delta_id: &ArtifactId,
    source_delta_digest: &str,
    independent_route: Option<&IndependentObservationRoute>,
    observed_action_id: Option<&ArtifactId>,
    observed_action_digest: Option<&str>,
    observation: Option<IndependentObservation>,
    delivery: Option<&DeliveredUseOwnerRecord<'_>>,
    decision: Option<&DecisionOwnerRecord<'_>>,
    basis: Option<&UseBasisOwnerRecord<'_>>,
    evaluation: Option<&LearningAssessmentCandidate>,
) -> (IndependenceOutcome, AttributionOutcome) {
    let minted = issue_independence_receipt(
        attributor,
        independent_route,
        observed_action_id,
        observed_action_digest,
        observation,
    );
    let independence = match &minted {
        Ok(receipt) => IndependenceOutcome::Observed(Box::new(receipt.clone())),
        Err(reason) => IndependenceOutcome::NotObserved {
            reason: reason.clone(),
        },
    };
    let input = UseAttributionOwnerInput {
        source_delta_id,
        source_delta_digest,
        attributor,
        delivery,
        decision,
        basis,
        evaluation,
        independence: minted.as_ref().ok(),
    };
    (independence, attribute_observed_use(&input))
}

/// The delivered-surface denominator read out of the delivery owner's record.
///
/// The eligible subjects of one decision opportunity are exactly the surfaces the
/// delivery owner actually delivered into the attempt: its skill, memory and
/// procedure refs. Harness refs are the compiled baseline rather than attributed
/// subjects, and a retrieval hit that was not delivered is never eligible, so
/// neither can enter the denominator by presence.
fn delivered_surfaces(activation: &HarnessActivationReceiptCandidate) -> Vec<ArtifactId> {
    let mut surfaces = Vec::new();
    for group in [
        &activation.skill_refs,
        &activation.memory_refs,
        &activation.procedure_refs,
    ] {
        surfaces.extend(group.iter().cloned());
    }
    sorted_unique_refs(surfaces)
}

/// Sort and deduplicate artifact references so a derived set binds stably.
fn sorted_unique_refs(refs: Vec<ArtifactId>) -> Vec<ArtifactId> {
    let mut refs = refs;
    refs.sort_by(|left, right| left.as_str().cmp(right.as_str()));
    refs.dedup();
    refs
}

/// Derive the use disposition from the delivery owner's own recorded sections.
///
/// The four closed dispositions are corroborated against what the delivery owner
/// actually recorded, never chosen to satisfy schema presence:
///
/// - the decision owner explicitly rejected the subject, so it is `NonUse`;
/// - observable activation was observed with a qualifying use ref, so the
///   subject is `Used` when the owner also observed the `USED_IN_ACTION` stage
///   and `Influential` when it did not — influence without action-linked use is
///   a distinct claim and stays distinct;
/// - the surface was delivered in full or in part with no qualifying activation,
///   so it is `Included`.
///
/// `NOT_OBSERVED` is explicitly *not* turned into non-use (I12.24 line 256: "it
/// does not prove non-use"), and a delivery the owner did not record leaves no
/// disposition to claim.
fn derive_disposition(
    activation: &HarnessActivationReceiptCandidate,
    subject_declared_non_use: bool,
) -> Result<UseDisposition, AttributionRefusal> {
    if subject_declared_non_use {
        return Ok(UseDisposition::NonUse);
    }
    let activated = activation.activation.status == ActivationStatus::Observed
        && activation
            .activation
            .first_qualifying_observable_use_ref
            .is_some();
    if activated {
        let used_in_action = activation.stages.iter().any(|stage| {
            stage.stage == LifecycleStage::UsedInAction
                && matches!(
                    stage.disposition,
                    StageDisposition::Observed | StageDisposition::Partial
                )
        });
        return Ok(if used_in_action {
            UseDisposition::Used
        } else {
            UseDisposition::Influential
        });
    }
    let delivered = matches!(
        activation.delivery.status,
        DeliveryStatus::Full | DeliveryStatus::Partial
    );
    if delivered {
        return Ok(UseDisposition::Included);
    }
    Err(AttributionRefusal::Owner(
        LearningContractError::MissingOwnerEvidence {
            field: "attribution.disposition_observation",
        },
    ))
}

/// Derive and seal one attributed candidate, or name the first failing seam.
#[allow(
    clippy::too_many_lines,
    reason = "one fail-closed check per owner seam, kept in evaluation order"
)]
fn derive_attribution(
    input: &UseAttributionOwnerInput<'_>,
) -> Result<UseAttributionCandidate, AttributionRefusal> {
    input.attributor.validate()?;
    if input.source_delta_id.as_str().trim().is_empty() {
        return Err(LearningContractError::Missing {
            field: "attribution.source_delta_id",
        }
        .into());
    }
    validate_digest(input.source_delta_digest, "attribution.source_delta_digest")?;

    // Owner seam 1 — delivery/use owner.
    let Some(delivery) = input.delivery else {
        return Err(AttributionRefusal::OwnerAbsent {
            field: "attribution.delivery_owner",
        });
    };
    // Owner seam 2 — action/decision owner.
    let Some(decision) = input.decision else {
        return Err(AttributionRefusal::OwnerAbsent {
            field: "attribution.decision_owner",
        });
    };
    // Owner seam 3 — basis owner.
    let Some(basis) = input.basis else {
        return Err(AttributionRefusal::OwnerAbsent {
            field: "attribution.basis_owner",
        });
    };
    // Owner seam 4 — outcome/verifier owner.
    let Some(evaluation) = input.evaluation else {
        return Err(AttributionRefusal::OwnerAbsent {
            field: "attribution.evaluation_owner",
        });
    };
    // Owner seam 5 — evaluator owner outside the attributor's failure domain.
    let Some(independence) = input.independence else {
        return Err(AttributionRefusal::OwnerAbsent {
            field: "attribution.independence_owner",
        });
    };

    delivery.activation.validate()?;
    delivery.subject.validate()?;
    independence.validate()?;

    let delivered = delivered_surfaces(delivery.activation);
    let subject_id = &delivery.subject.id;
    if !delivered.contains(subject_id) {
        return Err(LearningContractError::MissingOwnerEvidence {
            field: "attribution.delivered_surface",
        }
        .into());
    }
    for entry in decision.non_use {
        entry.validate()?;
        if !delivered.contains(&entry.subject) {
            return Err(LearningContractError::ScopeMismatch {
                field: "attribution.non_use_surface",
            }
            .into());
        }
    }
    let non_use_subjects: Vec<ArtifactId> = decision
        .non_use
        .iter()
        .map(|entry| entry.subject.clone())
        .collect();
    // The eligible set and the explicit non-use declarations partition the
    // complete denominator, so a subject the decision owner rejected is not
    // counted as eligible as well.
    let eligible_refs: Vec<ArtifactId> = delivered
        .iter()
        .filter(|candidate| !non_use_subjects.contains(*candidate))
        .cloned()
        .collect();
    let competing_contributors: Vec<ArtifactId> = eligible_refs
        .iter()
        .filter(|candidate| *candidate != subject_id)
        .cloned()
        .collect();

    // The basis owner must have observed every surface the attribution claims in
    // its denominator; an `eligible_refs` entry the basis route did not support
    // is refused by content, never by presence.
    for claimed in eligible_refs.iter().chain(non_use_subjects.iter()) {
        if !basis
            .observed_subject_refs
            .iter()
            .any(|observed| observed == claimed)
        {
            return Err(LearningContractError::ScopeMismatch {
                field: "attribution.basis_subject_coverage",
            }
            .into());
        }
    }
    match basis.basis {
        UseBasis::DirectObservation
        | UseBasis::ControlledComparison
        | UseBasis::IndependentEvaluator => {}
        UseBasis::RetrievalCount | UseBasis::Repetition | UseBasis::ModelJudgment => {
            return Err(LearningContractError::ScopeMismatch {
                field: "attribution.use_basis",
            }
            .into());
        }
    }
    if basis.basis_route == subject_id || basis.owner_receipt == subject_id {
        return Err(LearningContractError::ScopeMismatch {
            field: "attribution.basis_independence",
        }
        .into());
    }

    // The outcome owner's assessment is bound to the delivery owner's receipt by
    // content: same binding, target, overlay, activation identity and canonical
    // activation digest.
    evaluation.validate_against_activation(delivery.activation)?;

    // The independence receipt must be independent of this attributor, and must
    // have observed the exact decided action.
    if independence.attributing_actor_id != input.attributor.actor_id
        || independence.attributing_failure_domain != input.attributor.failure_domain.domain_digest
    {
        return Err(LearningContractError::ScopeMismatch {
            field: "attribution.independence_binding",
        }
        .into());
    }
    if independence.observation_failure_domain == input.attributor.failure_domain.domain_digest
        || independence.observation_route_id == input.attributor.route_id
    {
        return Err(LearningContractError::NonIndependentAssessment.into());
    }
    if &independence.observed_action_id != decision.decided_action_id {
        return Err(LearningContractError::ScopeMismatch {
            field: "attribution.observed_action",
        }
        .into());
    }

    let disposition =
        derive_disposition(delivery.activation, non_use_subjects.contains(subject_id))?;

    // The independent route's own receipt must be the owner receipt of the
    // `SOURCE_EVALUATOR_INDEPENDENCE` dimension, so the attributor's own
    // dimensioned self-assessment can never satisfy it.
    let Some(independence_dimension) = evaluation
        .dimensions
        .iter()
        .find(|dimension| dimension.dimension == AssessmentDimension::SourceEvaluatorIndependence)
    else {
        return Err(LearningContractError::IncompleteCoverage.into());
    };
    if independence_dimension.owner_receipt.as_ref() != Some(&independence.receipt_id) {
        return Err(LearningContractError::NonIndependentAssessment.into());
    }
    for required in [
        AssessmentDimension::Harm,
        AssessmentDimension::SourceEvaluatorIndependence,
    ] {
        if !evaluation
            .dimensions
            .iter()
            .any(|dimension| dimension.dimension == required)
        {
            return Err(LearningContractError::IncompleteCoverage.into());
        }
    }
    if matches!(disposition, UseDisposition::Used)
        && !evaluation
            .dimensions
            .iter()
            .any(|dimension| dimension.dimension == AssessmentDimension::ActionLinkedUse)
    {
        return Err(LearningContractError::IncompleteCoverage.into());
    }

    // The independent observation must not contradict the derived disposition.
    let contradicts = match disposition {
        UseDisposition::NonUse => {
            independence.observation == IndependentObservation::SubjectUsedInAction
        }
        UseDisposition::Used => {
            independence.observation != IndependentObservation::SubjectUsedInAction
        }
        UseDisposition::Included | UseDisposition::Influential => {
            independence.observation == IndependentObservation::SubjectNotUsedInAction
        }
    };
    if contradicts {
        return Err(LearningContractError::NonIndependentAssessment.into());
    }

    let total = u32::try_from(eligible_refs.len().saturating_add(decision.non_use.len())).map_err(
        |_| {
            AttributionRefusal::Owner(LearningContractError::Bound {
                field: "attribution.eligible_refs",
            })
        },
    )?;
    let denominator = SourceDenominator {
        declared: total,
        observed: total,
    };

    let evidence_refs = attribution_evidence_refs(
        delivery.activation,
        decision,
        basis,
        evaluation,
        independence,
    );
    if evidence_refs.is_empty() {
        return Err(LearningContractError::MissingOwnerEvidence {
            field: "attribution.evidence_refs",
        }
        .into());
    }
    let attribution_id = attribution_identity(input, delivery.subject)?;

    let mut candidate = UseAttributionCandidate {
        binding: delivery.activation.binding.clone(),
        attribution_id,
        target: delivery.activation.target.clone(),
        subject: delivery.subject.clone(),
        decision_action_id: decision.decided_action_id.clone(),
        source_delta_id: input.source_delta_id.clone(),
        source_delta_digest: input.source_delta_digest.to_owned(),
        disposition,
        use_basis: basis.basis,
        denominator,
        eligible_refs,
        non_use: decision.non_use.to_vec(),
        competing_contributors,
        evaluator_receipt: independence.receipt_id.clone(),
        evidence_refs,
        dimensions: evaluation.dimensions.clone(),
        claim_ceiling: evaluation.causal_ceiling,
        canonical_digest: String::new(),
    };
    candidate.seal()?;
    candidate.validate()?;
    Ok(candidate)
}

/// Content-address the attribution identity from its exact subject and lineage.
///
/// Two different records of the same subject, or the same record under a
/// different subject version, never share one attribution identity.
fn attribution_identity(
    input: &UseAttributionOwnerInput<'_>,
    subject: &AttributedSubject,
) -> Result<ArtifactId, AttributionRefusal> {
    let bytes = canonical_json_bytes(&(
        input.source_delta_id.as_str(),
        input.source_delta_digest,
        subject.id.as_str(),
        subject.version.as_str(),
        subject.digest.as_str(),
    ))
    .map_err(|_| AttributionRefusal::Owner(LearningContractError::Canonicalization))?;
    ArtifactId::new(format!("use-attribution:{}", sha256_hex(&bytes)))
        .map_err(|_| AttributionRefusal::Owner(LearningContractError::Foundation))
}

/// Collect the owner evidence handles the attribution is built from.
///
/// Every handle is an owner-issued, content-addressed receipt or evidence
/// reference. Nothing is added for presence alone, and the set is deduplicated
/// so the same receipt cannot inflate the evidence list.
fn attribution_evidence_refs(
    activation: &HarnessActivationReceiptCandidate,
    decision: &DecisionOwnerRecord<'_>,
    basis: &UseBasisOwnerRecord<'_>,
    evaluation: &LearningAssessmentCandidate,
    independence: &IndependentObservationReceipt,
) -> Vec<ArtifactId> {
    let mut refs = vec![
        activation.activation_id.clone(),
        decision.owner_receipt.clone(),
        basis.owner_receipt.clone(),
        basis.acceptance_item_ref.clone(),
        evaluation.assessment_receipt.clone(),
        independence.receipt_id.clone(),
        independence.route_owner_receipt.clone(),
    ];
    if let Some(use_ref) = &activation.activation.first_qualifying_observable_use_ref {
        refs.push(use_ref.clone());
    }
    for dimension in &evaluation.dimensions {
        if let Some(receipt) = &dimension.owner_receipt {
            refs.push(receipt.clone());
        }
        refs.extend(dimension.evidence.iter().cloned());
        refs.extend(dimension.metric_ids.iter().cloned());
    }
    sorted_unique_refs(refs)
}
