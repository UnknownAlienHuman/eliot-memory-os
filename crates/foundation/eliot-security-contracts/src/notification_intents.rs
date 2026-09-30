//! Named-owner notification and reassessment intents for the I8.8 indicator
//! inventory (issue #1760 W7, I8.7/I8.8 response, I13.10, I13.8).
//!
//! I8.8 asks the producer to "notify the named task/security/Human decision
//! owner with evidence, not alarmist prose", and separately to "open
//! Problem/Incident for high impact". Those are two different things, and this
//! module keeps them apart. A notification is a retained record addressed to a
//! named owner. High impact is an **input to the Incident-promotion gate** —
//! there is no field, variant or method anywhere below that opens an Incident,
//! and there is no reason vocabulary, because the closed reason set and the
//! promotion authority belong to `eliot-problem` (#1759) and are not restated
//! here.
//!
//! Four properties are structural rather than documented:
//!
//! - **High impact is derived, never declared.** It is a function of the
//!   retained record's own resolution through the finite indicator-to-source
//!   map, so a caller cannot assert it. A `ModelProposal` record, a record with
//!   missing comparison inputs, and every content-shaped class resolve to
//!   `CandidateOnly`, and therefore never carry high impact at all — the same
//!   "model opinion alone cannot open Incident" rule I13.10 states for Signals.
//! - **Publication dedups on an independent identity.** The identity is a
//!   digest over the notification's own content — assessed source revision,
//!   indicator class, observation provenance, evidence, owner, scope, impact —
//!   recomputed from the record each time. It is not a counter, a sequence
//!   number or a mutable field, so a replay of the same observation produces
//!   the same identity and no second entry.
//! - **Reassessment appends.** A later observation is pushed onto a retained
//!   list behind [`SecurityNotification::append_reassessment`]; nothing removes
//!   or replaces the original observation or its evidence. There is no removal
//!   entry point, and the appended entry must carry an observation identity
//!   distinct from the ones already retained.
//! - **Release needs fresh discriminating evidence.** A release cites evidence
//!   that is absent from everything the notification already retains, so
//!   re-observing the same handles cannot re-admit a restriction, and it names
//!   a profile revision different from the one the notification was prepared
//!   under. The release is itself appended: the assessment that motivated the
//!   restriction stays in the record after the restriction is released.
//!
//! Scope note: restoring authority to an already revoked generation is owned by
//! the existing influence-revocation and rebuild owners and is deliberately not
//! reachable from here. Nothing in this module mutates a
//! [`SourceAssurance`](crate::SourceAssurance), clears a quarantine state, or
//! re-grants a revoked use and effect; the release recorded here is the
//! authorized *decision* evidence, and the quarantine owner remains the only
//! thing that can act on it.

use eliot_contracts::StateFence;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::SecurityContractError;
use crate::injection_indicators::{
    IndicatorClass, IndicatorObservation, IndicatorResolution, IndicatorSourceMap,
};
use crate::surface_types::{
    AssessedSourceRevision, EffectCeiling, SourceAssessmentScope, assessment_refs, assessment_text,
};

/// Domain separator for the publication identity digest.
const PUBLICATION_IDENTITY_DOMAIN: &str = "eliot.security.notification-publication-identity.v1";

/// What the named owner is being told, in the closed vocabulary of this
/// contract.
///
/// `HighImpact` is the only variant that carries a promotion-gate input, and
/// [`SecurityNotification::promotion_input`] is the only way to obtain it. A
/// notification whose impact is `Recorded` returns `None` there, so high impact
/// has no route to anything but a review.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SecurityNotificationImpact {
    /// Retained for the named owner. No promotion input is expressible.
    Recorded,
    /// Assessed as high impact. This is an input to the Incident-promotion gate
    /// and nothing else; it is not an Incident and it opens nothing.
    HighImpact,
}

/// The evidence a high-impact notification presents to the Incident-promotion
/// gate.
///
/// This is a request, not a decision, and it is deliberately shaped so that no
/// caller can promote from it: it names no authority, carries no reason
/// vocabulary, and has no method that changes any Incident state. The closed
/// reason set and the promoting authority live in `eliot-problem::Incident`,
/// which decides on a retained review request. A model-proposed observation
/// cannot produce one, because its record resolves to
/// [`IndicatorResolution::CandidateOnly`] and therefore to
/// [`SecurityNotificationImpact::Recorded`].
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SecurityPromotionReviewInput {
    /// The exact source revision, digest and scope the assessment covers.
    pub assessed_source: AssessedSourceRevision,
    /// The provenance of the observation that was assessed. A model proposal
    /// appears here with no rule identity, because it has none to give.
    pub requesting_observation: IndicatorObservation,
    /// The exact retained evidence handles behind the assessment.
    pub evidence_refs: Vec<String>,
    /// The impact the producer derived. A promotion input is only meaningful at
    /// high impact, and `validate` refuses any other value.
    pub impact: SecurityNotificationImpact,
}

impl SecurityPromotionReviewInput {
    /// Validates the input's own shape.
    ///
    /// # Errors
    ///
    /// Returns an error when the observation provenance is malformed, the
    /// evidence list is empty or duplicated, or the input is not at high impact.
    pub fn validate(&self) -> Result<(), SecurityContractError> {
        if self.impact != SecurityNotificationImpact::HighImpact {
            return Err(SecurityContractError::IndicatorImpactUnproven {
                field: "promotion_input.impact",
            });
        }
        self.requesting_observation.validate()?;
        assessment_refs(&self.evidence_refs, "promotion_input.evidence_refs")
    }
}

/// A later observation reconciled against a notification, appended to it.
///
/// This carries evidence only. It has no field for a verdict that would replace
/// what came before, and appending it never removes or rewrites the original
/// observation, so the original uncertainty is still on the record afterwards.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SecurityReassessment {
    /// The provenance of the later observation.
    pub observation: IndicatorObservation,
    /// The retained evidence handles this later observation adds. They are
    /// additional to the notification's own evidence, never a replacement for
    /// it.
    pub evidence_refs: Vec<String>,
}

impl SecurityReassessment {
    /// Validates the appended observation's own shape.
    ///
    /// # Errors
    ///
    /// Returns an error when the observation provenance is malformed or the
    /// evidence list is empty or duplicated.
    pub fn validate(&self) -> Result<(), SecurityContractError> {
        self.observation.validate()?;
        assessment_refs(&self.evidence_refs, "reassessment.evidence_refs")
    }
}

/// An authorized decision to release the restriction a notification describes.
///
/// This is decision evidence, appended to the record. It does not clear a
/// quarantine state, widen a permitted use or effect, or act on a revoked
/// generation: the quarantine owner stays the only thing that can apply it.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AuthorizedSecurityRelease {
    /// The authorized decision or deterministic rule that admitted the release.
    pub authorizing_ref: String,
    /// The profile revision the release is admitted under. It must differ from
    /// the revision the notification was prepared under, so a release always
    /// lands on a new profile rather than the one that produced the finding.
    pub profile_revision: String,
    /// Evidence that discriminates the original assessment from its
    /// alternatives.
    ///
    /// Every handle here must be absent from everything the notification
    /// already retains. That is what makes it fresh: re-observing the same
    /// handles cites evidence already on the record and is refused, so a
    /// restriction cannot be re-admitted on a repeat of the same assessment.
    pub discriminating_evidence_refs: Vec<String>,
}

impl AuthorizedSecurityRelease {
    /// Validates the release's own shape.
    ///
    /// Freshness against the retained evidence and the new profile revision are
    /// checked by [`SecurityNotification::validate`], which is the only place
    /// that can see what the notification already retains.
    ///
    /// # Errors
    ///
    /// Returns an error when the authorizing reference or profile revision is
    /// blank, or when the discriminating evidence list is empty or duplicated.
    pub fn validate(&self) -> Result<(), SecurityContractError> {
        assessment_text(&self.authorizing_ref, "release.authorizing_ref")?;
        assessment_text(&self.profile_revision, "release.profile_revision")?;
        assessment_refs(
            &self.discriminating_evidence_refs,
            "release.discriminating_evidence_refs",
        )
    }
}

/// One retained notification of a security-source finding to a named owner.
///
/// The record carries what the named owner needs to decide — the exact source
/// revision and digest, the indicator class, the observation's rule and
/// provenance, the evidence handles, the affected scope, the pending effects
/// and the resolution condition — and nothing that would let it decide. There
/// is no field for a standing instruction, a tool definition, a policy, a
/// credential, an Incident or an Incident state.
///
/// A notification is produced by
/// [`crate::SourceSecurityAssessment::notification`], which derives every field
/// from the assessment's own retained record, so a caller cannot restate a
/// different source, scope or impact than the one assessed.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SecurityNotification {
    /// The exact source revision, digest and scope this notification covers.
    pub assessed_source: AssessedSourceRevision,
    /// The indicator class that was classified.
    pub indicator: IndicatorClass,
    /// The provenance of the classified observation, carrying the deterministic
    /// rule and its revision when the producer has one.
    pub observation: IndicatorObservation,
    /// The exact retained evidence handles behind the classification.
    pub evidence_refs: Vec<String>,
    /// The affected scope, taken verbatim from the assessment this notification
    /// was produced from.
    pub scope: SourceAssessmentScope,
    /// The effect ceilings left admissible by the restriction in question.
    ///
    /// Empty for a candidate-only resolution, which restricts nothing and so has
    /// no pending effect to report.
    pub pending_effects: Vec<EffectCeiling>,
    /// The condition that would resolve this finding, when the retained record
    /// stated one. A record that may propose no restriction states none.
    pub resolution_condition: Option<String>,
    /// The named task/security/Human decision owner this notification is
    /// addressed to.
    ///
    /// The route behind the name — task issue to the Task Controller, security
    /// and integrity to the System Owner/Recovery Principal — is selected by the
    /// Problem owner through `eliot_problem::OwnerRoute::for_class`, and the
    /// lease-backed name itself is issued by its own owner. This contract
    /// carries the name it was given and requires it to be present; it does not
    /// mint, guess or synthesize an owner.
    pub owner_ref: String,
    /// The profile revision the notification was prepared under. A release must
    /// name a different one.
    pub profile_revision: String,
    /// The impact derived from the retained record's own resolution.
    pub impact: SecurityNotificationImpact,
    /// Later observations reconciled against this notification, appended.
    #[serde(default)]
    pub reassessments: Vec<SecurityReassessment>,
    /// Authorized release decisions recorded against this notification,
    /// appended. The finding that motivated them is retained unchanged.
    #[serde(default)]
    pub releases: Vec<AuthorizedSecurityRelease>,
    /// The fence the notification was prepared under.
    pub state_fence: StateFence,
}

impl SecurityNotification {
    /// The content identity a publication is deduplicated on.
    ///
    /// Recomputed from the notification's own fields every time, over the
    /// assessed source revision and digest, the indicator class, the observation
    /// provenance, the evidence handles, the owner, the scope, the pending
    /// effects, the resolution condition and the derived impact. The retained
    /// reassessments and releases are excluded on purpose: they are the
    /// notification's own appended history, so including them would make a
    /// replay of an unchanged observation look like a new notification after the
    /// first reconciliation.
    ///
    /// # Errors
    ///
    /// Returns an error when this notification cannot be serialized
    /// canonically, which is the one condition under which no identity can be
    /// stated for it.
    pub fn publication_identity(&self) -> Result<String, SecurityContractError> {
        #[derive(serde::Serialize)]
        struct Identity<'a> {
            domain: &'static str,
            assessed_source: &'a AssessedSourceRevision,
            indicator: IndicatorClass,
            observation: &'a IndicatorObservation,
            evidence_refs: &'a [String],
            scope: &'a SourceAssessmentScope,
            pending_effects: &'a [EffectCeiling],
            resolution_condition: &'a Option<String>,
            owner_ref: &'a str,
            profile_revision: &'a str,
            impact: SecurityNotificationImpact,
        }

        let bytes = eliot_contracts::canonical_json_bytes(&Identity {
            domain: PUBLICATION_IDENTITY_DOMAIN,
            assessed_source: &self.assessed_source,
            indicator: self.indicator,
            observation: &self.observation,
            evidence_refs: &self.evidence_refs,
            scope: &self.scope,
            pending_effects: &self.pending_effects,
            resolution_condition: &self.resolution_condition,
            owner_ref: &self.owner_ref,
            profile_revision: &self.profile_revision,
            impact: self.impact,
        })
        .map_err(|error| SecurityContractError::Serialization(error.to_string()))?;
        Ok(eliot_contracts::sha256_hex(&bytes))
    }

    /// Validates the notification and everything appended to it.
    ///
    /// A high-impact notification is refused unless its own observation carries
    /// an independent deterministic rule binding, which is the case
    /// [`Self::promotion_input`] already requires and the case a model proposal
    /// can never satisfy. A release is refused unless it cites evidence the
    /// notification does not already retain and names a different profile
    /// revision, so a restriction cannot be re-admitted on a re-observation.
    /// A reassessment is refused when it repeats an observation identity already
    /// retained, which is the append-side of the same dedup.
    ///
    /// # Errors
    ///
    /// Returns an error when the source, scope, observation, evidence, owner,
    /// profile revision or fence is malformed; when the impact is high without
    /// an independent rule binding; when an appended observation or its evidence
    /// is malformed or repeats retained content; or when a release is not fresh.
    pub fn validate(&self) -> Result<(), SecurityContractError> {
        assessment_text(&self.assessed_source.source_ref, "notification.source_ref")?;
        assessment_text(&self.assessed_source.revision, "notification.revision")?;
        assessment_text(&self.scope.scope_ref, "notification.scope.scope_ref")?;
        self.observation.validate()?;
        assessment_refs(&self.evidence_refs, "notification.evidence_refs")?;
        assessment_text(&self.owner_ref, "notification.owner_ref")?;
        assessment_text(&self.profile_revision, "notification.profile_revision")?;
        self.state_fence
            .validate()
            .map_err(|_| SecurityContractError::InvalidFence {
                field: "notification.state_fence",
            })?;
        if self.impact == SecurityNotificationImpact::HighImpact
            && self.observation.rule_binding().is_none()
        {
            return Err(SecurityContractError::IndicatorImpactUnproven {
                field: "notification.observation",
            });
        }

        let mut retained = self.retained_evidence();
        for reassessment in &self.reassessments {
            reassessment.validate()?;
            if self.observes(&reassessment.observation) {
                return Err(SecurityContractError::DuplicateReference {
                    field: "notification.reassessments.observation",
                });
            }
            retained.extend(reassessment.evidence_refs.iter().map(String::as_str));
        }
        for release in &self.releases {
            release.validate()?;
            if release.profile_revision == self.profile_revision {
                return Err(SecurityContractError::IndicatorReleaseNotAdmissible {
                    field: "notification.releases.profile_revision",
                });
            }
            if release
                .discriminating_evidence_refs
                .iter()
                .any(|reference| retained.contains(&reference.as_str()))
            {
                return Err(SecurityContractError::IndicatorReleaseNotAdmissible {
                    field: "notification.releases.discriminating_evidence_refs",
                });
            }
        }
        Ok(())
    }

    /// Appends a later observation to this notification's history.
    ///
    /// The candidate is validated before it replaces anything, so a refused
    /// reassessment leaves the record byte-identical. Nothing is removed: the
    /// original observation, its evidence and its impact are still on the
    /// record afterwards, which is what keeps a reconciliation from laundering
    /// the uncertainty it followed.
    ///
    /// # Errors
    ///
    /// Returns an error when the appended observation or its evidence is
    /// malformed, when it repeats an observation identity this notification
    /// already retains, when the fence in force is not this notification's, or
    /// when the resulting record would not validate.
    pub fn append_reassessment(
        &mut self,
        expected_fence: &StateFence,
        reassessment: SecurityReassessment,
    ) -> Result<(), SecurityContractError> {
        if self.state_fence != *expected_fence {
            return Err(SecurityContractError::FenceMismatch);
        }
        reassessment.validate()?;
        if self.observes(&reassessment.observation) {
            return Err(SecurityContractError::DuplicateReference {
                field: "notification.reassessments.observation",
            });
        }
        let mut candidate = self.clone();
        candidate.reassessments.push(reassessment);
        candidate.validate()?;
        *self = candidate;
        Ok(())
    }

    /// Appends an authorized release decision to this notification's history.
    ///
    /// The release is admitted only against fresh discriminating evidence: every
    /// handle it cites must be absent from everything this notification already
    /// retains, and it must name a different profile revision. A refused release
    /// leaves the record byte-identical, so a refusal is itself visible rather
    /// than a silent no-op. The finding that motivated the restriction is
    /// retained unchanged whatever the outcome.
    ///
    /// # Errors
    ///
    /// Returns an error when the release is malformed, cites evidence the
    /// notification already retains, names the current profile revision, when
    /// the fence in force is not this notification's, or when the resulting
    /// record would not validate.
    pub fn append_release(
        &mut self,
        expected_fence: &StateFence,
        release: AuthorizedSecurityRelease,
    ) -> Result<(), SecurityContractError> {
        if self.state_fence != *expected_fence {
            return Err(SecurityContractError::FenceMismatch);
        }
        release.validate()?;
        let mut candidate = self.clone();
        candidate.releases.push(release);
        candidate.validate()?;
        *self = candidate;
        Ok(())
    }

    /// The input this notification presents to the Incident-promotion gate.
    ///
    /// `Some` only at high impact and only when the observation carries an
    /// independent deterministic rule binding, so a model-proposed record, an
    /// incomplete comparison and every content-shaped class return `None`. What
    /// comes back is a request that names the source, the provenance and the
    /// evidence; deciding on it, and any reason or authority for doing so,
    /// belongs to the Incident owner.
    ///
    /// # Errors
    ///
    /// Returns [`SecurityContractError::IndicatorImpactUnproven`] when the impact
    /// is high but the observation carries no independent rule binding, which is
    /// the one combination that could otherwise present itself to a gate.
    pub fn promotion_input(
        &self,
    ) -> Result<Option<SecurityPromotionReviewInput>, SecurityContractError> {
        if self.impact != SecurityNotificationImpact::HighImpact {
            return Ok(None);
        }
        if self.observation.rule_binding().is_none() {
            return Err(SecurityContractError::IndicatorImpactUnproven {
                field: "promotion_input.requesting_observation",
            });
        }
        let input = SecurityPromotionReviewInput {
            assessed_source: self.assessed_source.clone(),
            requesting_observation: self.observation.clone(),
            evidence_refs: self.evidence_refs.clone(),
            impact: self.impact,
        };
        input.validate()?;
        Ok(Some(input))
    }

    /// Whether this notification already records `observation`.
    ///
    /// Identity is the observation's own provenance: the producer identity, the
    /// revision it recorded for this observation, and the rule binding when it
    /// has one. A repeat of the same observation is therefore the same identity,
    /// and a genuinely later observation by any producer under any revision is
    /// a different one.
    fn observes(&self, observation: &IndicatorObservation) -> bool {
        observation == &self.observation
            || self
                .reassessments
                .iter()
                .any(|retained| retained.observation == *observation)
    }

    /// Every evidence handle this notification retains, its own and every
    /// appended reassessment's.
    fn retained_evidence(&self) -> Vec<&str> {
        self.evidence_refs
            .iter()
            .map(String::as_str)
            .chain(
                self.reassessments
                    .iter()
                    .flat_map(|reassessment| reassessment.evidence_refs.iter().map(String::as_str)),
            )
            .collect()
    }

    /// Builds the notification this retained record produces for a named owner.
    ///
    /// Every field is derived from the assessment and the record themselves, so
    /// a caller cannot restate a different source, scope, evidence or impact
    /// than the one assessed. The impact is the record's own resolution through
    /// the finite indicator-to-source map: high impact requires a bounded
    /// restriction, which requires an independent deterministic rule binding and
    /// complete comparison inputs, so a model-only record, a suspected pattern
    /// and an incomplete comparison all notify as `Recorded`.
    ///
    /// The `owner_ref` is the only caller-supplied identity, and the caller must
    /// hold the named owner's lease-backed name; the route behind it is selected
    /// by the Problem owner through `eliot_problem::OwnerRoute::for_class` and
    /// the Human escalation path is that owner's, not this contract's.
    ///
    /// # Errors
    ///
    /// Returns an error when the retained record, the named owner or the profile
    /// revision is malformed, or when the resolution would produce a restriction
    /// with no usable release condition.
    pub(crate) fn from_record(
        assessed_source: &AssessedSourceRevision,
        scope: &SourceAssessmentScope,
        record: &crate::RecordedIndicatorObservation,
        owner_ref: &str,
        profile_revision: &str,
        state_fence: &StateFence,
    ) -> Result<Self, SecurityContractError> {
        record.validate()?;
        assessment_text(owner_ref, "notification.owner_ref")?;
        assessment_text(profile_revision, "notification.profile_revision")?;
        let resolution = IndicatorSourceMap::resolve(
            record.indicator,
            &record.evidence,
            &record.observation,
            assessed_source,
            state_fence,
            record.release_condition.as_deref(),
        )?;
        let (impact, pending_effects) = match &resolution {
            IndicatorResolution::CandidateOnly { .. } => {
                (SecurityNotificationImpact::Recorded, Vec::new())
            }
            IndicatorResolution::BoundedRestriction(restriction) => (
                SecurityNotificationImpact::HighImpact,
                restriction.permitted_effects.to_vec(),
            ),
        };
        let notification = Self {
            assessed_source: assessed_source.clone(),
            indicator: record.indicator,
            observation: record.observation.clone(),
            evidence_refs: record.evidence.cited_refs(),
            scope: scope.clone(),
            pending_effects,
            resolution_condition: record.release_condition.clone(),
            owner_ref: owner_ref.to_owned(),
            profile_revision: profile_revision.to_owned(),
            impact,
            reassessments: Vec::new(),
            releases: Vec::new(),
            state_fence: state_fence.clone(),
        };
        notification.validate()?;
        Ok(notification)
    }
}

/// The retained publication history for one source scope.
///
/// Replayed observations and repeated publication intents land here. The
/// denominator is each notification's own recomputed content identity, so a
/// replay is recognised by the record matching the one already held rather than
/// by a counter that a second delivery would advance.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SecurityNotificationHistory {
    /// Retained notifications, in publication order.
    pub notifications: Vec<SecurityNotification>,
    /// The scope this history covers.
    pub scope_ref: String,
    /// The fence the history was opened under.
    pub state_fence: StateFence,
}

/// What publishing a notification to a history actually did.
///
/// `Replayed` is the ordinary outcome of a redelivery, not a failure: the
/// notification is already held, so no second entry and no second history row
/// were produced.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(
    tag = "outcome",
    rename_all = "SCREAMING_SNAKE_CASE",
    deny_unknown_fields
)]
pub enum SecurityPublication {
    /// A new notification was retained.
    Published {
        /// The identity it was retained under.
        identity: String,
    },
    /// An equivalent notification was already retained, so nothing was added.
    Replayed {
        /// The identity already held.
        identity: String,
    },
}

impl SecurityNotificationHistory {
    /// Validates the history and every notification it retains.
    ///
    /// Two entries sharing a publication identity are refused, so a history
    /// assembled by hand cannot hold a second copy of one notification even
    /// though publishing one would have deduplicated it.
    ///
    /// # Errors
    ///
    /// Returns an error when the scope or fence is malformed, when a retained
    /// notification does not validate, or when two retained notifications share
    /// one publication identity.
    pub fn validate(&self) -> Result<(), SecurityContractError> {
        assessment_text(&self.scope_ref, "history.scope_ref")?;
        self.state_fence
            .validate()
            .map_err(|_| SecurityContractError::InvalidFence {
                field: "history.state_fence",
            })?;
        for notification in &self.notifications {
            notification.validate()?;
        }
        let mut seen: Vec<String> = Vec::new();
        for identity in self.identities()? {
            if seen.contains(&identity) {
                return Err(SecurityContractError::DuplicateReference {
                    field: "history.notifications",
                });
            }
            seen.push(identity);
        }
        Ok(())
    }

    /// The publication identity of every notification this history retains.
    ///
    /// One place, so the denominator a publication is deduplicated against and
    /// the set a validation refuses a duplicate in are the same set.
    fn identities(&self) -> Result<Vec<String>, SecurityContractError> {
        self.notifications
            .iter()
            .map(SecurityNotification::publication_identity)
            .collect()
    }

    /// Publishes a notification, or recognises it as a replay of one already
    /// held.
    ///
    /// The notification is validated first, so a malformed or unauthorised one
    /// is refused rather than retained. Its publication identity is then
    /// recomputed from its own content and compared against the identities
    /// already held. A match appends nothing and reports
    /// [`SecurityPublication::Replayed`]; anything else appends it and reports
    /// [`SecurityPublication::Published`]. The candidate history is validated
    /// before it replaces the live one, so a refused publication leaves the
    /// history byte-identical.
    ///
    /// # Errors
    ///
    /// Returns an error when the fence in force is not this history's, when the
    /// notification does not validate, or when the resulting history would not.
    pub fn publish(
        &mut self,
        expected_fence: &StateFence,
        notification: SecurityNotification,
    ) -> Result<SecurityPublication, SecurityContractError> {
        if self.state_fence != *expected_fence {
            return Err(SecurityContractError::FenceMismatch);
        }
        notification.validate()?;
        let identity = notification.publication_identity()?;
        if self.identities()?.iter().any(|held| held == &identity) {
            return Ok(SecurityPublication::Replayed { identity });
        }
        let mut candidate = self.clone();
        candidate.notifications.push(notification);
        candidate.validate()?;
        *self = candidate;
        Ok(SecurityPublication::Published { identity })
    }
}
