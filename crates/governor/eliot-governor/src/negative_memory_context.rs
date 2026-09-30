//! Issue #1731 W7: expose the SAME admitted negative-memory rule and evidence
//! the enforcement side uses, in the existing negative-memory Context
//! projection and in the #1726 `QualityScorecard` axis.
//!
//! # Exposure, not a second gate
//!
//! The Governor owns semantic admission of the rule and its action policy
//! (`negative_memory_gate` applies it) and this crate owns neither the durable
//! record ([`eliot_dreamer_failure::NegativeMemoryFingerprint`]) nor the
//! comparison ([`eliot_dreamer_failure::match_negative_memory`]). This module
//! reads the matcher's already-produced
//! [`NegativeMemoryMatchResult`](eliot_dreamer_failure::NegativeMemoryMatchResult)
//! together with the already-admitted
//! [`NegativeMemoryActionPolicy`] values and makes them readable to Context.
//! It performs no comparison, admits no rule, and returns no block/allow
//! decision.
//!
//! # I12.19 — a warning is never governing authority
//!
//! A near match carries its differing field names and is exposed as
//! [`NegativeMemoryApplicability::NearAdvisory`], which is not
//! [`NegativeMemoryRuleExposure::Governing`]. Only an exact match backed by a
//! policy whose `validate_binding` proves it is admitted for that exact record
//! revision becomes governing, and even then the exposure records the admitted
//! disposition rather than applying it. Prose is never authority: every
//! [`AdmittedNegativeMemoryRule`] carries the rule identity, rule revision and
//! record content digest, so a caller can check the rule actually in force.
//!
//! The identity proof reuses the existing owners unchanged. `admitted_rule`
//! calls [`NegativeMemoryFingerprint::validate`] to check the ORIGINAL recorded
//! value — the record's own recomputed content digest and every cross-field
//! join — and then [`NegativeMemoryActionPolicy::validate_binding`], which
//! compares the policy's recorded identity, revision and digest against that
//! record's content. Nothing here recomputes a fresh checksum over what the
//! caller holds and calls that a check.
//!
//! # I12.16 / I1.8 — bound to the read that produced the comparison
//!
//! The projection carries the matcher's own
//! [`MatchEvidence`](eliot_dreamer_failure::MatchEvidence): the named read
//! handle (I1.8), the rule-set revision head observed before comparison
//! (I12.16 Fence A), the rule-set and assessed-candidate digests, and the
//! compared field counts. The exposure never re-derives or substitutes any of
//! them, so a caller can re-check freshness, scope and coverage from the
//! projection instead of from a summary.
//!
//! # I12.19 / I12.16 — a loss is a loss, never a reconstruction
//!
//! [`NegativeMemoryEvidenceLoss`] separates "the comparison could not be
//! decided" from "the governing backing record or policy could not be read".
//! Either loss forces [`NegativeMemoryApplicability::Undetermined`], which is
//! not absence: `certifies_rule_absence` is reachable only from
//! [`NegativeMemoryApplicability::Absent`], which is reachable only from a
//! matcher result that itself certifies rule absence. Evidence is never
//! rebuilt from the match summary — a matched rule whose record or policy is
//! absent is exposed as a named loss, not reconstructed from the comparison.
//!
//! # #1726 W3 — the scorecard is constructed from compilation evidence
//!
//! [`quality_axis_results`] writes all twelve axes of one
//! [`QualityScorecard`] from the compilation records themselves: the
//! [`AdmittedContextSet`] (admission, floor, economy and omission records), the
//! ordered [`RenderedAtom`] projection, the assembly owner's
//! [`SerializedContextMeasurement`] and [`ContextExecutionIdentity`], the exact
//! [`DecisionExecutionLineageRefs`] the decision owner issued, and this
//! module's own [`NegativeMemoryRuleProjection`]. Before this existed a card
//! arrived fully populated from an external caller, and the only axis this crate
//! ever wrote was the negative-memory one, from a projection that nothing
//! showed described the packet being graded.
//!
//! Four rules hold on every axis, and they are what makes the results evidence
//! rather than restatement:
//!
//! 1. **The expected set is never the caller's list.** Each axis derives its
//!    required member set from a record this module reads — the decision
//!    owner's own lineage relations, the admission owner's per-member source
//!    identity, the economy receipt's authorised-omission set, the floor
//!    owner's own capacity — compares content rather than handles, and then
//!    accounts for the *whole* admitted set against the *whole* rendered
//!    projection in **both** directions before any axis is graded. A count that
//!    can only go down is not accounting.
//! 2. **A role, label or keyword never establishes a fact.** Decision, causal
//!    and verifier readiness are graded from the task/requirement owner's own
//!    `Present` lineage members and their typed values, never from a
//!    `SemanticRole`; a role-labelled member that preserves none of the
//!    owner's references is itself a named missing member. Provenance consumes
//!    the exact source snapshot identity, revision, content digest and owner the
//!    ADMISSION owner recorded — re-proved by `AdmittedContextSet::validate`,
//!    which calls each record's own `SourceSnapshot::validate` — and compares
//!    them BY VALUE to the delivered member's own lineage. The State Fence
//!    half is the packet's own fence, recomputed by the context contract owner
//!    and compared by value to the decision owner's epoch. Rivals, conflicts,
//!    unknowns and instructions are graded by comparing *required* members
//!    against *preserved* ones, so one representative atom per role cannot
//!    stand for the set. Route, layout, reconstruction and telemetry cost read
//!    the measurement owner's own status and recorded values, so a cost is
//!    measured or explicitly unknown.
//! 3. **A pass is a lower bound, never a shortcut.** `Failed` and `Unknown` are
//!    derived from the lists and never chosen. An axis is never degraded or
//!    declared inapplicable on the strength of a "looks like" judgement: the one
//!    `Degraded` this module constructs is the negative-memory axis, and only
//!    where the matcher's OWN retained limitations or the projection's OWN
//!    named losses state the limitation. An axis that would otherwise have an
//!    empty required set is given an explicit named requirement instead, so no
//!    axis can pass vacuously, and `Unknown` carries the exact missing handle.
//! 4. **No semantic oracle runs here.** There is no model invocation, no
//!    retrieval, no similarity relation and no re-derivation of an owner's
//!    answer. The only computations are value comparisons, byte-substring
//!    matches over the packet's own recorded representations, and arithmetic on
//!    numbers an owner recorded.
//!
//! Anything this module cannot establish from those records is reported as a
//! named missing member or as a typed [`QualityEvidenceError`], never dropped
//! and never passed.

use std::collections::{BTreeMap, BTreeSet};

use eliot_context_contracts::{
    AdmittedAtom, AdmittedContextSet, AtomAvailability, AtomRepresentation, AuthorityClass,
    ContextBinding, ContextExecutionIdentity, DecisionExecutionLineageRefs,
    DecisionLineageCompleteness, DecisionLineagePhase, DecisionLineageRef, DecisionLineageSlot,
    MeasurementRef, MeasurementStatus, QUALITY_DIMENSIONS, QUALITY_RESULT_SCHEMA_VERSION,
    QualityDimension, QualityDimensionResult, QualityDimensionState, QualityScorecard,
    RenderedAtom, SemanticRole, SerializedContextMeasurement, canonical_fence_digest,
};
use eliot_contracts::ArtifactId;
use eliot_dreamer_failure::{
    IdentityRelation, IncompleteReason, MatchEvidence, NegativeMemoryActionPolicy,
    NegativeMemoryDisposition, NegativeMemoryFingerprint, NegativeMemoryHorizonRelation,
    NegativeMemoryMatchKind, NegativeMemoryMatchResult, NegativeMemoryOutcome,
};
use eliot_evidence::EpistemicStatus;
use eliot_receipts::ProofCeiling;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Wire revision of the admitted negative-memory exposure family.
pub const NEGATIVE_MEMORY_EXPOSURE_SCHEMA_VERSION: u32 = 1;

/// Maximum admitted rules one exposure may carry.
pub const MAX_ADMITTED_NEGATIVE_MEMORY_RULES: usize = 64;

/// Maximum compared-dimension identities one rule may expose.
pub const MAX_NEGATIVE_MEMORY_DIMENSIONS: usize = 256;

/// Maximum named losses one exposure may carry.
pub const MAX_NEGATIVE_MEMORY_LOSSES: usize = 64;

/// Maximum bytes of one exposed text field.
pub const MAX_NEGATIVE_MEMORY_EXPOSURE_TEXT: usize = 1024;

/// Fail-closed refusals from the pure exposure composer.
///
/// Every variant means the caller cannot read a governing rule from the values
/// it holds. None is a disposition and none is a block.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum NegativeMemoryExposureError {
    /// A bound text field was blank, control-bearing or over its bound.
    #[error("negative memory exposure field is invalid: {0}")]
    InvalidField(&'static str),
    /// A collection was empty, duplicated or over its own bound.
    #[error("negative memory exposure bound exceeded: {0}")]
    Bounds(&'static str),
    /// The exposure does not bind one admission identity, or a supplied value
    /// failed its own owner validation.
    #[error("negative memory exposure binding is inconsistent: {0}")]
    BindingInconsistent(&'static str),
}

/// Which recorded identity one exposed compared dimension covers.
#[derive(
    Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum NegativeMemoryDimensionKind {
    /// A recorded trigger-predicate dimension.
    TriggerPredicate,
    /// A recorded owner-issued scope, action, resource or environment field.
    ScopeIdentity,
}

/// One exposed compared dimension, read back from the matcher's own comparison.
///
/// The relation is the matcher's typed verdict, not a reformulation: no
/// substring, display-name or similarity relation exists in this type, so a
/// semantic near-miss can never be represented as an exact identity here.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NegativeMemoryComparedDimension {
    /// Which recorded identity this comparison covers.
    pub dimension_kind: NegativeMemoryDimensionKind,
    /// The owner-declared dimension or identity field name.
    pub field: String,
    /// The exact relation the matcher decided between the recorded and
    /// observed values.
    pub relation: IdentityRelation,
}

/// The validity of one exposed rule, in the rule's own clock/revision domain.
///
/// This is the recorded state, not a decision. An elapsed or unresolved horizon
/// is exposed rather than dropped, because a dropped rule cannot be
/// distinguished from one that was never admitted.
#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum NegativeMemoryRuleValidity {
    /// The observed reading is strictly inside the recorded do-not-repeat
    /// horizon, so the bound still elapses.
    InForce {
        /// Remaining owner-issued sequence distance to the bound.
        remaining_sequence_gap: u64,
    },
    /// The recorded horizon has been reached, so the bound no longer elapses.
    HorizonReached {
        /// The observed owner-issued sequence.
        observed_sequence: u64,
    },
    /// The recorded horizon names another clock/revision domain, so elapse
    /// decides nothing and this rule's validity is unresolved.
    HorizonUnresolved {
        /// Domain identity named by the record.
        recorded_domain_id: String,
        /// Domain identity the caller supplied.
        observed_domain_id: String,
    },
}

/// The recorded reopen state of one exposed rule.
///
/// The reopen condition is recorded, not evaluated: the matcher never evaluates
/// it and neither does this module. `ReopenUnobserved` is the honest default
/// when the caller has not supplied the reopening result, and it is
/// distinguishable from `Reopened`.
#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum NegativeMemoryRuleInvalidation {
    /// The recorded reopen condition is retained and no reopening evidence has
    /// been observed, so the rule still stands.
    Standing,
    /// The recorded reopen condition's required verifier has been named but its
    /// result is not part of this exposure.
    ReopenUnobserved {
        /// The owner-issued verifier that must produce the reopening evidence.
        required_verifier: String,
    },
    /// The recorded reopen condition has been satisfied, so the rule is no
    /// longer in force. The original failure episode is retained regardless.
    Reopened,
    /// The record's trigger is advisory and unresolved, so it can never satisfy
    /// an exact predicate and can never be read as any-scope.
    AdvisoryOnly,
}

/// How much authority one exposed rule carries in Context.
///
/// This is the single field that separates governing authority from a warning.
/// [`Self::Advisory`] covers both a near match and an advisory/unresolved
/// trigger, so a caller cannot obtain an advisory rule that reads as authority
/// by inspecting any other field.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum NegativeMemoryRuleExposure {
    /// The exact predicate and every owner-issued identity matched, and the
    /// owner's policy is admitted for that exact record revision.
    Governing {
        /// The owner-admitted disposition. It is recorded here, not applied.
        admitted_disposition: NegativeMemoryDisposition,
    },
    /// The rule is recorded but is not exact or not backed by an admitted
    /// policy. It warns and never blocks.
    Advisory,
}

/// The permitted next action for one exposed rule.
///
/// An `Admitted` action names the owner's own admitted policy, including the
/// discriminating check a `RequireCheck` disposition requires. `None` means the
/// owner admitted no policy for this exact record revision, which is an exposed
/// fact and never an implicit `Advisory` disposition.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum NegativeMemoryPermittedNextAction {
    /// The owner admitted this action policy for the exposed rule revision.
    Admitted {
        /// Owner-issued policy identity.
        policy_id: String,
        /// Monotone policy revision.
        policy_revision: u64,
        /// The discriminating check a `RequireCheck` disposition requires.
        /// Empty for every other disposition, exactly as the policy records it.
        named_check_id: String,
    },
    /// The owner has published no policy for this exact record revision.
    NoneAdmitted,
}

/// One admitted negative-memory rule, exposed with its exact identity.
///
/// Every identity field is the record's own, so a caller can check
/// `record_digest` against the rule actually in force; nothing here re-derives
/// it, and [`admitted_rule`] proves the match against the record before this
/// value exists.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AdmittedNegativeMemoryRule {
    /// Wire revision of this exposure value; must be 1.
    pub schema_version: u32,
    /// Immutable record identity of the exposed rule.
    pub record_id: String,
    /// Immutable rule revision of the exposed rule.
    pub rule_revision: u64,
    /// Content digest of the exposed rule revision, taken from the record.
    pub record_digest: String,
    /// Owner that holds semantic admission of the rule.
    pub semantic_owner: String,
    /// The violated invariant identity.
    pub invariant_id: String,
    /// The invariant revision the failure was assessed against.
    pub invariant_revision: String,
    /// How much authority this rule carries in Context.
    pub exposure: NegativeMemoryRuleExposure,
    /// Every compared dimension and the matcher's exact relation for it.
    pub compared_dimensions: Vec<NegativeMemoryComparedDimension>,
    /// The rule's validity in its own clock/revision domain.
    pub validity: NegativeMemoryRuleValidity,
    /// The rule's recorded reopen state.
    pub invalidation: NegativeMemoryRuleInvalidation,
    /// The owner-admitted permitted next action.
    pub permitted_next_action: NegativeMemoryPermittedNextAction,
}

/// What the exposure establishes about the compared subject.
///
/// `Absent` is the only value that clears a subject, and it is reachable only
/// from a matcher result that itself certifies rule absence — which the matcher
/// makes reachable only from a complete bounded enumeration. Every other value
/// leaves the subject uncleared, so an incomplete lookup can never be read as
/// "no applicable rule".
#[derive(
    Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum NegativeMemoryApplicability {
    /// One admitted rule's exact predicate and owner-issued identities matched.
    Matched,
    /// The same rule with at least one known, different identity: advisory only.
    NearAdvisory,
    /// A complete bounded enumeration compared every candidate and none
    /// applied, so the absence of an applicable rule is certified.
    Absent,
    /// The lookup was incomplete, unsupported, or its governing backing record
    /// or policy could not be read, so absence is NOT certified and the subject
    /// is not cleared.
    Undetermined,
}

impl NegativeMemoryApplicability {
    /// Whether this value clears the compared subject.
    ///
    /// This is [`NegativeMemoryMatchKind::certifies_rule_absence`] read off the
    /// exposure, so no other field of the projection can be inspected to reach
    /// the opposite conclusion.
    #[must_use]
    pub const fn certifies_rule_absence(self) -> bool {
        matches!(self, Self::Absent)
    }
}

/// One named reason the exposure does not establish a governing rule.
///
/// Each cause keeps its own variant, and every variant forces
/// [`NegativeMemoryApplicability::Undetermined`]. A caller that sees a loss can
/// never also read absence.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub enum NegativeMemoryEvidenceLoss {
    /// The comparison itself was not decidable. The matcher's own reason is
    /// retained verbatim; it is not summarised into prose here.
    ComparisonNotDecidable {
        /// The matcher's closed reason.
        reason: IncompleteReason,
    },
    /// The matched rule's backing record or its owner-admitted policy could not
    /// be read from the compared snapshot, so the governing content of the
    /// match cannot be exposed. The evidence is not reconstructed from the
    /// match summary.
    BackingAuthorityUnavailable {
        /// Identity of the rule whose backing could not be read.
        record_id: String,
        /// Its exact rule revision.
        rule_revision: u64,
        /// Whether the record or the policy was the missing member.
        missing: NegativeMemoryBackingMember,
    },
}

/// Which backing member of a matched rule could not be read.
#[derive(
    Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum NegativeMemoryBackingMember {
    /// The durable fingerprint record was not readable for the matched identity.
    Record,
    /// The owner admitted no readable policy for the matched record revision.
    Policy,
}

/// The exact negative-memory Context projection for one comparison.
///
/// It is the same admitted rule and evidence the enforcement side evaluates,
/// read through the same named read and the same record snapshot. It grants no
/// authority: `applicability`, each rule's `exposure`, and each rule's
/// `permitted_next_action` are all recorded facts, and applying them stays with
/// the Governor's gate.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NegativeMemoryRuleProjection {
    /// Wire revision of this projection; must be 1.
    pub schema_version: u32,
    /// What this exposure establishes about the compared subject.
    pub applicability: NegativeMemoryApplicability,
    /// Every exposed rule, in matcher order.
    pub rules: Vec<AdmittedNegativeMemoryRule>,
    /// The matcher's own evidence: named read handle, rule-set revision head
    /// observed before comparison, and the compared-field digests and counts.
    pub evidence: MatchEvidence,
    /// Every named reason a governing rule is not established here.
    pub losses: Vec<NegativeMemoryEvidenceLoss>,
}

impl NegativeMemoryRuleProjection {
    /// Whether this projection certifies that no applicable rule exists.
    #[must_use]
    pub const fn certifies_rule_absence(&self) -> bool {
        self.applicability.certifies_rule_absence()
    }

    /// The exact rules this projection exposes as governing authority.
    #[must_use]
    pub fn governing_rules(&self) -> Vec<&AdmittedNegativeMemoryRule> {
        self.rules
            .iter()
            .filter(|rule| matches!(rule.exposure, NegativeMemoryRuleExposure::Governing { .. }))
            .collect()
    }

    /// Whether any named loss blocks a governing conclusion.
    #[must_use]
    pub fn has_evidence_loss(&self) -> bool {
        !self.losses.is_empty()
    }

    /// Validates the projection's own shape and the coherence of its loss set.
    ///
    /// The expected set here is derived from the projection's OWN
    /// `applicability` and `losses`, the same two values the caller reads, so
    /// this is a coherence check rather than a second owner. It can only catch
    /// the one reading that would turn a loss into a pass: a projection that
    /// asserts absence while carrying a loss, or a projection that asserts
    /// `Undetermined` while carrying none.
    ///
    /// # Errors
    ///
    /// Returns [`NegativeMemoryExposureError`] for a bad version, a blank or
    /// over-bound text field, a duplicated rule identity, an over-bound
    /// collection, an exposure that contradicts the matcher's own outcome, or a
    /// loss set that contradicts the applicability it is reported with.
    pub fn validate(&self) -> Result<(), NegativeMemoryExposureError> {
        if self.schema_version != NEGATIVE_MEMORY_EXPOSURE_SCHEMA_VERSION {
            return Err(NegativeMemoryExposureError::InvalidField(
                "projection.schema_version",
            ));
        }
        check_exposure_text(
            &self.evidence.read_handle,
            "projection.evidence.read_handle",
        )?;
        check_exposure_text(
            &self.evidence.rule_set_revision,
            "projection.evidence.rule_set_revision",
        )?;
        if self.rules.len() > MAX_ADMITTED_NEGATIVE_MEMORY_RULES {
            return Err(NegativeMemoryExposureError::Bounds("projection.rules"));
        }
        let mut identities: Vec<(&str, u64)> = Vec::with_capacity(self.rules.len());
        for rule in &self.rules {
            rule.validate()?;
            let identity = (rule.record_id.as_str(), rule.rule_revision);
            if identities.contains(&identity) {
                return Err(NegativeMemoryExposureError::Bounds("projection.rules"));
            }
            identities.push(identity);
        }
        if self.losses.len() > MAX_NEGATIVE_MEMORY_LOSSES {
            return Err(NegativeMemoryExposureError::Bounds("projection.losses"));
        }
        if self.applicability.certifies_rule_absence() && !self.losses.is_empty() {
            return Err(NegativeMemoryExposureError::BindingInconsistent(
                "projection.losses",
            ));
        }
        if matches!(
            self.applicability,
            NegativeMemoryApplicability::Undetermined
        ) && self.losses.is_empty()
        {
            return Err(NegativeMemoryExposureError::BindingInconsistent(
                "projection.applicability",
            ));
        }
        if matches!(self.applicability, NegativeMemoryApplicability::Matched)
            && self.governing_rules().is_empty()
        {
            return Err(NegativeMemoryExposureError::BindingInconsistent(
                "projection.rules",
            ));
        }
        Ok(())
    }
}

impl AdmittedNegativeMemoryRule {
    /// Validates one exposed rule's identity, dimensions and admitted action.
    ///
    /// # Errors
    ///
    /// Returns [`NegativeMemoryExposureError`] for a bad version, a blank or
    /// over-bound identity, a non-positive rule revision, an over-bound or
    /// duplicated compared-dimension set, or a `RequireCheck` disposition whose
    /// admitted action names no discriminating check.
    pub fn validate(&self) -> Result<(), NegativeMemoryExposureError> {
        if self.schema_version != NEGATIVE_MEMORY_EXPOSURE_SCHEMA_VERSION {
            return Err(NegativeMemoryExposureError::InvalidField(
                "rule.schema_version",
            ));
        }
        check_exposure_text(&self.record_id, "rule.record_id")?;
        check_exposure_text(&self.record_digest, "rule.record_digest")?;
        check_exposure_text(&self.semantic_owner, "rule.semantic_owner")?;
        check_exposure_text(&self.invariant_id, "rule.invariant_id")?;
        check_exposure_text(&self.invariant_revision, "rule.invariant_revision")?;
        if self.rule_revision == 0 {
            return Err(NegativeMemoryExposureError::InvalidField(
                "rule.rule_revision",
            ));
        }
        if self.compared_dimensions.len() > MAX_NEGATIVE_MEMORY_DIMENSIONS {
            return Err(NegativeMemoryExposureError::Bounds(
                "rule.compared_dimensions",
            ));
        }
        let mut keys: Vec<(NegativeMemoryDimensionKind, &str)> =
            Vec::with_capacity(self.compared_dimensions.len());
        for dimension in &self.compared_dimensions {
            check_exposure_text(&dimension.field, "rule.compared_dimensions.field")?;
            let key = (dimension.dimension_kind, dimension.field.as_str());
            if keys.contains(&key) {
                return Err(NegativeMemoryExposureError::Bounds(
                    "rule.compared_dimensions",
                ));
            }
            keys.push(key);
        }
        match (&self.exposure, &self.permitted_next_action) {
            (
                NegativeMemoryRuleExposure::Governing {
                    admitted_disposition: NegativeMemoryDisposition::RequireCheck,
                },
                NegativeMemoryPermittedNextAction::Admitted { named_check_id, .. },
            ) => check_exposure_text(named_check_id, "rule.permitted_next_action").map_err(|_| {
                NegativeMemoryExposureError::InvalidField(
                    "rule.permitted_next_action.named_check_id",
                )
            }),
            (
                NegativeMemoryRuleExposure::Governing { .. },
                NegativeMemoryPermittedNextAction::NoneAdmitted,
            ) => Err(NegativeMemoryExposureError::BindingInconsistent(
                "rule.permitted_next_action",
            )),
            (
                NegativeMemoryRuleExposure::Advisory,
                NegativeMemoryPermittedNextAction::NoneAdmitted,
            ) => Ok(()),
            // Any other pairing is incoherent: an advisory rule can never carry
            // an admitted next action, and the two `Governing` shapes above are
            // the only governing pairings. The catch-all below refuses the rest.
            _ => Err(NegativeMemoryExposureError::BindingInconsistent(
                "rule.exposure",
            )),
        }
    }
}

fn check_exposure_text(
    value: &str,
    field: &'static str,
) -> Result<(), NegativeMemoryExposureError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(NegativeMemoryExposureError::InvalidField(field));
    }
    if value.len() > MAX_NEGATIVE_MEMORY_EXPOSURE_TEXT {
        return Err(NegativeMemoryExposureError::Bounds(field));
    }
    Ok(())
}

/// Proves one `policy` is the policy actually admitted for the rule `record`,
/// and exposes that rule from the matcher's own comparison.
///
/// The proof reuses the record and policy owners unchanged and checks the
/// ORIGINAL recorded values: [`NegativeMemoryFingerprint::validate`] verifies
/// the record's own content digest and every cross-field admission join, and
/// [`NegativeMemoryActionPolicy::validate`] plus
/// [`NegativeMemoryActionPolicy::validate_binding`] verify the policy and its
/// binding to that exact record identity, revision and content digest. A policy
/// bound to another rule revision is refused, never exposed.
///
/// When `policy` is `None` the rule is still exposed, as an advisory carrying
/// [`NegativeMemoryPermittedNextAction::NoneAdmitted`]: the owner admitting no
/// policy is a recorded fact, and it is never turned into an implicit
/// `Advisory` disposition or an implied next action.
///
/// # Errors
///
/// Returns [`NegativeMemoryExposureError::BindingInconsistent`] when the
/// matcher matched no rule, or when the matched identity or digest differs from
/// the record in force. Returns [`NegativeMemoryExposureError::InvalidField`]
/// when the record, the policy, or the composed exposure fails its own owner
/// validation.
pub fn admitted_rule(
    record: &NegativeMemoryFingerprint,
    policy: Option<&NegativeMemoryActionPolicy>,
    result: &NegativeMemoryMatchResult,
) -> Result<AdmittedNegativeMemoryRule, NegativeMemoryExposureError> {
    let inconsistent =
        |field: &'static str| NegativeMemoryExposureError::BindingInconsistent(field);
    let (exposure, permitted_next_action) = match &result.outcome {
        NegativeMemoryOutcome::Exact { matched } => {
            if matched.record_id != record.record_id
                || matched.rule_revision != record.rule_revision
            {
                return Err(inconsistent("admitted_rule.record_identity"));
            }
            if matched.record_digest != record.record_digest {
                return Err(inconsistent("admitted_rule.record_digest"));
            }
            match policy {
                None => (
                    NegativeMemoryRuleExposure::Advisory,
                    NegativeMemoryPermittedNextAction::NoneAdmitted,
                ),
                Some(policy) => {
                    policy.validate().map_err(|_| {
                        NegativeMemoryExposureError::InvalidField("admitted_rule.policy")
                    })?;
                    policy.validate_binding(record).map_err(|_| {
                        NegativeMemoryExposureError::InvalidField("admitted_rule.policy_binding")
                    })?;
                    (
                        NegativeMemoryRuleExposure::Governing {
                            admitted_disposition: policy.disposition,
                        },
                        NegativeMemoryPermittedNextAction::Admitted {
                            policy_id: policy.policy_id.clone(),
                            policy_revision: policy.policy_revision,
                            named_check_id: policy.named_check_id.clone(),
                        },
                    )
                }
            }
        }
        NegativeMemoryOutcome::Near { matched } => {
            if matched.record_id != record.record_id
                || matched.rule_revision != record.rule_revision
            {
                return Err(inconsistent("admitted_rule.record_identity"));
            }
            if matched.record_digest != record.record_digest {
                return Err(inconsistent("admitted_rule.record_digest"));
            }
            (
                NegativeMemoryRuleExposure::Advisory,
                NegativeMemoryPermittedNextAction::NoneAdmitted,
            )
        }
        NegativeMemoryOutcome::NoMatch { .. } | NegativeMemoryOutcome::Incomplete { .. } => {
            return Err(inconsistent("admitted_rule.outcome"));
        }
    };

    // The ORIGINAL recorded value is validated here, not a freshly computed
    // checksum over what the caller holds.
    record
        .validate()
        .map_err(|_| NegativeMemoryExposureError::InvalidField("admitted_rule.record"))?;

    let mut compared_dimensions = Vec::new();
    for comparison in predicate_comparisons_of(result) {
        compared_dimensions.push(NegativeMemoryComparedDimension {
            dimension_kind: NegativeMemoryDimensionKind::TriggerPredicate,
            field: comparison.dimension_name.clone(),
            relation: comparison.relation,
        });
    }
    for comparison in scope_comparisons_of(result) {
        compared_dimensions.push(NegativeMemoryComparedDimension {
            dimension_kind: NegativeMemoryDimensionKind::ScopeIdentity,
            field: comparison.field.clone(),
            relation: comparison.relation,
        });
    }

    let Some(horizon) = matched_horizon_of(result) else {
        return Err(inconsistent("admitted_rule.outcome"));
    };
    let rule = AdmittedNegativeMemoryRule {
        schema_version: NEGATIVE_MEMORY_EXPOSURE_SCHEMA_VERSION,
        record_id: record.record_id.clone(),
        rule_revision: record.rule_revision,
        record_digest: record.record_digest.clone(),
        semantic_owner: record.semantic_owner.clone(),
        invariant_id: record.invariant.invariant_id.clone(),
        invariant_revision: record.invariant.invariant_revision.clone(),
        exposure,
        compared_dimensions,
        validity: horizon_validity(horizon),
        invalidation: rule_invalidation(record),
        permitted_next_action,
    };
    rule.validate()?;
    Ok(rule)
}

/// The matcher's own trigger-predicate comparisons for the matched rule.
///
/// This is a read-only accessor over the already-produced comparison, not a new
/// comparison. [`ExactMatch`] and [`NearMatch`] are deliberately distinct types
/// in the matcher, so the only way to expose either one without re-deciding
/// anything is to read whichever payload the outcome carries.
fn predicate_comparisons_of(
    result: &NegativeMemoryMatchResult,
) -> &[eliot_dreamer_failure::PredicateComparison] {
    match &result.outcome {
        NegativeMemoryOutcome::Exact { matched } => &matched.predicate_comparisons,
        NegativeMemoryOutcome::Near { matched } => &matched.predicate_comparisons,
        NegativeMemoryOutcome::NoMatch { .. } | NegativeMemoryOutcome::Incomplete { .. } => &[],
    }
}

/// The matcher's own scope/action/resource/environment comparisons.
fn scope_comparisons_of(
    result: &NegativeMemoryMatchResult,
) -> &[eliot_dreamer_failure::ScopeComparison] {
    match &result.outcome {
        NegativeMemoryOutcome::Exact { matched } => &matched.scope_comparisons,
        NegativeMemoryOutcome::Near { matched } => &matched.scope_comparisons,
        NegativeMemoryOutcome::NoMatch { .. } | NegativeMemoryOutcome::Incomplete { .. } => &[],
    }
}

/// The matcher's own do-not-repeat horizon relation for the matched rule.
fn matched_horizon_of(
    result: &NegativeMemoryMatchResult,
) -> Option<&NegativeMemoryHorizonRelation> {
    match &result.outcome {
        NegativeMemoryOutcome::Exact { matched } => Some(&matched.horizon),
        NegativeMemoryOutcome::Near { matched } => Some(&matched.horizon),
        NegativeMemoryOutcome::NoMatch { .. } | NegativeMemoryOutcome::Incomplete { .. } => None,
    }
}

/// The matcher's own exact/near record identity, or `None` when nothing matched.
fn matched_identity_of(result: &NegativeMemoryMatchResult) -> Option<(&str, u64, &str)> {
    match &result.outcome {
        NegativeMemoryOutcome::Exact { matched } => Some((
            matched.record_id.as_str(),
            matched.rule_revision,
            matched.record_digest.as_str(),
        )),
        NegativeMemoryOutcome::Near { matched } => Some((
            matched.record_id.as_str(),
            matched.rule_revision,
            matched.record_digest.as_str(),
        )),
        NegativeMemoryOutcome::NoMatch { .. } | NegativeMemoryOutcome::Incomplete { .. } => None,
    }
}

/// The matcher's own retained evidence for whichever payload it produced.
fn outcome_evidence_of(result: &NegativeMemoryMatchResult) -> &MatchEvidence {
    match &result.outcome {
        NegativeMemoryOutcome::Exact { matched } => &matched.evidence,
        NegativeMemoryOutcome::Near { matched } => &matched.evidence,
        NegativeMemoryOutcome::NoMatch { observed } => &observed.evidence,
        NegativeMemoryOutcome::Incomplete { observed } => &observed.evidence,
    }
}

fn rule_invalidation(record: &NegativeMemoryFingerprint) -> NegativeMemoryRuleInvalidation {
    if !record.has_admitted_trigger() {
        return NegativeMemoryRuleInvalidation::AdvisoryOnly;
    }
    NegativeMemoryRuleInvalidation::ReopenUnobserved {
        required_verifier: record.reopen.required_verifier.clone(),
    }
}

fn horizon_validity(horizon: &NegativeMemoryHorizonRelation) -> NegativeMemoryRuleValidity {
    match horizon {
        NegativeMemoryHorizonRelation::WithinHorizon {
            remaining_sequence_gap,
        } => NegativeMemoryRuleValidity::InForce {
            remaining_sequence_gap: *remaining_sequence_gap,
        },
        NegativeMemoryHorizonRelation::HorizonReached { observed_sequence } => {
            NegativeMemoryRuleValidity::HorizonReached {
                observed_sequence: *observed_sequence,
            }
        }
        NegativeMemoryHorizonRelation::UnrelatedDomain {
            recorded_domain_id,
            observed_domain_id,
        } => NegativeMemoryRuleValidity::HorizonUnresolved {
            recorded_domain_id: recorded_domain_id.clone(),
            observed_domain_id: observed_domain_id.clone(),
        },
    }
}

fn applicability_of(result: &NegativeMemoryMatchResult) -> NegativeMemoryApplicability {
    match result.outcome.kind() {
        NegativeMemoryMatchKind::Exact => NegativeMemoryApplicability::Matched,
        NegativeMemoryMatchKind::Near => NegativeMemoryApplicability::NearAdvisory,
        NegativeMemoryMatchKind::NoMatch => NegativeMemoryApplicability::Absent,
        NegativeMemoryMatchKind::Incomplete => NegativeMemoryApplicability::Undetermined,
    }
}

/// Composes the negative-memory Context projection from the comparison the
/// enforcement side already produced, the records it compared, and the
/// policies the owner already admitted.
///
/// This is a pure projection. It runs no comparison, reads no store, admits no
/// rule, and returns no disposition.
///
/// `records` and `policies` are keyed by record identity and must be the
/// snapshot the comparison itself used. A matched rule whose record is absent,
/// or whose admitted policy is absent or not bound to that exact record
/// revision, is exposed as a named [`NegativeMemoryBackingMember`] loss and
/// forces [`NegativeMemoryApplicability::Undetermined`]. Its evidence is never
/// reconstructed from the match summary: the summary is exposed as a summary.
///
/// # Errors
///
/// Returns [`NegativeMemoryExposureError`] when a matched rule's record or
/// policy fails its own owner validation, when the composition over its own
/// bound fails, or when the composed projection fails [`Self::validate`].
pub fn project_negative_memory_rules(
    result: &NegativeMemoryMatchResult,
    records: &BTreeMap<String, NegativeMemoryFingerprint>,
    policies: &BTreeMap<String, NegativeMemoryActionPolicy>,
) -> Result<NegativeMemoryRuleProjection, NegativeMemoryExposureError> {
    let mut rules = Vec::new();
    let mut losses = Vec::new();
    if let Some((record_id, rule_revision, record_digest)) = matched_identity_of(result) {
        let Some(record) = records.get(record_id) else {
            losses.push(NegativeMemoryEvidenceLoss::BackingAuthorityUnavailable {
                record_id: record_id.to_owned(),
                rule_revision,
                missing: NegativeMemoryBackingMember::Record,
            });
            return finish(
                NegativeMemoryApplicability::Undetermined,
                rules,
                losses,
                result,
            );
        };
        let policy = policies.get(record_id).filter(|policy| {
            policy.binding.record_id == record_id
                && policy.binding.rule_revision == rule_revision
                && policy.binding.record_digest == record_digest
        });
        match policy {
            Some(policy) => rules.push(admitted_rule(record, Some(policy), result)?),
            None => {
                losses.push(NegativeMemoryEvidenceLoss::BackingAuthorityUnavailable {
                    record_id: record_id.to_owned(),
                    rule_revision,
                    missing: NegativeMemoryBackingMember::Policy,
                });
            }
        }
    } else if let NegativeMemoryOutcome::Incomplete { observed } = &result.outcome {
        for reason in &observed.reasons {
            losses.push(NegativeMemoryEvidenceLoss::ComparisonNotDecidable {
                reason: reason.clone(),
            });
        }
    }

    let applicability = if losses.is_empty() {
        applicability_of(result)
    } else {
        NegativeMemoryApplicability::Undetermined
    };
    finish(applicability, rules, losses, result)
}

fn finish(
    applicability: NegativeMemoryApplicability,
    rules: Vec<AdmittedNegativeMemoryRule>,
    losses: Vec<NegativeMemoryEvidenceLoss>,
    result: &NegativeMemoryMatchResult,
) -> Result<NegativeMemoryRuleProjection, NegativeMemoryExposureError> {
    if !matches!(
        result.enumeration,
        eliot_dreamer_failure::EnumerationCoverage::Complete { .. }
    ) && applicability.certifies_rule_absence()
    {
        return Err(NegativeMemoryExposureError::BindingInconsistent(
            "project_negative_memory_rules.enumeration",
        ));
    }
    let projection = NegativeMemoryRuleProjection {
        schema_version: NEGATIVE_MEMORY_EXPOSURE_SCHEMA_VERSION,
        applicability,
        rules,
        evidence: outcome_evidence_of(result).clone(),
        losses,
    };
    projection.validate()?;
    Ok(projection)
}

// ---------------------------------------------------------------------------
// #1726 W3 — construction of the twelve axes from compilation evidence
// ---------------------------------------------------------------------------

/// The twelve I12.13 dimensions in the canonical order a card carries them.
///
/// This is the independent denominator a constructed card is checked against:
/// the contract owner's own constant, not a list a caller supplies, so a card
/// can be complete by construction and a card that is missing, duplicated or
/// reordered is a structural failure rather than a narrower packet.
const QUALITY_AXIS_ORDER: [QualityDimension; 12] = QUALITY_DIMENSIONS;

/// The decision owner's lineage reference categories, per W3's evidence rule.
///
/// These are the lineage contract's own wire names, not a vocabulary invented
/// here. A required relation is the owner's `Present` member of that category; a
/// relation the owner recorded as `NotApplicable`, `NotYetProduced` or `Unknown`
/// is named as missing, never substituted by a role-labelled atom that happens
/// to look like it.
const OWNER_ACCEPTANCE_KINDS: [&str; 3] = ["acceptance", "criterion", "verification"];
const OWNER_RIVAL_KINDS: [&str; 2] = ["rival", "material_unknown"];
const OWNER_PROVENANCE_KINDS: [&str; 4] =
    ["evidence", "artifact_source", "observation", "artifact"];

/// Maximum length of one evidence handle.
///
/// Every handle is built from a record the compilation actually holds, so this
/// bounds the handle rather than the evidence. It is the one place a value can
/// become unusable, and it makes that a typed refusal instead of a handle that
/// silently names something else.
const MAX_AXIS_EVIDENCE: usize = 512;

/// Fail-closed errors from quality construction.
///
/// Every variant means a record this grade is read from does not satisfy the
/// owner contract it was read under, or that the delivered packet does not
/// account for the admitted set. None of them is a dimension state: a malformed
/// owner record is a refusal, never a pass and never a silent downgrade.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum QualityEvidenceError {
    /// A record the grade is read from failed its own owner validation.
    ///
    /// The admission owner, the measurement owner, the execution owner and the
    /// decision-lineage owner each have a validator, and each is called here. A
    /// record that fails it is not re-read under a local, weaker rule.
    #[error("quality axis evidence owner record is invalid: {0}")]
    Owner(&'static str),
    /// An owner-issued value could not be used as an evidence handle.
    #[error("quality axis evidence value is unusable: {0}")]
    Evidence(&'static str),
    /// The delivered packet does not account for the admitted set.
    ///
    /// The delivered identities are compared against the admitted identities in
    /// BOTH directions, so this fires for a rendered projection that DROPS an
    /// admitted member as well as one that INVENTS a member the admission owner
    /// never made, and for an omission set the owner did not authorise as well
    /// as an authorised omission the packet silently kept. Both are the same
    /// fact: what was delivered is not the admitted set.
    #[error("delivered packet does not account for the admitted set: {0}")]
    Unaccounted(&'static str),
}

/// The complete evidence one compiled packet's twelve grades are read from.
///
/// Every field is an existing owner record, read unchanged. This struct adds no
/// measurement, no score and no verdict: it is the set of facts the grade is
/// computed from, so a caller cannot grade a card against a rule, a profile or a
/// list of handles it supplied itself. Nothing here is derived from the card's
/// own `results`.
#[derive(Clone, Debug)]
pub struct QualityCompilationEvidence<'a> {
    /// The admitted set this packet was compiled from.
    pub admitted: &'a AdmittedContextSet,
    /// The ordered rendered projection of that admitted set.
    pub rendered: &'a [RenderedAtom],
    /// The measurement the assembly owner recorded for these exact bytes.
    pub measurement: &'a SerializedContextMeasurement,
    /// The execution identity the assembly owner states it applied.
    pub execution: &'a ContextExecutionIdentity,
    /// The admitted/rendered identities the assembly owner delivered.
    pub delivered: &'a [ArtifactId],
    /// The decision owner's own exact lineage contract for this decision.
    pub lineage: &'a DecisionExecutionLineageRefs,
    /// The negative-memory exposure read for this dispatch, when one was read.
    pub negative_memory: Option<&'a NegativeMemoryRuleProjection>,
}

/// Builds all twelve dimension results for one compiled packet from its own
/// compilation evidence and writes them onto `scorecard`.
///
/// The axes are produced in [`QUALITY_AXIS_ORDER`] — the contract owner's
/// canonical order, which is also the independent denominator — so the resulting
/// card always carries exactly one result per dimension. Completeness is
/// re-checked against that denominator before anything is written, and the
/// caller's previous `results` are not consulted: a card that arrived fully
/// populated is replaced, and none of its twelve results is an input here.
///
/// # Errors
///
/// [`QualityEvidenceError::Owner`] when the admitted set, the rendered
/// projection, the measurement, the execution identity, the negative-memory
/// exposure or the lineage contract fails its own owner validation.
/// [`QualityEvidenceError::Unaccounted`] when the delivery, the omission set or
/// the binding does not reconcile with the admitted set in both directions.
/// [`QualityEvidenceError::Evidence`] when an owner-issued value cannot be used
/// as an evidence handle.
pub fn quality_axis_results(
    evidence: &QualityCompilationEvidence<'_>,
    scorecard: &mut QualityScorecard,
) -> Result<(), QualityEvidenceError> {
    let builder = AxisBuilder::read(evidence, scorecard)?;
    let results = builder.all_axes()?;
    // The independent completeness check: built length and per-axis identity
    // against the declared denominator, never against a count of the card's own
    // previous entries.
    if results.len() != QUALITY_AXIS_ORDER.len() {
        return Err(QualityEvidenceError::Unaccounted("results"));
    }
    for (built, dimension) in results.iter().zip(QUALITY_AXIS_ORDER) {
        if built.dimension != dimension {
            return Err(QualityEvidenceError::Unaccounted("results"));
        }
    }
    scorecard.results = results;
    Ok(())
}

/// One member an axis requires, and whether a delivered member preserved it.
struct Requirement {
    /// The evidence handle naming this requirement.
    handle: ArtifactId,
    /// The exact owner-issued text a delivered member must preserve. `None` is
    /// a requirement with no text to match — a measured cost, a capacity, a
    /// State Fence — and is observed by its own record comparison instead.
    text: Option<String>,
    /// Whether a delivered member's own record preserved it.
    observed: bool,
}

/// Everything one call to [`quality_axis_results`] reads, validated once.
struct AxisBuilder<'a> {
    admitted: &'a AdmittedContextSet,
    measurement: &'a SerializedContextMeasurement,
    lineage: &'a DecisionExecutionLineageRefs,
    negative_memory: Option<&'a NegativeMemoryRuleProjection>,
    binding: ContextBinding,
    route_id: String,
    /// The verdict the decision-lineage owner recorded for this phase, read
    /// through the lineage contract's own `validate_for_phase`. A lineage that
    /// is not `Complete` cannot support a lineage-dependent pass.
    lineage_complete: bool,
    /// Every delivered member paired with the admission record it was
    /// delivered for. The expected set is `admitted.records`; this list is the
    /// delivered one, and the two are reconciled in both directions in
    /// [`AxisBuilder::read`].
    delivered: Vec<(&'a RenderedAtom, &'a AdmittedAtom)>,
}

impl<'a> AxisBuilder<'a> {
    /// Reads and validates every owner record the twelve axes are built from.
    ///
    /// Each owner's own validator is called here and is never weakened by a
    /// local shape test, and the delivered packet is reconciled against the
    /// admitted set in both directions BEFORE any axis is graded — so no axis
    /// can be built over a membership that already failed its own conservation.
    fn read(
        evidence: &QualityCompilationEvidence<'a>,
        scorecard: &QualityScorecard,
    ) -> Result<Self, QualityEvidenceError> {
        let admitted = evidence.admitted;
        admitted
            .validate()
            .map_err(|_| QualityEvidenceError::Owner("admitted"))?;
        // The card is bound to this compilation, and so is every record read
        // here. A card graded against another packet's binding is refused
        // before it is used as a denominator for anything.
        if admitted.binding != scorecard.binding {
            return Err(QualityEvidenceError::Unaccounted("binding"));
        }
        if evidence.lineage.context != admitted.binding
            || evidence.measurement.context != admitted.binding
        {
            return Err(QualityEvidenceError::Unaccounted("binding"));
        }
        evidence
            .measurement
            .validate()
            .map_err(|_| QualityEvidenceError::Owner("measurement"))?;
        evidence
            .execution
            .validate()
            .map_err(|_| QualityEvidenceError::Owner("execution"))?;
        // The execution identity the assembly owner states, compared against
        // the measurement owner's independent record of the same bytes.
        evidence
            .execution
            .binds_measurement(evidence.measurement)
            .map_err(|_| QualityEvidenceError::Owner("execution.measurement"))?;
        for atom in evidence.rendered {
            atom.representation
                .validate()
                .map_err(|_| QualityEvidenceError::Owner("rendered.representation"))?;
            atom.measurement
                .validate()
                .map_err(|_| QualityEvidenceError::Owner("rendered.measurement"))?;
        }
        if let Some(projection) = evidence.negative_memory {
            projection
                .validate()
                .map_err(|_| QualityEvidenceError::Owner("negative_memory"))?;
        }

        // The delivered packet IS the admitted set, in both directions. The
        // expected set is the admission owner's own record list; the delivered
        // set is what the assembly handed on. Comparing them in one direction
        // only would be a count that can go down, which is not accounting.
        let mut delivered: Vec<(&'a RenderedAtom, &'a AdmittedAtom)> =
            Vec::with_capacity(evidence.rendered.len());
        for atom in evidence.rendered {
            let Some(record) = admitted
                .records
                .iter()
                .find(|record| record.candidate.atom_id == atom.atom_id)
            else {
                return Err(QualityEvidenceError::Unaccounted("rendered.admitted"));
            };
            // Each delivered field is compared against the exact admitted
            // record, so the CONTENT of the delivered member is checked and not
            // only its identity.
            if atom.role != record.candidate.provider_role.role
                || atom.source_id != record.candidate.source.snapshot_id
                || atom.source_identity != record.candidate.source.source_id
                || atom.source_owner != record.candidate.source.owner
                || atom.source_revision != record.candidate.source.revision
                || atom.source_digest != record.candidate.source.content_sha256
                || atom.source_predecessor != record.candidate.source.predecessor
                || atom.representation != record.candidate.representation
                || atom.availability != record.candidate.availability
                || atom.authority != record.candidate.authority
                || atom.loss_policy != record.candidate.loss_policy
                || atom.status != record.candidate.status
                || atom.assertability != record.candidate.assertability
                || atom.measurement != record.candidate.measurement
                || atom.dependencies != record.candidate.dependencies
                || atom.proof != record.candidate.proof
            {
                return Err(QualityEvidenceError::Unaccounted("rendered.content"));
            }
            delivered.push((atom, record));
        }
        if delivered.len() != admitted.records.len() {
            return Err(QualityEvidenceError::Unaccounted("rendered.membership"));
        }
        let delivered_ids: BTreeSet<ArtifactId> = delivered
            .iter()
            .map(|(atom, _)| atom.atom_id.clone())
            .collect();
        if delivered_ids.len() != delivered.len() {
            return Err(QualityEvidenceError::Unaccounted("rendered.membership"));
        }
        // The assembly owner's own delivery record, reconciled the same way.
        let owner_delivered: BTreeSet<ArtifactId> = evidence.delivered.iter().cloned().collect();
        if owner_delivered.len() != evidence.delivered.len() || owner_delivered != delivered_ids {
            return Err(QualityEvidenceError::Unaccounted("delivered.membership"));
        }

        // Omission and expansion accounting, in both directions, before any
        // axis is graded. The expected set is the economy receipt's own
        // authorised-omission set; the omission records are the compilation's own
        // account of each one.
        let displaced: BTreeSet<ArtifactId> = admitted.economy.displaced.iter().cloned().collect();
        let omissions: BTreeSet<ArtifactId> = admitted
            .economy
            .omissions
            .iter()
            .map(|record| record.atom_id.clone())
            .collect();
        if displaced.len() != admitted.economy.displaced.len()
            || omissions.len() != admitted.economy.omissions.len()
            || displaced != omissions
            || !displaced.is_disjoint(&delivered_ids)
        {
            return Err(QualityEvidenceError::Unaccounted("economy.omissions"));
        }

        let lineage_complete = evidence
            .lineage
            .validate_for_phase(DecisionLineagePhase::BeforeEffect)
            .map_err(|_| QualityEvidenceError::Owner("lineage"))?
            == DecisionLineageCompleteness::Complete;

        Ok(Self {
            admitted,
            measurement: evidence.measurement,
            lineage: evidence.lineage,
            negative_memory: evidence.negative_memory,
            binding: admitted.binding.clone(),
            route_id: scorecard.output.route_id.clone(),
            lineage_complete,
            delivered,
        })
    }

    /// Every axis, in the contract owner's canonical order.
    ///
    /// One unreadable owner value refuses the whole construction rather than
    /// being absorbed into a weaker axis: a silently unnamed requirement is
    /// indistinguishable from a requirement that was never made, which is the
    /// shortcut W3 forbids.
    fn all_axes(&self) -> Result<Vec<QualityDimensionResult>, QualityEvidenceError> {
        QUALITY_AXIS_ORDER
            .iter()
            .map(|dimension| self.axis(*dimension))
            .collect()
    }

    fn axis(
        &self,
        dimension: QualityDimension,
    ) -> Result<QualityDimensionResult, QualityEvidenceError> {
        let result = match dimension {
            QualityDimension::AcceptanceDecisionCoverage => self.acceptance_axis()?,
            QualityDimension::CausalOperationalSufficiency => self.causal_axis()?,
            QualityDimension::ExactAnchorProvenanceCoverage => self.anchor_axis()?,
            QualityDimension::FreshnessStateFenceCoherence => self.freshness_axis()?,
            QualityDimension::RivalsConflictsUnknownsVisibility => self.rivals_axis()?,
            QualityDimension::NegativeMemoryInvariantCoverage => self.negative_memory_axis()?,
            QualityDimension::VerifierActionReadiness => self.verifier_axis()?,
            QualityDimension::RouteAccessibilityLayoutRisk => self.route_axis()?,
            QualityDimension::InstructionSufficiency => self.instruction_axis()?,
            QualityDimension::PayloadHandleReconstructionCost => self.reconstruction_axis()?,
            QualityDimension::KnownOmissionsExpansionPaths => self.omission_axis()?,
            QualityDimension::TelemetryMeasurementCostCoverage => self.telemetry_axis()?,
        };
        // The result is built for `dimension`; the identity is asserted here so
        // the two can never disagree.
        debug_assert_eq!(result.dimension, dimension);
        Ok(result)
    }

    // -----------------------------------------------------------------------
    // Evidence primitives
    // -----------------------------------------------------------------------

    /// One evidence handle naming an exact owner-issued fact.
    fn handle(
        &self,
        domain: &str,
        dimension: QualityDimension,
        value: &str,
    ) -> Result<ArtifactId, QualityEvidenceError> {
        if value.trim().is_empty() || value.chars().any(char::is_control) {
            return Err(QualityEvidenceError::Evidence(domain));
        }
        if value.len() > MAX_AXIS_EVIDENCE {
            return Err(QualityEvidenceError::Evidence(domain));
        }
        ArtifactId::new(std::format!("quality:{domain}:{value}"))
            .map_err(|_| QualityEvidenceError::Evidence(domain))
    }

    /// A requirement whose observation is a delivered member's own text.
    fn text_requirement(
        &self,
        domain: &str,
        dimension: QualityDimension,
        token: &str,
        text: &str,
    ) -> Result<Requirement, QualityEvidenceError> {
        let handle = self.handle(domain, dimension, token)?;
        let observed = self
            .delivered
            .iter()
            .map(|(atom, _)| *atom)
            .any(|atom| Self::preserved_text(atom).is_some_and(|held| held.contains(text)));
        Ok(Requirement {
            handle,
            text: Some(text.to_owned()),
            observed,
        })
    }

    /// A requirement whose observation is the record comparison beside it.
    fn record_requirement(
        &self,
        domain: &str,
        dimension: QualityDimension,
        token: &str,
        observed: bool,
    ) -> Result<Requirement, QualityEvidenceError> {
        Ok(Requirement {
            handle: self.handle(domain, dimension, token)?,
            text: None,
            observed,
        })
    }

    /// The packet's own State Fence digest, recomputed by the context contract
    /// owner from the binding and compared by value wherever a fence is graded.
    fn fence_digest(&self) -> Result<String, QualityEvidenceError> {
        canonical_fence_digest(&self.binding.state_fence)
            .map_err(|_| QualityEvidenceError::Owner("state_fence"))
    }

    /// The rule revision every state-bound axis is graded under.
    ///
    /// It is the packet's own State Fence, so a grade cannot claim a profile
    /// revision this packet was not compiled under, and it is the one revision
    /// every delivered member and the decision owner both answer to.
    fn fence_rule_revision(
        &self,
        dimension: QualityDimension,
    ) -> Result<ArtifactId, QualityEvidenceError> {
        self.handle("rule-revision", dimension, &self.fence_digest()?)
    }

    /// The readable text one delivered member preserves, or `None`.
    ///
    /// A `HANDLE` representation preserves an identity, not text, so a
    /// handle-only member cannot cover a reference dimension; it is reported by
    /// the reconstruction-cost axis instead of being read as coverage.
    fn preserved_text(atom: &RenderedAtom) -> Option<&str> {
        match &atom.representation {
            AtomRepresentation::Whole { content }
            | AtomRepresentation::Extractive { content, .. }
            | AtomRepresentation::Summary { content, .. } => Some(content.as_str()),
            AtomRepresentation::Handle { .. } => None,
        }
    }

    /// Whether one delivered member's own measurement was observed in the
    /// delivered set, compared by VALUE.
    fn measured(&self, atom: &RenderedAtom) -> bool {
        self.delivered
            .iter()
            .any(|(observed, _)| measurement_matches(&observed.measurement, &atom.measurement))
    }

    /// The members an axis requires from the decision owner's own lineage slots.
    fn owner_requirements(
        &self,
        dimension: QualityDimension,
        domain: &str,
        scalars: &[(&DecisionLineageSlot<DecisionLineageRef>, &str)],
        vectors: &[(&DecisionLineageSlot<Vec<DecisionLineageRef>>, &[&str])],
    ) -> Result<Vec<Requirement>, QualityEvidenceError> {
        let mut requirements = Vec::new();
        for (slot, wire_kind) in scalars {
            match slot {
                DecisionLineageSlot::Present { value } => {
                    let token = std::format!("present:{wire_kind}:{}", value.reference.id.as_str());
                    let text = value.reference.id.as_str().to_owned();
                    requirements.push(self.text_requirement(domain, dimension, &token, &text)?);
                }
                DecisionLineageSlot::NotApplicable { .. }
                | DecisionLineageSlot::NotYetProduced { .. }
                | DecisionLineageSlot::Unknown { .. } => {
                    // The owner did not present this relation. It is a named
                    // missing member, never a default and never substituted.
                    requirements.push(self.record_requirement(
                        domain,
                        dimension,
                        &std::format!("not-present:{wire_kind}"),
                        false,
                    )?);
                }
            }
        }
        for (slot, kinds) in vectors {
            match slot {
                DecisionLineageSlot::Present { value } => {
                    if value.is_empty() {
                        requirements.push(self.record_requirement(
                            domain,
                            dimension,
                            "present-empty:an owner-presented slot carried no member",
                            false,
                        )?);
                    }
                    for reference in value {
                        // The category filter is the lineage contract's own wire
                        // name, compared on the value, so a member of a
                        // different category is not counted as this one.
                        if !kinds.contains(&reference.kind.as_str()) {
                            continue;
                        }
                        let token = std::format!(
                            "present:{}:{}@{}",
                            reference.kind,
                            reference.id.as_str(),
                            reference.revision.as_str()
                        );
                        let text = reference.id.as_str().to_owned();
                        requirements.push(self.text_requirement(domain, dimension, &token, &text)?);
                    }
                }
                DecisionLineageSlot::NotApplicable { .. }
                | DecisionLineageSlot::NotYetProduced { .. }
                | DecisionLineageSlot::Unknown { .. } => {
                    requirements.push(self.record_requirement(
                        domain,
                        dimension,
                        "not-present:an owner relation in this category",
                        false,
                    )?);
                }
            }
        }
        Ok(requirements)
    }

    /// Places a finished axis on the card.
    ///
    /// The state is derived from the two lists and never chosen: a pass is
    /// exactly the empty missing set, a non-empty missing set with no
    /// observation at all is `Unknown`, and a partially covered dimension is
    /// `Failed`. `Degraded` and `NotApplicable` are never reached from a list —
    /// they are reached only where an owner record states the limitation, which
    /// is the negative-memory axis. Nothing is dropped: every requirement that
    /// was not observed is named, whether it was recorded as unobserved beside
    /// it or simply absent from the evidence list.
    #[allow(clippy::too_many_arguments)]
    fn place(
        &self,
        dimension: QualityDimension,
        mut required: Vec<Requirement>,
        mut observed: Vec<ArtifactId>,
        mut measurements: Vec<MeasurementRef>,
        rule_revision: ArtifactId,
    ) -> QualityDimensionResult {
        let missing: Vec<ArtifactId> = required
            .iter()
            .filter(|requirement| !requirement.observed)
            .map(|requirement| requirement.handle.clone())
            .collect();
        let required: Vec<ArtifactId> = required
            .iter()
            .map(|requirement| requirement.handle.clone())
            .collect();
        observed.sort();
        observed.dedup();
        // `MeasurementRef` is a digest plus a serializer identity and derives
        // neither `Ord` nor `Hash`, so it cannot be `sort`ed or `dedup`ed; the
        // retained list is compared by value instead, which is also what makes
        // a handle matching on one field a non-member.
        let mut distinct_measurements: Vec<MeasurementRef> = Vec::with_capacity(measurements.len());
        for measurement in measurements {
            if !distinct_measurements
                .iter()
                .any(|seen| measurement_matches(seen, &measurement))
            {
                distinct_measurements.push(measurement);
            }
        }
        let measurements = distinct_measurements;
        let state = if missing.is_empty() {
            QualityDimensionState::Passed
        } else if observed.is_empty() {
            QualityDimensionState::Unknown
        } else {
            QualityDimensionState::Failed
        };
        QualityDimensionResult {
            schema_version: QUALITY_RESULT_SCHEMA_VERSION,
            dimension,
            state,
            rule_revision,
            required_evidence: required,
            evidence: observed,
            measurements,
            failed_invariant: None,
            unknown_evidence: missing,
            proof_ceiling: ProofCeiling::ScopedVerification,
            invalidation: None,
            binding: self.binding.clone(),
        }
    }

    // -----------------------------------------------------------------------
    // The twelve axes
    // -----------------------------------------------------------------------
    //
    // Every axis below follows the same shape: derive the required member set
    // from an owner record (never from a caller-supplied list), observe each
    // required member from a delivered member's own content or an owner
    // comparison, and hand both to `place`, which derives the state. The
    // `rule_revision` is the packet's own State Fence digest wherever the axis
    // is state-bound, and the owner's own rule identity elsewhere.

    /// Admission and decision coverage.
    ///
    /// The required set is the task/requirement owner's own acceptance
    /// relations, read from the lineage contract's `Present` members. The
    /// observation is a delivered member whose own bytes preserve that exact
    /// reference. A delivered `ACCEPTANCE`-role member that preserves none of
    /// them is named, so one representative atom per role cannot stand in for
    /// the required member set.
    fn acceptance_axis(&self) -> Result<QualityDimensionResult, QualityEvidenceError> {
        let dimension = QualityDimension::AcceptanceDecisionCoverage;
        let required = self.owner_requirements(
            dimension,
            "acceptance",
            &[],
            &[(&self.lineage.acceptance, &OWNER_ACCEPTANCE_KINDS)],
        )?;
        self.role_axis(dimension, required, SemanticRole::Acceptance)
    }

    /// Causal and operational sufficiency.
    ///
    /// The required set is the task/model owner's goal, rationale, why-now and
    /// epistemic-position relations, plus the floor owner's exact interpretation
    /// dependencies. A dependency the floor names and no delivered member
    /// carries is named, whatever else the packet contains: the relation is the
    /// floor owner's, not a role label on a surviving atom.
    fn causal_axis(&self) -> Result<QualityDimensionResult, QualityEvidenceError> {
        let dimension = QualityDimension::CausalOperationalSufficiency;
        let mut required = self.owner_requirements(
            dimension,
            "causal",
            &[(&self.lineage.goal, "goal")],
            &[
                (&self.lineage.rationale, &["rationale"][..]),
                (&self.lineage.why_now, &["why_now"][..]),
                (
                    &self.lineage.epistemic_position,
                    &["epistemic_position"][..],
                ),
            ],
        )?;
        for dependency in &self.admitted.floor.interpretation_dependencies {
            required.push(self.text_requirement(
                "causal-dependency",
                dimension,
                &std::format!("floor-interpretation:{}", dependency.as_str()),
                dependency.as_str(),
            )?);
        }
        self.role_axis(dimension, required, SemanticRole::Goal)
    }

    /// Exact-anchor and provenance coverage.
    ///
    /// The required set is every delivered member's exact source identity as the
    /// ADMISSION owner recorded it, plus the decision owner's own evidence,
    /// artifact-source and observation references. The observation is a handle
    /// over that exact triple, content-matched BY VALUE to the delivered
    /// member's own recorded lineage, plus a delivered member preserving the
    /// owner's reference. A member whose source revision could not be matched
    /// to the admission owner's record is named, never assumed current.
    fn anchor_axis(&self) -> Result<QualityDimensionResult, QualityEvidenceError> {
        let dimension = QualityDimension::ExactAnchorProvenanceCoverage;
        let mut required = Vec::new();
        let mut observed = Vec::new();
        let mut measurements = Vec::new();
        for (atom, record) in &self.delivered {
            let source = &record.candidate.source;
            // The handle names the source the ADMISSION owner recorded and the
            // comparison is by value against the DELIVERED member's own
            // lineage, so a member that changed its claimed source cannot
            // produce this handle.
            let matched = atom.source_id == source.snapshot_id
                && atom.source_revision == source.revision
                && atom.source_digest == source.content_sha256
                && atom.source_owner == source.owner;
            let requirement = self.record_requirement(
                "anchor",
                dimension,
                &std::format!(
                    "source:{}@{}:{}:{}",
                    source.snapshot_id.as_str(),
                    source.revision,
                    source.content_sha256,
                    source.owner.as_str()
                ),
                matched,
            )?;
            if matched {
                observed.push(requirement.handle.clone());
                measurements.push(atom.measurement.clone());
            }
            required.push(requirement);
            // The exact range the provider measured, when it measured one. An
            // absent range stays absent: it is never defaulted into a range that
            // reads as exact, and it never becomes a required member the
            // provider did not claim.
            if let Some(range) = &record.candidate.source_range {
                let range_requirement = self.record_requirement(
                    "anchor-range",
                    dimension,
                    &std::format!(
                        "range:{}@{}:{}..{}:len:{}",
                        range.snapshot_id.as_str(),
                        range.source_revision,
                        range.start,
                        range.end_exclusive,
                        range.length
                    ),
                    range.snapshot_id == atom.source_id
                        && range.source_revision == atom.source_revision,
                )?;
                if range_requirement.observed {
                    observed.push(range_requirement.handle.clone());
                }
                required.push(range_requirement);
            }
        }
        let owner = self.owner_requirements(
            dimension,
            "provenance",
            &[],
            &[
                (&self.lineage.evidence, &OWNER_PROVENANCE_KINDS),
                (&self.lineage.observations, &OWNER_PROVENANCE_KINDS),
            ],
        )?;
        let (owner_observed, owner_measurements) = self.observe(&owner);
        observed.extend(owner_observed);
        measurements.extend(owner_measurements);
        required.extend(owner);
        Ok(self.place(
            dimension,
            required,
            observed,
            measurements,
            self.fence_rule_revision(dimension)?,
        ))
    }

    /// Freshness and State Fence coherence.
    ///
    /// The required set is every delivered member. The observation is the
    /// member's own recorded availability and epistemic status, content-matched
    /// to the admission owner's record for the same member, plus the decision
    /// owner's State Fence compared BY VALUE against the digest the context
    /// contract owner recomputes from this packet's binding. A lineage bound to
    /// another fence cannot observe this packet's coherence, and the lineage
    /// owner's own phase verdict is consumed rather than restated.
    fn freshness_axis(&self) -> Result<QualityDimensionResult, QualityEvidenceError> {
        let dimension = QualityDimension::FreshnessStateFenceCoherence;
        let mut required = Vec::new();
        let mut observed = Vec::new();
        let mut measurements = Vec::new();
        for (atom, record) in &self.delivered {
            let current = atom.availability == record.candidate.availability
                && atom.status == record.candidate.status
                && atom.availability == AtomAvailability::PresentCurrent
                && !matches!(
                    atom.status,
                    EpistemicStatus::Stale
                        | EpistemicStatus::Superseded
                        | EpistemicStatus::Rejected
                        | EpistemicStatus::Unknown
                );
            let requirement = self.record_requirement(
                "freshness",
                dimension,
                &std::format!(
                    "member:{}:availability:{:?}:status:{:?}:assertability:{:?}",
                    atom.atom_id.as_str(),
                    atom.availability,
                    atom.status,
                    atom.assertability
                ),
                current,
            )?;
            if current {
                observed.push(requirement.handle.clone());
                measurements.push(atom.measurement.clone());
            }
            required.push(requirement);
        }
        // The State Fence half, compared by value on both sides.
        let packet_fence = self.fence_digest()?;
        let owner_fence = canonical_fence_digest(&self.lineage.epoch.state_fence)
            .map_err(|_| QualityEvidenceError::Owner("lineage.epoch"))?;
        let fence_requirement = self.record_requirement(
            "state-fence",
            dimension,
            &owner_fence,
            owner_fence == packet_fence
                && self.lineage.epoch.state_fence == self.binding.state_fence,
        )?;
        if fence_requirement.observed {
            observed.push(fence_requirement.handle.clone());
        }
        required.push(fence_requirement);
        let completeness = self.record_requirement(
            "lineage-completeness",
            dimension,
            "the decision owner's own lineage is not complete for this phase",
            self.lineage_complete,
        )?;
        if completeness.observed {
            observed.push(completeness.handle.clone());
        }
        required.push(completeness);
        Ok(self.place(
            dimension,
            required,
            observed,
            measurements,
            self.fence_rule_revision(dimension)?,
        ))
    }

    /// Visibility of rivals, conflicts and unknowns.
    ///
    /// The required set is the decision owner's own material-unknown and
    /// unresolved-conflict relations, and every rival's own rejection reason. A
    /// packet carrying rivals the owner did not require, and none of the
    /// members it did require, fails on the exact members named.
    fn rivals_axis(&self) -> Result<QualityDimensionResult, QualityEvidenceError> {
        let dimension = QualityDimension::RivalsConflictsUnknownsVisibility;
        let mut required = self.owner_requirements(
            dimension,
            "rival",
            &[],
            &[(&self.lineage.material_unknowns, &OWNER_RIVAL_KINDS)],
        )?;
        match &self.lineage.rivals {
            DecisionLineageSlot::Present { value: rivals } => {
                for rival in rivals {
                    for (label, reference) in [
                        ("rival", &rival.rival.reference),
                        ("rejection-reason", &rival.rejection_reason.reference),
                    ] {
                        required.push(self.text_requirement(
                            "rival-member",
                            dimension,
                            &std::format!(
                                "{label}:{}@{}",
                                reference.id.as_str(),
                                reference.revision.as_str()
                            ),
                            reference.id.as_str(),
                        )?);
                    }
                }
            }
            DecisionLineageSlot::NotApplicable { .. }
            | DecisionLineageSlot::NotYetProduced { .. }
            | DecisionLineageSlot::Unknown { .. } => {
                required.push(self.record_requirement(
                    "rival-member",
                    dimension,
                    "not-present:the decision owner presented no rival set",
                    false,
                )?);
            }
        }
        self.role_axis(dimension, required, SemanticRole::MaterialUnknown)
    }

    /// Negative-memory and invariant coverage.
    ///
    /// Graded only from this module's own admitted-rule exposure. The required
    /// set is every rule the exposure carries, by record identity, rule revision
    /// AND content digest, and the observed set is the subset that carries
    /// governing authority: a rule that is merely advisory is a named missing
    /// member, not coverage. A named loss or a retained limitation means the
    /// compared rule set was not completely established, so the axis is
    /// `Degraded` with the reason that admits it. No read at all is `Unknown`
    /// with the missing handle named.
    fn negative_memory_axis(&self) -> Result<QualityDimensionResult, QualityEvidenceError> {
        let dimension = QualityDimension::NegativeMemoryInvariantCoverage;
        let Some(projection) = self.negative_memory else {
            let missing = self.record_requirement(
                "negative-memory",
                dimension,
                "no-negative-memory-read-was-taken-for-this-dispatch",
                false,
            )?;
            let handle = missing.handle.clone();
            return Ok(self.place(dimension, vec![missing], Vec::new(), Vec::new(), handle));
        };
        let mut required = Vec::new();
        let mut observed = Vec::new();
        for rule in &projection.rules {
            let governing = matches!(rule.exposure, NegativeMemoryRuleExposure::Governing { .. });
            let requirement = self.record_requirement(
                "negative-memory-rule",
                dimension,
                &std::format!(
                    "record:{}:revision:{}:digest:{}",
                    rule.record_id,
                    rule.rule_revision,
                    rule.record_digest
                ),
                governing,
            )?;
            if governing {
                observed.push(requirement.handle.clone());
            }
            required.push(requirement);
        }
        // The matcher's own retained limitations decide degradation, because
        // only the matcher knows the compared rule set was not established
        // completely.
        let rule_revision = self.handle(
            "negative-memory-rule-set",
            dimension,
            &std::format!(
                "read:{}:revision:{}:candidates:{}:fields:{}",
                projection.evidence.read_handle,
                projection.evidence.rule_set_revision,
                projection.evidence.assessed_record_count,
                projection.evidence.compared_predicate_dimension_count
                    + projection.evidence.compared_scope_field_count
            ),
        )?;
        let mut result = self.place(dimension, required, observed, Vec::new(), rule_revision);
        if !projection.losses.is_empty() || !projection.evidence.limitation_refs.is_empty() {
            result.state = QualityDimensionState::Degraded {
                reason: std::format!(
                    "negative-memory exposure over read {} carries {} named loss(es) and {} retained limitation(s); the unit is represented but its coverage is not established",
                    projection.evidence.read_handle,
                    projection.losses.len(),
                    projection.evidence.limitation_refs.len()
                ),
            };
        }
        Ok(result)
    }

    /// Verifier and action readiness.
    ///
    /// The required set is the decision owner's own verifier CONTRACT and action
    /// contract slots, plus the verifier each effect's expected observable
    /// requires. A `SemanticRole::Verifier` atom that preserves none of those
    /// references, a zero-cost flag and a past unrelated test pass are all
    /// reported as missing, never as readiness.
    fn verifier_axis(&self) -> Result<QualityDimensionResult, QualityEvidenceError> {
        let dimension = QualityDimension::VerifierActionReadiness;
        let mut required = Vec::new();
        match &self.lineage.verifiers {
            DecisionLineageSlot::Present { value: verifiers } => {
                if verifiers.is_empty() {
                    required.push(self.record_requirement(
                        "verifier",
                        dimension,
                        "present-empty:the decision owner issued an empty verifier set",
                        false,
                    )?);
                }
                for verifier in verifiers {
                    let reference = verifier.source.reference.id.as_str();
                    required.push(self.text_requirement(
                        "verifier",
                        dimension,
                        &std::format!(
                            "contract:{reference}@{}:ceiling:{:?}:artifacts:{}",
                            verifier.source.reference.revision.as_str(),
                            verifier.binding.proof_ceiling,
                            verifier.binding.artifact_ids.len()
                        ),
                        reference,
                    )?);
                }
            }
            DecisionLineageSlot::NotApplicable { .. }
            | DecisionLineageSlot::NotYetProduced { .. }
            | DecisionLineageSlot::Unknown { .. } => {
                required.push(self.record_requirement(
                    "verifier",
                    dimension,
                    "not-present:the decision owner issued no verifier set for this action",
                    false,
                )?);
            }
        }
        match &self.lineage.action_contract {
            DecisionLineageSlot::Present { value: contract } => {
                let reference = contract.reference.reference.id.as_str();
                required.push(self.text_requirement(
                    "action-contract",
                    dimension,
                    &std::format!(
                        "action:{reference}@{}",
                        contract.reference.reference.revision.as_str()
                    ),
                    reference,
                )?);
            }
            DecisionLineageSlot::NotApplicable { .. }
            | DecisionLineageSlot::NotYetProduced { .. }
            | DecisionLineageSlot::Unknown { .. } => {
                required.push(self.record_requirement(
                    "action-contract",
                    dimension,
                    "not-present:the decision owner issued no action contract",
                    false,
                )?);
            }
        }
        for effect in &self.lineage.effects {
            if let DecisionLineageSlot::Present { value: expected } = &effect.expected_observable {
                let reference = expected.verifier.reference.id.as_str();
                required.push(self.text_requirement(
                    "effect-verifier",
                    dimension,
                    &std::format!("required-by:{reference}"),
                    reference,
                )?);
            }
        }
        self.role_axis(dimension, required, SemanticRole::Verifier)
    }

    /// Route accessibility, layout and risk.
    ///
    /// The required set is the route capacity this packet was compiled for, as
    /// the floor owner recorded it. The observation is the measurement owner's
    /// own fit verdict for these bytes at that capacity, and a floor member
    /// that did not arrive whole is a layout risk named on its own identity. An
    /// unmeasurable cost is an explicit unknown, never a measured zero.
    fn route_axis(&self) -> Result<QualityDimensionResult, QualityEvidenceError> {
        let dimension = QualityDimension::RouteAccessibilityLayoutRisk;
        let capacity = self.admitted.floor.capacity.route_capacity;
        let mut required = Vec::new();
        let mut observed = Vec::new();
        let mut measurements = Vec::new();
        // The floor owner's capacity and the economy receipt's own allocation of
        // it are independent records of the same route, compared by value.
        let capacity_requirement = self.record_requirement(
            "route-capacity",
            dimension,
            &std::format!("route:{}:capacity:{capacity}", self.route_id),
            self.admitted.floor.capacity.route_capacity
                == self.admitted.economy.allocations.route_capacity,
        )?;
        if capacity_requirement.observed {
            observed.push(capacity_requirement.handle.clone());
        }
        required.push(capacity_requirement);
        // The measurement owner's own verdict on these bytes. `proves_fit`
        // returns `Err` for a cost that was never measured, and an unmeasured
        // cost is not a fit.
        let fit_requirement = self.record_requirement(
            "route-fit",
            dimension,
            &std::format!("route:{}:cost:{capacity}", self.route_id),
            matches!(self.measurement.proves_fit(capacity), Ok(true)),
        )?;
        measurements.push(self.measurement.clone());
        if fit_requirement.observed {
            observed.push(fit_requirement.handle.clone());
        }
        required.push(fit_requirement);
        // Layout risk: a governing whole unit the floor required that did not
        // arrive whole. The floor owner's identity is the expected set; the
        // delivered representation is the observation, compared by value.
        for member in &self.admitted.floor.members {
            if !matches!(
                member.role,
                SemanticRole::Authority | SemanticRole::Goal | SemanticRole::Acceptance
            ) {
                continue;
            }
            let Some((atom, _)) = self
                .delivered
                .iter()
                .find(|(atom, _)| atom.atom_id == member.atom_id)
            else {
                continue;
            };
            let whole_unit = self.record_requirement(
                "whole-unit",
                dimension,
                &std::format!(
                    "floor-member:{}:representation:{:?}:policy:{:?}",
                    member.atom_id.as_str(),
                    atom.representation.kind(),
                    atom.loss_policy
                ),
                atom.representation.is_whole(),
            )?;
            if whole_unit.observed {
                observed.push(whole_unit.handle.clone());
            }
            required.push(whole_unit);
        }
        Ok(self.place(
            dimension,
            required,
            observed,
            measurements,
            self.fence_rule_revision(dimension)?,
        ))
    }

    /// Instruction sufficiency.
    ///
    /// The required set is every delivered member the ADMISSION owner issued as
    /// governing or decision-relevant authority, together with the decision
    /// owner's own rationale relation. The observation is a delivered member
    /// whose own bytes preserve the reference, and a governing member that
    /// preserves no text is reported. An instruction-shaped atom the owner
    /// issued as merely informational is in neither list, so it cannot be read
    /// as an active directive.
    fn instruction_axis(&self) -> Result<QualityDimensionResult, QualityEvidenceError> {
        let dimension = QualityDimension::InstructionSufficiency;
        let mut required = self.owner_requirements(
            dimension,
            "instruction",
            &[],
            &[(&self.lineage.rationale, &["rationale"][..])],
        )?;
        for (atom, record) in &self.delivered {
            if !matches!(
                atom.authority,
                AuthorityClass::Governing | AuthorityClass::DecisionRelevant
            ) {
                continue;
            }
            let carries = Self::preserved_text(atom).is_some_and(|text| !text.trim().is_empty());
            let requirement = self.record_requirement(
                "directive-member",
                dimension,
                &std::format!(
                    "member:{}:role:{:?}:authority:{:?}:policy:{:?}",
                    atom.atom_id.as_str(),
                    atom.role,
                    atom.authority,
                    record.candidate.loss_policy
                ),
                carries && self.measured(atom),
            )?;
            required.push(requirement);
        }
        self.role_axis(dimension, required, SemanticRole::Instruction)
    }

    /// Payload, handle and reconstruction cost.
    ///
    /// The required set is every delivered member's own representation, named by
    /// identity, kind, loss policy and measured cost — so a whole unit is a
    /// required member too and the set is never empty. The observation is that
    /// member's own measured representation, content-matched against the
    /// delivered set, plus the packet's own serialized byte count. A member with
    /// no observed measurement is named, not assumed free.
    fn reconstruction_axis(&self) -> Result<QualityDimensionResult, QualityEvidenceError> {
        let dimension = QualityDimension::PayloadHandleReconstructionCost;
        let mut required = Vec::new();
        let mut observed = Vec::new();
        let mut measurements = Vec::new();
        for (atom, _) in &self.delivered {
            let member = self.record_requirement(
                "reconstruction",
                dimension,
                &std::format!(
                    "member:{}:kind:{:?}:policy:{:?}:measurement:{}@{}",
                    atom.atom_id.as_str(),
                    atom.representation.kind(),
                    atom.loss_policy,
                    atom.measurement.digest,
                    atom.measurement.serializer
                ),
                self.measured(atom),
            )?;
            if member.observed {
                observed.push(member.handle.clone());
                measurements.push(atom.measurement.clone());
            }
            required.push(member);
        }
        let bytes = self.record_requirement(
            "payload-bytes",
            dimension,
            &std::format!(
                "rendered-utf8-bytes:{}:status:{:?}:whole-units:{}",
                self.measurement.rendered_utf8_bytes,
                self.measurement.status,
                self.delivered
                    .iter()
                    .filter(|(atom, _)| atom.representation.is_whole())
                    .count()
            ),
            // The packet's own byte count is a measurement only when the
            // measurement owner qualified it as one.
            matches!(
                self.measurement.status,
                MeasurementStatus::ExactUtf8 | MeasurementStatus::ExactTokenizer
            ),
        )?;
        if bytes.observed {
            observed.push(bytes.handle.clone());
            measurements.push(self.measurement.clone());
        }
        required.push(bytes);
        Ok(self.place(
            dimension,
            required,
            observed,
            measurements,
            self.fence_rule_revision(dimension)?,
        ))
    }

    /// Known omissions and expansion paths.
    ///
    /// The required set is the economy receipt's OWN authorised-omission set —
    /// the displaced members, already reconciled in both directions in
    /// [`AxisBuilder::read`] — and the expected set is that receipt's, not the
    /// card's. The observation is each omission record's own content: its
    /// reason, competing constraint, exact measured cost or the explicit absence
    /// of one, and whether a valid expansion path or an explicit
    /// non-recoverable reason was recorded. An omission with neither is named as
    /// missing rather than being dropped from the axis, and a non-recoverable
    /// omission is still reported rather than being read as a path.
    fn omission_axis(&self) -> Result<QualityDimensionResult, QualityEvidenceError> {
        let dimension = QualityDimension::KnownOmissionsExpansionPaths;
        let economy = &self.admitted.economy;
        let mut required = Vec::new();
        let mut observed = Vec::new();
        for record in &economy.omissions {
            let cost = record
                .measured_cost
                .map_or_else(|| "unknown".to_owned(), |value| value.to_string());
            let path = match (&record.expansion, record.non_recoverable_reason) {
                (Some(handle), None) => std::format!("expansion:{}", handle.handle_id.as_str()),
                (None, Some(reason)) => std::format!("non-recoverable:{reason:?}"),
                _ => "none".to_owned(),
            };
            let omission = self.record_requirement(
                "omission",
                dimension,
                &std::format!(
                    "omission:{}:reason:{:?}:competing:{}:cost:{cost}:path:{path}:policy:{:?}",
                    record.atom_id.as_str(),
                    record.reason,
                    record.competing_constraint,
                    record.allowed_representation
                ),
                path != "none",
            )?;
            if omission.observed {
                observed.push(omission.handle.clone());
            }
            required.push(omission);
        }
        if required.is_empty() {
            // No omission was authorised. The economy receipt's own requested
            // and displaced counts are the observation, so the axis reports a
            // measured absence instead of an empty requirement that passes
            // vacuously.
            let none = self.record_requirement(
                "omission",
                dimension,
                &std::format!(
                    "no-omission:requested:{}:displaced:0:records:0:rule:{}",
                    economy.requested.len(),
                    economy.applied_rule.as_str()
                ),
                true,
            )?;
            observed.push(none.handle.clone());
            required.push(none);
        }
        let rule_revision = self.handle(
            "omission-rule",
            dimension,
            &std::format!(
                "applied-rule:{}:requested:{}:displaced:{}",
                economy.applied_rule.as_str(),
                economy.requested.len(),
                economy.displaced.len()
            ),
        )?;
        Ok(self.place(dimension, required, observed, Vec::new(), rule_revision))
    }

    /// Telemetry, measurement cost and coverage.
    ///
    /// The required set is the route capacity and the serializer identity this
    /// packet was produced under, both taken from the assembly owner's own
    /// execution record. The observation is the measurement owner's own record
    /// of these bytes: the envelope digest, the measured cost and the measured
    /// status. A `ConservativeStu`, `Unknown` or `Unavailable` status is an
    /// explicit unknown cost, never a measured one.
    fn telemetry_axis(&self) -> Result<QualityDimensionResult, QualityEvidenceError> {
        let dimension = QualityDimension::TelemetryMeasurementCostCoverage;
        let capacity = self.admitted.floor.capacity.route_capacity;
        let exact = matches!(
            self.measurement.status,
            MeasurementStatus::ExactUtf8 | MeasurementStatus::ExactTokenizer
        );
        let mut required = Vec::new();
        let mut observed = Vec::new();
        for (domain, token, satisfied) in [
            (
                "telemetry-route",
                std::format!("route:{}:capacity:{capacity}", self.route_id),
                true,
            ),
            (
                "telemetry-serializer",
                std::format!(
                    "serializer:{}@{}:options:{}",
                    self.measurement.serializer_id,
                    self.measurement.serializer_version,
                    self.measurement.serializer_options_digest
                ),
                true,
            ),
            (
                "telemetry-cost",
                std::format!(
                    "measurement:{}:envelope:{}:status:{:?}:{}",
                    self.measurement.measurement_id.as_str(),
                    self.measurement.envelope_digest,
                    self.measurement.status,
                    measured_cost(self.measurement)
                ),
                // Only an exact UTF-8 or tokenizer observation is a measured
                // cost; a conservative estimate or an unavailable measurement
                // is an explicit unknown and is reported as one.
                exact,
            ),
            (
                "telemetry-reserve",
                std::format!(
                    "fixed:{}:output:{}:review:{}:admitted-required:{}:admitted-optional:{}",
                    self.measurement.fixed_overhead,
                    self.measurement.output_reserve,
                    self.measurement.review_reserve,
                    self.admitted.economy.allocations.admitted_required,
                    self.admitted.economy.allocations.admitted_optional
                ),
                // The measurement owner's reserves against the floor owner's, as
                // independent records of the same route budget.
                self.measurement.fixed_overhead == self.admitted.floor.capacity.fixed_overhead
                    && self.measurement.output_reserve
                        == self.admitted.floor.capacity.output_reserve
                    && self.measurement.review_reserve
                        == self.admitted.floor.capacity.review_reserve,
            ),
        ] {
            let requirement = self.record_requirement(domain, dimension, &token, satisfied)?;
            if requirement.observed {
                observed.push(requirement.handle.clone());
            }
            required.push(requirement);
        }
        let mut measurements = vec![self.measurement.clone()];
        measurements.extend(
            self.delivered
                .iter()
                .map(|(atom, _)| atom.measurement.clone()),
        );
        Ok(self.place(
            dimension,
            required,
            observed,
            measurements,
            self.fence_rule_revision(dimension)?,
        ))
    }

    /// The shared shape for an axis graded from owner references plus a role.
    ///
    /// A required member is observed only when a delivered member's OWN bytes
    /// preserve it, and a delivered member of the dimension's governed role that
    /// preserves none of them is named. That is what stops one representative
    /// atom per role from standing in for a required member set.
    fn role_axis(
        &self,
        dimension: QualityDimension,
        mut required: Vec<Requirement>,
        governed_role: SemanticRole,
    ) -> Result<QualityDimensionResult, QualityEvidenceError> {
        for (atom, _) in self
            .delivered
            .iter()
            .filter(|(atom, _)| atom.role == governed_role)
        {
            let covers = required.iter().any(|candidate| {
                candidate.observed
                    && candidate.text.as_deref().is_some_and(|text| {
                        Self::preserved_text(atom).is_some_and(|held| held.contains(text))
                    })
            });
            required.push(self.record_requirement(
                "role-member",
                dimension,
                &std::format!(
                    "member:{}:role:{:?}:authority:{:?}:status:{:?}",
                    atom.atom_id.as_str(),
                    atom.role,
                    atom.authority,
                    atom.status
                ),
                covers,
            )?);
        }
        let (observed, measurements) = self.observe(&required);
        Ok(self.place(
            dimension,
            required,
            observed,
            measurements,
            self.fence_rule_revision(dimension)?,
        ))
    }

    /// The observed handles and the measurement handles of a requirement set.
    ///
    /// A requirement with owner text is observed by a delivered member's own
    /// bytes; one without is observed by the record comparison the axis already
    /// made. A requirement that is neither is named by [`Self::place`].
    fn observe(&self, requirements: &[Requirement]) -> (Vec<ArtifactId>, Vec<MeasurementRef>) {
        let mut observed = Vec::new();
        let mut measurements = Vec::new();
        for requirement in requirements {
            if !requirement.observed {
                continue;
            }
            observed.push(requirement.handle.clone());
            let Some(text) = requirement.text.as_deref() else {
                continue;
            };
            if let Some(atom) = self
                .delivered
                .iter()
                .map(|(atom, _)| *atom)
                .find(|atom| Self::preserved_text(atom).is_some_and(|held| held.contains(text)))
            {
                measurements.push(atom.measurement.clone());
            }
        }
        (observed, measurements)
    }
}

/// Compares two measurement handles by VALUE.
///
/// `MeasurementRef` is a digest plus a serializer identity and derives neither
/// `Ord` nor `Hash`, so it cannot be a set key; comparing both fields is what
/// makes a handle that matches on one field a non-member.
fn measurement_matches(left: &MeasurementRef, right: &MeasurementRef) -> bool {
    left.digest == right.digest && left.serializer == right.serializer
}

/// The cost the measurement owner actually recorded, or its explicit absence.
fn measured_cost(measurement: &SerializedContextMeasurement) -> String {
    match measurement.status {
        MeasurementStatus::ExactUtf8 => {
            std::format!("exact-utf8:{}", measurement.rendered_utf8_bytes)
        }
        MeasurementStatus::ExactTokenizer => std::format!(
            "exact-tokenizer:{}",
            measurement
                .tokenizer
                .as_ref()
                .map_or_else(|| "unrecorded".to_owned(), |seen| seen.tokens.to_string())
        ),
        MeasurementStatus::ConservativeStu => std::format!(
            "conservative-stu:{}",
            measurement
                .stu_estimate
                .as_ref()
                .map_or_else(|| "unrecorded".to_owned(), |seen| seen.value.to_string())
        ),
        MeasurementStatus::Unknown => "unknown".to_owned(),
        MeasurementStatus::Unavailable => "unavailable".to_owned(),
    }
}

/// Feeds the #1726 `QualityScorecard::NegativeMemoryInvariantCoverage` axis
/// from the same admitted-rule truth the Context projection carries.
///
/// The axis is graded from the projection, never defaulted:
///
/// * `Passed` — at least one governing rule is exposed and no named loss was
///   observed, so real coverage was measured against the compared rule set;
/// * `Unknown` — no governing rule was exposed and no loss explains it, so
///   nothing covers the dimension and the exact unknown evidence is named
///   rather than defaulted;
/// * `Degraded` — a named loss was observed. I12.13 admits whole-unit
///   degradation with an explicit reason, and an incomplete rule enumeration
///   is exactly that: the unit is represented, but its coverage is not
///   established.
///
/// The evidence handles are derived from the rule identities and read handle
/// the projection itself carries, so they name the exact records the exposure
/// was read from rather than a caller-supplied list. The completeness of the
/// card is checked against the owner's own [`QUALITY_DIMENSIONS`] set, which is
/// independent of the caller's `results` vector, and a card that does not
/// already carry exactly those twelve axes is refused rather than completed
/// here. Applying the axis mutates the caller's card in place; nothing else on
/// the card is touched.
///
/// # Errors
///
/// Returns [`NegativeMemoryExposureError::BindingInconsistent`] when the
/// projection does not validate, when the card does not already carry exactly
/// the twelve closed dimensions, or when the card does not already carry the
/// negative-memory axis.
pub fn apply_negative_memory_coverage(
    projection: &NegativeMemoryRuleProjection,
    scorecard: &mut QualityScorecard,
) -> Result<(), NegativeMemoryExposureError> {
    projection.validate()?;
    let mut seen: Vec<QualityDimension> = Vec::with_capacity(scorecard.results.len());
    for result in &scorecard.results {
        if !QUALITY_DIMENSIONS.contains(&result.dimension) || seen.contains(&result.dimension) {
            return Err(NegativeMemoryExposureError::BindingInconsistent(
                "scorecard.results",
            ));
        }
        seen.push(result.dimension);
    }
    if seen.len() != QUALITY_DIMENSIONS.len() {
        return Err(NegativeMemoryExposureError::BindingInconsistent(
            "scorecard.results",
        ));
    }
    let replacement = negative_memory_coverage_result(projection, scorecard, &scorecard.binding)?;
    match scorecard
        .results
        .iter_mut()
        .find(|result| result.dimension == QualityDimension::NegativeMemoryInvariantCoverage)
    {
        Some(axis) => {
            *axis = replacement;
            Ok(())
        }
        None => Err(NegativeMemoryExposureError::BindingInconsistent(
            "scorecard.results",
        )),
    }
}

/// Names one named loss by its own exact identity, bound to the read it was
/// observed against.
///
/// The handle never collapses two different losses into one: a rule identity
/// loss names the record it concerns, and an undecidable comparison names the
/// reason's own closed token. The read handle and rule-set revision are carried
/// on every handle so a reader can re-check freshness from the scorecard axis
/// alone, without consulting the projection it came from.
fn negative_memory_loss_token(
    loss: &NegativeMemoryEvidenceLoss,
    evidence: &MatchEvidence,
) -> String {
    let cause = match loss {
        NegativeMemoryEvidenceLoss::ComparisonNotDecidable { reason } => {
            format!("comparison_not_decidable:{reason:?}")
        }
        NegativeMemoryEvidenceLoss::BackingAuthorityUnavailable {
            record_id,
            rule_revision,
            missing,
        } => format!("backing_authority_unavailable:{record_id}:{rule_revision}:{missing:?}"),
    };
    format!(
        "{cause}:{}:{}",
        evidence.read_handle, evidence.rule_set_revision
    )
}

/// Builds the one negative-memory coverage result for a projection.
fn negative_memory_coverage_result(
    projection: &NegativeMemoryRuleProjection,
    scorecard: &QualityScorecard,
    binding: &ContextBinding,
) -> Result<QualityDimensionResult, NegativeMemoryExposureError> {
    let mut evidence: Vec<ArtifactId> = Vec::new();
    for rule in projection.governing_rules() {
        evidence.push(
            ArtifactId::new(std::format!(
                "negative-memory-rule:{}:{}:{}",
                rule.record_id,
                rule.rule_revision,
                rule.record_digest
            ))
            .map_err(|_| NegativeMemoryExposureError::InvalidField("quality.evidence"))?,
        );
    }
    let mut unknown_evidence: Vec<ArtifactId> = Vec::new();
    for loss in &projection.losses {
        unknown_evidence.push(
            ArtifactId::new(std::format!(
                "negative-memory-evidence-loss:{}",
                negative_memory_loss_token(loss, &projection.evidence)
            ))
            .map_err(|_| NegativeMemoryExposureError::InvalidField("quality.unknown_evidence"))?,
        );
    }
    if evidence.is_empty() && unknown_evidence.is_empty() {
        unknown_evidence.push(
            ArtifactId::new(std::format!(
                "negative-memory-exposure:{}",
                projection.evidence.read_handle
            ))
            .map_err(|_| NegativeMemoryExposureError::InvalidField("quality.unknown_evidence"))?,
        );
    }

    // A named loss means the compared rule set was not completely established,
    // so the axis is degraded whether or not some governing rules were exposed.
    // Grading it `Passed` here while the loss handles sit in the missing/stale
    // set would be a pass carrying unknowns, which the owner's own validation
    // rejects; the axis would then be ungradeable rather than honestly degraded,
    // and a partially observed comparison would read as complete coverage.
    let state = if !projection.losses.is_empty() {
        QualityDimensionState::Degraded {
            reason: std::format!(
                "negative-memory exposure carries {} named loss(es) against read {}; the unit is represented but its coverage is not established",
                projection.losses.len(),
                projection.evidence.read_handle
            ),
        }
    } else if !evidence.is_empty() {
        QualityDimensionState::Passed
    } else {
        QualityDimensionState::Unknown
    };

    let result = QualityDimensionResult {
        schema_version: QUALITY_RESULT_SCHEMA_VERSION,
        dimension: QualityDimension::NegativeMemoryInvariantCoverage,
        state,
        rule_revision: ArtifactId::new(std::format!(
            "negative-memory-rule-set:{}",
            projection.evidence.rule_set_revision
        ))
        .map_err(|_| NegativeMemoryExposureError::InvalidField("quality.rule_revision"))?,
        // The required member set is exactly the governing rules this
        // projection exposes; the result is a pass only because every one of
        // them was observed above.
        required_evidence: evidence.clone(),
        evidence,
        measurements: Vec::new(),
        failed_invariant: None,
        unknown_evidence,
        proof_ceiling: ProofCeiling::ScopedVerification,
        invalidation: None,
        binding: binding.clone(),
    };
    // The owner's own independent validation decides whether this result is a
    // legal scorecard value; it is never weakened here. `QualityScorecard`
    // exposes no per-axis validator, so the check is the owner's own card
    // validation over a card whose negative-memory axis is exactly this result.
    // It cannot pass vacuously: the owner's validator requires a `Passed` axis
    // to carry observed evidence and no unknown evidence, and a failed, unknown
    // or degraded axis to name its failed invariant or unknown evidence.
    let mut probe = QualityScorecard {
        schema_version: scorecard.schema_version,
        binding: binding.clone(),
        output: scorecard.output.clone(),
        applicability: scorecard.applicability.clone(),
        results: scorecard.results.clone(),
    };
    if let Some(axis) = probe
        .results
        .iter_mut()
        .find(|existing| existing.dimension == QualityDimension::NegativeMemoryInvariantCoverage)
    {
        *axis = result.clone();
    }
    probe
        .validate()
        .map_err(|_| NegativeMemoryExposureError::BindingInconsistent("scorecard.axis"))?;
    Ok(result)
}
