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

use std::collections::BTreeMap;

use eliot_context_contracts::{
    ContextBinding, QUALITY_DIMENSIONS, QUALITY_RESULT_SCHEMA_VERSION, QualityDimension,
    QualityDimensionResult, QualityDimensionState, QualityScorecard,
};
use eliot_contracts::ArtifactId;
use eliot_dreamer_failure::{
    IdentityRelation, IncompleteReason, MatchEvidence, NegativeMemoryActionPolicy,
    NegativeMemoryDisposition, NegativeMemoryFingerprint, NegativeMemoryHorizonRelation,
    NegativeMemoryMatchKind, NegativeMemoryMatchResult, NegativeMemoryOutcome,
};
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
