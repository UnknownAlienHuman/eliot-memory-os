//! Optional analysis admitted only within its own question (I8.9.1).
//!
//! I8.9.1 states the rule this module makes expressible: when deterministic
//! evidence is insufficient, "the agent receives evidence handles, a precise
//! question, no broad mutation authority and an explicit stop condition."
//!
//! Four prohibitions are structural here rather than checked at runtime:
//!
//! - **No broad corpus extraction.** A request names an exact handle set, and
//!   every handle's declared scope must already lie inside the domains the
//!   bound [`DisclosureDecision`] covers. The set has no "all sources" form, and
//!   the retained candidate's `bounded_by` is copied from the request, never
//!   from the answer, so an answer cannot widen the set it was given.
//! - **No reusable credentials.** The request carries no bearer credential. It
//!   carries a decision that is already bound to one exact
//!   [`DisclosureDependencyClosure`], and every handle is proven to lie inside
//!   that closure, so there is nothing in the request to lift into a later,
//!   wider one: widening needs a new authorized decision. It is also not
//!   `Serialize`, so it cannot be written into an ordinary log, a
//!   notification, or a remote model prompt, and it is not `Clone`, so it
//!   cannot be copied for a second use.
//! - **No standing mutation permission.** Neither the request nor the retained
//!   candidate has a field for a quarantine state, an Incident, an authority
//!   grant, a release condition or a source-use authority, so no producer can
//!   hand one to the other and no consumer can read one.
//! - **No model call triggered merely by a waiting hard gate.** A request
//!   cannot exist without one of exactly two evidence-anchored triggers, and
//!   neither of them is a state: they name a retained indicator observation, or
//!   one already-admitted `ConflictSet`. There is deliberately no variant for a
//!   blocked gate, a backlog, a heartbeat interval or any other condition that
//!   is not evidence, so a waiting gate has nothing to construct. Adding one is
//!   a visible contract change here, not a runtime check that can be deleted.
//!
//! [`AdmittedAnalysisCandidate::assertability`] is derived from
//! [`AdmittedAnalysisLineage`] and is never a supplied field, so an answer
//! whose lineage is incomplete cannot be read as a confident one: I12.20's
//! "if lineage incomplete, quarantine the bounded affected scope" reaches this
//! surface as bounded uncertainty rather than as a complete summary.

use eliot_contracts::StateFence;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::SecurityContractError;
use crate::surface_types::{
    AssessedSourceRevision, DisclosureDecision, DisclosureDecisionKind, DisclosureDependencyClosure,
    assessment_digest, assessment_refs, assessment_text,
};

/// Why one optional analysis was asked for.
///
/// Both variants name an already-retained evidence anchor. Neither names a
/// runtime state, so neither a blocked hard gate nor any other waiting
/// condition can produce a request.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "trigger", rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum AdmittedAnalysisTrigger {
    /// One bounded semantic question about one retained I8.8 indicator
    /// observation.
    RetainedIndicatorQuestion {
        /// The retained indicator observation this question is about.
        observation_ref: String,
    },
    /// One bounded semantic question over one `ConflictSet` that was already
    /// admitted. This is the route `analyze_conflict` may take: it processes a
    /// valid existing set as a candidate and acquires no source itself.
    AdmittedConflictSetQuestion {
        /// The already-admitted conflict set this question is about.
        conflict_set_ref: String,
    },
}

/// The only answer form an admitted analysis may return.
///
/// There is no variant that resolves a conflict, releases a quarantine, opens
/// an Incident, raises authority, or returns a plan, so the output contract has
/// no such output to be widened into.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AdmittedAnalysisOutputContract {
    /// A candidate interpretation of the admitted question, bounded by the
    /// admitted handles and retained with its counterevidence and unknowns.
    CandidateInterpretation,
}

/// The one terminal condition that ends an admitted analysis.
///
/// A request with no stop condition cannot be constructed.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AdmittedAnalysisStopCondition {
    /// The admitted question is answered from the admitted handles.
    QuestionAnswered,
    /// The admitted time bound is reached.
    TimeBoundReached,
    /// The admitted budget bound is reached.
    BudgetBoundReached,
    /// The requesting owner cancelled the analysis.
    Cancelled,
}

/// One optional analysis, admitted within exactly one question.
///
/// The seven facets I8.9.1 names are all required fields, so a request cannot
/// be built without them: the exact permitted handles, the recipient disclosure
/// domain, the question, the budget bound, the time bound, the output contract
/// and the stop condition. This type is deliberately neither `Clone` nor
/// `Serialize`; see the module documentation for why.
#[derive(Debug, Eq, PartialEq)]
pub struct AdmittedAnalysisRequest {
    /// Opaque identity of this one request.
    pub request_ref: String,
    /// The retained evidence anchor that caused the question to be asked.
    pub trigger: AdmittedAnalysisTrigger,
    /// The precise question, in the asker's own words.
    pub question: String,
    /// The exact source revisions this analysis may read. Non-empty and
    /// distinct by source; there is no whole-corpus form.
    pub permitted_handles: Vec<AssessedSourceRevision>,
    /// The dependency closure the permitted handles are drawn from.
    pub closure: DisclosureDependencyClosure,
    /// The disclosure decision for the recipient this analysis may reach. It is
    /// bound to `closure` and is the only disclosure authority present.
    pub disclosure: DisclosureDecision,
    /// The exact owner-issued budget bound admitted for this question.
    pub budget_bound: String,
    /// The exact owner-issued time bound admitted for this question.
    pub time_bound: String,
    /// The only answer form this request may return.
    pub output_contract: AdmittedAnalysisOutputContract,
    /// The one terminal condition that ends this request.
    pub stop_condition: AdmittedAnalysisStopCondition,
    /// The fence this request was admitted under.
    pub state_fence: StateFence,
}

impl AdmittedAnalysisRequest {
    /// Validates that all seven admitted facets hold together.
    ///
    /// # Errors
    ///
    /// Returns an error when a facet is blank or malformed, when the handle set
    /// is empty or repeats a source, when the closure or the decision fails
    /// their own existing validation, when the decision does not name this
    /// closure or admits a recipient that no decision kind may carry an answer
    /// to, or when a permitted handle reaches a scope outside the domains that
    /// decision covers.
    pub fn validate(&self) -> Result<(), SecurityContractError> {
        assessment_text(&self.request_ref, "analysis.request_ref")?;
        assessment_text(&self.question, "analysis.question")?;
        assessment_text(&self.budget_bound, "analysis.budget_bound")?;
        assessment_text(&self.time_bound, "analysis.time_bound")?;
        match &self.trigger {
            AdmittedAnalysisTrigger::RetainedIndicatorQuestion { observation_ref } => {
                assessment_text(observation_ref, "analysis.trigger.observation_ref")?;
            }
            AdmittedAnalysisTrigger::AdmittedConflictSetQuestion { conflict_set_ref } => {
                assessment_text(conflict_set_ref, "analysis.trigger.conflict_set_ref")?;
            }
        }
        self.state_fence
            .validate()
            .map_err(|_| SecurityContractError::InvalidFence {
                field: "analysis.state_fence",
            })?;
        self.closure.validate()?;
        self.disclosure.validate()?;
        if self.disclosure.subject_and_closure_ref != self.closure.closure_id {
            return Err(SecurityContractError::StaleSourceAssessment {
                field: "analysis.disclosure.subject_and_closure_ref",
            });
        }
        if !matches!(
            self.disclosure.decision,
            DisclosureDecisionKind::Allow | DisclosureDecisionKind::AllowRedacted
        ) {
            return Err(SecurityContractError::AnalysisRecipientNotAdmitted {
                decision: decision_kind_name(self.disclosure.decision),
            });
        }
        if self.disclosure.policy_snapshot_and_state_fence.state_fence != self.state_fence
            || self.closure.state_fence != self.state_fence
        {
            return Err(SecurityContractError::FenceMismatch);
        }

        if self.permitted_handles.is_empty() {
            return Err(SecurityContractError::EmptyCollection {
                field: "analysis.permitted_handles",
            });
        }
        let mut admitted: std::collections::BTreeSet<&str> = std::collections::BTreeSet::new();
        for handle in &self.permitted_handles {
            handle.validate()?;
            if !admitted.insert(handle.source_ref.as_str()) {
                return Err(SecurityContractError::DuplicateReference {
                    field: "analysis.permitted_handles",
                });
            }
            for reached in &handle.scope.included_refs {
                if !self.admits_domain(reached) {
                    return Err(SecurityContractError::AnalysisHandleOutsideAdmission {
                        reference: reached.clone(),
                    });
                }
            }
        }
        Ok(())
    }

    /// Whether this request's decision covers one exact domain of its closure.
    ///
    /// The closure, not the request or the decision, is the authority on which
    /// domains exist at all, so a decision cannot widen the request by naming a
    /// domain the closure does not carry.
    fn admits_domain(&self, domain_ref: &str) -> bool {
        self.disclosure.covered_domains.iter().any(|covered| {
            covered == domain_ref
                && self
                    .closure
                    .direct_domain_refs
                    .iter()
                    .any(|domain| &domain.domain_id == covered)
        })
    }
}

/// What the analysis owner reports back about the one question it ran.
///
/// This is a report of retained references. It carries no answer content, so a
/// raw secret canary has no field here to travel in.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AdmittedAnalysisOutcome {
    /// Where the retained answer itself lives, in its owner's restricted store.
    pub answer_ref: String,
    /// The permitted handles the answer actually used. Every entry must be one
    /// this request admitted.
    pub answered_from_handles: Vec<String>,
    /// Lineage roots shared across the answer and its inputs, so a repeated or
    /// model-common lineage stays visible rather than reading as independence.
    pub common_lineage_refs: Vec<String>,
    /// Retained evidence that counts against the answer.
    pub counterevidence_refs: Vec<String>,
    /// What the analysis could not establish.
    pub unknowns: Vec<String>,
    /// Whether every claim in the answer is attributed to a known lineage root.
    pub lineage: AdmittedAnalysisLineage,
    /// The fence the analysis actually ran under.
    pub state_fence: StateFence,
}

/// Whether an answer's lineage is fully attributed.
///
/// The variant that admits incompleteness carries the unattributed claims and
/// the admitted handles whose lineage could not be established, so bounded
/// uncertainty is stated rather than presented as a complete summary.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "lineage", rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum AdmittedAnalysisLineage {
    /// Every claim is attributed to a known lineage root.
    Attributed {
        /// Every lineage root the answer draws on.
        lineage_roots: Vec<String>,
    },
    /// At least one claim's lineage root is unknown or outside the admitted
    /// handles. The claim is retained and bounded, not dropped and not
    /// presented as complete.
    BoundedUncertainty {
        /// Claims whose lineage root could not be established.
        unattributed_claims: Vec<String>,
        /// Admitted handles whose lineage could not be established.
        unknown_lineage_handles: Vec<String>,
    },
}

/// How strongly a retained answer may be asserted.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AdmittedAnalysisAssertability {
    /// Lineage is fully attributed.
    Attributed,
    /// Lineage is incomplete; the answer states what it could not establish.
    BoundedUncertainty,
}

/// One retained candidate answer to one admitted question.
///
/// This record carries no quarantine state, Incident, authority grant, release
/// condition or source-use authority, so retaining it can release nothing and
/// raise nothing. It holds retained references only.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AdmittedAnalysisCandidate {
    /// The request this answers.
    pub request_ref: String,
    /// The admitted question, verbatim.
    pub question: String,
    /// The request's exact permitted handles, copied from the request rather
    /// than from the answer.
    pub bounded_by: Vec<AssessedSourceRevision>,
    /// The receipt of the disclosure decision this answer may reach.
    pub disclosure_receipt_ref: String,
    /// Where the retained answer lives.
    pub answer_ref: String,
    /// Shared lineage roots retained with the answer.
    pub common_lineage_refs: Vec<String>,
    /// Retained evidence that counts against the answer.
    pub counterevidence_refs: Vec<String>,
    /// What the analysis could not establish.
    pub unknowns: Vec<String>,
    /// Whether every claim in the answer is attributed.
    pub lineage: AdmittedAnalysisLineage,
    /// The fence this candidate was recorded under.
    pub state_fence: StateFence,
}

impl AdmittedAnalysisCandidate {
    /// How strongly this answer may be asserted.
    ///
    /// Derived from the recorded lineage and never a supplied field, so an
    /// answer with incomplete lineage has no confident reading to select.
    #[must_use]
    pub const fn assertability(&self) -> AdmittedAnalysisAssertability {
        match &self.lineage {
            AdmittedAnalysisLineage::Attributed { .. } => AdmittedAnalysisAssertability::Attributed,
            AdmittedAnalysisLineage::BoundedUncertainty { .. } => {
                AdmittedAnalysisAssertability::BoundedUncertainty
            }
        }
    }
}

/// Admits one optional analysis and retains exactly one candidate for it.
///
/// The answer's handle set is checked against the request's own handle set, and
/// the retained candidate's `bounded_by` is a clone of the request's handles, so
/// an answer cannot introduce, widen or silently drop the scope it was given.
///
/// # Errors
///
/// Returns an error when the request fails
/// [`AdmittedAnalysisRequest::validate`], when the answer reports a handle this
/// request did not admit, when a retained reference list is malformed, when the
/// lineage declares no root, or when the analysis ran under another fence.
pub fn admit_analysis(
    request: &AdmittedAnalysisRequest,
    outcome: &AdmittedAnalysisOutcome,
) -> Result<AdmittedAnalysisCandidate, SecurityContractError> {
    request.validate()?;
    if outcome.state_fence != request.state_fence {
        return Err(SecurityContractError::FenceMismatch);
    }
    assessment_text(&outcome.answer_ref, "analysis.answer_ref")?;
    assessment_refs(
        &outcome.answered_from_handles,
        "analysis.answered_from_handles",
    )?;
    optional_refs(&outcome.common_lineage_refs, "analysis.common_lineage_refs")?;
    optional_refs(&outcome.counterevidence_refs, "analysis.counterevidence_refs")?;
    optional_refs(&outcome.unknowns, "analysis.unknowns")?;
    match &outcome.lineage {
        AdmittedAnalysisLineage::Attributed { lineage_roots } => {
            assessment_refs(lineage_roots, "analysis.lineage.lineage_roots")?;
        }
        AdmittedAnalysisLineage::BoundedUncertainty {
            unattributed_claims,
            unknown_lineage_handles,
        } => {
            assessment_refs(
                unattributed_claims,
                "analysis.lineage.unattributed_claims",
            )?;
            assessment_refs(
                unknown_lineage_handles,
                "analysis.lineage.unknown_lineage_handles",
            )?;
        }
    }
    for used in &outcome.answered_from_handles {
        if !request
            .permitted_handles
            .iter()
            .any(|handle| &handle.source_ref == used)
        {
            return Err(SecurityContractError::AnalysisHandleOutsideAdmission {
                reference: used.clone(),
            });
        }
    }
    Ok(AdmittedAnalysisCandidate {
        request_ref: request.request_ref.clone(),
        question: request.question.clone(),
        bounded_by: request.permitted_handles.clone(),
        disclosure_receipt_ref: request.disclosure.receipt_ref.clone(),
        answer_ref: outcome.answer_ref.clone(),
        common_lineage_refs: outcome.common_lineage_refs.clone(),
        counterevidence_refs: outcome.counterevidence_refs.clone(),
        unknowns: outcome.unknowns.clone(),
        lineage: outcome.lineage.clone(),
        state_fence: outcome.state_fence.clone(),
    })
}

/// Same shape rule as [`assessment_refs`] for a list that may legitimately be
/// empty: no analysis finding counterevidence or unknown means "none found",
/// not "nothing recorded".
fn optional_refs(values: &[String], field: &'static str) -> Result<(), SecurityContractError> {
    let mut seen = std::collections::BTreeSet::new();
    for value in values {
        assessment_text(value, field)?;
        if !seen.insert(value) {
            return Err(SecurityContractError::DuplicateReference { field });
        }
    }
    Ok(())
}

fn decision_kind_name(kind: DisclosureDecisionKind) -> &'static str {
    match kind {
        DisclosureDecisionKind::Allow => "ALLOW",
        DisclosureDecisionKind::AllowRedacted => "ALLOW_REDACTED",
        DisclosureDecisionKind::RecomputeNarrower => "RECOMPUTE_NARROWER",
        DisclosureDecisionKind::ForkPrivate => "FORK_PRIVATE",
        DisclosureDecisionKind::RequireAuthority => "REQUIRE_AUTHORITY",
        DisclosureDecisionKind::Deny => "DENY",
    }
}

impl AssessedSourceRevision {
    /// Validates one exact source revision, digest and declared scope.
    ///
    /// # Errors
    ///
    /// Returns an error when an identity, revision or scope reference is blank
    /// or duplicated, when a declared scope is empty, or when the digest is not
    /// a lowercase SHA-256.
    pub fn validate(&self) -> Result<(), SecurityContractError> {
        assessment_text(&self.source_ref, "handle.source_ref")?;
        assessment_text(&self.revision, "handle.revision")?;
        assessment_digest(&self.digest, "handle.digest")?;
        assessment_text(&self.scope.scope_ref, "handle.scope.scope_ref")?;
        assessment_refs(&self.scope.included_refs, "handle.scope.included_refs")?;
        optional_refs(&self.scope.excluded_refs, "handle.scope.excluded_refs")
    }
}
