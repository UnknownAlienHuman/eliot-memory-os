//! Self-Quality conformance-diagnosis evidence for the improvement funnel
//! (issue #1867 W2/A1, I12.24).
//!
//! I12.24:50 lists `Architecture/Implementation/runtime conformance gap` among
//! the improvement triggers, and I12.24:60-64 puts the durable evidence set
//! that raised such a signal at the funnel's second step. This module is the
//! single projection of ONE already-diagnosed conformance finding into the
//! [`SourcedEvidence`](eliot_improvement::evidence_sources::SourcedEvidence)
//! bundle the improvement funnel takes. It goes through this crate's own
//! existing mechanisms and adds nothing:
//!
//! - the inert owner handoff is built by [`make_handoff`], the #971 routing
//!   contract's own constructor, and is validated by the normative
//!   `validate_handoff` inside it;
//! - the projection itself is
//!   [`sourced_evidence_from_handoff`](crate::improvement_handoff::sourced_evidence_from_handoff),
//!   which delegates to the improvement funnel's single validated constructor
//!   `eliot_improvement::sourced_evidence`. A second evidence constructor is not
//!   created here.
//!
//! # What this module does NOT do
//!
//! It adds no diagnosis. Severity, recurrence and causal standing remain the
//! #971 diagnosis's, and a symptom is never restated as a proven cause: the
//! projection maps every symptom ref to an `unproven-symptom:{ref}` hypothesis,
//! exactly as `improvement_handoff.rs` documents. It performs no planning, no
//! mutation, no effect, no authority issuance, no store access, no provider or
//! model call and no clock read, so the crate's `PROOF_CEILING` is unchanged.

use eliot_conformance_contracts::{Priority, SelfQualityHandoffOwner};
use eliot_improvement::evidence_sources::SourcedEvidence;

use crate::error::SelfQualityError;
use crate::improvement_handoff::sourced_evidence_from_handoff;
use crate::routing::make_handoff;

/// One already-routed conformance-diagnosis finding, in the exact terms the
/// #971 handoff contract owns.
///
/// This is a field group, not a new contract: every member is a field
/// [`make_handoff`] already requires, plus the two decision fields the
/// improvement funnel needs and the handoff cannot carry. It exists so the
/// ten-parameter handoff contract is assembled in one place — the crate that
/// owns it — instead of being restated by each consumer.
///
/// # Ref sets
///
/// `make_handoff` SORTS each ref set but does not de-duplicate it, and the
/// normative `validate_handoff` rejects both a repeated and an unsorted ref.
/// A caller therefore supplies each set already unique; an input that repeats a
/// ref is a contract rejection ([`SelfQualityError::Contract`]), never a
/// silently repaired set.
pub struct ConformanceDiagnosis {
    /// Stable identity of this finding's handoff.
    pub handoff_ref: String,
    /// The external decision owner the finding routes to.
    pub owner: SelfQualityHandoffOwner,
    /// The finding's urgency on the independent priority axis.
    pub priority: Priority,
    /// Observed symptoms. Never proven causes.
    pub symptom_refs: Vec<String>,
    /// The problem refs the finding raises.
    pub problem_refs: Vec<String>,
    /// The evidence refs the finding is observed on.
    pub evidence_refs: Vec<String>,
    /// Evidence the finding knows is missing, if any.
    pub missing_evidence_refs: Vec<String>,
    /// Conditions under which the finding applies.
    pub applicability_refs: Vec<String>,
    /// Constraints the owner's disposition must respect.
    pub constraint_refs: Vec<String>,
    /// What invalidates this finding; must be non-empty per `validate_handoff`.
    pub invalidation_set: Vec<String>,
    /// The problem statement or metric that raised the improvement signal.
    pub trigger_problem_or_metric: String,
    /// The validity scope the evidence is claimed for.
    pub validity_scope: String,
}

/// Projects one routed conformance-diagnosis finding into the improvement
/// funnel's evidence bundle.
///
/// Two steps, both existing and both validating: the finding becomes an inert
/// [`SelfQualityHandoff`](eliot_conformance_contracts::SelfQualityHandoff)
/// through [`make_handoff`] (which stamps the contract version and runs the
/// normative `validate_handoff`), and that handoff becomes
/// [`SourcedEvidence`](eliot_improvement::evidence_sources::SourcedEvidence)
/// with source [`ConformanceDiagnosis`](eliot_improvement::evidence_sources::EvidenceSource::ConformanceDiagnosis)
/// through
/// [`sourced_evidence_from_handoff`](crate::improvement_handoff::sourced_evidence_from_handoff).
///
/// The failure is the typed [`SelfQualityError`] of whichever step refused, so
/// a #971 contract rejection and a missing improvement-mapping ref stay
/// distinguishable across the layer boundary rather than collapsing into a
/// string.
pub fn sourced_evidence_from_conformance_diagnosis(
    finding: &ConformanceDiagnosis,
) -> Result<SourcedEvidence, SelfQualityError> {
    let handoff = make_handoff(
        &finding.handoff_ref,
        finding.owner,
        &finding.symptom_refs,
        &finding.problem_refs,
        &finding.evidence_refs,
        &finding.missing_evidence_refs,
        &finding.applicability_refs,
        finding.priority,
        &finding.constraint_refs,
        &finding.invalidation_set,
    )?;
    sourced_evidence_from_handoff(
        &handoff,
        &finding.trigger_problem_or_metric,
        &finding.validity_scope,
    )
}
