//! The resolver / `dev-fast` side of the stored plan seam.
//!
//! [`crate::PlanConsumer`] is the adapter seam between planning and the
//! runner. This module is its one real implementor: the resolver holds a
//! [`StoredPlanEnvelope`](crate::StoredPlanEnvelope) retained from the
//! publication path and hands it to this consumer together with the inputs
//! that are currently applicable. The consumer does exactly three things, in
//! this order:
//!
//! ```text
//! 1. validate the envelope binding   (StoredPlanEnvelope::validate)
//! 2. revalidate the applicable inputs before execution
//!                                     (revalidate_plan: candidate, target,
//!                                      features, graph revision, retained
//!                                      source commitments, and the frozen
//!                                      discovery join)
//! 3. refuse anything that would silently degrade, then emit the plan's own
//!    reference                     (ChangeImpactPlan::reference)
//! ```
//!
//! Properties this module makes structural rather than advisory
//! (`I18.3`, `I18.4`, `I18.6`, `I2.17`):
//!
//! ```text
//! drift detection is not reimplemented: every applicable-input check is
//!   routed through `revalidate_plan`, so one seam alone decides what
//!   invalidates a plan revision;
//! actually discovered tests are joined against the frozen plan before the
//!   reference is emitted: the normalized snapshot observed now is compared
//!   by value with the plan's frozen discovery join, and a moved candidate,
//!   target, feature set, snapshot revision, digest, entry count, or
//!   inventory completeness is refused rather than consumed as current
//!   evidence;
//! the emitted reference is the plan's own `reference()`; the consumer never
//!   mints, bumps, or re-digests a revision, so consuming a plan cannot
//!   rewrite history;
//! a plan that is incomplete, carries mandatory-but-deferred required checks,
//!   holds a pending check or unestablished affected-node coverage, or sits
//!   in a tier this site is not admitted for is refused rather than consumed
//!   at reduced fidelity: doubt never becomes a narrower or silently degraded
//!   run;
//! one envelope in, one reference out, and no side effect: no process is
//!   launched, no completion is decided, and the envelope is not mutated.
//! ```
//!
//! The consumer holds no mutable state, launches nothing, and decides no
//! completion; the runner and `FinishService` keep those boundaries
//! (`I10.8.4`, `I18.1`).

use crate::{
    BuildTestGraph, ChangeImpactPlan, CheckDisposition, DiscoveredTestSnapshot, PlanCompleteness,
    PlanConsumer, PlanError, PlanReference, SourceCommitment, StoredPlanEnvelope, revalidate_plan,
};

/// The inputs currently applicable at the resolver / `dev-fast` consume
/// site: the exact candidate, target and features, the graph as it stands
/// now, the source commitments required right now, and the normalized test
/// discovery snapshot discovered now.
///
/// These are observations supplied by their owning producers. The consumer
/// verifies them against the retained plan through
/// [`revalidate_plan`](crate::revalidate_plan); it never re-derives them.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApplicableInputs {
    pub candidate_revision: String,
    pub target: String,
    pub features: Vec<String>,
    /// The compiled graph as it stands now, for its revision and its retained
    /// producer commitments.
    pub graph: BuildTestGraph,
    /// Source revisions required by the current selection. Each is verified
    /// against the commitment the plan retained at plan time; a caller
    /// revision string is never trusted alone.
    pub expected_source: Vec<SourceCommitment>,
    /// The normalized discovery snapshot under the same candidate, target and
    /// features, as discovered now. It is joined against the plan's frozen
    /// discovery binding by value, so a moved inventory, a moved snapshot
    /// revision, or a snapshot from another candidate/target/feature set is
    /// refused instead of being consumed as current evidence.
    pub discovery: Option<DiscoveredTestSnapshot>,
}

impl ApplicableInputs {
    /// Binds the resolver / `dev-fast` inputs of one consume site to the
    /// exact graph and required source commitments of this plan.
    pub const fn new(
        candidate_revision: String,
        target: String,
        features: Vec<String>,
        graph: BuildTestGraph,
        expected_source: Vec<SourceCommitment>,
        discovery: Option<DiscoveredTestSnapshot>,
    ) -> Self {
        Self {
            candidate_revision,
            target,
            features,
            graph,
            expected_source,
            discovery,
        }
    }
}

/// The resolver / `dev-fast` [`PlanConsumer`].
///
/// It consumes one retained plan version for execution, revalidates the
/// applicable inputs first, and emits the plan reference for the caller's
/// receipt. It never duplicates [`BuildTestGraph::impact`], launches no
/// process, and decides no completion.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolverPlanConsumer {
    inputs: ApplicableInputs,
    /// Bounded `I18.4` tier this site is admitted for, or `None` when it is
    /// admitted for no broader tier: the same vocabulary and shape as
    /// [`PlanRequest::permitted_broader_tier`](crate::PlanRequest).
    permitted_broader_tier: Option<String>,
}

impl ResolverPlanConsumer {
    /// Binds a resolver / `dev-fast` site to the inputs currently applicable
    /// and the bounded broader tier it is admitted for.
    pub const fn new(inputs: ApplicableInputs, permitted_broader_tier: Option<String>) -> Self {
        Self {
            inputs,
            permitted_broader_tier,
        }
    }

    /// Validates the envelope binding, revalidates the applicable inputs
    /// before execution, and refuses silent degradation. A `PlanReference`
    /// carrying the verified discovery join results; the envelope is read
    /// only.
    pub fn consume(&self, stored: &StoredPlanEnvelope) -> Result<PlanReference, PlanError> {
        stored.validate()?;
        revalidate_plan(
            &stored.plan,
            &self.inputs.graph,
            &self.inputs.candidate_revision,
            &self.inputs.target,
            &self.inputs.features,
            &self.inputs.expected_source,
            self.inputs.discovery.as_ref(),
        )?;
        self.refuse_silent_degradation(&stored.plan)?;
        let reference = stored.plan.reference();
        reference.validate()?;
        Ok(reference)
    }

    /// Refuses any plan that would silently degrade: an incomplete plan, a
    /// plan whose required checks stay mandatory-but-deferred, a considered
    /// check with no settled disposition, unestablished affected-node
    /// coverage, or a broader tier this site is not admitted for. The plan's
    /// own `PlanGap` / `DeferredCheck` / `CheckDisposition` / `NodeCoverage`
    /// / tier vocabulary is reused; no parallel "can I run" concept is
    /// introduced.
    fn refuse_silent_degradation(&self, plan: &ChangeImpactPlan) -> Result<(), PlanError> {
        match &plan.completeness {
            PlanCompleteness::Complete => {}
            PlanCompleteness::Incomplete { gaps } => {
                return Err(PlanError::IncompletePlan {
                    regions: gaps.iter().map(|gap| gap.region.clone()).collect(),
                });
            }
            PlanCompleteness::BroaderTier { tier, .. } => {
                if self.permitted_broader_tier.as_deref() != Some(tier.as_str()) {
                    return Err(PlanError::UnpermittedTier { tier: tier.clone() });
                }
            }
        }
        if !plan.deferred.is_empty() {
            return Err(PlanError::DeferredRequiredCheck {
                checks: plan
                    .deferred
                    .iter()
                    .map(|deferred| deferred.check_id.clone())
                    .collect(),
            });
        }
        if plan
            .checks
            .iter()
            .any(|check| check.disposition == CheckDisposition::Pending)
        {
            return Err(PlanError::PendingCheck);
        }
        let unestablished = plan
            .directive
            .node_coverage
            .iter()
            .find(|(_, coverage)| !coverage.is_established())
            .map(|(node, _)| node.clone());
        if unestablished.is_some() || plan.directive.unknown_coverage {
            return Err(PlanError::UnknownCoverage {
                node: unestablished,
            });
        }
        Ok(())
    }
}

impl PlanConsumer for ResolverPlanConsumer {
    /// Consumes one stored plan envelope and returns its reference for the
    /// caller's downstream receipt.
    fn consume_stored_plan(&self, stored: &StoredPlanEnvelope) -> Result<PlanReference, PlanError> {
        self.consume(stored)
    }
}
