//! Canonical retrieval-plan compiler (I12.26).
//!
//! [`compile_retrieval_plan`] deterministically compiles explicit,
//! caller-owned compilation factors into a validated [`RetrievalPlan`]:
//! route and fence sets are ordered, the campaign handle set is ordered,
//! and the assembled record passes [`RetrievalPlan::validate`]. Route
//! SELECTION policy (which handles, kinds, fences, and requirement texts
//! apply to a task family) belongs to the caller — M1/M2 coordinate it —
//! this owner only normalizes, validates, and identifies. No graph is
//! consulted, no corpus is read, and no requirement text is interpreted.

#![forbid(unsafe_code)]

use eliot_context_contracts::ContextError;
use eliot_contracts::{ArtifactId, StateFence};

use crate::retrieval_plan::{
    CampaignBudgets, CampaignExperienceQuery, CampaignIntent, CampaignOutputMode, RetrievalPlan,
    RetrievalRouteKind, RouteExecution, SourceProjectionFence,
};

/// Explicit caller-owned compilation factors for one retrieval plan.
///
/// Shapes mirror [`RetrievalPlan`] field for field: the compiler orders set
/// members deterministically and validates the assembled record, but it
/// never invents routes, fences, budgets, or requirement texts.
pub struct PlanParts {
    /// Deterministic known-handle and exact-cue route identities.
    pub required_exact_routes: Vec<ArtifactId>,
    /// Typed optional route kinds selected for this retrieval.
    pub optional_routes: Vec<RetrievalRouteKind>,
    /// Route order or parallelism with its planning reason.
    pub execution: RouteExecution,
    /// Source owners with their projection fences.
    pub source_projection_fences: Vec<SourceProjectionFence>,
    /// Optional bounded campaign-experience query parts.
    pub campaign_experience_query: Option<CampaignQueryParts>,
    /// Coverage and negative-claim requirements text.
    pub coverage_and_negative_claims: String,
    /// Budget and stop-condition text.
    pub budget_and_stop_conditions: String,
    /// Fallback or abstention text.
    pub fallback_or_abstention: String,
}

/// Explicit caller-owned parts of one campaign-experience query.
pub struct CampaignQueryParts {
    /// Campaign or task-family scope the query is confined to.
    pub scope: String,
    /// What the query is for; `NONE` outside the applicable scope.
    pub intent: CampaignIntent,
    /// Exact handles the query is confined to.
    pub handles: Vec<ArtifactId>,
    /// Additional exact-handle filters text.
    pub filters: String,
    /// Artifact, step, tool, error, and metric predicates text.
    pub predicates: String,
    /// Temporal and lineage range text.
    pub temporal_and_lineage_range: String,
    /// How the selected slice is returned.
    pub output_mode: CampaignOutputMode,
    /// Token, byte, and time budgets.
    pub budgets: CampaignBudgets,
    /// Disclosure, retention, and hidden-reasoning fence.
    pub fence: StateFence,
}

/// Compile explicit factors into a validated canonical retrieval plan.
///
/// Orders route, fence, and handle sets deterministically (sorted by their
/// canonical identities), assembles the record, and validates the complete
/// closure fail-closed. Duplicate members are NOT silently collapsed: the
/// subsequent validation rejects them so caller policy errors stay visible.
pub fn compile_retrieval_plan(parts: PlanParts) -> Result<RetrievalPlan, ContextError> {
    let mut required_exact_routes = parts.required_exact_routes;
    required_exact_routes.sort();
    let mut optional_routes = parts.optional_routes;
    optional_routes.sort();
    let mut source_projection_fences = parts.source_projection_fences;
    source_projection_fences.sort_by(|left, right| left.source.cmp(&right.source));
    let campaign_experience_query = parts.campaign_experience_query.map(|query| {
        let mut handles = query.handles;
        handles.sort();
        CampaignExperienceQuery {
            scope: query.scope,
            intent: query.intent,
            handles,
            filters: query.filters,
            predicates: query.predicates,
            temporal_and_lineage_range: query.temporal_and_lineage_range,
            output_mode: query.output_mode,
            budgets: query.budgets,
            fence: query.fence,
        }
    });
    let plan = RetrievalPlan {
        required_exact_routes,
        optional_routes,
        execution: parts.execution,
        source_projection_fences,
        campaign_experience_query,
        coverage_and_negative_claims: parts.coverage_and_negative_claims,
        budget_and_stop_conditions: parts.budget_and_stop_conditions,
        fallback_or_abstention: parts.fallback_or_abstention,
    };
    plan.validate()?;
    Ok(plan)
}
