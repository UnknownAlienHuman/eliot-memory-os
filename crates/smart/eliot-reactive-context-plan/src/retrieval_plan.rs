//! Canonical retrieval plan record (I12.26).
//!
//! Candidate retrieval begins with deterministic known-handle lookup when a
//! handle is supplied; exact entity/path/symbol/error/task cues remain usable
//! even when every graph is empty. The remaining routes are compiled into a
//! [`RetrievalPlan`] from task, corpus, risk, freshness, coverage, latency,
//! and measured outcome/cost. There is no universal `lexical → dense → graph`
//! order: the plan names its required exact routes, typed optional routes,
//! order-or-parallelism with reason, source/projection fences, coverage and
//! negative-claim requirements, budgets, stop conditions, and
//! fallback/abstention. `campaign_experience_query` is optional and `NONE`
//! outside the applicable campaign/task-family scope; when present it selects
//! a bounded history slice from existing canonical owners without creating a
//! store, retaining hidden reasoning, or dumping full history.
//!
//! Shapes fully specified by I12.26 are typed (route kinds, campaign intent,
//! output mode, campaign budgets, fences). Requirements the contract names
//! without sub-shape (coverage/negative-claim requirements,
//! budget-and-stop conditions, fallback/abstention) are bounded requirement
//! text interpreted by the planning owner, not fabricated structure.

#![forbid(unsafe_code)]

use std::collections::BTreeSet;

use eliot_context_contracts::{ContextError, canonical_digest};
use eliot_contracts::{ArtifactId, SourceId, StateFence};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Maximum routes admitted across the required and optional route sets.
pub const MAX_PLAN_ROUTES: usize = 256;
/// Maximum campaign handles admitted in one experience query.
pub const MAX_PLAN_HANDLES: usize = 256;
/// Maximum Unicode scalar values admitted in one requirement text field.
pub const MAX_PLAN_TEXT_CHARS: usize = 1024;

/// Closed optional retrieval route kinds from I12.26.
#[derive(
    Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RetrievalRouteKind {
    TypedRelations,
    Lexical,
    Dense,
    Graph,
    Episode,
    Dreamer,
}

impl RetrievalRouteKind {
    /// Canonical wire value for this route kind.
    #[must_use]
    pub const fn as_wire_str(self) -> &'static str {
        match self {
            Self::TypedRelations => "TYPED_RELATIONS",
            Self::Lexical => "LEXICAL",
            Self::Dense => "DENSE",
            Self::Graph => "GRAPH",
            Self::Episode => "EPISODE",
            Self::Dreamer => "DREAMER",
        }
    }

    /// The exact six canonical wire values, in I12.26 contract order.
    #[must_use]
    pub const fn canonical_set() -> [&'static str; 6] {
        [
            "TYPED_RELATIONS",
            "LEXICAL",
            "DENSE",
            "GRAPH",
            "EPISODE",
            "DREAMER",
        ]
    }

    /// Resolve an exact canonical wire value to its route kind.
    ///
    /// Only the six [`Self::canonical_set`] spellings resolve; anything else
    /// returns `None` rather than coercing to a nearby route.
    #[must_use]
    pub fn from_wire_str(value: &str) -> Option<Self> {
        match value {
            "TYPED_RELATIONS" => Some(Self::TypedRelations),
            "LEXICAL" => Some(Self::Lexical),
            "DENSE" => Some(Self::Dense),
            "GRAPH" => Some(Self::Graph),
            "EPISODE" => Some(Self::Episode),
            "DREAMER" => Some(Self::Dreamer),
            _ => None,
        }
    }
}

/// Closed campaign-experience query intents from I12.26.
#[derive(
    Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CampaignIntent {
    None,
    FindSimilarFailure,
    CompareCandidates,
    TraceDecision,
    LocateInformationLoss,
    InspectToolLoop,
    FindRegression,
    FindPriorSuccess,
    InspectParentLineage,
    TestConfound,
    RetrieveRawSlice,
}

impl CampaignIntent {
    /// Canonical wire value for this intent.
    #[must_use]
    pub const fn as_wire_str(self) -> &'static str {
        match self {
            Self::None => "NONE",
            Self::FindSimilarFailure => "FIND_SIMILAR_FAILURE",
            Self::CompareCandidates => "COMPARE_CANDIDATES",
            Self::TraceDecision => "TRACE_DECISION",
            Self::LocateInformationLoss => "LOCATE_INFORMATION_LOSS",
            Self::InspectToolLoop => "INSPECT_TOOL_LOOP",
            Self::FindRegression => "FIND_REGRESSION",
            Self::FindPriorSuccess => "FIND_PRIOR_SUCCESS",
            Self::InspectParentLineage => "INSPECT_PARENT_LINEAGE",
            Self::TestConfound => "TEST_CONFOUND",
            Self::RetrieveRawSlice => "RETRIEVE_RAW_SLICE",
        }
    }

    /// The exact eleven canonical wire values, in I12.26 contract order.
    #[must_use]
    pub const fn canonical_set() -> [&'static str; 11] {
        [
            "NONE",
            "FIND_SIMILAR_FAILURE",
            "COMPARE_CANDIDATES",
            "TRACE_DECISION",
            "LOCATE_INFORMATION_LOSS",
            "INSPECT_TOOL_LOOP",
            "FIND_REGRESSION",
            "FIND_PRIOR_SUCCESS",
            "INSPECT_PARENT_LINEAGE",
            "TEST_CONFOUND",
            "RETRIEVE_RAW_SLICE",
        ]
    }

    /// Resolve an exact canonical wire value to its intent.
    ///
    /// Only the eleven [`Self::canonical_set`] spellings resolve; anything
    /// else returns `None` rather than coercing to a nearby intent.
    #[must_use]
    pub fn from_wire_str(value: &str) -> Option<Self> {
        match value {
            "NONE" => Some(Self::None),
            "FIND_SIMILAR_FAILURE" => Some(Self::FindSimilarFailure),
            "COMPARE_CANDIDATES" => Some(Self::CompareCandidates),
            "TRACE_DECISION" => Some(Self::TraceDecision),
            "LOCATE_INFORMATION_LOSS" => Some(Self::LocateInformationLoss),
            "INSPECT_TOOL_LOOP" => Some(Self::InspectToolLoop),
            "FIND_REGRESSION" => Some(Self::FindRegression),
            "FIND_PRIOR_SUCCESS" => Some(Self::FindPriorSuccess),
            "INSPECT_PARENT_LINEAGE" => Some(Self::InspectParentLineage),
            "TEST_CONFOUND" => Some(Self::TestConfound),
            "RETRIEVE_RAW_SLICE" => Some(Self::RetrieveRawSlice),
            _ => None,
        }
    }
}

/// Closed campaign-experience output modes from I12.26.
#[derive(
    Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CampaignOutputMode {
    Index,
    SummaryWithHandles,
    Diff,
    RawSlice,
    GraphNeighborhood,
}

impl CampaignOutputMode {
    /// Canonical wire value for this output mode.
    #[must_use]
    pub const fn as_wire_str(self) -> &'static str {
        match self {
            Self::Index => "INDEX",
            Self::SummaryWithHandles => "SUMMARY_WITH_HANDLES",
            Self::Diff => "DIFF",
            Self::RawSlice => "RAW_SLICE",
            Self::GraphNeighborhood => "GRAPH_NEIGHBORHOOD",
        }
    }

    /// The exact five canonical wire values, in I12.26 contract order.
    #[must_use]
    pub const fn canonical_set() -> [&'static str; 5] {
        [
            "INDEX",
            "SUMMARY_WITH_HANDLES",
            "DIFF",
            "RAW_SLICE",
            "GRAPH_NEIGHBORHOOD",
        ]
    }

    /// Resolve an exact canonical wire value to its output mode.
    ///
    /// Only the five [`Self::canonical_set`] spellings resolve; anything else
    /// returns `None` rather than coercing to a nearby mode.
    #[must_use]
    pub fn from_wire_str(value: &str) -> Option<Self> {
        match value {
            "INDEX" => Some(Self::Index),
            "SUMMARY_WITH_HANDLES" => Some(Self::SummaryWithHandles),
            "DIFF" => Some(Self::Diff),
            "RAW_SLICE" => Some(Self::RawSlice),
            "GRAPH_NEIGHBORHOOD" => Some(Self::GraphNeighborhood),
            _ => None,
        }
    }
}

/// Closed route execution order for one retrieval plan.
#[derive(
    Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RouteExecutionOrder {
    Sequential,
    Parallel,
}

/// Route order or parallelism with its planning reason.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RouteExecution {
    /// Whether routes run in sequence or in parallel.
    pub order: RouteExecutionOrder,
    /// Why this order serves the task, corpus, risk, and latency at hand.
    pub reason: String,
}

/// One source owner bound to the projection fence its reads must satisfy.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SourceProjectionFence {
    /// Stable source owner identity.
    pub source: SourceId,
    /// Projection fence every read from this source must satisfy.
    pub fence: StateFence,
}

/// Token, byte, and time budgets for one campaign-experience query.
///
/// Zero means unset by caller convention; the planning owner interprets the
/// triple, this record only carries it without policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CampaignBudgets {
    /// Maximum tokens the query may consume.
    pub max_tokens: u64,
    /// Maximum bytes the query may consume.
    pub max_bytes: u64,
    /// Maximum wall-clock milliseconds the query may consume.
    pub max_time_ms: u64,
}

/// Optional bounded campaign-experience query inside a retrieval plan.
///
/// Selects a bounded history slice from existing canonical attempt, memory,
/// artifact, journal, and Blob-handle owners. It creates no
/// `CampaignExperienceView` store, retains no hidden provider reasoning, and
/// authorizes no full-history dumping; every route stays under the same
/// admission, disclosure, retention, and proof ceilings.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CampaignExperienceQuery {
    /// Campaign or task-family scope the query is confined to.
    pub scope: String,
    /// What the query is for; `NONE` outside the applicable scope.
    pub intent: CampaignIntent,
    /// Exact handles the query is confined to.
    pub handles: Vec<ArtifactId>,
    /// Additional exact-handle filters, as bounded requirement text.
    pub filters: String,
    /// Artifact, step, tool, error, and metric predicates, as bounded text.
    pub predicates: String,
    /// Temporal and lineage range, as bounded requirement text.
    pub temporal_and_lineage_range: String,
    /// How the selected slice is returned.
    pub output_mode: CampaignOutputMode,
    /// Token, byte, and time budgets for the query.
    pub budgets: CampaignBudgets,
    /// Disclosure, retention, and hidden-reasoning fence for the query.
    pub fence: StateFence,
}

/// Canonical retrieval plan compiling task, corpus, risk, freshness,
/// coverage, latency, and measured outcome/cost into exact and typed routes.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RetrievalPlan {
    /// Deterministic known-handle and exact-cue routes that must run.
    pub required_exact_routes: Vec<ArtifactId>,
    /// Typed optional routes selected for this retrieval.
    pub optional_routes: Vec<RetrievalRouteKind>,
    /// Route order or parallelism with its planning reason.
    pub execution: RouteExecution,
    /// Source owners with the projection fences their reads must satisfy.
    pub source_projection_fences: Vec<SourceProjectionFence>,
    /// Optional bounded campaign-experience query.
    pub campaign_experience_query: Option<CampaignExperienceQuery>,
    /// Coverage and negative-claim requirements, as bounded text owned by
    /// the planning owner.
    pub coverage_and_negative_claims: String,
    /// Budgets and stop conditions, as bounded text owned by the planning
    /// owner.
    pub budget_and_stop_conditions: String,
    /// Fallback or abstention behavior, as bounded text owned by the planning
    /// owner.
    pub fallback_or_abstention: String,
}

fn validate_plan_text(value: &str, field: &'static str) -> Result<(), ContextError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(ContextError::InvalidField(field));
    }
    if value.chars().count() > MAX_PLAN_TEXT_CHARS {
        return Err(ContextError::Bounds { field });
    }
    Ok(())
}

impl CampaignExperienceQuery {
    /// Validate the complete query closure without retrieval or provider I/O.
    pub fn validate(&self) -> Result<(), ContextError> {
        validate_plan_text(&self.scope, "campaign_query.scope")?;
        validate_plan_text(&self.filters, "campaign_query.filters")?;
        validate_plan_text(&self.predicates, "campaign_query.predicates")?;
        validate_plan_text(
            &self.temporal_and_lineage_range,
            "campaign_query.temporal_and_lineage_range",
        )?;
        if self.handles.len() > MAX_PLAN_HANDLES {
            return Err(ContextError::Bounds {
                field: "campaign_query.handles",
            });
        }
        let mut seen = BTreeSet::new();
        for handle in &self.handles {
            if !seen.insert(handle.clone()) {
                return Err(ContextError::Duplicate("campaign_query.handles"));
            }
        }
        self.fence
            .validate()
            .map_err(|_| ContextError::InvalidFence)?;
        Ok(())
    }
}

impl RetrievalPlan {
    /// Validate the complete plan closure without retrieval or provider I/O.
    pub fn validate(&self) -> Result<(), ContextError> {
        if self.required_exact_routes.len() > MAX_PLAN_ROUTES
            || self.optional_routes.len() > MAX_PLAN_ROUTES
            || self.source_projection_fences.len() > MAX_PLAN_ROUTES
        {
            return Err(ContextError::Bounds {
                field: "retrieval_plan.routes",
            });
        }
        if self.required_exact_routes.is_empty() && self.optional_routes.is_empty() {
            return Err(ContextError::MissingField("retrieval_plan.routes"));
        }
        let mut routes = BTreeSet::new();
        for route in &self.required_exact_routes {
            if !routes.insert(route.clone()) {
                return Err(ContextError::Duplicate(
                    "retrieval_plan.required_exact_routes",
                ));
            }
        }
        let mut kinds = BTreeSet::new();
        for kind in &self.optional_routes {
            if !kinds.insert(*kind) {
                return Err(ContextError::Duplicate("retrieval_plan.optional_routes"));
            }
        }
        validate_plan_text(&self.execution.reason, "retrieval_plan.execution.reason")?;
        if self.source_projection_fences.is_empty() {
            return Err(ContextError::MissingField(
                "retrieval_plan.source_projection_fences",
            ));
        }
        let mut sources = BTreeSet::new();
        for entry in &self.source_projection_fences {
            if !sources.insert(entry.source.clone()) {
                return Err(ContextError::Duplicate(
                    "retrieval_plan.source_projection_fences",
                ));
            }
            entry
                .fence
                .validate()
                .map_err(|_| ContextError::InvalidFence)?;
        }
        if let Some(query) = &self.campaign_experience_query {
            query.validate()?;
        }
        validate_plan_text(
            &self.coverage_and_negative_claims,
            "retrieval_plan.coverage_and_negative_claims",
        )?;
        validate_plan_text(
            &self.budget_and_stop_conditions,
            "retrieval_plan.budget_and_stop_conditions",
        )?;
        validate_plan_text(
            &self.fallback_or_abstention,
            "retrieval_plan.fallback_or_abstention",
        )?;
        Ok(())
    }

    /// Compute the canonical digest identifying exactly this plan.
    pub fn canonical_digest(&self) -> Result<String, ContextError> {
        self.validate()?;
        canonical_digest(self)
    }
}
