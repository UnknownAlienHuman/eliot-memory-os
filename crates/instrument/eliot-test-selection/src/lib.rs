//! Conservative, deterministic test selection from a source-impact projection.
//!
//! The planner is deliberately a consumer of graph and instrument contracts. It
//! never infers impact from file names or model rationale, and it never turns a
//! stale, partial, or unavailable graph answer into a runnable test command.

#![forbid(unsafe_code)]

use std::collections::BTreeSet;

use eliot_contracts::{canonical_json_bytes, sha256_hex};
use eliot_graph_api::{
    CoordinateKind, GraphCoordinate, GraphCoverage, GraphFreshness, GraphQueryResult,
    GraphQueryStatus,
};
use eliot_instrument_api::InstrumentKind;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Stable identity of this planner surface.
pub const TEST_SELECTION_INSTRUMENT: &str = "eliot.instrument.test-selection";
/// Version of the serialized plan semantics.
pub const PLANNER_VERSION: &str = "impact-test-selection-v1";

/// Failures which prevent a selection request from being admitted.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum SelectionError {
    /// A required identifier or path is invalid.
    #[error("{field} must be non-blank and free of control characters")]
    InvalidText { field: &'static str },
    /// A numeric limit cannot be zero.
    #[error("{field} must be non-zero")]
    InvalidLimit { field: &'static str },
    /// A test identity occurred more than once.
    #[error("duplicate test identity: {0}")]
    DuplicateTest(String),
    /// A graph result did not satisfy its own contract.
    #[error("invalid impact graph result: {0}")]
    InvalidGraph(String),
    /// The request could not be canonicalized for its plan digest.
    #[error("selection canonicalization failed: {0}")]
    Canonicalization(String),
}

fn text(value: &str, field: &'static str) -> Result<(), SelectionError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        Err(SelectionError::InvalidText { field })
    } else {
        Ok(())
    }
}

/// A test target and the graph coordinates it exercises.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TestTarget {
    /// Stable test identity, normally the fully qualified test name.
    pub test_id: String,
    /// Package containing the test.
    pub package: String,
    /// Source path containing the test declaration.
    pub path: String,
    /// Graph symbols/files/packages covered by this test.
    pub impact_coordinates: Vec<GraphCoordinate>,
    /// Whether this test is a release or safety critical guard.
    pub critical: bool,
    /// Relative execution cost used for bounded planning.
    pub estimated_cost: u32,
}

impl TestTarget {
    /// Validates identity and graph anchors without checking repository state.
    pub fn validate(&self) -> Result<(), SelectionError> {
        text(&self.test_id, "test_id")?;
        text(&self.package, "package")?;
        text(&self.path, "path")?;
        if self.estimated_cost == 0 {
            return Err(SelectionError::InvalidLimit {
                field: "estimated_cost",
            });
        }
        if self.impact_coordinates.is_empty() {
            return Err(SelectionError::InvalidText {
                field: "impact_coordinates",
            });
        }
        for coordinate in &self.impact_coordinates {
            coordinate
                .validate()
                .map_err(|error| SelectionError::InvalidGraph(error.to_string()))?;
        }
        Ok(())
    }
}

/// Limits applied while constructing a runnable selection.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SelectionBudget {
    /// Maximum number of selected tests.
    pub max_tests: u32,
    /// Maximum sum of target estimates.
    pub max_cost: u32,
}

impl SelectionBudget {
    fn validate(self) -> Result<(), SelectionError> {
        if self.max_tests == 0 {
            return Err(SelectionError::InvalidLimit { field: "max_tests" });
        }
        if self.max_cost == 0 {
            return Err(SelectionError::InvalidLimit { field: "max_cost" });
        }
        Ok(())
    }
}

/// Input to the impact-based planner.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SelectionRequest {
    /// Stable identity for this planning operation.
    pub selection_id: String,
    /// Workspace or task scope used to fence the graph result.
    pub scope: String,
    /// Graph impact projection for the changed source.
    pub impact: GraphQueryResult,
    /// Catalog of tests available in the same scope.
    pub tests: Vec<TestTarget>,
    /// Bounded execution allowance.
    pub budget: SelectionBudget,
}

impl SelectionRequest {
    /// Validates all input contracts before planning.
    pub fn validate(&self) -> Result<(), SelectionError> {
        text(&self.selection_id, "selection_id")?;
        text(&self.scope, "scope")?;
        self.budget.validate()?;
        self.impact
            .validate()
            .map_err(|error| SelectionError::InvalidGraph(error.to_string()))?;
        let mut ids = BTreeSet::new();
        for test in &self.tests {
            test.validate()?;
            if !ids.insert(test.test_id.clone()) {
                return Err(SelectionError::DuplicateTest(test.test_id.clone()));
            }
        }
        Ok(())
    }
}

/// Why a candidate was admitted to the plan.
#[derive(
    Clone, Copy, Debug, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SelectionReason {
    /// An exact graph coordinate was covered by the test.
    ExactCoordinate,
    /// The test and impact share a source file or package boundary.
    ScopeCoordinate,
    /// No graph node was impacted in the declared scope.
    NoImpactedTests,
}

/// One selected target with its deterministic impact score.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SelectedTest {
    /// Selected test identity.
    pub test_id: String,
    /// Package containing the selected test.
    pub package: String,
    /// Test source path.
    pub path: String,
    /// Why the test was selected.
    pub reason: SelectionReason,
    /// Higher scores indicate stronger graph correspondence.
    pub impact_score: u16,
    /// Cost charged against the plan budget.
    pub estimated_cost: u32,
    /// The instrument kind this plan dispatches.
    pub instrument_kind: InstrumentKind,
}

/// Planner disposition, including safe fail-closed states.
#[derive(Clone, Copy, Debug, Eq, Hash, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SelectionDisposition {
    /// The graph was current and a runnable subset was produced.
    Ready,
    /// The graph was valid but no test had a matching impact anchor.
    Empty,
    /// The graph could not safely establish the affected scope.
    Blocked,
}

/// Immutable output of one bounded selection operation.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SelectionPlan {
    /// Selection operation identity.
    pub selection_id: String,
    /// Scope inherited from the request.
    pub scope: String,
    /// Planner semantics version.
    pub planner_version: String,
    /// Instrument kind for every selected item.
    pub instrument_kind: InstrumentKind,
    /// Safe disposition of this plan.
    pub disposition: SelectionDisposition,
    /// Selected tests in dispatch order.
    pub selected: Vec<SelectedTest>,
    /// Total cost charged to the budget.
    pub total_cost: u32,
    /// Graph revision that supplied the impact.
    pub graph_revision: u64,
    /// Stable digest of the complete plan.
    pub plan_digest: String,
}

impl SelectionPlan {
    /// Validates the plan's internal budget and digest binding.
    pub fn validate(&self) -> Result<(), SelectionError> {
        text(&self.selection_id, "selection_id")?;
        text(&self.scope, "scope")?;
        text(&self.planner_version, "planner_version")?;
        if self.graph_revision == 0 {
            return Err(SelectionError::InvalidLimit {
                field: "graph_revision",
            });
        }
        let computed = digest_without_digest(self)?;
        if computed != self.plan_digest {
            return Err(SelectionError::Canonicalization(
                "plan digest does not bind plan contents".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Builds a conservative, deterministic plan from a graph impact result.
pub fn plan_selection(request: &SelectionRequest) -> Result<SelectionPlan, SelectionError> {
    request.validate()?;
    let disposition = if matches!(
        request.impact.status,
        GraphQueryStatus::Found | GraphQueryStatus::NotFound
    ) && matches!(request.impact.freshness, GraphFreshness::Current)
        && matches!(request.impact.coverage, GraphCoverage::Complete)
    {
        SelectionDisposition::Ready
    } else {
        SelectionDisposition::Blocked
    };

    let mut selected = Vec::new();
    if matches!(disposition, SelectionDisposition::Ready)
        && !matches!(request.impact.status, GraphQueryStatus::NotFound)
    {
        let impacted = impacted_coordinates(&request.impact);
        let mut candidates = request
            .tests
            .iter()
            .filter_map(|test| best_match(test, &impacted))
            .collect::<Vec<_>>();
        candidates.sort_by(|left, right| {
            right
                .2
                .cmp(&left.2)
                .then_with(|| right.0.critical.cmp(&left.0.critical))
                .then_with(|| left.0.estimated_cost.cmp(&right.0.estimated_cost))
                .then_with(|| left.0.test_id.cmp(&right.0.test_id))
        });
        let mut total_cost = 0_u32;
        let max_tests = usize::try_from(request.budget.max_tests).unwrap_or(usize::MAX);
        for (test, reason, score) in candidates {
            if selected.len() >= max_tests
                || total_cost.saturating_add(test.estimated_cost) > request.budget.max_cost
            {
                continue;
            }
            total_cost = total_cost.saturating_add(test.estimated_cost);
            selected.push(SelectedTest {
                test_id: test.test_id.clone(),
                package: test.package.clone(),
                path: test.path.clone(),
                reason,
                impact_score: score,
                estimated_cost: test.estimated_cost,
                instrument_kind: InstrumentKind::Test,
            });
        }
    }
    let disposition = if matches!(disposition, SelectionDisposition::Ready) && selected.is_empty() {
        SelectionDisposition::Empty
    } else {
        disposition
    };
    let total_cost = selected.iter().map(|test| test.estimated_cost).sum();
    let mut plan = SelectionPlan {
        selection_id: request.selection_id.clone(),
        scope: request.scope.clone(),
        planner_version: PLANNER_VERSION.to_owned(),
        instrument_kind: InstrumentKind::Test,
        disposition,
        selected,
        total_cost,
        graph_revision: request.impact.revision.value(),
        plan_digest: String::new(),
    };
    plan.plan_digest = digest_without_digest(&plan)?;
    Ok(plan)
}

fn impacted_coordinates(result: &GraphQueryResult) -> BTreeSet<GraphCoordinate> {
    let mut coordinates = BTreeSet::new();
    coordinates.extend(result.nodes.iter().map(|node| node.coordinate.clone()));
    for edge in &result.edges {
        coordinates.insert(edge.from.clone());
        coordinates.insert(edge.to.clone());
    }
    coordinates
}

fn best_match<'a>(
    test: &'a TestTarget,
    impacted: &BTreeSet<GraphCoordinate>,
) -> Option<(&'a TestTarget, SelectionReason, u16)> {
    let mut best = None;
    for test_coordinate in &test.impact_coordinates {
        for impacted_coordinate in impacted {
            if let Some((reason, score)) = coordinate_match(test_coordinate, impacted_coordinate)
                && best.as_ref().is_none_or(|(_, _, current)| score > *current)
            {
                best = Some((test, reason, score));
            }
        }
    }
    best
}

fn coordinate_match(
    test: &GraphCoordinate,
    impacted: &GraphCoordinate,
) -> Option<(SelectionReason, u16)> {
    if test == impacted {
        return Some((SelectionReason::ExactCoordinate, 100));
    }
    if test.package != impacted.package {
        return None;
    }
    if impacted.kind == CoordinateKind::Package || test.kind == CoordinateKind::Package {
        return Some((SelectionReason::ScopeCoordinate, 70));
    }
    if test.path.is_some() && test.path == impacted.path {
        return Some((SelectionReason::ScopeCoordinate, 80));
    }
    None
}

fn digest_without_digest(plan: &SelectionPlan) -> Result<String, SelectionError> {
    let mut value = plan.clone();
    value.plan_digest.clear();
    canonical_json_bytes(&value)
        .map(|bytes| sha256_hex(&bytes))
        .map_err(|error| SelectionError::Canonicalization(error.to_string()))
}
