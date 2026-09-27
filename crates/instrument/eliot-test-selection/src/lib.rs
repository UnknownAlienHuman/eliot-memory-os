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
/// Version of the frozen dev-fast selection semantics (issue #1802 step 3).
pub const FROZEN_SELECTION_VERSION: &str = "dev-fast-frozen-selection-v1";
/// Version of the persisted `TestSelectionReceipt` semantics (I18.6 step 9).
pub const SELECTION_RECEIPT_VERSION: &str = "eliot-test-selection-receipt-v1";

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

/// Minimal consumer view of the #1803 stored `ChangeImpactPlan`.
///
/// This is the small agreed interface between the impact-plan producer
/// (issue #1803, built over `BuildTestGraph::impact`) and the dev-fast
/// consumer (issue #1802 step 3): the plan revision, the exact candidate
/// it was computed for, the source graph commitments, and the conservative
/// impact answer. The consumer binds every selected/omitted stage and test
/// to this view; it never re-derives impact, duplicates the graph, or
/// selects by test-name substring. Field types are plain data so the view
/// carries no producer dependency; #1803's stored plan must supply every
/// field verbatim.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "each flag is an independent evidence dimension of the agreed #1803 consumer interface; grouping would break the plain-data shape"
)]
pub struct ChangeImpactPlanView {
    /// Stored plan revision supplied by the #1803 producer.
    pub plan_revision: String,
    /// Exact candidate the plan was computed for (base/candidate/diff
    /// identity from the producer).
    pub candidate: String,
    /// Source graph revision commitment the plan was computed from.
    pub graph_revision: String,
    /// Whether the source graph answer was current when the plan was made.
    pub graph_current: bool,
    /// Whether the source graph answer was complete when the plan was made.
    pub graph_complete: bool,
    /// Affected nodes from the conservative impact answer.
    pub affected_nodes: Vec<String>,
    /// Verifiers with exact complete coverage of affected targets.
    pub exact_verifiers: Vec<String>,
    /// Whether the impact answer carries unknown coverage.
    pub unknown_coverage: bool,
    /// Whether the impact answer requires a broader profile tier.
    pub required_broader_profile: bool,
    /// Stable digest binding the complete view.
    pub plan_digest: String,
}

impl ChangeImpactPlanView {
    /// Validates the view shape and its digest binding.
    pub fn validate(&self) -> Result<(), SelectionError> {
        text(&self.plan_revision, "plan_revision")?;
        text(&self.candidate, "candidate")?;
        text(&self.graph_revision, "graph_revision")?;
        for node in &self.affected_nodes {
            text(node, "affected_nodes")?;
        }
        for verifier in &self.exact_verifiers {
            text(verifier, "exact_verifiers")?;
        }
        let mut value = self.clone();
        value.plan_digest.clear();
        let computed = canonical_json_bytes(&value)
            .map(|bytes| sha256_hex(&bytes))
            .map_err(|error| SelectionError::Canonicalization(error.to_string()))?;
        if computed != self.plan_digest {
            return Err(SelectionError::Canonicalization(
                "impact plan digest does not bind plan contents".to_owned(),
            ));
        }
        Ok(())
    }

    /// Whether the underlying graph evidence is fresh enough to select from.
    pub fn evidence_fresh(&self) -> bool {
        self.graph_current && self.graph_complete && !self.unknown_coverage
    }
}

/// Why one discovered test was omitted from the frozen selection.
#[derive(
    Clone, Copy, Debug, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum OmissionCause {
    /// No impact coordinate reaches the test under fresh graph evidence.
    NoImpact,
    /// The test fell outside the admitted bounded selection budget.
    OverBudget,
    /// The test is ignored in the discovery inventory.
    Ignored,
    /// Unknown or stale graph evidence cannot establish coverage; the
    /// omission is explicit incomplete coverage, never a safe omission.
    UnknownCoverage,
}

/// One omitted discovered test with its exact reason.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OmittedTest {
    /// Omitted test identity (`package/binary/test`).
    pub test_id: String,
    /// Exact omission reason.
    pub reason: OmissionCause,
}

/// Disposition of one frozen dev-fast selection.
#[derive(Clone, Copy, Debug, Eq, Hash, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FrozenDisposition {
    /// Fresh exact evidence selected a runnable set.
    Ready,
    /// Fresh evidence selected nothing; the empty selection is exact.
    Empty,
    /// Unknown or stale graph evidence widened the bounded permitted tier.
    WidenedTier,
    /// Coverage cannot be established; the receipt records explicit
    /// incomplete coverage instead of a runnable selection.
    Incomplete,
}

/// One frozen selection bound to its impact plan and discovery snapshot.
///
/// The selection freezes before execution: source/configuration drift
/// requires a new linked plan (checked via
/// [`FrozenSelection::check_candidate`]), never mixing results from
/// different candidates. Unknown or stale graph evidence widens a bounded
/// permitted tier or yields [`FrozenDisposition::Incomplete`]; it never
/// proves a safe omission.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FrozenSelection {
    /// Frozen selection identity.
    pub selection_id: String,
    /// Frozen selection semantics version.
    pub frozen_version: String,
    /// Digest of the consumed [`ChangeImpactPlanView`].
    pub plan_digest: String,
    /// Candidate the selection is frozen for.
    pub candidate: String,
    /// Discovery snapshot digest the selection was frozen against.
    pub discovery_digest: String,
    /// Number of discovered tests in the snapshot.
    pub discovered_count: u64,
    /// Frozen disposition.
    pub disposition: FrozenDisposition,
    /// Selected tests with reasons, in dispatch order.
    pub selected: Vec<SelectedTest>,
    /// Omitted discovered tests with exact reasons.
    pub omitted: Vec<OmittedTest>,
    /// Total cost charged to the budget.
    pub total_cost: u32,
    /// Stable digest binding the complete frozen selection.
    pub frozen_digest: String,
}

impl FrozenSelection {
    /// Validates the frozen selection shape and its digest binding.
    pub fn validate(&self) -> Result<(), SelectionError> {
        text(&self.selection_id, "selection_id")?;
        text(&self.frozen_version, "frozen_version")?;
        text(&self.plan_digest, "plan_digest")?;
        text(&self.candidate, "candidate")?;
        text(&self.discovery_digest, "discovery_digest")?;
        let mut value = self.clone();
        value.frozen_digest.clear();
        let computed = canonical_json_bytes(&value)
            .map(|bytes| sha256_hex(&bytes))
            .map_err(|error| SelectionError::Canonicalization(error.to_string()))?;
        if computed != self.frozen_digest {
            return Err(SelectionError::Canonicalization(
                "frozen digest does not bind frozen selection contents".to_owned(),
            ));
        }
        Ok(())
    }

    /// Refuses a selection frozen for a different candidate.
    ///
    /// Source/configuration drift requires a new linked plan; results from
    /// different candidates are never mixed under one frozen selection.
    pub fn check_candidate(&self, candidate: &str) -> Result<(), SelectionError> {
        if self.candidate != candidate {
            return Err(SelectionError::InvalidGraph(format!(
                "frozen selection is bound to candidate '{}', not '{candidate}'",
                self.candidate,
            )));
        }
        Ok(())
    }
}

/// One discovered test identity supplied to the freezer.
///
/// This mirrors the nextest owner's normalized discovery identity without
/// depending on it: the freezer joins caller-supplied discovery rows
/// against the impact plan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DiscoveredRow {
    /// Canonical `package/binary/test` identity.
    pub test_id: String,
    /// Cargo package owning the test.
    pub package: String,
    /// Source path carrying the test, when known.
    pub path: String,
    /// Whether the test is ignored in the discovery inventory.
    pub ignored: bool,
    /// Relative execution cost used for bounded planning.
    pub estimated_cost: u32,
}

/// Freezes one dev-fast selection over discovery joined to the impact plan.
///
/// Exact consumer edges (an affected node naming the test package, or an
/// exact verifier covering it) select their required checks. Unknown or
/// stale graph evidence never proves a safe omission: when the impact
/// answer requires a broader tier and the budget admits it, the bounded
/// permitted tier widens to the affected packages; otherwise the freeze
/// yields [`FrozenDisposition::Incomplete`] with every discovered test
/// explicitly omitted. Ignored tests are omitted with their exact cause.
/// The freeze is deterministic: identical inputs always yield the identical
/// frozen selection.
pub fn freeze_selection(
    selection_id: &str,
    plan: &ChangeImpactPlanView,
    discovery_digest: &str,
    discovered: &[DiscoveredRow],
    budget: SelectionBudget,
) -> Result<FrozenSelection, SelectionError> {
    text(selection_id, "selection_id")?;
    text(discovery_digest, "discovery_digest")?;
    plan.validate()?;
    budget.validate()?;
    let mut seen = BTreeSet::new();
    for row in discovered {
        text(&row.test_id, "test_id")?;
        text(&row.package, "package")?;
        if row.estimated_cost == 0 {
            return Err(SelectionError::InvalidLimit {
                field: "estimated_cost",
            });
        }
        if !seen.insert(row.test_id.clone()) {
            return Err(SelectionError::DuplicateTest(row.test_id.clone()));
        }
    }
    let mut rows: Vec<&DiscoveredRow> = discovered.iter().collect();
    rows.sort_by(|left, right| left.test_id.cmp(&right.test_id));
    let (selected, omitted, total_cost) = if plan.evidence_fresh() {
        collect_frozen_rows(
            &rows,
            budget,
            SelectionReason::ExactCoordinate,
            100,
            |row| {
                plan.affected_nodes
                    .iter()
                    .any(|node| node == &row.package || node == &row.test_id)
                    || plan
                        .exact_verifiers
                        .iter()
                        .any(|verifier| verifier == &row.package || verifier == &row.test_id)
            },
        )
    } else if plan.required_broader_profile {
        collect_frozen_rows(&rows, budget, SelectionReason::ScopeCoordinate, 70, |row| {
            plan.affected_nodes
                .iter()
                .any(|node| node == &row.package || node == &row.test_id)
        })
    } else {
        let omitted = rows
            .iter()
            .map(|row| OmittedTest {
                test_id: row.test_id.clone(),
                reason: OmissionCause::UnknownCoverage,
            })
            .collect();
        (Vec::new(), omitted, 0)
    };
    let disposition = if plan.evidence_fresh() {
        if selected.is_empty() {
            FrozenDisposition::Empty
        } else {
            FrozenDisposition::Ready
        }
    } else if plan.required_broader_profile {
        FrozenDisposition::WidenedTier
    } else {
        FrozenDisposition::Incomplete
    };
    let mut frozen = FrozenSelection {
        selection_id: selection_id.to_owned(),
        frozen_version: FROZEN_SELECTION_VERSION.to_owned(),
        plan_digest: plan.plan_digest.clone(),
        candidate: plan.candidate.clone(),
        discovery_digest: discovery_digest.to_owned(),
        discovered_count: u64::try_from(discovered.len()).unwrap_or(u64::MAX),
        disposition,
        selected,
        omitted,
        total_cost,
        frozen_digest: String::new(),
    };
    let mut digest_value = frozen.clone();
    digest_value.frozen_digest.clear();
    frozen.frozen_digest = canonical_json_bytes(&digest_value)
        .map(|bytes| sha256_hex(&bytes))
        .map_err(|error| SelectionError::Canonicalization(error.to_string()))?;
    Ok(frozen)
}

/// Collects one runnable frozen row set over sorted discovery rows.
///
/// Rows the `impacted` predicate rejects are omitted with their exact
/// cause; ignored rows keep their own cause; budget overflow omits with
/// its own cause. Collection order follows the sorted input, so
/// identical inputs always yield the identical selection.
fn collect_frozen_rows(
    rows: &[&DiscoveredRow],
    budget: SelectionBudget,
    reason: SelectionReason,
    impact_score: u16,
    impacted: impl Fn(&DiscoveredRow) -> bool,
) -> (Vec<SelectedTest>, Vec<OmittedTest>, u32) {
    let mut selected = Vec::new();
    let mut omitted = Vec::new();
    let mut total_cost = 0_u32;
    let max_tests = usize::try_from(budget.max_tests).unwrap_or(usize::MAX);
    for row in rows {
        if row.ignored {
            omitted.push(OmittedTest {
                test_id: row.test_id.clone(),
                reason: OmissionCause::Ignored,
            });
            continue;
        }
        if !impacted(row) {
            omitted.push(OmittedTest {
                test_id: row.test_id.clone(),
                reason: OmissionCause::NoImpact,
            });
            continue;
        }
        if selected.len() >= max_tests
            || total_cost.saturating_add(row.estimated_cost) > budget.max_cost
        {
            omitted.push(OmittedTest {
                test_id: row.test_id.clone(),
                reason: OmissionCause::OverBudget,
            });
            continue;
        }
        total_cost = total_cost.saturating_add(row.estimated_cost);
        selected.push(SelectedTest {
            test_id: row.test_id.clone(),
            package: row.package.clone(),
            path: row.path.clone(),
            reason,
            impact_score,
            estimated_cost: row.estimated_cost,
            instrument_kind: InstrumentKind::Test,
        });
    }
    (selected, omitted, total_cost)
}

/// Canonical `TestSelectionReceipt` persisted with one
/// `VerificationProfileRun` (I18.6 step 9).
///
/// The receipt binds candidate/profile revision, the discovery snapshot,
/// selected and omitted tests/stages with reasons, impact evidence and
/// unknown coverage, expected/executed counts, resource groups and
/// cache/target identity, and the raw retained outputs. It makes
/// false-negative selection auditable and allows replay after an escaped
/// regression.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TestSelectionReceipt {
    /// Receipt semantics version.
    pub receipt_version: String,
    /// Candidate the receipt is bound to.
    pub candidate: String,
    /// Admitted profile name.
    pub profile: String,
    /// Exact admitted profile revision.
    pub profile_revision: u64,
    /// Profile definition digest.
    pub profile_digest: String,
    /// Stage DAG digest.
    pub dag_digest: String,
    /// Digest of the consumed impact plan view.
    pub plan_digest: String,
    /// Digest of the frozen selection.
    pub frozen_digest: String,
    /// Frozen disposition (`READY`, `EMPTY`, `WIDENED_TIER`, `INCOMPLETE`).
    pub disposition: FrozenDisposition,
    /// Discovery snapshot digest.
    pub discovery_digest: String,
    /// Number of discovered tests in the snapshot.
    pub discovered_count: u64,
    /// Selected tests with reasons.
    pub selected: Vec<SelectedTest>,
    /// Omitted tests with exact reasons.
    pub omitted: Vec<OmittedTest>,
    /// Selected stages with reasons (`stage_id`, reason).
    pub selected_stages: Vec<(String, String)>,
    /// Omitted stages with exact reasons (`stage_id`, reason).
    pub omitted_stages: Vec<(String, String)>,
    /// Whether the impact evidence carries unknown coverage.
    pub unknown_coverage: bool,
    /// Impact gaps recorded as explicit incomplete coverage.
    pub impact_gaps: Vec<String>,
    /// Expected test executions from the frozen selection.
    pub expected_count: u64,
    /// Executed test catalog identities observed at runtime.
    pub executed_count: u64,
    /// Resource groups the selection was scheduled under.
    pub resource_groups: Vec<String>,
    /// Target/cache identity (`workspace/worktree/class` plus roots digest).
    pub target_identity: String,
    /// Raw retained output references bound to the receipt.
    pub raw_refs: Vec<String>,
    /// Stable digest binding the complete receipt.
    pub receipt_digest: String,
}

impl TestSelectionReceipt {
    /// Assembles one receipt over a frozen selection and observed counts.
    ///
    /// Expected executions come from the frozen selection; executed counts
    /// and raw references come from runtime observation. Unknown impact
    /// yields explicit [`FrozenDisposition::Incomplete`] coverage, never a
    /// runnable claim.
    #[allow(clippy::too_many_arguments)]
    pub fn assemble(
        candidate: String,
        profile: String,
        profile_revision: u64,
        profile_digest: String,
        dag_digest: String,
        frozen: &FrozenSelection,
        selected_stages: Vec<(String, String)>,
        omitted_stages: Vec<(String, String)>,
        unknown_coverage: bool,
        impact_gaps: Vec<String>,
        executed_count: u64,
        resource_groups: Vec<String>,
        target_identity: String,
        raw_refs: Vec<String>,
    ) -> Result<Self, SelectionError> {
        text(&candidate, "candidate")?;
        text(&profile, "profile")?;
        text(&profile_digest, "profile_digest")?;
        text(&dag_digest, "dag_digest")?;
        text(&target_identity, "target_identity")?;
        frozen.validate()?;
        frozen.check_candidate(&candidate)?;
        if profile_revision == 0 {
            return Err(SelectionError::InvalidLimit {
                field: "profile_revision",
            });
        }
        let mut receipt = Self {
            receipt_version: SELECTION_RECEIPT_VERSION.to_owned(),
            candidate,
            profile,
            profile_revision,
            profile_digest,
            dag_digest,
            plan_digest: frozen.plan_digest.clone(),
            frozen_digest: frozen.frozen_digest.clone(),
            disposition: frozen.disposition,
            discovery_digest: frozen.discovery_digest.clone(),
            discovered_count: frozen.discovered_count,
            selected: frozen.selected.clone(),
            omitted: frozen.omitted.clone(),
            selected_stages,
            omitted_stages,
            unknown_coverage,
            impact_gaps,
            expected_count: u64::try_from(frozen.selected.len()).unwrap_or(u64::MAX),
            executed_count,
            resource_groups,
            target_identity,
            raw_refs,
            receipt_digest: String::new(),
        };
        let mut digest_value = receipt.clone();
        digest_value.receipt_digest.clear();
        receipt.receipt_digest = canonical_json_bytes(&digest_value)
            .map(|bytes| sha256_hex(&bytes))
            .map_err(|error| SelectionError::Canonicalization(error.to_string()))?;
        Ok(receipt)
    }

    /// Validates the receipt shape and its digest binding.
    pub fn validate(&self) -> Result<(), SelectionError> {
        text(&self.receipt_version, "receipt_version")?;
        text(&self.candidate, "candidate")?;
        text(&self.profile, "profile")?;
        text(&self.profile_digest, "profile_digest")?;
        text(&self.dag_digest, "dag_digest")?;
        text(&self.plan_digest, "plan_digest")?;
        text(&self.frozen_digest, "frozen_digest")?;
        text(&self.discovery_digest, "discovery_digest")?;
        text(&self.target_identity, "target_identity")?;
        if self.profile_revision == 0 {
            return Err(SelectionError::InvalidLimit {
                field: "profile_revision",
            });
        }
        let mut value = self.clone();
        value.receipt_digest.clear();
        let computed = canonical_json_bytes(&value)
            .map(|bytes| sha256_hex(&bytes))
            .map_err(|error| SelectionError::Canonicalization(error.to_string()))?;
        if computed != self.receipt_digest {
            return Err(SelectionError::Canonicalization(
                "receipt digest does not bind receipt contents".to_owned(),
            ));
        }
        Ok(())
    }
}
