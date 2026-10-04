//! Capability-based staffing policy for `eliotd` (issue #1963).
//!
//! Architecture: I3.6 places `ModelRolePolicy` plus per-task plan receipts in
//! the Governor application; I3.4 owns the capability/route evidence view this
//! policy consumes. This module is the Governor-application decision policy:
//! human-selected assurance/cost intent (one of five built-in presets), never
//! a permanent provider allocation. Actual lanes/routes are selected from
//! current capability evidence, quota/capacity, privacy, and independence
//! inputs threaded per call. There is no static provider percentage anywhere
//! in this type: the struct has no provider field by construction.
//!
//! Actual routes are selected from current capability evidence, observed task
//! outcomes ([`RouteOutcomeEvidence`]), quotas, machine capacity, privacy and
//! independence. An outcome profile is a derived empirical profile (I3.4): it
//! can only keep a route whose own equal-stack samples failed out of the
//! selection, it never admits a route, widens an envelope, or authorizes an
//! action, a sparse or stale profile carries no signal at all, and every
//! consulted profile is recorded in the receipt so aggregated success cannot
//! hide the counts it was derived from.
//!
//! Pure and deterministic: no threads, no store, no provider execution, no
//! credential handling. The planner returns a candidate receipt plus explicit
//! dispositions; it persists nothing itself. A required-but-unstaffed audit
//! class yields an escalate disposition, policy-declared non-executing
//! Dreamer classes yield defer dispositions, and a missing writer is a typed
//! [`StaffingPolicyError::NoWriterRoute`] rather than a silent substitution.
//! An independent audit is staffed only when the frozen request materializes a
//! distinct audit lane: a receipt lane no compiled lane and no attempt could
//! ever run would read as satisfied review while nothing reviews anything, so
//! the unstaffable class is escalated explicitly instead.
//! A caller cannot widen the selected policy through supplied constraints:
//! the constraints budget must sit within the policy per-job budget and a
//! local-only privacy ceiling closes external lanes fail-closed. Provider
//! switching mid-attempt is denied unless an explicit receipted
//! policy-authorized degradation binds the continuation before it proceeds.
//!
//! The Governor caller persists the returned candidate;
//! [`verify_receipt_digest`] rebinds the digest at that boundary, and
//! [`enforce_plan_receipt`] re-checks it there.
//!
//! [`plan_coordinator_staffing`] is the checked, lossless bridge from the live
//! `eliotd` coordinator request ([`StaffingPlanRequest`]) onto
//! [`plan_staffing`]. It is not a second planner: it only translates the live
//! request's own route candidates, quota/capacity evidence, privacy class and
//! budgets into the policy planner's inputs, and the receipt it returns is the
//! single authority on which routes a plan may use.
//! [`enforce_plan_receipt`] is the matching check on the compiled coordinator
//! candidate: a lane route the receipt did not authorize — including a
//! same-family or paid substitute for an unavailable independent audit — is
//! refused instead of dispatched, and every receipted route must actually be run
//! by exactly one compiled lane.
//!
//! A route is placed in a class only where the route owner, recipe, role, and
//! launch all name that exact class. Human preset/cost intent and route-owner
//! class/privacy evidence are explicit request inputs, preserved in the
//! canonical plan receipt, and never reconstructed from recipe shape, route
//! identity, or a local default. [`route_outcome_evidence`] reads the
//! Governor's own retained outcome profiles for exactly that reason: the
//! behaviour identity those profiles are keyed under is owner-issued, and this
//! policy derives no behaviour fingerprint from a route fingerprint.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use eliot_agent_api::{BudgetEnvelope, LowercaseSha256, RouteFingerprint};
use eliot_agent_coordinator::{
    CoordinatorConfig, RouteCandidateEvidence, StaffingLaneRequest, StaffingPlanCandidate,
    StaffingPlanRequest,
};
use eliot_governor::{RouteBehaviorFingerprint, RouteOutcomeProfileIndex};
use eliot_security_contracts::PrivacyClass;
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub use eliot_agent_coordinator::StaffingPreset;

/// Canonical I3.6 route classes staffed by this policy.
pub const ROUTE_CLASS_BULK_IMPLEMENTATION: &str = "bulk_implementation";
pub const ROUTE_CLASS_ARCHITECTURE_REASONING: &str = "architecture_reasoning";
pub const ROUTE_CLASS_INDEPENDENT_BLIND_AUDIT: &str = "independent_blind_audit";
pub const ROUTE_CLASS_FAST_READ_ONLY_SCOUT: &str = "fast_read_only_scout";
pub const ROUTE_CLASS_WATCHDOG_DIAGNOSTIC: &str = "watchdog_diagnostic";
pub const ROUTE_CLASS_DREAMER_CURATION: &str = "dreamer_curation";
pub const ROUTE_CLASS_DREAMER_ORIENTATION: &str = "dreamer_orientation";
pub const ROUTE_CLASS_RESEARCH_SYNTHESIS: &str = "research_synthesis";
pub const ROUTE_CLASS_SUBJECTIVE_EVALUATION: &str = "subjective_evaluation";

/// Reason recorded on an independent-audit class the frozen request cannot run.
///
/// I3.6 makes independent review a real second lane, and the coordinator
/// compiles exactly one candidate lane per request lane, so a request that binds
/// the audit class only to the writer's own lane can never dispatch a reviewer.
/// The receipt says so and escalates; it never staffs an entry that reads as
/// satisfied review while nothing reviews anything.
pub const UNAUDITABLE_REVIEW_REASON: &str = "independent audit cannot be staffed: the frozen request admits no lane that runs the audit apart from the writer's own lane; escalating instead of recording a lane nothing would dispatch";

/// Independence requirements for review staffing.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IndependentReviewRequirements {
    /// Whether an independent review lane is required for the task class.
    pub required: bool,
    /// Whether the audit must be blind to the writer route identity.
    pub blind: bool,
    /// Whether the audit must come from a different family/lineage than the
    /// writer. Same-family substitution never satisfies this requirement.
    pub cross_family: bool,
}

/// Typed `ModelRolePolicy` (I3.6 shape). Role route classes, independence,
/// data-class limits, budgets/quota windows, lane/writer/swarm limits, launch
/// rules, approvals, and preview policy. No provider allocation field exists:
///
/// ```text
/// main/worker/auditor/verifier/watchdog/dreamer route classes;
/// independence requirements; local-only vs external-allowed data classes;
/// per-job budgets; quota windows; lane/writer/swarm limits;
/// native-child policy; auto-launch classes; approval classes; preview policy.
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelRolePolicy {
    pub preset: StaffingPreset,
    pub main_agent_route_classes: Vec<String>,
    pub worker_route_classes: Vec<String>,
    pub auditor_route_classes: Vec<String>,
    pub verifier_model_route_classes: Vec<String>,
    pub watchdog_route_classes: Vec<String>,
    pub dreamer_route_classes: Vec<String>,
    pub independent_review_requirements: IndependentReviewRequirements,
    pub local_only_data_classes: Vec<String>,
    pub external_allowed_data_classes: Vec<String>,
    pub per_job_budget: BudgetEnvelope,
    pub active_quota_windows: Vec<String>,
    pub max_active_lanes: u16,
    pub max_writers_per_deliverable: u16,
    pub max_swarm_fanout: u16,
    pub max_swarm_depth: u16,
    pub native_child_policy: String,
    pub auto_launch_job_classes: Vec<String>,
    pub human_approval_classes: Vec<String>,
    pub preview_beta_policy: String,
}

/// Current capability evidence for one route class (I3.4 view consumed here,
/// never minted here). Availability joins route intent with liveness,
/// quota/capacity, privacy, and independence inputs.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteClassEvidence {
    /// I3.6 route class this evidence covers.
    pub route_class: String,
    /// Candidate routes offering this class, in caller preference order.
    pub candidates: Vec<RouteCandidate>,
    /// Evidence handles (capability records, outcome profiles, quota reads).
    pub evidence_refs: Vec<String>,
}

/// Quota/capacity/privacy admission for one candidate route. The three
/// dimensions are checked together before any ranking; grouping them keeps
/// the economic `paid` property of [`RouteCandidate`] distinct from current
/// admission.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteEligibility {
    /// Current quota-window admission for this route.
    pub quota_admits: bool,
    /// Current machine-capacity admission for this route.
    pub capacity_admits: bool,
    /// Whether this route admits the task privacy class.
    pub privacy_admits: bool,
}

/// Minimum observed sample count before an outcome profile may move a route.
///
/// I3.4 keeps routing on policy defaults and controlled pilots "before enough
/// equal-stack evidence exists", and the profile index is keyed by the complete
/// effective route key, so the samples behind one profile are equal-stack by
/// construction. Below this count the profile is too sparse to move anything
/// and carries no signal: it is recorded in the receipt and otherwise ignored.
pub const MIN_ROUTE_OUTCOME_SAMPLES: u32 = 3;

/// One route's derived empirical outcome profile as this policy consumes it
/// (I3.4 "Route outcome profile").
///
/// A profile, never a capability and never a proof by itself. It is carried as
/// named sample counts plus the evidence that produced them rather than as an
/// aggregate score, because a number without its counts would let aggregated
/// success hide a minority failure. The only decision it can drive is negative:
/// a route whose own observed samples for this task class produced nothing
/// verified while at least one sample failed or stayed unknown is kept out of
/// the selection when another eligible route exists. It can never admit a
/// route, promote one over another, widen an envelope, or authorize an action.
///
/// `stale` marks a profile whose own declared stale dependencies (fingerprint,
/// evaluator, task distribution, or behavior-affecting harness) moved. A stale
/// profile carries no signal: it is neither read as success nor as failure.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteOutcomeEvidence {
    /// Samples whose output was verified complete.
    pub verified_complete: u32,
    /// Samples that finished with a partial result.
    pub partial: u32,
    /// Samples that failed.
    pub failed: u32,
    /// Samples whose outcome was never established. A real count, not an
    /// absence: an unreconciled sample must stay visible.
    pub unknown: u32,
    /// Whether the profile's declared stale dependencies moved.
    pub stale: bool,
    /// Evidence references backing the profile. Must be non-empty: a profile
    /// with no evidence proves nothing and is refused rather than consumed.
    pub evidence_refs: Vec<String>,
}

impl RouteOutcomeEvidence {
    /// Total observed samples behind this profile.
    fn samples(&self) -> u32 {
        self.verified_complete
            .saturating_add(self.partial)
            .saturating_add(self.failed)
            .saturating_add(self.unknown)
    }

    /// Whether this profile keeps its route out of the selection.
    ///
    /// Negative-only by construction: success never promotes a route (so
    /// aggregated success cannot authorize anything) and a profile that observed
    /// at least one verified-complete sample never hides that route's minority
    /// failures. Only a route whose own equal-stack samples produced nothing
    /// verified while at least one sample failed or stayed unknown is skipped.
    fn blocks_selection(&self) -> bool {
        if self.stale || self.samples() < MIN_ROUTE_OUTCOME_SAMPLES || self.verified_complete > 0 {
            return false;
        }
        self.failed > 0 || self.unknown > 0
    }
}

/// One consulted outcome profile, bound to the exact route it was observed on.
///
/// Recorded for every candidate route the plan considered, not only the staffed
/// ones, so the receipt shows which empirical input the selection stood on — and
/// shows the ones that were refused.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteOutcomeRecord {
    pub route: RouteFingerprint,
    pub profile: RouteOutcomeEvidence,
}

/// Owner-issued binding from one coordinator route to the behaviour identity its
/// outcome profiles are recorded under, plus whether that binding is current.
///
/// The profile index is keyed by the complete effective route key over the
/// Governor's `RouteBehaviorFingerprint`, a behaviour identity with facets the
/// coordinator's `RouteFingerprint` does not carry (adapter and runtime
/// versions, protocol and transport kinds, account mode, execution identity,
/// user-broker class, retention/network/session/workspace policy, tool-call id
/// and role ordering, reasoning/continuation/compaction). This policy therefore
/// never derives a behaviour fingerprint from a route fingerprint and never
/// mints one: the route owner supplies the fingerprint and its currentness.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RouteOutcomeBinding {
    pub fingerprint: RouteBehaviorFingerprint,
    /// Whether the binding's declared stale dependencies moved. A stale binding
    /// contributes no signal rather than an assumed outcome.
    pub stale: bool,
}

/// One candidate route plus the orthogonal eligibility dimensions the policy
/// checks before any ranking.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteCandidate {
    pub route: RouteFingerprint,
    /// Family/lineage used only for the independence check. Must be
    /// non-blank: an auditor candidate with unknown lineage can never prove
    /// cross-family independence.
    pub family: String,
    /// Paid route flag: a paid fallback never silently satisfies an
    /// unavailable independent-audit requirement.
    pub paid: bool,
    /// Current quota/capacity/privacy admission for this route.
    pub eligibility: RouteEligibility,
    /// Capability evidence handle for this candidate. Must be non-blank so
    /// the receipt binds real evidence inputs.
    pub evidence_ref: String,
    /// This route's derived empirical outcome profile, when the owner retained
    /// one. `None` means no profile was retained for the exact effective route,
    /// which leaves the candidate on policy-default order.
    pub outcome: Option<RouteOutcomeEvidence>,
}

/// Budget/privacy constraints the receipt binds.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StaffingConstraints {
    pub budget: BudgetEnvelope,
    pub privacy_ceiling: PrivacyClass,
    pub evidence_refs: Vec<String>,
}

/// Explicit disposition for one unavailable route class. Persisted in the
/// plan receipt; silent substitution, silent extra spend, mid-attempt
/// provider change, and privacy-class export never occur.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum UnavailableDispositionKind {
    Defer,
    Degrade,
    Escalate,
}

/// Persisted explicit disposition for one unavailable route class.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnavailableClassDisposition {
    pub route_class: String,
    pub disposition: UnavailableDispositionKind,
    pub reason: String,
    pub evidence_refs: Vec<String>,
}

/// One staffed lane in the plan receipt.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StaffedLane {
    /// Lane role: `writer` or `auditor`.
    pub role: String,
    pub route_class: String,
    pub route: RouteFingerprint,
    pub evidence_refs: Vec<String>,
}

/// Canonical plan receipt: task-class staffing computed from current
/// evidence. Identifies selected route classes, routes, budget/privacy
/// constraints, and evidence inputs used.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StaffingPlanReceipt {
    pub preset: StaffingPreset,
    pub task_class: String,
    pub lanes: Vec<StaffedLane>,
    pub unavailable: Vec<UnavailableClassDisposition>,
    /// Exact owner-supplied capability-class and privacy evidence for every
    /// route considered by the live coordinator bridge.
    pub route_policy_evidence: Vec<RoutePolicyEvidence>,
    /// Every derived outcome profile the selection consulted, bound to the exact
    /// route it was observed on. Empty when no owner profile was retained: an
    /// absent profile is recorded as absent and never replaced by an assumed
    /// success, and a profile that kept a route out of the selection stays
    /// visible here next to the counts it was derived from.
    pub route_outcome_evidence: Vec<RouteOutcomeRecord>,
    /// Exact Human-selected per-job cost ceiling. `budget` below records the
    /// effective plan ask; this preserves the intent the plan was checked
    /// against.
    pub policy_budget: BudgetEnvelope,
    /// Effective plan ask computed from lane budgets and bounded by
    /// `policy_budget`.
    pub budget: BudgetEnvelope,
    pub privacy_ceiling: PrivacyClass,
    pub evidence_refs: Vec<String>,
    /// Canonical-JSON SHA-256 over the receipt body (all fields above).
    pub receipt_digest: String,
}

/// Route-local policy evidence bound into the canonical staffing receipt.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoutePolicyEvidence {
    pub route: RouteFingerprint,
    pub route_classes: Vec<String>,
    pub route_class_evidence_refs: Vec<String>,
    pub privacy_classes: Vec<PrivacyClass>,
    pub privacy_evidence_refs: Vec<String>,
}

/// Explicit receipted policy-authorized degradation authorizing one route
/// continuation after meaningful attempt output. Bound before continuation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyAuthorizedDegradation {
    pub attempt_id: String,
    pub from_route_digest: String,
    pub to_route_digest: String,
    pub reason: String,
    pub policy_revision: String,
}

/// Staffing policy errors. Every variant is load-bearing and distinct.
#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum StaffingPolicyError {
    #[error("staffing contract: {0}")]
    Contract(String),
    #[error("no eligible writer route: {0}")]
    NoWriterRoute(String),
    #[error("provider switch denied mid-attempt: {0}")]
    ProviderSwitchDenied(String),
}

fn validate_text(value: &str, field: &'static str) -> Result<(), StaffingPolicyError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(StaffingPolicyError::Contract(format!(
            "blank or control-bearing {field}"
        )));
    }
    Ok(())
}

fn validate_route_class(value: &str) -> Result<(), StaffingPolicyError> {
    validate_text(value, "route_class")?;
    if value.contains('%') || value.contains('/') {
        return Err(StaffingPolicyError::Contract(
            "route class must be a capability class, never a provider percentage split".to_owned(),
        ));
    }
    Ok(())
}

fn digest_receipt_body(body: &serde_json::Value) -> Result<String, StaffingPolicyError> {
    let bytes = eliot_contracts::canonical_json_bytes(body)
        .map_err(|error| StaffingPolicyError::Contract(format!("canonical bytes: {error}")))?;
    Ok(eliot_contracts::sha256_hex(&bytes))
}

fn route_digest(route: &RouteFingerprint) -> Result<String, StaffingPolicyError> {
    let bytes = eliot_contracts::canonical_json_bytes(route)
        .map_err(|error| StaffingPolicyError::Contract(format!("route bytes: {error}")))?;
    Ok(eliot_contracts::sha256_hex(&bytes))
}

impl ModelRolePolicy {
    fn base(
        preset: StaffingPreset,
        independent: IndependentReviewRequirements,
        per_job_budget: BudgetEnvelope,
    ) -> Result<Self, StaffingPolicyError> {
        let policy = Self {
            preset,
            main_agent_route_classes: vec![
                ROUTE_CLASS_ARCHITECTURE_REASONING.to_owned(),
                ROUTE_CLASS_BULK_IMPLEMENTATION.to_owned(),
            ],
            worker_route_classes: vec![ROUTE_CLASS_BULK_IMPLEMENTATION.to_owned()],
            auditor_route_classes: vec![ROUTE_CLASS_INDEPENDENT_BLIND_AUDIT.to_owned()],
            verifier_model_route_classes: vec![ROUTE_CLASS_SUBJECTIVE_EVALUATION.to_owned()],
            watchdog_route_classes: vec![ROUTE_CLASS_WATCHDOG_DIAGNOSTIC.to_owned()],
            dreamer_route_classes: vec![
                ROUTE_CLASS_DREAMER_CURATION.to_owned(),
                ROUTE_CLASS_DREAMER_ORIENTATION.to_owned(),
            ],
            independent_review_requirements: independent,
            local_only_data_classes: vec!["secret".to_owned(), "licensed".to_owned()],
            external_allowed_data_classes: vec!["public".to_owned(), "internal".to_owned()],
            per_job_budget,
            active_quota_windows: vec!["rolling_hours".to_owned()],
            max_active_lanes: 4,
            max_writers_per_deliverable: 1,
            max_swarm_fanout: 4,
            max_swarm_depth: 3,
            native_child_policy: "bounded".to_owned(),
            auto_launch_job_classes: vec!["fast_read_only_scout".to_owned()],
            human_approval_classes: vec!["incident_escalation".to_owned()],
            preview_beta_policy: "deny".to_owned(),
        };
        policy.validate()?;
        Ok(policy)
    }

    /// Economy: one cheap worker; review only on risk/failure.
    pub fn economy(budget: BudgetEnvelope) -> Result<Self, StaffingPolicyError> {
        Self::base(
            StaffingPreset::Economy,
            IndependentReviewRequirements {
                required: false,
                blind: false,
                cross_family: false,
            },
            budget,
        )
    }

    /// Balanced: one writer plus conditional independent review.
    pub fn balanced(budget: BudgetEnvelope) -> Result<Self, StaffingPolicyError> {
        Self::base(
            StaffingPreset::Balanced,
            IndependentReviewRequirements {
                required: false,
                blind: true,
                cross_family: true,
            },
            budget,
        )
    }

    /// Assurance: one writer plus mandatory blind cross-family audit.
    pub fn assurance(budget: BudgetEnvelope) -> Result<Self, StaffingPolicyError> {
        Self::base(
            StaffingPreset::Assurance,
            IndependentReviewRequirements {
                required: true,
                blind: true,
                cross_family: true,
            },
            budget,
        )
    }

    /// Research: incremental read-only evidence fan-out and synthesis.
    pub fn research(budget: BudgetEnvelope) -> Result<Self, StaffingPolicyError> {
        let mut policy = Self::base(
            StaffingPreset::Research,
            IndependentReviewRequirements {
                required: false,
                blind: false,
                cross_family: false,
            },
            budget,
        )?;
        policy.main_agent_route_classes = vec![ROUTE_CLASS_RESEARCH_SYNTHESIS.to_owned()];
        policy.worker_route_classes = vec![ROUTE_CLASS_FAST_READ_ONLY_SCOUT.to_owned()];
        policy.validate()?;
        Ok(policy)
    }

    /// Incident: bounded rival-hypothesis lanes, strong logging/escalation.
    pub fn incident(budget: BudgetEnvelope) -> Result<Self, StaffingPolicyError> {
        let mut policy = Self::base(
            StaffingPreset::Incident,
            IndependentReviewRequirements {
                required: true,
                blind: false,
                cross_family: true,
            },
            budget,
        )?;
        policy.human_approval_classes = vec![
            "incident_escalation".to_owned(),
            "rival_hypothesis_launch".to_owned(),
        ];
        policy.validate()?;
        Ok(policy)
    }

    /// Validates the policy shape. Rejects blank/control text, empty lane
    /// bounds, and any static provider-percentage spelling in route classes.
    pub fn validate(&self) -> Result<(), StaffingPolicyError> {
        for class in self
            .main_agent_route_classes
            .iter()
            .chain(self.worker_route_classes.iter())
            .chain(self.auditor_route_classes.iter())
            .chain(self.verifier_model_route_classes.iter())
            .chain(self.watchdog_route_classes.iter())
            .chain(self.dreamer_route_classes.iter())
        {
            validate_route_class(class)?;
        }
        if self.max_active_lanes == 0 || self.max_writers_per_deliverable == 0 {
            return Err(StaffingPolicyError::Contract(
                "lane/writer bounds must be nonzero".to_owned(),
            ));
        }
        if self.max_writers_per_deliverable > 1 {
            return Err(StaffingPolicyError::Contract(
                "at most one writer per deliverable".to_owned(),
            ));
        }
        validate_text(&self.native_child_policy, "native_child_policy")?;
        validate_text(&self.preview_beta_policy, "preview_beta_policy")?;
        self.per_job_budget
            .validate()
            .map_err(|error| StaffingPolicyError::Contract(format!("budget: {error}")))?;
        Ok(())
    }
}

/// Plans task-class staffing from current evidence under the given policy.
///
/// Returns a candidate receipt: selected lanes plus explicit dispositions
/// for the classes this plan requires but cannot staff. This function
/// persists nothing; the Governor caller persists the returned candidate and
/// rebinds its integrity with [`verify_receipt_digest`] at that boundary.
///
/// The writer is selected from worker route classes; the auditor (when the
/// preset or task requires independent review) is selected only from
/// auditor route classes with cross-family independence, quota/capacity, and
/// privacy admission. A required-but-unstaffed audit class yields an
/// explicit escalate disposition: same-family and paid fallbacks are
/// rejected, never silently substituted. Policy-declared non-executing
/// Dreamer classes always yield defer dispositions. A missing writer is a
/// typed [`StaffingPolicyError::NoWriterRoute`], never a disposition.
/// Role classes this task plan does not require (main-agent, verifier,
/// watchdog) carry no disposition: they are not unavailable, they are
/// simply not staffed by this plan.
///
/// The supplied constraints cannot widen the selected policy: the
/// constraints budget must sit within the policy per-job budget, and a
/// privacy ceiling naming a policy local-only class closes external lanes
/// fail-closed instead of exporting the class.
pub fn plan_staffing(
    policy: &ModelRolePolicy,
    task_class: &str,
    requires_independent_review: bool,
    evidence: &[RouteClassEvidence],
    constraints: &StaffingConstraints,
) -> Result<StaffingPlanReceipt, StaffingPolicyError> {
    validate_text(task_class, "task_class")?;
    policy.validate()?;
    validate_evidence(evidence)?;
    constraints
        .budget
        .validate()
        .map_err(|error| StaffingPolicyError::Contract(format!("constraints budget: {error}")))?;

    let audit_required =
        policy.independent_review_requirements.required || requires_independent_review;
    // The caller selects intent, never a wider envelope: the supplied budget
    // must sit within the policy per-job budget, and a local-only ceiling
    // closes external lanes before any candidate is considered.
    constraints
        .budget
        .is_within(&policy.per_job_budget)
        .map_err(|error| {
            StaffingPolicyError::Contract(format!("constraints budget exceeds policy: {error}"))
        })?;
    let lanes_open = external_lanes_open(policy, constraints.privacy_ceiling);

    let writer = select_writer(policy, evidence, lanes_open)?;
    let mut lanes = vec![writer.clone()];
    let mut unavailable = Vec::new();

    if audit_required {
        match select_independent_auditor(policy, evidence, &writer, lanes_open) {
            Ok(auditor) => lanes.push(auditor),
            Err(reason) => unavailable.push(UnavailableClassDisposition {
                route_class: ROUTE_CLASS_INDEPENDENT_BLIND_AUDIT.to_owned(),
                disposition: UnavailableDispositionKind::Escalate,
                reason,
                evidence_refs: evidence_refs_for(evidence, ROUTE_CLASS_INDEPENDENT_BLIND_AUDIT),
            }),
        }
    }

    // Dreamer is non-executing: its route classes are never staffed here, so
    // they always carry an explicit defer disposition instead of a silent
    // substitution or a spent budget.
    for class in &policy.dreamer_route_classes {
        unavailable.push(UnavailableClassDisposition {
            route_class: class.clone(),
            disposition: UnavailableDispositionKind::Defer,
            reason: "dreamer route class is non-executing on this base".to_owned(),
            evidence_refs: evidence_refs_for(evidence, class),
        });
    }

    let mut evidence_refs: Vec<String> = constraints.evidence_refs.clone();
    for lane in &lanes {
        evidence_refs.extend(lane.evidence_refs.iter().cloned());
    }
    for record in consulted_outcome_profiles(evidence)? {
        evidence_refs.extend(record.profile.evidence_refs.iter().cloned());
    }
    evidence_refs.sort();
    evidence_refs.dedup();

    let mut receipt = StaffingPlanReceipt {
        preset: policy.preset,
        task_class: task_class.to_owned(),
        lanes,
        unavailable,
        // This lower-level policy function receives already-compiled class
        // eligibility booleans. The live coordinator bridge fills this with
        // exact route-owner evidence before sealing the receipt.
        route_policy_evidence: Vec::new(),
        route_outcome_evidence: consulted_outcome_profiles(evidence)?,
        policy_budget: policy.per_job_budget.clone(),
        budget: constraints.budget.clone(),
        privacy_ceiling: constraints.privacy_ceiling,
        evidence_refs,
        receipt_digest: String::new(),
    };
    seal_receipt_digest(&mut receipt)?;
    Ok(receipt)
}

/// Every owner outcome profile the selection consulted, one record per exact
/// route, ordered by the route's canonical digest so the receipt is
/// deterministic for equivalent admitted inputs.
///
/// A candidate route retained in several classes appears once. Routes with no
/// retained profile contribute nothing: an absent profile is never fabricated
/// into an assumed success.
fn consulted_outcome_profiles(
    evidence: &[RouteClassEvidence],
) -> Result<Vec<RouteOutcomeRecord>, StaffingPolicyError> {
    let mut by_digest: BTreeMap<String, RouteOutcomeRecord> = BTreeMap::new();
    for record in evidence {
        for candidate in &record.candidates {
            let Some(profile) = candidate.outcome.clone() else {
                continue;
            };
            if profile.evidence_refs.is_empty() {
                return Err(StaffingPolicyError::Contract(
                    "route outcome profile carries no evidence reference".to_owned(),
                ));
            }
            for reference in &profile.evidence_refs {
                validate_text(reference, "outcome evidence_ref")?;
            }
            by_digest
                .entry(route_digest(&candidate.route)?)
                .or_insert(RouteOutcomeRecord {
                    route: candidate.route.clone(),
                    profile,
                });
        }
    }
    Ok(by_digest.into_values().collect())
}

fn seal_receipt_digest(receipt: &mut StaffingPlanReceipt) -> Result<(), StaffingPolicyError> {
    let body = serde_json::to_value(&*receipt)
        .map_err(|error| StaffingPolicyError::Contract(format!("receipt body: {error}")))?;
    let mut body_map = body
        .as_object()
        .cloned()
        .ok_or_else(|| StaffingPolicyError::Contract("receipt body shape".to_owned()))?;
    body_map.remove("receipt_digest");
    receipt.receipt_digest = digest_receipt_body(&serde_json::Value::Object(body_map))?;
    Ok(())
}

/// Rebinds a candidate receipt's integrity at the persistence boundary.
///
/// Recomputes the canonical-JSON digest over the receipt body (all fields
/// except `receipt_digest`) and accepts the receipt only when it matches.
/// The Governor caller runs this check when persisting the candidate
/// returned by [`plan_staffing`]; a mismatch fails closed instead of
/// persisting a tampered or mis-bound plan.
pub fn verify_receipt_digest(receipt: &StaffingPlanReceipt) -> Result<(), StaffingPolicyError> {
    let body = serde_json::to_value(receipt)
        .map_err(|error| StaffingPolicyError::Contract(format!("receipt body: {error}")))?;
    let mut body_map = body
        .as_object()
        .cloned()
        .ok_or_else(|| StaffingPolicyError::Contract("receipt body shape".to_owned()))?;
    body_map.remove("receipt_digest");
    let expected = digest_receipt_body(&serde_json::Value::Object(body_map))?;
    if receipt.receipt_digest != expected {
        return Err(StaffingPolicyError::Contract(
            "plan receipt digest does not bind the receipt body".to_owned(),
        ));
    }
    Ok(())
}

fn validate_evidence(evidence: &[RouteClassEvidence]) -> Result<(), StaffingPolicyError> {
    for record in evidence {
        validate_route_class(&record.route_class)?;
        for candidate in &record.candidates {
            validate_text(&candidate.family, "candidate family")?;
            validate_text(&candidate.evidence_ref, "candidate evidence_ref")?;
        }
    }
    Ok(())
}

fn eligible_candidate(candidate: &RouteCandidate) -> bool {
    candidate.eligibility.quota_admits
        && candidate.eligibility.capacity_admits
        && candidate.eligibility.privacy_admits
}

/// Wire name of a privacy ceiling in policy data-class terms.
fn privacy_data_class(ceiling: PrivacyClass) -> &'static str {
    match ceiling {
        PrivacyClass::Public => "public",
        PrivacyClass::Internal => "internal",
        PrivacyClass::Private => "private",
        PrivacyClass::Secret => "secret",
        PrivacyClass::Licensed => "licensed",
    }
}

/// Whether lanes may be staffed on external candidate routes under the task
/// ceiling. A ceiling naming a policy local-only class closes external lanes
/// fail-closed: without route-locality evidence the planner cannot prove a
/// lane would keep the class local, so no lane is staffed instead of risking
/// a higher privacy class exported externally (I3.6).
fn external_lanes_open(policy: &ModelRolePolicy, ceiling: PrivacyClass) -> bool {
    !policy
        .local_only_data_classes
        .iter()
        .any(|class| class == privacy_data_class(ceiling))
}

fn select_writer(
    policy: &ModelRolePolicy,
    evidence: &[RouteClassEvidence],
    lanes_open: bool,
) -> Result<StaffedLane, StaffingPolicyError> {
    if !lanes_open {
        return Err(StaffingPolicyError::NoWriterRoute(
            "local-only privacy ceiling closes external lanes; no writer staffed".to_owned(),
        ));
    }
    let mut outcome_refused = false;
    for class in &policy.worker_route_classes {
        if let Some(record) = evidence.iter().find(|item| &item.route_class == class) {
            for candidate in &record.candidates {
                if !eligible_candidate(candidate) {
                    continue;
                }
                // Observed outcomes are consulted only after hard eligibility:
                // a route whose own equal-stack samples produced nothing
                // verified while at least one failed or stayed unknown is kept
                // out of the selection, and the refusal is remembered so a plan
                // with no alternative reports the outcome reason instead of the
                // generic "no eligible route".
                if candidate
                    .outcome
                    .as_ref()
                    .is_some_and(RouteOutcomeEvidence::blocks_selection)
                {
                    outcome_refused = true;
                    continue;
                }
                candidate.route.validate().map_err(|error| {
                    StaffingPolicyError::Contract(format!("writer route: {error}"))
                })?;
                return Ok(StaffedLane {
                    role: "writer".to_owned(),
                    route_class: class.clone(),
                    route: candidate.route.clone(),
                    evidence_refs: vec![candidate.evidence_ref.clone()],
                });
            }
        }
    }
    if outcome_refused {
        return Err(StaffingPolicyError::NoWriterRoute(
            "every eligible writer route's observed outcome profile shows this task class failing; refusing to staff a route its own samples rejected"
                .to_owned(),
        ));
    }
    Err(StaffingPolicyError::NoWriterRoute(
        "no eligible writer route under current evidence, quota, capacity, and privacy".to_owned(),
    ))
}

fn select_independent_auditor(
    policy: &ModelRolePolicy,
    evidence: &[RouteClassEvidence],
    writer: &StaffedLane,
    lanes_open: bool,
) -> Result<StaffedLane, String> {
    if !lanes_open {
        return Err(
            "local-only privacy ceiling closes external lanes; escalating instead of substituting"
                .to_owned(),
        );
    }
    let writer_family = writer_family(evidence, writer);
    let mut specific_reason: Option<String> = None;
    let mut outcome_refused = false;
    for class in &policy.auditor_route_classes {
        let Some(record) = evidence.iter().find(|item| &item.route_class == class) else {
            continue;
        };
        let mut saw_same_family = false;
        let mut saw_paid_fallback = false;
        for candidate in &record.candidates {
            if !eligible_candidate(candidate) {
                continue;
            }
            // An outcome profile never admits an audit route and never promotes
            // one; it only keeps a route out whose own samples rejected this
            // task class. Aggregated success still cannot hide the counts,
            // because every consulted profile is recorded in the receipt.
            if candidate
                .outcome
                .as_ref()
                .is_some_and(RouteOutcomeEvidence::blocks_selection)
            {
                outcome_refused = true;
                continue;
            }
            if policy.independent_review_requirements.cross_family
                && candidate.family == writer_family
            {
                saw_same_family = true;
                continue;
            }
            if candidate.paid {
                // A paid route never silently satisfies an unavailable
                // independent-audit requirement; it would escape the selected
                // budget intent.
                saw_paid_fallback = true;
                continue;
            }
            if candidate.route.validate().is_err() {
                continue;
            }
            return Ok(StaffedLane {
                role: "auditor".to_owned(),
                route_class: class.clone(),
                route: candidate.route.clone(),
                evidence_refs: vec![candidate.evidence_ref.clone()],
            });
        }
        if (saw_same_family || saw_paid_fallback) && specific_reason.is_none() {
            specific_reason = Some(
                "independent audit unavailable: only same-family or paid routes offered; escalating instead of substituting"
                    .to_owned(),
            );
        }
    }
    if outcome_refused && specific_reason.is_none() {
        return Err(
            "independent audit unavailable: every eligible audit route's observed outcome profile shows this task class failing; escalating instead of substituting"
                .to_owned(),
        );
    }
    Err(specific_reason.unwrap_or_else(|| {
        "independent audit unavailable under current capability evidence; escalating instead of substituting"
            .to_owned()
    }))
}

fn writer_family(evidence: &[RouteClassEvidence], writer: &StaffedLane) -> String {
    for record in evidence {
        for candidate in &record.candidates {
            if candidate.route == writer.route {
                return candidate.family.clone();
            }
        }
    }
    String::new()
}

fn evidence_refs_for(evidence: &[RouteClassEvidence], route_class: &str) -> Vec<String> {
    evidence
        .iter()
        .find(|item| item.route_class == route_class)
        .map(|item| item.evidence_refs.clone())
        .unwrap_or_default()
}

/// Reads one route's derived empirical outcome profile out of the Governor's
/// retained profile index (I3.4 `RouteOutcomeProfileIndex`).
///
/// `bindings` maps the coordinator route's own effective route key to the
/// owner-issued behaviour identity that route's profiles are recorded under, so
/// this policy reads the exact effective route's samples and never a
/// provider/model-identical sibling's. Three absences are distinguished and none
/// of them becomes an assumed success:
///
/// * no binding for the route — the owner issued no behaviour identity, so no
///   profile is consumed;
/// * a binding marked stale — the binding's declared dependencies moved, so it
///   contributes no signal;
/// * a binding with no retained profile under that exact effective route key.
///
/// A retained profile is carried as its own named sample counts plus its
/// evidence references. A profile with no evidence reference proves nothing and
/// is refused rather than consumed.
///
/// # Errors
///
/// Returns [`StaffingPolicyError::Contract`] when the route's effective key or
/// the behaviour identity's effective key cannot be computed, or when a
/// retained profile carries no evidence reference. A route is never recorded
/// under a placeholder key.
pub fn route_outcome_evidence<S: std::hash::BuildHasher>(
    profiles: &RouteOutcomeProfileIndex,
    bindings: &HashMap<LowercaseSha256, RouteOutcomeBinding, S>,
    route: &RouteFingerprint,
) -> Result<Option<RouteOutcomeEvidence>, StaffingPolicyError> {
    let route_key = crate::route_receipts::effective_route_key(route)
        .map_err(|error| StaffingPolicyError::Contract(format!("outcome route key: {error}")))?;
    let Some(binding) = bindings.get(&route_key) else {
        return Ok(None);
    };
    if binding.stale {
        return Ok(None);
    }
    let Some(profile) = profiles.lookup(&binding.fingerprint).map_err(|error| {
        StaffingPolicyError::Contract(format!("outcome profile lookup: {error}"))
    })?
    else {
        return Ok(None);
    };
    if profile.evidence_refs.is_empty() {
        return Err(StaffingPolicyError::Contract(
            "retained route outcome profile carries no evidence reference".to_owned(),
        ));
    }
    Ok(Some(RouteOutcomeEvidence {
        verified_complete: profile.outcome_counts.verified_complete,
        partial: profile.outcome_counts.partial,
        failed: profile.outcome_counts.failed,
        unknown: profile.outcome_counts.unknown,
        stale: false,
        evidence_refs: profile.evidence_refs.clone(),
    }))
}

/// Guards attempt continuation against silent provider switching.
///
/// The same route fingerprint continues freely. A different fingerprint
/// continues only with an explicit receipted policy-authorized degradation
/// binding this exact attempt and both route digests before continuation.
pub fn check_attempt_route_continuity(
    previous: &RouteFingerprint,
    next: &RouteFingerprint,
    degradation: Option<&PolicyAuthorizedDegradation>,
    attempt_id: &str,
) -> Result<(), StaffingPolicyError> {
    validate_text(attempt_id, "attempt_id")?;
    if previous == next {
        return Ok(());
    }
    let Some(approval) = degradation else {
        return Err(StaffingPolicyError::ProviderSwitchDenied(
            "route changed mid-attempt without a receipted policy-authorized degradation"
                .to_owned(),
        ));
    };
    if approval.attempt_id != attempt_id {
        return Err(StaffingPolicyError::ProviderSwitchDenied(
            "degradation binds a different attempt".to_owned(),
        ));
    }
    let from = route_digest(previous)?;
    let to = route_digest(next)?;
    if approval.from_route_digest != from || approval.to_route_digest != to {
        return Err(StaffingPolicyError::ProviderSwitchDenied(
            "degradation does not bind the exact route transition".to_owned(),
        ));
    }
    validate_text(&approval.reason, "degradation_reason")?;
    validate_text(&approval.policy_revision, "policy_revision")?;
    Ok(())
}

/// Per-job budget ceiling for one coordinator plan: the element-wise union of
/// the request's lane budgets. Every lane budget of the plan therefore sits
/// within this ceiling, and no lane can widen it.
fn coordinator_plan_budget(
    request: &StaffingPlanRequest,
) -> Result<BudgetEnvelope, StaffingPolicyError> {
    let mut ceiling: Option<BudgetEnvelope> = None;
    for lane in &request.lanes {
        lane.budget
            .validate()
            .map_err(|error| StaffingPolicyError::Contract(format!("lane budget: {error}")))?;
        ceiling = Some(match ceiling {
            None => lane.budget.clone(),
            Some(current) => BudgetEnvelope {
                context_tokens: current.context_tokens.max(lane.budget.context_tokens),
                wall_time_ms: current.wall_time_ms.max(lane.budget.wall_time_ms),
                output_bytes: current.output_bytes.max(lane.budget.output_bytes),
                cost_microunits: current.cost_microunits.max(lane.budget.cost_microunits),
                max_depth: current.max_depth.max(lane.budget.max_depth),
                max_descendants: current.max_descendants.max(lane.budget.max_descendants),
            },
        });
    }
    let ceiling = ceiling.ok_or_else(|| {
        StaffingPolicyError::Contract("staffing plan requires at least one lane".to_owned())
    })?;
    ceiling
        .validate()
        .map_err(|error| StaffingPolicyError::Contract(format!("plan budget: {error}")))?;
    Ok(ceiling)
}

/// Task-class `ModelRolePolicy` selected by explicit Human intent, plus
/// whether the recipe carries an explicit independent-review requirement.
///
/// # Errors
///
/// Returns [`StaffingPolicyError::Contract`] when the recipe requests more
/// lanes than the selected policy's active-lane bound, or declares more
/// mutation-capable roles than its writer bound.
fn coordinator_recipe_policy(
    request: &StaffingPlanRequest,
) -> Result<(ModelRolePolicy, bool), StaffingPolicyError> {
    let review_requested = !request.recipe.audit_requirements.is_empty();
    let human_intent = &request.human_staffing_intent;
    let policy = match human_intent.preset {
        StaffingPreset::Economy => ModelRolePolicy::economy(human_intent.per_job_budget.clone())?,
        StaffingPreset::Balanced => ModelRolePolicy::balanced(human_intent.per_job_budget.clone())?,
        StaffingPreset::Assurance => {
            ModelRolePolicy::assurance(human_intent.per_job_budget.clone())?
        }
        StaffingPreset::Research => ModelRolePolicy::research(human_intent.per_job_budget.clone())?,
        StaffingPreset::Incident => ModelRolePolicy::incident(human_intent.per_job_budget.clone())?,
    };
    if request.lanes.len() > usize::from(policy.max_active_lanes) {
        return Err(StaffingPolicyError::Contract(format!(
            "recipe requests {} lanes above the policy active-lane bound {}",
            request.lanes.len(),
            policy.max_active_lanes
        )));
    }
    let mutation_capable = request
        .recipe
        .role_profiles
        .iter()
        .filter(|profile| profile.mutation_capable)
        .count();
    if mutation_capable > usize::from(policy.max_writers_per_deliverable) {
        return Err(StaffingPolicyError::Contract(format!(
            "recipe declares {mutation_capable} mutation-capable roles above the policy writer bound {}",
            policy.max_writers_per_deliverable
        )));
    }
    Ok((policy, review_requested))
}

/// One live route candidate as the policy consumes it.
///
/// Family is the I3.4 host-family identity layer. A candidate whose observed
/// budget evidence already carries model cost is a paid route, so it can never
/// silently satisfy an unavailable independent-audit requirement. Quota
/// admission is the coordinator's own active capacity window: the candidate
/// must carry the exact `capacity_identity`/`capacity_revision` of the live
/// [`CoordinatorConfig`].
///
/// Route capability classes and privacy classes are supplied by the route
/// owner. They must carry their own source references; task/role declarations
/// alone cannot admit a route into a capability class or privacy scope.
///
/// A candidate's derived outcome profile is looked up separately through
/// [`route_outcome_evidence`], because it needs the owner-issued behaviour
/// identity its profile is keyed under. No outcome profile is derived or
/// defaulted here: an absent profile leaves the candidate on policy-default
/// order and is recorded as absent in the receipt.
fn coordinator_route_candidate(
    config: &CoordinatorConfig,
    privacy_class: PrivacyClass,
    candidate: &RouteCandidateEvidence,
) -> Result<RouteCandidate, StaffingPolicyError> {
    if candidate.route_classes.is_empty()
        || candidate.route_class_evidence_refs.is_empty()
        || candidate.privacy_classes.is_empty()
        || candidate.privacy_evidence_refs.is_empty()
    {
        return Err(StaffingPolicyError::Contract(
            "route candidate lacks owner-supplied capability or privacy evidence".to_owned(),
        ));
    }
    let evidence_ref = candidate
        .route_class_evidence_refs
        .first()
        .ok_or_else(|| {
            StaffingPolicyError::Contract(
                "route candidate carries no route-class evidence reference".to_owned(),
            )
        })?
        .clone();
    Ok(RouteCandidate {
        family: candidate.route.host_family.clone(),
        paid: candidate.budget_evidence.model_cost_micros > 0,
        route: candidate.route.clone(),
        eligibility: RouteEligibility {
            quota_admits: candidate.capacity_identity == config.capacity_identity
                && candidate.capacity_revision == config.capacity_revision,
            capacity_admits: candidate.capacity_limit > 0,
            privacy_admits: candidate.privacy_classes.contains(&privacy_class),
        },
        evidence_ref,
        outcome: None,
    })
}

/// The I3.6 capability classes the request itself binds to one staffing lane.
///
/// I3.6 makes the default route classes capability-based (`bulk_implementation`,
/// `independent_blind_audit`, …), so a class is eligible for a route only where
/// the owner declared that class. The coordinator's own admission already
/// requires a lane's candidates to be admitted by the recipe, by the lane's
/// role profile, and by the launch, so all three declarations are intersected
/// here and a class survives only when every one of them names it exactly.
///
/// Nothing maps a provider or adapter label onto a capability class, so a
/// request whose declared vocabulary carries adapter labels (`codex-app-server`,
/// `claude.agent-sdk.local-sidecar`, `provider-model-a`) proves no I3.6 class at
/// all and every class is refused. A lane whose role profile is absent from the
/// frozen recipe likewise proves nothing.
fn coordinator_lane_class_binding(
    request: &StaffingPlanRequest,
    lane: &StaffingLaneRequest,
    candidate: &RouteCandidateEvidence,
) -> BTreeSet<String> {
    let Some(profile) = request
        .recipe
        .role_profiles
        .iter()
        .find(|profile| profile.role_id == lane.role_id)
    else {
        return BTreeSet::new();
    };
    request
        .recipe
        .eligible_route_classes
        .iter()
        .filter(|class| {
            profile.allowed_route_classes.contains(class)
                && request.launch.allowed_route_classes.contains(class)
                && candidate.route_classes.contains(class)
        })
        .cloned()
        .collect()
}

/// The I3.6 capability classes one request lane's own candidates bind, across
/// every candidate the lane carries.
///
/// Same intersection as [`coordinator_lane_class_binding`], applied once per
/// lane instead of once per candidate, so a lane can be classified as a writer
/// lane or an independent-audit lane without re-deriving its bindings.
fn coordinator_lane_bound_classes(
    request: &StaffingPlanRequest,
    lane: &StaffingLaneRequest,
) -> BTreeSet<String> {
    lane.route_candidates
        .iter()
        .flat_map(|candidate| coordinator_lane_class_binding(request, lane, candidate))
        .collect()
}

/// Identity of one request lane inside its frozen plan.
fn coordinator_lane_key(lane: &StaffingLaneRequest) -> (String, String) {
    (
        lane.work_unit_id.as_str().to_owned(),
        lane.role_id.as_str().to_owned(),
    )
}

/// Request lanes that can actually run an independent audit on their own.
///
/// The coordinator compiles exactly one candidate lane per request lane, and the
/// fabric authorizes attempt `n` of an admission on the receipt's `n`th staffed
/// route. An audit class bound only to a lane that also staffs the writer would
/// therefore staff a receipt lane that no compiled lane and no attempt can ever
/// run — a trailing entry that reads as satisfied independent review while
/// nothing reviews anything. An audit lane is a request lane that binds an
/// auditor class and binds no worker class, so the writer role and the audit
/// role are always two different lanes.
fn coordinator_audit_lane_keys(
    request: &StaffingPlanRequest,
    policy: &ModelRolePolicy,
) -> BTreeSet<(String, String)> {
    request
        .lanes
        .iter()
        .filter(|lane| {
            let bound = coordinator_lane_bound_classes(request, lane);
            bound
                .iter()
                .any(|class| policy.auditor_route_classes.contains(class))
                && !bound
                    .iter()
                    .any(|class| policy.worker_route_classes.contains(class))
        })
        .map(coordinator_lane_key)
        .collect()
}

/// The live request's route candidates as capability evidence per I3.6 class.
///
/// A route is placed in a class only where the route owner, recipe, role, and
/// launch all name that exact class. The same complete lane pool is never
/// copied into every worker, auditor, and Dreamer class. An auditor class draws
/// only from a lane that can run the audit on its own, so an audit class with no
/// such lane ends up empty and is escalated by the receipt rather than staffed as
/// a lane nothing would run.
fn coordinator_route_evidence(
    config: &CoordinatorConfig,
    request: &StaffingPlanRequest,
    policy: &ModelRolePolicy,
) -> Result<Vec<RouteClassEvidence>, StaffingPolicyError> {
    let audit_lanes = coordinator_audit_lane_keys(request, policy);
    let mut classes: Vec<String> = policy.worker_route_classes.clone();
    classes.extend(policy.auditor_route_classes.iter().cloned());
    classes.extend(policy.dreamer_route_classes.iter().cloned());
    classes.sort();
    classes.dedup();

    let mut placed: BTreeMap<String, Vec<RouteCandidate>> = BTreeMap::new();
    for lane in &request.lanes {
        let audit_capable = audit_lanes.contains(&coordinator_lane_key(lane));
        for candidate in &lane.route_candidates {
            let mapped = coordinator_route_candidate(config, request.privacy_class, candidate)?;
            let binding = coordinator_lane_class_binding(request, lane, candidate);
            for class in binding {
                if policy.auditor_route_classes.contains(&class) && !audit_capable {
                    continue;
                }
                let candidates = placed.entry(class.clone()).or_default();
                if !candidates.iter().any(|seen| seen.route == mapped.route) {
                    candidates.push(mapped.clone());
                }
            }
        }
    }

    let mut records = Vec::with_capacity(classes.len());
    for class in classes {
        let candidates = placed.remove(&class).unwrap_or_default();
        let mut evidence_refs: Vec<String> = candidates
            .iter()
            .map(|item| item.evidence_ref.clone())
            .collect();
        evidence_refs.sort();
        evidence_refs.dedup();
        records.push(RouteClassEvidence {
            route_class: class,
            candidates,
            evidence_refs,
        });
    }
    Ok(records)
}

fn coordinator_route_policy_evidence(
    request: &StaffingPlanRequest,
) -> Result<Vec<RoutePolicyEvidence>, StaffingPolicyError> {
    let mut by_route = BTreeMap::<String, RoutePolicyEvidence>::new();
    for lane in &request.lanes {
        for candidate in &lane.route_candidates {
            candidate.route.validate().map_err(|error| {
                StaffingPolicyError::Contract(format!("route capability evidence: {error}"))
            })?;
            if candidate.route_classes.is_empty()
                || candidate.route_class_evidence_refs.is_empty()
                || candidate.privacy_classes.is_empty()
                || candidate.privacy_evidence_refs.is_empty()
            {
                return Err(StaffingPolicyError::Contract(
                    "route candidate lacks owner-supplied capability or privacy evidence"
                        .to_owned(),
                ));
            }
            let mut route_classes = candidate.route_classes.clone();
            for class in &route_classes {
                validate_route_class(class)?;
            }
            route_classes.sort();
            route_classes.dedup();

            let mut privacy_classes = candidate.privacy_classes.clone();
            privacy_classes.sort_by_key(|class| privacy_data_class(*class));
            privacy_classes.dedup();

            let mut route_class_evidence_refs = candidate.route_class_evidence_refs.clone();
            for evidence in &route_class_evidence_refs {
                validate_text(evidence, "route_class_evidence_ref")?;
            }
            route_class_evidence_refs.sort();
            route_class_evidence_refs.dedup();

            let mut privacy_evidence_refs = candidate.privacy_evidence_refs.clone();
            for evidence in &privacy_evidence_refs {
                validate_text(evidence, "privacy_evidence_ref")?;
            }
            privacy_evidence_refs.sort();
            privacy_evidence_refs.dedup();

            let key = route_digest(&candidate.route)?;
            match by_route.get_mut(&key) {
                Some(existing) => {
                    if existing.route != candidate.route
                        || existing.route_classes != route_classes
                        || existing.privacy_classes != privacy_classes
                    {
                        return Err(StaffingPolicyError::Contract(
                            "one route has conflicting owner capability or privacy evidence"
                                .to_owned(),
                        ));
                    }
                    existing
                        .route_class_evidence_refs
                        .extend(route_class_evidence_refs);
                    existing.route_class_evidence_refs.sort();
                    existing.route_class_evidence_refs.dedup();
                    existing.privacy_evidence_refs.extend(privacy_evidence_refs);
                    existing.privacy_evidence_refs.sort();
                    existing.privacy_evidence_refs.dedup();
                }
                None => {
                    by_route.insert(
                        key,
                        RoutePolicyEvidence {
                            route: candidate.route.clone(),
                            route_classes,
                            route_class_evidence_refs,
                            privacy_classes,
                            privacy_evidence_refs,
                        },
                    );
                }
            }
        }
    }
    Ok(by_route.into_values().collect())
}

/// Budget/privacy constraints the plan receipt binds, taken verbatim from the
/// live request: the plan budget ceiling this request's lanes actually ask for,
/// the request's own privacy class, and every capability evidence reference the
/// request carries.
///
/// The lane budgets are the *plan's* ask and the policy's `per_job_budget` is
/// the Human's cost intent, so they stay separate inputs: [`plan_staffing`]
/// then really checks that the ask sits within the intent instead of comparing
/// the intent with itself.
fn coordinator_constraints(
    request: &StaffingPlanRequest,
) -> Result<StaffingConstraints, StaffingPolicyError> {
    let budget = coordinator_plan_budget(request)?;
    let mut evidence_refs = request.launch.evidence_capability_refs.clone();
    for lane in &request.lanes {
        for candidate in &lane.route_candidates {
            evidence_refs.extend(candidate.evidence_refs.iter().cloned());
            evidence_refs.extend(candidate.route_class_evidence_refs.iter().cloned());
            evidence_refs.extend(candidate.privacy_evidence_refs.iter().cloned());
        }
    }
    evidence_refs.sort();
    evidence_refs.dedup();
    Ok(StaffingConstraints {
        budget,
        privacy_ceiling: request.privacy_class,
        evidence_refs,
    })
}

/// Plans task-class staffing for the live coordinator request (I3.6).
///
/// This is the bridge from `eliot_agent_coordinator::StaffingPlanRequest` onto
/// [`plan_staffing`], not a second planner and not a second policy type: the
/// coordinator request keeps its own vocabulary and its own deterministic
/// ranking, and the returned [`StaffingPlanReceipt`] becomes the single
/// authority on which routes this task class may use. The receipt identifies
/// the selected route classes, the selected routes, the budget/privacy
/// constraints it was computed under, the outcome profiles it consulted, and
/// the evidence inputs used.
///
/// Route-class eligibility comes from the request's own declarations
/// ([`coordinator_lane_class_binding`]), so an unavailable class yields the
/// explicit typed disposition I3.6 requires rather than a candidate borrowed
/// from a neighbouring class. The Human intent and route-owner evidence are
/// bound into the returned receipt.
///
/// Every lane the receipt staffs is a lane the coordinator will compile and the
/// fabric will run: an auditor class with no audit lane of its own is escalated
/// by name instead of being staffed as a receipt entry nothing could dispatch.
///
/// # Errors
///
/// Returns the planner rejection unchanged, including
/// [`StaffingPolicyError::Contract`] when the recipe exceeds the selected
/// policy's lane or writer bound, and
/// [`StaffingPolicyError::NoWriterRoute`] when no writer route clears quota,
/// capacity and privacy admission under current evidence.
pub fn plan_coordinator_staffing(
    config: &CoordinatorConfig,
    request: &StaffingPlanRequest,
) -> Result<StaffingPlanReceipt, StaffingPolicyError> {
    let (policy, review_requested) = coordinator_recipe_policy(request)?;
    let audit_lane_available = !coordinator_audit_lane_keys(request, &policy).is_empty();
    let evidence = coordinator_route_evidence(config, request, &policy)?;
    let constraints = coordinator_constraints(request)?;
    let mut receipt = plan_staffing(
        &policy,
        request.work_class.as_wire_str(),
        review_requested,
        &evidence,
        &constraints,
    )?;
    if !audit_lane_available {
        record_unauditable_review(&mut receipt, &policy);
    }
    receipt.route_policy_evidence = coordinator_route_policy_evidence(request)?;
    seal_receipt_digest(&mut receipt)?;
    Ok(receipt)
}

/// Names the exact reason an independent-audit class could not be staffed.
///
/// The planner's own escalate reason for the class is replaced, not appended to,
/// so the receipt carries one disposition per unavailable class and states the
/// cause this bridge actually established: the frozen request admits no lane that
/// can run the audit apart from the writer's own lane.
fn record_unauditable_review(receipt: &mut StaffingPlanReceipt, policy: &ModelRolePolicy) {
    for class in &policy.auditor_route_classes {
        let Some(item) = receipt
            .unavailable
            .iter_mut()
            .find(|item| &item.route_class == class)
        else {
            continue;
        };
        item.disposition = UnavailableDispositionKind::Escalate;
        UNAUDITABLE_REVIEW_REASON.clone_into(&mut item.reason);
    }
}

/// Enforces one staffing plan receipt against the compiled coordinator
/// candidate.
///
/// The receipt is the only source of authorized routes for the plan, so this
/// is the structural form of "no silent substitution". Each compiled lane is
/// bound to the receipt lane that staffed the same *route*, never to a
/// position: the coordinator sorts its lanes by priority, work unit, role and
/// route key, so a positional comparison would compare a writer against an
/// auditor whenever priorities differ. Binding by route identity is also what
/// stops a writer route from being reused as its own review lane: a lane that
/// selected a route no receipt lane staffed is refused, and a lane can claim a
/// receipted route only once, so the audit route cannot be run twice or run in
/// the writer's place.
///
/// Coverage is checked in both directions, which is the point. A compiled lane
/// running an unstaffed route is refused, and a receipted route no compiled lane
/// runs is refused too — a receipt lane that no lane and no attempt would ever
/// dispatch is a trailing entry that would read as satisfied independent review
/// while nothing reviews anything. The plan's privacy class must equal the
/// receipt's ceiling and lane budgets may not exceed the receipt's effective plan
/// budget.
///
/// The receipt's integrity is re-bound here through [`verify_receipt_digest`],
/// so a receipt that did not survive its persistence boundary fails closed.
///
/// # Errors
///
/// Returns the receipt or contract rejection describing the first compiled lane
/// the receipt does not authorize, the receipted route no compiled lane runs, or
/// the repeated claim of one receipted route.
pub fn enforce_plan_receipt(
    receipt: &StaffingPlanReceipt,
    candidate: &StaffingPlanCandidate,
) -> Result<(), StaffingPolicyError> {
    verify_receipt_digest(receipt)?;
    if candidate.privacy_class != receipt.privacy_ceiling {
        return Err(StaffingPolicyError::Contract(
            "planned privacy class does not match the staffing plan ceiling".to_owned(),
        ));
    }
    let mut claimed = vec![false; receipt.lanes.len()];
    for planned in &candidate.lanes {
        let Some(selected) = planned.routing.selected.as_ref() else {
            return Err(StaffingPolicyError::Contract(
                "planned lane selected no route; the staffing plan receipt authorizes no substitution"
                    .to_owned(),
            ));
        };
        let Some(position) = receipt
            .lanes
            .iter()
            .position(|staffed| &staffed.route == selected)
        else {
            return Err(StaffingPolicyError::Contract(format!(
                "planned lane selected a route the staffing plan receipt did not staff; the receipt authorizes {} staffed route(s) and this one is not among them",
                receipt.lanes.len()
            )));
        };
        let staffed = &receipt.lanes[position];
        if claimed[position] {
            return Err(StaffingPolicyError::Contract(format!(
                "the staffing plan receipt authorizes one {} route per lane; two compiled lanes claimed it",
                staffed.role
            )));
        }
        claimed[position] = true;
        let Some(route_evidence) = receipt
            .route_policy_evidence
            .iter()
            .find(|evidence| &evidence.route == selected)
        else {
            return Err(StaffingPolicyError::Contract(
                "planned route has no owner-supplied route policy evidence in the staffing receipt"
                    .to_owned(),
            ));
        };
        if !route_evidence.route_classes.contains(&staffed.route_class) {
            return Err(StaffingPolicyError::Contract(
                "staffed route class is not present in the route owner's capability evidence"
                    .to_owned(),
            ));
        }
        if !route_evidence
            .privacy_classes
            .contains(&candidate.privacy_class)
        {
            return Err(StaffingPolicyError::Contract(
                "staffed route does not admit the plan's privacy class".to_owned(),
            ));
        }
        planned.budget.is_within(&receipt.budget).map_err(|error| {
            StaffingPolicyError::Contract(format!("planned lane budget: {error}"))
        })?;
    }
    if let Some(staffed) = claimed
        .iter()
        .position(|claimed| !claimed)
        .map(|position| &receipt.lanes[position])
    {
        return Err(StaffingPolicyError::Contract(format!(
            "the staffing plan receipt staffed a {} route for {} that this plan does not run; a receipted independent review lane is never dropped",
            staffed.role, staffed.route_class
        )));
    }
    Ok(())
}
