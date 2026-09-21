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
//! Pure and deterministic: no threads, no store, no provider execution, no
//! credential handling. Unavailable route classes yield explicit persisted
//! defer/degrade/escalate dispositions; provider switching mid-attempt is
//! denied unless an explicit receipted policy-authorized degradation binds
//! the continuation before it proceeds.

use eliot_agent_api::{BudgetEnvelope, RouteFingerprint};
use eliot_security_contracts::PrivacyClass;
use serde::{Deserialize, Serialize};
use thiserror::Error;

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

/// Built-in decision presets (I3.6). Each is a decision policy, never a
/// provider percentage split.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum StaffingPreset {
    Economy,
    Balanced,
    Assurance,
    Research,
    Incident,
}

impl StaffingPreset {
    /// Canonical wire spelling.
    #[must_use]
    pub const fn as_wire_str(self) -> &'static str {
        match self {
            Self::Economy => "economy",
            Self::Balanced => "balanced",
            Self::Assurance => "assurance",
            Self::Research => "research",
            Self::Incident => "incident",
        }
    }
}

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
    pub budget: BudgetEnvelope,
    pub privacy_ceiling: PrivacyClass,
    pub evidence_refs: Vec<String>,
    /// Canonical-JSON SHA-256 over the receipt body (all fields above).
    pub receipt_digest: String,
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
/// The writer is selected from worker route classes; the auditor (when the
/// preset or task requires independent review) is selected only from
/// auditor route classes with cross-family independence, quota/capacity, and
/// privacy admission. An unavailable audit class yields an explicit
/// escalate disposition: same-family and paid fallbacks are rejected, never
/// silently substituted. Every unavailable policy route class (including the
/// non-executing Dreamer classes) yields a persisted defer/degrade/escalate
/// disposition.
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

    let writer = select_writer(policy, evidence)?;
    let mut lanes = vec![writer.clone()];
    let mut unavailable = Vec::new();

    if audit_required {
        match select_independent_auditor(policy, evidence, &writer) {
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
    evidence_refs.sort();
    evidence_refs.dedup();

    let mut receipt = StaffingPlanReceipt {
        preset: policy.preset,
        task_class: task_class.to_owned(),
        lanes,
        unavailable,
        budget: constraints.budget.clone(),
        privacy_ceiling: constraints.privacy_ceiling,
        evidence_refs,
        receipt_digest: String::new(),
    };
    let body = serde_json::to_value(&receipt)
        .map_err(|error| StaffingPolicyError::Contract(format!("receipt body: {error}")))?;
    let mut body_map = body
        .as_object()
        .cloned()
        .ok_or_else(|| StaffingPolicyError::Contract("receipt body shape".to_owned()))?;
    body_map.remove("receipt_digest");
    receipt.receipt_digest = digest_receipt_body(&serde_json::Value::Object(body_map))?;
    Ok(receipt)
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

fn select_writer(
    policy: &ModelRolePolicy,
    evidence: &[RouteClassEvidence],
) -> Result<StaffedLane, StaffingPolicyError> {
    for class in &policy.worker_route_classes {
        if let Some(record) = evidence.iter().find(|item| &item.route_class == class) {
            for candidate in &record.candidates {
                if eligible_candidate(candidate) {
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
    }
    Err(StaffingPolicyError::NoWriterRoute(
        "no eligible writer route under current evidence, quota, capacity, and privacy".to_owned(),
    ))
}

fn select_independent_auditor(
    policy: &ModelRolePolicy,
    evidence: &[RouteClassEvidence],
    writer: &StaffedLane,
) -> Result<StaffedLane, String> {
    let writer_family = writer_family(evidence, writer);
    let mut specific_reason: Option<String> = None;
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
