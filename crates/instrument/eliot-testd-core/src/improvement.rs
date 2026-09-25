//! Durable, owner-stamped improvement experiment contracts retained by TestD.
//!
//! TestD owns experiment execution and its raw evidence. It does not decide
//! whether an improvement is admissible or activate a generation. This module
//! stores the immutable candidate/intake declaration before execution, exact
//! operation identities, terminal evaluator evidence, and a candidate-only
//! canary/rollback handoff disposition. Governor maintenance remains the
//! admission owner; Kernel/#11 remains the future canary/promotion owner.

use std::collections::{BTreeMap, BTreeSet};

use eliot_contracts::{StateFence, canonical_json_bytes, sha256_hex};
use eliot_instrument_api::{
    EvidenceCoverage, EvidenceFreshness, InstrumentInvocation, VerificationOutcome,
};
use eliot_protocol::RequestIdentity;
use serde::{Deserialize, Serialize};

use super::{
    TESTD_PRODUCTIVE_PROFILE, TestdError, TestdProcessToolIntent, TestdSourceObservation,
    is_binding_digest, testd_profile_binding, validate_text,
};

/// Stable schema for the durable TestD improvement experiment record.
pub const IMPROVEMENT_EXPERIMENT_SCHEMA: &str = "eliot.testd.improvement-experiment.v1";
/// Only effect ceiling admitted by the candidate path.
pub const IMPROVEMENT_EFFECT_CEILING: &str = "candidate-only";
/// Governor maintenance proposal owner.
pub const IMPROVEMENT_OWNER: &str = "governor-maintenance-G-19";
/// Authenticated owner route that may issue the maintenance admission receipt.
pub const GOVERNOR_IMPROVEMENT_OWNER_OPERATION: &str = "eliot.kernel.governor-improvement-submit";
/// TestD experiment execution and measurement owner.
pub const IMPROVEMENT_TESTD_OWNER: &str = "eliot-testd-20";
/// Independent Instrument verifier owner.
pub const IMPROVEMENT_VERIFIER_OWNER: &str = "eliot-verifier-20-1111";
/// Kernel generation/canary handoff owner.
pub const IMPROVEMENT_KERNEL_OWNER: &str = "eliot-kernel-canary-11";
/// Product activation remains outside this candidate pipeline.
pub const IMPROVEMENT_PRODUCT_OWNER: &str = "eliot-product-activation-11";

/// Closed risk class for an improvement experiment.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImprovementRiskClass {
    /// Reversible, bounded, and effect-free until an external canary owner acts.
    BoundedReversible,
}

/// Closed privacy class for candidate and evidence material.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImprovementPrivacyClass {
    /// Material remains on the local machine.
    LocalOnly,
    /// A separately admitted external provider may receive the bounded bundle.
    GovernedExternal,
}

/// Predeclared falsifiable mechanism for one candidate experiment.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MechanismDeclaration {
    /// Stable mechanism identity.
    pub mechanism_id: String,
    /// Falsifiable hypothesis tested by the experiment.
    pub hypothesis: String,
    /// Causal link from the intervention to the measured delta.
    pub causal_link: String,
}

impl MechanismDeclaration {
    fn validate(&self) -> Result<(), TestdError> {
        for (value, field) in [
            (&self.mechanism_id, "mechanism_id"),
            (&self.hypothesis, "hypothesis"),
            (&self.causal_link, "causal_link"),
        ] {
            validate_text(value, field)?;
        }
        Ok(())
    }
}

/// Exact invalidation and repair contract declared before outcomes exist.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RollbackContract {
    /// Owner of rollback and forward repair.
    pub owner_id: String,
    /// Rollback/disable operation or recipe reference.
    pub rollback_ref: String,
    /// Forward-repair operation or recipe reference.
    pub forward_repair_ref: String,
    /// Canonical sorted invalidation set covered by this contract.
    pub invalidation_set: Vec<String>,
    /// Digest over the canonical invalidation set.
    pub invalidation_set_digest: String,
}

impl RollbackContract {
    /// Builds and validates a rollback contract over an exact set.
    pub fn new(
        owner_id: impl Into<String>,
        rollback_ref: impl Into<String>,
        forward_repair_ref: impl Into<String>,
        mut invalidation_set: Vec<String>,
    ) -> Result<Self, TestdError> {
        invalidation_set.sort();
        if invalidation_set.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(TestdError::Invalid {
                field: "rollback.invalidation_set",
                reason: "must not contain duplicate identities",
            });
        }
        let contract = Self {
            owner_id: owner_id.into(),
            rollback_ref: rollback_ref.into(),
            forward_repair_ref: forward_repair_ref.into(),
            invalidation_set_digest: digest_strings(&invalidation_set)?,
            invalidation_set,
        };
        contract.validate()?;
        Ok(contract)
    }

    /// Validates owner, repair routes, and the exact invalidation-set digest.
    pub fn validate(&self) -> Result<(), TestdError> {
        validate_text(&self.owner_id, "rollback.owner_id")?;
        validate_text(&self.rollback_ref, "rollback.rollback_ref")?;
        validate_text(&self.forward_repair_ref, "rollback.forward_repair_ref")?;
        if self.invalidation_set.is_empty()
            || self
                .invalidation_set
                .iter()
                .any(|value| value.trim().is_empty())
            || self
                .invalidation_set
                .windows(2)
                .any(|pair| pair[0] >= pair[1])
        {
            return Err(TestdError::Invalid {
                field: "rollback.invalidation_set",
                reason: "must be non-empty, sorted, and unique",
            });
        }
        if self.invalidation_set_digest != digest_strings(&self.invalidation_set)? {
            return Err(TestdError::InvalidBinding);
        }
        Ok(())
    }
}

/// A new evidence/input discriminator for a materially repeated experiment.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImprovementDiscriminator {
    /// Stable discriminator identity.
    pub discriminator_id: String,
    /// Existing candidate evidence/input reference that supplies the new signal.
    pub evidence_ref: String,
    /// Canonical owner evidence record that proves the signal is new.  A
    /// discriminator without this record is not progress evidence.
    #[serde(default)]
    pub canonical_evidence_id: Option<String>,
    /// Digest of the canonical owner evidence record.
    #[serde(default)]
    pub canonical_evidence_sha256: Option<String>,
}

impl ImprovementDiscriminator {
    fn validate(&self) -> Result<(), TestdError> {
        validate_text(&self.discriminator_id, "discriminator_id")?;
        validate_text(&self.evidence_ref, "discriminator.evidence_ref")?;
        match (&self.canonical_evidence_id, &self.canonical_evidence_sha256) {
            (Some(id), Some(digest)) => {
                validate_text(id, "discriminator.canonical_evidence_id")?;
                if !is_binding_digest(digest) {
                    return Err(TestdError::InvalidBinding);
                }
            }
            (None, None) => {}
            _ => return Err(TestdError::InvalidBinding),
        }
        Ok(())
    }

    /// Whether this discriminator names a genuinely new canonical record.
    #[must_use]
    pub fn has_new_canonical_evidence(&self) -> bool {
        self.canonical_evidence_id.is_some() && self.canonical_evidence_sha256.is_some()
    }
}

/// Candidate/intake material submitted before a TestD experiment starts.
///
/// Kernel does not trust the caller for fence, generation, budget, deadline,
/// operation identity, declaration owner, or declaration timestamp. Those
/// values are added to the immutable [`ImprovementProposal`] only after the
/// authenticated Kernel owner re-derives them from the current frame and
/// registered profile.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImprovementExperimentRequest {
    /// Exact `ImprovementCandidate` identity.
    pub candidate_id: String,
    /// Exact candidate revision.
    pub candidate_revision: u64,
    /// Canonical JSON bytes of the actual `eliot-improvement` candidate.
    pub candidate_json: String,
    /// SHA-256 of `candidate_json`.
    pub candidate_digest: String,
    /// Exact safe-boundary brief identity produced by intake.
    pub intake_brief_id: String,
    /// Independent evaluator identity predeclared by the Governor intake.
    pub evaluator_id: String,
    /// Canonical JSON bytes of the actual improvement brief.
    pub intake_brief_json: String,
    /// SHA-256 of `intake_brief_json`.
    pub intake_brief_digest: String,
    /// Candidate project identity.
    pub project_id: String,
    /// Candidate target surface, verified against candidate JSON at consumption.
    pub target_surface: String,
    /// Exact delivery target from the candidate.
    pub delivery_target: String,
    /// Exact canary plan from the candidate.
    pub canary_plan: String,
    /// Exact stop condition from the candidate.
    pub stop_condition: String,
    /// Mechanism registered before any outcome exists.
    pub mechanism: MechanismDeclaration,
    /// Expected measurable delta narrative.
    pub expected_delta: String,
    /// Candidate baseline metrics that must contain these expected deltas.
    pub expected_metric_names: Vec<String>,
    /// Exact minimum expected deltas for those metrics.
    pub expected_deltas: BTreeMap<String, f64>,
    /// Candidate counter-metric names that may not regress.
    pub counter_metric_names: Vec<String>,
    /// Closed risk ceiling.
    pub risk_class: ImprovementRiskClass,
    /// Exact effect ceiling; this path cannot mutate or activate product state.
    pub effect_ceiling: String,
    /// Closed privacy class.
    pub privacy_class: ImprovementPrivacyClass,
    /// Matched budget ledger selected at intake.
    pub budget_ledger_ref: String,
    /// Canonical JSON bytes of the complete intake budget proof.
    pub budget_proof_json: String,
    /// Canonical digest of the complete intake budget proof.
    pub budget_proof_digest: String,
    /// Rollback and forward-repair contract.
    pub rollback: RollbackContract,
    /// Optional new discriminator for a repeated experiment.
    pub new_discriminator: Option<ImprovementDiscriminator>,
}

impl ImprovementExperimentRequest {
    /// Validates the pre-execution request and all embedded digests.
    pub fn validate(&self) -> Result<(), TestdError> {
        for (value, field) in [
            (&self.candidate_id, "candidate_id"),
            (&self.intake_brief_id, "intake_brief_id"),
            (&self.evaluator_id, "evaluator_id"),
            (&self.project_id, "project_id"),
            (&self.target_surface, "target_surface"),
            (&self.delivery_target, "delivery_target"),
            (&self.canary_plan, "canary_plan"),
            (&self.stop_condition, "stop_condition"),
            (&self.expected_delta, "expected_delta"),
            (&self.effect_ceiling, "effect_ceiling"),
            (&self.budget_ledger_ref, "budget_ledger_ref"),
        ] {
            validate_text(value, field)?;
        }
        if self.effect_ceiling != IMPROVEMENT_EFFECT_CEILING {
            return Err(TestdError::InvalidBinding);
        }
        if self.candidate_digest != canonical_json_digest(&self.candidate_json)? {
            return Err(TestdError::InvalidBinding);
        }
        if self.intake_brief_digest != canonical_json_digest(&self.intake_brief_json)? {
            return Err(TestdError::InvalidBinding);
        }
        if self.budget_proof_digest != canonical_json_digest(&self.budget_proof_json)? {
            return Err(TestdError::InvalidBinding);
        }
        validate_candidate_and_brief_json(self)?;
        if !is_binding_digest(&self.budget_proof_digest) {
            return Err(TestdError::Invalid {
                field: "budget_proof_digest",
                reason: "must be a lowercase SHA-256 digest",
            });
        }
        self.mechanism.validate()?;
        self.rollback.validate()?;
        if self.expected_metric_names.is_empty()
            || self
                .expected_metric_names
                .iter()
                .any(|name| name.trim().is_empty())
            || self
                .expected_metric_names
                .windows(2)
                .any(|pair| pair[0] >= pair[1])
            || self.expected_metric_names.len() != self.expected_deltas.len()
            || self
                .expected_metric_names
                .iter()
                .any(|name| !self.expected_deltas.contains_key(name))
            || self
                .expected_deltas
                .keys()
                .any(|name| name.trim().is_empty())
            || self
                .expected_deltas
                .values()
                .any(|value| !value.is_finite())
            || self
                .counter_metric_names
                .windows(2)
                .any(|pair| pair[0] >= pair[1])
            || self
                .counter_metric_names
                .iter()
                .any(|name| name.trim().is_empty())
        {
            return Err(TestdError::Invalid {
                field: "expected_deltas",
                reason: "must bind a sorted non-empty finite metric set",
            });
        }
        if let Some(discriminator) = &self.new_discriminator {
            discriminator.validate()?;
            if !discriminator.has_new_canonical_evidence() {
                return Err(TestdError::Invalid {
                    field: "new_discriminator",
                    reason: "a repeated experiment requires a new canonical evidence record",
                });
            }
        }
        Ok(())
    }
}

/// Exact target and current runtime binding for one TestD experiment.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImprovementExperimentTarget {
    /// Project identity bound by the authenticated TestD submission.
    pub project_id: String,
    /// Task identity from the admitted request.
    pub task_id: String,
    /// WorkScope identity from the admitted request.
    pub work_scope_id: String,
    /// Instrument target, never free-form shell text.
    pub capability_ref: String,
    /// Candidate target surface retained in the owner-stamped target.
    pub target_surface: String,
    /// Instrument-declared scope.
    pub declared_scope: String,
    /// Exact Instrument request identity.
    pub invocation_id: String,
    /// Registered Instrument profile.
    pub profile: String,
    /// Input artifacts bound to the invocation.
    pub input_artifact_ids: Vec<String>,
    /// Kernel-selected canonical source root.
    pub source_root: String,
    /// Kernel-derived source identity digest.
    pub source_identity: String,
    /// Kernel-derived runtime/toolchain identity digest.
    pub runtime_identity: String,
    /// Kernel-derived data/input identity digest.
    pub data_identity: String,
}

impl ImprovementExperimentTarget {
    fn validate(&self) -> Result<(), TestdError> {
        for (value, field) in [
            (&self.project_id, "target.project_id"),
            (&self.task_id, "target.task_id"),
            (&self.work_scope_id, "target.work_scope_id"),
            (&self.capability_ref, "target.capability_ref"),
            (&self.target_surface, "target.target_surface"),
            (&self.declared_scope, "target.declared_scope"),
            (&self.invocation_id, "target.invocation_id"),
            (&self.profile, "target.profile"),
            (&self.source_root, "target.source_root"),
            (&self.source_identity, "target.source_identity"),
            (&self.runtime_identity, "target.runtime_identity"),
            (&self.data_identity, "target.data_identity"),
        ] {
            validate_text(value, field)?;
        }
        if self.profile != TESTD_PRODUCTIVE_PROFILE
            || self.input_artifact_ids.is_empty()
            || !is_binding_digest(&self.source_identity)
            || !is_binding_digest(&self.runtime_identity)
            || !is_binding_digest(&self.data_identity)
        {
            return Err(TestdError::InvalidBinding);
        }
        Ok(())
    }
}

/// Exact registered-profile budget and deadline derived by Kernel.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImprovementExperimentBudget {
    /// Matched budget-equivalence ledger.
    pub budget_ledger_ref: String,
    /// Digest of the intake budget proof.
    pub budget_proof_digest: String,
    /// Selected toolchain identity.
    pub toolchain: String,
    /// Installed nextest executable digest.
    pub tool_artifact_digest: String,
    /// Wall timeout from the closed TestD profile.
    pub wall_timeout_ms: u64,
    /// CPU timeout from the closed TestD profile.
    pub cpu_time_ms: u64,
    /// Memory ceiling from the closed TestD profile.
    pub memory_bytes: u64,
    /// Stdout capture ceiling.
    pub stdout_bytes: u64,
    /// Stderr capture ceiling.
    pub stderr_bytes: u64,
    /// Descendant ceiling.
    pub max_descendants: u32,
    /// Effective request/profile deadline.
    pub deadline_unix_ms: u64,
}

impl ImprovementExperimentBudget {
    fn validate(&self, declared_at_unix_ms: u64) -> Result<(), TestdError> {
        validate_text(&self.budget_ledger_ref, "budget.budget_ledger_ref")?;
        validate_text(&self.toolchain, "budget.toolchain")?;
        if !is_binding_digest(&self.budget_proof_digest)
            || !is_binding_digest(&self.tool_artifact_digest)
            || self.wall_timeout_ms == 0
            || self.cpu_time_ms == 0
            || self.memory_bytes == 0
            || self.stdout_bytes == 0
            || self.stderr_bytes == 0
            || self.max_descendants == 0
            || self.deadline_unix_ms <= declared_at_unix_ms
        {
            return Err(TestdError::InvalidBinding);
        }
        Ok(())
    }
}

/// One exact operation identity in the improvement lifecycle.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImprovementOperationKind {
    /// Candidate proposal.
    Propose,
    /// Governor admission to bounded experiment.
    AdmitExperiment,
    /// TestD execution.
    ExecuteExperiment,
    /// TestD measurement.
    Measure,
    /// Independent Instrument evaluation.
    Evaluate,
    /// Governor post-evaluation admission.
    AdmitCanary,
    /// Kernel canary handoff.
    CanaryHandoff,
    /// Product activation, never executed here.
    Promote,
    /// Owner-bound rollback or forward repair.
    Rollback,
}

/// Operation identity plus its fixed current owner.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImprovementOperationBinding {
    /// Operation stage.
    pub kind: ImprovementOperationKind,
    /// Durable operation identity.
    pub operation_id: String,
    /// Current named owner.
    pub owner_id: String,
}

fn fixed_owner(kind: ImprovementOperationKind, rollback_owner: &str) -> &'static str {
    match kind {
        ImprovementOperationKind::Propose
        | ImprovementOperationKind::AdmitExperiment
        | ImprovementOperationKind::AdmitCanary => IMPROVEMENT_OWNER,
        ImprovementOperationKind::ExecuteExperiment | ImprovementOperationKind::Measure => {
            IMPROVEMENT_TESTD_OWNER
        }
        ImprovementOperationKind::Evaluate => IMPROVEMENT_VERIFIER_OWNER,
        ImprovementOperationKind::CanaryHandoff => IMPROVEMENT_KERNEL_OWNER,
        ImprovementOperationKind::Promote => IMPROVEMENT_PRODUCT_OWNER,
        ImprovementOperationKind::Rollback => {
            let _ = rollback_owner;
            "rollback-owner-bound"
        }
    }
}

/// Complete set of distinct improvement operation identities.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImprovementOperationSet {
    /// Ordered operation bindings.
    pub operations: Vec<ImprovementOperationBinding>,
}

impl ImprovementOperationSet {
    fn from_base(base: &str, rollback_owner: &str) -> Result<Self, TestdError> {
        const KINDS: [ImprovementOperationKind; 9] = [
            ImprovementOperationKind::Propose,
            ImprovementOperationKind::AdmitExperiment,
            ImprovementOperationKind::ExecuteExperiment,
            ImprovementOperationKind::Measure,
            ImprovementOperationKind::Evaluate,
            ImprovementOperationKind::AdmitCanary,
            ImprovementOperationKind::CanaryHandoff,
            ImprovementOperationKind::Promote,
            ImprovementOperationKind::Rollback,
        ];
        let operations = KINDS
            .iter()
            .map(|kind| ImprovementOperationBinding {
                kind: *kind,
                operation_id: format!("{base}:improvement:{kind:?}").to_ascii_lowercase(),
                owner_id: if *kind == ImprovementOperationKind::Rollback {
                    rollback_owner.to_owned()
                } else {
                    fixed_owner(*kind, rollback_owner).to_owned()
                },
            })
            .collect();
        let set = Self { operations };
        set.validate(rollback_owner)?;
        Ok(set)
    }

    /// Returns the durable identity for one exact stage.
    pub fn operation_id(&self, kind: ImprovementOperationKind) -> Option<&str> {
        self.operations
            .iter()
            .find(|operation| operation.kind == kind)
            .map(|operation| operation.operation_id.as_str())
    }

    fn validate(&self, rollback_owner: &str) -> Result<(), TestdError> {
        let mut kinds = BTreeSet::new();
        let mut ids = BTreeSet::new();
        for operation in &self.operations {
            validate_text(&operation.operation_id, "operation_id")?;
            if !kinds.insert(operation.kind) || !ids.insert(operation.operation_id.as_str()) {
                return Err(TestdError::Invalid {
                    field: "improvement_operations",
                    reason: "stage and operation identities must be distinct",
                });
            }
            let expected = if operation.kind == ImprovementOperationKind::Rollback {
                rollback_owner
            } else {
                fixed_owner(operation.kind, rollback_owner)
            };
            if operation.owner_id != expected {
                return Err(TestdError::InvalidBinding);
            }
        }
        if kinds.len() != 9 {
            return Err(TestdError::Invalid {
                field: "improvement_operations",
                reason: "all nine lifecycle stages must be present",
            });
        }
        Ok(())
    }
}

/// Stable schema for the typed, immutable experiment plan retained before
/// execution.  The plan is the canonical join consumed by the verifier; a
/// terminal caller cannot replace it with a metric table or a new timestamp.
pub const IMPROVEMENT_EXPERIMENT_PLAN_SCHEMA: &str = "eliot.testd.improvement-experiment-plan.v1";

/// Canonical experiment plan retained beside the durable proposal.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImprovementExperimentPlan {
    pub schema: String,
    pub plan_id: String,
    pub proposal_id: String,
    pub experiment_id: String,
    pub candidate_id: String,
    pub candidate_digest: String,
    pub intake_brief_id: String,
    pub intake_brief_digest: String,
    pub budget_ledger_ref: String,
    pub budget_proof_digest: String,
    pub evidence_refs: Vec<String>,
    pub work_scope_id: String,
    pub target: ImprovementExperimentTarget,
    pub state_fence: StateFence,
    pub generation: u64,
    pub evaluator_id: String,
    pub expected_metric_names: Vec<String>,
    pub expected_deltas: BTreeMap<String, f64>,
    pub counter_metric_names: Vec<String>,
    pub rollback: RollbackContract,
    pub canary: ImprovementCanaryIdentity,
    pub owner_admission_receipt_sha256: String,
    pub declared_at_unix_ms: u64,
    pub plan_digest: String,
}

impl ImprovementExperimentPlan {
    /// Validates the immutable plan and all owner-derived joins.
    pub fn validate(&self) -> Result<(), TestdError> {
        if self.schema != IMPROVEMENT_EXPERIMENT_PLAN_SCHEMA
            || self.generation == 0
            || self.declared_at_unix_ms == 0
            || self.state_fence.resource_generation.value() != self.generation
            || self.work_scope_id != self.target.work_scope_id
            || self.canary.work_scope_id != self.work_scope_id
            || self.canary.generation != self.generation
            || self.canary.state_fence != self.state_fence
            || self.canary.owner_id != IMPROVEMENT_KERNEL_OWNER
            || self.canary.effect_ceiling != IMPROVEMENT_EFFECT_CEILING
            || !is_binding_digest(&self.owner_admission_receipt_sha256)
            || self.evidence_refs.is_empty()
            || self
                .evidence_refs
                .iter()
                .any(|value| value.trim().is_empty() || value.chars().any(char::is_control))
            || self.evidence_refs.windows(2).any(|pair| pair[0] >= pair[1])
        {
            return Err(TestdError::InvalidBinding);
        }
        for (value, field) in [
            (&self.plan_id, "plan_id"),
            (&self.proposal_id, "plan.proposal_id"),
            (&self.experiment_id, "plan.experiment_id"),
            (&self.candidate_id, "plan.candidate_id"),
            (&self.candidate_digest, "plan.candidate_digest"),
            (&self.intake_brief_id, "plan.intake_brief_id"),
            (&self.intake_brief_digest, "plan.intake_brief_digest"),
            (&self.budget_ledger_ref, "plan.budget_ledger_ref"),
            (&self.budget_proof_digest, "plan.budget_proof_digest"),
            (&self.evaluator_id, "plan.evaluator_id"),
        ] {
            validate_text(value, field)?;
        }
        if !is_binding_digest(&self.candidate_digest)
            || !is_binding_digest(&self.intake_brief_digest)
            || !is_binding_digest(&self.budget_proof_digest)
            || self.expected_metric_names.is_empty()
            || self.expected_metric_names.len() != self.expected_deltas.len()
            || self
                .expected_metric_names
                .windows(2)
                .any(|pair| pair[0] >= pair[1])
            || self
                .counter_metric_names
                .windows(2)
                .any(|pair| pair[0] >= pair[1])
            || self
                .expected_metric_names
                .iter()
                .any(|name| self.counter_metric_names.contains(name))
            || self
                .expected_deltas
                .values()
                .any(|value| !value.is_finite())
        {
            return Err(TestdError::InvalidBinding);
        }
        for (value, field) in [
            (&self.canary.canary_id, "plan.canary_id"),
            (&self.canary.operation_id, "plan.canary.operation_id"),
            (&self.canary.owner_id, "plan.canary.owner_id"),
            (&self.canary.work_scope_id, "plan.canary.work_scope_id"),
            (&self.canary.effect_ceiling, "plan.canary.effect_ceiling"),
        ] {
            validate_text(value, field)?;
        }
        self.target.validate()?;
        self.state_fence
            .validate()
            .map_err(|_| TestdError::InvalidBinding)?;
        self.rollback.validate()?;
        if self.plan_digest != self.compute_digest()? {
            return Err(TestdError::InvalidBinding);
        }
        Ok(())
    }

    fn compute_digest(&self) -> Result<String, TestdError> {
        #[derive(Serialize)]
        struct Preimage<'a> {
            schema: &'a str,
            plan_id: &'a str,
            proposal_id: &'a str,
            experiment_id: &'a str,
            candidate_id: &'a str,
            candidate_digest: &'a str,
            intake_brief_id: &'a str,
            intake_brief_digest: &'a str,
            budget_ledger_ref: &'a str,
            budget_proof_digest: &'a str,
            evidence_refs: &'a [String],
            work_scope_id: &'a str,
            target: &'a ImprovementExperimentTarget,
            state_fence: &'a StateFence,
            generation: u64,
            evaluator_id: &'a str,
            expected_metric_names: &'a [String],
            expected_deltas: &'a BTreeMap<String, f64>,
            counter_metric_names: &'a [String],
            rollback: &'a RollbackContract,
            canary: &'a ImprovementCanaryIdentity,
            owner_admission_receipt_sha256: &'a str,
            declared_at_unix_ms: u64,
        }
        typed_digest(&Preimage {
            schema: &self.schema,
            plan_id: &self.plan_id,
            proposal_id: &self.proposal_id,
            experiment_id: &self.experiment_id,
            candidate_id: &self.candidate_id,
            candidate_digest: &self.candidate_digest,
            intake_brief_id: &self.intake_brief_id,
            intake_brief_digest: &self.intake_brief_digest,
            budget_ledger_ref: &self.budget_ledger_ref,
            budget_proof_digest: &self.budget_proof_digest,
            evidence_refs: &self.evidence_refs,
            work_scope_id: &self.work_scope_id,
            target: &self.target,
            state_fence: &self.state_fence,
            generation: self.generation,
            evaluator_id: &self.evaluator_id,
            expected_metric_names: &self.expected_metric_names,
            expected_deltas: &self.expected_deltas,
            counter_metric_names: &self.counter_metric_names,
            rollback: &self.rollback,
            canary: &self.canary,
            owner_admission_receipt_sha256: &self.owner_admission_receipt_sha256,
            declared_at_unix_ms: self.declared_at_unix_ms,
        })
    }
}

/// Stable identity of the future Kernel canary/generation owner.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImprovementCanaryIdentity {
    pub canary_id: String,
    pub operation_id: String,
    pub owner_id: String,
    pub work_scope_id: String,
    pub generation: u64,
    pub state_fence: StateFence,
    pub effect_ceiling: String,
}

/// Closed external activation/effect result.  A canary handoff without this
/// record is never treated as activation evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImprovementActivationStatus {
    NotAttempted,
    Attempted,
    Applied,
    Unknown,
    Rejected,
}

/// Owner-issued receipt for one external activation/effect attempt.
///
/// The receipt is intentionally separate from the candidate admission receipt:
/// it binds the later external owner, effect operation, canonical fact, and
/// authenticated request identity. A caller-provided status or arbitrary text
/// cannot stand in for this owner evidence.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImprovementExternalOwnerReceipt {
    pub schema: String,
    pub owner_id: String,
    pub owner_principal_digest: String,
    pub owner_module_id: String,
    pub owner_artifact_id: String,
    pub owner_session_epoch: u64,
    pub request_identity_sha256: String,
    pub effect_operation_id: String,
    pub canonical_fact_id: String,
    pub effect_receipt_sha256: String,
    pub issued_at_unix_ms: u64,
    pub receipt_sha256: String,
}

impl ImprovementExternalOwnerReceipt {
    /// Stable external-owner receipt schema.
    pub const SCHEMA: &'static str = "eliot.improvement.external-owner-receipt.v1";

    fn compute_digest(&self) -> Result<String, TestdError> {
        typed_digest(&(
            &self.schema,
            &self.owner_id,
            &self.owner_principal_digest,
            &self.owner_module_id,
            &self.owner_artifact_id,
            self.owner_session_epoch,
            &self.request_identity_sha256,
            &self.effect_operation_id,
            &self.canonical_fact_id,
            &self.effect_receipt_sha256,
            self.issued_at_unix_ms,
        ))
    }

    /// Issues an external-owner receipt over an authenticated effect request.
    #[allow(clippy::too_many_arguments)]
    pub fn issue(
        identity: &RequestIdentity,
        owner_id: &str,
        owner_principal_digest: &str,
        owner_module_id: &str,
        owner_artifact_id: &str,
        owner_session_epoch: u64,
        effect_operation_id: &str,
        canonical_fact_id: &str,
        effect_receipt_sha256: &str,
        issued_at_unix_ms: u64,
    ) -> Result<Self, TestdError> {
        identity
            .validate()
            .map_err(|_| TestdError::InvalidBinding)?;
        validate_text(owner_id, "external_owner.owner_id")?;
        validate_text(
            owner_principal_digest,
            "external_owner.owner_principal_digest",
        )?;
        validate_text(owner_module_id, "external_owner.owner_module_id")?;
        validate_text(owner_artifact_id, "external_owner.owner_artifact_id")?;
        validate_text(effect_operation_id, "external_owner.effect_operation_id")?;
        if owner_id != IMPROVEMENT_KERNEL_OWNER
            || !is_binding_digest(owner_principal_digest)
            || !is_binding_digest(canonical_fact_id)
            || !is_binding_digest(effect_receipt_sha256)
            || owner_session_epoch == 0
            || issued_at_unix_ms == 0
        {
            return Err(TestdError::InvalidBinding);
        }
        let mut receipt = Self {
            schema: Self::SCHEMA.to_owned(),
            owner_id: owner_id.to_owned(),
            owner_principal_digest: owner_principal_digest.to_owned(),
            owner_module_id: owner_module_id.to_owned(),
            owner_artifact_id: owner_artifact_id.to_owned(),
            owner_session_epoch,
            request_identity_sha256: typed_digest(identity)?,
            effect_operation_id: effect_operation_id.to_owned(),
            canonical_fact_id: canonical_fact_id.to_owned(),
            effect_receipt_sha256: effect_receipt_sha256.to_owned(),
            issued_at_unix_ms,
            receipt_sha256: String::new(),
        };
        receipt.receipt_sha256 = receipt.compute_digest()?;
        Ok(receipt)
    }

    fn validate_for(
        &self,
        identity: &RequestIdentity,
        effect_operation_id: &str,
        canonical_fact_id: &str,
        effect_receipt_sha256: &str,
    ) -> Result<(), TestdError> {
        identity
            .validate()
            .map_err(|_| TestdError::InvalidBinding)?;
        if self.schema != Self::SCHEMA
            || self.owner_id != IMPROVEMENT_KERNEL_OWNER
            || !is_binding_digest(&self.owner_principal_digest)
            || self.owner_session_epoch == 0
            || self.request_identity_sha256 != typed_digest(identity)?
            || self.effect_operation_id != effect_operation_id
            || self.canonical_fact_id != canonical_fact_id
            || self.effect_receipt_sha256 != effect_receipt_sha256
            || self.receipt_sha256 != self.compute_digest()?
        {
            return Err(TestdError::InvalidBinding);
        }
        Ok(())
    }
}

/// Typed evidence for one authenticated external activation/effect attempt.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImprovementActivationEvidence {
    pub schema: String,
    pub proposal_id: String,
    pub proposal_digest: String,
    pub canary: ImprovementCanaryIdentity,
    pub attempt_id: String,
    pub effect_operation_id: String,
    pub canonical_fact_id: String,
    pub canonical_fact_sha256: String,
    pub effect_receipt_sha256: String,
    pub effect_request_identity: RequestIdentity,
    pub owner_id: String,
    pub owner_receipt: ImprovementExternalOwnerReceipt,
    pub owner_receipt_sha256: String,
    pub execution_reality: eliot_instrument_api::ExecutionReality,
    pub status: ImprovementActivationStatus,
    pub recorded_at_unix_ms: u64,
}

impl ImprovementActivationEvidence {
    /// Stable schema for activation evidence.
    pub const SCHEMA: &'static str = "eliot.improvement.activation-evidence.v1";

    /// Validates an authenticated external effect record.  Unknown outcomes
    /// are accepted only as an unresolved record; they never authorize retry.
    pub fn validate_for(&self, proposal: &ImprovementProposal) -> Result<(), TestdError> {
        self.effect_request_identity
            .validate()
            .map_err(|_| TestdError::InvalidBinding)?;
        if self.schema != Self::SCHEMA
            || self.proposal_id != proposal.proposal_id
            || self.proposal_digest != proposal.proposal_digest
            || self.canary != proposal.experiment_plan.canary
            || self.owner_id != IMPROVEMENT_KERNEL_OWNER
            || self.owner_id != self.canary.owner_id
            || self.effect_request_identity.request.state_fence != proposal.state_fence
            || self
                .effect_request_identity
                .request
                .metadata
                .task_id
                .as_ref()
                .map(ToString::to_string)
                != Some(proposal.target.task_id.clone())
            || self
                .effect_request_identity
                .request
                .metadata
                .request_id
                .as_str()
                == proposal.target.invocation_id
            || !self.execution_reality.is_live()
            || !is_binding_digest(&self.canonical_fact_id)
            || !is_binding_digest(&self.canonical_fact_sha256)
            || !is_binding_digest(&self.effect_receipt_sha256)
            || !is_binding_digest(&self.owner_receipt_sha256)
            || self.owner_receipt_sha256 != self.owner_receipt.receipt_sha256
        {
            return Err(TestdError::InvalidBinding);
        }
        self.owner_receipt.validate_for(
            &self.effect_request_identity,
            &self.effect_operation_id,
            &self.canonical_fact_id,
            &self.effect_receipt_sha256,
        )?;
        for (value, field) in [
            (&self.canary.canary_id, "activation.canary_id"),
            (&self.canary.operation_id, "activation.operation_id"),
            (&self.canary.owner_id, "activation.owner_id"),
            (&self.canary.work_scope_id, "activation.work_scope_id"),
            (&self.attempt_id, "activation.attempt_id"),
            (&self.effect_operation_id, "activation.effect_operation_id"),
            (&self.owner_id, "activation.owner_id"),
        ] {
            validate_text(value, field)?;
        }
        if self.recorded_at_unix_ms <= proposal.mechanism_receipt.declared_at_unix_ms
            || self.owner_receipt.issued_at_unix_ms > self.recorded_at_unix_ms
            || matches!(self.status, ImprovementActivationStatus::NotAttempted)
        {
            return Err(TestdError::InvalidBinding);
        }
        Ok(())
    }
}

/// Evidence required to reconcile a prior unknown external outcome.  The
/// daemon supplies no caller-authored `WriteReceipt` or terminal outcome; the
/// owner rehydrates the durable sidecar and this typed evidence supplies only
/// a new external attempt bound to a new canonical fact.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImprovementReconciliationEvidence {
    pub schema: String,
    pub proposal_id: String,
    pub proposal_digest: String,
    pub job_id: String,
    pub canonical_fact_id: String,
    pub canonical_fact_sha256: String,
    pub verifier_run_id: String,
    pub evidence_id: String,
    pub committed_receipt_sha256: String,
    pub activation: ImprovementActivationEvidence,
    pub recorded_at_unix_ms: u64,
}

impl ImprovementReconciliationEvidence {
    /// Stable reconciliation evidence schema.
    pub const SCHEMA: &'static str = "eliot.improvement.reconciliation-evidence.v1";

    /// Validates the new attempt and its canonical joins against the retained
    /// proposal. The owner additionally compares the attempt/fact identities
    /// with the prior unknown outcome before committing the transition.
    pub fn validate_for(
        &self,
        proposal: &ImprovementProposal,
        previous: &ImprovementExperimentOutcome,
    ) -> Result<(), TestdError> {
        if self.schema != Self::SCHEMA
            || self.proposal_id != proposal.proposal_id
            || self.proposal_digest != proposal.proposal_digest
            || self.job_id != proposal.experiment_id
            || !is_binding_digest(&self.canonical_fact_id)
            || !is_binding_digest(&self.canonical_fact_sha256)
            || !is_binding_digest(&self.committed_receipt_sha256)
            || self.verifier_run_id.trim().is_empty()
            || self.evidence_id.trim().is_empty()
            || self.recorded_at_unix_ms <= previous.recorded_at_unix_ms
            || self.activation.canonical_fact_id != self.canonical_fact_id
            || self.activation.canonical_fact_sha256 != self.canonical_fact_sha256
            || self.activation.owner_id != IMPROVEMENT_KERNEL_OWNER
            || matches!(
                self.activation.status,
                ImprovementActivationStatus::Unknown
                    | ImprovementActivationStatus::Attempted
                    | ImprovementActivationStatus::NotAttempted
            )
            || previous.evidence_id == self.evidence_id
            || previous.verifier_run_id == self.verifier_run_id
            || previous.canonical_fact_id == self.canonical_fact_id
            || previous
                .activation_attempt_id
                .as_deref()
                .is_some_and(|attempt| attempt == self.activation.attempt_id)
        {
            return Err(TestdError::InvalidBinding);
        }
        self.activation.validate_for(proposal)
    }
}

/// Owner-authenticated maintenance admission receipt carried with intake.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImprovementOwnerAdmissionReceipt {
    pub schema: String,
    pub owner_id: String,
    pub operation_id: String,
    /// Digest of the exact authenticated daemon request identity.
    pub request_identity_sha256: String,
    /// Handle-bound owner principal observed by Kernel, not a caller label.
    pub owner_principal_digest: String,
    /// Module identity admitted by the same live session.
    pub owner_module_id: String,
    /// Module artifact identity admitted by the same live session.
    pub owner_artifact_id: String,
    /// Monotonic transport session epoch that authenticated the owner.
    pub owner_session_epoch: u64,
    pub candidate_digest: String,
    pub brief_digest: String,
    pub budget_proof_digest: String,
    pub state_fence: StateFence,
    pub issued_at_unix_ms: u64,
    pub receipt_sha256: String,
}

impl ImprovementOwnerAdmissionReceipt {
    /// Stable receipt schema.
    pub const SCHEMA: &'static str = "eliot.improvement.owner-admission.v1";

    fn compute_digest(&self) -> Result<String, TestdError> {
        typed_digest(&(
            &self.schema,
            &self.owner_id,
            &self.operation_id,
            &self.request_identity_sha256,
            &self.owner_principal_digest,
            &self.owner_module_id,
            &self.owner_artifact_id,
            self.owner_session_epoch,
            &self.candidate_digest,
            &self.brief_digest,
            &self.budget_proof_digest,
            &self.state_fence,
            self.issued_at_unix_ms,
        ))
    }

    /// Revalidates the material and digest portions retained by a proposal.
    /// The frame identity itself is checked at the owner route before the
    /// receipt is issued; a durable proposal never reconstructs an identity
    /// from a caller string.
    pub fn validate_material(
        &self,
        request: &ImprovementExperimentRequest,
        state_fence: &StateFence,
    ) -> Result<(), TestdError> {
        request.validate()?;
        state_fence
            .validate()
            .map_err(|_| TestdError::InvalidBinding)?;
        if self.schema != Self::SCHEMA
            || self.owner_id != IMPROVEMENT_OWNER
            || self.operation_id != GOVERNOR_IMPROVEMENT_OWNER_OPERATION
            || self.candidate_digest != request.candidate_digest
            || self.brief_digest != request.intake_brief_digest
            || self.budget_proof_digest != request.budget_proof_digest
            || self.state_fence != *state_fence
            || self.owner_module_id.trim().is_empty()
            || self.owner_artifact_id.trim().is_empty()
            || !is_binding_digest(&self.request_identity_sha256)
            || !is_binding_digest(&self.owner_principal_digest)
            || self.owner_session_epoch == 0
            || self.receipt_sha256 != self.compute_digest()?
        {
            return Err(TestdError::InvalidBinding);
        }
        Ok(())
    }

    /// Issues the owner receipt over the already-validated inert request and
    /// authenticated frame identity.  The owner id/operation are still
    /// checked by the receiving Kernel route; the receipt is not a string
    /// label and cannot substitute for the frame identity.
    #[allow(clippy::too_many_arguments)]
    pub fn issue(
        request: &ImprovementExperimentRequest,
        identity: &RequestIdentity,
        owner_id: &str,
        operation_id: &str,
        owner_principal_digest: &str,
        owner_module_id: &str,
        owner_artifact_id: &str,
        owner_session_epoch: u64,
        issued_at_unix_ms: u64,
    ) -> Result<Self, TestdError> {
        request.validate()?;
        identity
            .validate()
            .map_err(|_| TestdError::InvalidBinding)?;
        validate_text(owner_id, "owner_admission.owner_id")?;
        validate_text(operation_id, "owner_admission.operation_id")?;
        if owner_id != IMPROVEMENT_OWNER || operation_id != GOVERNOR_IMPROVEMENT_OWNER_OPERATION {
            return Err(TestdError::InvalidBinding);
        }
        validate_text(
            owner_principal_digest,
            "owner_admission.owner_principal_digest",
        )?;
        validate_text(owner_module_id, "owner_admission.owner_module_id")?;
        validate_text(owner_artifact_id, "owner_admission.owner_artifact_id")?;
        if !is_binding_digest(owner_principal_digest)
            || owner_session_epoch == 0
            || issued_at_unix_ms == 0
        {
            return Err(TestdError::InvalidBinding);
        }
        let identity_sha256 = typed_digest(identity)?;
        let mut receipt = Self {
            schema: Self::SCHEMA.to_owned(),
            owner_id: owner_id.to_owned(),
            operation_id: operation_id.to_owned(),
            request_identity_sha256: identity_sha256,
            owner_principal_digest: owner_principal_digest.to_owned(),
            owner_module_id: owner_module_id.to_owned(),
            owner_artifact_id: owner_artifact_id.to_owned(),
            owner_session_epoch,
            candidate_digest: request.candidate_digest.clone(),
            brief_digest: request.intake_brief_digest.clone(),
            budget_proof_digest: request.budget_proof_digest.clone(),
            state_fence: identity.request.state_fence.clone(),
            issued_at_unix_ms,
            receipt_sha256: String::new(),
        };
        receipt.receipt_sha256 = receipt.compute_digest()?;
        Ok(receipt)
    }

    /// Revalidates the receipt against the request and frame identity.
    pub fn validate_for(
        &self,
        request: &ImprovementExperimentRequest,
        identity: &RequestIdentity,
    ) -> Result<(), TestdError> {
        identity
            .validate()
            .map_err(|_| TestdError::InvalidBinding)?;
        self.validate_material(request, &identity.request.state_fence)?;
        if self.request_identity_sha256 != typed_digest(identity)? {
            return Err(TestdError::InvalidBinding);
        }
        Ok(())
    }
}

/// Owner/timestamp/receipt proving predeclaration occurred before outcomes.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MechanismDeclarationReceipt {
    /// Authenticated Kernel principal that submitted the declaration.
    pub declared_by: String,
    /// Kernel observation time before worker dispatch.
    pub declared_at_unix_ms: u64,
    /// Digest over proposal, mechanism, principal, and timestamp.
    pub receipt_sha256: String,
}

impl MechanismDeclarationReceipt {
    fn validate(&self, proposal_id: &str, material_digest: &str) -> Result<(), TestdError> {
        validate_text(&self.declared_by, "mechanism.declared_by")?;
        if self.declared_at_unix_ms == 0 || !is_binding_digest(&self.receipt_sha256) {
            return Err(TestdError::InvalidBinding);
        }
        let expected = typed_digest(&(
            "eliot.improvement.mechanism-receipt.v1",
            proposal_id,
            material_digest,
            self.declared_by.as_str(),
            self.declared_at_unix_ms,
        ))?;
        if self.receipt_sha256 != expected {
            return Err(TestdError::InvalidBinding);
        }
        Ok(())
    }
}

/// Immutable, owner-stamped improvement proposal persisted before execution.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImprovementProposal {
    /// Stable schema identity.
    pub schema: String,
    /// Stable proposal identity.
    pub proposal_id: String,
    /// TestD job/experiment identity.
    pub experiment_id: String,
    /// Predeclared candidate/intake request.
    pub request: ImprovementExperimentRequest,
    /// Exact current target.
    pub target: ImprovementExperimentTarget,
    /// Exact current State Fence and target generation.
    pub state_fence: StateFence,
    /// Exact closed-profile budget and deadline.
    pub budget: ImprovementExperimentBudget,
    /// Distinct operation identities and fixed owners.
    pub operations: ImprovementOperationSet,
    /// Kernel-stamped mechanism declaration receipt.
    pub mechanism_receipt: MechanismDeclarationReceipt,
    /// Authenticated Governor-maintenance admission receipt for this exact
    /// request and live owner session.
    pub owner_admission_receipt: ImprovementOwnerAdmissionReceipt,
    /// Canonical pre-execution experiment plan, including WorkScope,
    /// generation, evidence, metric, canary and invalidation identities.
    pub experiment_plan: ImprovementExperimentPlan,
    /// Digest over all load-bearing proposal fields.
    pub proposal_digest: String,
    /// Material identity used for durable no-progress comparison.
    pub material_digest: String,
}

impl ImprovementProposal {
    /// Derives the immutable proposal from an authenticated Kernel frame and
    /// the registered TestD profile. No caller-supplied fence, generation,
    /// budget, deadline, operation identity, owner, or timestamp is trusted.
    #[allow(clippy::too_many_arguments)]
    pub fn from_kernel_facts_with_owner_receipt(
        request: &ImprovementExperimentRequest,
        identity: &RequestIdentity,
        invocation: &InstrumentInvocation,
        process_tool: &TestdProcessToolIntent,
        owner_admission_receipt: &ImprovementOwnerAdmissionReceipt,
        job_id: &str,
        project_id: &str,
        source_root: &str,
        principal_ref: &str,
        now_unix_ms: u64,
    ) -> Result<Self, TestdError> {
        request.validate()?;
        identity
            .validate()
            .map_err(|_| TestdError::InvalidBinding)?;
        owner_admission_receipt
            .validate_for(request, identity)
            .map_err(|_| TestdError::InvalidBinding)?;
        invocation
            .validate()
            .map_err(|error| TestdError::Contract(error.to_string()))?;
        process_tool.observation.validate()?;
        validate_text(job_id, "improvement.job_id")?;
        validate_text(project_id, "improvement.project_id")?;
        validate_text(source_root, "improvement.source_root")?;
        validate_text(principal_ref, "improvement.principal_ref")?;
        if now_unix_ms == 0
            || identity.request.metadata != invocation.request
            || identity.request.state_fence != invocation.request.state_fence
            || project_id != request.project_id
            || invocation.profile != TESTD_PRODUCTIVE_PROFILE
        {
            return Err(TestdError::InvalidBinding);
        }
        let task_id = identity
            .request
            .metadata
            .task_id
            .as_ref()
            .ok_or(TestdError::InvalidBinding)?;
        // The protocol request metadata carries the task and source binding;
        // the declared Instrument scope is the authenticated work-scope
        // identity at this seam.  It is copied, never interpreted as a path.
        let work_scope_id = invocation.declared_scope.clone();
        let profile = testd_profile_binding(
            TESTD_PRODUCTIVE_PROFILE,
            &process_tool.observation.nextest_sha256,
        )?;
        let deadline_unix_ms = identity
            .deadline_unix_ms
            .min(now_unix_ms.saturating_add(profile.wall_timeout_ms));
        if deadline_unix_ms <= now_unix_ms {
            return Err(TestdError::InvalidBinding);
        }
        let source_identity = typed_digest(&(
            "eliot.improvement.source.v1",
            source_root,
            &identity.request.state_fence,
        ))?;
        let runtime_identity = typed_digest(&(
            "eliot.improvement.runtime.v1",
            invocation.profile.as_str(),
            process_tool.observation.selected_toolchain.as_str(),
            process_tool.observation.nextest_sha256.as_str(),
            &identity.request.state_fence,
        ))?;
        let data_identity = typed_digest(&(
            "eliot.improvement.data.v1",
            &invocation.input_artifacts,
            &request.candidate_digest,
            &request.intake_brief_digest,
        ))?;
        let target = ImprovementExperimentTarget {
            project_id: project_id.to_owned(),
            task_id: task_id.as_str().to_owned(),
            work_scope_id,
            capability_ref: invocation.target.clone(),
            target_surface: request.target_surface.clone(),
            declared_scope: invocation.declared_scope.clone(),
            invocation_id: invocation.request.request_id.to_string(),
            profile: invocation.profile.clone(),
            input_artifact_ids: invocation
                .input_artifacts
                .iter()
                .map(ToString::to_string)
                .collect(),
            source_root: source_root.to_owned(),
            source_identity,
            runtime_identity,
            data_identity,
        };
        target.validate()?;
        let budget = ImprovementExperimentBudget {
            budget_ledger_ref: request.budget_ledger_ref.clone(),
            budget_proof_digest: request.budget_proof_digest.clone(),
            toolchain: process_tool.observation.selected_toolchain.clone(),
            tool_artifact_digest: process_tool.observation.nextest_sha256.clone(),
            wall_timeout_ms: profile.wall_timeout_ms,
            cpu_time_ms: profile.cpu_time_ms.ok_or(TestdError::InvalidBinding)?,
            memory_bytes: profile.memory_bytes.ok_or(TestdError::InvalidBinding)?,
            stdout_bytes: profile.stdout_bytes,
            stderr_bytes: profile.stderr_bytes,
            max_descendants: profile.max_descendants,
            deadline_unix_ms,
        };
        let operations = ImprovementOperationSet::from_base(
            invocation.request.request_id.as_str(),
            &request.rollback.owner_id,
        )?;
        let material_digest = material_digest(request, &target)?;
        let proposal_id = format!(
            "improvement-{}",
            &typed_digest(&(
                "eliot.improvement.proposal-id.v1",
                job_id,
                request.candidate_id.as_str(),
                request.candidate_digest.as_str(),
                material_digest.as_str(),
            ))?[..32]
        );
        let mechanism_receipt = MechanismDeclarationReceipt {
            declared_by: principal_ref.to_owned(),
            declared_at_unix_ms: now_unix_ms,
            receipt_sha256: String::new(),
        };
        let canary_operation_id = operations
            .operation_id(ImprovementOperationKind::CanaryHandoff)
            .ok_or(TestdError::InvalidBinding)?
            .to_owned();
        let canary_id = format!(
            "canary-{}",
            &typed_digest(&(
                "eliot.improvement.canary-id.v1",
                &proposal_id,
                canary_operation_id.as_str(),
                identity.request.state_fence.resource_generation.value(),
            ))?[..32]
        );
        let canary = ImprovementCanaryIdentity {
            canary_id,
            operation_id: canary_operation_id,
            owner_id: IMPROVEMENT_KERNEL_OWNER.to_owned(),
            work_scope_id: target.work_scope_id.clone(),
            generation: identity.request.state_fence.resource_generation.value(),
            state_fence: identity.request.state_fence.clone(),
            effect_ceiling: IMPROVEMENT_EFFECT_CEILING.to_owned(),
        };
        let candidate_value: serde_json::Value = serde_json::from_str(&request.candidate_json)
            .map_err(|_| TestdError::InvalidBinding)?;
        let mut evidence_refs = candidate_value
            .get("evidence_refs")
            .and_then(serde_json::Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(serde_json::Value::as_str)
            .map(ToOwned::to_owned)
            .collect::<Vec<_>>();
        evidence_refs.extend(
            candidate_value
                .get("source_trace_refs")
                .and_then(serde_json::Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(serde_json::Value::as_str)
                .map(ToOwned::to_owned),
        );
        evidence_refs.sort();
        evidence_refs.dedup();
        if evidence_refs.is_empty() {
            return Err(TestdError::InvalidBinding);
        }
        let plan_id = format!(
            "experiment-plan-{}",
            &typed_digest(&(
                "eliot.improvement.experiment-plan-id.v1",
                &proposal_id,
                request.candidate_digest.as_str(),
                request.intake_brief_digest.as_str(),
                request.budget_proof_digest.as_str(),
            ))?[..32]
        );
        let mut experiment_plan = ImprovementExperimentPlan {
            schema: IMPROVEMENT_EXPERIMENT_PLAN_SCHEMA.to_owned(),
            plan_id,
            proposal_id: proposal_id.clone(),
            experiment_id: job_id.to_owned(),
            candidate_id: request.candidate_id.clone(),
            candidate_digest: request.candidate_digest.clone(),
            intake_brief_id: request.intake_brief_id.clone(),
            intake_brief_digest: request.intake_brief_digest.clone(),
            budget_ledger_ref: request.budget_ledger_ref.clone(),
            budget_proof_digest: request.budget_proof_digest.clone(),
            evidence_refs,
            work_scope_id: target.work_scope_id.clone(),
            target: target.clone(),
            state_fence: identity.request.state_fence.clone(),
            generation: identity.request.state_fence.resource_generation.value(),
            evaluator_id: request.evaluator_id.clone(),
            expected_metric_names: request.expected_metric_names.clone(),
            expected_deltas: request.expected_deltas.clone(),
            counter_metric_names: request.counter_metric_names.clone(),
            rollback: request.rollback.clone(),
            canary,
            owner_admission_receipt_sha256: owner_admission_receipt.receipt_sha256.clone(),
            declared_at_unix_ms: now_unix_ms,
            plan_digest: String::new(),
        };
        experiment_plan.plan_digest = experiment_plan.compute_digest()?;
        experiment_plan.validate()?;
        let mut proposal = Self {
            schema: IMPROVEMENT_EXPERIMENT_SCHEMA.to_owned(),
            proposal_id,
            experiment_id: job_id.to_owned(),
            request: request.clone(),
            target,
            state_fence: identity.request.state_fence.clone(),
            budget,
            operations,
            mechanism_receipt,
            owner_admission_receipt: owner_admission_receipt.clone(),
            experiment_plan,
            proposal_digest: String::new(),
            material_digest,
        };
        proposal.mechanism_receipt.receipt_sha256 = typed_digest(&(
            "eliot.improvement.mechanism-receipt.v1",
            proposal.proposal_id.as_str(),
            proposal.material_digest.as_str(),
            principal_ref,
            now_unix_ms,
        ))?;
        proposal.proposal_digest = compute_proposal_digest(&proposal)?;
        proposal.validate()?;
        Ok(proposal)
    }

    /// Validates every load-bearing binding and both durable digests.
    pub fn validate(&self) -> Result<(), TestdError> {
        if self.schema != IMPROVEMENT_EXPERIMENT_SCHEMA {
            return Err(TestdError::Invalid {
                field: "improvement.schema",
                reason: "unsupported improvement experiment schema",
            });
        }
        validate_text(&self.proposal_id, "proposal_id")?;
        validate_text(&self.experiment_id, "experiment_id")?;
        self.request.validate()?;
        self.target.validate()?;
        self.state_fence
            .validate()
            .map_err(|_| TestdError::InvalidBinding)?;
        self.budget
            .validate(self.mechanism_receipt.declared_at_unix_ms)?;
        self.operations.validate(&self.request.rollback.owner_id)?;
        self.owner_admission_receipt
            .validate_material(&self.request, &self.state_fence)?;
        self.experiment_plan.validate()?;
        if self.experiment_plan.proposal_id != self.proposal_id
            || self.experiment_plan.experiment_id != self.experiment_id
            || self.experiment_plan.candidate_id != self.request.candidate_id
            || self.experiment_plan.candidate_digest != self.request.candidate_digest
            || self.experiment_plan.intake_brief_id != self.request.intake_brief_id
            || self.experiment_plan.intake_brief_digest != self.request.intake_brief_digest
            || self.experiment_plan.budget_ledger_ref != self.budget.budget_ledger_ref
            || self.experiment_plan.budget_proof_digest != self.budget.budget_proof_digest
            || self.experiment_plan.target != self.target
            || self.experiment_plan.state_fence != self.state_fence
            || self.experiment_plan.generation != self.state_fence.resource_generation.value()
            || self.experiment_plan.evaluator_id != self.request.evaluator_id
            || self.experiment_plan.expected_metric_names != self.request.expected_metric_names
            || self.experiment_plan.expected_deltas != self.request.expected_deltas
            || self.experiment_plan.counter_metric_names != self.request.counter_metric_names
            || self.experiment_plan.rollback != self.request.rollback
            || self.experiment_plan.owner_admission_receipt_sha256
                != self.owner_admission_receipt.receipt_sha256
            || self.experiment_plan.declared_at_unix_ms
                != self.mechanism_receipt.declared_at_unix_ms
        {
            return Err(TestdError::InvalidBinding);
        }
        if self.target.project_id != self.request.project_id
            || self.target.target_surface != self.request.target_surface
            || self.target.invocation_id.is_empty()
            || self.state_fence.resource_generation.value() == 0
            || self.budget.budget_ledger_ref != self.request.budget_ledger_ref
            || self.budget.budget_proof_digest != self.request.budget_proof_digest
            || self.budget.deadline_unix_ms <= self.mechanism_receipt.declared_at_unix_ms
            || self.target.source_identity
                != typed_digest(&(
                    "eliot.improvement.source.v1",
                    &self.target.source_root,
                    &self.state_fence,
                ))?
            || self.target.runtime_identity
                != typed_digest(&(
                    "eliot.improvement.runtime.v1",
                    self.target.profile.as_str(),
                    self.budget.toolchain.as_str(),
                    self.budget.tool_artifact_digest.as_str(),
                    &self.state_fence,
                ))?
            || self.target.data_identity
                != typed_digest(&(
                    "eliot.improvement.data.v1",
                    &self.target.input_artifact_ids,
                    &self.request.candidate_digest,
                    &self.request.intake_brief_digest,
                ))?
            || self.proposal_digest != compute_proposal_digest(self)?
            || self.material_digest != material_digest(&self.request, &self.target)?
        {
            return Err(TestdError::InvalidBinding);
        }
        self.mechanism_receipt
            .validate(&self.proposal_id, &self.material_digest)
    }

    /// Returns one exact operation identity.
    pub fn operation_id(&self, kind: ImprovementOperationKind) -> Option<&str> {
        self.operations.operation_id(kind)
    }
}

/// Terminal candidate disposition retained beside the TestD job.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImprovementExperimentDisposition {
    /// Independent evidence rejected the candidate.
    Rejected,
    /// Evidence was incomplete, stale, or inconclusive.
    Inconclusive,
    /// The experiment regressed and an owner-bound rollback handoff is required.
    RegressionRollbackHandoff,
    /// External outcome is unknown and must be reconciled before retry.
    UnknownRequiresReconciliation,
    /// A materially identical failed repeat has no new discriminator.
    NoProgress,
    /// Governor admitted a candidate-only Kernel canary handoff.
    CanaryHandoffPending,
}

/// Exact terminal evidence and handoff decision for one proposal.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImprovementExperimentOutcome {
    /// Stable outcome schema.
    pub schema: String,
    /// Exact proposal identity.
    pub proposal_id: String,
    /// Exact proposal digest.
    pub proposal_digest: String,
    /// Exact TestD job identity.
    pub job_id: String,
    /// Exact candidate identity.
    pub candidate_id: String,
    /// Terminal candidate disposition.
    pub disposition: ImprovementExperimentDisposition,
    /// Operation that produced the decision.
    pub decision_operation_id: String,
    /// Independent evaluator evidence identity.
    pub evidence_id: String,
    /// Independent verifier run identity.
    pub verifier_run_id: String,
    /// Committed canonical verifier-fact receipt digest.
    pub committed_receipt_sha256: String,
    /// Canonical verifier-fact identity retained by the owner.
    pub canonical_fact_id: String,
    /// Digest of the canonical fact bytes.
    pub canonical_fact_sha256: String,
    /// External activation attempt, present only after reconciliation.
    #[serde(default)]
    pub activation_attempt_id: Option<String>,
    /// External activation status, present only after reconciliation.
    #[serde(default)]
    pub activation_status: Option<ImprovementActivationStatus>,
    /// Exact invalidation set covered by rollback/forward repair.
    pub invalidation_set: Vec<String>,
    /// Digest over the exact invalidation set.
    pub invalidation_set_digest: String,
    /// Owner of rollback/forward repair.
    pub rollback_owner_id: String,
    /// Rollback reference.
    pub rollback_ref: String,
    /// Forward-repair reference.
    pub forward_repair_ref: String,
    /// Daemon observation time after independent evaluation.
    pub recorded_at_unix_ms: u64,
}

impl ImprovementExperimentOutcome {
    /// Validates the outcome against the exact immutable proposal and job.
    pub fn validate_for(
        &self,
        proposal: &ImprovementProposal,
        job_id: &str,
    ) -> Result<(), TestdError> {
        if self.schema != IMPROVEMENT_EXPERIMENT_SCHEMA
            || self.proposal_id != proposal.proposal_id
            || self.proposal_digest != proposal.proposal_digest
            || self.job_id != job_id
            || proposal.experiment_id != job_id
            || self.candidate_id != proposal.request.candidate_id
            || !is_binding_digest(&self.committed_receipt_sha256)
            || !is_binding_digest(&self.canonical_fact_id)
            || !is_binding_digest(&self.canonical_fact_sha256)
            || self.evidence_id.trim().is_empty()
            || self.verifier_run_id.trim().is_empty()
            || (self.activation_attempt_id.is_some() != self.activation_status.is_some())
            || self
                .activation_attempt_id
                .as_deref()
                .is_some_and(|value| value.trim().is_empty())
            || (self.disposition == ImprovementExperimentDisposition::UnknownRequiresReconciliation
                && (self.activation_attempt_id.is_some() || self.activation_status.is_some()))
            || (self.disposition != ImprovementExperimentDisposition::UnknownRequiresReconciliation
                && self.activation_status.is_some_and(|status| {
                    matches!(
                        status,
                        ImprovementActivationStatus::Unknown
                            | ImprovementActivationStatus::Attempted
                            | ImprovementActivationStatus::NotAttempted
                    )
                }))
            || self.recorded_at_unix_ms <= proposal.mechanism_receipt.declared_at_unix_ms
            || self.invalidation_set != proposal.request.rollback.invalidation_set
            || self.invalidation_set_digest != proposal.request.rollback.invalidation_set_digest
            || self.rollback_owner_id != proposal.request.rollback.owner_id
            || self.rollback_ref != proposal.request.rollback.rollback_ref
            || self.forward_repair_ref != proposal.request.rollback.forward_repair_ref
        {
            return Err(TestdError::InvalidBinding);
        }
        let expected_operation = match self.disposition {
            ImprovementExperimentDisposition::RegressionRollbackHandoff => {
                proposal.operation_id(ImprovementOperationKind::Rollback)
            }
            ImprovementExperimentDisposition::CanaryHandoffPending => {
                proposal.operation_id(ImprovementOperationKind::CanaryHandoff)
            }
            ImprovementExperimentDisposition::UnknownRequiresReconciliation => {
                proposal.operation_id(ImprovementOperationKind::Evaluate)
            }
            ImprovementExperimentDisposition::Rejected
            | ImprovementExperimentDisposition::Inconclusive
            | ImprovementExperimentDisposition::NoProgress => {
                proposal.operation_id(ImprovementOperationKind::AdmitCanary)
            }
        };
        if self.decision_operation_id != expected_operation.unwrap_or_default() {
            return Err(TestdError::InvalidBinding);
        }
        Ok(())
    }

    /// Builds the owner-owned outcome for a new external reconciliation
    /// attempt. Callers provide typed reconciliation evidence, never a
    /// disposition or `WriteReceipt`; the durable owner derives the state from
    /// the authenticated activation status.
    pub fn from_reconciliation_evidence(
        proposal: &ImprovementProposal,
        previous: &ImprovementExperimentOutcome,
        evidence: &ImprovementReconciliationEvidence,
    ) -> Result<Self, TestdError> {
        evidence.validate_for(proposal, previous)?;
        let disposition = match evidence.activation.status {
            ImprovementActivationStatus::Applied => {
                ImprovementExperimentDisposition::CanaryHandoffPending
            }
            ImprovementActivationStatus::Rejected => ImprovementExperimentDisposition::Rejected,
            ImprovementActivationStatus::Unknown
            | ImprovementActivationStatus::Attempted
            | ImprovementActivationStatus::NotAttempted => {
                return Err(TestdError::InvalidBinding);
            }
        };
        let decision_operation_id = match disposition {
            ImprovementExperimentDisposition::CanaryHandoffPending => proposal
                .operation_id(ImprovementOperationKind::CanaryHandoff)
                .ok_or(TestdError::InvalidBinding)?,
            ImprovementExperimentDisposition::Rejected => proposal
                .operation_id(ImprovementOperationKind::AdmitCanary)
                .ok_or(TestdError::InvalidBinding)?,
            _ => return Err(TestdError::InvalidBinding),
        };
        let outcome = Self {
            schema: IMPROVEMENT_EXPERIMENT_SCHEMA.to_owned(),
            proposal_id: proposal.proposal_id.clone(),
            proposal_digest: proposal.proposal_digest.clone(),
            job_id: proposal.experiment_id.clone(),
            candidate_id: proposal.request.candidate_id.clone(),
            disposition,
            decision_operation_id: decision_operation_id.to_owned(),
            evidence_id: evidence.evidence_id.clone(),
            verifier_run_id: evidence.verifier_run_id.clone(),
            committed_receipt_sha256: evidence.committed_receipt_sha256.clone(),
            canonical_fact_id: evidence.canonical_fact_id.clone(),
            canonical_fact_sha256: evidence.canonical_fact_sha256.clone(),
            activation_attempt_id: Some(evidence.activation.attempt_id.clone()),
            activation_status: Some(evidence.activation.status),
            invalidation_set: proposal.request.rollback.invalidation_set.clone(),
            invalidation_set_digest: proposal.request.rollback.invalidation_set_digest.clone(),
            rollback_owner_id: proposal.request.rollback.owner_id.clone(),
            rollback_ref: proposal.request.rollback.rollback_ref.clone(),
            forward_repair_ref: proposal.request.rollback.forward_repair_ref.clone(),
            recorded_at_unix_ms: evidence.recorded_at_unix_ms,
        };
        outcome.validate_for(proposal, &proposal.experiment_id)?;
        Ok(outcome)
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImprovementExperimentState {
    /// Proposal and mechanism are durable; execution has not produced outcomes.
    Predeclared,
    /// Worker evidence is terminal and awaiting daemon/Governor disposition.
    TerminalEvidencePending,
    /// Candidate was rejected.
    Rejected,
    /// Candidate evidence was inconclusive.
    Inconclusive,
    /// Candidate regressed; exact rollback/forward repair is owner-pending.
    RegressionRollbackHandoff,
    /// External outcome requires reconciliation.
    UnknownRequiresReconciliation,
    /// Material repeat had no new discriminator.
    NoProgress,
    /// Candidate-only Kernel canary handoff is pending.
    CanaryHandoffPending,
}

/// Durable TestD sidecar for one improvement experiment.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImprovementExperimentRecord {
    /// owning TestD job identity
    pub job_id: String,
    /// immutable pre-execution proposal
    pub proposal: ImprovementProposal,
    /// actual source identity captured before the worker claim
    pub source_observation: Option<TestdSourceObservation>,
    /// current sidecar state
    pub state: ImprovementExperimentState,
    /// exact terminal outcome, once independently evaluated
    pub outcome: Option<ImprovementExperimentOutcome>,
}

impl ImprovementExperimentRecord {
    /// Creates the predeclared sidecar stored with a new TestD job.
    pub fn predeclared(job_id: &str, proposal: ImprovementProposal) -> Result<Self, TestdError> {
        proposal.validate()?;
        if proposal.experiment_id != job_id {
            return Err(TestdError::InvalidBinding);
        }
        Ok(Self {
            job_id: job_id.to_owned(),
            proposal,
            source_observation: None,
            state: ImprovementExperimentState::Predeclared,
            outcome: None,
        })
    }

    /// Revalidates the complete durable sidecar.
    pub fn validate(&self) -> Result<(), TestdError> {
        validate_text(&self.job_id, "improvement_record.job_id")?;
        self.proposal.validate()?;
        if self.proposal.experiment_id != self.job_id {
            return Err(TestdError::InvalidBinding);
        }
        if let Some(observation) = &self.source_observation {
            observation.validate()?;
            if observation.repository_root != self.proposal.target.source_root {
                return Err(TestdError::InvalidBinding);
            }
        }
        if let Some(outcome) = &self.outcome {
            outcome.validate_for(&self.proposal, &self.job_id)?;
            if self.state != state_for(outcome.disposition) {
                return Err(TestdError::InvalidBinding);
            }
        } else if !matches!(
            self.state,
            ImprovementExperimentState::Predeclared
                | ImprovementExperimentState::TerminalEvidencePending
        ) {
            return Err(TestdError::InvalidBinding);
        }
        Ok(())
    }

    /// Marks the sidecar as awaiting independent terminal evaluation.
    pub fn mark_terminal_evidence_pending(&mut self) -> Result<(), TestdError> {
        if self.outcome.is_some() {
            return Err(TestdError::InvalidBinding);
        }
        if !matches!(self.state, ImprovementExperimentState::Predeclared) {
            return Err(TestdError::InvalidBinding);
        }
        self.state = ImprovementExperimentState::TerminalEvidencePending;
        self.validate()
    }

    /// Applies one independently evidenced terminal disposition exactly once.
    /// Replaying the same outcome is stable; a different outcome under the
    /// same proposal is a conflict rather than a replacement.
    pub fn apply_outcome(
        &mut self,
        outcome: &ImprovementExperimentOutcome,
    ) -> Result<(), TestdError> {
        outcome.validate_for(&self.proposal, &self.job_id)?;
        if let Some(existing) = &self.outcome {
            if existing == outcome {
                return Ok(());
            }
            return Err(TestdError::JobConflict(self.job_id.clone()));
        }
        if !matches!(
            self.state,
            ImprovementExperimentState::TerminalEvidencePending
        ) {
            return Err(TestdError::InvalidBinding);
        }
        self.state = state_for(outcome.disposition);
        self.outcome = Some(outcome.clone());
        self.validate()
    }

    /// Reconciles one prior unknown external outcome with a newly executed,
    /// exact evidence identity. The first outcome is never overwritten by a
    /// caller retry; a different evidence identity must be strictly later and
    /// must carry a new verifier run/evidence identity.
    pub fn reconcile_unknown_outcome(
        &mut self,
        outcome: &ImprovementExperimentOutcome,
    ) -> Result<(), TestdError> {
        let Some(previous) = &self.outcome else {
            return Err(TestdError::InvalidBinding);
        };
        if previous.disposition != ImprovementExperimentDisposition::UnknownRequiresReconciliation {
            return Err(TestdError::InvalidBinding);
        }
        if previous == outcome {
            return Ok(());
        }
        if outcome.evidence_id == previous.evidence_id
            || outcome.verifier_run_id == previous.verifier_run_id
            || outcome.recorded_at_unix_ms <= previous.recorded_at_unix_ms
        {
            return Err(TestdError::InvalidBinding);
        }
        outcome.validate_for(&self.proposal, &self.job_id)?;
        self.state = state_for(outcome.disposition);
        self.outcome = Some(outcome.clone());
        self.validate()
    }

    /// Whether this terminal record is a settled failed material attempt.
    pub fn is_failed_attempt(&self) -> bool {
        self.outcome.as_ref().is_some_and(|outcome| {
            matches!(
                outcome.disposition,
                ImprovementExperimentDisposition::Rejected
                    | ImprovementExperimentDisposition::Inconclusive
                    | ImprovementExperimentDisposition::RegressionRollbackHandoff
                    | ImprovementExperimentDisposition::NoProgress
            )
        })
    }

    /// Whether this record still requires external-outcome reconciliation.
    pub fn requires_reconciliation(&self) -> bool {
        self.outcome.as_ref().is_some_and(|outcome| {
            outcome.disposition == ImprovementExperimentDisposition::UnknownRequiresReconciliation
        })
    }
}

fn state_for(disposition: ImprovementExperimentDisposition) -> ImprovementExperimentState {
    match disposition {
        ImprovementExperimentDisposition::Rejected => ImprovementExperimentState::Rejected,
        ImprovementExperimentDisposition::Inconclusive => ImprovementExperimentState::Inconclusive,
        ImprovementExperimentDisposition::RegressionRollbackHandoff => {
            ImprovementExperimentState::RegressionRollbackHandoff
        }
        ImprovementExperimentDisposition::UnknownRequiresReconciliation => {
            ImprovementExperimentState::UnknownRequiresReconciliation
        }
        ImprovementExperimentDisposition::NoProgress => ImprovementExperimentState::NoProgress,
        ImprovementExperimentDisposition::CanaryHandoffPending => {
            ImprovementExperimentState::CanaryHandoffPending
        }
    }
}

fn digest_strings(values: &[String]) -> Result<String, TestdError> {
    typed_digest(&("eliot.testd.string-set.v1", values))
}

fn canonical_json_digest(value: &str) -> Result<String, TestdError> {
    let parsed: serde_json::Value =
        serde_json::from_str(value).map_err(|_| TestdError::Invalid {
            field: "canonical_json",
            reason: "must contain valid JSON",
        })?;
    let canonical =
        canonical_json_bytes(&parsed).map_err(|error| TestdError::Contract(error.to_string()))?;
    let text =
        String::from_utf8(canonical).map_err(|error| TestdError::Contract(error.to_string()))?;
    if text != value {
        return Err(TestdError::Invalid {
            field: "canonical_json",
            reason: "must use canonical JSON bytes",
        });
    }
    Ok(sha256_hex(text.as_bytes()))
}

fn typed_digest<T: Serialize>(value: &T) -> Result<String, TestdError> {
    let bytes =
        canonical_json_bytes(value).map_err(|error| TestdError::Contract(error.to_string()))?;
    Ok(sha256_hex(&bytes))
}

fn validate_candidate_and_brief_json(
    request: &ImprovementExperimentRequest,
) -> Result<(), TestdError> {
    let candidate: serde_json::Value =
        serde_json::from_str(&request.candidate_json).map_err(|_| TestdError::InvalidBinding)?;
    let brief: serde_json::Value =
        serde_json::from_str(&request.intake_brief_json).map_err(|_| TestdError::InvalidBinding)?;
    let candidate_id = candidate
        .get("candidate_id")
        .and_then(serde_json::Value::as_str);
    let project_id = candidate
        .get("project_id")
        .and_then(serde_json::Value::as_str);
    let target_surface = candidate
        .get("target_surface")
        .and_then(serde_json::Value::as_str);
    let revision = candidate
        .get("revision")
        .and_then(serde_json::Value::as_u64);
    let brief_id = brief.get("brief_id").and_then(serde_json::Value::as_str);
    let brief_candidate_id = brief
        .get("candidate_id")
        .and_then(serde_json::Value::as_str);
    let brief_revision = brief
        .get("candidate_revision")
        .and_then(serde_json::Value::as_u64);
    let candidate_evidence = candidate
        .get("evidence_refs")
        .and_then(serde_json::Value::as_array);
    let candidate_trace = candidate
        .get("source_trace_refs")
        .and_then(serde_json::Value::as_array);
    let brief_evidence = brief
        .get("evidence_refs")
        .and_then(serde_json::Value::as_array);
    let candidate_evidence_values = candidate_evidence.and_then(|values| {
        values
            .iter()
            .map(|value| value.as_str().map(ToOwned::to_owned))
            .collect::<Option<Vec<_>>>()
    });
    let brief_evidence_values = brief_evidence.and_then(|values| {
        values
            .iter()
            .map(|value| value.as_str().map(ToOwned::to_owned))
            .collect::<Option<Vec<_>>>()
    });
    let baseline = candidate
        .get("baseline_metrics")
        .and_then(serde_json::Value::as_object);
    let counter_metrics = candidate
        .get("counter_metrics")
        .and_then(serde_json::Value::as_object);
    if candidate_id != Some(request.candidate_id.as_str())
        || project_id != Some(request.project_id.as_str())
        || target_surface != Some(request.target_surface.as_str())
        || revision != Some(request.candidate_revision)
        || candidate
            .get("advisory_only")
            .and_then(serde_json::Value::as_bool)
            != Some(true)
        || candidate
            .get("lifecycle")
            .and_then(serde_json::Value::as_str)
            != Some("triaged")
        || candidate
            .get("delivery_target")
            .and_then(serde_json::Value::as_str)
            != Some(request.delivery_target.as_str())
        || candidate
            .get("canary_plan")
            .and_then(serde_json::Value::as_str)
            != Some(request.canary_plan.as_str())
        || candidate
            .get("rollback")
            .and_then(serde_json::Value::as_str)
            != Some(request.rollback.rollback_ref.as_str())
        || candidate
            .get("stop_condition")
            .and_then(serde_json::Value::as_str)
            != Some(request.stop_condition.as_str())
        || brief_id != Some(request.intake_brief_id.as_str())
        || brief_candidate_id != Some(request.candidate_id.as_str())
        || brief_revision != Some(request.candidate_revision)
        || candidate_evidence.is_none_or(Vec::is_empty)
        || candidate_trace.is_none_or(Vec::is_empty)
        || brief_evidence.is_none_or(Vec::is_empty)
        || candidate_evidence_values != brief_evidence_values
        || baseline.is_none_or(|metrics| {
            request
                .expected_metric_names
                .iter()
                .any(|name| !metrics.contains_key(name))
        })
        || counter_metrics.is_none_or(|metrics| {
            request
                .counter_metric_names
                .iter()
                .any(|name| !metrics.contains_key(name))
        })
    {
        return Err(TestdError::InvalidBinding);
    }
    Ok(())
}

fn material_digest(
    request: &ImprovementExperimentRequest,
    target: &ImprovementExperimentTarget,
) -> Result<String, TestdError> {
    #[derive(Serialize)]
    struct MaterialPreimage<'a> {
        domain: &'a str,
        candidate_id: &'a str,
        candidate_revision: u64,
        candidate_digest: &'a str,
        intake_brief_id: &'a str,
        intake_brief_digest: &'a str,
        evaluator_id: &'a str,
        project_id: &'a str,
        target_surface: &'a str,
        delivery_target: &'a str,
        canary_plan: &'a str,
        stop_condition: &'a str,
        mechanism: &'a MechanismDeclaration,
        expected_delta: &'a str,
        expected_metric_names: &'a [String],
        expected_deltas: &'a BTreeMap<String, f64>,
        counter_metric_names: &'a [String],
        risk_class: ImprovementRiskClass,
        effect_ceiling: &'a str,
        privacy_class: ImprovementPrivacyClass,
        budget_ledger_ref: &'a str,
        budget_proof_json: &'a str,
        budget_proof_digest: &'a str,
        rollback: &'a RollbackContract,
        new_discriminator: Option<&'a ImprovementDiscriminator>,
        capability_ref: &'a str,
        declared_scope: &'a str,
        profile: &'a str,
        input_artifact_ids: &'a [String],
        source_identity: &'a str,
        runtime_identity: &'a str,
        data_identity: &'a str,
    }
    typed_digest(&MaterialPreimage {
        domain: "eliot.improvement.material.v1",
        candidate_id: &request.candidate_id,
        candidate_revision: request.candidate_revision,
        candidate_digest: &request.candidate_digest,
        intake_brief_id: &request.intake_brief_id,
        intake_brief_digest: &request.intake_brief_digest,
        evaluator_id: &request.evaluator_id,
        project_id: &request.project_id,
        target_surface: &request.target_surface,
        delivery_target: &request.delivery_target,
        canary_plan: &request.canary_plan,
        stop_condition: &request.stop_condition,
        mechanism: &request.mechanism,
        expected_delta: &request.expected_delta,
        expected_metric_names: &request.expected_metric_names,
        expected_deltas: &request.expected_deltas,
        counter_metric_names: &request.counter_metric_names,
        risk_class: request.risk_class,
        effect_ceiling: &request.effect_ceiling,
        privacy_class: request.privacy_class,
        budget_ledger_ref: &request.budget_ledger_ref,
        budget_proof_json: &request.budget_proof_json,
        budget_proof_digest: &request.budget_proof_digest,
        rollback: &request.rollback,
        new_discriminator: request.new_discriminator.as_ref(),
        capability_ref: &target.capability_ref,
        declared_scope: &target.declared_scope,
        profile: &target.profile,
        input_artifact_ids: &target.input_artifact_ids,
        source_identity: &target.source_identity,
        runtime_identity: &target.runtime_identity,
        data_identity: &target.data_identity,
    })
}

fn compute_proposal_digest(proposal: &ImprovementProposal) -> Result<String, TestdError> {
    #[derive(Serialize)]
    struct Preimage<'a> {
        schema: &'a str,
        proposal_id: &'a str,
        experiment_id: &'a str,
        request: &'a ImprovementExperimentRequest,
        target: &'a ImprovementExperimentTarget,
        state_fence: &'a StateFence,
        budget: &'a ImprovementExperimentBudget,
        operations: &'a ImprovementOperationSet,
        mechanism_receipt: &'a MechanismDeclarationReceipt,
        owner_admission_receipt: &'a ImprovementOwnerAdmissionReceipt,
        experiment_plan: &'a ImprovementExperimentPlan,
        material_digest: &'a str,
    }

    typed_digest(&Preimage {
        schema: &proposal.schema,
        proposal_id: &proposal.proposal_id,
        experiment_id: &proposal.experiment_id,
        request: &proposal.request,
        target: &proposal.target,
        state_fence: &proposal.state_fence,
        budget: &proposal.budget,
        operations: &proposal.operations,
        mechanism_receipt: &proposal.mechanism_receipt,
        owner_admission_receipt: &proposal.owner_admission_receipt,
        experiment_plan: &proposal.experiment_plan,
        material_digest: &proposal.material_digest,
    })
}

/// Durable prior-attempt disposition used for replay and reconciliation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImprovementPriorOutcome {
    /// Settled negative/inconclusive failure eligible for no-progress.
    Failed,
    /// External outcome still requires reconciliation.
    Unknown,
    /// Positive candidate handoff; it is not a failed repeat.
    Passed,
    /// No terminal outcome yet.
    Pending,
}

/// Evidence shape used by the durable no-progress comparison.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImprovementPriorAttempt {
    /// Exact prior TestD job.
    pub job_id: String,
    /// Material identity of the prior proposal.
    pub material_digest: String,
    /// Optional discriminator on the prior proposal.
    pub discriminator_id: Option<String>,
    /// Canonical evidence identity supplied by the prior owner.
    pub canonical_evidence_id: Option<String>,
    /// Canonical evidence digest supplied by the prior owner.
    pub canonical_evidence_sha256: Option<String>,
    /// Exact durable prior disposition.
    pub outcome: ImprovementPriorOutcome,
}

/// Detects a materially identical failed repeat without a new discriminator.
pub fn is_improvement_no_progress(
    proposal: &ImprovementProposal,
    prior_attempts: &[ImprovementPriorAttempt],
) -> bool {
    let current_discriminator = proposal.request.new_discriminator.as_ref();
    prior_attempts.iter().any(|prior| {
        if prior.outcome != ImprovementPriorOutcome::Failed
            || prior.material_digest != proposal.material_digest
            || prior.discriminator_id.as_deref()
                != current_discriminator.map(|value| value.discriminator_id.as_str())
        {
            return false;
        }
        let Some(current) = current_discriminator else {
            return true;
        };
        // A different discriminator label is not enough: the owner must
        // present a different canonical evidence identity and digest. Missing
        // prior evidence cannot prove progress and therefore remains debt.
        let genuinely_new = current.has_new_canonical_evidence()
            && prior.canonical_evidence_id.is_some()
            && prior.canonical_evidence_sha256.is_some()
            && prior.canonical_evidence_id.as_deref() != current.canonical_evidence_id.as_deref()
            && prior.canonical_evidence_sha256.as_deref()
                != current.canonical_evidence_sha256.as_deref();
        !genuinely_new
    })
}

/// Exact source binding observed by the independent evaluator.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ImprovementSourceBinding {
    /// The same complete source observation was present before and after the
    /// experiment.
    ExactUnchanged,
    /// The source changed during the experiment.
    Changed,
    /// No complete source observation was available.
    Absent,
}

/// Per-metric disposition derived from exact observed deltas.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ImprovementMetricDisposition {
    /// Expected minimum delta was met.
    Meets,
    /// Evidence was finite but below the expected minimum.
    Misses,
    /// A counter metric regressed.
    Regresses,
    /// The metric was not measured completely.
    Incomplete,
}

/// Evidence dimensions required from the independent Instrument evaluator.
#[derive(Clone, Debug, PartialEq)]
pub struct IndependentExecutionEvidence {
    /// Stable evidence identity.
    pub evidence_id: String,
    /// Registered verifier contract.
    pub verifier_id: String,
    /// Exact verifier run.
    pub verifier_run_id: String,
    /// Bound TestD job.
    pub job_id: String,
    /// Independent evaluator operation identity predeclared by the proposal.
    pub operation_id: String,
    /// Exact TestD process operation that produced the executed evidence.
    pub executed_operation_id: String,
    /// Bound Instrument invocation.
    pub invocation_id: String,
    /// Semantic outcome.
    pub outcome: VerificationOutcome,
    /// Coverage axis.
    pub coverage: EvidenceCoverage,
    /// Freshness axis.
    pub freshness: EvidenceFreshness,
    /// Exact before/after source binding.
    pub source_binding: ImprovementSourceBinding,
    /// Exact observed deltas keyed by the declared metric names.
    pub observed_metric_deltas: BTreeMap<String, f64>,
    /// Exact observed deltas for declared counter metrics.
    pub counter_metric_deltas: BTreeMap<String, f64>,
    /// Per-metric disposition, when the evaluator emitted a complete table.
    pub metric_dispositions: BTreeMap<String, ImprovementMetricDisposition>,
    /// Raw evidence handles.
    pub raw_evidence_refs: Vec<String>,
    /// Normalized evidence identities.
    pub normalized_evidence_refs: Vec<String>,
    /// Exact current State Fence.
    pub state_fence: StateFence,
    /// Committed canonical fact receipt digest.
    pub committed_receipt_sha256: String,
}

impl IndependentExecutionEvidence {
    /// Rejects evidence not executed by the registered independent verifier
    /// for the exact proposal, target, job, invocation, and fence.
    pub fn validate_for(
        &self,
        proposal: &ImprovementProposal,
        job_id: &str,
    ) -> Result<(), TestdError> {
        if self.verifier_id != proposal.request.evaluator_id || self.verifier_id.trim().is_empty() {
            return Err(TestdError::InvalidBinding);
        }
        if self.job_id != job_id
            || proposal.experiment_id != job_id
            || self.operation_id
                != proposal
                    .operation_id(ImprovementOperationKind::Evaluate)
                    .ok_or(TestdError::InvalidBinding)?
            || self.executed_operation_id.trim().is_empty()
            || self.invocation_id != proposal.target.invocation_id
            || self.state_fence != proposal.state_fence
            || !is_binding_digest(&self.committed_receipt_sha256)
            || !is_binding_digest(&self.evidence_id)
            || self.verifier_run_id.trim().is_empty()
            || self
                .observed_metric_deltas
                .values()
                .any(|value| !value.is_finite())
            || self
                .counter_metric_deltas
                .values()
                .any(|value| !value.is_finite())
            || self.metric_dispositions.is_empty()
            || self
                .metric_dispositions
                .keys()
                .any(|name| name.trim().is_empty())
            || self.raw_evidence_refs.is_empty()
            || self.normalized_evidence_refs.is_empty()
            || self
                .raw_evidence_refs
                .iter()
                .chain(&self.normalized_evidence_refs)
                .any(|value| value.trim().is_empty())
        {
            return Err(TestdError::InvalidBinding);
        }
        Ok(())
    }
}
