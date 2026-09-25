//! Material-readiness gate over typed onboarding state (issue #1789).
//!
//! The cold-start compiler ([`ColdStartController`](super::ColdStartController))
//! emits an [`OnboardingReadinessReceipt`](super::OnboardingReadinessReceipt)
//! that binds one scope, instance, lineage, [`StateFence`], governing-source
//! generation and task selection — but the receipt alone never admits work.
//! This module is the readiness authority object and gate at the
//! Kernel/governor boundary: [`assess_material_readiness`] returns the exact
//! lifecycle state, fence currency and lease expiry, missing inputs, safe
//! allowed actions, truth-surface/verifier readiness, the privacy/authority
//! route, task binding status and governing-source coverage, and
//! [`evaluate_material_request`] admits or denies one requested effect.
//!
//! Grounding in the linked fragments:
//!
//! - I4.4: adequate Level 0 is required before scope-sensitive durable
//!   promotion or an unobserved Material effect, while initial exploration,
//!   safe capture and probes that construct Level 0 may begin earlier in the
//!   provisional scope. Hence [`RequestedEffect::requires_material_readiness`]
//!   admits only `READY_MATERIAL` for canonical writes and Material effects,
//!   and [`allowed_effects`] permits only read-only orientation, safe capture,
//!   discriminative probes and discovery in provisional and `READY_READ_ONLY`
//!   states.
//! - I4.2: an ambiguous match is never selected silently and Material
//!   authority is withheld until resolution. Hence ambiguity — ambiguous task
//!   handles or an ambiguous guard receipt — denies Material effects with
//!   [`MaterialReadinessDirective::AmbiguousResult`] (the token the resolver
//!   slice already names), never with a silent retarget.
//!
//! Denials are always typed: [`MaterialReadinessDirective`] carries
//! `TASK_SELECTION_REQUIRED` for absent task data, `AMBIGUOUS_RESULT` for
//! multiple plausible scope/task candidates, `GOVERNING_CONTEXT_REQUIRED` for
//! deficient source or verifier grounding, and `READINESS_REEVALUATION_REQUIRED`
//! when the Kernel fence changed, the scope guard detected a changed
//! generation, or the governing source set went stale or conflicted. The
//! missing-context directive names the exact gap in `missing_inputs`, which is
//! the honest no-proof disposition: a declared gap, never a generic denial and
//! never a fabricated allow.
//!
//! No README or Architecture document is mandatory: [`GoverningCoverage`] also
//! accepts an explicit, evidence-backed [`ExplicitAbsenceRecord`] ("none
//! found / not applicable") when task, source and truth-surface grounding is
//! otherwise sufficient.

use super::{
    GoverningSourceRole, GoverningSourceSet, OnboardingLease, OnboardingReadinessReceipt,
    ReadinessLifecycle, ScopeBindingDisposition, ScopeBindingGuardReceipt, ScopeResolutionState,
    TaskBindingState, WorkScopeDescriptor, WorkScopeError, candidate_source_roles, counter, text,
    unique,
};
use eliot_contracts::{StateFence, fences_match_exact};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Requested work effect class, in the issue's vocabulary.
///
/// The first four classes are the read-only orientation family that I4.4 lets
/// proceed in provisional scopes; the last two are the scope-sensitive
/// canonical writes and Material project effects that require
/// `READY_MATERIAL`.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RequestedEffect {
    ReadOnlyOrientation,
    SafeCapture,
    DiscriminativeProbe,
    Discovery,
    CanonicalWrite,
    MaterialEffect,
}

impl RequestedEffect {
    /// Returns whether the effect needs `READY_MATERIAL` readiness.
    ///
    /// Only scope-sensitive canonical writes and Material project effects
    /// return true; the read-only orientation family returns false.
    #[must_use]
    pub const fn requires_material_readiness(self) -> bool {
        matches!(self, Self::CanonicalWrite | Self::MaterialEffect)
    }
}

/// Typed readiness directive returned instead of a generic denial.
///
/// Serialized names are the issue's literal tokens. `GoverningContextRequired`
/// is the onboarding-specific missing-context/proof directive for deficient
/// source or verifier grounding; `ReadinessReevaluationRequired` reports a
/// changed Kernel fence, a changed scope generation, or a stale/conflicted
/// governing source set so the caller recompiles readiness instead of
/// retrying the effect.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum MaterialReadinessDirective {
    TaskSelectionRequired,
    AmbiguousResult,
    GoverningContextRequired,
    ReadinessReevaluationRequired,
}

impl MaterialReadinessDirective {
    /// Returns the stable wire token for this directive.
    #[must_use]
    pub const fn kind_str(self) -> &'static str {
        match self {
            Self::TaskSelectionRequired => "TASK_SELECTION_REQUIRED",
            Self::AmbiguousResult => "AMBIGUOUS_RESULT",
            Self::GoverningContextRequired => "GOVERNING_CONTEXT_REQUIRED",
            Self::ReadinessReevaluationRequired => "READINESS_REEVALUATION_REQUIRED",
        }
    }
}

/// Explicit, evidence-backed "none found / not applicable" coverage.
///
/// A project without an applicable governing document (no README or
/// Architecture role to admit) records that outcome here instead of failing
/// source closure: which roles were sought, why none applies, and the
/// evidence backing the claim. Empty sources are never silently accepted —
/// the reason and its evidence are mandatory.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ExplicitAbsenceRecord {
    pub scope_ref: String,
    pub generation: u64,
    pub absent_roles: Vec<GoverningSourceRole>,
    pub reason_ref: String,
    pub evidence_refs: Vec<String>,
}

impl ExplicitAbsenceRecord {
    /// Validates the absence claim without authenticating any source.
    ///
    /// # Errors
    ///
    /// Returns an error when identity or reason references are blank, the
    /// generation is zero, roles are duplicated, or the backing evidence is
    /// not between one and eight unique non-blank references.
    pub fn validate(&self) -> Result<(), WorkScopeError> {
        text(&self.scope_ref, "absence.scope_ref")?;
        counter(self.generation, "absence.generation")?;
        unique(self.absent_roles.iter(), "absence.absent_roles")?;
        text(&self.reason_ref, "absence.reason_ref")?;
        if self.evidence_refs.is_empty() || self.evidence_refs.len() > 8 {
            return Err(WorkScopeError::EmptyCollection {
                field: "absence.evidence_refs",
            });
        }
        for evidence in &self.evidence_refs {
            text(evidence, "absence.evidence_refs")?;
        }
        unique(self.evidence_refs.iter(), "absence.evidence_refs")
    }

    /// Returns whether this record covers the named scope generation.
    #[must_use]
    pub fn binds_scope(&self, scope_ref: &str, generation: u64) -> bool {
        self.scope_ref == scope_ref && self.generation == generation
    }
}

/// Governing-source coverage for one readiness evaluation.
///
/// Either an admitted source set that must close over the scope generation
/// under the retained privacy boundary, or an explicit absence record. Both
/// shapes bind to one scope generation; neither invents sources.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", tag = "coverage", content = "detail")]
pub enum GoverningCoverage {
    AdmittedSources(GoverningSourceSet),
    ExplicitAbsence(ExplicitAbsenceRecord),
}

impl GoverningCoverage {
    /// Validates the coverage shape without checking scope closure.
    ///
    /// Closure over the scope generation under the privacy boundary is
    /// checked by [`assess_material_readiness`], which owns the scope and
    /// the retained descriptor.
    ///
    /// # Errors
    ///
    /// Returns an error when references are blank, counters are zero, or an
    /// absence record is malformed.
    pub fn validate(&self) -> Result<(), WorkScopeError> {
        match self {
            Self::AdmittedSources(set) => {
                text(&set.scope_ref, "coverage.scope_ref")?;
                counter(set.generation, "coverage.generation")?;
                Ok(())
            }
            Self::ExplicitAbsence(record) => record.validate(),
        }
    }

    /// Returns whether this coverage names the given scope generation.
    #[must_use]
    pub fn binds_scope(&self, scope_ref: &str, generation: u64) -> bool {
        match self {
            Self::AdmittedSources(set) => {
                set.scope_ref == scope_ref && set.generation == generation
            }
            Self::ExplicitAbsence(record) => record.binds_scope(scope_ref, generation),
        }
    }
}

/// Caller-supplied facts for one readiness evaluation.
///
/// Every field is caller-observed authority: the compiled receipt, the
/// retained descriptor (truth-surface/verifier references, privacy boundary,
/// authority route), the governing coverage, the current guard receipt, the
/// onboarding lease, the current Kernel fence, and the evaluation tick. This
/// crate reads no filesystem, process, store, or credential state.
#[derive(Clone, Copy, Debug)]
pub struct MaterialReadinessInputs<'a> {
    pub receipt: &'a OnboardingReadinessReceipt,
    pub descriptor: &'a WorkScopeDescriptor,
    pub coverage: &'a GoverningCoverage,
    pub guard_receipt: &'a ScopeBindingGuardReceipt,
    pub lease: &'a OnboardingLease,
    pub fence: &'a StateFence,
    pub now: u64,
}

/// Readiness authority object: the explicit, visible readiness lifecycle.
///
/// This is the compiled first-useful-work gate made observable: exact
/// lifecycle state, fence currency and lease expiry, missing inputs, safe
/// allowed actions, truth-surface/verifier readiness, the privacy/authority
/// route, task binding status, and governing-source coverage. It grants
/// nothing by itself; [`evaluate_material_request`] decides one effect.
///
/// The eight flags are independent readiness legs, not a ladder, so the
/// struct keeps them as plain booleans by design.
#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MaterialReadinessReport {
    pub receipt_ref: String,
    pub lifecycle: ReadinessLifecycle,
    pub scope_resolution: ScopeResolutionState,
    pub fence_current: bool,
    pub lease_current: bool,
    pub lease_deadline: u64,
    pub guard: ScopeBindingDisposition,
    pub guard_bound: bool,
    pub instance_bound: bool,
    pub coverage_sufficient: bool,
    pub truth_surface_ready: bool,
    pub verifier_ready: bool,
    pub authority_route_ready: bool,
    pub authority_profile_ref: Option<String>,
    pub governance_profile_ref: String,
    pub route_profile_ref: String,
    pub task_binding: TaskBindingState,
    pub missing_inputs: Vec<String>,
    pub next_safe_action: String,
    pub allowed_effects: Vec<RequestedEffect>,
}

impl MaterialReadinessReport {
    /// Validates a report without re-running the evaluation.
    ///
    /// # Errors
    ///
    /// Returns an error when a bound reference is blank.
    pub fn validate(&self) -> Result<(), WorkScopeError> {
        text(&self.receipt_ref, "report.receipt_ref")?;
        text(
            &self.governance_profile_ref,
            "report.governance_profile_ref",
        )?;
        text(&self.route_profile_ref, "report.route_profile_ref")?;
        text(&self.next_safe_action, "report.next_safe_action")?;
        for missing in &self.missing_inputs {
            text(missing, "report.missing_inputs")?;
        }
        Ok(())
    }
}

/// Admission decision for one requested effect under one readiness report.
///
/// `Admitted` carries the bound receipt and effect so the Kernel admission
/// path can check identity without re-resolving authority. `Denied` carries
/// the typed directive and the exact missing inputs instead of a generic
/// denial; nothing is launched on a denial.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", tag = "decision", content = "detail")]
pub enum MaterialAdmission {
    Admitted {
        receipt_ref: String,
        effect: RequestedEffect,
    },
    Denied {
        receipt_ref: String,
        effect: RequestedEffect,
        directive: MaterialReadinessDirective,
        missing_inputs: Vec<String>,
    },
}

impl MaterialAdmission {
    /// Returns whether the requested effect may launch.
    #[must_use]
    pub const fn is_admitted(&self) -> bool {
        matches!(self, Self::Admitted { .. })
    }

    /// Returns the typed directive for a denial, or `None` when admitted.
    #[must_use]
    pub const fn directive(&self) -> Option<MaterialReadinessDirective> {
        match self {
            Self::Admitted { .. } => None,
            Self::Denied { directive, .. } => Some(*directive),
        }
    }
}

/// Returns the safe allowed actions for one lifecycle position.
///
/// `ReadyMaterial` allows every class. Provisional positions (`NeedsTask`)
/// and `ReadyReadOnly` allow only read-only orientation, safe capture,
/// discriminative probes, and discovery. Any other position — unseen,
/// scanning, scope/source need, degraded, or conflicted — allows nothing:
/// there is no orientable state to act in.
#[must_use]
pub fn allowed_effects(lifecycle: ReadinessLifecycle) -> Vec<RequestedEffect> {
    match lifecycle {
        ReadinessLifecycle::ReadyMaterial => vec![
            RequestedEffect::ReadOnlyOrientation,
            RequestedEffect::SafeCapture,
            RequestedEffect::DiscriminativeProbe,
            RequestedEffect::Discovery,
            RequestedEffect::CanonicalWrite,
            RequestedEffect::MaterialEffect,
        ],
        ReadinessLifecycle::NeedsTask | ReadinessLifecycle::ReadyReadOnly => vec![
            RequestedEffect::ReadOnlyOrientation,
            RequestedEffect::SafeCapture,
            RequestedEffect::DiscriminativeProbe,
            RequestedEffect::Discovery,
        ],
        ReadinessLifecycle::Unseen
        | ReadinessLifecycle::Scanning
        | ReadinessLifecycle::NeedsScope
        | ReadinessLifecycle::NeedsSources
        | ReadinessLifecycle::Degraded
        | ReadinessLifecycle::Conflicted => Vec::new(),
    }
}

fn guard_agrees_with_receipt(
    guard: &ScopeBindingGuardReceipt,
    receipt: &OnboardingReadinessReceipt,
) -> bool {
    guard.observed_scope_ref == receipt.scope.scope_ref
        && guard.observed_lineage_ref == receipt.scope.lineage_ref
        && guard.observed_instance_ref == receipt.scope.instance_ref
        && guard.source_generation == receipt.governing_source_generation
}

fn descriptor_binds_receipt(
    descriptor: &WorkScopeDescriptor,
    receipt: &OnboardingReadinessReceipt,
) -> bool {
    descriptor.scope_ref == receipt.scope.scope_ref
        && descriptor.kind == receipt.scope.kind
        && descriptor.instances.iter().any(|instance| {
            instance.instance_ref == receipt.scope.instance_ref
                && instance.root_identity == receipt.scope.root_identity
        })
}

fn coverage_closes(
    coverage: &GoverningCoverage,
    receipt: &OnboardingReadinessReceipt,
    descriptor: &WorkScopeDescriptor,
) -> bool {
    match coverage {
        GoverningCoverage::AdmittedSources(set) => set
            .validate_for(&receipt.scope, &descriptor.privacy)
            .is_ok(),
        // An absence claim is sufficient only when it surveys the whole
        // governing-source set: every role the source model may surface
        // (see `candidate_source_roles`) must be declared absent with
        // backing evidence. A partial absence leaves coverage open.
        GoverningCoverage::ExplicitAbsence(record) => candidate_source_roles()
            .iter()
            .all(|role| record.absent_roles.contains(role)),
    }
}

fn push_missing(missing: &mut Vec<String>, token: &str) {
    if !missing.iter().any(|entry| entry == token) {
        missing.push(token.to_owned());
    }
}

/// Compiles the readiness authority object for one evaluation.
///
/// Checks, in order: receipt/descriptor/coverage shape; lease linkage to the
/// receipt's scope, instance, lineage and source generation; Kernel fence
/// currency; lease expiry; guard agreement with the receipt; descriptor
/// instance binding; and coverage/truth-surface/verifier/authority depth.
/// Structural malformation fails as an error; every semantic gap is reported
/// as data so [`evaluate_material_request`] can direct it.
///
/// # Errors
///
/// Returns an error when the receipt, descriptor, or coverage is malformed,
/// or when the lease is invalid or names another scope, instance, lineage,
/// or source generation than the receipt.
pub fn assess_material_readiness(
    inputs: &MaterialReadinessInputs<'_>,
) -> Result<MaterialReadinessReport, WorkScopeError> {
    let receipt = inputs.receipt;
    let descriptor = inputs.descriptor;
    receipt.validate()?;
    descriptor.validate()?;
    inputs.coverage.validate()?;
    let lease = inputs.lease;
    lease
        .validate()
        .map_err(|_| WorkScopeError::InvalidCounter { field: "lease" })?;
    if lease.lease_ref != receipt.lease_ref
        || lease.lineage_candidate_ref != receipt.scope.lineage_ref.as_deref().unwrap_or("")
        || lease.workspace_instance_candidate_ref != receipt.scope.instance_ref
        || lease.governing_source_generation != receipt.governing_source_generation
    {
        return Err(WorkScopeError::BindingReceiptMismatch);
    }
    let fence_current = fences_match_exact(&receipt.state_fence, inputs.fence);
    let lease_current = lease.is_active(inputs.now);
    let guard = inputs.guard_receipt.disposition;
    let guard_bound = guard == ScopeBindingDisposition::Matched
        && guard_agrees_with_receipt(inputs.guard_receipt, receipt);
    let instance_bound = descriptor_binds_receipt(descriptor, receipt);
    let coverage_bound = inputs
        .coverage
        .binds_scope(&receipt.scope.scope_ref, receipt.scope.generation);
    let coverage_sufficient =
        coverage_bound && coverage_closes(inputs.coverage, receipt, descriptor);
    let truth_surface_ready = !descriptor.truth_surface_refs.is_empty();
    let verifier_ready = !descriptor.verifier_refs.is_empty();
    let authority_route_ready = descriptor.authority_profile_ref.is_some();
    let mut missing_inputs = receipt.missing_inputs.clone();
    if !coverage_sufficient {
        push_missing(&mut missing_inputs, "governing_sources");
    }
    if !truth_surface_ready {
        push_missing(&mut missing_inputs, "truth_surface");
    }
    if !verifier_ready {
        push_missing(&mut missing_inputs, "verifier");
    }
    if !authority_route_ready {
        push_missing(&mut missing_inputs, "authority_profile");
    }
    let report = MaterialReadinessReport {
        receipt_ref: receipt.receipt_ref.clone(),
        lifecycle: receipt.readiness,
        scope_resolution: receipt.scope_resolution,
        fence_current,
        lease_current,
        lease_deadline: lease.deadline,
        guard,
        guard_bound,
        instance_bound,
        coverage_sufficient,
        truth_surface_ready,
        verifier_ready,
        authority_route_ready,
        authority_profile_ref: descriptor.authority_profile_ref.clone(),
        governance_profile_ref: receipt.governance_profile_ref.clone(),
        route_profile_ref: receipt.route_profile_ref.clone(),
        task_binding: receipt.task_binding.clone(),
        missing_inputs,
        next_safe_action: receipt.next_safe_action.clone(),
        allowed_effects: allowed_effects(receipt.readiness),
    };
    report.validate()?;
    Ok(report)
}

fn denied(
    receipt_ref: &str,
    effect: RequestedEffect,
    directive: MaterialReadinessDirective,
    missing_inputs: &[String],
    hint: &str,
) -> MaterialAdmission {
    let mut missing = missing_inputs.to_owned();
    push_missing(&mut missing, hint);
    MaterialAdmission::Denied {
        receipt_ref: receipt_ref.to_owned(),
        effect,
        directive,
        missing_inputs: missing,
    }
}

fn evaluate_material_depth(
    report: &MaterialReadinessReport,
    receipt: &OnboardingReadinessReceipt,
    effect: RequestedEffect,
) -> MaterialAdmission {
    if !(report.coverage_sufficient
        && report.truth_surface_ready
        && report.verifier_ready
        && report.authority_route_ready)
    {
        return denied(
            &report.receipt_ref,
            effect,
            MaterialReadinessDirective::GoverningContextRequired,
            &report.missing_inputs,
            "governing_context",
        );
    }
    match (&receipt.task_binding, receipt.readiness) {
        (TaskBindingState::Ambiguous { .. }, _) => denied(
            &report.receipt_ref,
            effect,
            MaterialReadinessDirective::AmbiguousResult,
            &report.missing_inputs,
            "task_disambiguation",
        ),
        (TaskBindingState::CurrentTaskContract { .. }, ReadinessLifecycle::ReadyMaterial) => {
            MaterialAdmission::Admitted {
                receipt_ref: report.receipt_ref.clone(),
                effect,
            }
        }
        _ => denied(
            &report.receipt_ref,
            effect,
            MaterialReadinessDirective::TaskSelectionRequired,
            &report.missing_inputs,
            "current_task_contract",
        ),
    }
}

/// Admits or denies one requested effect under current readiness.
///
/// Fail-closed evaluation order: receipt/descriptor/coverage shape, then
/// currency (Kernel fence, lease, descriptor instance binding, sufficient
/// governing-source closure) denies with
/// `READINESS_REEVALUATION_REQUIRED`; a non-matched guard denies with
/// `AMBIGUOUS_RESULT` for an ambiguous scope and `REEVALUATION` otherwise;
/// an ambiguous scope resolution denies every effect with `AMBIGUOUS_RESULT`;
/// a Material effect then needs full grounding (`GOVERNING_CONTEXT_REQUIRED`
/// when sources, truth surface, verifier, or authority route are deficient)
/// and an exact current task contract at `READY_MATERIAL`
/// (`TASK_SELECTION_REQUIRED` otherwise, `AMBIGUOUS_RESULT` for preserved
/// candidate handles). A read-only effect is admitted in any orientable
/// lifecycle once currency holds, and denied with the missing-context
/// directive when no orientable state exists. A denial never launches the
/// effect.
///
/// # Errors
///
/// Returns an error when [`assess_material_readiness`] rejects the inputs.
pub fn evaluate_material_request(
    inputs: &MaterialReadinessInputs<'_>,
    effect: RequestedEffect,
) -> Result<MaterialAdmission, WorkScopeError> {
    let report = assess_material_readiness(inputs)?;
    let receipt = inputs.receipt;
    // Currency is fence, lease, descriptor instance binding, and sufficient
    // governing coverage: stale or conflicted sources deny with
    // `READINESS_REEVALUATION_REQUIRED` even when the coverage still names
    // the scope generation, so no effect — read-only or material — proceeds
    // on unclosed coverage.
    let currency_ok = report.fence_current
        && report.lease_current
        && report.instance_bound
        && report.coverage_sufficient;
    if !currency_ok {
        return Ok(denied(
            &report.receipt_ref,
            effect,
            MaterialReadinessDirective::ReadinessReevaluationRequired,
            &report.missing_inputs,
            "readiness_refresh",
        ));
    }
    if !report.guard_bound {
        if report.guard == ScopeBindingDisposition::Ambiguous {
            return Ok(denied(
                &report.receipt_ref,
                effect,
                MaterialReadinessDirective::AmbiguousResult,
                &report.missing_inputs,
                "scope_disambiguation",
            ));
        }
        return Ok(denied(
            &report.receipt_ref,
            effect,
            MaterialReadinessDirective::ReadinessReevaluationRequired,
            &report.missing_inputs,
            "readiness_refresh",
        ));
    }
    // An ambiguous scope resolution is never selected silently (I4.2): even
    // with a current task contract at `READY_MATERIAL`, an ambiguous scope
    // denies every effect with `AMBIGUOUS_RESULT` until resolution.
    if receipt.scope_resolution == ScopeResolutionState::Ambiguous {
        return Ok(denied(
            &report.receipt_ref,
            effect,
            MaterialReadinessDirective::AmbiguousResult,
            &report.missing_inputs,
            "scope_disambiguation",
        ));
    }
    if effect.requires_material_readiness() {
        return Ok(evaluate_material_depth(&report, receipt, effect));
    }
    if report.allowed_effects.contains(&effect) {
        Ok(MaterialAdmission::Admitted {
            receipt_ref: report.receipt_ref.clone(),
            effect,
        })
    } else {
        Ok(denied(
            &report.receipt_ref,
            effect,
            MaterialReadinessDirective::GoverningContextRequired,
            &report.missing_inputs,
            "governing_context",
        ))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)] // test-only panic-acceptable (#838).
    use super::super::{
        ColdStartController, GenerationEvidence, GoverningSource, GoverningSourceRole,
        GoverningSourceSet, OnboardingLease, OnboardingLeaseState, PrivacyProfile,
        RepositoryLineageIdentity, ResourceExecutionIdentity, ScopeBinding, ScopeBindingGuard,
        ScopeIdentity, ScopeKind, ScopeLifecycle, SourceStatus, TaskBindingInput,
        WorkScopeCandidate, WorkspaceInstanceIdentity,
    };
    use super::*;
    use eliot_contracts::{EpochId, EpochLineageId, ResourceGeneration};
    use eliot_security_contracts::PrivacyClass;
    use serde::de::DeserializeOwned;
    use std::num::NonZeroU64;

    const TEST_LINEAGE_A: &str = "550e8400-e29b-41d4-a716-446655440000";

    fn test_epoch(lineage: &str, sequence: u64) -> EpochId {
        EpochId::new(
            EpochLineageId::new(lineage).expect("valid test lineage"),
            NonZeroU64::new(sequence).expect("nonzero test sequence"),
        )
        .expect("valid test epoch")
    }

    fn from_json<T: DeserializeOwned>(value: serde_json::Value) -> T {
        match serde_json::from_value(value) {
            Ok(value) => value,
            Err(error) => panic!("fixture is invalid: {error}"),
        }
    }

    fn source_assurance(privacy_class: PrivacyClass) -> eliot_security_contracts::SourceAssurance {
        from_json(serde_json::json!({
            "source_ref": "architecture",
            "provenance_ref": "artifact:architecture",
            "integrity": "VERIFIED",
            "freshness": "CURRENT",
            "competence": "DOMAIN_VERIFIED",
            "independence": "INDEPENDENT",
            "privacy_class": match serde_json::to_value(privacy_class) {
                Ok(value) => value,
                Err(_) => serde_json::Value::String("INTERNAL".into()),
            },
            "instruction_taint": "CLEARED",
            "allowed_epistemic_use": ["OBSERVATION"],
            "allowed_effects": ["READ_ONLY"],
            "required_verifier": null,
            "quarantine": "NONE",
            "state_fence": {
                "authority_epoch": {"lineage_id": TEST_LINEAGE_A, "sequence": 1},
                "resource_generation": 1,
                "task_revision": null,
                "policy_revision": null,
                "integration_revision": null
            }
        }))
    }

    fn candidate() -> WorkScopeCandidate {
        let scope = ScopeIdentity {
            scope_ref: "scope:instance:a".into(),
            kind: ScopeKind::GitRepo,
            lineage_ref: Some("lineage:one".into()),
            instance_ref: "instance:a".into(),
            root_identity: "root:a".into(),
            generation: 1,
        };
        WorkScopeCandidate {
            instance: WorkspaceInstanceIdentity {
                instance_ref: "instance:a".into(),
                root_identity: "root:a".into(),
                vcs_identity_ref: Some("vcs:one".into()),
                generation: 1,
            },
            scope,
            lineage: Some(RepositoryLineageIdentity {
                lineage_ref: "lineage:one".into(),
                object_store_ref: "store:one".into(),
                initial_history_ref: "history:one".into(),
                normalized_remote_ref: Some("remote:one".into()),
                manifest_identity_ref: Some("manifest:one".into()),
            }),
            privacy_class: PrivacyClass::Internal,
        }
    }

    fn fence() -> StateFence {
        StateFence::new(test_epoch(TEST_LINEAGE_A, 1), ResourceGeneration::genesis())
    }

    fn lease() -> OnboardingLease {
        OnboardingLease {
            lease_ref: "onboarding:one".into(),
            lineage_candidate_ref: "lineage:one".into(),
            workspace_instance_candidate_ref: "instance:a".into(),
            governing_source_generation: 1,
            compiler_epoch: 1,
            state: OnboardingLeaseState::Compiling,
            deadline: 10,
        }
    }

    fn privacy() -> PrivacyProfile {
        PrivacyProfile {
            admitted_classes: vec![PrivacyClass::Internal],
        }
    }

    fn sources() -> GoverningSourceSet {
        match GoverningSourceSet::new(
            "scope:instance:a".to_owned(),
            1,
            vec![GoverningSource {
                source_ref: "architecture".into(),
                role: GoverningSourceRole::Architecture,
                assurance: source_assurance(PrivacyClass::Internal),
                applicable_generation: 1,
                status: SourceStatus::Admitted,
                domains: Vec::new(),
            }],
            Vec::new(),
        ) {
            Ok(value) => value,
            Err(error) => panic!("source fixture is invalid: {error}"),
        }
    }

    fn receipt_with(task: TaskBindingInput) -> OnboardingReadinessReceipt {
        let one = candidate();
        match ColdStartController.compile(
            "receipt:one",
            &lease(),
            "principal:test",
            "session:test",
            &one.scope,
            &one.instance,
            one.lineage.as_ref(),
            &one,
            &sources(),
            &fence(),
            "governance-profile:test",
            vec!["integration:evidence:one".into()],
            "route-profile:test",
            "serializer:test",
            "serializer-version:test",
            "serializer-options:test",
            "tokenizer:test",
            "tokenizer-version:test",
            "tokenizer-hash:test",
            "projection-source:test",
            1,
            &privacy(),
            task,
            1,
        ) {
            Ok(value) => value,
            Err(error) => panic!("readiness compilation failed: {error}"),
        }
    }

    fn descriptor() -> WorkScopeDescriptor {
        let one = candidate();
        WorkScopeDescriptor {
            scope_ref: one.scope.scope_ref.clone(),
            descriptor_revision: 1,
            kind: one.scope.kind,
            display_name: "scope a".into(),
            lineage: one.lineage.clone(),
            instances: vec![one.instance.clone()],
            owner_refs: vec!["owner:test".into()],
            canonical_resource_refs: Vec::new(),
            root_identities: vec!["root:a".into()],
            external_resource_refs: Vec::new(),
            truth_surface_refs: vec!["truth:architecture".into()],
            verifier_refs: vec!["verifier:suite".into()],
            privacy: privacy(),
            authority_profile_ref: Some("authority:test".into()),
            execution_identity: ResourceExecutionIdentity::Service,
            generation: GenerationEvidence {
                branch_ref: None,
                commit_ref: None,
                dirty_summary_ref: None,
                task_revision: None,
                resource_generation: ResourceGeneration::genesis(),
            },
            state_fence: fence(),
            available_capabilities: Vec::new(),
            missing_capabilities: Vec::new(),
            lifecycle: ScopeLifecycle::Active,
        }
    }

    fn guard_receipt() -> ScopeBindingGuardReceipt {
        let one = candidate();
        let binding = ScopeBinding {
            scope: one.scope.clone(),
            privacy_class: PrivacyClass::Internal,
            governing_source_generation: 1,
        };
        ScopeBindingGuard.check(&binding, &binding, &sources(), &privacy())
    }

    fn inputs<'a>(
        receipt: &'a OnboardingReadinessReceipt,
        descriptor: &'a WorkScopeDescriptor,
        coverage: &'a GoverningCoverage,
        guard: &'a ScopeBindingGuardReceipt,
        lease_value: &'a OnboardingLease,
        fence_value: &'a StateFence,
    ) -> MaterialReadinessInputs<'a> {
        MaterialReadinessInputs {
            receipt,
            descriptor,
            coverage,
            guard_receipt: guard,
            lease: lease_value,
            fence: fence_value,
            now: 1,
        }
    }

    fn current_task() -> TaskBindingInput {
        TaskBindingInput::Current {
            task_ref: "task:one".into(),
            task_revision: 1,
            acceptance_digest: "digest:acceptance:one".into(),
        }
    }

    #[test]
    fn mutation_without_admitted_task_returns_task_selection_required() {
        let receipt = receipt_with(TaskBindingInput::NoTask);
        let descriptor_value = descriptor();
        let coverage = GoverningCoverage::AdmittedSources(sources());
        let guard = guard_receipt();
        let lease_value = lease();
        let fence_value = fence();
        let admission = match evaluate_material_request(
            &inputs(
                &receipt,
                &descriptor_value,
                &coverage,
                &guard,
                &lease_value,
                &fence_value,
            ),
            RequestedEffect::CanonicalWrite,
        ) {
            Ok(value) => value,
            Err(error) => panic!("gate evaluation failed: {error}"),
        };
        assert!(!admission.is_admitted());
        assert_eq!(
            admission.directive(),
            Some(MaterialReadinessDirective::TaskSelectionRequired)
        );
        assert_eq!(
            admission
                .directive()
                .map(MaterialReadinessDirective::kind_str),
            Some("TASK_SELECTION_REQUIRED")
        );
    }

    #[test]
    fn exploratory_task_reads_but_does_not_launch_mutation() {
        let receipt = receipt_with(TaskBindingInput::Exploratory {
            task_ref: "task:explore".into(),
            task_revision: 1,
            acceptance_digest: "digest:acceptance:explore".into(),
        });
        let descriptor_value = descriptor();
        let coverage = GoverningCoverage::AdmittedSources(sources());
        let guard = guard_receipt();
        let lease_value = lease();
        let fence_value = fence();
        let probe = match evaluate_material_request(
            &inputs(
                &receipt,
                &descriptor_value,
                &coverage,
                &guard,
                &lease_value,
                &fence_value,
            ),
            RequestedEffect::Discovery,
        ) {
            Ok(value) => value,
            Err(error) => panic!("gate evaluation failed: {error}"),
        };
        assert!(probe.is_admitted());
        let mutation = match evaluate_material_request(
            &inputs(
                &receipt,
                &descriptor_value,
                &coverage,
                &guard,
                &lease_value,
                &fence_value,
            ),
            RequestedEffect::MaterialEffect,
        ) {
            Ok(value) => value,
            Err(error) => panic!("gate evaluation failed: {error}"),
        };
        assert!(!mutation.is_admitted());
        assert_eq!(
            mutation.directive(),
            Some(MaterialReadinessDirective::TaskSelectionRequired)
        );
    }

    #[test]
    fn complete_grounding_is_ready_material_and_kernel_eligible() {
        let receipt = receipt_with(current_task());
        let descriptor_value = descriptor();
        let coverage = GoverningCoverage::AdmittedSources(sources());
        let guard = guard_receipt();
        let lease_value = lease();
        let fence_value = fence();
        let args = inputs(
            &receipt,
            &descriptor_value,
            &coverage,
            &guard,
            &lease_value,
            &fence_value,
        );
        let report = match assess_material_readiness(&args) {
            Ok(value) => value,
            Err(error) => panic!("readiness assessment failed: {error}"),
        };
        assert_eq!(report.lifecycle, ReadinessLifecycle::ReadyMaterial);
        assert!(report.fence_current);
        assert!(report.lease_current);
        assert!(report.guard_bound);
        assert!(report.instance_bound);
        assert!(report.coverage_sufficient);
        assert!(report.truth_surface_ready);
        assert!(report.verifier_ready);
        assert!(report.authority_route_ready);
        assert!(
            report
                .allowed_effects
                .contains(&RequestedEffect::MaterialEffect)
        );
        let admission = match evaluate_material_request(&args, RequestedEffect::MaterialEffect) {
            Ok(value) => value,
            Err(error) => panic!("gate evaluation failed: {error}"),
        };
        assert!(admission.is_admitted());
        assert_eq!(admission.directive(), None);
    }

    #[test]
    fn changed_kernel_fence_requires_reevaluation() {
        let receipt = receipt_with(current_task());
        let descriptor_value = descriptor();
        let coverage = GoverningCoverage::AdmittedSources(sources());
        let guard = guard_receipt();
        let lease_value = lease();
        let advanced = StateFence::new(
            test_epoch(TEST_LINEAGE_A, 1),
            match ResourceGeneration::new(2) {
                Ok(value) => value,
                Err(error) => panic!("fence fixture is invalid: {error}"),
            },
        );
        let admission = match evaluate_material_request(
            &inputs(
                &receipt,
                &descriptor_value,
                &coverage,
                &guard,
                &lease_value,
                &advanced,
            ),
            RequestedEffect::MaterialEffect,
        ) {
            Ok(value) => value,
            Err(error) => panic!("gate evaluation failed: {error}"),
        };
        assert!(!admission.is_admitted());
        assert_eq!(
            admission.directive(),
            Some(MaterialReadinessDirective::ReadinessReevaluationRequired)
        );
    }

    #[test]
    fn explicit_absence_covers_projects_without_governing_sources() {
        let receipt = receipt_with(current_task());
        let descriptor_value = descriptor();
        let absence = ExplicitAbsenceRecord {
            scope_ref: "scope:instance:a".into(),
            generation: 1,
            // Absence must survey the whole governing-source set: every
            // role the source model may surface is declared not applicable.
            absent_roles: candidate_source_roles(),
            reason_ref: "none-found:no-architecture-doc".into(),
            evidence_refs: vec!["evidence:manifest-scan:empty".into()],
        };
        if let Err(error) = absence.validate() {
            panic!("absence fixture is invalid: {error}");
        }
        let coverage = GoverningCoverage::ExplicitAbsence(absence);
        let guard = guard_receipt();
        let lease_value = lease();
        let fence_value = fence();
        let admission = match evaluate_material_request(
            &inputs(
                &receipt,
                &descriptor_value,
                &coverage,
                &guard,
                &lease_value,
                &fence_value,
            ),
            RequestedEffect::MaterialEffect,
        ) {
            Ok(value) => value,
            Err(error) => panic!("gate evaluation failed: {error}"),
        };
        assert!(admission.is_admitted());
    }

    #[test]
    fn ambiguous_task_candidates_deny_mutation_with_ambiguous_result() {
        let receipt = receipt_with(TaskBindingInput::AmbiguousCandidates(vec![
            "task:a".to_owned(),
            "task:b".to_owned(),
        ]));
        let descriptor_value = descriptor();
        let coverage = GoverningCoverage::AdmittedSources(sources());
        let guard = guard_receipt();
        let lease_value = lease();
        let fence_value = fence();
        let admission = match evaluate_material_request(
            &inputs(
                &receipt,
                &descriptor_value,
                &coverage,
                &guard,
                &lease_value,
                &fence_value,
            ),
            RequestedEffect::MaterialEffect,
        ) {
            Ok(value) => value,
            Err(error) => panic!("gate evaluation failed: {error}"),
        };
        assert!(!admission.is_admitted());
        assert_eq!(
            admission.directive(),
            Some(MaterialReadinessDirective::AmbiguousResult)
        );
        assert_eq!(
            admission
                .directive()
                .map(MaterialReadinessDirective::kind_str),
            Some("AMBIGUOUS_RESULT")
        );
    }

    #[test]
    fn ambiguous_scope_resolution_denies_material_with_ambiguous_result() {
        let mut receipt = receipt_with(current_task());
        receipt.scope_resolution = ScopeResolutionState::Ambiguous;
        let descriptor_value = descriptor();
        let coverage = GoverningCoverage::AdmittedSources(sources());
        let guard = guard_receipt();
        let lease_value = lease();
        let fence_value = fence();
        let admission = match evaluate_material_request(
            &inputs(
                &receipt,
                &descriptor_value,
                &coverage,
                &guard,
                &lease_value,
                &fence_value,
            ),
            RequestedEffect::CanonicalWrite,
        ) {
            Ok(value) => value,
            Err(error) => panic!("gate evaluation failed: {error}"),
        };
        assert!(!admission.is_admitted());
        assert_eq!(
            admission.directive(),
            Some(MaterialReadinessDirective::AmbiguousResult)
        );
        assert_eq!(
            admission
                .directive()
                .map(MaterialReadinessDirective::kind_str),
            Some("AMBIGUOUS_RESULT")
        );
    }

    #[test]
    fn stale_governing_coverage_requires_reevaluation() {
        let receipt = receipt_with(current_task());
        let descriptor_value = descriptor();
        let mut stale = sources();
        stale.sources[0].status = SourceStatus::Stale;
        let coverage = GoverningCoverage::AdmittedSources(stale);
        let guard = guard_receipt();
        let lease_value = lease();
        let fence_value = fence();
        for effect in [RequestedEffect::MaterialEffect, RequestedEffect::Discovery] {
            let admission = match evaluate_material_request(
                &inputs(
                    &receipt,
                    &descriptor_value,
                    &coverage,
                    &guard,
                    &lease_value,
                    &fence_value,
                ),
                effect,
            ) {
                Ok(value) => value,
                Err(error) => panic!("gate evaluation failed: {error}"),
            };
            assert!(!admission.is_admitted());
            assert_eq!(
                admission.directive(),
                Some(MaterialReadinessDirective::ReadinessReevaluationRequired)
            );
        }
    }

    #[test]
    fn partial_absence_does_not_close_governing_coverage() {
        let receipt = receipt_with(current_task());
        let descriptor_value = descriptor();
        let absence = ExplicitAbsenceRecord {
            scope_ref: "scope:instance:a".into(),
            generation: 1,
            absent_roles: vec![GoverningSourceRole::Architecture],
            reason_ref: "none-found:no-architecture-doc".into(),
            evidence_refs: vec!["evidence:manifest-scan:empty".into()],
        };
        if let Err(error) = absence.validate() {
            panic!("absence fixture is invalid: {error}");
        }
        let coverage = GoverningCoverage::ExplicitAbsence(absence);
        let guard = guard_receipt();
        let lease_value = lease();
        let fence_value = fence();
        let admission = match evaluate_material_request(
            &inputs(
                &receipt,
                &descriptor_value,
                &coverage,
                &guard,
                &lease_value,
                &fence_value,
            ),
            RequestedEffect::MaterialEffect,
        ) {
            Ok(value) => value,
            Err(error) => panic!("gate evaluation failed: {error}"),
        };
        assert!(!admission.is_admitted());
        assert_eq!(
            admission.directive(),
            Some(MaterialReadinessDirective::ReadinessReevaluationRequired)
        );
    }
}
