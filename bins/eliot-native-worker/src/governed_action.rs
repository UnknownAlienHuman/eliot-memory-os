//! Governed action envelope for declared external-adapter operations.
//!
//! Issue #1911 (A10.1/A10.2/A10.3/A10.8): every externally effective
//! operation exposed by this binary (`register`, `claim`, `reconcile`,
//! `start_claimed`, `serve_stdio`) runs through a Harness action contract
//! before any adapter is invoked. The Governor derives impact from the
//! registered tool/effect profile plus affected resources; Material and
//! Critical effects require the A10.3 action-model fields; the returned
//! observation binds the State Fence and verifier; finish uses the honest
//! A10.8 vocabulary and never labels work complete without admissible proof.
//!
//! This module mints no authority and starts nothing: it validates the
//! presented envelope against itself (WorkScope, State Fence, Authority
//! Epoch, tool/effect profile, derived impact, applicable authority, stop
//! condition) and refuses fail-closed with a standardized rejection before
//! any adapter closure runs. Kernel admission, the executable join, and the
//! dispatch grant stay with the existing admitted contour.

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};

/// Declared external-adapter operations traced by this contour.
pub const EXTERNAL_ADAPTER_OPS: [&str; 5] = [
    "register",
    "claim",
    "reconcile",
    "start_claimed",
    "serve_stdio",
];

/// Maximum text length accepted for any single envelope string field.
pub const MAX_ENVELOPE_TEXT_LEN: usize = 2048;
/// Maximum affected resources carried on one envelope.
pub const MAX_AFFECTED_RESOURCES: usize = 16;
/// Maximum text length accepted for one affected-resource entry.
pub const MAX_RESOURCE_LEN: usize = 128;
/// Maximum identity length (operation, scope, authority, verifier).
pub const MAX_IDENTITY_LEN: usize = 256;

/// Governor-derived impact class (A10.2, ARCH-ACT-01).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ImpactClass {
    /// No external change.
    Observe,
    /// Small local rollback.
    Reversible,
    /// Changes behavior, several resources, or external state.
    Material,
    /// Security, schema, credentials, or irreversible/high-blast effect.
    Critical,
    /// Prohibited by an active Hard Boundary or Policy.
    Forbidden,
}

impl ImpactClass {
    /// Returns the canonical impact name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Observe => "OBSERVE",
            Self::Reversible => "REVERSIBLE",
            Self::Material => "MATERIAL",
            Self::Critical => "CRITICAL",
            Self::Forbidden => "FORBIDDEN",
        }
    }

    /// Returns true for effects that require the full A10.3 action model.
    #[must_use]
    pub const fn requires_action_model(self) -> bool {
        matches!(self, Self::Material | Self::Critical)
    }
}

/// Honest finish-state vocabulary (A10.8). Only `VerifiedComplete` is completion.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FinishState {
    /// Admissible proof bound to the verifier.
    VerifiedComplete,
    /// Honestly preserved partial progress.
    Partial,
    /// Blocked on authority, scope, or input.
    Blocked,
    /// The verifier ran and did not accept the outcome.
    FailedVerification,
    /// No admissible proof; completion is not claimed.
    DegradedNoProof,
    /// Finishing would be unsafe.
    UnsafeToFinish,
    /// Cancelled before completion.
    Cancelled,
    /// Replaced by a newer unit of work.
    Superseded,
}

impl FinishState {
    /// Returns the canonical finish name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::VerifiedComplete => "VERIFIED_COMPLETE",
            Self::Partial => "PARTIAL",
            Self::Blocked => "BLOCKED",
            Self::FailedVerification => "FAILED_VERIFICATION",
            Self::DegradedNoProof => "DEGRADED_NO_PROOF",
            Self::UnsafeToFinish => "UNSAFE_TO_FINISH",
            Self::Cancelled => "CANCELLED",
            Self::Superseded => "SUPERSEDED",
        }
    }

    /// Returns true only for proof-bearing completion (ARCH-FIN-01).
    #[must_use]
    pub const fn is_complete(self) -> bool {
        matches!(self, Self::VerifiedComplete)
    }
}

/// Governed action envelope presented before any external-adapter invoke.
///
/// Closed shape (`deny_unknown_fields`): every field is untrusted presenter
/// bytes until [`validate_envelope`] accepts them. `state_fence` and
/// `authority_epoch` carry the admitted fence/epoch as canonical JSON objects;
/// only their shape is checked here (object, non-null) — currentness stays
/// with the Kernel admission contour. A `verifier` starting with `unknown:`
/// explicitly preserves the unknown per A10.1 step 8 instead of binding a
/// verifier.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionEnvelope {
    /// Declared external-adapter operation (one of [`EXTERNAL_ADAPTER_OPS`]).
    pub operation: String,
    /// Intent for the action (A10.3).
    pub intent: String,
    /// `WorkScope` the action executes under (A10.1 step 1).
    pub scope_ref: String,
    /// Preconditions (A10.3).
    pub preconditions: String,
    /// Expected effect or observable (A10.1 step 4, A10.3).
    pub expected_effect: String,
    /// Invariants (A10.3).
    pub invariants: String,
    /// Known failures (A10.3).
    pub known_failures: String,
    /// Rollback or compensation (A10.3).
    pub rollback_or_compensation: String,
    /// Bound verifier, or `unknown:<reason>` when explicitly preserved.
    pub verifier: String,
    /// Stop or revision condition (A10.3).
    pub stop_condition: String,
    /// Admitted State Fence as canonical JSON (must be an object).
    pub state_fence: serde_json::Value,
    /// Admitted Authority Epoch as canonical JSON (must be an object).
    pub authority_epoch: serde_json::Value,
    /// Registered tool/effect profile name driving impact derivation.
    pub tool_profile: String,
    /// Affected resources driving impact derivation.
    pub affected_resources: Vec<String>,
    /// Applicable authority the envelope is bound to (A10.1 step 5).
    pub applicable_authority: String,
}

/// Validated action admitted to exactly one external-adapter invoke.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedAction {
    /// Declared operation the envelope binds.
    pub operation: String,
    /// Governor-derived impact class.
    pub impact: ImpactClass,
    /// `WorkScope` the invoke executes under.
    pub scope_ref: String,
    /// Applicable authority the invoke is bound to.
    pub applicable_authority: String,
    /// Admitted State Fence the recorded effect links to.
    pub state_fence: serde_json::Value,
    /// Bound verifier, or the explicit `unknown:` marker.
    pub verifier: String,
}

/// Standardized rejected-action output (A10.1): why the action was rejected,
/// what was preserved, retry availability, required repair/probe/authority,
/// and the allowed next action. The adapter is never invoked on this path.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionRejection {
    /// Declared operation that was refused.
    pub operation: String,
    /// Why the action was rejected.
    pub reason: String,
    /// What was preserved (no adapter effect, prior state unchanged).
    pub preserved_state: String,
    /// Whether resubmission can succeed.
    pub retryable: bool,
    /// Retry status detail.
    pub retry_status: String,
    /// Authority required before resubmission.
    pub required_authority: String,
    /// Repair or probe required before resubmission.
    pub required_repair: String,
    /// The allowed next action.
    pub allowed_next_action: String,
}

impl std::fmt::Display for ActionRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "governed action rejected for '{}': {}. preserved: {}. retry: {}. required authority: {}. required repair: {}. allowed next: {}",
            self.operation,
            self.reason,
            self.preserved_state,
            self.retry_status,
            self.required_authority,
            self.required_repair,
            self.allowed_next_action
        )
    }
}

impl std::error::Error for ActionRejection {}

/// Observation/effect recorded through the Harness (A10.1 steps 7-8).
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecordedEffect {
    /// Declared operation that produced the effect.
    pub operation: String,
    /// `WorkScope` the effect executed under.
    pub scope_ref: String,
    /// State Fence the effect links to.
    pub state_fence: serde_json::Value,
    /// Bound verifier, or the explicit `unknown:` marker.
    pub verifier: String,
    /// Recorded observation or effect summary.
    pub observation: String,
}

/// Returns true when the operation is a declared external-adapter operation.
#[must_use]
pub fn is_external_adapter_op(operation: &str) -> bool {
    EXTERNAL_ADAPTER_OPS.contains(&operation)
}

/// Derives impact from the registered tool/effect profile plus affected
/// resources (A10.2, ARCH-ACT-01: effect defines impact, not intent).
///
/// Deterministic projection: `forbidden` markers dominate, then critical
/// markers, then any external-adapter profile or non-empty affected set
/// classifies Material, then `reversible`, else Observe. Uncertainty resolves
/// upward to Material, never silently downward.
#[must_use]
pub fn derive_impact(tool_profile: &str, affected_resources: &[String]) -> ImpactClass {
    let profile = tool_profile.trim().to_lowercase();
    let resources: Vec<String> = affected_resources
        .iter()
        .map(|resource| resource.trim().to_lowercase())
        .collect();
    let has = |marker: &str| profile == marker || resources.iter().any(|r| r == marker);
    if has("forbidden") || has("hard-boundary") || has("hard_boundary") {
        return ImpactClass::Forbidden;
    }
    for marker in [
        "critical",
        "security",
        "schema",
        "credential",
        "credentials",
        "irreversible",
    ] {
        if has(marker) {
            return ImpactClass::Critical;
        }
    }
    if profile == "material"
        || profile == "external-adapter"
        || is_external_adapter_op(profile.as_str())
        || !resources.iter().all(String::is_empty)
    {
        return ImpactClass::Material;
    }
    if profile == "reversible" {
        return ImpactClass::Reversible;
    }
    ImpactClass::Observe
}

fn generic_rejection(operation: &str, reason: &str) -> ActionRejection {
    ActionRejection {
        operation: operation.to_owned(),
        reason: reason.to_owned(),
        preserved_state: format!(
            "no adapter invoked for '{operation}'; prior registration/claim state unchanged"
        ),
        retryable: true,
        retry_status: "retryable: resubmit with a valid authority-bound envelope".to_owned(),
        required_authority: format!(
            "authority-bound action envelope for '{operation}' (WorkScope, State Fence, Authority Epoch, applicable authority)"
        ),
        required_repair: "attach intent/scope, preconditions, expected effect, invariants/known failures, rollback/compensation, verifier, and stop condition"
            .to_owned(),
        allowed_next_action: format!(
            "submit '{operation}' with a valid envelope; or submit an Observe probe"
        ),
    }
}

/// Validates one presented envelope against itself, fail-closed.
///
/// Checks the declared operation, non-empty intent/scope/authority/profile/
/// stop condition, object-shaped State Fence and Authority Epoch, bounded
/// affected resources, the Governor-derived impact, and — for Material or
/// Critical effects — every A10.3 action-model field. A `Forbidden` impact is
/// refused outright. Returns the validated action the adapter invoke may bind.
// The typed refusal carries the full A10.1 repair shape by value so the
// acceptance fields stay directly readable; boxing would obscure them.
#[allow(
    clippy::result_large_err,
    reason = "typed refusal surface is matched by value on purpose"
)]
pub fn validate_envelope(envelope: &ActionEnvelope) -> Result<ValidatedAction, ActionRejection> {
    if !is_external_adapter_op(envelope.operation.as_str()) {
        return Err(ActionRejection {
            operation: envelope.operation.clone(),
            reason: format!(
                "unknown external-adapter operation '{}'; declared operations are register, claim, reconcile, start_claimed, serve_stdio",
                envelope.operation
            ),
            preserved_state: format!(
                "no adapter invoked for '{}'; prior registration/claim state unchanged",
                envelope.operation
            ),
            retryable: false,
            retry_status: "not-retryable: unknown operations never invoke an adapter".to_owned(),
            required_authority:
                "authority-bound action envelope for a declared operation (`WorkScope`, State Fence, Authority Epoch, applicable authority)"
                    .to_owned(),
            required_repair: "attach intent/scope, preconditions, expected effect, invariants/known failures, rollback/compensation, verifier, and stop condition"
                .to_owned(),
            allowed_next_action: "submit one declared operation with a valid envelope".to_owned(),
        });
    }
    let operation = envelope.operation.clone();
    check_required_text(envelope, &operation)?;
    check_authority_binding(envelope, &operation)?;
    let impact = check_resources_and_impact(envelope, &operation)?;
    check_action_model(envelope, &operation, impact)?;
    Ok(ValidatedAction {
        operation,
        impact,
        scope_ref: envelope.scope_ref.clone(),
        applicable_authority: envelope.applicable_authority.clone(),
        state_fence: envelope.state_fence.clone(),
        verifier: envelope.verifier.clone(),
    })
}

/// Builds the standard pre-adapter refusal for one declared operation.
fn reject_for(operation: &str, reason: String) -> ActionRejection {
    ActionRejection {
        operation: operation.to_owned(),
        reason,
        preserved_state: format!(
            "no adapter invoked for '{operation}'; prior registration/claim state unchanged"
        ),
        retryable: true,
        retry_status: "retryable: resubmit with a valid authority-bound envelope".to_owned(),
        required_authority: format!(
            "authority-bound action envelope for '{operation}' (`WorkScope`, State Fence, Authority Epoch, applicable authority)"
        ),
        required_repair: "attach intent/scope, preconditions, expected effect, invariants/known failures, rollback/compensation, verifier, and stop condition"
            .to_owned(),
        allowed_next_action: format!(
            "submit '{operation}' with a valid envelope; or submit an Observe probe"
        ),
    }
}

/// Checks the required envelope text: every always-required field present and
/// bounded, every action-model field bounded (presence enforced later by
/// impact in [`check_action_model`]).
#[allow(
    clippy::result_large_err,
    reason = "typed refusal surface is matched by value on purpose"
)]
fn check_required_text(envelope: &ActionEnvelope, operation: &str) -> Result<(), ActionRejection> {
    for (field, value, limit) in [
        ("intent", envelope.intent.as_str(), MAX_ENVELOPE_TEXT_LEN),
        ("scope_ref", envelope.scope_ref.as_str(), MAX_IDENTITY_LEN),
        (
            "applicable_authority",
            envelope.applicable_authority.as_str(),
            MAX_IDENTITY_LEN,
        ),
        (
            "tool_profile",
            envelope.tool_profile.as_str(),
            MAX_IDENTITY_LEN,
        ),
        (
            "stop_condition",
            envelope.stop_condition.as_str(),
            MAX_ENVELOPE_TEXT_LEN,
        ),
        ("verifier", envelope.verifier.as_str(), MAX_IDENTITY_LEN),
    ] {
        if value.len() > limit {
            return Err(reject_for(
                operation,
                format!("envelope field '{field}' is oversized"),
            ));
        }
        if value.trim().is_empty() {
            return Err(reject_for(
                operation,
                format!("envelope field '{field}' is missing"),
            ));
        }
    }
    for (field, value) in [
        ("preconditions", envelope.preconditions.as_str()),
        ("expected_effect", envelope.expected_effect.as_str()),
        ("invariants", envelope.invariants.as_str()),
        ("known_failures", envelope.known_failures.as_str()),
        (
            "rollback_or_compensation",
            envelope.rollback_or_compensation.as_str(),
        ),
    ] {
        if value.len() > MAX_ENVELOPE_TEXT_LEN {
            return Err(reject_for(
                operation,
                format!("envelope field '{field}' is oversized"),
            ));
        }
    }
    Ok(())
}

/// Checks the authority binding: the State Fence and Authority Epoch must
/// each be an admitted object. Currentness stays with the Kernel contour.
#[allow(
    clippy::result_large_err,
    reason = "typed refusal surface is matched by value on purpose"
)]
fn check_authority_binding(
    envelope: &ActionEnvelope,
    operation: &str,
) -> Result<(), ActionRejection> {
    if !envelope.state_fence.is_object() {
        return Err(reject_for(
            operation,
            "envelope State Fence is not bound: an admitted fence object is required".to_owned(),
        ));
    }
    if !envelope.authority_epoch.is_object() {
        return Err(reject_for(
            operation,
            "envelope Authority Epoch is not bound: an admitted epoch object is required"
                .to_owned(),
        ));
    }
    Ok(())
}

/// Checks the affected-resource bounds and derives the Governor impact,
/// refusing `Forbidden` outright.
#[allow(
    clippy::result_large_err,
    reason = "typed refusal surface is matched by value on purpose"
)]
fn check_resources_and_impact(
    envelope: &ActionEnvelope,
    operation: &str,
) -> Result<ImpactClass, ActionRejection> {
    if envelope.affected_resources.len() > MAX_AFFECTED_RESOURCES {
        return Err(reject_for(
            operation,
            "envelope affected resources exceed 16 entries".to_owned(),
        ));
    }
    for resource in &envelope.affected_resources {
        if resource.len() > MAX_RESOURCE_LEN || resource.trim().is_empty() {
            return Err(reject_for(
                operation,
                "envelope affected resource is missing or oversized".to_owned(),
            ));
        }
    }
    let impact = derive_impact(envelope.tool_profile.as_str(), &envelope.affected_resources);
    if impact == ImpactClass::Forbidden {
        return Err(ActionRejection {
            operation: operation.to_owned(),
            reason: "forbidden impact: prohibited by an active Hard Boundary or Policy".to_owned(),
            preserved_state: format!(
                "no adapter invoked for '{operation}'; prior registration/claim state unchanged"
            ),
            retryable: false,
            retry_status: "not-retryable: forbidden effects never invoke an adapter".to_owned(),
            required_authority: "policy exception (out of scope for this contour)".to_owned(),
            required_repair: "remove the forbidden effect or submit a Diagnose-only probe"
                .to_owned(),
            allowed_next_action: "submit an Observe probe".to_owned(),
        });
    }
    Ok(impact)
}

/// Requires every A10.3 action-model field for Material or Critical effects.
#[allow(
    clippy::result_large_err,
    reason = "typed refusal surface is matched by value on purpose"
)]
fn check_action_model(
    envelope: &ActionEnvelope,
    operation: &str,
    impact: ImpactClass,
) -> Result<(), ActionRejection> {
    if !impact.requires_action_model() {
        return Ok(());
    }
    for (field, value) in [
        ("preconditions", envelope.preconditions.as_str()),
        ("expected_effect", envelope.expected_effect.as_str()),
        ("invariants", envelope.invariants.as_str()),
        ("known_failures", envelope.known_failures.as_str()),
        (
            "rollback_or_compensation",
            envelope.rollback_or_compensation.as_str(),
        ),
    ] {
        if value.trim().is_empty() {
            return Err(reject_for(
                operation,
                format!("material action-model field '{field}' is missing (A10.3)"),
            ));
        }
    }
    Ok(())
}

/// Requires a valid authority-bound envelope for one declared operation.
///
/// A missing envelope, an envelope bound to a different operation, or an
/// invalid envelope is rejected pre-adapter with the standardized reason,
/// preserved state, retry status, required authority/repair, and allowed next
/// action. The caller must invoke the adapter only on `Ok`.
// The typed refusal carries the full A10.1 repair shape by value so the
// acceptance fields stay directly readable; boxing would obscure them.
#[allow(
    clippy::result_large_err,
    reason = "typed refusal surface is matched by value on purpose"
)]
pub fn require_governed_op(
    envelope: Option<&ActionEnvelope>,
    operation: &str,
) -> Result<ValidatedAction, ActionRejection> {
    let Some(presented) = envelope else {
        return Err(generic_rejection(
            operation,
            &format!(
                "declared external-adapter op '{operation}' requires a valid authority-bound action envelope; none was presented"
            ),
        ));
    };
    if presented.operation != operation {
        return Err(ActionRejection {
            operation: operation.to_owned(),
            reason: format!(
                "action envelope binds '{}' but '{operation}' was requested",
                presented.operation
            ),
            preserved_state: format!(
                "no adapter invoked for '{operation}'; prior registration/claim state unchanged"
            ),
            retryable: false,
            retry_status:
                "not-retryable: rebinding an envelope to another operation never invokes an adapter"
                    .to_owned(),
            required_authority: format!(
                "authority-bound action envelope for '{operation}' (`WorkScope`, State Fence, Authority Epoch, applicable authority)"
            ),
            required_repair: "attach intent/scope, preconditions, expected effect, invariants/known failures, rollback/compensation, verifier, and stop condition"
                .to_owned(),
            allowed_next_action: format!(
                "submit '{operation}' with a valid envelope; or submit an Observe probe"
            ),
        });
    }
    validate_envelope(presented)
}

/// Records the returned observation/effect bound to the State Fence and
/// verifier (A10.1 steps 7-8). Pure projection: it stores no durable state.
#[must_use]
pub fn record_effect(validated: &ValidatedAction, observation: &str) -> RecordedEffect {
    RecordedEffect {
        operation: validated.operation.clone(),
        scope_ref: validated.scope_ref.clone(),
        state_fence: validated.state_fence.clone(),
        verifier: validated.verifier.clone(),
        observation: observation.chars().take(MAX_ENVELOPE_TEXT_LEN).collect(),
    }
}

/// Maps the verifier verdict to the honest finish vocabulary (A10.8).
///
/// A bound verifier that is met with admissible proof finishes
/// `VERIFIED_COMPLETE`. An unmet verifier finishes `FAILED_VERIFICATION`; an
/// explicit `unknown:` verifier or inadmissible proof finishes
/// `DEGRADED_NO_PROOF`. Completion is never returned without both.
#[must_use]
pub fn finish_for_verdict(
    validated: &ValidatedAction,
    verifier_met: bool,
    proof_admissible: bool,
) -> FinishState {
    if validated
        .verifier
        .trim_start()
        .to_lowercase()
        .starts_with("unknown:")
    {
        return FinishState::DegradedNoProof;
    }
    if verifier_met && proof_admissible {
        FinishState::VerifiedComplete
    } else if verifier_met {
        FinishState::DegradedNoProof
    } else {
        FinishState::FailedVerification
    }
}

/// Runs one declared external-adapter invoke behind the governed gate.
///
/// The adapter closure runs if and only if the envelope validates; every
/// refusal returns without invoking the closure, so a missing or invalid
/// envelope records no adapter effect. Returns the validated action plus the
/// adapter output on success.
// The typed refusal carries the full A10.1 repair shape by value so the
// acceptance fields stay directly readable; boxing would obscure them.
#[allow(
    clippy::result_large_err,
    reason = "typed refusal surface is matched by value on purpose"
)]
pub fn run_governed_external_op<T>(
    operation: &str,
    envelope: Option<&ActionEnvelope>,
    adapter: impl FnOnce(&ValidatedAction) -> T,
) -> Result<(ValidatedAction, T), ActionRejection> {
    let validated = require_governed_op(envelope, operation)?;
    let output = adapter(&validated);
    Ok((validated, output))
}

impl From<ActionRejection> for crate::NativeWorkerError {
    fn from(rejection: ActionRejection) -> Self {
        Self::KernelAdmissionRequired(rejection.to_string())
    }
}
