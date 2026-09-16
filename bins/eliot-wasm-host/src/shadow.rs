//! Host-side shadow no-effect enforcement gate (issue #21, AC4).
//!
//! Normative basis: A13.3 — a shadow performs no external effect and changes
//! no canonical state, scheduling, policy, or memory influence; it produces
//! divergence evidence. This module owns only the host half of that property:
//! after the Wasmtime provider produces an [`EngineReport`] and before that
//! report leaves the host toward the A-12 facade, the gate denies any
//! shadow-contour report that carries canonical/external effect content or
//! scheduling/memory demand beyond its admitted envelope. At the provider
//! boundary a violation maps to [`PortError::Denied`], so a violating shadow
//! report is never propagated to the facade.
//!
//! Non-shadow contours pass through untouched. Admission, policy, routing,
//! generation, fencing, and promotion verdicts stay with the Governor/Kernel
//! owners; the Governor-half verifier
//! (`PromotionVerificationPort::verify_execution`,
//! `crates/modules/eliot-wasm-runtime/src/ports.rs:42-48`) is a recorded
//! handoff, not implemented here. No new crate, no compat shims, and no
//! policy or routing decisions: the gate reads only the contour, the
//! already-admitted limits, and the provider's own report.

use std::fmt;

use eliot_wasm_runtime::{
    EngineReport, EngineTermination, ExecutionContour, InvocationLimits, PortError,
};

/// Fail-closed shadow gate errors with stable codes. Reasons are fixed
/// reason strings; no guest payload, digest, or backtrace is echoed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ShadowError {
    /// Shadow report carries canonical effect content.
    CanonicalEffectDenied(&'static str),
    /// Shadow report carries external effect content.
    ExternalEffectDenied(&'static str),
    /// Shadow report demands scheduling influence beyond its envelope.
    SchedulingInfluenceDenied(&'static str),
    /// Shadow report demands memory or cache influence beyond its envelope.
    MemoryInfluenceDenied(&'static str),
}

impl fmt::Display for ShadowError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CanonicalEffectDenied(reason) => {
                write!(formatter, "SHADOW_CANONICAL_EFFECT_DENIED:{reason}")
            }
            Self::ExternalEffectDenied(reason) => {
                write!(formatter, "SHADOW_EXTERNAL_EFFECT_DENIED:{reason}")
            }
            Self::SchedulingInfluenceDenied(reason) => {
                write!(formatter, "SHADOW_SCHEDULING_INFLUENCE_DENIED:{reason}")
            }
            Self::MemoryInfluenceDenied(reason) => {
                write!(formatter, "SHADOW_MEMORY_INFLUENCE_DENIED:{reason}")
            }
        }
    }
}

impl std::error::Error for ShadowError {}

/// Maps a gate violation to the fail-closed provider port error. The typed
/// [`ShadowError`] remains observable at the gate itself (and in its proof);
/// the port carries only denial, never the violating report.
#[must_use]
pub const fn shadow_port_error(_: ShadowError) -> PortError {
    PortError::Denied
}

/// Enforces shadow no-effect for one provider report against its contour and
/// admitted limits. Returns `Ok` for non-shadow contours without inspecting
/// the report, and for shadow reports that carry no effect content and stay
/// inside every admitted scheduling/memory bound. Any violation on the shadow
/// contour returns the typed denial.
///
/// # Errors
///
/// Returns [`ShadowError`] when the shadow contour carries proposed effects,
/// state deltas, host calls, or out-of-envelope scheduling/memory demand.
pub fn enforce_shadow_no_effect(
    contour: ExecutionContour,
    limits: &InvocationLimits,
    report: &EngineReport,
) -> Result<(), ShadowError> {
    if !matches!(contour, ExecutionContour::Shadow) {
        return Ok(());
    }
    deny_effect_content(report)?;
    deny_scheduling_influence(limits, report)?;
    deny_memory_influence(limits, report)?;
    Ok(())
}

/// Denies canonical/external effect content on the shadow contour. Shadow
/// output bytes remain allowed: they are divergence evidence for the
/// Governor-owned comparison, not an effect.
fn deny_effect_content(report: &EngineReport) -> Result<(), ShadowError> {
    // Canonical state: proposed effects and observed state deltas must be
    // absent, mirroring the facade contract that shadow reports carry none.
    if !report.proposed_effects.is_empty() {
        return Err(ShadowError::CanonicalEffectDenied("proposed-effects"));
    }
    if !report.observed_state_delta.is_empty() {
        return Err(ShadowError::CanonicalEffectDenied("state-delta"));
    }
    // External effects: neither named host calls nor counted host-call usage
    // may escape a shadow execution.
    if !report.host_calls.is_empty() || report.usage.host_calls != 0 {
        return Err(ShadowError::ExternalEffectDenied("host-calls"));
    }
    Ok(())
}

/// Denies scheduling influence beyond the admitted envelope: the effective
/// epoch policy must equal the admitted one, epoch ticks must stay within
/// the admitted deadline, and wall time beyond the deadline is admitted only
/// with a deadline termination the provider actually observed.
fn deny_scheduling_influence(
    limits: &InvocationLimits,
    report: &EngineReport,
) -> Result<(), ShadowError> {
    if report.usage.effective_epoch_policy != limits.epoch {
        return Err(ShadowError::SchedulingInfluenceDenied("epoch-policy"));
    }
    if report
        .usage
        .epoch_ticks
        .is_none_or(|ticks| ticks > limits.epoch.deadline_ticks)
    {
        return Err(ShadowError::SchedulingInfluenceDenied("epoch-ticks"));
    }
    if report.usage.elapsed_ms > limits.wall_deadline_ms
        && !matches!(
            report.termination,
            EngineTermination::Deadline | EngineTermination::EpochDeadline
        )
    {
        return Err(ShadowError::SchedulingInfluenceDenied("wall-deadline"));
    }
    Ok(())
}

/// Denies memory and cache influence beyond the admitted envelope: peak
/// memory, table elements, instances, stack, and artifact reads must stay
/// inside the limits the provider itself enforced, and every accessed
/// artifact digest must remain allow-listed so shadow execution cannot pull
/// unadmitted bytes into shared caches.
fn deny_memory_influence(
    limits: &InvocationLimits,
    report: &EngineReport,
) -> Result<(), ShadowError> {
    if report
        .usage
        .peak_memory_bytes
        .is_none_or(|bytes| bytes > limits.max_memory_bytes)
    {
        return Err(ShadowError::MemoryInfluenceDenied("peak-memory"));
    }
    if report
        .usage
        .table_elements
        .is_none_or(|elements| elements > limits.max_table_elements)
    {
        return Err(ShadowError::MemoryInfluenceDenied("table-elements"));
    }
    if report.usage.instances > limits.max_instances {
        return Err(ShadowError::MemoryInfluenceDenied("instances"));
    }
    if report
        .usage
        .stack_bytes
        .is_some_and(|bytes| bytes > limits.max_stack_bytes)
        || report.usage.enforced_stack_limit_bytes != Some(limits.max_stack_bytes)
    {
        return Err(ShadowError::MemoryInfluenceDenied("stack-limit"));
    }
    if report.usage.artifact_reads > limits.artifact_access.max_reads
        || report.usage.artifact_bytes > limits.artifact_access.max_bytes
    {
        return Err(ShadowError::MemoryInfluenceDenied("artifact-bounds"));
    }
    if !report
        .usage
        .accessed_artifact_digests
        .iter()
        .all(|digest| limits.artifact_access.allowed_digests.contains(digest))
    {
        return Err(ShadowError::MemoryInfluenceDenied("artifact-allowlist"));
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use eliot_wasm_runtime::{CapabilityId, EffectProposal, EngineUsage, Sha256Digest};

    #[test]
    fn shadow_gate_denies_influence_and_passes_clean_or_governed() {
        let digest = Sha256Digest::of_bytes(b"shadow-gate-fixture");
        let limits = crate::typed_execution::default_experimental_limits(digest.clone());
        let usage = EngineUsage {
            attempted_output_bytes: 0, output_bytes: 0, host_calls: 0, fuel_consumed: 7,
            peak_memory_bytes: Some(1024), table_elements: Some(0), instances: 1, stack_bytes: None,
            enforced_stack_limit_bytes: Some(limits.max_stack_bytes), elapsed_ms: 3,
            effective_epoch_policy: limits.epoch, epoch_ticks: Some(9), artifact_reads: 1,
            artifact_bytes: 1024, accessed_artifact_digests: vec![digest.clone()],
        };
        let mut report = EngineReport {
            request_digest: digest.clone(), termination: EngineTermination::Completed, usage,
            output: Vec::new(), host_calls: Vec::new(), proposed_effects: Vec::new(),
            observed_state_delta: Vec::new(), post_commit_known: true,
        };
        let shadow = ExecutionContour::Shadow;
        assert_eq!(enforce_shadow_no_effect(shadow, &limits, &report), Ok(()));
        report.proposed_effects = vec![EffectProposal {
            effect_kind: CapabilityId::new("effect").expect("effect"),
            payload_digest: digest.clone(),
        }];
        assert_eq!(enforce_shadow_no_effect(ExecutionContour::Active, &limits, &report), Ok(()));
        assert_eq!(
            enforce_shadow_no_effect(shadow, &limits, &report),
            Err(ShadowError::CanonicalEffectDenied("proposed-effects"))
        );
        report.proposed_effects = Vec::new();
        report.observed_state_delta = vec![9];
        assert_eq!(
            enforce_shadow_no_effect(shadow, &limits, &report),
            Err(ShadowError::CanonicalEffectDenied("state-delta"))
        );
        report.observed_state_delta = Vec::new();
        report.usage.host_calls = 1;
        report.host_calls = vec![CapabilityId::new("call").expect("call")];
        assert_eq!(
            enforce_shadow_no_effect(shadow, &limits, &report),
            Err(ShadowError::ExternalEffectDenied("host-calls"))
        );
        report.usage.host_calls = 0;
        report.host_calls = Vec::new();
        report.usage.effective_epoch_policy.deadline_ticks += 1;
        assert_eq!(
            enforce_shadow_no_effect(shadow, &limits, &report),
            Err(ShadowError::SchedulingInfluenceDenied("epoch-policy"))
        );
        report.usage.effective_epoch_policy = limits.epoch;
        report.usage.peak_memory_bytes = Some(limits.max_memory_bytes + 1);
        assert_eq!(
            enforce_shadow_no_effect(shadow, &limits, &report),
            Err(ShadowError::MemoryInfluenceDenied("peak-memory"))
        );
    }
}
