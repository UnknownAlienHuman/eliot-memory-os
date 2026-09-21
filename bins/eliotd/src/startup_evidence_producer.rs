//! Governor startup evidence producer for I1.11 steps 8 and 9 (issue #1967).
//!
//! Architecture: I1.11 (Startup algorithm) steps 8 (`eliotd` loads
//! Config/Policy snapshots and rebuilds hot mirrors) and 9 (required
//! capability set is evaluated); I1.10 (service health) readiness meaning;
//! A2.3 (contract → ports → adapters layering); A0.3 hard boundaries stay
//! fail-closed. This cell is the Governor application evaluation owned by
//! `eliotd`: it binds the live transport operation binding, the admitted and
//! observed fences, canonical mirror rebuild outputs, and required
//! capability outcomes into one authenticated [`EliotdStartupEvidence`]
//! payload for the Kernel consumer (`bins/eliot-kernel` step 8/9 cursor;
//! see `2241-owner-handoff.md` and `1967-governor-protocol-handoff.md`).
//!
//! Evidence model (no completed flags, no ready synthesis):
//!
//! - the payload carries observed VALUES (present) and explicit ABSENCE
//!   markers (`None`), never a step claim. The Kernel cursor records a step
//!   only from satisfied values; absent markers leave the step absent. A
//!   missing acquirable input (transport binding, fences, Config mirror)
//!   blocks the build with [`StartupEvidenceError::Missing`]; inputs whose
//!   owner does not exist yet in this tree (Policy mirror, required set,
//!   outcomes, registry digest, generation fingerprint) build as absence
//!   markers with warn diagnostics naming them.
//! - ready is never set from a nonempty list, a caller flag, or a newly
//!   instantiated default `Config`. Present mirror digests must be validated
//!   [`PlatformHandle`] values and byte-equal between the canonical source
//!   and the rebuilt mirror. The operation fence must equal the transport
//!   binding fence exactly and be compatible with the independently observed
//!   Kernel fence (same authority tuple and generation).
//! - every observed required capability needs a validated, live outcome
//!   covering it; an unvalidated broad outcome, an expired-only coverage, or
//!   a route the registry view deems ineligible blocks the build. The
//!   capability registry digest is recomputed from the evaluated outcomes
//!   and must match the threaded digest, so bare definition agreement
//!   without the same dependencies cannot pass.
//! - `WriteReceipt.status=committed` and `DaemonStatus.ready` prove durable
//!   transport and daemon liveness only. Neither satisfies a mirror digest,
//!   an outcome, or eligibility here because none of those are inputs.
//!
//! Delegation boundary (delegate, never copy):
//!
//! - durable commit, projection publication, Doctor rebuild recipes,
//!   Material-decision support, and the Kernel step cursor stay with their
//!   owners. The caller threads already-observed values per call, so a
//!   refresh surfaces as an exact mismatch instead of silent divergence.
//! - [`CapabilityOutcome`] validation, registry recording, and
//!   [`CapabilityRegistryView::is_route_eligible`] stay owned by
//!   `capability_outcome.rs`; this cell reuses them and never duplicates the
//!   semantic `CapabilityOutcome` owner. Kernel-side agreement on the shared
//!   wire form is recorded in `1967-governor-protocol-handoff.md`; the Kernel
//!   lane must neither import this binary crate nor re-implement the owner.
//! - the transport operation binding is minted by the authenticated channel
//!   owner (`DaemonKernelClient::mint_startup_evidence_identity`) for this
//!   exact publish and correlated by `send_startup_evidence`; the producer
//!   never mints identities. A store-domain `OperationIdentity` has no
//!   source at daemon startup, so the evidence binds the transport identity
//!   the Kernel already authenticates instead of synthesizing one.
//! - policy content comes only from the recovered Governor `PolicyOwner`
//!   (actual canonical snapshot, fence/revision/digest correlated at
//!   recovery). In particular the unaccepted 1966 precedence helper is not
//!   a canonical policy source: only digests bound to caller-observed
//!   canonical rebuild outputs enter the payload. While the Kernel does not
//!   serve the Policy named read, the owner is absent and the mirror stays
//!   an explicit marker (see below) — never a Config digest.
//!
//! Caller integration (exact owner handoff):
//!
//! - [`build_startup_evidence`] evaluates one [`StartupEvidenceRequest`]
//!   into the wire payload. The owning daemon flow calls
//!   [`publish_daemon_startup_evidence`] at the real readiness site (after
//!   `report_ready`), threading the live Kernel fence, the admitted
//!   composition fence, the Kernel-observed protected digest, and the
//!   recovered Config projection digest; values not yet observable stay
//!   missing and yield explicit diagnostics instead of a ready claim.
//!   Publish transport failure never fails the daemon: the existing step-7
//!   live-receipt path is unchanged and the Kernel keeps steps 8/9 fenced
//!   until its consumer lands.
//! - Config mirror sources (both live, same digest domain, independently
//!   retained): canonical = the Kernel snapshot protected digest;
//!   rebuilt = the recovered `ConfigOwner` projection digest. Rotation
//!   between recovery and the readiness site fails the build instead of
//!   publishing skew.
//! - absent owners (explicit markers, warn diagnostics, follow-up owners):
//!   Policy mirror while the Kernel does not serve the Policy named read
//!   (owner absent; needs the Kernel-served read plus the live projection),
//!   required set and outcomes (no retained registry or startup evaluation
//!   in the daemon yet; B2280 capability-admission coordination point),
//!   generation fingerprint (Generation Registry scheme is Kernel-owned).
//!
//! Like the neighboring admission joins, this helper never mints admission,
//! identity, or fences: it evaluates presented values and returns evidence
//! or a named blocker.

use eliot_contracts::{StateFence, sha256_hex};
use eliot_platform::PlatformHandle;
use eliot_protocol::RequestIdentity;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::capability_outcome::{CapabilityOutcome, CapabilityRegistryView};

/// Authenticated daemon readiness exchange operation carrying the startup
/// evidence payload. The Kernel consumer (BHost/Ramanujan lane) serves this
/// alongside the existing `daemon_ready` live receipt; see
/// `1967-governor-protocol-handoff.md`. Unknown-operation rejection before
/// the consumer lands is fail-closed and expected.
pub const DAEMON_STARTUP_EVIDENCE_OPERATION: &str = "daemon_startup_evidence";

/// Maximum required capabilities evaluated in one evidence payload.
pub const MAX_REQUIRED_CAPABILITIES: usize = 64;
/// Maximum capability outcomes evaluated in one evidence payload.
pub const MAX_CAPABILITY_OUTCOMES: usize = 256;
/// Maximum auxiliary evidence references carried in one payload.
pub const MAX_EVIDENCE_REFS: usize = 64;
/// Maximum bytes for one required capability name or fingerprint.
pub const MAX_IDENTITY_LEN: usize = 256;

/// Fail-closed startup evidence error: malformed input, missing acquirable
/// prerequisite, or a value mismatch against canonical observations.
///
/// Missing acquirable sources are explicit not-ready evidence: the caller
/// (and its diagnostics) receives the named prerequisite instead of a ready
/// claim. Markers for not-yet-existing owners are carried in the payload,
/// not in this error.
#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum StartupEvidenceError {
    /// A required acquirable prerequisite was not observed (no transport
    /// binding, no operation fence, no Config mirror, incomplete capability
    /// evaluation inputs).
    #[error("startup evidence missing: {0}")]
    Missing(String),
    /// An observed value disagrees with its canonical counterpart (changed
    /// digest, incompatible fence, expired or ineligible capability,
    /// registry digest not bound to the evaluated outcomes).
    #[error("startup evidence mismatch: {0}")]
    Mismatch(String),
    /// A field is malformed or an owned validator rejected it.
    #[error("startup evidence contract: {0}")]
    Contract(String),
}

fn check_name(field: &str, value: &str) -> Result<(), StartupEvidenceError> {
    if value.trim().is_empty()
        || value.len() > MAX_IDENTITY_LEN
        || value.chars().any(char::is_control)
    {
        return Err(StartupEvidenceError::Contract(format!(
            "{field} is blank, unbounded, or contains control characters"
        )));
    }
    Ok(())
}

/// One observed Config/Policy mirror rebuild output (I1.11 step 8).
///
/// The canonical source digest comes from the canonical owner (e.g. the
/// Kernel-observed protected digest for Config); the rebuilt digest is the
/// live recovered projection. The producer compares values only and never
/// reads the underlying stores.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MirrorObservation {
    /// Canonical source digest the mirror must reproduce.
    pub canonical_source_digest: PlatformHandle,
    /// Digest of the actually rebuilt hot mirror.
    pub rebuilt_digest: PlatformHandle,
}

/// Required-capability evaluation inputs threaded per evidence call.
///
/// Every `Option` is load-bearing. `None` on an acquirable input blocks the
/// build with an explicit missing prerequisite. `None` on a future-owner
/// input (policy mirror, required set, outcomes, registry digest,
/// generation fingerprint) builds as an explicit absence marker: the Kernel
/// cursor leaves the corresponding step absent. The durable store, the
/// registry owner, and the capability model own truth; this shape is the
/// exact observed value the caller presents for one evaluation.
#[derive(Clone, Debug)]
pub struct StartupEvidenceRequest {
    /// Transport operation binding minted by the authenticated channel for
    /// this exact publish. The daemon never synthesizes it: `None` blocks
    /// the build until the channel owner provides the live binding.
    pub transport_binding: Option<RequestIdentity>,
    /// State fence the evidence is bound to (admitted composition fence).
    /// Must equal the binding fence exactly and stay compatible with the
    /// independently observed Kernel fence.
    pub operation_fence: Option<StateFence>,
    /// Independently observed Kernel fence (live snapshot). Always required:
    /// without the Kernel observation nothing can be evaluated.
    pub observed_kernel_fence: StateFence,
    /// Observed Config mirror rebuild output. Acquirable: `None` blocks.
    pub config_mirror: Option<MirrorObservation>,
    /// Observed Policy mirror rebuild output. `None` builds as an absence
    /// marker while the Kernel does not serve the Policy named read
    /// (owner absent); a served owner threads its canonical/rebuilt pair.
    pub policy_mirror: Option<MirrorObservation>,
    /// Required capability names from the capability model. `None` builds
    /// as an absence marker; an explicitly empty set is satisfied and
    /// documented as such.
    pub required_capabilities: Option<Vec<String>>,
    /// Evaluated capability outcomes covering the required set.
    pub capability_outcomes: Option<Vec<CapabilityOutcome>>,
    /// Digest of the capability registry the outcomes were evaluated
    /// against. Recomputed from the outcomes and required to match, so the
    /// digest is bound to evidence instead of asserted alongside it.
    pub capability_registry_digest: Option<PlatformHandle>,
    /// Active generation fingerprint the eligibility check runs against. The
    /// fingerprint scheme belongs to the generation owner (Kernel Generation
    /// Registry); eliotd threads the observed value and never mints it.
    pub active_generation_fingerprint: Option<String>,
    /// Session scope for the eligibility check, when the daemon runs under
    /// an owner session. `None` checks installation and generation blocks
    /// only and documents that session scoping was not evaluated.
    pub session_id: Option<String>,
    /// Auxiliary evidence references carried opaquely (each a validated
    /// handle). May be empty when the caller observed no extra refs.
    pub evidence_refs: Vec<PlatformHandle>,
    /// Caller-observed clock for outcome expiry checks only; never authority.
    pub now_unix_ms: u64,
}

/// Authenticated Governor startup evidence payload (I1.11 steps 8/9).
///
/// Exact wire shape agreed with the Kernel consumer; see
/// `1967-governor-protocol-handoff.md`. `Option` fields carry explicit
/// absence (`null` on the wire; fields must be present, not omitted): the
/// Kernel records step 8 only with both mirror digests validated, and step 9
/// only with a complete capability evaluation. Absent markers leave the
/// corresponding step absent; they never satisfy it.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EliotdStartupEvidence {
    /// Transport operation binding this evidence is published under,
    /// minted by the authenticated channel for this exact publish.
    pub transport_binding: RequestIdentity,
    /// State fence this evidence is bound to (equals the binding fence).
    pub state_fence: StateFence,
    /// Validated Config mirror digest.
    pub config_mirror_digest: PlatformHandle,
    /// Validated Policy mirror digest, or explicit absence.
    pub policy_mirror_digest: Option<PlatformHandle>,
    /// Capability registry digest bound to the evaluated outcomes, or
    /// explicit absence.
    pub capability_registry_digest: Option<PlatformHandle>,
    /// Required capability names evaluated, or explicit absence.
    pub required_capabilities: Option<Vec<String>>,
    /// Validated outcomes covering the required set, or explicit absence.
    pub capability_outcomes: Option<Vec<CapabilityOutcome>>,
    /// Auxiliary evidence references.
    pub evidence_refs: Vec<PlatformHandle>,
}

impl EliotdStartupEvidence {
    /// Validates the payload through the owning validators and the
    /// cross-field consistency rules. Malformed payloads admit nothing and
    /// are never published. A payload with absence markers validates: the
    /// markers are explicit, and only the Kernel cursor decides steps.
    ///
    /// # Errors
    ///
    /// Returns [`StartupEvidenceError::Contract`] when any owned validator
    /// rejects the payload or the optional capability fields are
    /// inconsistently populated (a partial capability evaluation is neither
    /// evidence nor an honest marker).
    pub fn validate(&self) -> Result<(), StartupEvidenceError> {
        self.transport_binding.validate().map_err(|error| {
            StartupEvidenceError::Contract(format!("transport binding: {error}"))
        })?;
        self.state_fence
            .validate()
            .map_err(|error| StartupEvidenceError::Contract(format!("state fence: {error}")))?;
        if self.state_fence != self.transport_binding.request.state_fence {
            return Err(StartupEvidenceError::Contract(
                "state fence must equal the transport binding fence".to_owned(),
            ));
        }
        if self.evidence_refs.len() > MAX_EVIDENCE_REFS {
            return Err(StartupEvidenceError::Contract(
                "evidence reference set is unbounded".to_owned(),
            ));
        }
        let capabilities_present = self.required_capabilities.is_some()
            || self.capability_outcomes.is_some()
            || self.capability_registry_digest.is_some();
        if capabilities_present
            && (self.required_capabilities.is_none()
                || self.capability_outcomes.is_none()
                || self.capability_registry_digest.is_none())
        {
            return Err(StartupEvidenceError::Contract(
                "capability evaluation must be complete or entirely absent".to_owned(),
            ));
        }
        if let Some(required) = &self.required_capabilities {
            if required.len() > MAX_REQUIRED_CAPABILITIES {
                return Err(StartupEvidenceError::Contract(
                    "required capability set is unbounded".to_owned(),
                ));
            }
            for name in required {
                check_name("required capability", name)?;
            }
        }
        if let Some(outcomes) = &self.capability_outcomes {
            if outcomes.len() > MAX_CAPABILITY_OUTCOMES {
                return Err(StartupEvidenceError::Contract(
                    "capability outcome set is unbounded".to_owned(),
                ));
            }
            for outcome in outcomes {
                outcome.validate().map_err(|error| {
                    StartupEvidenceError::Contract(format!(
                        "capability '{}': {error}",
                        outcome.capability
                    ))
                })?;
            }
        }
        Ok(())
    }
}

/// Evaluates one mirror rebuild output: present, well-formed, and byte-equal
/// between the canonical source and the rebuilt mirror.
///
/// # Errors
///
/// Returns [`StartupEvidenceError::Missing`] when the mirror was not
/// observed, or [`StartupEvidenceError::Mismatch`] when the rebuilt digest
/// differs from the canonical source (changed/stale mirror).
fn evaluate_mirror(
    mirror_name: &str,
    mirror: Option<&MirrorObservation>,
) -> Result<PlatformHandle, StartupEvidenceError> {
    let Some(mirror) = mirror else {
        return Err(StartupEvidenceError::Missing(format!(
            "{mirror_name} mirror has no rebuilt observation"
        )));
    };
    if mirror.canonical_source_digest != mirror.rebuilt_digest {
        return Err(StartupEvidenceError::Mismatch(format!(
            "{mirror_name} mirror rebuilt digest differs from the canonical source"
        )));
    }
    Ok(mirror.canonical_source_digest.clone())
}

/// Recomputes the capability registry digest from the evaluated outcomes.
///
/// Scheme (documented for the Kernel consumer): canonical JSON of each
/// outcome, sorted byte-wise, concatenated, SHA-256 hex. Order-independent
/// so admission compares values instead of arrival order; any outcome change
/// (including a silent substitution) changes the digest.
///
/// # Errors
///
/// Returns [`StartupEvidenceError::Contract`] when the outcomes are not
/// canonical JSON or the digest is not a valid handle.
fn registry_digest_for(
    outcomes: &[CapabilityOutcome],
) -> Result<PlatformHandle, StartupEvidenceError> {
    let mut forms = Vec::with_capacity(outcomes.len());
    for outcome in outcomes {
        let value = serde_json::to_value(outcome).map_err(|error| {
            StartupEvidenceError::Contract(format!("capability outcomes are not JSON: {error}"))
        })?;
        forms.push(serde_json::to_string(&value).map_err(|error| {
            StartupEvidenceError::Contract(format!("capability outcomes are not JSON: {error}"))
        })?);
    }
    forms.sort();
    let digest = sha256_hex(forms.concat().as_bytes());
    PlatformHandle::new(digest).map_err(|error| {
        StartupEvidenceError::Contract(format!("registry digest is not a valid handle: {error}"))
    })
}

/// Evaluates a complete required capability set (I1.11 step 9): every
/// required capability carries a validated live outcome, the registry
/// digest binds exactly those outcomes, and the registry eligibility agrees
/// for the active generation.
///
/// # Errors
///
/// Returns [`StartupEvidenceError::Missing`] for an absent registry digest
/// or generation fingerprint; [`StartupEvidenceError::Contract`] for
/// malformed names or unvalidated (e.g. unevidenced broad) outcomes;
/// [`StartupEvidenceError::Mismatch`] for expired-only coverage, an
/// unbound registry digest, uncovered requirements, or a route the registry
/// deems ineligible.
#[allow(
    clippy::too_many_arguments,
    reason = "one evaluation needs the full threaded observation; a grouped struct would duplicate StartupEvidenceRequest"
)]
fn evaluate_required_capabilities(
    required: &[String],
    outcomes: &[CapabilityOutcome],
    registry_digest: Option<&PlatformHandle>,
    active_generation_fingerprint: Option<&str>,
    session_id: Option<&str>,
    now_unix_ms: u64,
) -> Result<PlatformHandle, StartupEvidenceError> {
    if required.len() > MAX_REQUIRED_CAPABILITIES {
        return Err(StartupEvidenceError::Contract(
            "required capability set is unbounded".to_owned(),
        ));
    }
    for name in required {
        check_name("required capability", name)?;
    }
    if outcomes.len() > MAX_CAPABILITY_OUTCOMES {
        return Err(StartupEvidenceError::Contract(
            "capability outcome set is unbounded".to_owned(),
        ));
    }
    for outcome in outcomes {
        outcome.validate().map_err(|error| {
            StartupEvidenceError::Contract(format!("capability '{}': {error}", outcome.capability))
        })?;
    }
    let Some(threaded_digest) = registry_digest else {
        return Err(StartupEvidenceError::Missing(
            "capability registry digest was not observed".to_owned(),
        ));
    };
    let bound = registry_digest_for(outcomes)?;
    if bound != *threaded_digest {
        return Err(StartupEvidenceError::Mismatch(
            "capability registry digest does not match the evaluated outcomes".to_owned(),
        ));
    }
    for name in required {
        let covering: Vec<&CapabilityOutcome> = outcomes
            .iter()
            .filter(|outcome| outcome.capability == *name)
            .collect();
        if covering.is_empty() {
            return Err(StartupEvidenceError::Missing(format!(
                "required capability '{name}' has no outcome"
            )));
        }
        if covering.iter().all(|outcome| !outcome.is_live(now_unix_ms)) {
            return Err(StartupEvidenceError::Mismatch(format!(
                "required capability '{name}' has no live outcome (recorded outcomes expired)"
            )));
        }
    }
    let Some(fingerprint) = active_generation_fingerprint else {
        return Err(StartupEvidenceError::Missing(
            "active generation fingerprint was not observed".to_owned(),
        ));
    };
    check_name("generation fingerprint", fingerprint)?;
    let mut view = CapabilityRegistryView::default();
    for outcome in outcomes {
        view.record(outcome).map_err(|error| {
            StartupEvidenceError::Contract(format!("capability registry record: {error}"))
        })?;
    }
    if !view.is_route_eligible(fingerprint, session_id, now_unix_ms) {
        return Err(StartupEvidenceError::Mismatch(
            "required capabilities are not route-eligible for the active generation".to_owned(),
        ));
    }
    Ok(bound)
}

/// Builds the authenticated startup evidence payload from one threaded
/// observation (I1.11 steps 8 and 9).
///
/// Fail-closed order: the observed Kernel fence validates first; the
/// transport binding and operation fence must be present, valid, exactly
/// equal, and compatible with the Kernel observation; the Config mirror
/// must reproduce its canonical source. Policy and capability inputs whose
/// owners do not exist yet build as explicit absence markers (never
/// satisfied, never blocking the acquirable evidence); a partially observed
/// capability evaluation blocks. The first blocker wins and names its
/// prerequisite.
///
/// # Errors
///
/// Returns [`StartupEvidenceError`] naming the blocking prerequisite. A
/// missing acquirable source is explicit not-ready evidence, never a ready
/// claim.
pub fn build_startup_evidence(
    request: &StartupEvidenceRequest,
) -> Result<EliotdStartupEvidence, StartupEvidenceError> {
    request.observed_kernel_fence.validate().map_err(|error| {
        StartupEvidenceError::Contract(format!("observed kernel fence: {error}"))
    })?;
    let Some(binding) = &request.transport_binding else {
        return Err(StartupEvidenceError::Missing(
            "no transport operation binding was observed".to_owned(),
        ));
    };
    binding
        .validate()
        .map_err(|error| StartupEvidenceError::Contract(format!("transport binding: {error}")))?;
    let Some(operation_fence) = &request.operation_fence else {
        return Err(StartupEvidenceError::Missing(
            "no operation fence was observed".to_owned(),
        ));
    };
    operation_fence
        .validate()
        .map_err(|error| StartupEvidenceError::Contract(format!("operation fence: {error}")))?;
    if *operation_fence != binding.request.state_fence {
        return Err(StartupEvidenceError::Mismatch(
            "operation fence must equal the transport binding fence".to_owned(),
        ));
    }
    if !operation_fence.is_compatible_with(&request.observed_kernel_fence) {
        return Err(StartupEvidenceError::Mismatch(
            "operation fence is not compatible with the observed kernel fence (wrong generation or epoch)"
                .to_owned(),
        ));
    }
    let config_digest = evaluate_mirror("config", request.config_mirror.as_ref())?;
    if request.evidence_refs.len() > MAX_EVIDENCE_REFS {
        return Err(StartupEvidenceError::Contract(
            "evidence reference set is unbounded".to_owned(),
        ));
    }
    let policy_digest = match &request.policy_mirror {
        Some(mirror) => Some(evaluate_mirror("policy", Some(mirror))?),
        None => None,
    };
    let (required, outcomes, registry) =
        match (&request.required_capabilities, &request.capability_outcomes) {
            (None, None) => (None, None, None),
            (Some(required), Some(outcomes)) => {
                let digest = evaluate_required_capabilities(
                    required,
                    outcomes,
                    request.capability_registry_digest.as_ref(),
                    request.active_generation_fingerprint.as_deref(),
                    request.session_id.as_deref(),
                    request.now_unix_ms,
                )?;
                (Some(required.clone()), Some(outcomes.clone()), Some(digest))
            }
            _ => {
                return Err(StartupEvidenceError::Missing(
                    "capability evaluation inputs are partially observed".to_owned(),
                ));
            }
        };
    let evidence = EliotdStartupEvidence {
        transport_binding: binding.clone(),
        state_fence: operation_fence.clone(),
        config_mirror_digest: config_digest,
        policy_mirror_digest: policy_digest,
        capability_registry_digest: registry,
        required_capabilities: required,
        capability_outcomes: outcomes,
        evidence_refs: request.evidence_refs.clone(),
    };
    evidence.validate()?;
    Ok(evidence)
}

/// Publishes Governor startup evidence from the live daemon flow.
///
/// Called at the real readiness site after `report_ready`: threads the live
/// transport binding, the admitted composition fence, the Kernel-observed
/// protected digest, and the recovered Config projection digest. Values
/// whose owners do not exist yet stay missing and yield explicit warn
/// diagnostics naming them instead of a ready claim. A built payload is
/// published on the authenticated daemon channel; publish transport failure
/// never fails the daemon — the existing step-7 live-receipt path is
/// unchanged and the Kernel keeps steps 8/9 fenced until its consumer
/// lands. Mirror, registry, capability, and operation owners extend this
/// call with their retained observations when available.
pub fn publish_daemon_startup_evidence(
    kernel: &super::DaemonKernelClient,
    composition: &super::DaemonComposition,
) {
    let observed = kernel.kernel_fence();
    let outcome = (|| -> Result<EliotdStartupEvidence, StartupEvidenceError> {
        let binding = kernel.mint_startup_evidence_identity().map_err(|error| {
            StartupEvidenceError::Contract(format!("transport binding mint: {error}"))
        })?;
        let canonical = PlatformHandle::new(
            composition
                .kernel_snapshot()
                .protected_snapshot_digest
                .clone(),
        )
        .map_err(|error| {
            StartupEvidenceError::Contract(format!("kernel protected digest: {error}"))
        })?;
        let rebuilt =
            PlatformHandle::new(composition.config_snapshot_digest()).map_err(|error| {
                StartupEvidenceError::Contract(format!("recovered config digest: {error}"))
            })?;
        // Policy mirror (I1.11 step 8): the canonical half is the
        // Kernel-observed payload digest retained at recovery; the rebuilt
        // half is recomputed live from the retained canonical snapshot. Both
        // halves come from the actual Policy owner — never a Config digest.
        // Unconfigured (Kernel does not serve the Policy read yet) stays an
        // explicit absence marker.
        let policy_mirror = match composition.policy_owner() {
            Some(owner) => {
                let canonical = PlatformHandle::new(owner.canonical_digest()).map_err(|error| {
                    StartupEvidenceError::Contract(format!("kernel policy digest: {error}"))
                })?;
                let rebuilt_digest = owner.rebuilt_envelope_digest().map_err(|error| {
                    StartupEvidenceError::Contract(format!("rebuilt policy digest: {error}"))
                })?;
                let rebuilt = PlatformHandle::new(rebuilt_digest).map_err(|error| {
                    StartupEvidenceError::Contract(format!("rebuilt policy digest: {error}"))
                })?;
                Some(MirrorObservation {
                    canonical_source_digest: canonical,
                    rebuilt_digest: rebuilt,
                })
            }
            None => None,
        };
        let request = StartupEvidenceRequest {
            transport_binding: Some(binding.clone()),
            operation_fence: Some(composition.kernel_snapshot().state_fence()),
            observed_kernel_fence: observed,
            config_mirror: Some(MirrorObservation {
                canonical_source_digest: canonical,
                rebuilt_digest: rebuilt,
            }),
            policy_mirror,
            required_capabilities: None,
            capability_outcomes: None,
            capability_registry_digest: None,
            active_generation_fingerprint: None,
            session_id: None,
            evidence_refs: Vec::new(),
            now_unix_ms: super::unix_ms(),
        };
        let evidence = build_startup_evidence(&request)?;
        kernel
            .send_startup_evidence(&evidence, binding)
            .map_err(|error| {
                StartupEvidenceError::Contract(format!("evidence publish: {error}"))
            })?;
        Ok(evidence)
    })();
    match outcome {
        Ok(_) => {}
        Err(error) => {
            tracing::warn!("governor startup evidence not ready (steps 8/9 stay fenced): {error}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use eliot_contracts::{
        ClockReading, EpochId, EpochLineageId, ProductId, RequestId, RequestMetadata,
        ResourceGeneration, SourceId,
    };
    use eliot_receipts::RequestBinding;
    use std::num::NonZeroU64;

    use crate::capability_outcome::DegradationScope;

    const TEST_LINEAGE: &str = "550e8400-e29b-41d4-a716-446655440000";

    fn contract(reason: impl Into<String>) -> StartupEvidenceError {
        StartupEvidenceError::Contract(reason.into())
    }

    fn test_epoch(sequence: u64) -> Result<EpochId, StartupEvidenceError> {
        let lineage = EpochLineageId::new(TEST_LINEAGE)
            .map_err(|error| contract(format!("test lineage: {error}")))?;
        let sequence =
            NonZeroU64::new(sequence).ok_or_else(|| contract("test sequence must be nonzero"))?;
        EpochId::new(lineage, sequence).map_err(|error| contract(format!("test epoch: {error}")))
    }

    fn test_fence(generation: u64) -> Result<StateFence, StartupEvidenceError> {
        let resource = ResourceGeneration::new(generation)
            .map_err(|error| contract(format!("test generation: {error}")))?;
        Ok(StateFence::new(test_epoch(1)?, resource))
    }

    fn digest(fill: &str) -> Result<PlatformHandle, StartupEvidenceError> {
        PlatformHandle::new(fill.repeat(64))
            .map_err(|error| contract(format!("test digest: {error}")))
    }

    fn mirror() -> Result<MirrorObservation, StartupEvidenceError> {
        Ok(MirrorObservation {
            canonical_source_digest: digest("a")?,
            rebuilt_digest: digest("a")?,
        })
    }

    fn transport_binding(fence: &StateFence) -> Result<RequestIdentity, StartupEvidenceError> {
        let request_id = RequestId::new("eliotd:daemon_startup_evidence:1")
            .map_err(|error| contract(format!("test request id: {error}")))?;
        let metadata = RequestMetadata {
            request_id: request_id.clone(),
            session_id: None,
            task_id: None,
            product_id: ProductId::new("eliotd")
                .map_err(|error| contract(format!("test product: {error}")))?,
            source_id: SourceId::new("eliotd")
                .map_err(|error| contract(format!("test source: {error}")))?,
            state_fence: fence.clone(),
            clock: ClockReading::default(),
        };
        Ok(RequestIdentity {
            request: RequestBinding {
                metadata,
                state_fence: fence.clone(),
            },
            idempotency_key: "eliotd:daemon_startup_evidence:1".to_owned(),
            deadline_unix_ms: 1_800_000_000_000,
            cancellation_id: "eliotd:daemon_startup_evidence:1:cancel".to_owned(),
        })
    }

    fn healthy_outcome(capability: &str) -> CapabilityOutcome {
        CapabilityOutcome {
            capability: capability.to_owned(),
            requested_mode: "route-a".to_owned(),
            effective_mode: "route-a".to_owned(),
            degradation_scope: DegradationScope::Attempt,
            reason: "route-a ran within budget".to_owned(),
            evidence_refs: Vec::new(),
            affected_outputs_or_operations: vec!["dispatch".to_owned()],
            proof_ceiling: "supported".to_owned(),
            recovery_requalification_or_expiry: "requalify-on-failure".to_owned(),
            scope_owner: "attempt-startup-1".to_owned(),
            generation_fingerprint: String::new(),
            valid_until_unix_ms: None,
        }
    }

    fn request() -> Result<StartupEvidenceRequest, StartupEvidenceError> {
        let fence = test_fence(7)?;
        let outcomes = vec![
            healthy_outcome("provider.dispatch"),
            healthy_outcome("store.read"),
        ];
        let registry_digest = registry_digest_for(&outcomes)?;
        Ok(StartupEvidenceRequest {
            transport_binding: Some(transport_binding(&fence)?),
            operation_fence: Some(fence.clone()),
            observed_kernel_fence: fence,
            config_mirror: Some(mirror()?),
            policy_mirror: Some(mirror()?),
            required_capabilities: Some(vec![
                "provider.dispatch".to_owned(),
                "store.read".to_owned(),
            ]),
            capability_outcomes: Some(outcomes),
            capability_registry_digest: Some(registry_digest),
            active_generation_fingerprint: Some("gen-7".to_owned()),
            session_id: None,
            evidence_refs: Vec::new(),
            now_unix_ms: 1_000,
        })
    }

    fn blocked_with(
        mutate: impl FnOnce(&mut StartupEvidenceRequest) -> Result<(), StartupEvidenceError>,
    ) -> Result<StartupEvidenceError, StartupEvidenceError> {
        let mut request = request()?;
        mutate(&mut request)?;
        match build_startup_evidence(&request) {
            Err(error) => Ok(error),
            Ok(_) => Err(contract("expected the evidence gate to block")),
        }
    }

    fn test_outcomes(
        request: &mut StartupEvidenceRequest,
    ) -> Result<Vec<CapabilityOutcome>, StartupEvidenceError> {
        request
            .capability_outcomes
            .take()
            .ok_or_else(|| contract("test outcomes"))
    }

    fn rebind_registry(request: &mut StartupEvidenceRequest) -> Result<(), StartupEvidenceError> {
        let outcomes = request
            .capability_outcomes
            .as_deref()
            .ok_or_else(|| contract("test outcomes"))?;
        request.capability_registry_digest = Some(registry_digest_for(outcomes)?);
        Ok(())
    }

    #[test]
    fn complete_observation_builds_evidence_with_exact_identity_and_refs()
    -> Result<(), StartupEvidenceError> {
        let request = request()?;
        let evidence = build_startup_evidence(&request)?;
        let binding = request
            .transport_binding
            .ok_or_else(|| contract("test binding"))?;
        assert_eq!(evidence.transport_binding, binding);
        assert_eq!(evidence.state_fence, test_fence(7)?);
        assert_eq!(evidence.config_mirror_digest, digest("a")?);
        assert_eq!(evidence.policy_mirror_digest, Some(digest("a")?));
        let registry = request
            .capability_registry_digest
            .ok_or_else(|| contract("test digest"))?;
        assert_eq!(evidence.capability_registry_digest, Some(registry));
        assert_eq!(
            evidence.required_capabilities,
            Some(vec![
                "provider.dispatch".to_owned(),
                "store.read".to_owned()
            ])
        );
        let outcomes = evidence
            .capability_outcomes
            .as_deref()
            .ok_or_else(|| contract("test outcomes"))?;
        assert_eq!(outcomes.len(), 2);
        let wire = serde_json::to_string(&evidence)
            .map_err(|error| StartupEvidenceError::Contract(error.to_string()))?;
        assert!(wire.contains("\"policy_mirror_digest\""));
        let back: EliotdStartupEvidence = serde_json::from_str(&wire)
            .map_err(|error| StartupEvidenceError::Contract(error.to_string()))?;
        assert_eq!(back, evidence);
        Ok(())
    }

    #[test]
    fn production_partial_observation_builds_marked_evidence() -> Result<(), StartupEvidenceError> {
        // Production shape today: real fences, binding, and Config mirror;
        // Policy and capability owners do not exist yet, so their markers
        // must be explicit absence — never satisfied, never blocking the
        // acquirable evidence, and never readable as step satisfaction: the
        // Kernel cursor leaves steps 8/9 absent on these markers.
        let fence = test_fence(7)?;
        let request = StartupEvidenceRequest {
            transport_binding: Some(transport_binding(&fence)?),
            operation_fence: Some(fence.clone()),
            observed_kernel_fence: fence,
            config_mirror: Some(mirror()?),
            policy_mirror: None,
            required_capabilities: None,
            capability_outcomes: None,
            capability_registry_digest: None,
            active_generation_fingerprint: None,
            session_id: None,
            evidence_refs: Vec::new(),
            now_unix_ms: 1_000,
        };
        let evidence = build_startup_evidence(&request)?;
        assert_eq!(evidence.config_mirror_digest, digest("a")?);
        assert_eq!(evidence.policy_mirror_digest, None);
        assert_eq!(evidence.required_capabilities, None);
        assert_eq!(evidence.capability_outcomes, None);
        assert_eq!(evidence.capability_registry_digest, None);
        Ok(())
    }

    #[test]
    fn missing_config_mirror_is_explicit_not_ready() -> Result<(), StartupEvidenceError> {
        let error = blocked_with(|request| {
            request.config_mirror = None;
            Ok(())
        })?;
        if !matches!(error, StartupEvidenceError::Missing(_)) {
            return Err(contract(format!(
                "missing mirror must be explicit not-ready, got {error}"
            )));
        }
        Ok(())
    }

    #[test]
    fn changed_policy_digest_does_not_advance() -> Result<(), StartupEvidenceError> {
        let error = blocked_with(|request| {
            request.policy_mirror = Some(MirrorObservation {
                canonical_source_digest: digest("a")?,
                rebuilt_digest: digest("b")?,
            });
            Ok(())
        })?;
        if !matches!(error, StartupEvidenceError::Mismatch(_)) {
            return Err(contract(format!(
                "changed digest must mismatch, got {error}"
            )));
        }
        Ok(())
    }

    #[test]
    fn wrong_generation_fence_does_not_advance() -> Result<(), StartupEvidenceError> {
        let error = blocked_with(|request| {
            request.operation_fence = Some(test_fence(9)?);
            Ok(())
        })?;
        if !matches!(error, StartupEvidenceError::Mismatch(_)) {
            return Err(contract(format!(
                "wrong generation must mismatch, got {error}"
            )));
        }
        Ok(())
    }

    #[test]
    fn skewed_transport_binding_fence_does_not_advance() -> Result<(), StartupEvidenceError> {
        // The operation fence must equal the transport binding fence
        // exactly: a binding minted for another fence cannot carry this
        // evidence even when both fences are individually valid.
        let error = blocked_with(|request| {
            let other = test_fence(7)?;
            request.transport_binding = Some(transport_binding(&other)?);
            request.operation_fence = Some(test_fence(8)?);
            request.observed_kernel_fence = test_fence(8)?;
            Ok(())
        })?;
        if !matches!(error, StartupEvidenceError::Mismatch(_)) {
            return Err(contract(format!(
                "skewed binding fence must mismatch, got {error}"
            )));
        }
        Ok(())
    }

    #[test]
    fn unvalidated_broad_outcome_does_not_advance() -> Result<(), StartupEvidenceError> {
        let error = blocked_with(|request| {
            let mut outcomes = test_outcomes(request)?;
            let mut broad = healthy_outcome("provider.dispatch");
            broad.degradation_scope = DegradationScope::Installation;
            broad.evidence_refs = Vec::new();
            broad.scope_owner = "installation-1".to_owned();
            outcomes.push(broad);
            request.capability_outcomes = Some(outcomes);
            // Rebind the digest so the failure under test is validation, not binding.
            rebind_registry(request)
        })?;
        if !matches!(error, StartupEvidenceError::Contract(_)) {
            return Err(contract(format!(
                "unvalidated broad outcome must be a contract rejection, got {error}"
            )));
        }
        Ok(())
    }

    #[test]
    fn expired_only_coverage_does_not_advance() -> Result<(), StartupEvidenceError> {
        let error = blocked_with(|request| {
            let mut outcomes = test_outcomes(request)?;
            for outcome in &mut outcomes {
                outcome.valid_until_unix_ms = Some(500);
            }
            request.capability_outcomes = Some(outcomes);
            rebind_registry(request)
        })?;
        if !matches!(error, StartupEvidenceError::Mismatch(_)) {
            return Err(contract(format!(
                "expired coverage must mismatch, got {error}"
            )));
        }
        Ok(())
    }

    #[test]
    fn ineligible_required_capability_does_not_advance() -> Result<(), StartupEvidenceError> {
        let error = blocked_with(|request| {
            let mut outcomes = test_outcomes(request)?;
            outcomes.push(CapabilityOutcome {
                capability: "provider.dispatch".to_owned(),
                requested_mode: "route-a".to_owned(),
                effective_mode: "blocked".to_owned(),
                degradation_scope: DegradationScope::Generation,
                reason: "exact-generation challenge failed".to_owned(),
                evidence_refs: vec!["challenge-receipt-gen-7-1".to_owned()],
                affected_outputs_or_operations: vec!["dispatch".to_owned()],
                proof_ceiling: "none".to_owned(),
                recovery_requalification_or_expiry: "requalify-on-pass".to_owned(),
                scope_owner: "generation-owner-7".to_owned(),
                generation_fingerprint: "gen-7".to_owned(),
                valid_until_unix_ms: None,
            });
            request.capability_outcomes = Some(outcomes);
            rebind_registry(request)
        })?;
        if !matches!(error, StartupEvidenceError::Mismatch(_)) {
            return Err(contract(format!(
                "ineligible capability must mismatch, got {error}"
            )));
        }
        Ok(())
    }
}
