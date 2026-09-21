//! Governor startup evidence producer for I1.11 steps 8 and 9 (issue #1967).
//!
//! Architecture: I1.11 (Startup algorithm) steps 8 (`eliotd` loads
//! Config/Policy snapshots and rebuilds hot mirrors) and 9 (required
//! capability set is evaluated); I1.10 (service health) readiness meaning;
//! A2.3 (contract → ports → adapters layering); A0.3 hard boundaries stay
//! fail-closed. This cell is the Governor application evaluation owned by
//! `eliotd`: it binds live canonical mirror rebuild outputs, the active
//! operation identity and fence, and required capability outcomes into one
//! authenticated [`EliotdStartupEvidence`] payload for the Kernel consumer
//! (`bins/eliot-kernel` step 8/9 cursor; see `2241-owner-handoff.md`).
//!
//! Fail-closed rules (no invented readiness):
//!
//! - ready is never set from a nonempty list, a caller flag, or a newly
//!   instantiated default `Config`. Both mirror digests must be validated
//!   [`PlatformHandle`] values and byte-equal between the canonical source
//!   and the rebuilt mirror. A missing mirror is explicit not-ready evidence
//!   ([`StartupEvidenceError::Missing`]), never a silent skip.
//! - the operation fence must validate and be exactly compatible with the
//!   independently observed Kernel fence (same authority tuple and
//!   generation); a wrong generation or fence blocks the payload.
//! - every required capability needs a validated, live outcome covering it;
//!   an unvalidated broad outcome, an expired outcome, or a required
//!   capability the registry view deems ineligible blocks the payload. The
//!   capability registry digest is recomputed from the evaluated outcomes and
//!   must match the threaded digest, so bare definition agreement without the
//!   same dependencies cannot pass.
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
//!   semantic `CapabilityOutcome` owner.
//! - policy content is never sourced here. In particular the unaccepted 1966
//!   precedence helper is not a canonical policy source: only digests bound
//!   to caller-observed canonical rebuild outputs enter the payload.
//!
//! Caller integration (exact owner handoff; see also
//! `1967-governor-protocol-handoff.md` for the Kernel consumer):
//!
//! - [`build_startup_evidence`] evaluates one [`StartupEvidenceRequest`]
//!   into the wire payload. The owning daemon flow calls
//!   [`publish_daemon_startup_evidence`] at the real readiness site (after
//!   `DaemonKernelClient::report_ready`), threading the live Kernel fence;
//!   mirror, registry, capability, and operation values not yet observable
//!   stay missing and yield explicit not-ready evidence instead of a ready
//!   claim. Publish transport failure never fails the daemon: the existing
//!   step-7 live-receipt path is unchanged and the Kernel keeps steps 8/9
//!   fenced until its consumer lands.
//!
//! Like the neighboring admission joins, this helper never mints admission,
//! identity, or fences: it evaluates presented values and returns evidence
//! or a named blocker.

use eliot_contracts::{StateFence, sha256_hex};
use eliot_platform::PlatformHandle;
use eliot_store_api::OperationIdentity;
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

/// Fail-closed startup evidence error: malformed input, missing prerequisite,
/// or a value mismatch against canonical observations.
///
/// Missing canonical sources are explicit not-ready evidence: the caller (and
/// its diagnostics) receives the named prerequisite instead of a ready claim.
#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum StartupEvidenceError {
    /// A required prerequisite was not observed (no mirror rebuild, no
    /// operation identity, no registry digest, no required set, no outcomes,
    /// no generation fingerprint).
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
/// Host-approved protected snapshot for Config); the rebuilt digest is the
/// live hot-mirror rebuild output. The producer compares values only and
/// never reads the underlying stores.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MirrorObservation {
    /// Canonical source digest the mirror must reproduce.
    pub canonical_source_digest: PlatformHandle,
    /// Digest of the actually rebuilt hot mirror.
    pub rebuilt_digest: PlatformHandle,
}

/// Required-capability evaluation inputs threaded per evidence call.
///
/// Every `Option` is load-bearing: `None` means the owner has not observed
/// the value, which blocks the payload with an explicit missing prerequisite
/// instead of a default. The durable store, the registry owner, and the
/// capability model own truth; this shape is the exact observed value the
/// caller presents for one evaluation.
#[derive(Clone, Debug)]
pub struct StartupEvidenceRequest {
    /// Active operation identity the evidence is bound to. The daemon never
    /// mints this: `None` blocks the payload until the owning admission path
    /// provides the live identity.
    pub operation_id: Option<OperationIdentity>,
    /// State fence the evidence is bound to.
    pub operation_fence: Option<StateFence>,
    /// Independently observed Kernel fence (live snapshot). Always required:
    /// without the Kernel observation nothing can be evaluated.
    pub observed_kernel_fence: StateFence,
    /// Observed Config mirror rebuild output.
    pub config_mirror: Option<MirrorObservation>,
    /// Observed Policy mirror rebuild output.
    pub policy_mirror: Option<MirrorObservation>,
    /// Digest of the capability registry the outcomes were evaluated
    /// against. Recomputed from the outcomes and required to match, so the
    /// digest is bound to evidence instead of asserted alongside it.
    pub capability_registry_digest: Option<PlatformHandle>,
    /// Required capability names from the capability model. `None` blocks;
    /// an explicitly empty set is satisfied and documented as such.
    pub required_capabilities: Option<Vec<String>>,
    /// Evaluated capability outcomes covering the required set.
    pub capability_outcomes: Option<Vec<CapabilityOutcome>>,
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
/// `1967-governor-protocol-handoff.md`. The Kernel records step 8 only after
/// both mirror digests validate against the canonical rebuild outputs, and
/// step 9 only after every required capability carries a validated outcome
/// and the registry eligibility agrees for the active generation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EliotdStartupEvidence {
    /// Active operation identity this evidence is bound to.
    pub operation_id: OperationIdentity,
    /// State fence this evidence is bound to.
    pub state_fence: StateFence,
    /// Validated Config mirror digest.
    pub config_mirror_digest: PlatformHandle,
    /// Validated Policy mirror digest.
    pub policy_mirror_digest: PlatformHandle,
    /// Capability registry digest bound to the evaluated outcomes.
    pub capability_registry_digest: PlatformHandle,
    /// Required capability names evaluated.
    pub required_capabilities: Vec<String>,
    /// Validated outcomes covering the required set.
    pub capability_outcomes: Vec<CapabilityOutcome>,
    /// Auxiliary evidence references.
    pub evidence_refs: Vec<PlatformHandle>,
}

impl EliotdStartupEvidence {
    /// Validates the payload through the owning validators. Malformed
    /// payloads admit nothing and are never published.
    ///
    /// # Errors
    ///
    /// Returns [`StartupEvidenceError::Contract`] when any owned validator
    /// rejects the payload.
    pub fn validate(&self) -> Result<(), StartupEvidenceError> {
        self.operation_id.validate().map_err(|error| {
            StartupEvidenceError::Contract(format!("operation identity: {error}"))
        })?;
        self.state_fence
            .validate()
            .map_err(|error| StartupEvidenceError::Contract(format!("state fence: {error}")))?;
        for name in &self.required_capabilities {
            check_name("required capability", name)?;
        }
        for outcome in &self.capability_outcomes {
            outcome.validate().map_err(|error| {
                StartupEvidenceError::Contract(format!(
                    "capability '{}': {error}",
                    outcome.capability
                ))
            })?;
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

/// Evaluates the required capability set (I1.11 step 9): every required
/// capability carries a validated live outcome, the registry digest binds
/// exactly those outcomes, and the registry eligibility agrees for the
/// active generation.
///
/// # Errors
///
/// Returns [`StartupEvidenceError::Missing`] for absent required set,
/// outcomes, registry digest, or generation fingerprint; [`StartupEvidenceError::Contract`]
/// for malformed names or unvalidated (e.g. unevidenced broad) outcomes;
/// [`StartupEvidenceError::Mismatch`] for expired-only coverage, an
/// unbound registry digest, uncovered requirements, or a route the registry
/// deems ineligible.
#[allow(
    clippy::too_many_arguments,
    reason = "one evaluation needs the full threaded observation; grouped struct would duplicate StartupEvidenceRequest"
)]
fn evaluate_required_capabilities(
    required: Option<&[String]>,
    outcomes: Option<&[CapabilityOutcome]>,
    registry_digest: Option<&PlatformHandle>,
    active_generation_fingerprint: Option<&str>,
    session_id: Option<&str>,
    now_unix_ms: u64,
) -> Result<PlatformHandle, StartupEvidenceError> {
    let Some(required) = required else {
        return Err(StartupEvidenceError::Missing(
            "required capability set was not observed".to_owned(),
        ));
    };
    if required.len() > MAX_REQUIRED_CAPABILITIES {
        return Err(StartupEvidenceError::Contract(
            "required capability set is unbounded".to_owned(),
        ));
    }
    for name in required {
        check_name("required capability", name)?;
    }
    let Some(outcomes) = outcomes else {
        return Err(StartupEvidenceError::Missing(
            "capability outcomes were not observed".to_owned(),
        ));
    };
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
/// Fail-closed order: the observed Kernel fence validates first; the active
/// operation identity and fence must be present, valid, and exactly
/// compatible with the Kernel observation; both mirror digests must
/// reproduce their canonical sources; every required capability must carry
/// a validated live outcome with a bound registry digest and an agreeing
/// eligibility verdict. The first blocker wins and names its prerequisite.
///
/// # Errors
///
/// Returns [`StartupEvidenceError`] naming the blocking prerequisite. A
/// missing canonical source is explicit not-ready evidence, never a ready
/// claim.
pub fn build_startup_evidence(
    request: &StartupEvidenceRequest,
) -> Result<EliotdStartupEvidence, StartupEvidenceError> {
    request.observed_kernel_fence.validate().map_err(|error| {
        StartupEvidenceError::Contract(format!("observed kernel fence: {error}"))
    })?;
    let Some(operation_id) = &request.operation_id else {
        return Err(StartupEvidenceError::Missing(
            "no active operation identity was observed".to_owned(),
        ));
    };
    operation_id
        .validate()
        .map_err(|error| StartupEvidenceError::Contract(format!("operation identity: {error}")))?;
    let Some(operation_fence) = &request.operation_fence else {
        return Err(StartupEvidenceError::Missing(
            "no operation fence was observed".to_owned(),
        ));
    };
    operation_fence
        .validate()
        .map_err(|error| StartupEvidenceError::Contract(format!("operation fence: {error}")))?;
    if !operation_fence.is_compatible_with(&request.observed_kernel_fence) {
        return Err(StartupEvidenceError::Mismatch(
            "operation fence is not compatible with the observed kernel fence (wrong generation or epoch)"
                .to_owned(),
        ));
    }
    let config_digest = evaluate_mirror("config", request.config_mirror.as_ref())?;
    let policy_digest = evaluate_mirror("policy", request.policy_mirror.as_ref())?;
    if request.evidence_refs.len() > MAX_EVIDENCE_REFS {
        return Err(StartupEvidenceError::Contract(
            "evidence reference set is unbounded".to_owned(),
        ));
    }
    let registry_digest = evaluate_required_capabilities(
        request.required_capabilities.as_deref(),
        request.capability_outcomes.as_deref(),
        request.capability_registry_digest.as_ref(),
        request.active_generation_fingerprint.as_deref(),
        request.session_id.as_deref(),
        request.now_unix_ms,
    )?;
    let evidence = EliotdStartupEvidence {
        operation_id: operation_id.clone(),
        state_fence: operation_fence.clone(),
        config_mirror_digest: config_digest,
        policy_mirror_digest: policy_digest,
        capability_registry_digest: registry_digest,
        required_capabilities: request.required_capabilities.clone().unwrap_or_default(),
        capability_outcomes: request.capability_outcomes.clone().unwrap_or_default(),
        evidence_refs: request.evidence_refs.clone(),
    };
    evidence.validate()?;
    Ok(evidence)
}

/// Publishes Governor startup evidence from the live daemon flow.
///
/// Called at the real readiness site after `report_ready`: threads the live
/// Kernel fence and marks every not-yet-observable value missing, so the
/// producer yields explicit not-ready evidence instead of a ready claim.
/// A built payload is published on the authenticated daemon channel;
/// publish transport failure never fails the daemon — the existing step-7
/// live-receipt path is unchanged and the Kernel keeps steps 8/9 fenced
/// until its consumer lands. Mirror, registry, capability, and operation
/// owners extend this call with their retained observations when available.
pub fn publish_daemon_startup_evidence(kernel: &super::DaemonKernelClient) {
    let request = StartupEvidenceRequest {
        operation_id: None,
        operation_fence: None,
        observed_kernel_fence: kernel.kernel_fence(),
        config_mirror: None,
        policy_mirror: None,
        capability_registry_digest: None,
        required_capabilities: None,
        capability_outcomes: None,
        active_generation_fingerprint: None,
        session_id: None,
        evidence_refs: Vec::new(),
        now_unix_ms: super::unix_ms(),
    };
    match build_startup_evidence(&request) {
        Ok(evidence) => {
            if let Err(error) = kernel.report_startup_evidence(&evidence) {
                tracing::warn!(
                    "governor startup evidence publish failed (steps 8/9 stay fenced): {error}"
                );
            }
        }
        Err(error) => {
            tracing::warn!("governor startup evidence not ready (steps 8/9 stay fenced): {error}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use eliot_contracts::{EpochId, EpochLineageId, OperationId, ResourceGeneration};
    use eliot_store_api::OperationIdentity;
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

    fn operation_id() -> Result<OperationIdentity, StartupEvidenceError> {
        let operation = OperationId::new("op-startup-1")
            .map_err(|error| contract(format!("test operation id: {error}")))?;
        Ok(OperationIdentity {
            operation_id: operation,
            idempotency_key: "idem-startup-1".to_owned(),
            canonical_request_hash: "c".repeat(64),
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
        let outcomes = vec![
            healthy_outcome("provider.dispatch"),
            healthy_outcome("store.read"),
        ];
        let registry_digest = registry_digest_for(&outcomes)?;
        Ok(StartupEvidenceRequest {
            operation_id: Some(operation_id()?),
            operation_fence: Some(test_fence(7)?),
            observed_kernel_fence: test_fence(7)?,
            config_mirror: Some(mirror()?),
            policy_mirror: Some(mirror()?),
            capability_registry_digest: Some(registry_digest),
            required_capabilities: Some(vec![
                "provider.dispatch".to_owned(),
                "store.read".to_owned(),
            ]),
            capability_outcomes: Some(outcomes),
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
        let operation = request
            .operation_id
            .ok_or_else(|| contract("test operation"))?;
        assert_eq!(evidence.operation_id.operation_id, operation.operation_id);
        assert_eq!(evidence.state_fence, test_fence(7)?);
        assert_eq!(evidence.config_mirror_digest, digest("a")?);
        assert_eq!(evidence.policy_mirror_digest, digest("a")?);
        let registry = request
            .capability_registry_digest
            .ok_or_else(|| contract("test digest"))?;
        assert_eq!(evidence.capability_registry_digest, registry);
        assert_eq!(evidence.required_capabilities.len(), 2);
        assert_eq!(evidence.capability_outcomes.len(), 2);
        let wire = serde_json::to_string(&evidence)
            .map_err(|error| StartupEvidenceError::Contract(error.to_string()))?;
        let back: EliotdStartupEvidence = serde_json::from_str(&wire)
            .map_err(|error| StartupEvidenceError::Contract(error.to_string()))?;
        assert_eq!(back, evidence);
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
