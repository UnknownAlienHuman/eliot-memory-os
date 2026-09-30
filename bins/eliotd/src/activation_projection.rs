//! Read-only activation resolution projection.
//!
//! # Architecture
//! - **A2.3 Modular architecture** — bounded pure projection cell; no new runtime/process/failure boundary.
//! - **A13.2 Kernel and failure domains** — Kernel remains sole authority/fencing owner; this projection only reads the admitted Governor snapshot.
//! - **A13.10 Observability and Diagnostic Brief** — decision is a derived projection/receipt; it does not prove a transition.
//! - **ARCH-MOD-02 Depth is additive and micro-modular** — extracted as independently understandable/testable/replaceable capability cell; size and physical form remain empirical.
//!
//! # Implementation
//! - **I1.11 Startup algorithm** — resolution is available only after Governor/Kernel admission; no startup authority issuance here.
//! - **I2.2 When a capability becomes a separate crate** — pure contract/test seam justifies isolated module; no placeholder proliferation.
//! - **I2.23 Capability-family topology and crate extraction decisions** — Governor task/authority/canonical-transition family; validated via `CrateExtractionDecision`.
//! - **Semantic-grant handle: `eliot_governor::GovernorActivationOutcome` / `eliot_protocol::AgentActivationResolutionTicket` -> `eliot_protocol::AgentActivationResolutionResult` via `GovernorComposition::resolve_activation_outcome`** — Kernel-issued ticket resolved against the current Governor owner set.
//! - **Wave 2 Governor-internal outcome -> protocol v2**: `eliot_governor::GovernorActivationOutcome` -> `eliot_protocol::AgentActivationResolutionResult` is a lossless, exhaustive mapping; no resolver error is coerced to success or dropped.
//!
//! This is a read-only activation resolution projection and owns no authority issuance, write/effect, fence, default, retry, Kernel, Store, or lifecycle semantics.

use eliot_governor::{
    GovernorActivationOutcome, GovernorCandidateCoverage, GovernorRetryDirective,
    GovernorSelectionDirective,
};
use eliot_protocol::{
    AgentActivationCandidateCoverage, AgentActivationResolutionDisposition,
    AgentActivationResolutionResult, AgentActivationResolutionTicket,
    AgentActivationResolvedBinding, AgentActivationRetryDirective,
    AgentActivationSelectionDirective, AgentResponseDisposition,
};

use crate::DaemonError;
use crate::task_binding_admission::{ActivationCorrelation, MaterialBootstrap};

/// Validate-first outcome for one Kernel-claimed activation ticket value.
///
/// Pure claim-arm classification (issue #202, owner decision ii): no Governor
/// handle enters and none is read. `Empty` is the null-poll backoff;
/// `Valid` carries the ticket that may proceed to the deadline gate and the
/// Governor-backed v2 resolver; `Invalid` preserves the exact claimed bytes
/// plus a bounded reason for the terminal artifact. Decoding or validating
/// here never constructs a digest-bound result and never schedules a retry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ActivationClaim {
    /// Null claim: empty queue, back off until the next tick.
    Empty,
    /// Claimed bytes decoded and validated; may proceed down the claim arm.
    /// Boxed: the ticket is the large variant next to the small
    /// empty/invalid shapes.
    Valid(Box<AgentActivationResolutionTicket>),
    /// Claimed bytes failed closed validation before any Governor read.
    /// The holder must construct the terminal artifact, idle the flight,
    /// and continue the loop: no typed-result submit, no reconcile of typed
    /// results, no retry of the rejected revision.
    Invalid {
        /// Raw claimed ticket bytes preserved verbatim.
        ticket_bytes: Vec<u8>,
        /// Bounded validation-failure reason (never a semantic digest).
        reason: String,
    },
}

/// Rejects a caller-supplied reason fail-closed into the terminal-artifact
/// shape (no surrounding whitespace, no control characters, no replacement
/// characters). Only trimming is applied; empty or oversize input stays that
/// way so the protocol constructor fails closed instead of inventing or
/// silently trimming a reason. Control-containing or replacement-char input
/// is refused here (existing [`DaemonError::Lifecycle`]), never accepted.
fn sanitize_invalid_ticket_reason(raw: &str) -> Result<String, DaemonError> {
    if raw.chars().any(char::is_control) || raw.contains('\u{FFFD}') {
        return Err(DaemonError::Lifecycle(
            "invalid ticket reason contains control or replacement characters".to_owned(),
        ));
    }
    Ok(raw.trim().to_owned())
}

/// Bounds one owner error for embedding in a classified-claim reason so the
/// resulting `ticket invalid: …` / `ticket unparseable: …` reason always fits
/// the 512-byte terminal wire bound. Truncation applies only to the embedded
/// owner error text on the classification path, never to a direct
/// `terminal_for_invalid_ticket` caller reason.
fn bound_claim_error_text(raw: &str) -> String {
    let cleaned = raw
        .trim()
        .chars()
        .map(|cell| {
            if cell.is_control() || cell == '\u{FFFD}' {
                '?'
            } else {
                cell
            }
        })
        .collect::<String>()
        .trim()
        .to_owned();
    if cleaned.is_empty() {
        return "unclassified validation failure".to_owned();
    }
    let mut bounded = String::new();
    for cell in cleaned.chars() {
        if bounded.len() + cell.len_utf8() > 400 {
            break;
        }
        bounded.push(cell);
    }
    bounded.trim().to_owned()
}

/// Classifies one Kernel-claimed ticket from its raw transport bytes,
/// validate-first.
///
/// The caller threads the exact claimed bytes observed on the transport
/// (encoded before any typed decode at the claim call site); decoding happens
/// inside, first to a value for the null-poll check, then to the typed
/// ticket. `Null` (`b"null"`) is the empty-queue backoff (`Empty`). Any
/// present ticket decodes and validates from the same bytes: a decode or
/// validation failure yields `Invalid` carrying those bytes verbatim and a
/// bounded reason. Bytes are only ever copied verbatim; no fallback bytes are
/// fabricated on any path. No Governor is read, no digest-bound result is
/// constructed, and no retry is scheduled on this path.
#[must_use]
pub fn classify_claimed_ticket_value(ticket_bytes: &[u8]) -> ActivationClaim {
    let value: serde_json::Value = match serde_json::from_slice(ticket_bytes) {
        Ok(value) => value,
        Err(error) => {
            return ActivationClaim::Invalid {
                ticket_bytes: ticket_bytes.to_vec(),
                reason: format!(
                    "ticket unparseable: {}",
                    bound_claim_error_text(&error.to_string())
                ),
            };
        }
    };
    if value.is_null() {
        return ActivationClaim::Empty;
    }
    let ticket: AgentActivationResolutionTicket = match serde_json::from_slice(ticket_bytes) {
        Ok(ticket) => ticket,
        Err(error) => {
            return ActivationClaim::Invalid {
                ticket_bytes: ticket_bytes.to_vec(),
                reason: format!(
                    "ticket unparseable: {}",
                    bound_claim_error_text(&error.to_string())
                ),
            };
        }
    };
    match ticket.validate() {
        Ok(()) => ActivationClaim::Valid(Box::new(ticket)),
        Err(error) => ActivationClaim::Invalid {
            ticket_bytes: ticket_bytes.to_vec(),
            reason: format!(
                "ticket invalid: {}",
                bound_claim_error_text(&error.to_string())
            ),
        },
    }
}

/// Constructs the terminal artifact for one invalid claim (issue #202).
///
/// Takes only the preserved bytes, the bounded reason, and the observation
/// clock. No Governor handle is taken or read, no digest-bound result is
/// constructed, and no retry is scheduled: the artifact `is_terminal` always
/// holds, so holders idle the flight and continue the loop instead of
/// retrying the rejected revision.
///
/// # Errors
///
/// Returns [`DaemonError::Lifecycle`] when the bytes, reason, or clock fail
/// the closed terminal shape.
pub fn terminal_for_invalid_ticket(
    ticket_bytes: Vec<u8>,
    reason: &str,
    observed_at_unix_ms: u64,
) -> Result<eliot_protocol::AgentActivationInvalidTicket, DaemonError> {
    let artifact = eliot_protocol::AgentActivationInvalidTicket::rejected(
        ticket_bytes,
        sanitize_invalid_ticket_reason(reason)?,
        observed_at_unix_ms,
    )
    .map_err(|error| DaemonError::Lifecycle(error.to_string()))?;
    debug_assert!(artifact.is_terminal());
    Ok(artifact)
}

/// Read-only semantic-resolution boundary owned by eliotd.
///
/// The boundary accepts only a Kernel-issued correlation ticket. It does not
/// accept caller-selected semantic IDs and does not issue transport sessions,
/// fences, capabilities, or effects.
pub trait AgentActivationResolver {
    /// Canonical v2 production spine: resolves one exact ticket to the typed
    /// v2 result. This is the lossless projection for wave 2; every
    /// `GovernorActivationOutcome` variant maps to exactly one
    /// `AgentActivationResolutionDisposition` without silent coercion.
    ///
    /// No default body is provided on purpose: every concrete resolver must
    /// supply the exhaustive typed-outcome projection, so a resolver that has
    /// not moved to the typed outcome fails closed at build time instead of
    /// silently inheriting a synthesized `Resolved` binding.
    fn resolve_agent_activation_v2(
        &self,
        ticket: &AgentActivationResolutionTicket,
        now: u64,
    ) -> Result<AgentActivationResolutionResult, DaemonError>;
}

// ---------------------------------------------------------------------------
// Wave 2: lossless Governor -> protocol v2 mapping
// ---------------------------------------------------------------------------

fn map_coverage(coverage: GovernorCandidateCoverage) -> AgentActivationCandidateCoverage {
    match coverage {
        GovernorCandidateCoverage::Complete => AgentActivationCandidateCoverage::Complete,
        GovernorCandidateCoverage::Partial => AgentActivationCandidateCoverage::Partial,
        GovernorCandidateCoverage::Unknown => AgentActivationCandidateCoverage::Unknown,
    }
}

fn map_selection(selection: GovernorSelectionDirective) -> AgentActivationSelectionDirective {
    AgentActivationSelectionDirective {
        candidate_handles: selection.candidate_handles,
        candidate_coverage: map_coverage(selection.candidate_coverage),
        recovery_handle: selection.recovery_handle,
    }
}

fn map_retry(retry: GovernorRetryDirective) -> AgentActivationRetryDirective {
    AgentActivationRetryDirective {
        dependency_ref: retry.dependency_ref,
        observed_dependency_revision: retry.observed_dependency_revision,
        not_before_unix_ms: retry.not_before_unix_ms,
    }
}

fn build_protocol_result(
    ticket: &AgentActivationResolutionTicket,
    resolved_at_unix_ms: u64,
    disposition: AgentActivationResolutionDisposition,
    owner_revision: u64,
    successor_observation: Option<(u64, String)>,
) -> Result<AgentActivationResolutionResult, DaemonError> {
    let result = if ticket.successor_of.is_some() {
        let (_, observed_dependency_revision) = successor_observation.ok_or_else(|| {
            DaemonError::Lifecycle(
                "successor activation result lacks a fresh dependency observation".to_owned(),
            )
        })?;
        AgentActivationResolutionResult::new_for_successor(
            ticket,
            resolved_at_unix_ms,
            disposition,
            owner_revision,
            observed_dependency_revision,
        )
    } else {
        if successor_observation.is_some() {
            return Err(DaemonError::Lifecycle(
                "initial activation ticket carried successor dependency evidence".to_owned(),
            ));
        }
        AgentActivationResolutionResult::new_with_owner_evidence(
            ticket,
            resolved_at_unix_ms,
            disposition,
            owner_revision,
        )
    }
    .map_err(|error| DaemonError::Lifecycle(error.to_string()))?;
    Ok(result)
}

/// Lossless mapping from the Governor-internal typed outcome to the wire v2
/// protocol result. Every variant is preserved 1:1; no error is coerced to
/// `Resolved` and no error is dropped. A `Resolved` snapshot whose fence is
/// not the exact ticket fence is not mappable: it fails closed as a mapping
/// error, never as a binding, so stale selection cannot receive authority
/// (issue #1746, W2/A2).
pub fn map_governor_outcome_to_protocol(
    ticket: &AgentActivationResolutionTicket,
    outcome: GovernorActivationOutcome,
    resolved_at_unix_ms: u64,
) -> Result<AgentActivationResolutionResult, DaemonError> {
    map_governor_outcome_to_protocol_inner(ticket, outcome, resolved_at_unix_ms, None)
}

/// Maps a fresh semantic-owner observation for one successor ticket. The
/// observation is taken from the same coherent Governor read as the outcome.
pub fn map_governor_outcome_to_protocol_for_successor(
    ticket: &AgentActivationResolutionTicket,
    outcome: GovernorActivationOutcome,
    resolved_at_unix_ms: u64,
    owner_revision: u64,
    observed_dependency_revision: String,
) -> Result<AgentActivationResolutionResult, DaemonError> {
    map_governor_outcome_to_protocol_inner(
        ticket,
        outcome,
        resolved_at_unix_ms,
        Some((owner_revision, observed_dependency_revision)),
    )
}

/// Revalidates the frozen owner map against the built result: the mapped
/// disposition admits owner authority exactly when the Governor resolved,
/// and owner evidence is present exactly then.
fn revalidate_owner_map_against_outcome(
    was_resolved: bool,
    result: &AgentActivationResolutionResult,
) -> Result<(), DaemonError> {
    let admits_owner = matches!(
        result.disposition,
        AgentActivationResolutionDisposition::Resolved { .. }
    );
    if admits_owner != was_resolved || result.owner_evidence.is_some() != was_resolved {
        return Err(DaemonError::Lifecycle(
            "activation result owner map drifted from the mapped Governor outcome".to_owned(),
        ));
    }
    Ok(())
}

fn map_governor_outcome_to_protocol_inner(
    ticket: &AgentActivationResolutionTicket,
    outcome: GovernorActivationOutcome,
    resolved_at_unix_ms: u64,
    successor_observation: Option<(u64, String)>,
) -> Result<AgentActivationResolutionResult, DaemonError> {
    // #740: request/result span over the typed projection boundary. The
    // Governor outcome stays the sole discriminator; the span only names the
    // resulting disposition plus the available ticket/result identities.
    let _span = tracing::info_span!(
        "eliotd.activation_projection",
        ticket = %crate::diagnostics::sanitize_identity(&ticket.ticket_id)
    )
    .entered();
    // Issue #1746 (W2/A2): a Governor snapshot resolved under another fence is
    // stale selection for this exact ticket. Projecting it as `Resolved`
    // would mint application identity (principal/session/task) under the wrong
    // epoch/generation, so the mapping fails closed here — before any binding
    // is built — and the caller answers through the typed mapping-failure
    // terminal instead. The live resolver pre-checks this same equality, so
    // this arm only fires for out-of-band callers; it changes no live path.
    if let GovernorActivationOutcome::Resolved(snapshot) = &outcome
        && snapshot.state_fence != ticket.state_fence
    {
        return Err(DaemonError::Lifecycle(
            "resolved activation snapshot fence differs from the exact ticket fence".to_owned(),
        ));
    }
    let owner_revision = match &outcome {
        GovernorActivationOutcome::Resolved(snapshot) => snapshot.owner_revision,
        _ => successor_observation
            .as_ref()
            .map_or(1, |(owner_revision, _)| *owner_revision),
    };
    // Issue #1775 (W1-map): the operation-to-owner map for the activation
    // route is frozen here, on the real Governor→protocol caller path. Only
    // a `Resolved` operation admits owner authority; every other operation
    // maps to a terminal carrying proof of no owner. Captured before the
    // move into the disposition match below.
    let was_resolved = matches!(&outcome, GovernorActivationOutcome::Resolved(_));
    let disposition = match outcome {
        GovernorActivationOutcome::Resolved(snapshot) => {
            // #740: resolved scope/task/fence triple, preserved exactly as the
            // coherent Governor observation supplied it. The fence renders the
            // exact (lineage, sequence, generation) tuple in the documented
            // `epoch:…/gen:…` daemon identity shape: equal sequences from
            // different lineages are unrelated authorities, so the lineage is
            // part of the exact identity.
            let fence = format!(
                "epoch:{}:{}/gen:{}",
                snapshot.state_fence.authority_epoch.lineage_id.as_str(),
                snapshot.state_fence.authority_epoch.sequence.get(),
                snapshot.state_fence.resource_generation.value()
            );
            let task_id = snapshot.task_id.to_string();
            let _ =
                crate::diagnostics::ScopeIdentities::of(&snapshot.work_scope_id, &task_id, &fence)
                    .emit();
            let binding = AgentActivationResolvedBinding {
                principal_id: snapshot.principal_id,
                session_id: snapshot.session_id,
                task_id: snapshot.task_id.to_string(),
                work_unit_id: snapshot.work_unit_id,
                work_scope_id: snapshot.work_scope_id,
                task_revision: snapshot.task_revision.to_string(),
                plan_id: snapshot.plan_id,
                plan_revision: snapshot.plan_revision,
            };
            AgentActivationResolutionDisposition::Resolved {
                binding: Box::new(binding),
            }
        }
        GovernorActivationOutcome::TaskSelectionRequired { selection } => {
            AgentActivationResolutionDisposition::TaskSelectionRequired {
                selection: map_selection(selection),
            }
        }
        GovernorActivationOutcome::ScopeSelectionRequired { selection } => {
            AgentActivationResolutionDisposition::ScopeSelectionRequired {
                selection: map_selection(selection),
            }
        }
        GovernorActivationOutcome::ScopeAmbiguous { selection } => {
            AgentActivationResolutionDisposition::ScopeAmbiguous {
                selection: map_selection(selection),
            }
        }
        GovernorActivationOutcome::NotReady {
            recovery_handle,
            retry,
        } => AgentActivationResolutionDisposition::NotReady {
            recovery_handle,
            retry: map_retry(retry),
        },
        GovernorActivationOutcome::StaleFence {
            recovery_handle,
            observed_state_fence,
        } => AgentActivationResolutionDisposition::StaleFence {
            recovery_handle,
            observed_state_fence,
        },
        GovernorActivationOutcome::FailedInternal { failure_handle } => {
            AgentActivationResolutionDisposition::FailedInternal { failure_handle }
        }
    };

    let result = build_protocol_result(
        ticket,
        resolved_at_unix_ms,
        disposition,
        owner_revision,
        successor_observation,
    )?;
    // Independent owner-map revalidation against the original outcome: the
    // mapped disposition admits owner authority exactly when the Governor
    // resolved, and owner evidence is present exactly then. A drift between
    // the map and the built result fails closed instead of projecting owner
    // authority — or hiding it — for the wrong operation.
    revalidate_owner_map_against_outcome(was_resolved, &result)?;
    // #740: result span carries disposition + digest identities only.
    let _ = crate::diagnostics::AdmissionRecord::of(
        crate::diagnostics::disposition_of_resolution(&result.disposition),
        &ticket.ticket_id,
        &result.result_sha256,
    )
    .emit();
    Ok(result)
}

/// Typed fail-closed result for a `Resolved` snapshot whose fence no longer
/// matches the Kernel-issued ticket fence (#66).
///
/// The Governor owner resolved against current state, but the ticket was
/// issued under a different fence (e.g. generation advanced between daemon
/// admission and claim). Submitting the stale binding would create a Session
/// under the wrong fence; dropping it as a hard daemon error would kill the
/// loop instead of answering the ticket. Return a `StaleFence` terminal
/// result carrying the observed fence, so the Kernel fails closed without
/// creating a Session and the daemon stays alive for the next claim. Never
/// produces a binding.
#[cfg(test)]
pub fn stale_fence_for_resolved_mismatch(
    ticket: &AgentActivationResolutionTicket,
    observed_state_fence: eliot_contracts::StateFence,
    resolved_at_unix_ms: u64,
) -> Result<AgentActivationResolutionResult, DaemonError> {
    stale_fence_for_resolved_mismatch_with_observation(
        ticket,
        observed_state_fence,
        resolved_at_unix_ms,
        None,
    )
}

pub fn stale_fence_for_resolved_mismatch_with_observation(
    ticket: &AgentActivationResolutionTicket,
    observed_state_fence: eliot_contracts::StateFence,
    resolved_at_unix_ms: u64,
    successor_observation: Option<(u64, String)>,
) -> Result<AgentActivationResolutionResult, DaemonError> {
    let disposition = AgentActivationResolutionDisposition::StaleFence {
        recovery_handle: "daemon.fence-mismatch:recovery".to_owned(),
        observed_state_fence: Some(observed_state_fence),
    };
    build_protocol_result(
        ticket,
        resolved_at_unix_ms,
        disposition,
        successor_observation
            .as_ref()
            .map_or(1, |(revision, _)| *revision),
        successor_observation,
    )
}

/// Typed fail-closed result when the Governor is not ready to classify the
/// exact ticket (#204).
///
/// The ticket is already validated at this point, but no Governor outcome
/// exists to map: returning a hard error would kill the daemon loop and leave
/// the claimed ticket unanswered, so the bridge waiter would observe a
/// result-less expiry (a timeout-like outcome) instead of the distinct
/// internal failure. Answer with a `FailedInternal` terminal result instead,
/// so the Kernel records a typed disposition that stays distinct from every
/// other negative and from the deadline outcome, and the daemon stays alive
/// for the next claim. Never produces a binding and never retries the ticket.
/// If the fallback itself cannot bind (e.g. the deadline passed under the
/// resolver), the caller keeps the original readiness error unchanged.
#[cfg(test)]
pub fn failed_internal_for_unready_governor(
    ticket: &AgentActivationResolutionTicket,
    resolved_at_unix_ms: u64,
) -> Result<AgentActivationResolutionResult, DaemonError> {
    failed_internal_for_unready_governor_with_observation(ticket, resolved_at_unix_ms, None)
}

pub fn failed_internal_for_unready_governor_with_observation(
    ticket: &AgentActivationResolutionTicket,
    resolved_at_unix_ms: u64,
    successor_observation: Option<(u64, String)>,
) -> Result<AgentActivationResolutionResult, DaemonError> {
    let disposition = AgentActivationResolutionDisposition::FailedInternal {
        failure_handle: "daemon.governor-not-ready:recovery".to_owned(),
    };
    build_protocol_result(
        ticket,
        resolved_at_unix_ms,
        disposition,
        successor_observation
            .as_ref()
            .map_or(1, |(revision, _)| *revision),
        successor_observation,
    )
}

/// Typed fail-closed result when the Governor→protocol mapping rejects a
/// classified outcome for the exact ticket (#202).
///
/// The Governor classified the ticket, but the classified data cannot bind it
/// (e.g. a `NotReady` retry window at or past the Kernel deadline, an
/// ambiguity finding with fewer than two candidates, or a stale-fence
/// observation equal to the ticket fence). Returning the mapping error would
/// kill the daemon loop and leave the ticket unanswered; a `FailedInternal`
/// terminal result answers the ticket instead, so the Kernel records a typed
/// disposition and the daemon stays alive for the next claim. The failed
/// outcome kind is carried in the bounded failure handle; the full mapping
/// error stays in daemon diagnostics. Never produces a binding and never
/// retries the same ticket.
#[cfg(test)]
pub fn failed_internal_for_mapping_failure(
    ticket: &AgentActivationResolutionTicket,
    outcome_kind: &str,
    resolved_at_unix_ms: u64,
) -> Result<AgentActivationResolutionResult, DaemonError> {
    failed_internal_for_mapping_failure_with_observation(
        ticket,
        outcome_kind,
        resolved_at_unix_ms,
        None,
    )
}

pub fn failed_internal_for_mapping_failure_with_observation(
    ticket: &AgentActivationResolutionTicket,
    outcome_kind: &str,
    resolved_at_unix_ms: u64,
    successor_observation: Option<(u64, String)>,
) -> Result<AgentActivationResolutionResult, DaemonError> {
    let disposition = AgentActivationResolutionDisposition::FailedInternal {
        failure_handle: format!("daemon.mapping-failure:{outcome_kind}:recovery"),
    };
    build_protocol_result(
        ticket,
        resolved_at_unix_ms,
        disposition,
        successor_observation
            .as_ref()
            .map_or(1, |(revision, _)| *revision),
        successor_observation,
    )
}

// ---------------------------------------------------------------------------
// Issue #1746 W5/W6 + A4/A5: bootstrap bound to activation, revalidated
// through dispatch
// ---------------------------------------------------------------------------

/// I7.20 conflict directive carried by every bootstrap-dispatch conflict.
///
/// The old operation is rebound under a new operation identity; it is never
/// rewritten to the new task/principal/session under its own identity, never
/// duplicated, and already-possible effects keep their original identity for
/// reconciliation. Shared safe status/recovery remains available under its own
/// authority and never passes through the revalidation entry.
// Issue #1746: dispatch seam consumed by the STITCH composition caller
// (`DaemonComposition::commit_canonical_and_refresh`); allow until that wiring
// lands.
#[allow(dead_code)]
pub const BOOTSTRAP_DISPATCH_CONFLICT_DIRECTIVE: &str = "rebind-under-new-operation";

/// I7.20 recovery directive carried by a bootstrap bind refusal for an
/// unresolved activation.
///
/// The caller answers with the bounded selection/intake response the
/// activation already carries; nothing is selected here and no task is created
/// to remove the missing selection.
// Issue #1746: dispatch seam consumed by the STITCH composition caller
// (`DaemonComposition::commit_canonical_and_refresh`); allow until that wiring
// lands.
#[allow(dead_code)]
pub const BOOTSTRAP_SELECTION_INTAKE_DIRECTIVE: &str = "answer-with-bounded-selection-intake";

/// I7.20 agent-facing outcome for the bootstrap↔activation join and for
/// dispatch revalidation (issue #1746, W5/W6; acceptance A4/A5).
///
/// Every value carries the closed control disposition, the exact open reason
/// code from the I7.20 registry, the applicable recovery/conflict directive,
/// a bounded detail, and the same operation identity the binding was sealed
/// under (empty only when no identity was ever presented) — never a rewritten
/// identity. Bridges switch on the stable disposition and MAY specialize the
/// reason code; the reason code is never collapsed into prose.
///
/// The bind leg ([`bind_bootstrap_to_activation`]) answers selection arms with
/// `NEEDS_EVIDENCE`/`TASK_SELECTION_REQUIRED` and drifted or denied arms with
/// `STALE_OR_CONFLICT`; the revalidate leg ([`revalidate_bootstrap_dispatch`])
/// always answers `STALE_OR_CONFLICT`.
// Issue #1746: dispatch seam consumed by the STITCH composition caller
// (`DaemonComposition::commit_canonical_and_refresh`); allow until that wiring
// lands.
#[allow(dead_code)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BootstrapDispatchOutcome {
    disposition: AgentResponseDisposition,
    reason_code: &'static str,
    directive: &'static str,
    detail: &'static str,
    operation_id: String,
}

// Issue #1746: see the struct-level seam note; the constructors and
// accessors are consumed together with the seal once wired.
#[allow(dead_code)]
impl BootstrapDispatchOutcome {
    fn conflict(reason_code: &'static str, detail: &'static str, operation_id: &str) -> Self {
        Self {
            disposition: AgentResponseDisposition::StaleOrConflict,
            reason_code,
            directive: BOOTSTRAP_DISPATCH_CONFLICT_DIRECTIVE,
            detail,
            operation_id: operation_id.to_owned(),
        }
    }

    fn needs_evidence(reason_code: &'static str, detail: &'static str, operation_id: &str) -> Self {
        Self {
            disposition: AgentResponseDisposition::NeedsEvidence,
            reason_code,
            directive: BOOTSTRAP_SELECTION_INTAKE_DIRECTIVE,
            detail,
            operation_id: operation_id.to_owned(),
        }
    }

    /// Closed I7.20 control disposition for this outcome.
    #[must_use]
    pub const fn disposition(&self) -> AgentResponseDisposition {
        self.disposition
    }

    /// Exact open I7.20 reason code for this outcome.
    #[must_use]
    pub const fn reason_code(&self) -> &'static str {
        self.reason_code
    }

    /// Applicable I7.20 recovery/conflict directive.
    #[must_use]
    pub const fn directive(&self) -> &'static str {
        self.directive
    }

    /// Bounded detail naming the drifted or missing field (never a task guess).
    #[must_use]
    pub const fn detail(&self) -> &'static str {
        self.detail
    }

    /// Same operation identity the binding was sealed under.
    #[must_use]
    pub fn operation_id(&self) -> &str {
        &self.operation_id
    }
}

impl std::fmt::Display for BootstrapDispatchOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}: {}: {}: operation {}",
            self.disposition.as_str(),
            self.reason_code,
            self.detail,
            self.operation_id
        )
    }
}

impl std::error::Error for BootstrapDispatchOutcome {}

/// Bootstrap bound to its exact activation identity for dispatch
/// (issue #1746, W5/W6; I7.11, I7.20).
///
/// The seal joins the owner-resolved activation correlation for the exact
/// ticket ([`ActivationCorrelation::Resolved`]: principal/session/task/scope,
/// task revision, owner revision, state fence) to the owner-evidenced
/// [`MaterialBootstrap`] (receipt/lease, principal/session, scope, task
/// evidence with acceptance digest, fence, receipt/governance/projection
/// source revisions) under one stable operation identity. The Decision Safety
/// Floor (I7.11) travels by value and is never compacted away here:
/// goal/acceptance via the task evidence and its acceptance digest, current
/// scope, authority/policy and State Fence, load-bearing source/provenance via
/// the receipt/lease/profile/projection revisions, and recovery via the
/// conflict outcome on drift. Sealed only by [`bind_bootstrap_to_activation`];
/// minted nowhere else; selects nothing.
// Issue #1746: dispatch seam consumed by the STITCH composition caller
// (`DaemonComposition::commit_canonical_and_refresh`); allow until that wiring
// lands.
#[allow(dead_code)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BoundBootstrapDispatch {
    /// Exact ticket-bound activation identity, owner-resolved.
    pub activation: ActivationCorrelation,
    /// Owner-evidenced bootstrap bound to the same session/scope/task.
    pub bootstrap: MaterialBootstrap,
    /// Stable operation identity; preserved across revalidation, never mutated.
    pub operation_id: String,
}

/// Binds one owner-evidenced bootstrap to its exact activation identity
/// (issue #1746, W5; I7.8 step 4, I7.11; acceptance A4).
///
/// The activation correlation is the existing route's typed result for the
/// exact ticket ([`crate::task_binding_admission::correlate_activation_result`],
/// behind `GovernorComposition::resolve_activation_outcome`); the bootstrap is
/// #8's response surface joined to the compiled receipt and the verified
/// coverage/governance profiles
/// ([`crate::task_binding_admission::admit_bootstrap_context`]). Both sides
/// must name the same principal, session, `WorkScope`, task, task revision,
/// and state fence, or the join fails closed with the agent-facing outcome:
/// selection arms answer `NEEDS_EVIDENCE`/`TASK_SELECTION_REQUIRED` (answer
/// with the bounded selection/intake response, never a Material bootstrap),
/// while retry/stale/denial arms and any drifted
/// session/scope/task/revision/fence answer `STALE_OR_CONFLICT`
/// (`TASK_SCOPE_INCOMPATIBLE`: re-resolve the exact ticket, rebind, no
/// rewrite).
///
/// Only a `Material` bootstrap can enter: the signature takes
/// [`MaterialBootstrap`] itself, so a diagnostic bootstrap (always the no-task
/// case — never Material authority) or an intake shape cannot be passed at
/// all. The sealed value is still not Material authority by itself: Material
/// work proceeds only through the #1742 owner gate
/// (`GovernorComposition::commit_canonical_with_readiness`, which runs
/// `check_material_readiness_for_write`). This entry mints no profile,
/// receipt, lease, or authority; it only binds owner values verbatim.
///
/// Designated caller (STITCH, daemon composition lane):
/// `DaemonComposition::commit_canonical_and_refresh`, between the activation
/// correlation and the bootstrap admission for the same lease at the write
/// fence, passing the sealed value toward the dispatch effect gate
/// ([`revalidate_bootstrap_dispatch`]).
// Issue #1746: dispatch seam consumed by the STITCH composition caller
// (`DaemonComposition::commit_canonical_and_refresh`); allow until that wiring
// lands.
#[allow(dead_code)]
pub fn bind_bootstrap_to_activation(
    activation: ActivationCorrelation,
    bootstrap: &MaterialBootstrap,
    operation_id: String,
) -> Result<BoundBootstrapDispatch, BootstrapDispatchOutcome> {
    // I7.20: the same operation identity when one exists. A blank identity is
    // not sealed; the refusal carries no operation to preserve.
    if operation_id.trim().is_empty() || operation_id.chars().any(char::is_control) {
        return Err(BootstrapDispatchOutcome::needs_evidence(
            "TASK_SELECTION_REQUIRED",
            "bootstrap dispatch names no operation identity",
            "",
        ));
    }
    match &activation {
        ActivationCorrelation::TaskSelectionRequired { .. }
        | ActivationCorrelation::ScopeSelectionRequired { .. }
        | ActivationCorrelation::ScopeAmbiguous { .. } => {
            return Err(BootstrapDispatchOutcome::needs_evidence(
                "TASK_SELECTION_REQUIRED",
                "bootstrap binds no resolved task; answer with the bounded selection/intake response, never a Material bootstrap",
                &operation_id,
            ));
        }
        ActivationCorrelation::Retry { .. }
        | ActivationCorrelation::Stale { .. }
        | ActivationCorrelation::Denied { .. } => {
            return Err(BootstrapDispatchOutcome::conflict(
                "TASK_SCOPE_INCOMPATIBLE",
                "activation carries no resolved identity to bind a bootstrap to; re-resolve the exact ticket",
                &operation_id,
            ));
        }
        ActivationCorrelation::Resolved {
            principal_id,
            session_id,
            task_id,
            work_scope_id,
            task_revision,
            owner_revision: _,
            state_fence,
        } => {
            // The ORIGINAL owner evidence sealed in the bootstrap is validated
            // as compiled before any field is compared: structural validation
            // of a request-supplied copy is never sufficient.
            if bootstrap.task.validate().is_err() {
                return Err(BootstrapDispatchOutcome::needs_evidence(
                    "TASK_SELECTION_REQUIRED",
                    "task selection evidence invalid",
                    &operation_id,
                ));
            }
            if bootstrap.task.is_contaminated() {
                return Err(BootstrapDispatchOutcome::needs_evidence(
                    "TASK_SELECTION_REQUIRED",
                    "task selection is contaminated",
                    &operation_id,
                ));
            }
            if bootstrap.principal_ref != *principal_id {
                return Err(BootstrapDispatchOutcome::conflict(
                    "TASK_SCOPE_INCOMPATIBLE",
                    "bootstrap names another principal than the exact activation identity",
                    &operation_id,
                ));
            }
            if bootstrap.session_ref != *session_id {
                return Err(BootstrapDispatchOutcome::conflict(
                    "TASK_SCOPE_INCOMPATIBLE",
                    "bootstrap names another session than the exact activation identity",
                    &operation_id,
                ));
            }
            if bootstrap.scope_ref != *work_scope_id {
                return Err(BootstrapDispatchOutcome::conflict(
                    "TASK_SCOPE_INCOMPATIBLE",
                    "bootstrap names another WorkScope than the exact activation identity",
                    &operation_id,
                ));
            }
            if bootstrap.task.task_ref != *task_id || bootstrap.task.task_revision != *task_revision
            {
                return Err(BootstrapDispatchOutcome::conflict(
                    "TASK_SCOPE_INCOMPATIBLE",
                    "bootstrap names another task revision than the exact activation identity",
                    &operation_id,
                ));
            }
            if !eliot_contracts::fences_match_exact(&bootstrap.state_fence, state_fence) {
                return Err(BootstrapDispatchOutcome::conflict(
                    "TASK_SCOPE_INCOMPATIBLE",
                    "bootstrap was assembled at another fence than the exact activation identity",
                    &operation_id,
                ));
            }
        }
    }
    Ok(BoundBootstrapDispatch {
        activation,
        bootstrap: bootstrap.clone(),
        operation_id,
    })
}

/// Revalidates one bound bootstrap at the dispatch effect gate against the
/// live owners (issue #1746, W6; acceptance A5; I7.20).
///
/// The live task/scope, principal/session, task revision, acceptance digest,
/// bootstrap receipt revision, governance profile reference/revision,
/// projection generation, and fence come from the live owners at the existing
/// queued-claim/launch/effect gate — never from the request and never from a
/// mutable ambient selection. An intervening rebind, task revision or
/// acceptance change, logout, or generation change returns the I7.20 conflict
/// outcome (`STALE_OR_CONFLICT` disposition, exact registry reason code,
/// rebind directive, same operation identity): the old operation is not
/// rewritten to the new task/principal/session under its identity, never
/// duplicated, and already-possible effects keep their original identity for
/// reconciliation. Shared safe status/recovery remains available under its own
/// authority and never passes through this entry.
///
/// Reason-code mapping (all members of the I7.20 registry): unbound live task
/// → `TASK_SELECTION_REQUIRED`; moved task → `TASK_SCOPE_INCOMPATIBLE`; moved
/// scope → `SCOPE_CONFLICT`; moved principal/session (logout/rebind) →
/// `IDENTITY_CONFLICT`; moved task revision → `STALE_STATE_FENCE`; moved
/// acceptance digest → `EVIDENCE_STALE`; moved receipt/governance revision →
/// `EVIDENCE_STALE`; re-projected bootstrap → `STALE_PROJECTION`; moved
/// generation → `STALE_AUTHORITY_EPOCH`; otherwise moved fence →
/// `STALE_STATE_FENCE`.
///
/// Designated caller (STITCH, daemon composition lane): the pre-commit effect
/// gate in `DaemonComposition::commit_canonical_and_refresh`, passing the live
/// Governor task/scope, principal/session, revisions, and kernel-snapshot
/// fence. This entry mints no binding and installs none.
#[allow(
    clippy::too_many_arguments,
    reason = "revalidation joins the sealed bootstrap identity against every live owner value that can invalidate it in one fail-closed edge"
)]
// Issue #1746: dispatch seam consumed by the STITCH composition caller (the
// pre-commit effect gate in `DaemonComposition::commit_canonical_and_refresh`);
// allow until that wiring lands.
#[allow(dead_code)]
pub fn revalidate_bootstrap_dispatch(
    bound: &BoundBootstrapDispatch,
    live_principal_ref: &str,
    live_session_ref: &str,
    live_task_ref: Option<&str>,
    live_scope_ref: &str,
    live_task_revision: u64,
    live_acceptance_digest: &str,
    live_receipt_revision: u64,
    live_governance_profile_ref: &str,
    live_governance_revision: u64,
    live_projection_generation: u64,
    live_fence: &eliot_contracts::StateFence,
) -> Result<(), BootstrapDispatchOutcome> {
    let conflict = |reason_code: &'static str, detail: &'static str| {
        BootstrapDispatchOutcome::conflict(reason_code, detail, &bound.operation_id)
    };
    let ActivationCorrelation::Resolved {
        task_id,
        work_scope_id,
        principal_id,
        session_id,
        task_revision,
        owner_revision: _,
        state_fence: _,
    } = &bound.activation
    else {
        return Err(conflict(
            "TASK_SCOPE_INCOMPATIBLE",
            "bound bootstrap carries no resolved activation identity",
        ));
    };
    // Admitted task evidence is the sealed original; live values below come
    // from the live owners, never from the request.
    let evidence = &bound.bootstrap.task;
    let Some(live_task_ref) = live_task_ref else {
        return Err(conflict(
            "TASK_SELECTION_REQUIRED",
            "live task is unbound; answer with the bounded intake shape, no silent carry",
        ));
    };
    if live_task_ref != task_id || live_task_ref != evidence.task_ref {
        return Err(conflict(
            "TASK_SCOPE_INCOMPATIBLE",
            "live task is not the admitted task; rebind under a new operation, no rewrite",
        ));
    }
    if live_scope_ref != work_scope_id || live_scope_ref != bound.bootstrap.scope_ref {
        return Err(conflict(
            "SCOPE_CONFLICT",
            "live WorkScope is not the admitted WorkScope; rebind, no rewrite",
        ));
    }
    // An intervening logout or rebind moved the live principal/session. The
    // old operation conflicts for rebind under a new operation identity; it is
    // never rewritten to the new principal/session.
    if live_principal_ref != principal_id || live_principal_ref != bound.bootstrap.principal_ref {
        return Err(conflict(
            "IDENTITY_CONFLICT",
            "live principal is not the admitted principal; logout or rebind under a new operation, no rewrite",
        ));
    }
    if live_session_ref != session_id || live_session_ref != bound.bootstrap.session_ref {
        return Err(conflict(
            "IDENTITY_CONFLICT",
            "live session is not the admitted session; logout or rebind under a new operation, no rewrite",
        ));
    }
    // An intervening task revision or acceptance change moved the contract the
    // bootstrap was bound under. The sealed revision/digest is compared with
    // the live owner values here, never refreshed in place.
    if live_task_revision != *task_revision || live_task_revision != evidence.task_revision {
        return Err(conflict(
            "STALE_STATE_FENCE",
            "admitted task revision moved before dispatch; rebind at the live revision, no silent rebind",
        ));
    }
    if live_acceptance_digest != evidence.acceptance_digest {
        return Err(conflict(
            "EVIDENCE_STALE",
            "admitted acceptance digest moved before dispatch; rebind at the live digest, no silent rebind",
        ));
    }
    // Source-revision drift: the bootstrap rests on the receipt, governance
    // profile, and projection revisions sealed at bind time. Any move conflicts
    // for rebind; the admitted projection is never silently adopted under the
    // old operation identity.
    if live_receipt_revision != bound.bootstrap.receipt_revision {
        return Err(conflict(
            "EVIDENCE_STALE",
            "admitted bootstrap receipt revision moved before dispatch; rebind at the live revision, no silent rebind",
        ));
    }
    if live_governance_profile_ref != bound.bootstrap.governance_profile_ref
        || live_governance_revision != bound.bootstrap.governance_revision
    {
        return Err(conflict(
            "EVIDENCE_STALE",
            "admitted governance profile revision moved before dispatch; rebind at the live revision, no silent rebind",
        ));
    }
    if live_projection_generation != bound.bootstrap.projection_generation {
        return Err(conflict(
            "STALE_PROJECTION",
            "admitted bootstrap was re-projected before dispatch; rebind at the live projection, no silent adoption",
        ));
    }
    if live_fence.resource_generation != bound.bootstrap.state_fence.resource_generation {
        return Err(conflict(
            "STALE_AUTHORITY_EPOCH",
            "admitted generation moved before dispatch; rebind at the live fence, no silent rebind",
        ));
    }
    if !eliot_contracts::fences_match_exact(&bound.bootstrap.state_fence, live_fence) {
        return Err(conflict(
            "STALE_STATE_FENCE",
            "admitted fence moved before dispatch; rebind at the live fence, no silent rebind",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod projection_tests {
    #![allow(clippy::expect_used)] // test-only panic-acceptable (#838).
    use super::*;
    use eliot_contracts::RequestId;
    use eliot_contracts::{EpochId, EpochLineageId, ResourceGeneration, StateFence};
    use eliot_governor::{
        GovernorActivationSnapshot, GovernorCandidateCoverage, GovernorSelectionDirective,
        fixture_failed_internal, fixture_not_ready, fixture_scope_ambiguous,
        fixture_scope_selection_required, fixture_stale_fence, fixture_task_selection_required,
    };
    use eliot_protocol::AgentActivationResolutionTicket;
    use std::num::NonZeroU64;

    const TEST_LINEAGE_A: &str = "550e8400-e29b-41d4-a716-446655440000";

    fn test_epoch(sequence: u64) -> EpochId {
        EpochId::new(
            EpochLineageId::new(TEST_LINEAGE_A).expect("valid test lineage"),
            NonZeroU64::new(sequence).expect("nonzero test sequence"),
        )
        .expect("valid test epoch")
    }

    fn test_ticket(deadline: u64) -> AgentActivationResolutionTicket {
        let mut ticket = AgentActivationResolutionTicket {
            wire_id: eliot_protocol::AGENT_ACTIVATION_RESOLUTION_TICKET_WIRE_ID.to_owned(),
            wire_version: eliot_protocol::AGENT_ACTIVATION_RESOLUTION_TICKET_WIRE_VERSION,
            ticket_id: "ticket-test".to_owned(),
            activation_request_id: RequestId::new("activation-request-1").expect("request id"),
            demand_id: "activation-demand-1".to_owned(),
            activation_request_sha256: "a".repeat(64),
            peer_admission_receipt_sha256: "b".repeat(64),
            connection_id: "connection-1".to_owned(),
            workspace_selector: None,
            cancellation_id: "cancellation-1".to_owned(),
            state_fence: StateFence::new(test_epoch(1), ResourceGeneration::new(1).expect("gen")),
            kernel_deadline_unix_ms: deadline,
            successor_of: None,
            ticket_sha256: String::new(),
        };
        ticket.ticket_sha256 = ticket.compute_digest().expect("digest");
        ticket
    }

    fn test_snapshot() -> GovernorActivationSnapshot {
        GovernorActivationSnapshot {
            state_fence: StateFence::new(test_epoch(1), ResourceGeneration::new(1).expect("gen")),
            owner_revision: 1,
            principal_id: "principal-1".to_owned(),
            session_id: "session-1".to_owned(),
            task_id: eliot_contracts::TaskId::new("task-1").expect("task id"),
            work_unit_id: "work-1".to_owned(),
            work_scope_id: "scope-1".to_owned(),
            task_revision: 7,
            plan_id: "plan-1".to_owned(),
            plan_revision: "plan-revision-1".to_owned(),
        }
    }

    #[test]
    fn lossless_resolved_maps_to_protocol_resolved() {
        let ticket = test_ticket(100);
        let snapshot = test_snapshot();
        let result = map_governor_outcome_to_protocol(
            &ticket,
            GovernorActivationOutcome::Resolved(snapshot),
            50,
        )
        .expect("resolved mapping");
        assert!(matches!(
            result.disposition,
            AgentActivationResolutionDisposition::Resolved { .. }
        ));
        assert_eq!(result.ticket_id, ticket.ticket_id);
        result.validate_against(&ticket).expect("valid binding");
    }

    #[test]
    fn task_selection_required_is_not_coerced_to_resolved() {
        let ticket = test_ticket(100);
        let outcome = fixture_task_selection_required();
        let result = map_governor_outcome_to_protocol(&ticket, outcome, 50).expect("mapping");
        assert!(matches!(
            result.disposition,
            AgentActivationResolutionDisposition::TaskSelectionRequired { .. }
        ));
        // Must not be Resolved.
        assert!(result.resolved_binding().is_none());
        result.validate_against(&ticket).expect("valid");
    }

    #[test]
    fn scope_ambiguous_requires_two_candidates_and_is_preserved() {
        let ticket = test_ticket(100);
        let outcome = fixture_scope_ambiguous(vec!["scope:a".to_owned(), "scope:b".to_owned()]);
        let result = map_governor_outcome_to_protocol(&ticket, outcome, 50).expect("mapping");
        match result.disposition {
            AgentActivationResolutionDisposition::ScopeAmbiguous { selection } => {
                assert_eq!(selection.candidate_handles.len(), 2);
            }
            _ => panic!("expected ScopeAmbiguous"),
        }
    }

    #[test]
    fn scope_selection_required_is_distinct_from_ambiguous() {
        let ticket = test_ticket(100);
        let outcome = fixture_scope_selection_required(Vec::new());
        let result = map_governor_outcome_to_protocol(&ticket, outcome, 50).expect("mapping");
        assert!(matches!(
            result.disposition,
            AgentActivationResolutionDisposition::ScopeSelectionRequired { .. }
        ));
        // Ambiguous would require >=2 candidates; this has 0 with Unknown -> distinct.
    }

    #[test]
    fn not_ready_carries_dependency_and_is_transient() {
        let ticket = test_ticket(100);
        let outcome = fixture_not_ready("governor.session", "rev-1", 60);
        let result = map_governor_outcome_to_protocol(&ticket, outcome, 50).expect("mapping");
        assert!(result.is_transient_retry());
        match result.disposition {
            AgentActivationResolutionDisposition::NotReady { retry, .. } => {
                assert_eq!(retry.dependency_ref, "governor.session");
                assert!(retry.not_before_unix_ms > 50);
                assert!(retry.not_before_unix_ms < 100);
            }
            _ => panic!("expected NotReady"),
        }
    }

    #[test]
    fn stale_fence_is_not_success_and_does_not_create_session() {
        let ticket = test_ticket(100);
        let outcome = fixture_stale_fence(None);
        let result = map_governor_outcome_to_protocol(&ticket, outcome, 50).expect("mapping");
        assert!(matches!(
            result.disposition,
            AgentActivationResolutionDisposition::StaleFence { .. }
        ));
        assert!(result.resolved_binding().is_none());
    }

    #[test]
    fn stale_fence_with_observed_fence_preserves_difference() {
        let ticket = test_ticket(100);
        let observed = StateFence::new(test_epoch(1), ResourceGeneration::new(2).expect("gen"));
        let outcome = fixture_stale_fence(Some(observed.clone()));
        let result = map_governor_outcome_to_protocol(&ticket, outcome, 50).expect("mapping");
        match result.disposition {
            AgentActivationResolutionDisposition::StaleFence {
                observed_state_fence: Some(fence),
                ..
            } => assert_ne!(fence, ticket.state_fence),
            _ => panic!("expected StaleFence with fence"),
        }
    }

    #[test]
    fn failed_internal_is_not_task_ambiguity() {
        let ticket = test_ticket(100);
        let outcome = fixture_failed_internal("malformed-snapshot");
        let result = map_governor_outcome_to_protocol(&ticket, outcome, 50).expect("mapping");
        assert!(matches!(
            result.disposition,
            AgentActivationResolutionDisposition::FailedInternal { .. }
        ));
        // Must not be coerced to TaskSelectionRequired.
        assert!(!matches!(
            result.disposition,
            AgentActivationResolutionDisposition::TaskSelectionRequired { .. }
        ));
    }

    // WORK_UNIT_CASE: 839/13
    #[test]
    fn task_selection_preserves_candidates_coverage_and_recovery() {
        let ticket = test_ticket(100);
        let candidates = vec!["task:a".to_owned(), "task:b".to_owned()];
        let outcome = GovernorActivationOutcome::TaskSelectionRequired {
            selection: GovernorSelectionDirective::new(
                candidates.clone(),
                GovernorCandidateCoverage::Partial,
                "governor.task-selection:recovery",
            ),
        };
        let result = map_governor_outcome_to_protocol(&ticket, outcome, 50).expect("mapping");
        match &result.disposition {
            AgentActivationResolutionDisposition::TaskSelectionRequired { selection } => {
                assert_eq!(selection.candidate_handles, candidates);
                assert_eq!(
                    selection.candidate_coverage,
                    AgentActivationCandidateCoverage::Partial
                );
                assert_eq!(
                    selection.recovery_handle,
                    "governor.task-selection:recovery"
                );
            }
            _ => panic!("expected TaskSelectionRequired"),
        }
        assert!(result.resolved_binding().is_none());
        result.validate_against(&ticket).expect("valid binding");
    }

    // WORK_UNIT_CASE: 839/14
    #[test]
    fn scope_selection_preserves_distinct_candidates_coverage_and_recovery() {
        let ticket = test_ticket(100);
        let outcome = fixture_scope_selection_required(vec!["scope:candidate".to_owned()]);
        let result = map_governor_outcome_to_protocol(&ticket, outcome, 50).expect("mapping");
        match &result.disposition {
            AgentActivationResolutionDisposition::ScopeSelectionRequired { selection } => {
                assert_eq!(
                    selection.candidate_handles,
                    vec!["scope:candidate".to_owned()]
                );
                assert_eq!(
                    selection.candidate_coverage,
                    AgentActivationCandidateCoverage::Partial
                );
                assert_eq!(
                    selection.recovery_handle,
                    "governor.scope-selection:recovery"
                );
            }
            _ => panic!("expected ScopeSelectionRequired"),
        }
        assert!(result.resolved_binding().is_none());
        result.validate_against(&ticket).expect("valid binding");
    }

    // WORK_UNIT_CASE: 839/16
    #[test]
    fn not_ready_preserves_dependency_revision_and_due_time() {
        let ticket = test_ticket(100);
        let result = map_governor_outcome_to_protocol(
            &ticket,
            fixture_not_ready("governor.session", "revision-7", 60),
            50,
        )
        .expect("mapping");
        match &result.disposition {
            AgentActivationResolutionDisposition::NotReady {
                recovery_handle,
                retry,
            } => {
                assert_eq!(recovery_handle, "governor.not-ready:recovery");
                assert_eq!(retry.dependency_ref, "governor.session");
                assert_eq!(retry.observed_dependency_revision, "revision-7");
                assert_eq!(retry.not_before_unix_ms, 60);
            }
            _ => panic!("expected NotReady"),
        }
        assert!(result.is_transient_retry());
        result.validate_against(&ticket).expect("valid binding");
    }

    // WORK_UNIT_CASE: 839/18
    #[test]
    fn failed_internal_preserves_failure_identity_without_retry_or_selection() {
        let ticket = test_ticket(100);
        let result = map_governor_outcome_to_protocol(
            &ticket,
            fixture_failed_internal("snapshot-corrupt"),
            50,
        )
        .expect("mapping");
        match &result.disposition {
            AgentActivationResolutionDisposition::FailedInternal { failure_handle } => {
                assert_eq!(failure_handle, "governor.internal:snapshot-corrupt");
            }
            _ => panic!("expected FailedInternal"),
        }
        assert!(result.resolved_binding().is_none());
        assert!(!result.is_transient_retry());
        assert!(!matches!(
            result.disposition,
            AgentActivationResolutionDisposition::TaskSelectionRequired { .. }
                | AgentActivationResolutionDisposition::ScopeSelectionRequired { .. }
                | AgentActivationResolutionDisposition::ScopeAmbiguous { .. }
        ));
        result.validate_against(&ticket).expect("valid binding");
    }

    // WORK_UNIT_CASE: 839/19
    #[test]
    fn every_governor_outcome_maps_to_distinct_protocol_kind() {
        let ticket = test_ticket(100);
        let snapshot = test_snapshot();
        let outcomes = vec![
            (GovernorActivationOutcome::Resolved(snapshot), "RESOLVED"),
            (fixture_task_selection_required(), "TASK_SELECTION_REQUIRED"),
            (
                fixture_scope_selection_required(vec!["scope:x".to_owned()]),
                "SCOPE_SELECTION_REQUIRED",
            ),
            (
                fixture_scope_ambiguous(vec!["scope:a".to_owned(), "scope:b".to_owned()]),
                "SCOPE_AMBIGUOUS",
            ),
            (fixture_not_ready("dep", "rev", 60), "NOT_READY"),
            (fixture_stale_fence(None), "STALE_FENCE"),
            (fixture_failed_internal("internal"), "FAILED_INTERNAL"),
        ];
        let mut kinds = std::collections::BTreeSet::new();
        for (outcome, expected_kind) in outcomes {
            let expected = expected_kind;
            let result = map_governor_outcome_to_protocol(&ticket, outcome, 50).expect("mapping");
            let kind = match result.disposition {
                AgentActivationResolutionDisposition::Resolved { .. } => "RESOLVED",
                AgentActivationResolutionDisposition::TaskSelectionRequired { .. } => {
                    "TASK_SELECTION_REQUIRED"
                }
                AgentActivationResolutionDisposition::ScopeSelectionRequired { .. } => {
                    "SCOPE_SELECTION_REQUIRED"
                }
                AgentActivationResolutionDisposition::ScopeAmbiguous { .. } => "SCOPE_AMBIGUOUS",
                AgentActivationResolutionDisposition::NotReady { .. } => "NOT_READY",
                AgentActivationResolutionDisposition::StaleFence { .. } => "STALE_FENCE",
                AgentActivationResolutionDisposition::FailedInternal { .. } => "FAILED_INTERNAL",
            };
            assert_eq!(kind, expected);
            assert!(kinds.insert(kind.to_owned()), "duplicate kind {kind}");
        }
        assert_eq!(kinds.len(), 7);
    }

    #[test]
    fn no_resolver_error_is_silently_dropped_or_coerced_to_success() {
        let ticket = test_ticket(100);
        // Each non-resolved outcome must not produce an Ok(Resolved) result.
        let non_resolved = vec![
            fixture_task_selection_required(),
            fixture_scope_selection_required(Vec::new()),
            fixture_scope_ambiguous(vec!["scope:a".to_owned(), "scope:b".to_owned()]),
            fixture_not_ready("dep", "rev", 60),
            fixture_stale_fence(None),
            fixture_failed_internal("failure"),
        ];
        for outcome in non_resolved {
            let result = map_governor_outcome_to_protocol(&ticket, outcome.clone(), 50)
                .expect("non-resolved must map to Ok with correct disposition, not Err");
            assert!(
                result.resolved_binding().is_none(),
                "resolver error was coerced to success: {:?}",
                result.disposition
            );
        }
        // Resolved must be the only path that yields a binding.
        let resolved = map_governor_outcome_to_protocol(
            &ticket,
            GovernorActivationOutcome::Resolved(test_snapshot()),
            50,
        )
        .expect("resolved");
        assert!(resolved.resolved_binding().is_some());
    }

    #[test]
    fn protocol_validation_rejects_coerced_observed_fence_equal_to_ticket() {
        let ticket = test_ticket(100);
        // Governor StaleFence with observed == ticket fence must be rejected by
        // protocol validation, proving the mapping does not hide fence mismatches.
        let outcome = fixture_stale_fence(Some(ticket.state_fence.clone()));
        let err = map_governor_outcome_to_protocol(&ticket, outcome, 50).expect_err("must reject");
        // The error is surfaced as DaemonError::Lifecycle wrapping ProtocolError,
        // not dropped or mapped to Resolved.
        assert!(err.to_string().contains("observed_state_fence"));
    }

    #[test]
    fn not_ready_window_must_be_before_deadline() {
        let ticket = test_ticket(100);
        // not_before == deadline must fail, not be silently accepted.
        let outcome = fixture_not_ready("dep", "rev", 100);
        let err = map_governor_outcome_to_protocol(&ticket, outcome, 50).expect_err("must reject");
        assert!(err.to_string().contains("not_before_unix_ms"));
    }

    #[test]
    fn scope_ambiguous_with_one_candidate_is_rejected_not_coerced() {
        let ticket = test_ticket(100);
        let outcome = fixture_scope_ambiguous(vec!["only-one".to_owned()]);
        let err = map_governor_outcome_to_protocol(&ticket, outcome, 50).expect_err("must reject");
        assert!(err.to_string().contains("SCOPE_AMBIGUOUS"));
    }

    // WORK_UNIT_CASE: 839/8
    #[test]
    fn resolved_fence_mismatch_yields_typed_stale_fence_without_binding() {
        // #66: a Resolved snapshot under a stale fence must surface as a
        // typed StaleFence terminal result, never as a Session binding and
        // never as a silent drop.
        let ticket = test_ticket(100);
        let observed = StateFence::new(test_epoch(1), ResourceGeneration::new(2).expect("gen"));
        assert_ne!(observed, ticket.state_fence);
        let result = stale_fence_for_resolved_mismatch(&ticket, observed.clone(), 50)
            .expect("stale fence result");
        assert!(matches!(
            result.disposition,
            AgentActivationResolutionDisposition::StaleFence { .. }
        ));
        assert!(result.resolved_binding().is_none());
        match &result.disposition {
            AgentActivationResolutionDisposition::StaleFence {
                observed_state_fence: Some(fence),
                ..
            } => assert_eq!(fence, &observed),
            _ => panic!("expected StaleFence with observed fence"),
        }
        result.validate_against(&ticket).expect("valid binding");
    }

    #[test]
    fn resolved_fence_mismatch_with_equal_fence_is_rejected() {
        // The helper must not hide a fence match as StaleFence: an observed
        // fence equal to the ticket fence is rejected by protocol validation.
        let ticket = test_ticket(100);
        let err = stale_fence_for_resolved_mismatch(&ticket, ticket.state_fence.clone(), 50)
            .expect_err("equal fence must reject");
        assert!(err.to_string().contains("observed_state_fence"));
    }

    #[test]
    fn not_ready_past_deadline_falls_back_to_failed_internal() {
        // #202: a Governor NotReady whose retry window reaches the Kernel
        // deadline cannot bind the ticket, so the mapping rejects it. The
        // fallback answers the same ticket with a typed FailedInternal
        // terminal result instead of leaving it unanswered.
        let ticket = test_ticket(100);
        let outcome = fixture_not_ready("dep", "rev", 100);
        let err = map_governor_outcome_to_protocol(&ticket, outcome, 50).expect_err("must reject");
        assert!(err.to_string().contains("not_before_unix_ms"));
        let result =
            failed_internal_for_mapping_failure(&ticket, "NOT_READY", 50).expect("fallback result");
        assert!(matches!(
            result.disposition,
            AgentActivationResolutionDisposition::FailedInternal { .. }
        ));
        assert!(result.resolved_binding().is_none());
        assert!(!result.is_transient_retry());
        result.validate_against(&ticket).expect("valid binding");
    }

    #[test]
    fn failed_internal_fallback_carries_kind_and_no_binding() {
        // #202: the fallback carries the failed outcome kind in its bounded
        // failure handle and never produces a binding.
        let ticket = test_ticket(100);
        let result = failed_internal_for_mapping_failure(&ticket, "SCOPE_AMBIGUOUS", 50)
            .expect("fallback result");
        match &result.disposition {
            AgentActivationResolutionDisposition::FailedInternal { failure_handle } => {
                assert!(failure_handle.contains("SCOPE_AMBIGUOUS"));
            }
            _ => panic!("expected FailedInternal"),
        }
        assert!(result.resolved_binding().is_none());
        result.validate_against(&ticket).expect("valid binding");
    }

    #[test]
    fn unready_governor_yields_typed_failed_internal_without_binding() {
        // #204: an unready Governor answers the exact valid ticket with a
        // typed FailedInternal terminal result instead of a hard loop-fatal
        // error: distinct from every other negative, never transient, and
        // never a binding.
        let ticket = test_ticket(100);
        let result =
            failed_internal_for_unready_governor(&ticket, 50).expect("unready fallback result");
        match &result.disposition {
            AgentActivationResolutionDisposition::FailedInternal { failure_handle } => {
                assert!(failure_handle.contains("governor-not-ready"));
            }
            _ => panic!("expected FailedInternal"),
        }
        assert!(result.resolved_binding().is_none());
        assert!(!result.is_transient_retry());
        assert_eq!(result.ticket_id, ticket.ticket_id);
        result.validate_against(&ticket).expect("valid binding");
    }

    #[test]
    fn unready_governor_fallback_at_deadline_fails_closed() {
        // #204: the fallback never fabricates a result past the Kernel
        // deadline; a ticket that expired under the resolver stays an error.
        let ticket = test_ticket(100);
        assert!(
            failed_internal_for_unready_governor(&ticket, 100).is_err(),
            "resolved_at at the deadline must not bind"
        );
    }

    // WORK_UNIT_CASE: 839/5
    #[test]
    fn tampered_ticket_is_rejected_by_every_fail_closed_constructor() {
        // #204 scenario 10: a tampered/wrong ticket (digest mismatch) binds
        // nothing. Every fail-closed constructor validates the ticket first
        // via `AgentActivationResolutionResult::new`, so each stays Err with
        // no binding and no new mapping.
        let mut ticket = test_ticket(100);
        ticket.ticket_id = "ticket-tampered".to_owned();
        // Digest still covers the original id: tampered by construction.
        assert!(ticket.validate().is_err());
        let observed = StateFence::new(test_epoch(1), ResourceGeneration::new(2).expect("gen"));
        assert!(
            map_governor_outcome_to_protocol(
                &ticket,
                GovernorActivationOutcome::Resolved(test_snapshot()),
                50,
            )
            .is_err(),
            "tampered ticket must not map"
        );
        assert!(
            stale_fence_for_resolved_mismatch(&ticket, observed, 50).is_err(),
            "tampered ticket must not yield StaleFence"
        );
        assert!(
            failed_internal_for_mapping_failure(&ticket, "NOT_READY", 50).is_err(),
            "tampered ticket must not yield mapping-failure FailedInternal"
        );
        assert!(
            failed_internal_for_unready_governor(&ticket, 50).is_err(),
            "tampered ticket must not yield unready FailedInternal"
        );
    }

    // WORK_UNIT_CASE: 839/4
    #[test]
    fn malformed_wire_rejected_before_semantic_resolution() {
        // Malformed wire identity with a fresh digest: the shape defect is
        // reported, never a digest mismatch. The production resolver
        // (`DaemonComposition::resolve_agent_activation_v2`) invokes
        // `ticket.validate()` before readiness/deadline/Governor access, so
        // this rejection provably precedes any Governor read.
        let mut ticket = test_ticket(100);
        ticket.wire_id = "eliot.agent.activation.resolution.ticket.malformed".to_owned();
        ticket.ticket_sha256 = ticket.compute_digest().expect("digest");
        let error = match ticket.validate() {
            Ok(()) => panic!("malformed wire id validated"),
            Err(error) => error.to_string(),
        };
        assert!(
            error.contains("agent_activation_resolution_ticket.wire"),
            "malformed wire reported the wrong field: {error}"
        );
        // Zero wire version is equally malformed.
        let mut zeroed = test_ticket(100);
        zeroed.wire_version = 0;
        zeroed.ticket_sha256 = zeroed.compute_digest().expect("digest");
        assert!(zeroed.validate().is_err(), "zero wire version validated");
        // No fail-closed constructor may consume either malformed ticket.
        let observed = StateFence::new(test_epoch(1), ResourceGeneration::new(2).expect("gen"));
        for bad in [&ticket, &zeroed] {
            assert!(
                map_governor_outcome_to_protocol(
                    bad,
                    GovernorActivationOutcome::Resolved(test_snapshot()),
                    50,
                )
                .is_err(),
                "typed mapping consumed a malformed-wire ticket"
            );
            assert!(
                stale_fence_for_resolved_mismatch(bad, observed.clone(), 50).is_err(),
                "stale-fence fallback consumed a malformed-wire ticket"
            );
            assert!(
                failed_internal_for_unready_governor(bad, 50).is_err(),
                "unready-Governor fallback consumed a malformed-wire ticket"
            );
            assert!(
                failed_internal_for_mapping_failure(bad, "NOT_READY", 50).is_err(),
                "mapping-failure fallback consumed a malformed-wire ticket"
            );
        }
    }

    // WORK_UNIT_CASE: 839/21
    #[test]
    fn unknown_wire_version_rejected_before_semantic_resolution() {
        // Well-formed ticket on a future version with a matching digest: an
        // unknown version, not a malformed shape and not a digest mismatch.
        // Rejected by the same `ticket.validate()` the production resolver
        // runs before any Governor read, so no v2 data is ever decoded.
        let mut ticket = test_ticket(100);
        ticket.wire_version = AgentActivationResolutionTicket::CONTRACT_VERSION + 1;
        ticket.ticket_sha256 = ticket.compute_digest().expect("digest");
        let error = match ticket.validate() {
            Ok(()) => panic!("unknown wire version validated"),
            Err(error) => error.to_string(),
        };
        assert!(
            error.contains("agent_activation_resolution_ticket.wire"),
            "unknown version reported the wrong field: {error}"
        );
        assert!(
            map_governor_outcome_to_protocol(
                &ticket,
                GovernorActivationOutcome::Resolved(test_snapshot()),
                50,
            )
            .is_err(),
            "typed mapping consumed an unknown-version ticket"
        );
        let observed = StateFence::new(test_epoch(1), ResourceGeneration::new(2).expect("gen"));
        assert!(
            stale_fence_for_resolved_mismatch(&ticket, observed, 50).is_err(),
            "stale-fence fallback consumed an unknown-version ticket"
        );
        assert!(
            failed_internal_for_unready_governor(&ticket, 50).is_err(),
            "unready-Governor fallback consumed an unknown-version ticket"
        );
        assert!(
            failed_internal_for_mapping_failure(&ticket, "NOT_READY", 50).is_err(),
            "mapping-failure fallback consumed an unknown-version ticket"
        );
    }

    // WORK_UNIT_CASE: 839/9
    #[test]
    fn post_deadline_resolved_at_is_rejected_by_every_fail_closed_constructor() {
        // #204 scenario 11: no valid terminal result at or past the Kernel
        // deadline. `Result::new` requires resolved_at strictly earlier than
        // the deadline, so each constructor stays Err and never fabricates a
        // typed negative past expiry. (Unready past-deadline covered above.)
        let ticket = test_ticket(100);
        let observed = StateFence::new(test_epoch(1), ResourceGeneration::new(2).expect("gen"));
        assert!(
            map_governor_outcome_to_protocol(
                &ticket,
                GovernorActivationOutcome::Resolved(test_snapshot()),
                100,
            )
            .is_err(),
            "resolved_at at the deadline must not bind"
        );
        assert!(
            stale_fence_for_resolved_mismatch(&ticket, observed, 100).is_err(),
            "stale-fence fallback at the deadline must not bind"
        );
        assert!(
            failed_internal_for_mapping_failure(&ticket, "NOT_READY", 100).is_err(),
            "mapping-failure fallback at the deadline must not bind"
        );
    }

    #[test]
    fn wrong_ticket_result_binding_is_rejected() {
        // #204 scenario 10 (wrong-ticket half): a result bound to one ticket
        // never validates against another ticket identity.
        let ticket = test_ticket(100);
        let result = failed_internal_for_unready_governor(&ticket, 50).expect("fallback result");
        result.validate_against(&ticket).expect("valid binding");
        let mut other = test_ticket(100);
        other.ticket_id = "ticket-other".to_owned();
        other.ticket_sha256 = other.compute_digest().expect("digest");
        assert!(other.validate().is_ok());
        assert!(
            result.validate_against(&other).is_err(),
            "result bound to one ticket must not validate against another"
        );
    }

    // WORK_UNIT_CASE: 839/12
    #[test]
    fn resolved_preserves_all_binding_fields() {
        // Every field of the Governor snapshot survives the v2 mapping
        // verbatim: principal/session/task/work-unit/scope/plan identities
        // plus task and plan revisions. Drives the actual production mapper
        // (`map_governor_outcome_to_protocol`); no Governor read is stubbed.
        let ticket = test_ticket(100);
        let snapshot = test_snapshot();
        let result = map_governor_outcome_to_protocol(
            &ticket,
            GovernorActivationOutcome::Resolved(snapshot.clone()),
            50,
        )
        .expect("resolved mapping");
        match &result.disposition {
            AgentActivationResolutionDisposition::Resolved { binding } => {
                assert_eq!(binding.principal_id, snapshot.principal_id);
                assert_eq!(binding.session_id, snapshot.session_id);
                assert_eq!(binding.task_id, snapshot.task_id.to_string());
                assert_eq!(binding.work_unit_id, snapshot.work_unit_id);
                assert_eq!(binding.work_scope_id, snapshot.work_scope_id);
                assert_eq!(binding.task_revision, snapshot.task_revision.to_string());
                assert_eq!(binding.plan_id, snapshot.plan_id);
                assert_eq!(binding.plan_revision, snapshot.plan_revision);
            }
            _ => panic!("expected Resolved"),
        }
        assert_eq!(result.ticket_id, ticket.ticket_id);
        assert_eq!(result.ticket_sha256, ticket.ticket_sha256);
        assert!(result.resolved_binding().is_some());
        result.validate_against(&ticket).expect("valid binding");
    }

    // WORK_UNIT_CASE: 839/15
    #[test]
    fn scope_ambiguous_preserves_candidates_and_coverage() {
        // ScopeAmbiguous keeps the exact candidate handles, coverage, and
        // recovery handle through the v2 mapping. Complete and Partial
        // coverage both bind; Unknown and single-candidate findings stay
        // fail-closed rejections instead of being coerced.
        let ticket = test_ticket(100);
        let candidates = vec!["scope:a".to_owned(), "scope:b".to_owned()];
        let outcome = fixture_scope_ambiguous(candidates.clone());
        let result = map_governor_outcome_to_protocol(&ticket, outcome, 50).expect("mapping");
        match &result.disposition {
            AgentActivationResolutionDisposition::ScopeAmbiguous { selection } => {
                assert_eq!(selection.candidate_handles, candidates);
                assert_eq!(
                    selection.candidate_coverage,
                    AgentActivationCandidateCoverage::Complete
                );
                assert_eq!(
                    selection.recovery_handle,
                    "governor.scope-ambiguous:recovery"
                );
            }
            _ => panic!("expected ScopeAmbiguous"),
        }
        assert!(result.resolved_binding().is_none());
        result.validate_against(&ticket).expect("valid");
        // Partial coverage with two exact candidates also binds verbatim.
        let partial = GovernorActivationOutcome::ScopeAmbiguous {
            selection: GovernorSelectionDirective::new(
                candidates.clone(),
                GovernorCandidateCoverage::Partial,
                "governor.scope-ambiguous:recovery",
            ),
        };
        let partial_result =
            map_governor_outcome_to_protocol(&ticket, partial, 50).expect("partial mapping");
        match &partial_result.disposition {
            AgentActivationResolutionDisposition::ScopeAmbiguous { selection } => {
                assert_eq!(selection.candidate_handles, candidates);
                assert_eq!(
                    selection.candidate_coverage,
                    AgentActivationCandidateCoverage::Partial
                );
            }
            _ => panic!("expected ScopeAmbiguous for partial coverage"),
        }
        partial_result.validate_against(&ticket).expect("valid");
        // Unknown coverage and single-candidate findings never coerce.
        let unknown = GovernorActivationOutcome::ScopeAmbiguous {
            selection: GovernorSelectionDirective::new(
                candidates,
                GovernorCandidateCoverage::Unknown,
                "governor.scope-ambiguous:recovery",
            ),
        };
        assert!(
            map_governor_outcome_to_protocol(&ticket, unknown, 50).is_err(),
            "ambiguous with UNKNOWN coverage must be rejected, not coerced"
        );
        assert!(
            map_governor_outcome_to_protocol(
                &ticket,
                fixture_scope_ambiguous(vec!["only-one".to_owned()]),
                50,
            )
            .is_err(),
            "ambiguous with one candidate must be rejected, not coerced"
        );
    }

    // WORK_UNIT_CASE: 839/17
    #[test]
    fn stale_fence_preserves_observed_fence_and_recovery() {
        // StaleFence carries the available observed fence and the
        // owner-issued recovery handle through the v2 mapping without ever
        // producing a Session binding. Absent observation (None) also binds
        // as a typed terminal result.
        let ticket = test_ticket(100);
        let observed = StateFence::new(test_epoch(1), ResourceGeneration::new(2).expect("gen"));
        let result = map_governor_outcome_to_protocol(
            &ticket,
            fixture_stale_fence(Some(observed.clone())),
            50,
        )
        .expect("mapping");
        match &result.disposition {
            AgentActivationResolutionDisposition::StaleFence {
                recovery_handle,
                observed_state_fence: Some(fence),
            } => {
                assert_eq!(fence, &observed);
                assert_ne!(fence, &ticket.state_fence);
                assert_eq!(recovery_handle, "governor.stale-fence:recovery");
            }
            _ => panic!("expected StaleFence with observed fence"),
        }
        assert!(result.resolved_binding().is_none());
        assert!(!result.is_transient_retry());
        result.validate_against(&ticket).expect("valid");
        // No observed fence is still a typed terminal result, never Resolved.
        let none_result = map_governor_outcome_to_protocol(&ticket, fixture_stale_fence(None), 50)
            .expect("none mapping");
        match &none_result.disposition {
            AgentActivationResolutionDisposition::StaleFence {
                observed_state_fence: None,
                ..
            } => {}
            _ => panic!("expected StaleFence without observed fence"),
        }
        assert!(none_result.resolved_binding().is_none());
        none_result.validate_against(&ticket).expect("valid");
    }

    // WORK_UNIT_CASE: 839/10
    #[test]
    fn exact_replay_preserves_semantic_result_and_digest() {
        // Exact replay under the same ticket preserves the full semantic
        // result and its digest: mapping the same Governor outcome twice
        // yields the identical typed result, so a resubmission replays
        // instead of diverging. Drives the actual production mapper twice;
        // no Governor read is stubbed.
        let ticket = test_ticket(100);
        let first =
            map_governor_outcome_to_protocol(&ticket, fixture_task_selection_required(), 50)
                .expect("first mapping");
        let second =
            map_governor_outcome_to_protocol(&ticket, fixture_task_selection_required(), 50)
                .expect("second mapping");
        assert_eq!(first, second);
        assert_eq!(first.result_sha256, second.result_sha256);
        assert_eq!(
            first.canonical_unsigned_bytes().expect("canonical bytes"),
            second.canonical_unsigned_bytes().expect("canonical bytes"),
        );
        first.validate_against(&ticket).expect("valid binding");
        second.validate_against(&ticket).expect("valid binding");
        // The retained acknowledgement echoes the exact result verbatim and
        // uses one stable positive outcome for fresh commit, replay, and
        // reconcile, so retry transport cannot change response bytes.
        let ack = eliot_protocol::AgentActivationResultAck::accepted(&first).expect("stable ack");
        let replay_ack =
            eliot_protocol::AgentActivationResultAck::accepted(&second).expect("replay ack");
        assert_eq!(
            ack.outcome,
            eliot_protocol::AgentActivationResultAckOutcome::Accepted
        );
        assert_eq!(ack, replay_ack);
        assert_eq!(ack.result.as_ref(), Some(&second));
        ack.validate().expect("valid ack");
    }

    // WORK_UNIT_CASE: 839/11
    #[test]
    fn changed_result_under_same_ticket_conflicts_on_digest() {
        // A changed semantic result under the same ticket is never an exact
        // replay: both results bind the exact ticket, but their digests
        // differ, so the Kernel reconcile leg (which matches on ticket plus
        // digest) distinguishes conflict from replay. The daemon preserves
        // the distinguishing identity; the Kernel owns the conflict decision.
        let ticket = test_ticket(100);
        let resolved = map_governor_outcome_to_protocol(
            &ticket,
            GovernorActivationOutcome::Resolved(test_snapshot()),
            50,
        )
        .expect("resolved mapping");
        let selection =
            map_governor_outcome_to_protocol(&ticket, fixture_task_selection_required(), 50)
                .expect("selection mapping");
        assert_ne!(
            resolved.result_sha256, selection.result_sha256,
            "changed disposition must change the result digest"
        );
        resolved.validate_against(&ticket).expect("valid binding");
        selection.validate_against(&ticket).expect("valid binding");
        let query = eliot_protocol::AgentActivationResultReconcile::new(
            ticket.ticket_id.clone(),
            resolved.result_sha256.clone(),
        )
        .expect("reconcile query");
        assert_ne!(query.result_sha256, selection.result_sha256);
        let ack =
            eliot_protocol::AgentActivationResultAck::accepted(&resolved).expect("accept ack");
        assert_ne!(ack.result_sha256, selection.result_sha256);
        assert_ne!(ack.result.as_ref(), Some(&selection));
        ack.validate().expect("valid ack");
    }
}
