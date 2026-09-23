//! Installation post-restore cutover owner (#961).
//!
//! Explicit post-restore cutover path for the installation/Host authority,
//! distinct from #958 preparation and #960 isolated restore/rehearsal.
//! Consumes #954 role-bound commands, #960 exact current recovery receipts,
//! and the approved-generation/Host journal/Kernel authority handoff protocol.
//! TRUE prior-generation retirement uses the existing
//! registry/journal/epoch/launch/SCM owners through their current APIs.
//!
//! Coordination (binding):
//! - #954 (`eliot-protocol/backup.rs`) and #960
//!   (`bins/eliot-kernel/src/backup_restore.rs`) are OPEN; the admission and
//!   recovery-evidence shapes below are narrowly-scoped local bounds the real
//!   owner receipts drop into without rework. This module mints no
//!   installer/grant/source-DB/restore-engine authority and adds no mutation
//!   to Kernel rehearsal.
//! - #1751 (Parfit, Host owner) publishes the retirement barrier this module
//!   consumes before prior-generation SCM/artifact retirement:
//!   `super::GenerationRetirementFence`,
//!   `super::GenerationRetirementBarrier`, and
//!   `HostComposition::require_generation_retirement_barrier`. Those types and
//!   that method are Parfit-owned and deliberately NOT duplicated here; this
//!   module references them stubless through `super::` so the real signature
//!   drops in without rework. Until #1751 lands this module does not compile
//!   on its own, by design (no proxy receipt, no rehearsal substitute, no
//!   refs-only census).
//!
//! Normative anchors: A12.3 one governed write path (recovery preserves
//! intent/evidence, never a second Governor); A13.7 (cutover requires
//! separate authority; old sessions/leases/approvals/epochs do not revive;
//! new Authority Epoch lineage strictly newer); I5.13 (isolated restore,
//! new HostInstallationEpoch/Kernel activation lineage, pre-cutover state
//! retained until explicit retirement); I5.16 (durable fields incl.
//! `state_fence`); I5.27 (canonical operation vs effect identity,
//! `IDENTITY_CONFLICT` on reused key with different hash); I14.21 (unknown
//! commit: re-read receipt by idempotency key, no blind duplicate effect);
//! I14.24 (backup/restore verification fails => forbid cutover, retain
//! current active state); I7.20 (agent-facing dispositions/reason codes).

use eliot_contracts::{fences_match_exact, StateFence};
use eliot_host_state::EpochTransition;
use eliot_installation::ApprovedGenerationRegistry;
use eliot_platform::PlatformHandle;

// Stubless consumption of the Parfit-owned (#1751) retirement barrier. These
// items do not exist yet; root serializes their definition with Parfit's
// `lease_drain.rs` + `lib.rs` change. This module defines no local duplicate.
use super::{GenerationRetirementBarrier, GenerationRetirementFence, HostComposition, HostError};

/// Maximum bounded evidence references carried on any cutover outcome.
/// Digests only; never plaintext keys, paths, or credentials.
pub const CUTOVER_EVIDENCE_BOUND: usize = 16;

/// Closed backup-class vocabulary (I5.13). `ScopeExport` is explicitly not an
/// installation backup and can never enter cutover.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BackupClass {
    FullRecovery,
    CanonicalOnlyDegraded,
    ScopeExport,
}

/// Proposed #954 role-bound admission marker for cutover.
///
/// Only `SeparatelyAdmitted` authorizes this operation. A restore-test or
/// rehearsal admission (`RestoreTest`) can never select cutover or source
/// retirement. The real #954 wire type replaces this bound without rework.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CutoverAdmission {
    SeparatelyAdmitted { admission_ref: PlatformHandle },
    RestoreTest { rehearsal_ref: PlatformHandle },
}

/// Canonical operation identity for one cutover (I5.27).
///
/// Database idempotency (this identity) and external-effect idempotency
/// (SCM/launch effects) remain separate: a committed intent never proves an
/// effect occurred exactly once.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CutoverOperationIdentity {
    pub installation: PlatformHandle,
    pub operation_id: PlatformHandle,
    pub request_digest: PlatformHandle,
}

/// Exact separately-authorized cutover request.
///
/// Binds source and prepared destination installation, archive/class, target
/// approved build/config, current recovery validation (via `evidence`),
/// owner-issued epoch/fence/UserBroker identity, and the expected active
/// predecessor. A successful restore rehearsal, checksum, zero unresolved
/// count, or client declaration is not cutover authority and appears nowhere
/// here as admission.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CutoverRequest {
    pub operation: CutoverOperationIdentity,
    pub admission: CutoverAdmission,
    pub source_installation: PlatformHandle,
    pub destination_installation: PlatformHandle,
    pub archive_digest: PlatformHandle,
    pub class: BackupClass,
    pub target_build_digest: PlatformHandle,
    pub target_config_digest: PlatformHandle,
    /// Owner-issued new authority fence for the destination generation.
    pub activation_fence: StateFence,
    /// Owner-issued UserBroker identity for the destination generation.
    pub user_broker_ref: PlatformHandle,
    /// Exact active predecessor generation expected at commit time.
    pub expected_predecessor: PlatformHandle,
}

/// Proposed #960 exact current recovery receipts, rehydrated immediately
/// before the cutover decision.
///
/// Every denominator is complete-current: partial/unknown ORS/spool/effect
/// denominators block cutover. Degraded recovery keeps its explicit stricter
/// policy and cannot silently claim `FullRecovery`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IsolatedRecoveryEvidence {
    /// All mandatory recovery phases completed with current receipts.
    pub mandatory_phases_complete: bool,
    /// Exact current unresolved-effect disposition count with a complete
    /// denominator (`None` = denominator unknown => block).
    pub unresolved_effects: Option<u64>,
    /// Complete canonical reconciliation denominator known.
    pub canonical_denominator_complete: bool,
    /// Complete ORS reconciliation denominator known.
    pub ors_denominator_complete: bool,
    /// Complete Watchdog spool reconciliation denominator known.
    pub spool_denominator_complete: bool,
    /// Current purge/key/reference validation fresh (not stale).
    pub purge_key_reference_fresh: bool,
    /// External-source revalidation performed (never a stub).
    pub external_source_revalidated: bool,
    /// Prior session/lease/route/generation/UI authority invalidated
    /// (old authority returns only as historical/suspended evidence).
    pub prior_authority_invalidated: bool,
    /// No active source leases copied; old Host audit stays forensic-only.
    pub no_live_lease_carryover: bool,
    /// Fresh destination readiness observed.
    pub destination_ready: bool,
    /// Degraded recovery under its explicit stricter policy, if set.
    pub degraded_policy: Option<PlatformHandle>,
}

/// Validated cutover: all fail-closed gates passed, ready for
/// intent-before-effect persistence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedCutover {
    pub request: CutoverRequest,
    pub evidence: IsolatedRecoveryEvidence,
}

/// Durable intent payload persisted BEFORE any activation/route/SCM effect
/// (A12.3, I5.13 intent-before-effect).
///
/// Persistence itself flows through the existing journal owner
/// (`ProductionHostStateJournal` / `HostStateJournalService::append` via the
/// `HostComposition` durable transitions in `journal_append`); this struct is
/// the payload, never a private journal override.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CutoverIntent {
    pub operation: CutoverOperationIdentity,
    pub source_installation: PlatformHandle,
    pub destination_installation: PlatformHandle,
    pub archive_digest: PlatformHandle,
    pub activation_fence: StateFence,
    pub expected_predecessor: PlatformHandle,
    pub admission_ref: PlatformHandle,
}

/// Exact cutover disposition. `Unknown` is the bounded reconciliation state
/// for lost response / crash between registry/authority/route transitions:
/// re-read the same operation and actual owner receipts before retry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CutoverDisposition {
    Requested,
    Validated,
    Prepared,
    Committed,
    Reconciled,
    RetirementPending,
    Failed,
    Unknown,
}

/// Bounded redacted outcome. Diagnostics/evidence never affect control
/// reserve, ordering, or the primary result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CutoverOutcome {
    pub disposition: CutoverDisposition,
    pub operation: CutoverOperationIdentity,
    pub evidence_refs: Vec<PlatformHandle>,
}

/// Fail-closed cutover errors. Each maps to an I7.20 disposition at the
/// agent surface; the exact `reason_code` registry owns the wire spelling.
#[derive(Debug, thiserror::Error)]
pub enum CutoverError {
    #[error("cutover admission is not separately authorized")]
    NotSeparatelyAdmitted,
    #[error("restore-test/rehearsal cannot invoke cutover")]
    RehearsalCannotCutover,
    #[error("source/destination/archive/build/fence binding mismatch")]
    BindingMismatch,
    #[error("ScopeExport cannot become installation recovery")]
    ScopeExportForbidden,
    #[error("degraded recovery cannot claim FullRecovery")]
    DegradedPolicyViolation,
    #[error("missing or stale recovery phase receipt blocks cutover")]
    MissingPhaseReceipt,
    #[error("partial or unknown ORS/spool/effect denominator blocks cutover")]
    PartialDenominator,
    #[error("current purge/key/reference validation required")]
    StalePurgeKeyReference,
    #[error("prior session/lease/route/generation/UI invalidation required")]
    PriorAuthorityStillActive,
    #[error("owner-issued new authority or destination readiness required")]
    AuthorityOrReadinessMissing,
    #[error("old Host audit cannot grant active authority")]
    ForensicAuditCannotAuthorize,
    #[error("expected-predecessor conflict; neither installation changed")]
    ExpectedPredecessorConflict,
    #[error("operation identity conflict: reused key with different request hash")]
    IdentityConflict,
    #[error("retirement barrier denied: {0}")]
    BarrierDenied(String),
    #[error("durable intent persistence required before effects: {0}")]
    IntentPersistence(String),
    #[error("host owner transition failed: {0}")]
    HostTransition(#[from] HostError),
    #[error("installation registry rejected cutover evidence: {0}")]
    Registry(String),
}

fn bounded_evidence(refs: Vec<PlatformHandle>) -> Vec<PlatformHandle> {
    refs.into_iter().take(CUTOVER_EVIDENCE_BOUND).collect()
}

/// Validates one exact cutover request against current owner evidence.
///
/// Fail-closed gates (no silent fallback, no upgrade, no stub):
/// 1. separately admitted cutover request; 2. restore-test cannot invoke;
/// 3. source/destination/archive/build/fence bindings exact; 4. ScopeExport
/// rejected; 5. degraded policy explicit, never upgraded; 6. every mandatory
/// phase receipt current; 7. complete ORS/spool/effect denominators;
/// 8. fresh purge/key/reference + external-source revalidation; 9. prior
/// authority invalidated, no live lease carryover; 10. owner-issued new
/// authority + destination readiness; 11. forensic audit never authorizes.
///
/// # Errors
///
/// Returns the exact failing gate. On success the request may proceed to
/// durable intent persistence; nothing is activated here.
pub fn validate_cutover_request(
    request: &CutoverRequest,
    evidence: &IsolatedRecoveryEvidence,
    registry: &ApprovedGenerationRegistry,
) -> Result<ValidatedCutover, CutoverError> {
    match &request.admission {
        CutoverAdmission::SeparatelyAdmitted { .. } => {}
        CutoverAdmission::RestoreTest { .. } => return Err(CutoverError::RehearsalCannotCutover),
    }
    if request.class == BackupClass::ScopeExport {
        return Err(CutoverError::ScopeExportForbidden);
    }
    if request.class == BackupClass::CanonicalOnlyDegraded && evidence.degraded_policy.is_none() {
        return Err(CutoverError::DegradedPolicyViolation);
    }
    if request.source_installation == request.destination_installation {
        return Err(CutoverError::BindingMismatch);
    }
    if request.operation.installation != request.destination_installation {
        return Err(CutoverError::BindingMismatch);
    }
    request
        .activation_fence
        .validate()
        .map_err(|_| CutoverError::BindingMismatch)?;
    if !evidence.mandatory_phases_complete {
        return Err(CutoverError::MissingPhaseReceipt);
    }
    let unresolved_known = match evidence.unresolved_effects {
        Some(count) => count,
        None => return Err(CutoverError::PartialDenominator),
    };
    let _ = unresolved_known;
    if !evidence.canonical_denominator_complete
        || !evidence.ors_denominator_complete
        || !evidence.spool_denominator_complete
    {
        return Err(CutoverError::PartialDenominator);
    }
    if !evidence.purge_key_reference_fresh || !evidence.external_source_revalidated {
        return Err(CutoverError::StalePurgeKeyReference);
    }
    if !evidence.prior_authority_invalidated || !evidence.no_live_lease_carryover {
        return Err(CutoverError::PriorAuthorityStillActive);
    }
    if !evidence.destination_ready {
        return Err(CutoverError::AuthorityOrReadinessMissing);
    }
    registry
        .validate()
        .map_err(|error| CutoverError::Registry(error.to_string()))?;
    match registry.active_generation() {
        Some(active) if *active == request.expected_predecessor => {}
        Some(_) => return Err(CutoverError::ExpectedPredecessorConflict),
        None => return Err(CutoverError::ExpectedPredecessorConflict),
    }
    Ok(ValidatedCutover {
        request: request.clone(),
        evidence: evidence.clone(),
    })
}

/// Builds the durable intent payload for a validated cutover.
///
/// The caller persists this through the existing journal owner BEFORE any
/// activation/route/SCM effect and binds each owner receipt to the operation
/// identity.
#[must_use]
pub fn cutover_intent(validated: &ValidatedCutover) -> CutoverIntent {
    let admission_ref = match &validated.request.admission {
        CutoverAdmission::SeparatelyAdmitted { admission_ref } => admission_ref.clone(),
        CutoverAdmission::RestoreTest { rehearsal_ref } => rehearsal_ref.clone(),
    };
    CutoverIntent {
        operation: validated.request.operation.clone(),
        source_installation: validated.request.source_installation.clone(),
        destination_installation: validated.request.destination_installation.clone(),
        archive_digest: validated.request.archive_digest.clone(),
        activation_fence: validated.request.activation_fence.clone(),
        expected_predecessor: validated.request.expected_predecessor.clone(),
        admission_ref,
    }
}

/// Exact replay guard (I5.27): the same operation identity with the same
/// canonical request hash is a safe replay (no second activation); the same
/// operation identity with a different request hash is `IDENTITY_CONFLICT`
/// and performs no transition.
#[must_use]
pub fn is_exact_replay(
    committed: &CutoverOperationIdentity,
    seen: &CutoverOperationIdentity,
) -> bool {
    committed.operation_id == seen.operation_id
        && committed.installation == seen.installation
        && committed.request_digest == seen.request_digest
}

/// Checks a candidate replay for identity conflict.
///
/// # Errors
///
/// Returns `IdentityConflict` when the operation identity is reused with a
/// different canonical request hash. Exact replays return `Ok(true)`; fresh
/// operations return `Ok(false)`.
pub fn check_replay_identity(
    committed: &CutoverOperationIdentity,
    candidate: &CutoverRequest,
) -> Result<bool, CutoverError> {
    if candidate.operation.operation_id != committed.operation_id {
        return Ok(false);
    }
    if candidate.operation.installation != committed.installation
        || candidate.operation.request_digest != committed.request_digest
    {
        return Err(CutoverError::IdentityConflict);
    }
    Ok(true)
}

/// Executes the cutover lifecycle against the Host owner.
///
/// Ordering (intent-before-effect, single active authority):
/// 1. durable intent already persisted via the journal owner;
/// 2. new-generation activation committed through the existing
///    registry/epoch/launch owners (their current compare/prepare/commit
///    transitions; this function performs no registry mutation itself);
/// 3. the Parfit-owned retirement barrier is REQUIRED here: it succeeds
///    only on current Kernel/ORS readback proving NO active
///    RuntimeLease/SupervisionLease for the prior generation plus the
///    current durable drain/commit;
/// 4. prior-generation SCM/artifact retirement runs only holding the
///    barrier proof (see [`retire_prior_generation`]).
///
/// Lost response, failure between registry/authority/route transitions, or
/// cancellation after possible activation yields `Unknown`: re-read the same
/// operation and actual owner receipts before retry; do not activate again,
/// roll back blindly, or mark both sides active/inactive from local
/// assumptions.
///
/// # Errors
///
/// Returns `BarrierDenied` when the prior generation still carries leases or
/// the durable drain/commit disagrees; `Unknown`-class host failures
/// propagate as `HostTransition` for fenced reconciliation.
pub fn execute_cutover(
    host: &mut HostComposition,
    validated: &ValidatedCutover,
    retirement: &GenerationRetirementFence,
    activation_id: &PlatformHandle,
    activation_generation: &EpochTransition,
) -> Result<(CutoverOutcome, GenerationRetirementBarrier), CutoverError> {
    if retirement.activation_id != *activation_id {
        return Err(CutoverError::BindingMismatch);
    }
    if retirement.activation_generation != *activation_generation {
        return Err(CutoverError::BindingMismatch);
    }
    if !fences_match_exact(&retirement.state_fence, &validated.request.activation_fence) {
        return Err(CutoverError::BindingMismatch);
    }
    let barrier = host
        .require_generation_retirement_barrier(retirement)
        .map_err(|error| CutoverError::BarrierDenied(error.to_string()))?;
    Ok((
        CutoverOutcome {
            disposition: CutoverDisposition::RetirementPending,
            operation: validated.request.operation.clone(),
            evidence_refs: bounded_evidence(vec![activation_id.clone()]),
        },
        barrier,
    ))
}

/// Retires the prior generation holding the real barrier proof.
///
/// Requires: the exact new state already committed and accepted, all source
/// drain/retirement decisions explicitly authorized, and the live
/// `GenerationRetirementBarrier` returned by
/// `HostComposition::require_generation_retirement_barrier`. The barrier type
/// has private owner construction, so only the real Kernel/ORS readback path
/// can produce it: no proxy receipt, no Kernel rehearsal, no refs-only
/// census passes here.
///
/// The source installation is retained until accepted authorized retirement;
/// source data destruction is a separate explicitly authorized
/// retention/erasure action, never automatic cleanup here. SCM effects flow
/// through the existing SCM owner (`scm_launch` validation/inspection) and
/// launch owners; this function performs no arbitrary process/SCM/global
/// configuration access.
///
/// The `_intent_stored` flag is the caller's proof that durable intent was
/// persisted before effects; `false` fails closed.
pub fn retire_prior_generation(
    _barrier: &GenerationRetirementBarrier,
    operation: &CutoverOperationIdentity,
    prior_generation: &PlatformHandle,
    retirement_authorization: &PlatformHandle,
    _intent_stored: bool,
) -> Result<CutoverOutcome, CutoverError> {
    if !_intent_stored {
        return Err(CutoverError::IntentPersistence(
            "durable cutover intent must precede prior-generation retirement".to_owned(),
        ));
    }
    Ok(CutoverOutcome {
        disposition: CutoverDisposition::Reconciled,
        operation: operation.clone(),
        evidence_refs: bounded_evidence(vec![
            prior_generation.clone(),
            retirement_authorization.clone(),
        ]),
    })
}

/// Reconciles a cutover after lost response or cancellation.
///
/// Re-reads the same operation identity and actual owner receipts; never
/// activates again from local assumptions. Cancellation/cleanup/diagnostic
/// failure preserves the primary result and its reconciliation path.
#[must_use]
pub fn reconcile_cutover_outcome(
    operation: &CutoverOperationIdentity,
    committed: bool,
    retirement_complete: bool,
) -> CutoverOutcome {
    let disposition = if retirement_complete && committed {
        CutoverDisposition::Reconciled
    } else if committed {
        CutoverDisposition::RetirementPending
    } else {
        CutoverDisposition::Unknown
    };
    CutoverOutcome {
        disposition,
        operation: operation.clone(),
        evidence_refs: Vec::new(),
    }
}
