//! Installation post-restore cutover owner (#961).
//!
//! Explicit post-restore cutover path for the installation/Host authority,
//! distinct from #958 preparation and #960 isolated restore/rehearsal.
//! TRUE prior-generation retirement uses the existing
//! registry/journal/epoch/launch/SCM owners through their current APIs.
//! This module mints no installer/grant/source-DB/restore-engine authority
//! and adds no mutation to Kernel rehearsal.
//!
//! Actual-owner integration (read from current main, no substitutes):
//! - Admission: `eliot_protocol::{HostRequestEnvelope,
//!   HostRequestAdmissionReceipt, HostRequestKind, host_request_operation_id}`
//!   (`crates/foundation/eliot-protocol/src/lib.rs`: `HostRequestKind` at
//!   2641, `HostRequestEnvelope::validate` at 2898, `host_request_operation_id`
//!   at 3044, `HostRequestAdmissionReceipt::validate` at 3118). The protocol
//!   wire is closed with five kinds and no backup/cutover kind: a cutover
//!   command travels as an `Invocation` of the exact admitted envelope, and a
//!   restore-test/rehearsal envelope derives a different digest-bound
//!   `hostreq:` operation handle, so it can never satisfy this admission.
//! - Recovery receipts: `eliot_backup::{RestorePlan::execute_with_journal,
//!   RestoreTarget::{apply_restore_effect, reconcile_restore_effect},
//!   RestoreJournalPort::{load, compare_and_swap}, BackupBundle::validate,
//!   BackupClass::{select, is_full_recovery, is_canonical_only},
//!   RestoreEvidenceLevel::for_class, OperationalValidationEvidence}`
//!   (`crates/storage/eliot-backup/src/lib.rs`: `BackupClass` at 122,
//!   `BackupBundle::validate` at 670, `RestoreJournalPort` at 1334,
//!   `RestorePlan::execute_with_journal` at 1438 with "No active cutover is
//!   performed here", `RestoreEvidenceLevel::for_class` at 1951,
//!   `OperationalValidationEvidence` at 2102, `RestoreTarget` at 2666).
//!   `RestoreEvidenceLevel::permits_operational_readiness` (1969) is false for
//!   every library-emitted level: a restore receipt alone never qualifies for
//!   cutover, which is why this module additionally requires the
//!   owner-issued operational-validation receipt plus this separate cutover
//!   admission. The legacy `eliot_types::RestorePlan`
//!   (`crates/eliot-types/src/safety.rs:166`, stringly plan/check shape) is
//!   NOT the accepted contract and is not consumed here.
//! - Pending dependency edge (#974 owns Cargo/root/lock per #959/#960):
//!   `eliot-backup` is not in `bins/eliot-host/Cargo.toml` (precedent:
//!   `bins/eliot/Cargo.toml:22` carries its own path edge), so the typed
//!   `eliot_backup::{BackupClass, RestoreReceipt,
//!   OperationalValidationEvidence}` imports in this module resolve once
//!   #974 takes the one-line edge hunk (in the report, never applied here).
//!   Nothing here is an opaque substitute: class gates run through
//!   `is_full_recovery`/`is_canonical_only`/`evidence_level`, receipt gates
//!   through `RestoreReceipt::validate` plus bundle/fence/level bindings,
//!   validation gates through `OperationalValidationEvidence::validate`
//!   plus the observed-fence binding. No `From` bridges, no parallel
//!   vocabulary.
//! - Prior-introduction fencing rides the real ORS readback rows
//!   (`eliot_ors::CapabilityIntroductionProjection`, `model.rs:2043`, and
//!   `OperationalPhase::Fenced` at `model.rs:1928`, both on current main
//!   past #2388 via `pub use model::*`): every row must read `Fenced`.
//!   These names postdate this branch's base, so they resolve after root
//!   moves integration past `b452be52` (same standing as the barrier).
//!   The module-route cutover machinery in
//!   `eliot-ors/src/cutover_ownership.rs` was read and deliberately NOT
//!   consumed: it switches module route scopes under scalar
//!   `ResourceGeneration`/`AuthorityEpoch`, a different authority domain
//!   from installation cutover. The #2389 bank/feedback records were read
//!   and likewise not consumed: observation-bank semantics for #223, not
//!   operational recovery evidence.
//! - Retirement barrier (#1751, Parfit, Host owner): `super::
//!   GenerationRetirementFence`, `super::GenerationRetirementBarrier`, and
//!   `HostComposition::require_generation_retirement_barrier` are Parfit-owned
//!   and deliberately NOT duplicated here. The fence binds
//!   `activation_id: PlatformHandle` (`eliot_platform`, as in host `lib.rs`
//!   line 214), `activation_generation: EpochTransition` (`eliot_host_state`
//!   re-export of `eliot_contracts`, `epoch_identity.rs:211`), and
//!   `state_fence: StateFence` (`eliot_contracts`). Until #1751 lands this
//!   module does not compile standalone, by design.
//!
//! Real effect callgraph (every call below resolves to an existing owner):
//! - `HostComposition::ensure_admission_open` (host `lib.rs:7128`, private in
//!   the crate root, visible to this descendant module): admission guard.
//! - `super::open_registry_store_at` (host `lib.rs:3954`, `pub(crate)`):
//!   short-lived registry handle, dropped after one CAS or load; plus
//!   `RedbInstallationRegistry::load`
//!   (`crates/kernel/eliot-installation/src/redb_state.rs:275`, inside
//!   `impl super::RedbInstallationRegistry` at line 171),
//!   `ApprovedGenerationRegistry::{validate, active_generation, generations,
//!   revision}` (`approved_generation_registry.rs:4105,3656,3650,2775`), and
//!   the new cutover CAS `RedbInstallationRegistry::commit_cutover_activation`
//!   (`installation_registry.rs`, beside `commit_pending_activation` at
//!   line 951): same-closure `mutate_atomic` onto the existing
//!   `ApprovedGenerationRegistry::activate` (`approved_generation_registry.
//!   rs:3953`, approved-target check, exact-replay `Ok`, predecessor-gated
//!   flip recording the prior generation as last-known-good). No schema or
//!   wire change, no new persisted fields: the operation audit binding lives
//!   in the Host journal retirement record.
//! - `HostOwnerLease::activation_capability` through
//!   `HostComposition::owner_lease` (host `lib.rs:3724`, used by every owner
//!   contour): live-guard capability for the CAS.
//! - `super::journal_append::append_reconciled` (host `journal_append.rs:281`,
//!   `pub(super)` choke for every `ProductionHostStateJournal` write, with
//!   `OutcomeUnknown` fail-closed reconciliation): persists the
//!   `HostStateRecord::EpochRetirement(EpochRetirementRecord)`
//!   (`eliot-host-state/src/model.rs:1667,1493`) carrying the cutover
//!   operation identity, barrier-bound fence, and bounded evidence refs, and
//!   returns the real `AppendReceipt`
//!   (`eliot-host-state/src/journal.rs:41`, `sequence()`/`disposition()`/
//!   `transaction_id()`). Intent is bound inside this record before any
//!   route/SCM effect; this path performs no process/SCM effects itself.
//!   Record helpers `super::{record_fence, fresh_identity}` (host `lib.rs`
//!   :3568,:3444, private in the root, visible here) build owner-shaped
//!   values only.
//! - Prior-generation process/SCM retirement effects run through the existing
//!   drain/stop contours (`HostComposition::stop`, host `lib.rs:7159;
//!   `drain_commit_record_for_stop`, `journal_append.rs:451;
//!   `scm_launch::{validate_host_scm_bootstrap,
//!   classify_host_scm_inspection}`, `scm_launch.rs:430,262) driven by the
//!   committed retirement record. `scm_launch` owns no stop/deregister API on
//!   current main, so this module claims no SCM effect it cannot call.
//!
//! Normative anchors: A12.3 one governed write path; A13.7 separate cutover
//! authority, old authority never revives; I5.13 isolated restore, new
//! lineage, pre-cutover state retained; I5.16 durable fields; I5.27
//! operation vs effect identity and `IDENTITY_CONFLICT`; I14.21 unknown
//! commit; I14.24 failed verification forbids cutover; I7.20 dispositions;
//! I1.5 activation/drain generations never overlap; I14.14 cutover record
//! owns the linearization point (here: the journal append receipt).

use eliot_backup::{BackupClass, OperationalValidationEvidence, RestoreReceipt};
use eliot_contracts::{fences_match_exact, StateFence};
use eliot_host_state::{
    AppendReceipt, EpochRetirementRecord, EpochTransition, HostInstallationEpoch, HostStateRecord,
    IdempotencyIdentity, RecordFence,
};
use eliot_installation::ApprovedGenerationRegistry;
use eliot_ors::{CapabilityIntroductionProjection, OperationalPhase};
use eliot_platform::PlatformHandle;
use eliot_protocol::{
    host_request_operation_id, HostRequestAdmissionReceipt, HostRequestEnvelope, HostRequestKind,
};

// Stubless consumption of the Parfit-owned (#1751) retirement barrier. These
// items do not exist yet; root serializes their definition with Parfit's
// `lease_drain.rs` + `lib.rs` change. This module defines no local duplicate.
use super::{GenerationRetirementBarrier, GenerationRetirementFence, HostComposition, HostError};

/// Maximum bounded evidence references carried on any cutover outcome or
/// journaled retirement record. Digests only; never plaintext keys, paths,
/// or credentials. The journal owner additionally rejects duplicates.
pub const CUTOVER_EVIDENCE_BOUND: usize = 16;

/// Canonical operation identity for one cutover (I5.27).
///
/// Database idempotency (this identity, bound into the journaled retirement
/// record) and external-effect idempotency (SCM/launch effects owned by the
/// drain/stop contours) remain separate: a committed intent never proves an
/// effect occurred exactly once.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CutoverOperationIdentity {
    pub installation: PlatformHandle,
    pub operation_id: PlatformHandle,
    pub request_digest: PlatformHandle,
}

/// Exact separately-authorized cutover request.
///
/// `envelope` + `admission` are the real #954-adjacent role-bound command
/// and its Kernel-issued admission receipt: the receipt proves only that the
/// Kernel admission gate accepted the exact envelope digest for routing (it
/// creates no Session, task, or result). A successful restore rehearsal,
/// checksum, zero unresolved count, or client declaration is not cutover
/// authority and appears nowhere here as admission.
#[derive(Clone, Debug)]
pub struct CutoverRequest {
    pub operation: CutoverOperationIdentity,
    /// Exact admitted command envelope (real owner type).
    pub envelope: HostRequestEnvelope,
    /// Kernel-issued admission receipt for exactly `envelope` (real owner
    /// type; validated with its own `validate()`).
    pub admission: HostRequestAdmissionReceipt,
    pub source_installation: PlatformHandle,
    pub destination_installation: PlatformHandle,
    pub archive_digest: PlatformHandle,
    /// Real archive class from the backup owner (`eliot_backup::BackupClass`,
    /// `crates/storage/eliot-backup/src/lib.rs:122`). Gates run through its
    /// real methods (`is_full_recovery`, `is_canonical_only`,
    /// `evidence_level`); no parallel vocabulary lives here.
    pub archive_class: BackupClass,
    /// Explicit degraded-installation policy reference; required when the
    /// archive is canonical-only. Degraded recovery keeps this policy and
    /// can never silently claim `FullRecovery`.
    pub archive_canonical_only_policy: Option<PlatformHandle>,
    pub target_build_digest: PlatformHandle,
    pub target_config_digest: PlatformHandle,
    /// Exact approved target generation to activate. It must already be
    /// approved in the registry projection (staged by the
    /// installer/preparation flow); cutover never approves a generation.
    pub target_generation: PlatformHandle,
    /// Owner-issued new authority fence for the destination generation.
    pub activation_fence: StateFence,
    /// Owner-issued UserBroker identity for the destination generation.
    pub user_broker_ref: PlatformHandle,
    /// Exact active predecessor generation expected at commit time.
    pub expected_predecessor: PlatformHandle,
}

/// Current recovery evidence consumed from the actual owners (#960 shape).
///
/// Every denominator is complete-current: partial/unknown ORS/spool/effect
/// denominators block cutover. The typed `RestoreReceipt` (from
/// `RestorePlan::execute_with_journal` / `RestoreTarget::finalize_isolated`,
/// which performs no cutover) and the typed owner-issued
/// `OperationalValidationEvidence` carry the recovery proof: per
/// `RestoreEvidenceLevel::permits_operational_readiness`, no
/// library-emitted level alone qualifies, so both values are required.
/// Lease quiescence is proven separately by the barrier, never by a local
/// flag: there is no live-lease boolean here by design.
#[derive(Clone, Debug)]
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
    /// Fresh destination readiness observed.
    pub destination_ready: bool,
    /// Real isolated-restore receipt from `RestorePlan::execute_with_journal`
    /// / `RestoreTarget::finalize_isolated` (`eliot_backup`, lib.rs:2612; "It
    /// is not a cutover receipt"). Gates run through its real `validate()`,
    /// bundle/fence/level bindings, and `cutover_performed == false`.
    pub restore_receipt: RestoreReceipt,
    /// Real owner-issued operational-validation evidence (`eliot_backup`,
    /// lib.rs:2102; only the named owner may issue it, only for the exact
    /// isolated destination). Gates run through its real `validate()` and
    /// the observed-fence binding.
    pub operational_validation: OperationalValidationEvidence,
    /// Real ORS introduction readback rows for every prior capability
    /// introduction (`eliot_ors::CapabilityIntroductionProjection`,
    /// `model.rs:2043` on current main past #2388; empty when the restored
    /// generation carries no prior introductions). Every row must read
    /// `OperationalPhase::Fenced`: a fenced introduction can never read as
    /// usable again, while any `Active` row blocks cutover. Readback
    /// completeness is the admitted contour's obligation; lease quiescence
    /// is independently proven by the barrier, whose ORS enumeration is
    /// Parfit's (#1751) domain.
    pub fenced_introductions: Vec<CapabilityIntroductionProjection>,
    /// Degraded recovery under its explicit stricter policy, if set.
    pub degraded_policy: Option<PlatformHandle>,
}

/// Validated cutover: all fail-closed gates passed, ready for the
/// barrier-gated durable path.
#[derive(Clone, Debug)]
pub struct ValidatedCutover {
    pub request: CutoverRequest,
    pub evidence: IsolatedRecoveryEvidence,
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
    #[error("cutover admission is not separately authorized: {0}")]
    NotSeparatelyAdmitted(String),
    #[error("restore-test/rehearsal envelope cannot invoke cutover")]
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
    #[error("owner-issued new authority, explicit retirement authorization, or destination readiness required")]
    AuthorityOrReadinessMissing,
    #[error("expected-predecessor conflict; neither installation changed")]
    ExpectedPredecessorConflict,
    #[error("operation identity conflict: reused key with different request hash")]
    IdentityConflict,
    #[error("retirement barrier denied: {0}")]
    BarrierDenied(String),
    #[error("owner recovery receipt rejected: {0}")]
    InvalidRecoveryReceipt(String),
    #[error("host owner transition failed: {0}")]
    HostTransition(#[from] HostError),
    #[error("installation registry rejected cutover evidence: {0}")]
    Registry(String),
}

/// Bounds and dedupes evidence references for owner records, which reject
/// empty and duplicate handle sets.
fn bounded_evidence(refs: Vec<PlatformHandle>) -> Vec<PlatformHandle> {
    let mut seen = Vec::with_capacity(CUTOVER_EVIDENCE_BOUND);
    for item in refs.into_iter().take(CUTOVER_EVIDENCE_BOUND) {
        if !seen.contains(&item) {
            seen.push(item);
        }
    }
    seen
}

fn admission_handle(
    admission: &HostRequestAdmissionReceipt,
) -> Result<PlatformHandle, CutoverError> {
    PlatformHandle::new(admission.operation_id.clone()).map_err(|_| CutoverError::BindingMismatch)
}

/// Projects one owner receipt digest field into the bounded evidence set.
/// The digest was already validated by its owner (`RestoreReceipt::validate`
/// / `OperationalValidationEvidence::validate` during admission); this only
/// carries the exact field into journaled evidence refs.
fn receipt_handle(digest: &str) -> Result<PlatformHandle, CutoverError> {
    PlatformHandle::new(digest).map_err(|_| CutoverError::BindingMismatch)
}

/// Validates one exact cutover request against current owner evidence.
///
/// Real owner calls: `envelope.validate()`, `admission.validate()`, the
/// digest binding through `host_request_operation_id` (a rehearsal envelope
/// derives a different `hostreq:` handle and fails here, never as cutover),
/// `RestoreReceipt::validate` (which itself rejects `cutover_performed`
/// with `CutoverNotAuthorized`), `OperationalValidationEvidence::validate`,
/// and the class ceiling through `BackupClass::evidence_level`.
/// Fail-closed gates: separately admitted `Invocation` envelope whose fence
/// exactly matches the activation fence; bindings exact, including the
/// receipt's bundle digest, restored fence, and class ceiling against the
/// request; scope transfers rejected; degraded policy explicit, never
/// upgraded; every mandatory phase receipt current; complete denominators;
/// fresh purge/key/reference plus external-source revalidation; every prior
/// introduction row fenced (lease quiescence proven separately by the
/// barrier); observed operational-validation fence exact; expected
/// predecessor and approved target match the registry projection.
///
/// # Errors
///
/// Returns the exact failing gate. Nothing is activated here.
pub fn validate_cutover_request(
    request: &CutoverRequest,
    evidence: &IsolatedRecoveryEvidence,
    registry: &ApprovedGenerationRegistry,
) -> Result<ValidatedCutover, CutoverError> {
    request
        .envelope
        .validate()
        .map_err(|error| CutoverError::NotSeparatelyAdmitted(error.to_string()))?;
    request
        .admission
        .validate()
        .map_err(|error| CutoverError::NotSeparatelyAdmitted(error.to_string()))?;
    if request.envelope.kind != HostRequestKind::Invocation {
        return Err(CutoverError::NotSeparatelyAdmitted(
            "cutover requires an Invocation-kind admitted envelope".to_owned(),
        ));
    }
    if request.admission.kind != request.envelope.kind {
        return Err(CutoverError::BindingMismatch);
    }
    if request.admission.request_sha256 != request.envelope.envelope_sha256 {
        return Err(CutoverError::BindingMismatch);
    }
    let expected_operation = host_request_operation_id(&request.envelope);
    if request.admission.operation_id != expected_operation {
        // A restore-test/rehearsal envelope (or any changed envelope)
        // derives a different digest-bound handle: it can never present
        // this cutover admission.
        return Err(CutoverError::RehearsalCannotCutover);
    }
    if !fences_match_exact(&request.envelope.state_fence, &request.activation_fence) {
        return Err(CutoverError::BindingMismatch);
    }
    if request.archive_class == BackupClass::ScopeExport {
        return Err(CutoverError::ScopeExportForbidden);
    }
    if request.archive_class.is_canonical_only() && request.archive_canonical_only_policy.is_none()
    {
        return Err(CutoverError::DegradedPolicyViolation);
    }
    evidence
        .restore_receipt
        .validate()
        .map_err(|error| CutoverError::InvalidRecoveryReceipt(error.to_string()))?;
    if evidence.restore_receipt.cutover_performed {
        // The owner forbids this too (`CutoverNotAuthorized` inside
        // `validate`); the distinct disposition names the rehearsal
        // exclusion at the cutover boundary.
        return Err(CutoverError::RehearsalCannotCutover);
    }
    if evidence.restore_receipt.bundle_sha256 != request.archive_digest.as_str() {
        return Err(CutoverError::BindingMismatch);
    }
    if evidence.restore_receipt.canonical_only != request.archive_class.is_canonical_only() {
        return Err(CutoverError::BindingMismatch);
    }
    if evidence.restore_receipt.evidence_level != request.archive_class.evidence_level() {
        return Err(CutoverError::BindingMismatch);
    }
    if evidence.restore_receipt.restored_fence.authority_epoch
        != request.activation_fence.authority_epoch
        || evidence.restore_receipt.restored_fence.resource_generation
            != request.activation_fence.resource_generation
    {
        return Err(CutoverError::BindingMismatch);
    }
    evidence
        .operational_validation
        .validate()
        .map_err(|error| CutoverError::InvalidRecoveryReceipt(error.to_string()))?;
    if !fences_match_exact(
        &evidence.operational_validation.observed_at_state_fence,
        &request.activation_fence,
    ) {
        return Err(CutoverError::BindingMismatch);
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
    if evidence.unresolved_effects.is_none() {
        return Err(CutoverError::PartialDenominator);
    }
    if !evidence.canonical_denominator_complete
        || !evidence.ors_denominator_complete
        || !evidence.spool_denominator_complete
    {
        return Err(CutoverError::PartialDenominator);
    }
    if !evidence.purge_key_reference_fresh || !evidence.external_source_revalidated {
        return Err(CutoverError::StalePurgeKeyReference);
    }
    if !evidence
        .fenced_introductions
        .iter()
        .all(|introduction| introduction.phase() == OperationalPhase::Fenced)
    {
        return Err(CutoverError::PriorAuthorityStillActive);
    }
    if !evidence.destination_ready {
        return Err(CutoverError::AuthorityOrReadinessMissing);
    }
    registry
        .validate()
        .map_err(|error| CutoverError::Registry(error.to_string()))?;
    if request.target_generation == request.expected_predecessor {
        return Err(CutoverError::BindingMismatch);
    }
    if !registry
        .generations()
        .iter()
        .any(|item| item.manifest.generation == request.target_generation)
    {
        return Err(CutoverError::Registry(
            "cutover target generation is not approved".to_owned(),
        ));
    }
    match registry.active_generation() {
        Some(active) if *active == request.expected_predecessor => {}
        Some(_) | None => return Err(CutoverError::ExpectedPredecessorConflict),
    }
    Ok(ValidatedCutover {
        request: request.clone(),
        evidence: evidence.clone(),
    })
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
/// Real owner calls, in order: `HostComposition::ensure_admission_open`;
/// fresh registry readback through `super::open_registry_store_at` plus
/// `RedbInstallationRegistry::load` with the expected-predecessor and
/// target-approval rechecks (TOCTOU fence: the cached projection check in
/// validation is not enough); exact barrier-fence bindings; then the
/// Parfit-owned `HostComposition::require_generation_retirement_barrier`,
/// which succeeds only on current Kernel/ORS readback proving NO active
/// RuntimeLease/SupervisionLease for the prior generation plus the current
/// durable drain/commit; finally the activation linearization point
/// `RedbInstallationRegistry::commit_cutover_activation` (same-closure CAS
/// through `mutate_atomic` onto the existing `ApprovedGenerationRegistry::
/// activate`, expected revision + predecessor fenced, exact replay safe).
/// The handle is dropped immediately after the CAS, never retained.
///
/// Lost response, failure between registry/authority/route transitions, or
/// cancellation after possible activation yields `Unknown` on reconcile:
/// re-read the same operation and actual owner receipts before retry; do not
/// activate again, roll back blindly, or mark both sides active/inactive
/// from local assumptions.
///
/// # Errors
///
/// Returns `BarrierDenied` when the prior generation still carries leases or
/// the durable drain/commit disagrees; `Registry` on CAS conflict or an
/// unapproved target; `Unknown`-class host failures propagate as
/// `HostTransition` for fenced reconciliation.
pub fn execute_cutover(
    host: &mut HostComposition,
    validated: &ValidatedCutover,
    retirement: &GenerationRetirementFence,
    activation_id: &PlatformHandle,
    activation_generation: &EpochTransition,
) -> Result<(CutoverOutcome, GenerationRetirementBarrier), CutoverError> {
    host.ensure_admission_open()?;
    let store = super::open_registry_store_at(&host.registry_host_root)?;
    let fresh = store
        .load()
        .map_err(|error| CutoverError::Registry(error.to_string()))?;
    fresh
        .validate()
        .map_err(|error| CutoverError::Registry(error.to_string()))?;
    if !fresh
        .generations()
        .iter()
        .any(|item| item.manifest.generation == validated.request.target_generation)
    {
        return Err(CutoverError::Registry(
            "cutover target generation is not approved".to_owned(),
        ));
    }
    match fresh.active_generation() {
        Some(active) if *active == validated.request.expected_predecessor => {}
        Some(_) | None => return Err(CutoverError::ExpectedPredecessorConflict),
    }
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
    let capability = host.owner_lease.activation_capability();
    store
        .commit_cutover_activation(
            &capability,
            fresh.revision(),
            &validated.request.expected_predecessor,
            &validated.request.target_generation,
        )
        .map_err(|error| CutoverError::Registry(error.to_string()))?;
    drop(store);
    Ok((
        CutoverOutcome {
            disposition: CutoverDisposition::Committed,
            operation: validated.request.operation.clone(),
            evidence_refs: bounded_evidence(vec![
                admission_handle(&validated.request.admission)?,
                activation_id.clone(),
                validated.request.target_generation.clone(),
            ]),
        },
        barrier,
    ))
}

/// Retires the prior generation holding the real barrier proof.
///
/// Real owner calls: `HostComposition::ensure_admission_open`, then the
/// journal-owner write `super::journal_append::append_reconciled` persisting
/// `HostStateRecord::EpochRetirement` with the cutover operation identity,
/// the barrier-bound fence, and bounded evidence refs. The barrier type has
/// private owner construction, so only the real Kernel/ORS readback path can
/// produce it: no proxy receipt, no Kernel rehearsal, no refs-only census
/// passes here. The returned `AppendReceipt` is the durable linearization
/// receipt for this retirement; prior-generation process/SCM retirement
/// effects then run through the existing drain/stop contours driven by the
/// committed record.
///
/// Requires: the exact new state already committed and accepted, all source
/// drain/retirement decisions explicitly authorized
/// (`retirement_authorization` is bound into the record; empty values are
/// rejected, never defaulted), the prior epoch from the same installation,
/// and a live barrier. The source installation is retained until accepted
/// authorized retirement; source data destruction is a separate explicitly
/// authorized retention/erasure action, never automatic cleanup here.
///
/// # Errors
///
/// Fails closed on authorization, prior-epoch binding, or journal outcome;
/// `OutcomeUnknown` reconciles through the choke and never forges success.
pub fn retire_prior_generation(
    host: &HostComposition,
    validated: &ValidatedCutover,
    retirement: &GenerationRetirementFence,
    _barrier: &GenerationRetirementBarrier,
    prior_host: &HostInstallationEpoch,
    retirement_authorization: &PlatformHandle,
) -> Result<CutoverOutcome, CutoverError> {
    host.ensure_admission_open()?;
    if retirement_authorization.as_str().trim().is_empty() {
        return Err(CutoverError::AuthorityOrReadinessMissing);
    }
    if prior_host.installation != host.host.installation {
        return Err(CutoverError::BindingMismatch);
    }
    if prior_host.epoch == host.host.epoch {
        return Err(CutoverError::BindingMismatch);
    }
    let operation = IdempotencyIdentity {
        operation_id: validated.request.operation.operation_id.clone(),
        idempotency_key: validated.request.operation.request_digest.clone(),
    };
    // Deterministic per cutover operation and prior epoch: the journal
    // transaction id binds operation identity, Host epoch, and the full
    // record checksum (`journal.rs:126-145`), so a retry after
    // `OutcomeUnknown` must append byte-identical record bytes to replay
    // (`Replayed`) instead of duplicating the retirement. A fresh random
    // identity here would fork a second transaction on every retry.
    let retired_digest = super::sha256_json(&(
        "cutover-retired-at-v1",
        &validated.request.operation.operation_id,
        &validated.request.operation.request_digest,
        &prior_host.installation,
        &prior_host.epoch,
    ))?;
    let retired_at = PlatformHandle::new(format!("cutover-retired-at:{retired_digest}"))
        .map_err(|_| CutoverError::BindingMismatch)?;
    let record = HostStateRecord::EpochRetirement(EpochRetirementRecord {
        // Full fence shape comes straight from the barrier-bound fence
        // already checked in `execute_cutover` (same installation
        // activation id + generation the barrier was issued for). The
        // journal reducer runs the complete owner `validate()` on append,
        // including `HostInstallationEpoch::validate`, which this crate
        // cannot call directly (`pub(crate)` in `eliot-host-state`).
        fence: RecordFence {
            host: host.host.clone(),
            activation_id: retirement.activation_id.clone(),
            activation_generation: retirement.activation_generation.clone(),
        },
        operation,
        retired_host: prior_host.clone(),
        retirement_evidence_refs: bounded_evidence(vec![
            admission_handle(&validated.request.admission)?,
            validated.request.archive_digest.clone(),
            receipt_handle(&validated.evidence.restore_receipt.receipt_id)?,
            receipt_handle(&validated.evidence.restore_receipt.effect_receipt_sha256)?,
            receipt_handle(&validated.evidence.operational_validation.validation_digest)?,
            retirement_authorization.clone(),
        ]),
        retired_at,
    });
    let receipt = super::journal_append::append_reconciled(&host.journal, record)?;
    Ok(CutoverOutcome {
        disposition: CutoverDisposition::Reconciled,
        operation: validated.request.operation.clone(),
        evidence_refs: bounded_evidence(vec![
            receipt.transaction_id().clone(),
            admission_handle(&validated.request.admission)?,
            retirement_authorization.clone(),
        ]),
    })
}

/// Reconciles a cutover from real owner observations after lost response or
/// cancellation.
///
/// `registry_active` is the active generation freshly read back from the
/// registry owner (`RedbInstallationRegistry::load().active_generation()`)
/// and `retirement_receipt` is the actual `AppendReceipt` read back from
/// the journal owner for the cutover operation identity (`None` when no
/// such receipt exists); never locally assumed booleans. A present receipt
/// proves the durable retirement commit; a registry flip without a receipt
/// proves the activation commit with retirement still pending; anything
/// else stays `Unknown` for evidence-backed retry under the same identity.
/// Cancellation/cleanup/diagnostic failure preserves the primary result and
/// its reconciliation path.
#[must_use]
pub fn reconcile_cutover_outcome(
    operation: &CutoverOperationIdentity,
    registry_active: Option<&PlatformHandle>,
    target_generation: &PlatformHandle,
    retirement_receipt: Option<&AppendReceipt>,
) -> CutoverOutcome {
    if let Some(receipt) = retirement_receipt {
        return CutoverOutcome {
            disposition: CutoverDisposition::Reconciled,
            operation: operation.clone(),
            evidence_refs: vec![receipt.transaction_id().clone()],
        };
    }
    if registry_active == Some(target_generation) {
        return CutoverOutcome {
            disposition: CutoverDisposition::Committed,
            operation: operation.clone(),
            evidence_refs: vec![target_generation.clone()],
        };
    }
    CutoverOutcome {
        disposition: CutoverDisposition::Unknown,
        operation: operation.clone(),
        evidence_refs: Vec::new(),
    }
}
