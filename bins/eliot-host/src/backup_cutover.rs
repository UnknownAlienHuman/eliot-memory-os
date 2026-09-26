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
//!   and deliberately NOT duplicated here. LANDED in Parfit's branch
//!   (`codex/finish-windows1751-20260922` @ `552ee79a`,
//!   `bins/eliot-host/src/lease_drain.rs:12-73`: fence with pub
//!   `activation_id`/`activation_generation`/`state_fence`; barrier with
//!   private fields plus pub read accessors `fence()`,
//!   `drain_commit_operation()`, `runtime_lease_census()`,
//!   `kernel_process_id()`, `kernel_process_start_time_100ns()`; `pub fn`
//!   on `HostComposition` taking `&mut self`; registered as
//!   `#[cfg(windows)] mod lease_drain;` +
//!   `#[cfg(windows)] pub use lease_drain::{GenerationRetirementBarrier,
//!   GenerationRetirementFence};`). Remaining here: root serialization +
//!   registration, then this module compiles wired. The fence binds
//!   `activation_id: PlatformHandle` (`eliot_platform`, as in host `lib.rs`
//!   line 214), `activation_generation: EpochTransition` (`eliot_host_state`
//!   re-export of `eliot_contracts`, `epoch_identity.rs:211`), and
//!   `state_fence: StateFence` (`eliot_contracts`). Retirement reads the
//!   issued fence through `barrier.fence()`; the barrier is otherwise held
//!   opaquely and never destructured.
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

use eliot_backup::{
    BackupClass, OperationalValidationEvidence, ReconciliationDenominator, RestoreReceipt,
};
use eliot_contracts::{StateFence, fences_match_exact};
use eliot_host_state::{
    AppendReceipt, CutoverIntentRecord, CutoverIntentState, EpochRetirementRecord, EpochTransition,
    HostInstallationEpoch, HostStateRecord, IdempotencyIdentity, RecordFence,
};
use eliot_installation::{ApprovedGeneration, ApprovedGenerationRegistry, CandidateManifest};
use eliot_ors::{CapabilityIntroductionProjection, OperationalPhase};
use eliot_platform::PlatformHandle;
use eliot_protocol::{
    HostRequestAdmissionReceipt, HostRequestEnvelope, HostRequestKind, host_request_operation_id,
};
use eliot_store_api::{WriteReceipt, WriteReceiptStatus};
use serde::Deserialize;

// Stubless consumption of the Parfit-owned (#1751) retirement barrier,
// landed in Parfit's branch (see module docs); root serializes the
// definition + registration. This module defines no local duplicate.
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
#[derive(Clone, Debug, Eq, PartialEq, Deserialize)]
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
///
/// `Deserialize` (M2 integration) lets the admitted-cutover console
/// envelope carry the exact typed request; every field is re-validated by
/// owner calls in `validate_cutover_request`, so transport shape grants
/// nothing by itself.
#[derive(Clone, Debug, Deserialize)]
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
    /// Owner-issued `UserBroker` identity for the destination generation.
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
///
/// `Deserialize` (M2 integration) mirrors the request: transport only, all
/// gates re-checked by owner calls.
#[allow(
    clippy::struct_excessive_bools,
    reason = "the #960 owner evidence denominator is a flat set of independent current-completeness facts; grouping them would hide a required gate"
)]
#[derive(Clone, Debug, Deserialize)]
pub struct IsolatedRecoveryEvidence {
    /// All mandatory recovery phases completed with current receipts.
    pub mandatory_phases_complete: bool,
    /// Exact current unresolved-effect disposition, as the complete current
    /// owner-issued reconciliation denominator
    /// (`eliot_backup::ReconciliationDenominator`, `lib.rs:2164`).
    ///
    /// A bare count is not a disposition: the denominator names its issuing
    /// owner and its denominator reference, names every reconciled item in
    /// `reconciled_refs`, and its own `validate()` refuses a count that does not
    /// equal the named items, so no presented value can be an arbitrary number
    /// and `is_known_zero()` requires a genuinely empty current denominator.
    /// `None` means the denominator is unknown, which blocks cutover exactly
    /// like a non-zero count: suspension is not resolution.
    ///
    /// Provenance, stated precisely: like the other owner receipts in this
    /// bundle (`RestoreReceipt`, `OperationalValidationEvidence`,
    /// `coordination_receipt`), the *shape* is owner-issued and structurally
    /// re-validated here, while authority comes from the separately admitted
    /// command envelope and the live owner readbacks in `execute_cutover` — not
    /// from the field alone. This gate therefore removes the arbitrary-count
    /// hole; it does not by itself prove an issuer.
    pub unresolved_effect_denominator: Option<ReconciliationDenominator>,
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
    /// usable again, while any `Active` row blocks cutover. Shape alone
    /// never suffices: the coordination receipt below proves these rows
    /// passed the journal-owner live readback gate at restore time.
    pub fenced_introductions: Vec<CapabilityIntroductionProjection>,
    /// Committed Governor coordination receipt for this restore (F-AUR-1).
    ///
    /// The bridge-issued receipt for the coordination row keyed by the
    /// restore operation identity. Coordination rows commit only through
    /// the gated restore dispatch, which live-verifies every presented
    /// introduction against owner/ORS readback before any effect — so a
    /// structurally valid receipt bound to this restore proves its
    /// introductions passed the live gate. Only the canonical store bridge
    /// can mint such a receipt; console bytes alone never suffice.
    pub coordination_receipt: WriteReceipt,
    /// Restore operation identity keying the coordination row (must equal
    /// both the request operation identity and the receipt's operation).
    pub coordination_row_key: String,
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
    #[error(
        "owner-issued new authority, explicit retirement authorization, or destination readiness required"
    )]
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

// F-LOG-HOST-8 (#983) backup cutover diagnostics: observation-only helpers.
//
// Through the #889 facade's target and bounded-field helpers only, on the
// existing subscriber; the Event Log seam stays typed-Unavailable (never
// implemented here, #984 still open). `EntrypointStage` describes process
// startup/shutdown, not backup phases, so these observations carry local event
// names and never reuse that enum.
//
// Observation-only contract: every helper projects facts already produced by
// the semantic owner. Arguments are static tokens, owner disposition tokens,
// or counts; never operation/installation/archive/build/fence strings,
// digests, reasons, receipts, or arbitrary error `Debug`/`Display` (a canary
// stays absent even inside an alleged identity string). Truncation bounds
// size, never sensitivity. Macro arguments are precomputed pure values; sink
// outcome never alters call counts, order, results, receipts, rollback, or
// cleanup, and stdout framing is untouched (facade stderr subscriber). No
// owner reads, effects, hashing, retries, or mutation are added for logging.
// Requested/validated/prepared/committed/reconciled/retirement-pending/
// failed/unknown stay exactly the owner-observed dispositions: rehearsal
// never emits success, ambiguity stays unknown, and retirement-pending never
// implies erasure.
//
// Terminal ownership (W4): the leaf emits nonterminal phase/refusal evidence
// only, with no dedup cache. The single terminal record per failed operation
// belongs to the outer caller boundary, which owns the one
// `observe_terminal_error` call. Handoff (caller-owned, not applied here):
// `backup_dispatch_cutover` / `backup_dispatch_cutover_disposition` /
// `backup_dispatch_cutover_retire` arm one terminal guard each with a frozen
// `host-backup-cutover-failed` code; operation failure stays distinct from
// any process shutdown failure.
//
// Explicit no-event list: `is_exact_replay`/`check_replay_identity` (pure
// predicates; the observed replay is recorded at the committed-intent return
// in `execute_cutover`, never as a second effect),
// `bind_approved_target`/`read_and_verify_prior_authority`/
// `commit_with_durable_intent`/`append_cutover_intent`/`bounded_evidence`/
// `admission_handle`/`receipt_handle`/`owner_approved_build_digests`/
// `cutover_intent_state_spelling` (private steps whose outcome surfaces with
// its exact category at the validate/execute/retire boundary).

/// Notes the facade's actual Event Log seam status (typed-unavailable).
fn backup_cutover_note_event_log_unavailable() {
    let _ = crate::windows_event_log::event_log_sink_status();
}

/// Counts bounded collections as a log-safe `u64` without truncation casts.
fn backup_cutover_count(len: usize) -> u64 {
    u64::try_from(len).unwrap_or(u64::MAX)
}

/// Projects one [`CutoverError`] to its stable diagnostic category. Pure and
/// exhaustive; carries no payloads, digests, or owner error text.
#[must_use]
fn cutover_error_category(error: &CutoverError) -> &'static str {
    match error {
        CutoverError::NotSeparatelyAdmitted(_) => "not_separately_admitted",
        CutoverError::RehearsalCannotCutover => "rehearsal_cannot_cutover",
        CutoverError::BindingMismatch => "binding_mismatch",
        CutoverError::ScopeExportForbidden => "scope_export_forbidden",
        CutoverError::DegradedPolicyViolation => "degraded_policy_violation",
        CutoverError::MissingPhaseReceipt => "missing_phase_receipt",
        CutoverError::PartialDenominator => "partial_denominator",
        CutoverError::StalePurgeKeyReference => "stale_purge_key_reference",
        CutoverError::PriorAuthorityStillActive => "prior_authority_still_active",
        CutoverError::AuthorityOrReadinessMissing => "authority_or_readiness_missing",
        CutoverError::ExpectedPredecessorConflict => "expected_predecessor_conflict",
        CutoverError::IdentityConflict => "identity_conflict",
        CutoverError::BarrierDenied(_) => "barrier_denied",
        CutoverError::InvalidRecoveryReceipt(_) => "invalid_recovery_receipt",
        CutoverError::HostTransition(_) => "host_transition",
        CutoverError::Registry(_) => "registry",
    }
}

/// Projects one owner [`CutoverDisposition`] to its stable diagnostic token.
/// Pure and exhaustive; the token repeats the owner observation verbatim.
#[must_use]
fn cutover_disposition_token(disposition: CutoverDisposition) -> &'static str {
    match disposition {
        CutoverDisposition::Requested => "requested",
        CutoverDisposition::Validated => "validated",
        CutoverDisposition::Prepared => "prepared",
        CutoverDisposition::Committed => "committed",
        CutoverDisposition::Reconciled => "reconciled",
        CutoverDisposition::RetirementPending => "retirement_pending",
        CutoverDisposition::Failed => "failed",
        CutoverDisposition::Unknown => "unknown",
    }
}

/// Observes one nonterminal cutover phase outcome after the decision exists.
/// `disposition` repeats the owner-observed disposition (or `"none"` when the
/// step produces none); `evidence_count` counts refs without naming them.
fn observe_cutover_progress(
    op: &'static str,
    outcome: &'static str,
    disposition: &'static str,
    evidence_count: u64,
) {
    backup_cutover_note_event_log_unavailable();
    let op = crate::host_diagnostics::bound_field(op);
    let outcome = crate::host_diagnostics::bound_field(outcome);
    let disposition = crate::host_diagnostics::bound_field(disposition);
    tracing::info!(
        target: crate::host_diagnostics::HOST_DIAGNOSTICS_TARGET,
        event = "host.backup.cutover_phase",
        op = op.text(),
        outcome = outcome.text(),
        disposition = disposition.text(),
        evidence_count = evidence_count,
        "host backup cutover phase observed"
    );
}

/// Observes one typed cutover refusal after the decision exists, then hands
/// the unchanged error back. Terminal ownership stays with the outer caller.
fn note_cutover_error(op: &'static str, error: CutoverError) -> CutoverError {
    backup_cutover_note_event_log_unavailable();
    let category = cutover_error_category(&error);
    let op = crate::host_diagnostics::bound_field(op);
    let category = crate::host_diagnostics::bound_field(category);
    tracing::warn!(
        target: crate::host_diagnostics::HOST_DIAGNOSTICS_TARGET,
        event = "host.backup.cutover_refusal",
        op = op.text(),
        category = category.text(),
        "host backup cutover refused"
    );
    error
}

/// Observes one failed owner read behind disposition projection, then hands
/// the unchanged error back. The unowned [`HostError`] text is never logged:
/// a failed read is an error, never a disposition.
fn note_cutover_read_error(error: super::HostError) -> super::HostError {
    backup_cutover_note_event_log_unavailable();
    tracing::warn!(
        target: crate::host_diagnostics::HOST_DIAGNOSTICS_TARGET,
        event = "host.backup.cutover_refusal",
        op = "read_disposition",
        category = "owner_read_failed",
        "host backup cutover disposition read failed"
    );
    error
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

/// Returns the exact owner-approved artifact digests of one committed
/// candidate manifest, in manifest order.
///
/// This is byte-for-byte the same set as
/// `backup_config_projection::bind_approved_build`'s
/// `ApprovedBuildBinding::artifact_digests` — the installer's own definition of
/// "approved build facts", which the #958 preparation path already subset-checks
/// presented builds against. Aligning with it means the cutover accepts exactly
/// the builds preparation accepts, and no narrower or wider build vocabulary is
/// invented here.
///
/// That binding is deliberately not reused: it requires the record to be
/// `active`, while the cutover target is by definition the staged, not-yet-active
/// generation, and forging an active copy to reach it would invent installation
/// state. Reading the immutable approved manifest keeps one vocabulary and one
/// owner — the installation registry.
fn owner_approved_build_digests(manifest: &CandidateManifest) -> Vec<&PlatformHandle> {
    vec![
        &manifest.kernel_artifact_digest,
        &manifest.store_bridge_artifact_digest,
        &manifest.canonical_store_artifact_digest,
        &manifest.host_artifact_digest,
        &manifest.doctor_artifact_digest,
        &manifest.testd_artifact_digest,
        &manifest.native_worker_artifact_digest,
        &manifest.wasm_host_artifact_digest,
    ]
}

/// Resolves the exact approved target generation and checks the request's
/// approved build/config bindings against it.
///
/// `target_config_digest` must equal the committed candidate configuration
/// digest, and `target_build_digest` must be one of that manifest's
/// owner-approved artifacts. A build or config mismatch therefore refuses
/// before the barrier and before the registry CAS, exactly like the source,
/// destination, archive and fence bindings.
fn bind_approved_target<'a>(
    request: &CutoverRequest,
    registry: &'a ApprovedGenerationRegistry,
) -> Result<&'a ApprovedGeneration, CutoverError> {
    let target = registry
        .generations()
        .iter()
        .find(|item| item.manifest.generation == request.target_generation)
        .ok_or_else(|| {
            CutoverError::Registry("cutover target generation is not approved".to_owned())
        })?;
    if request.target_config_digest != target.manifest.config_digest {
        return Err(CutoverError::BindingMismatch);
    }
    if !owner_approved_build_digests(&target.manifest).contains(&&request.target_build_digest) {
        return Err(CutoverError::BindingMismatch);
    }
    Ok(target)
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
///
/// The outcome is observed once: success repeats the validated disposition,
/// and each refusal carries its exact typed category. No request, evidence,
/// or receipt string is logged.
pub fn validate_cutover_request(
    request: &CutoverRequest,
    evidence: &IsolatedRecoveryEvidence,
    registry: &ApprovedGenerationRegistry,
) -> Result<ValidatedCutover, CutoverError> {
    match validate_cutover_request_inner(request, evidence, registry) {
        Ok(validated) => {
            observe_cutover_progress(
                "validate",
                "validated",
                "validated",
                backup_cutover_count(validated.evidence.fenced_introductions.len()),
            );
            Ok(validated)
        }
        Err(error) => Err(note_cutover_error("validate", error)),
    }
}

/// Validation gate body behind the outcome observation.
#[allow(
    clippy::too_many_lines,
    reason = "the ordered fail-closed cutover gate set stays in one boundary so no admission, receipt, or registry check can be skipped between neighbors"
)]
fn validate_cutover_request_inner(
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
    // Exact current unresolved-effect disposition: the owner-issued denominator
    // must validate and must prove known-zero. An absent denominator, a
    // denominator whose named items do not match its own count, and a
    // non-zero count all refuse — a client-declared count (including a
    // declared zero) is never cutover authority (I5.13; #960 "known-zero
    // unresolved work requires a complete current denominator").
    let Some(denominator) = evidence.unresolved_effect_denominator.as_ref() else {
        return Err(CutoverError::PartialDenominator);
    };
    denominator
        .validate()
        .map_err(|error| CutoverError::InvalidRecoveryReceipt(error.to_string()))?;
    if !denominator.is_known_zero() {
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
    // F-AUR-1 cutover-side binding (enforced invariant, not relabeling):
    // the presented introductions above are shape-checked only, but the
    // coordination receipt below is sound evidence because EVERY committed
    // coordination row passes the journal-owner live readback INSIDE
    // `commit_coordination_row` (subject/fence/order/phase vs owner/ORS,
    // unconditional — no direct-commit bypass exists: the single call site
    // threads the presented list). A structurally valid, committed receipt
    // bound to this restore identity/row-key/fence therefore proves its
    // introductions passed the live gate. Only the canonical store bridge
    // can mint such a receipt; console bytes alone never suffice.
    evidence
        .coordination_receipt
        .validate()
        .map_err(|error| CutoverError::InvalidRecoveryReceipt(error.to_string()))?;
    if evidence.coordination_receipt.status != WriteReceiptStatus::Committed {
        return Err(CutoverError::BindingMismatch);
    }
    if evidence.coordination_receipt.operation_id.as_str()
        != request.operation.operation_id.as_str()
        || evidence.coordination_row_key != request.operation.operation_id.as_str()
    {
        return Err(CutoverError::BindingMismatch);
    }
    if !fences_match_exact(
        &evidence.coordination_receipt.state_fence,
        &request.activation_fence,
    ) {
        return Err(CutoverError::BindingMismatch);
    }
    if !evidence.destination_ready {
        return Err(CutoverError::AuthorityOrReadinessMissing);
    }
    // New owner-issued authority for the destination generation: the
    // `UserBroker` identity must be a real, non-degenerate handle and must
    // name neither this cutover's own generations nor its admission receipt.
    // Identity reuse across a cutover would revive retired authority under a
    // new fence, which I5.13 and A13.7 forbid outright.
    if request.user_broker_ref.as_str().trim().is_empty()
        || request.user_broker_ref == request.target_generation
        || request.user_broker_ref == request.expected_predecessor
        || request.user_broker_ref == request.operation.operation_id
        || request.user_broker_ref == request.operation.request_digest
    {
        return Err(CutoverError::AuthorityOrReadinessMissing);
    }
    registry
        .validate()
        .map_err(|error| CutoverError::Registry(error.to_string()))?;
    if request.target_generation == request.expected_predecessor {
        return Err(CutoverError::BindingMismatch);
    }
    // Exact approved build/config binding against the committed target
    // manifest. This is the only place the target generation is resolved, so
    // the build and config identities the request binds are checked against
    // the same owner record that authorizes the generation.
    bind_approved_target(request, registry)?;
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
///
/// Refusals are observed here with their exact typed category. Successes are
/// observed at the exact inner return that produced them, so an observed
/// replay stays distinct from a fresh commit.
pub fn execute_cutover(
    host: &mut HostComposition,
    validated: &ValidatedCutover,
    retirement: &GenerationRetirementFence,
    activation_id: &PlatformHandle,
    activation_generation: &EpochTransition,
) -> Result<(CutoverOutcome, GenerationRetirementBarrier), CutoverError> {
    execute_cutover_inner(
        host,
        validated,
        retirement,
        activation_id,
        activation_generation,
    )
    .map_err(|error| note_cutover_error("execute", error))
}

/// Execution body behind the refusal observation.
fn execute_cutover_inner(
    host: &mut HostComposition,
    validated: &ValidatedCutover,
    retirement: &GenerationRetirementFence,
    activation_id: &PlatformHandle,
    activation_generation: &EpochTransition,
) -> Result<(CutoverOutcome, GenerationRetirementBarrier), CutoverError> {
    host.ensure_material_admission_open_for_target(&validated.request.target_generation, false)?;
    let store = super::open_registry_store_at(&host.registry_host_root)?;
    let fresh = store
        .load()
        .map_err(|error| CutoverError::Registry(error.to_string()))?;
    fresh
        .validate()
        .map_err(|error| CutoverError::Registry(error.to_string()))?;
    // TOCTOU fence for the target approval and the approved build/config
    // bindings: the fresh owner readback, not the cached projection check, is
    // what the effect runs against. `bind_approved_target` also refuses an
    // unapproved target, so it replaces the previous inline approval probe.
    bind_approved_target(&validated.request, &fresh)?;
    match fresh.active_generation() {
        Some(active) if *active == validated.request.expected_predecessor => {}
        Some(_) | None => return Err(CutoverError::ExpectedPredecessorConflict),
    }
    // F-AUR-1 live owner readback with exact-set completeness (not shape
    // trust): reload the COMPLETE live introduction set from the canonical
    // ORS owner through the authenticated Kernel front door, then require
    // exact subject-set equality with the presented set — any omitted live
    // subject or surprise presented subject (including an unjustified empty
    // list against live rows) refuses. Scope derivation: one operational
    // store holds one installation's rows (source and destination are exact
    // different installation/store identities per #952/#961; Kernel-owned
    // ORS is per-installation per I1.2/I05.2), so full enumeration IS the
    // operation scope — no cross-installation rows can occur, and lineage
    // namespaces are deliberately not compared across the disjoint ORS
    // opaque-label / contract-UUID domains (I6.10). Per subject, in
    // row-lifecycle order: live+Fenced/presented+Fenced requires byte-exact
    // fence and order (fenced rows are immutable); live+Fenced/presented+
    // Active allows a legitimate fencing race (live order at least presented
    // order); live+Active of any presentation refuses (prior authority still
    // live); and every live row must read Fenced for cutover (no live
    // authority may survive retirement, joining the barrier-proven lease
    // quiescence and the registry CAS).
    read_and_verify_prior_authority(host, validated)?;
    // New `UserBroker` authority for the destination generation may not be an
    // identity this cutover retires. The comparison is against the *presented*
    // prior-generation set, which `read_and_verify_prior_authority` has already
    // proved exactly equal to the complete live ORS set — so a retired broker
    // identity cannot be re-presented as the new generation's authority under a
    // fresh fence (A13.7: old sessions, leases, approvals and epochs do not
    // revive). It deliberately does not consult the destination's own
    // registrations: a broker the destination legitimately owns is not retired
    // authority, and refusing it would block an honest cutover.
    if validated
        .evidence
        .fenced_introductions
        .iter()
        .any(|introduction| {
            introduction.record().subject_id.as_str() == validated.request.user_broker_ref.as_str()
        })
    {
        return Err(CutoverError::PriorAuthorityStillActive);
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
    // Exact replay guard against the durable intent, not against local state
    // (I5.27). The committed identity is rebuilt from the durable record's own
    // installation, cutover operation and canonical request digest, so the
    // comparison never takes a component from the presented request. A
    // committed intent for the same operation identity with the same request
    // digest is a safe replay of the same cutover: the activation already
    // happened exactly once. The same operation identity under a different
    // request digest is `IDENTITY_CONFLICT` and performs no transition.
    let journal = host.journal.snapshot().map_err(|error| {
        CutoverError::HostTransition(HostError::OwnerLeaseRecovery(error.to_string()))
    })?;
    if let Some(committed) = journal
        .pending_cutover
        .as_ref()
        .filter(|intent| intent.cutover_operation == validated.request.operation.operation_id)
    {
        let identity = CutoverOperationIdentity {
            installation: committed.installation.clone(),
            operation_id: committed.cutover_operation.clone(),
            request_digest: committed.request_digest.clone(),
        };
        if !is_exact_replay(&identity, &validated.request.operation) {
            return Err(CutoverError::IdentityConflict);
        }
        match committed.state {
            CutoverIntentState::Committed => {
                // Observed replay of the same committed cutover, not a second
                // activation: the durable intent already proves it happened.
                let outcome = CutoverOutcome {
                    disposition: CutoverDisposition::Committed,
                    operation: validated.request.operation.clone(),
                    evidence_refs: bounded_evidence(vec![
                        admission_handle(&validated.request.admission)?,
                        committed.target_generation.clone(),
                    ]),
                };
                observe_cutover_progress(
                    "execute",
                    "replay_observed",
                    "committed",
                    backup_cutover_count(outcome.evidence_refs.len()),
                );
                return Ok((outcome, barrier));
            }
            // A refused operation is terminal for that operation identity, and
            // the durable record is never revised. Re-running the activation
            // under the same key would contradict the journal, so a fresh
            // attempt must carry a new separately admitted operation identity
            // (I5.27).
            CutoverIntentState::Failed => {
                return Err(CutoverError::NotSeparatelyAdmitted(
                    "cutover operation is terminally refused; a new attempt requires a new \
                     separately admitted operation identity"
                        .to_owned(),
                ));
            }
            // Authorized but not applied: the same operation may still complete
            // it, which is the exact same-transaction resumption the registry
            // replay branch also accepts.
            CutoverIntentState::Pending => {}
        }
    }
    drop(journal);
    // The registry handle is deliberately released before the durable intent
    // append and the activation CAS: the Host opens the registry through a
    // short-lived lease and never retains a handle across a wait or a journal
    // fsync (A13.9). `commit_cutover_activation` re-reads the projection under
    // its own expected-revision CAS, so the revision captured here is the
    // fence, not a held lock.
    let expected_revision = fresh.revision();
    drop(store);
    let committed_outcome = commit_with_durable_intent(
        host,
        validated,
        retirement,
        expected_revision,
        activation_id,
    )?;
    observe_cutover_progress(
        "execute",
        "committed",
        "committed",
        backup_cutover_count(committed_outcome.evidence_refs.len()),
    );
    Ok((committed_outcome, barrier))
}

/// Reloads the COMPLETE live ORS introduction set and requires exact
/// prior-generation quiescence (F-AUR-1).
///
/// Live owner readback with exact-set completeness, not shape trust: the
/// canonical ORS owner is read through the authenticated Kernel front door,
/// then the live set must equal the presented set exactly — any omitted live
/// subject or surprise presented subject (including an unjustified empty list
/// against live rows) refuses. Scope derivation: one operational store holds
/// one installation's rows (source and destination are exact different
/// installation/store identities per #952/#961; Kernel-owned ORS is
/// per-installation per I1.2/I05.2), so full enumeration IS the operation
/// scope — no cross-installation rows can occur, and lineage namespaces are
/// deliberately not compared across the disjoint ORS opaque-label /
/// contract-UUID domains (I6.10). Per subject, in row-lifecycle order:
/// live+Fenced/presented+Fenced requires byte-exact fence and order (fenced
/// rows are immutable); live+Fenced/presented+Active allows a legitimate
/// fencing race (live order at least presented order); live+Active of any
/// presentation refuses; and every live row must read Fenced for cutover (no
/// live authority may survive retirement, joining the barrier-proven lease
/// quiescence and the registry CAS).
///
/// Bound discipline: the owner refuses limits above `MAX_RECOVERY_PAGE`, so
/// the query carries exactly that bound (never `u16::MAX`, which would refuse
/// every cutover unconditionally). Over-bound tables refuse explicitly via the
/// owner; silently truncated views can never verify.
fn read_and_verify_prior_authority(
    host: &HostComposition,
    validated: &ValidatedCutover,
) -> Result<Vec<eliot_kernel_service::IntroductionRow>, CutoverError> {
    let presented = &validated.evidence.fenced_introductions;
    let live = super::introduction_readback::read_live_introductions(
        host,
        &validated.request.activation_fence,
        eliot_ors::MAX_RECOVERY_PAGE,
    )
    .map_err(|_| CutoverError::AuthorityOrReadinessMissing)?;
    let mut presented_subjects: Vec<&str> = presented
        .iter()
        .map(|introduction| introduction.record().subject_id.as_str())
        .collect();
    presented_subjects.sort_unstable();
    let mut live_subjects: Vec<&str> = live.iter().map(|row| row.subject_id.as_str()).collect();
    live_subjects.sort_unstable();
    if presented_subjects != live_subjects {
        return Err(CutoverError::PriorAuthorityStillActive);
    }
    for introduction in presented {
        let subject = introduction.record().subject_id.as_str();
        let current = live
            .iter()
            .find(|row| row.subject_id == subject)
            .ok_or(CutoverError::PriorAuthorityStillActive)?;
        if current.phase != "FENCED" {
            return Err(CutoverError::PriorAuthorityStillActive);
        }
        match introduction.phase() {
            OperationalPhase::Fenced => {
                if current.fence_digest != introduction.record().state_fence.sha256
                    || current.operation_order != introduction.operation_order()
                {
                    return Err(CutoverError::PriorAuthorityStillActive);
                }
            }
            OperationalPhase::Active => {
                if current.operation_order < introduction.operation_order() {
                    return Err(CutoverError::PriorAuthorityStillActive);
                }
            }
            _ => return Err(CutoverError::PriorAuthorityStillActive),
        }
    }
    Ok(live)
}

/// Persists the cutover intent, runs the activation linearization point, and
/// persists the terminal disposition — in that order.
///
/// The `Pending` record is durable before the registry CAS, so an activation
/// can never exist without the intent that authorized it; the `Committed` or
/// `Failed` record is durable after it, so reconciliation never has to infer
/// the outcome from local state.
fn commit_with_durable_intent(
    host: &mut HostComposition,
    validated: &ValidatedCutover,
    retirement: &GenerationRetirementFence,
    expected_revision: u64,
    activation_id: &PlatformHandle,
) -> Result<CutoverOutcome, CutoverError> {
    let intent = append_cutover_intent(
        host,
        validated,
        retirement,
        CutoverIntentState::Pending,
        &validated.request.admission,
    )?;
    // The registry owner is re-opened here, after the durable intent, so the
    // handle is held only across the single bounded CAS.
    let store = host.open_registry_store()?;
    let capability = host.owner_lease.activation_capability();
    let committed = store.commit_cutover_activation(
        &capability,
        expected_revision,
        &validated.request.expected_predecessor,
        &validated.request.target_generation,
    );
    drop(store);
    let refusal = committed.as_ref().err().map(ToString::to_string);
    let terminal = if refusal.is_some() {
        CutoverIntentState::Failed
    } else {
        CutoverIntentState::Committed
    };
    // The terminal record is a separate journal mutation, so a registry
    // refusal cannot destroy the primary error: the registry reason is
    // returned even when the terminal append itself fails, and the append
    // failure is reported only when the registry accepted.
    let terminal_receipt = append_cutover_intent(
        host,
        validated,
        retirement,
        terminal,
        &validated.request.admission,
    );
    if let Some(refusal) = refusal {
        return Err(CutoverError::Registry(refusal));
    }
    terminal_receipt?;
    Ok(CutoverOutcome {
        disposition: CutoverDisposition::Committed,
        operation: validated.request.operation.clone(),
        evidence_refs: bounded_evidence(vec![
            admission_handle(&validated.request.admission)?,
            activation_id.clone(),
            validated.request.target_generation.clone(),
            intent,
        ]),
    })
}

/// Reads the exact cutover disposition for one operation from the real owners.
///
/// This is the implementation behind
/// [`crate::HostComposition::backup_dispatch_cutover_disposition`]. It
/// re-reads the Host journal's own durable cutover projection and the
/// installation registry's active generation and projects them through
/// [`reconcile_cutover_outcome`], so the returned disposition is the exact
/// requested/validated/prepared/committed/reconciled/retirement-pending/
/// failed/unknown state of the operation rather than a local assumption.
///
/// # Errors
///
/// Returns [`HostError`] when the durable Host journal or the installation
/// registry cannot be read. A failed read is an error, never a disposition:
/// reporting a state the owners did not prove is exactly the local assumption
/// this function exists to remove.
pub fn read_cutover_disposition(
    host: &HostComposition,
    request: &CutoverRequest,
    validated: bool,
    retirement_receipt: Option<&AppendReceipt>,
) -> Result<CutoverOutcome, HostError> {
    let snapshot = host
        .journal
        .snapshot()
        .map_err(|error| note_cutover_read_error(super::HostError::from(error)))?;
    let registry = host
        .open_registry_store()
        .map_err(note_cutover_read_error)?
        .load()
        .map_err(|error| HostError::Platform(error.to_string()))
        .map_err(note_cutover_read_error)?;
    Ok(reconcile_cutover_outcome(
        &request.operation,
        validated,
        snapshot.pending_cutover.as_ref(),
        registry.active_generation(),
        &request.target_generation,
        retirement_receipt,
    ))
}

/// Runs the separately authorized prior-generation retirement that completes
/// one committed cutover.
///
/// This is the implementation behind
/// [`crate::HostComposition::backup_dispatch_cutover_retire`]; it owns no
/// algorithm. Retirement is never automatic cleanup: the caller must present
/// the barrier returned by the cutover dispatch for the same operation, the
/// exact prior epoch still retained by the journal, and an explicit non-empty
/// retirement authorization.
///
/// The gate is the **durable committed cutover intent**, not the pre-activation
/// owner gate set: `validate_cutover_request` requires the active generation to
/// still equal the expected predecessor, which is by construction false once
/// the activation committed, so re-running it here could never succeed. The
/// committed intent is the owner's own record that the exact new state was
/// applied, and the named prior epoch must still be outstanding in this Host
/// journal.
///
/// The gate is therefore live only inside the Host epoch that performed the
/// cutover, because the intent record lives in that epoch's log. After a
/// restart the intent is gone and retirement must be re-authorized against the
/// registry readback by the owner surface; this function refuses rather than
/// inferring.
///
/// # Errors
///
/// Returns [`CutoverError`] when this operation has no durable cutover intent,
/// when the intent has not committed (or was refused), when the presented
/// barrier does not belong to this cutover's activation, or when the journal
/// owner refuses the retirement record.
pub fn retire_authorized_generation(
    host: &HostComposition,
    request: &CutoverRequest,
    evidence: &IsolatedRecoveryEvidence,
    barrier: &GenerationRetirementBarrier,
    prior_host: &HostInstallationEpoch,
    retirement_authorization: &PlatformHandle,
) -> Result<CutoverOutcome, CutoverError> {
    let journal = host.journal.snapshot().map_err(|error| {
        note_cutover_error(
            "retire_authorize",
            CutoverError::HostTransition(HostError::OwnerLeaseRecovery(error.to_string())),
        )
    })?;
    let intent = journal
        .pending_cutover
        .as_ref()
        .filter(|intent| {
            intent.cutover_operation == request.operation.operation_id
                && intent.installation == request.operation.installation
                && intent.request_digest == request.operation.request_digest
        })
        .ok_or_else(|| {
            note_cutover_error(
                "retire_authorize",
                CutoverError::NotSeparatelyAdmitted(
                    "retirement has no durable cutover intent for this operation".to_owned(),
                ),
            )
        })?;
    match intent.state {
        CutoverIntentState::Committed => {}
        CutoverIntentState::Pending => {
            return Err(note_cutover_error(
                "retire_authorize",
                CutoverError::AuthorityOrReadinessMissing,
            ));
        }
        CutoverIntentState::Failed => {
            return Err(note_cutover_error(
                "retire_authorize",
                CutoverError::Registry(
                    "retirement refused: the cutover activation was not applied".to_owned(),
                ),
            ));
        }
    }
    if intent.target_generation != request.target_generation
        || barrier.fence().activation_id != intent.fence.activation_id
        || barrier.fence().activation_generation != intent.fence.activation_generation
        || !fences_match_exact(&barrier.fence().state_fence, &request.activation_fence)
    {
        return Err(note_cutover_error(
            "retire_authorize",
            CutoverError::BindingMismatch,
        ));
    }
    // The prior epoch must be one this Host journal still retains, unretired,
    // and different from the epoch performing the cutover. Stated precisely:
    // the cutover determines the predecessor *generation* (the registry owns
    // that), while the journal owns the *epochs*, so the gate proves the named
    // epoch is genuinely outstanding — it does not claim to know which of the
    // retained epochs the predecessor generation maps to, because no owner
    // exposes that mapping. The journal reducer re-checks the same condition
    // on append.
    let outstanding = journal.retained_epochs.iter().any(|retained| {
        retained.host == *prior_host
            && !retained.retired
            && prior_host.installation == host.host.installation
            && prior_host.epoch != host.host.epoch
    });
    if !outstanding {
        return Err(note_cutover_error(
            "retire_authorize",
            CutoverError::BindingMismatch,
        ));
    }
    // The retirement step owns its outcome record; this notes only the
    // propagation of its failure to the authorization boundary.
    retire_prior_generation(
        host,
        &ValidatedCutover {
            request: request.clone(),
            evidence: evidence.clone(),
        },
        barrier,
        prior_host,
        retirement_authorization,
    )
    .map_err(|error| note_cutover_error("retire_authorize", error))
}

/// Stable wire spelling of one cutover intent disposition, used to derive the
/// per-disposition journal mutation identity. Keep it in lockstep with
/// [`eliot_host_state::CutoverIntentState`]'s `SCREAMING_SNAKE_CASE` serde.
const fn cutover_intent_state_spelling(state: CutoverIntentState) -> &'static str {
    match state {
        CutoverIntentState::Pending => "pending",
        CutoverIntentState::Committed => "committed",
        CutoverIntentState::Failed => "failed",
    }
}

/// Appends one durable cutover intent/terminal record through the Host journal
/// owner and returns its bounded transaction identity.
///
/// `Pending` is written before the activation CAS, `Committed` or `Failed`
/// after it, all under the same operation identity. The record carries the
/// exact admitted build/config/`UserBroker` bindings and the bounded owner
/// receipt set, so a later reconciliation reads the identities from the
/// durable owner instead of trusting a console-presented value.
fn append_cutover_intent(
    host: &HostComposition,
    validated: &ValidatedCutover,
    retirement: &GenerationRetirementFence,
    state: CutoverIntentState,
    admission: &HostRequestAdmissionReceipt,
) -> Result<PlatformHandle, CutoverError> {
    // One journal mutation identity per disposition. The journal keys
    // `applied_operations` on this identity, so the intent and its terminal
    // record must not share one; a retry of the *same* disposition reuses it
    // and therefore replays byte-identically instead of forking a second
    // transaction (the same convention the Store-rebind seam uses).
    let mutation = PlatformHandle::new(format!(
        "{}:{}",
        validated.request.operation.operation_id.as_str(),
        cutover_intent_state_spelling(state)
    ))
    .map_err(|_| CutoverError::BindingMismatch)?;
    let operation = IdempotencyIdentity {
        operation_id: mutation,
        idempotency_key: validated.request.operation.request_digest.clone(),
    };
    let record = CutoverIntentRecord {
        fence: RecordFence {
            host: host.host.clone(),
            activation_id: retirement.activation_id.clone(),
            activation_generation: retirement.activation_generation.clone(),
        },
        operation,
        installation: validated.request.operation.installation.clone(),
        cutover_operation: validated.request.operation.operation_id.clone(),
        request_digest: validated.request.operation.request_digest.clone(),
        expected_predecessor: validated.request.expected_predecessor.clone(),
        target_generation: validated.request.target_generation.clone(),
        target_build_digest: validated.request.target_build_digest.clone(),
        target_config_digest: validated.request.target_config_digest.clone(),
        user_broker_ref: validated.request.user_broker_ref.clone(),
        intent_evidence_refs: bounded_evidence(vec![
            admission_handle(admission)?,
            validated.request.archive_digest.clone(),
            receipt_handle(&validated.evidence.restore_receipt.receipt_id)?,
            receipt_handle(&validated.evidence.restore_receipt.effect_receipt_sha256)?,
            receipt_handle(&validated.evidence.operational_validation.validation_digest)?,
        ]),
        state,
    };
    let receipt = super::journal_append::append_reconciled(
        &host.journal,
        HostStateRecord::CutoverIntent(record),
    )?;
    Ok(receipt.transaction_id().clone())
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
    barrier: &GenerationRetirementBarrier,
    prior_host: &HostInstallationEpoch,
    retirement_authorization: &PlatformHandle,
) -> Result<CutoverOutcome, CutoverError> {
    host.ensure_material_admission_open_for_target(&validated.request.target_generation, false)
        .map_err(|error| note_cutover_error("retire", CutoverError::from(error)))?;
    if retirement_authorization.as_str().trim().is_empty() {
        return Err(note_cutover_error(
            "retire",
            CutoverError::AuthorityOrReadinessMissing,
        ));
    }
    if prior_host.installation != host.host.installation {
        return Err(note_cutover_error("retire", CutoverError::BindingMismatch));
    }
    if prior_host.epoch == host.host.epoch {
        return Err(note_cutover_error("retire", CutoverError::BindingMismatch));
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
        // Fence shape comes from the ISSUED barrier itself
        // (`GenerationRetirementBarrier::fence`), not a second
        // caller-supplied copy: the activation id + generation recorded
        // here are exactly the ones the barrier was issued for, already
        // cross-checked against the request in `execute_cutover`. The
        // journal reducer runs the complete owner `validate()` on append,
        // including `HostInstallationEpoch::validate`, which this crate
        // cannot call directly (`pub(crate)` in `eliot-host-state`).
        fence: RecordFence {
            host: host.host.clone(),
            activation_id: barrier.fence().activation_id.clone(),
            activation_generation: barrier.fence().activation_generation.clone(),
        },
        operation,
        retired_host: prior_host.clone(),
        retirement_evidence_refs: bounded_evidence(vec![
            admission_handle(&validated.request.admission)
                .map_err(|error| note_cutover_error("retire", error))?,
            validated.request.archive_digest.clone(),
            validated.request.target_generation.clone(),
            // The exact new authority this retirement completes: without it
            // the durable record would not name which `UserBroker` identity and
            // which approved build/config the surviving generation runs under.
            validated.request.user_broker_ref.clone(),
            validated.request.target_build_digest.clone(),
            validated.request.target_config_digest.clone(),
            receipt_handle(&validated.evidence.restore_receipt.receipt_id)
                .map_err(|error| note_cutover_error("retire", error))?,
            receipt_handle(&validated.evidence.restore_receipt.effect_receipt_sha256)
                .map_err(|error| note_cutover_error("retire", error))?,
            receipt_handle(&validated.evidence.operational_validation.validation_digest)
                .map_err(|error| note_cutover_error("retire", error))?,
            retirement_authorization.clone(),
        ]),
        retired_at,
    });
    let receipt = super::journal_append::append_reconciled(&host.journal, record)
        .map_err(|error| note_cutover_error("retire", CutoverError::from(error)))?;
    let outcome = CutoverOutcome {
        disposition: CutoverDisposition::Reconciled,
        operation: validated.request.operation.clone(),
        evidence_refs: bounded_evidence(vec![
            receipt.transaction_id().clone(),
            admission_handle(&validated.request.admission)
                .map_err(|error| note_cutover_error("retire", error))?,
            retirement_authorization.clone(),
        ]),
    };
    // Observed authorized retirement only; source erasure is a separate
    // explicitly authorized action and is never inferred here.
    observe_cutover_progress(
        "retire",
        "reconciled",
        "reconciled",
        backup_cutover_count(outcome.evidence_refs.len()),
    );
    Ok(outcome)
}

/// Reconciles a cutover from real owner observations after lost response,
/// crash between the registry and the journal, or cancellation.
///
/// Every owner observation is a real read: `durable_intent` is the Host
/// journal's own `pending_cutover` projection for this cutover (`None` when no
/// intent was ever committed), `registry_active` is the active generation
/// freshly read back from the registry owner
/// (`RedbInstallationRegistry::load().active_generation()`), and
/// `retirement_receipt` is the actual `AppendReceipt` read back from the
/// journal owner for the cutover operation identity (`None` when no such
/// receipt exists). `validated` is the one caller-supplied input: it records
/// whether the owner gate set actually passed for this attempt, and it is
/// never used to assert an effect.
///
/// The dispositions are read off those observations, never assumed: a durable
/// `Failed` intent is the terminal refusal that changed nothing and outranks
/// every other observation, because the owner recorded it after observing the
/// refusal; a present retirement receipt proves the lifecycle is durably
/// reconciled; a registry flip to the target **together with** this operation's
/// own durable intent proves the activation committed with retirement still
/// owed; a durable `Pending` intent with no flip proves the effect has not been
/// applied yet; and with no durable intent at all the operation is `Validated`
/// when the gate set passed and `Requested` when it did not.
///
/// A bare active target with **no** durable intent of ours is somebody else's
/// activation — an installer commit, or a cutover whose Host epoch has been
/// re-based away — and stays `Unknown`, never `RetirementPending` or
/// `Committed`: this function never marks an operation active from an
/// observation it cannot bind to that operation. That, and a foreign intent or
/// an unexpected active generation, is the complete `Unknown` set.
/// `Committed` is not produced here: it is the immediate post-CAS outcome
/// `execute_cutover` returns, and a later read of the same operation reports
/// `RetirementPending` until the retirement receipt exists.
/// Cancellation/cleanup/diagnostic failure preserves the primary result and its
/// reconciliation path.
#[must_use]
pub fn reconcile_cutover_outcome(
    operation: &CutoverOperationIdentity,
    validated: bool,
    durable_intent: Option<&CutoverIntentRecord>,
    registry_active: Option<&PlatformHandle>,
    target_generation: &PlatformHandle,
    retirement_receipt: Option<&AppendReceipt>,
) -> CutoverOutcome {
    let ours = durable_intent.filter(|intent| {
        intent.cutover_operation == operation.operation_id
            && intent.installation == operation.installation
            && intent.request_digest == operation.request_digest
    });
    let foreign = durable_intent.is_some() && ours.is_none();
    let disposition = if foreign {
        // An outstanding intent that is not this exact operation is
        // cross-operation confusion, never evidence about this one.
        CutoverDisposition::Unknown
    } else if ours.is_some_and(|intent| intent.state == CutoverIntentState::Failed) {
        CutoverDisposition::Failed
    } else if retirement_receipt.is_some() {
        CutoverDisposition::Reconciled
    } else if ours.is_some() && registry_active == Some(target_generation) {
        CutoverDisposition::RetirementPending
    } else if ours.is_some_and(|intent| intent.state == CutoverIntentState::Pending) {
        CutoverDisposition::Prepared
    } else if ours.is_none() && registry_active == Some(target_generation) {
        // The target is active but nothing durable binds that flip to this
        // operation: an installer's commit, or a cutover from a Host epoch that
        // has since been re-based. Never reported as this operation's success.
        CutoverDisposition::Unknown
    } else if ours.is_none() && validated {
        CutoverDisposition::Validated
    } else if ours.is_none() {
        CutoverDisposition::Requested
    } else {
        CutoverDisposition::Unknown
    };
    let outcome = CutoverOutcome {
        disposition,
        operation: operation.clone(),
        evidence_refs: bounded_evidence(match retirement_receipt {
            Some(receipt) => vec![receipt.transaction_id().clone(), target_generation.clone()],
            None => ours.map_or_else(
                || vec![target_generation.clone()],
                |intent| {
                    vec![
                        intent.cutover_operation.clone(),
                        intent.target_generation.clone(),
                    ]
                },
            ),
        }),
    };
    // The projected disposition repeats the owner observations verbatim:
    // ambiguity stays unknown with the original operation identity, and no
    // rollback request or archive hash can surface as a commit here.
    observe_cutover_progress(
        "reconcile",
        "projected",
        cutover_disposition_token(outcome.disposition),
        backup_cutover_count(outcome.evidence_refs.len()),
    );
    outcome
}
