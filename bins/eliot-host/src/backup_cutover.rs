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
//! - Cutover body: `eliot_protocol::BackupCutoverPayload`
//!   (`crates/foundation/eliot-protocol/src/backup.rs`, the closed, versioned
//!   body owned by #954). `validate_cutover_request_inner` builds that body
//!   from the presented request — no caller ever supplies its own bytes — and
//!   proves it against the admitted envelope with the owner's own
//!   `BackupCutoverPayload::validate_admitted_payload`, which compares the
//!   body's canonical content digest with the envelope's
//!   `identity.payload_sha256` under `BACKUP_CUTOVER_PAYLOAD_SCHEMA_ID` and
//!   requires an `Invocation`. `BackupCutoverPayload::operation_request_digest`
//!   supplies the operation-identity domain, so the payload content domain, the
//!   envelope payload domain and the operation domain stay three explicit
//!   domains and are never equated merely because all are SHA-256 strings.
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
//!   rs:4043`, approved-target check, exact-replay `Ok`, predecessor-gated
//!   flip recording the prior generation as last-known-good). The CAS also
//!   carries the cutover operation binding and the registry retains it as
//!   `CommittedCutoverActivation`, so recovery resolves a possibly-applied
//!   activation under the ORIGINAL operation identity instead of attributing
//!   an active-generation pointer to an operation (#2737). An active pointer
//!   alone attributes nothing: an installer commit and another operation's
//!   cutover produce the same pointer. No wire-version bump and no change to
//!   any existing field: the new member is an optional additive projection
//!   whose `None` state serializes byte-identically to before.
//! - `HostOwnerLease::activation_capability` through
//!   `HostComposition::owner_lease` (host `lib.rs:3724`, used by every owner
//!   contour): live-guard capability for the CAS.
//! - `super::journal_append::append_reconciled` (host `journal_append.rs:281`,
//!   `pub(super)` choke for every `ProductionHostStateJournal` write, with
//!   `OutcomeUnknown` fail-closed reconciliation): persists the
//!   `HostStateRecord::EpochRetirement(EpochRetirementRecord)`
//!   (`eliot-host-state/src/model.rs`, `EpochRetirementRecord` and
//!   `PredecessorRetirementRelation`) carrying the cutover operation identity,
//!   barrier-bound fence, bounded evidence refs, and the owner-issued
//!   predecessor-generation-to-Host-epoch relation, and returns the real
//!   `AppendReceipt`
//!   (`eliot-host-state/src/journal.rs:41`, `sequence()`/`disposition()`/
//!   `transaction_id()`). Intent is bound inside this record before any
//!   route/SCM effect; this path performs no process/SCM effects itself.
//!   Record helpers `super::{record_fence, fresh_identity}` (host `lib.rs`
//!   :3568,:3444, private in the root, visible here) build owner-shaped
//!   values only.
//! - Retirement readback (#2739) goes back through the SAME journal owner
//!   through `HostComposition::journal::query_epoch_retirement`
//!   (`eliot-host-state/src/service.rs:97` delegating to
//!   `HostStateJournal::query_epoch_retirement`, `journal.rs`, the
//!   `query_epoch_retirement` method) under the
//!   exact `IdempotencyIdentity` `retire_prior_generation` wrote into the
//!   record — the cutover operation id with the retained request digest. The
//!   owner selects the record from the log it replayed, recomputes the record's
//!   transaction identity itself, and answers a typed absence or a typed
//!   contradiction. An `AppendReceipt` is only a lookup hint there: it proves
//!   that SOME append happened (sequence, disposition, transaction id) and
//!   never which record kind, so a presented receipt must name the owner's own
//!   transaction identity to be believed, and a mismatch is explicit absence.
//!   The owner-resolved `EpochRetirementObservation` is then re-proved here
//!   against the request from the record's OWN durable fields: the exact
//!   operation identity it was applied under, the installation/Host lineage, a
//!   genuinely prior epoch, the Host epoch that retained it, the target and
//!   approved facts the retirement recorded, and — since #2868 — the stored
//!   `PredecessorRetirementRelation`, which must map this request's exact
//!   `expected_predecessor` onto the exact retired epoch. A record carrying no
//!   relation is reported as `RelationUnproven` rather than as this operation's
//!   effect. The single cutover-intent slot is
//!   current applicability, not history: it corroborates the retirement when it
//!   still holds this operation's own intent, and a later legitimate operation
//!   replacing that slot neither erases the retained retirement record nor is
//!   read as evidence about this operation. Only then is the retirement
//!   projected as this operation's effect. The journal's identity algorithm is
//!   used only through the owner's accessor; `eliot-host` never re-derives a
//!   transaction id.
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
    AppendReceipt, CutoverIntentRecord, CutoverIntentState, EpochRetirementObservation,
    EpochRetirementQuery, EpochRetirementQueryError, EpochRetirementRecord, EpochTransition,
    HostState, HostStateRecord, IdempotencyIdentity, JournalError, PredecessorRetirementRelation,
    RecordFence,
};
use eliot_installation::{
    ApprovedGeneration, ApprovedGenerationRegistry, CandidateManifest, CommittedCutoverActivation,
};
use eliot_ors::{CapabilityIntroductionProjection, OperationalPhase};
use eliot_platform::PlatformHandle;
use eliot_protocol::{
    BACKUP_CUTOVER_PAYLOAD_WIRE_ID, BACKUP_CUTOVER_PAYLOAD_WIRE_VERSION, BackupClassWire,
    BackupCutoverPayload, BackupOperationKind, HostRequestAdmissionReceipt, HostRequestEnvelope,
    HostRequestKind, host_request_operation_id,
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

/// Bounded recheck attempts for one status read's cross-store coherence.
///
/// The Host journal and the installation registry have no shared transaction, so
/// a status read proves its pair by sampling the journal on both sides of the
/// registry load. The ordinary case settles on the first attempt, because nothing
/// changed; a second attempt absorbs one genuine concurrent commit. The ceiling
/// keeps a continuously moving installation from turning a read into an unbounded
/// loop, and the read reports movement rather than a settled pair once it is
/// reached. Deliberately small: this is a diagnostic/status path, not a retry
/// loop (I14.21 — no blind duplicate).
const CUTOVER_DISPOSITION_READ_ATTEMPTS: u8 = 3;

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
///
/// The fields are private and the only constructor is
/// [`ValidatedCutover::seal`], which re-proves the retained body against the
/// admitted envelope. A `ValidatedCutover` therefore cannot be produced by a
/// struct literal from this module, from a sibling module, or from another
/// crate, and no caller-controlled boolean stands in for the owner check: the
/// value exists only where the owner's own cross-record join succeeded
/// (#2738).
#[derive(Clone, Debug)]
pub struct ValidatedCutover {
    request: CutoverRequest,
    evidence: IsolatedRecoveryEvidence,
    /// The retained, content-checked cutover body. Its `content_digest` is the
    /// canonical digest of these exact bytes, and those bytes are the body the
    /// admitted envelope committed to.
    body: BackupCutoverPayload,
    /// The checked content digest captured at seal time. Never a caller value.
    content_digest: String,
}

impl ValidatedCutover {
    /// Seals a presented request and its recovery evidence behind the retained
    /// validated cutover body.
    ///
    /// The body is proved again here rather than trusted from its builder: the
    /// seal is only created when the body's own canonical content digest equals
    /// the digest the admitted envelope committed to, so a body that was edited
    /// after the payload binding cannot be sealed and no struct literal can
    /// stand in for the check.
    fn seal(
        request: &CutoverRequest,
        evidence: &IsolatedRecoveryEvidence,
        body: BackupCutoverPayload,
    ) -> Result<Self, CutoverError> {
        prove_admitted_cutover_body(&request.envelope, &body)?;
        let content_digest = body
            .checked_content_digest()
            .map_err(|_error| CutoverError::BindingMismatch)?;
        Ok(Self {
            request: request.clone(),
            evidence: evidence.clone(),
            body,
            content_digest,
        })
    }

    /// The exact admitted request this seal retains.
    ///
    /// `pub(crate)` only because the composition root reads the retained
    /// target generation from the seal when it projects the post-commit owner
    /// readback. It is a read accessor, not a constructor: the fields stay
    /// private to this module, so no caller can build or reshape a
    /// `ValidatedCutover` through it.
    pub(crate) fn request(&self) -> &CutoverRequest {
        &self.request
    }

    /// The owner recovery evidence this seal retains.
    fn evidence(&self) -> &IsolatedRecoveryEvidence {
        &self.evidence
    }

    /// The checked canonical content digest of the retained body, carried as
    /// durable evidence so reconciliation reads the same body commitment from
    /// the journal owner instead of recomputing it from console bytes.
    fn content_digest(&self) -> &str {
        &self.content_digest
    }

    /// Re-runs the authoritative body/admitted-envelope join at an effect
    /// boundary.
    ///
    /// The seal already proved this at construction; repeating it immediately
    /// before a journal mutation or a registry CAS means the effect runs only
    /// against a body that is still the admitted one, with no `verified` flag
    /// and no second source of truth.
    fn recheck_admitted_body(&self) -> Result<(), CutoverError> {
        prove_admitted_cutover_body(&self.request.envelope, &self.body)
    }

    /// The cutover operation identity derived from the retained body.
    ///
    /// Installation and operation id are read from the body itself, and the
    /// request digest is the body's own operation-identity domain — never the
    /// presented text. The seal proved that presentation already equals this
    /// derivation, so the intent, the registry binding, the replay comparison
    /// and the returned outcome all name the same body-derived identity.
    fn sealed_operation(&self) -> Result<CutoverOperationIdentity, CutoverError> {
        let installation = PlatformHandle::new(self.body.installation_id.clone())
            .map_err(|_error| CutoverError::BindingMismatch)?;
        let operation_id = PlatformHandle::new(self.body.operation_id.clone())
            .map_err(|_error| CutoverError::BindingMismatch)?;
        let request_digest = PlatformHandle::new(
            self.body
                .operation_request_digest()
                .map_err(|_error| CutoverError::BindingMismatch)?,
        )
        .map_err(|_error| CutoverError::BindingMismatch)?;
        Ok(CutoverOperationIdentity {
            installation,
            operation_id,
            request_digest,
        })
    }
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

/// Causal residual that bounds one projected cutover disposition.
///
/// Closed: every variant names WHY the owner observations do or do not
/// establish the disposition that was projected. It never introduces a status
/// a caller must learn — the disposition vocabulary is unchanged — and it never
/// carries owner error text, handles, digests, or an inferred effect. A
/// residual of [`CutoverResidual::None`] means the owner observations agree; a
/// non-`None` residual is the preserved uncertainty (I14.21), not a failure
/// code.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CutoverResidual {
    /// The owner observations agree: nothing unresolved bounds this
    /// disposition.
    None,
    /// A durable cutover intent exists, but it names another operation, target
    /// or predecessor, so it is not evidence about this attempt.
    ForeignDurableIntent,
    /// The registry's active-generation pointer is not bound to this operation
    /// by the registry's own operation-bound cutover receipt. An active pointer
    /// attributes a flip to nobody.
    UnattributedActivation,
    /// The journal owner holds more than one `EpochRetirement` for this exact
    /// operation identity. A contradiction about durable state is reported,
    /// never resolved by choosing one.
    ContradictoryRetirement,
    /// The journal owner resolved a retirement for this exact operation, but
    /// that record does not bind to this request's installation lineage, prior
    /// epoch, activation or evidence, so it is not this cutover's retirement.
    UnboundRetirement,
    /// The registry's active generation is not this operation's expected
    /// predecessor, so the pre-effect state a `Pending` intent requires is not
    /// established and the attempt is not known to be unapplied.
    PredecessorNotActive,
    /// This operation has a durable committed intent, but neither an
    /// owner-resolved retirement nor a registry-attributed flip establishes
    /// what the owners committed. Preserved, never guessed (I14.21).
    ActivationOutcomeUnestablished,
    /// This operation's activation committed under the registry's own
    /// operation-bound receipt together with this operation's durable intent,
    /// and no owner-resolved retirement exists yet. Retirement stays a
    /// separate explicitly authorized step.
    RetirementOutstanding,
    /// The retirement is authentic history, but the registry's current active
    /// generation is no longer this operation's target, so the historical
    /// retirement is not a current activation of the old target.
    RetirementSuperseded,
    /// This operation's own owner-resolved retirement is bound to this request
    /// and is therefore reported, but the Host journal's cutover intent
    /// projection — one slot, and the only place the owner retains a cutover
    /// intent — no longer holds THIS operation's intent. A later legitimate
    /// operation replaced it, exactly as the journal reducer is allowed to do
    /// once the previous intent is terminal
    /// (`eliot_host_state::journal`, the `CutoverIntent` arm), so the retirement
    /// survives while the intent's own disposition is simply not re-readable
    /// from the owner. The completion is therefore history only: it grants no
    /// current authority, and neither the later operation's registry pointer nor
    /// pointer equality says anything about this one. Retained rather than
    /// erased (I5.13: pre-cutover state is retained until explicit retirement;
    /// A13.7: old authority never revives).
    RetirementWithoutRetainedIntent,
    /// This operation's own durable intent reached the terminal `Failed` state
    /// AND the journal owner holds non-absent retirement evidence for this same
    /// operation identity — resolved, contradictory, or resolved-but-unbound.
    /// The owner observations contradict each other, so neither "nothing
    /// changed" nor "the cutover completed" is reported; the contradiction
    /// itself is the result. Choosing the `Failed` arm first would silently
    /// discard a reconciled history, which is exactly the flattening this
    /// residual exists to prevent.
    FailedIntentWithResolvedRetirement,
    /// The cutover-relevant projection of the Host journal could not be
    /// observed as one moment: it changed while the installation registry was
    /// read, and the bounded recheck did not re-prove the pair. There is no
    /// cross-store atomic read guarantee, so a positive claim built from the
    /// torn pair would be an impossible state, not a fact. Refusals are still
    /// reported — only the effect- and history-bearing dispositions require a
    /// coherent pair. A failed journal READ is a different thing and is
    /// propagated as an error, never reported as movement.
    ConcurrentOwnerMovement,
    /// No owner can state which Host epoch carried this cutover's exact
    /// expected predecessor generation, so the epoch to retire is not
    /// determined by the request (#2868).
    ///
    /// The installation registry's approved-generation/Host-activation handoff
    /// relates a generation to a Host epoch for the activation being COMMITTED,
    /// but the registry retains one such fence - and staging the cutover's target
    /// generation, a prerequisite of its registry CAS, clears it - and the fence
    /// carries no activation identity, issuer or issuance instant for the epoch
    /// being retired. The Host journal's `CutoverIntentRecord` names
    /// installation generations, but binds them to the epoch that performed the
    /// cutover rather than the epoch that carried the predecessor.
    ///
    /// The retirement effect is therefore refused before any record is appended:
    /// no outstanding epoch is retired and no journal or registry state changes.
    /// What is retained is the PRE-RETIREMENT state - the cutover itself has
    /// already committed and activated the target, which is the separately
    /// authorized step that happened earlier. Naming an arbitrary outstanding
    /// epoch instead would report a completed retirement of authority this
    /// cutover never consumed.
    PredecessorEpochUnknown,
    /// A retirement record for this operation exists and is otherwise bound to
    /// this request, but it was written without the predecessor-generation
    /// relation (#2868).
    ///
    /// Legacy history stays visible and is never erased; it simply cannot close
    /// predecessor retirement, so the disposition is `Unknown` rather than
    /// `Reconciled` even though every other binding agrees.
    RetirementWithoutPredecessorRelation,
}

/// Coherence of one status read's two cross-store owner observations.
///
/// The Host journal and the installation registry are separate durable owners
/// with no shared transaction. A status read samples the journal, then loads the
/// registry, then re-samples the journal, and a change to the cutover-relevant
/// projection between those samples produces a pair that never existed at any
/// single moment. `Prepared` in particular claims "the effect has not been
/// applied", so returning it from a torn pair would assert the opposite of what
/// the owners did.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OwnerObservationCoherence {
    /// The cutover-relevant projection was unchanged across the registry read,
    /// so the projected pair describes one moment with respect to this cutover.
    Coherent,
    /// The cutover-relevant projection changed during the read and the bounded
    /// recheck did not settle the pair. No effect- or history-bearing
    /// disposition may be projected.
    Moving,
}

/// True when nothing this projection consumes changed between two journal
/// samples.
///
/// The journal's global `sequence` and `last_checksum` advance for EVERY applied
/// record of any kind — observations, wakes, readiness frames, clean markers —
/// so comparing them would report ordinary Host traffic as owner movement and
/// make a settled cutover flap to `Unknown` under normal load. Only the records
/// the disposition actually consumes are compared: the single cutover-intent
/// slot, the epoch retirements, the Host installation/epoch identity, and the
/// retained epoch evidence the retirement binder scans.
///
/// Not covered: the cross-store registry load has no shared transaction with
/// the journal, and `read_cutover_disposition` samples the journal on BOTH sides
/// of it and on BOTH sides of the `query_epoch_retirement` lookup, so the pair
/// it hands the mapper is one moment with respect to this cutover or is reported
/// as `Moving`. `HostComposition::backup_dispatch_cutover` performs the same
/// bracketing for the execute path, but resolves the retirement outside its
/// compared interval; the key here bounds what this function proves.
pub(crate) fn cutover_observation_unchanged(before: &HostState, after: &HostState) -> bool {
    before.pending_cutover == after.pending_cutover
        && before.epoch_retirements == after.epoch_retirements
        && before.host == after.host
        && before.retained_epochs == after.retained_epochs
}

/// Bounded redacted outcome. Diagnostics/evidence never affect control
/// reserve, ordering, or the primary result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CutoverOutcome {
    pub disposition: CutoverDisposition,
    /// Causal residual that bounds `disposition`; see [`CutoverResidual`].
    pub residual: CutoverResidual,
    pub operation: CutoverOperationIdentity,
    pub evidence_refs: Vec<PlatformHandle>,
}

/// One owner-resolved `EpochRetirement`, bound to the cutover request it was
/// proved against.
///
/// Construction is restricted to this module's read wrapper
/// (`resolve_cutover_retirement`): every field is private, there is no public
/// constructor, no `Default`, no deserialization and no `verified: bool`, so
/// the only way to obtain one is to resolve the exact retirement through the
/// journal owner and re-prove its bindings. The pure mapper therefore cannot
/// be handed a fabricated retirement, and it is not asked to repeat the owner's
/// validation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BoundRetirementEvidence {
    operation: CutoverOperationIdentity,
    transaction_id: PlatformHandle,
    evidence_refs: Vec<PlatformHandle>,
}

impl BoundRetirementEvidence {
    /// Binds one owner-resolved observation to the request it was proved
    /// against. Private on purpose: this is the only constructor, so a
    /// retirement can reach the mapper only through the owner lookup.
    fn bind(
        operation: &CutoverOperationIdentity,
        transaction_id: &PlatformHandle,
        evidence_refs: &[PlatformHandle],
    ) -> Self {
        Self {
            operation: operation.clone(),
            transaction_id: transaction_id.clone(),
            evidence_refs: evidence_refs.to_vec(),
        }
    }

    /// The cutover operation identity this retirement was resolved and proved
    /// under.
    pub const fn operation(&self) -> &CutoverOperationIdentity {
        &self.operation
    }

    /// Transaction identity the JOURNAL owner computed for the record it
    /// resolved — never a recomputed or presented value.
    pub const fn transaction_id(&self) -> &PlatformHandle {
        &self.transaction_id
    }

    /// Evidence digests the durable retirement record carried, re-proved
    /// against this request before it was bound.
    pub fn evidence_refs(&self) -> &[PlatformHandle] {
        &self.evidence_refs
    }
}

/// What the journal owner established about one cutover operation's
/// prior-generation retirement, and how far that establishment binds to the
/// request it is reported for.
///
/// Closed: every state is a typed owner answer, and none of them can be
/// reached without the journal owner's own lookup. `Absent` and `Contradictory`
/// are deliberately distinct from `Unbound` so "there is no retirement" and
/// "the owner found a retirement that is not this cutover's" never collapse
/// into the same claim, and `RelationUnproven` is distinct from both because
/// "the right record with the predecessor-relation binding missing" is a third
/// fact again (#2868).
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CutoverRetirementEvidence {
    /// This Host journal applied no `EpochRetirement` under this exact
    /// operation identity. Explicitly absent, not unproven by omission.
    Absent,
    /// This Host journal applied more than one `EpochRetirement` under this
    /// exact operation identity. The contradiction is reported, never resolved.
    Contradictory,
    /// The journal owner resolved a retirement for this exact operation
    /// identity, but its installation lineage, prior epoch, activation fence
    /// or recorded evidence do not match this request, so it is not this
    /// cutover's retirement. Rejected as a substitution, not reported as an
    /// effect. A single intent slot that now names a DIFFERENT operation never
    /// produces this state: that is current applicability, not a substitution
    /// of the record.
    Unbound,
    /// The journal owner resolved exactly one `EpochRetirement` for this exact
    /// operation identity and every other binding agrees, but the record was
    /// written without the predecessor-generation relation (#2868).
    ///
    /// Deliberately distinct from both `Unbound` and `Resolved`. Collapsing it
    /// into `Unbound` would report a substitution that did not happen, and
    /// reading it as `Resolved` would report an exact completion of a retirement
    /// whose retired epoch was never shown to be the one the cutover consumed.
    RelationUnproven,
    /// The journal owner resolved exactly one `EpochRetirement` for this exact
    /// operation identity and the read wrapper proved its bindings against
    /// this request.
    Resolved(BoundRetirementEvidence),
}

impl CutoverRetirementEvidence {
    /// The owner-resolved retirement that binds to exactly this operation, or
    /// `None` when this operation has no resolved retirement. A resolution
    /// bound to another operation is never evidence about this one.
    pub fn resolved_for(
        &self,
        operation: &CutoverOperationIdentity,
    ) -> Option<&BoundRetirementEvidence> {
        match self {
            Self::Resolved(evidence) if evidence.operation() == operation => Some(evidence),
            // Absent, contradictory, relation-unproven, unbound, and a
            // resolution bound to a different operation are all "no retirement
            // this operation can read as its own effect".
            _ => None,
        }
    }

    /// The residual that keeps this retirement from establishing an effect, or
    /// `None` when the retirement state is one the mapper may read as this
    /// operation's evidence.
    pub const fn unresolved_residual(&self) -> Option<CutoverResidual> {
        match self {
            Self::Absent | Self::Resolved(_) => None,
            Self::Contradictory => Some(CutoverResidual::ContradictoryRetirement),
            Self::Unbound => Some(CutoverResidual::UnboundRetirement),
            // The record agrees on everything except the one binding that makes
            // the retirement THIS cutover's, so it is reported as a weaker proof
            // with its own name rather than as a substitution.
            Self::RelationUnproven => Some(CutoverResidual::RetirementWithoutPredecessorRelation),
        }
    }
}

/// How one cutover attempt relates to the operation this Host journal already
/// retains durably (I5.27 exact replay; I14.21 unknown commit).
///
/// This is the classification that must exist BEFORE any fresh-activation
/// gate is evaluated. The expected-predecessor gate is true by construction
/// only for an activation that has not happened, so evaluating it first makes
/// an exact committed retry and an interrupted post-CAS operation permanently
/// unrecoverable under their own identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RetainedCutoverOperation {
    /// No durable cutover intent names this operation: a genuinely NEW
    /// cutover, so every fresh-activation gate applies unchanged.
    Absent,
    /// The same operation identity under the same canonical request digest with
    /// a terminal `Failed` record: refused for good. A new attempt needs a new
    /// separately admitted operation identity, never a re-run under this one.
    Refused,
    /// The same operation identity under the same canonical request digest with
    /// a durable `Committed` record: the activation happened exactly once.
    Committed,
    /// The same operation identity under the same canonical request digest with
    /// a durable `Pending` record: admitted, possibly applied, and its terminal
    /// record is not durable. The registry owner must decide the outcome.
    Pending,
    /// The same operation identity under a different canonical request digest:
    /// `IDENTITY_CONFLICT`, which performs no transition at all.
    IdentityConflict,
    /// An outstanding intent belonging to a different operation:
    /// cross-operation confusion, never evidence about this one.
    Foreign,
}

/// Whether the expected-predecessor gate applies to one attempt.
///
/// Derived only from the durable retained-operation classification, never from
/// a caller assertion. A genuinely fresh activation is the single case in
/// which the active generation must still equal the expected predecessor
/// (I5.13 retains pre-cutover state; #961 acceptance 14-18).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PredecessorGate {
    /// Fresh activation: the active generation must equal the expected
    /// predecessor.
    Required,
    /// A retained operation of this exact identity already owns the attempt.
    /// The gate is not re-evaluated because it is false by construction once
    /// that operation's activation committed; the retained-operation and
    /// registry-outcome checks decide instead.
    SupersededByRetainedOperation,
}

/// What the installation registry proves about a possibly-applied cutover
/// activation, read under the attempt's ORIGINAL operation identity.
///
/// The registry's operation-bound receipt — not its active-generation pointer —
/// is what attributes a flip to one operation (I5.27: a committed canonical
/// intent never proves an effect occurred, and an active pointer attributes a
/// flip to nobody).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CutoverActivationResolution {
    /// The registry's operation-bound receipt names this exact operation,
    /// installation, request digest and target: the CAS committed once.
    Committed,
    /// The registry still shows the expected predecessor active and records no
    /// cutover for this operation: the CAS never applied, so the same
    /// operation may still complete it.
    NotApplied,
    /// The registry cannot establish the outcome: the operation, its retained
    /// intent and its predecessor requirement are preserved and the bounded
    /// unknown state is retained. No effect is inferred from a storage
    /// condition and no new operation is created to escape it (I14.21).
    Unresolved,
}

/// How one cutover attempt is executed, resolved from the durable owners before
/// any fresh-activation gate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CutoverAttemptPlan {
    /// No durable record of this operation: a genuinely fresh activation.
    Fresh,
    /// The same operation, terminal `Committed`: replay the observed outcome.
    /// The registry is never mutated again.
    ReplayCommitted,
    /// The same operation, durable `Pending`, and the registry's operation-bound
    /// receipt proves the CAS committed: persist the matching terminal record
    /// under the ORIGINAL identity, then leave retirement to its own separate
    /// authorization.
    SettleCommitted,
    /// The same operation, durable `Pending`, and the registry still shows the
    /// expected predecessor active: the CAS never applied, so the same
    /// operation completes it exactly as a fresh one would.
    ResumeFresh,
    /// The same operation, durable `Pending`, and the registry cannot
    /// establish the outcome: retain the bounded recoverable unknown state.
    RetainUnknown,
}

impl CutoverAttemptPlan {
    /// Whether the expected-predecessor gate still governs this attempt.
    #[must_use]
    pub const fn requires_active_predecessor(self) -> bool {
        matches!(self, Self::Fresh | Self::ResumeFresh)
    }

    /// The predecessor gate this plan implies for the admission gate set.
    #[must_use]
    pub const fn predecessor_gate(self) -> PredecessorGate {
        if self.requires_active_predecessor() {
            PredecessorGate::Required
        } else {
            PredecessorGate::SupersededByRetainedOperation
        }
    }
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
// `cutover_intent_state_spelling`/`cutover_class_wire`/`cutover_payload`/
// `prove_admitted_cutover_body`/`bind_admitted_cutover_body` (private steps
// whose outcome surfaces with its exact category at the validate/execute/retire
// boundary).

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

/// Classifies one cutover attempt against the operation this Host journal
/// already retains, BEFORE any fresh-activation gate is evaluated.
///
/// The retained identity is rebuilt from the durable record's own
/// installation, cutover operation and canonical request digest, so no
/// comparison ever takes a component from the presented request. A reused
/// operation key under a different canonical request hash is
/// `IDENTITY_CONFLICT` and performs no transition (I5.27).
#[must_use]
pub fn classify_retained_cutover(
    retained: Option<&CutoverIntentRecord>,
    candidate: &CutoverOperationIdentity,
) -> RetainedCutoverOperation {
    let Some(intent) = retained else {
        return RetainedCutoverOperation::Absent;
    };
    let retained_identity = CutoverOperationIdentity {
        installation: intent.installation.clone(),
        operation_id: intent.cutover_operation.clone(),
        request_digest: intent.request_digest.clone(),
    };
    if check_replay_identity(&retained_identity, candidate).is_err() {
        return RetainedCutoverOperation::IdentityConflict;
    }
    if !is_exact_replay(&retained_identity, candidate) {
        return RetainedCutoverOperation::Foreign;
    }
    match intent.state {
        CutoverIntentState::Committed => RetainedCutoverOperation::Committed,
        CutoverIntentState::Pending => RetainedCutoverOperation::Pending,
        CutoverIntentState::Failed => RetainedCutoverOperation::Refused,
    }
}

/// Resolves what the installation registry proves about a possibly-applied
/// cutover activation, under the attempt's ORIGINAL operation identity.
///
/// A flip is attributed to an operation only when the registry's durable
/// operation-bound receipt names that operation, installation, request digest
/// AND target. An active-generation pointer alone attributes the flip to nobody:
/// an installer commit, or another operation's cutover to the same target,
/// produces the same pointer, and is reported as unresolved rather than as
/// this operation's effect.
#[must_use]
pub fn resolve_cutover_activation(
    committed_activation: Option<&CommittedCutoverActivation>,
    registry_active: Option<&PlatformHandle>,
    retained_intent: &CutoverIntentRecord,
    operation: &CutoverOperationIdentity,
) -> CutoverActivationResolution {
    if let Some(receipt) = committed_activation
        && receipt.operation_id == operation.operation_id
        && receipt.installation == operation.installation
        && receipt.request_digest == operation.request_digest
    {
        // The registry attributes a flip to this exact operation. It settles
        // this attempt only when it names the retained target: contradictory
        // owner evidence stays unresolved instead of being read as progress.
        return if receipt.target_generation == retained_intent.target_generation {
            CutoverActivationResolution::Committed
        } else {
            CutoverActivationResolution::Unresolved
        };
    }
    if registry_active == Some(&retained_intent.expected_predecessor) {
        return CutoverActivationResolution::NotApplied;
    }
    CutoverActivationResolution::Unresolved
}

/// Reads the backup owner's real archive class as the protocol owner's closed
/// wire class.
///
/// `eliot_backup::BackupClass` is the class owner (`crates/storage/
/// eliot-backup/src/lib.rs:120`) and `eliot_protocol::backup::BackupClassWire`
/// is the wire vocabulary; the protocol crate deliberately does not depend on
/// the backup crate, so this total readback is the join between them. It
/// invents no third vocabulary: every class maps to exactly one wire class, and
/// an unrecognised class is impossible because both sets are closed.
fn cutover_class_wire(class: BackupClass) -> BackupClassWire {
    match class {
        BackupClass::FullRecovery => BackupClassWire::FullRecovery,
        BackupClass::CanonicalOnlyDegraded => BackupClassWire::CanonicalOnlyDegraded,
        BackupClass::ScopeExport => BackupClassWire::ScopeExport,
    }
}

/// Builds the closed, versioned cutover body from the presented request.
///
/// The body is derived here, never received: a caller cannot present its own
/// payload bytes, so there is no path on which a body and a claimed digest can
/// be edited independently. The content digest is computed by the protocol
/// owner's own canonical encoding owner through `with_computed_digest`, which
/// clears `content_digest` before encoding, so the digest never covers itself
/// and the bytes carry no admission receipt and no journal record.
///
/// The two class gates move here from the ordered gate set so they keep their
/// exact dispositions: a scope export is not an installation cutover body, and
/// a canonical-only class can never reach a body without an explicit degraded
/// policy reference. The body contract refuses both structurally as well; this
/// only preserves which cutover disposition names the refusal.
fn cutover_payload(request: &CutoverRequest) -> Result<BackupCutoverPayload, CutoverError> {
    if request.archive_class == BackupClass::ScopeExport {
        return Err(CutoverError::ScopeExportForbidden);
    }
    if request.archive_class.is_canonical_only() && request.archive_canonical_only_policy.is_none()
    {
        return Err(CutoverError::DegradedPolicyViolation);
    }
    BackupCutoverPayload {
        wire_id: BACKUP_CUTOVER_PAYLOAD_WIRE_ID.to_owned(),
        wire_version: BACKUP_CUTOVER_PAYLOAD_WIRE_VERSION,
        // The cutover runs under the destination installation; the ordered gate
        // set below proves the operation's installation is that same identity.
        installation_id: request.destination_installation.as_str().to_owned(),
        source_installation: request.source_installation.as_str().to_owned(),
        dest_installation: request.destination_installation.as_str().to_owned(),
        operation_id: request.operation.operation_id.as_str().to_owned(),
        archive_digest: request.archive_digest.as_str().to_owned(),
        archive_class: cutover_class_wire(request.archive_class),
        canonical_only_policy: request
            .archive_canonical_only_policy
            .as_ref()
            .map(|policy| policy.as_str().to_owned()),
        target_generation: request.target_generation.as_str().to_owned(),
        target_build_digest: request.target_build_digest.as_str().to_owned(),
        target_config_digest: request.target_config_digest.as_str().to_owned(),
        expected_predecessor: request.expected_predecessor.as_str().to_owned(),
        activation_fence: request.activation_fence.clone(),
        user_broker_ref: request.user_broker_ref.as_str().to_owned(),
        content_digest: String::new(),
    }
    .with_computed_digest()
    .map_err(|_error| CutoverError::BindingMismatch)
}

/// Proves that one cutover body is exactly the body its admitted envelope
/// commits to.
///
/// Two distinct fail-closed joins, in order. First the body must be
/// self-consistent: its claimed content digest must equal its own canonical
/// bytes, which is a fact about one record only. Then, and only then, the
/// cross-record join: the recomputed content digest must equal the ADMITTED
/// envelope's `identity.payload_sha256`, the envelope must carry the
/// [`eliot_protocol::BACKUP_CUTOVER_PAYLOAD_SCHEMA_ID`] payload-schema identity,
/// and it must be an `Invocation`. That is a comparison between two different
/// records, not a self-comparison, so an unrelated but perfectly valid admitted
/// `Invocation` — `eliot.query`, `eliot.state`, any other schema — refuses here
/// and can never authorize this body. A self-consistent serialized receipt is
/// not proof of issuance: the envelope compared against is the one the owner
/// admitted, and its admission is resolved through the authenticated
/// owner/readback path, not by any string comparison here.
fn prove_admitted_cutover_body(
    envelope: &HostRequestEnvelope,
    body: &BackupCutoverPayload,
) -> Result<(), CutoverError> {
    body.validate()
        .map_err(|_error| CutoverError::BindingMismatch)?;
    body.validate_admitted_payload(envelope)
        .map_err(|error| CutoverError::NotSeparatelyAdmitted(error.to_string()))?;
    Ok(())
}

/// Binds the presented request to its admitted cutover body and to the
/// operation identity that body implies.
///
/// This is the binding that did not exist before: the request body is proved to
/// be the body the owner admitted, and the operation request digest stops being
/// caller-chosen text. The claimed
/// [`CutoverOperationIdentity::request_digest`] must equal the body's own
/// operation-identity domain, which is derived from the body's canonical bytes
/// under the operation separator and can never equal a content digest. A body
/// whose source, destination, archive, class, target generation, build, config,
/// predecessor, authority, `UserBroker` or fence changed while the old claimed
/// digest is retained therefore refuses here as `IDENTITY_CONFLICT`, before any
/// journal mutation, registry CAS, or effect (I5.27). The same body replayed
/// under the same operation derives the same digest, so an exact authorized
/// replay still preserves the original content and operation.
fn bind_admitted_cutover_body(
    request: &CutoverRequest,
) -> Result<BackupCutoverPayload, CutoverError> {
    let body = cutover_payload(request)?;
    prove_admitted_cutover_body(&request.envelope, &body)?;
    let operation_request_digest = body
        .operation_request_digest()
        .map_err(|_error| CutoverError::BindingMismatch)?;
    if request.operation.request_digest.as_str() != operation_request_digest {
        return Err(CutoverError::IdentityConflict);
    }
    Ok(body)
}

/// Resolves the backup operation an admitted cutover payload authorizes.
///
/// The Host dispatch arms resolve their operation from this, not from a
/// routing table: the closed [`BackupOperationKind`] vocabulary has exactly one
/// member a cutover body can authorize, and this returns it only after the
/// presented body has been proved to be the body the admitted envelope commits
/// to. A separately supplied selector therefore authorizes nothing — it can
/// only agree with, or disagree with, what the admitted payload proves, and a
/// valid selector can never override an unrelated admitted body.
///
/// # Errors
///
/// Returns [`CutoverError`] when the presented request is not a cutover body
/// the admitted envelope committed to, or when the claimed operation request
/// digest is not the one that body derives.
pub fn admitted_cutover_operation(
    request: &CutoverRequest,
) -> Result<BackupOperationKind, CutoverError> {
    bind_admitted_cutover_body(request)?;
    Ok(BackupOperationKind::AdmitCutover)
}

/// Validates the authenticated identity of one cutover request, and nothing else.
///
/// This is the FIRST gate on every cutover path, deliberately separated from
/// the retained-operation lookup and from admission of a new cutover. The
/// retained-operation classification reports a typed difference between "no
/// such operation", "terminally refused" and "same key, different content",
/// so running it before this gate would turn those into a pre-authentication
/// oracle on an unauthenticated presented operation id. Authentication first,
/// classification second.
pub fn validate_cutover_identity(request: &CutoverRequest) -> Result<(), CutoverError> {
    request
        .envelope
        .validate()
        .map_err(|error| CutoverError::NotSeparatelyAdmitted(error.to_string()))?;
    if request.envelope.kind != HostRequestKind::Invocation {
        return Err(CutoverError::NotSeparatelyAdmitted(
            "cutover requires an Invocation-kind admitted envelope".to_owned(),
        ));
    }
    if request.admission.operation_id != host_request_operation_id(&request.envelope) {
        // A restore-test/rehearsal envelope (or any changed envelope)
        // derives a different digest-bound handle: it can never present
        // this cutover admission.
        return Err(CutoverError::RehearsalCannotCutover);
    }
    // The owner's own receipt-to-envelope binding replaces the hand-rolled
    // field-by-field comparison: `validate_envelope` validates the receipt and
    // the envelope and then requires the receipt to name exactly this envelope
    // (operation handle, request id, kind, connection, request digest and
    // deadline), so a receipt that is internally self-consistent but was issued
    // for a different envelope cannot be substituted here.
    request
        .admission
        .validate_envelope(&request.envelope)
        .map_err(|error| CutoverError::NotSeparatelyAdmitted(error.to_string()))?;
    Ok(())
}

/// Resolves one cutover attempt against the durable owners, under its ORIGINAL
/// operation identity, and BEFORE any fresh-activation gate.
///
/// A terminal refusal and an identity conflict are returned as errors here
/// because no plan can execute them: re-running a refused operation would
/// contradict the journal, and a reused key under different content must
/// perform no transition (I5.27).
pub fn plan_cutover_attempt(
    host: &HostComposition,
    request: &CutoverRequest,
    registry: &ApprovedGenerationRegistry,
) -> Result<CutoverAttemptPlan, CutoverError> {
    let snapshot = host.journal.snapshot().map_err(|error| {
        note_cutover_error(
            "plan",
            CutoverError::HostTransition(HostError::OwnerLeaseRecovery(error.to_string())),
        )
    })?;
    let retained = classify_retained_cutover(snapshot.pending_cutover.as_ref(), &request.operation);
    let plan = match retained {
        RetainedCutoverOperation::IdentityConflict => {
            return Err(note_cutover_error("plan", CutoverError::IdentityConflict));
        }
        RetainedCutoverOperation::Refused => {
            return Err(note_cutover_error(
                "plan",
                CutoverError::NotSeparatelyAdmitted(
                    "cutover operation is terminally refused; a new attempt requires a new \
                     separately admitted operation identity"
                        .to_owned(),
                ),
            ));
        }
        // A foreign outstanding intent does not make this attempt fresh or
        // stale: it is not evidence about this operation, so this operation is
        // admitted on its own merits and the expected-predecessor gate applies.
        // Safety of proceeding while a FOREIGN `Pending` intent is outstanding
        // rests on the journal owner's own reducer, which refuses a second
        // `Pending` intent for a distinct operation
        // (`eliot_host_state::journal`, the `CutoverIntent` arm), so the
        // foreign record is never overwritten and no CAS is reached.
        RetainedCutoverOperation::Absent | RetainedCutoverOperation::Foreign => {
            CutoverAttemptPlan::Fresh
        }
        RetainedCutoverOperation::Committed => CutoverAttemptPlan::ReplayCommitted,
        RetainedCutoverOperation::Pending => {
            // `classify_retained_cutover` reached this arm only after an exact
            // replay match on all three identity fields, so this lookup is
            // total: it can only fail if the two reads disagree, which the
            // journal's single-writer projection makes impossible.
            let intent = snapshot
                .pending_cutover
                .as_ref()
                .ok_or_else(|| note_cutover_error("plan", CutoverError::IdentityConflict))?;
            match resolve_cutover_activation(
                registry.committed_cutover_activation(),
                registry.active_generation(),
                intent,
                &request.operation,
            ) {
                CutoverActivationResolution::Committed => CutoverAttemptPlan::SettleCommitted,
                CutoverActivationResolution::NotApplied => CutoverAttemptPlan::ResumeFresh,
                CutoverActivationResolution::Unresolved => CutoverAttemptPlan::RetainUnknown,
            }
        }
    };
    Ok(plan)
}

/// # Errors
///
/// Validates one exact cutover request against current owner evidence.
///
/// Real owner calls: `envelope.validate()`,
/// `admission.validate_envelope(&envelope)` (the owner's own receipt-to-envelope
/// binding, which also proves a rehearsal envelope's different `hostreq:` handle
/// can never present this admission, never as cutover),
/// `BackupCutoverPayload::validate` plus
/// `BackupCutoverPayload::validate_admitted_payload(&envelope)` for the content
/// commitment of the whole body, `BackupCutoverPayload::operation_request_digest`
/// for the operation identity domain, `RestoreReceipt::validate` (which itself
/// rejects `cutover_performed` with `CutoverNotAuthorized`),
/// `OperationalValidationEvidence::validate`, and the class ceiling through
/// `BackupClass::evidence_level`.
/// Fail-closed gates: the complete cutover body bound to the admitted envelope
/// and to its claimed operation digest before any other gate; separately
/// admitted `Invocation` envelope whose fence exactly matches the activation
/// fence; bindings exact, including the receipt's bundle digest, restored fence,
/// and class ceiling against the request; scope transfers rejected; degraded
/// policy explicit, never upgraded; every mandatory phase receipt current;
/// complete denominators; fresh purge/key/reference plus external-source
/// revalidation; every prior introduction row fenced (lease quiescence proven
/// separately by the barrier); observed operational-validation fence exact;
/// expected predecessor and approved target match the registry projection.
///
/// # Errors
///
/// Returns the exact failing gate. Nothing is activated here.
///
/// `predecessor_gate` is derived by [`plan_cutover_attempt`] from the durable
/// retained-operation classification, so it is never a caller assertion: only
/// a genuinely fresh activation requires the active generation to still equal
/// the expected predecessor.
///
/// The outcome is observed once: success repeats the validated disposition,
/// and each refusal carries its exact typed category. No request, evidence,
/// or receipt string is logged.
pub fn validate_cutover_request(
    request: &CutoverRequest,
    evidence: &IsolatedRecoveryEvidence,
    registry: &ApprovedGenerationRegistry,
    predecessor_gate: PredecessorGate,
) -> Result<ValidatedCutover, CutoverError> {
    match validate_cutover_request_inner(request, evidence, registry, predecessor_gate) {
        Ok(validated) => {
            observe_cutover_progress(
                "validate",
                "validated",
                "validated",
                backup_cutover_count(validated.evidence().fenced_introductions.len()),
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
    predecessor_gate: PredecessorGate,
) -> Result<ValidatedCutover, CutoverError> {
    validate_cutover_identity(request)?;
    // The complete cutover body is built and bound to the admitted envelope
    // before every other gate. Nothing below can be reached with a body the
    // owner did not admit: an unrelated but valid admitted `Invocation`, a
    // changed body carrying the old envelope commitment, and a changed body
    // carrying the old claimed operation digest all refuse here, before the
    // fence, class, receipt, evidence, registry, and predecessor gates and
    // therefore long before any journal mutation or CAS.
    let body = bind_admitted_cutover_body(request)?;
    if !fences_match_exact(&request.envelope.state_fence, &request.activation_fence) {
        return Err(CutoverError::BindingMismatch);
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
    // The expected-predecessor gate governs a genuinely fresh activation only.
    // It is false by construction once a retained operation of this exact
    // identity has committed, so evaluating it unconditionally is what made an
    // exact committed retry and an interrupted post-CAS operation permanently
    // unrecoverable. The gate is derived from the durable retained-operation
    // classification, never asserted by a caller.
    if predecessor_gate == PredecessorGate::Required {
        match registry.active_generation() {
            Some(active) if *active == request.expected_predecessor => {}
            Some(_) | None => return Err(CutoverError::ExpectedPredecessorConflict),
        }
    }
    ValidatedCutover::seal(request, evidence, body)
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
/// operations return `Ok(false)`. Both sides are operation identities, never
/// whole requests, so the retained durable record and the candidate attempt
/// are compared on the same three identity fields.
pub fn check_replay_identity(
    committed: &CutoverOperationIdentity,
    candidate: &CutoverOperationIdentity,
) -> Result<bool, CutoverError> {
    if candidate.operation_id != committed.operation_id {
        return Ok(false);
    }
    if candidate.installation != committed.installation
        || candidate.request_digest != committed.request_digest
    {
        return Err(CutoverError::IdentityConflict);
    }
    Ok(true)
}

/// Executes the cutover lifecycle against the Host owner.
///
/// Real owner calls, in order: `HostComposition::ensure_admission_open`;
/// `BackupCutoverPayload::validate_admitted_payload` against the admitted
/// envelope again, at this effect boundary, so the activation runs only
/// against the exact body the owner admitted; fresh registry readback through
/// `super::open_registry_store_at` plus
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
/// The intent record, the registry operation binding and the returned outcome
/// are all built from the retained validated body, so the per-phase journal
/// mutation identities remain distinct from the operation identity they key
/// (`<operation>:<disposition>`) and both are derived from that body rather
/// than from presented text.
///
/// Lost response, failure between registry/authority/route transitions, or
/// cancellation after possible activation is resolved under the attempt's
/// ORIGINAL operation identity, not by re-running the activation:
/// [`plan_cutover_attempt`] classifies the durable retained intent and the
/// registry's operation-bound receipt BEFORE any fresh-activation gate, so an
/// exact committed retry replays the observed outcome without a second CAS, a
/// `Pending` intent whose CAS provably committed has its terminal record
/// settled under the same per-phase journal mutation identity, a `Pending`
/// intent whose CAS never applied completes exactly as a fresh one would, and
/// an outcome the owners cannot establish is returned as the bounded
/// `Unknown` state. In every case: do not activate again, roll back blindly,
/// or mark both sides active/inactive from local assumptions (I5.27, I14.21).
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
    // Effect boundary: the retained body is proved against the admitted envelope
    // again before any journal mutation or registry CAS, so the activation runs
    // only against the exact body the owner admitted. This is the owner's own
    // cross-record join, not a caller-controlled trusted flag.
    validated.recheck_admitted_body()?;
    host.ensure_material_admission_open_for_target(&validated.request().target_generation, false)?;
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
    bind_approved_target(validated.request(), &fresh)?;
    // The retained operation and the registry's operation-bound outcome are
    // resolved BEFORE any fresh-activation gate, under this attempt's original
    // operation identity. The predecessor gate below then governs only the
    // plans that are genuinely fresh, so an exact committed retry and a
    // possibly-applied Pending intent are both reachable under their own
    // identity instead of being refused by a gate that can only be true before
    // the activation happened.
    let plan = plan_cutover_attempt(host, validated.request(), &fresh)?;
    if plan.requires_active_predecessor() {
        match fresh.active_generation() {
            Some(active) if *active == validated.request().expected_predecessor => {}
            Some(_) | None => return Err(CutoverError::ExpectedPredecessorConflict),
        }
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
            introduction.record().subject_id.as_str()
                == validated.request().user_broker_ref.as_str()
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
    if !fences_match_exact(
        &retirement.state_fence,
        &validated.request().activation_fence,
    ) {
        return Err(CutoverError::BindingMismatch);
    }
    let barrier = host
        .require_generation_retirement_barrier(retirement)
        .map_err(|error| CutoverError::BarrierDenied(error.to_string()))?;
    // The retained durable intent is re-read here for the evidence it carries,
    // never to decide: `plan_cutover_attempt` already resolved the attempt
    // under the operation's own identity from the same owner, and the
    // classification it produced is what selects the branch below. Reading the
    // record again only supplies the exact fields the durable owner recorded.
    let journal = host.journal.snapshot().map_err(|error| {
        CutoverError::HostTransition(HostError::OwnerLeaseRecovery(error.to_string()))
    })?;
    let retained_intent = journal.pending_cutover.as_ref().and_then(|intent| {
        matches!(
            plan,
            CutoverAttemptPlan::ReplayCommitted
                | CutoverAttemptPlan::SettleCommitted
                | CutoverAttemptPlan::ResumeFresh
                | CutoverAttemptPlan::RetainUnknown
        )
        .then(|| intent.clone())
    });
    drop(journal);
    if let Some(recovered) =
        recover_retained_cutover(host, validated, retirement, plan, retained_intent.as_ref())?
    {
        return Ok((recovered, barrier));
    }
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

/// Applies the recovery transition for a cutover attempt whose operation this
/// Host journal already retains, and returns `None` for the plans that must
/// still run the activation CAS.
///
/// `ResumeFresh` reaches the CAS on purpose: it is a genuinely fresh activation
/// of an operation whose earlier attempt provably never applied, so the same
/// operation completes it under the same identity with the predecessor gate
/// enforced above. No recovery path mutates the registry, rolls anything back,
/// or creates a new operation, and none of them is itself a retirement permit.
fn recover_retained_cutover(
    host: &HostComposition,
    validated: &ValidatedCutover,
    retirement: &GenerationRetirementFence,
    plan: CutoverAttemptPlan,
    retained_intent: Option<&CutoverIntentRecord>,
) -> Result<Option<CutoverOutcome>, CutoverError> {
    let outcome = match plan {
        CutoverAttemptPlan::Fresh | CutoverAttemptPlan::ResumeFresh => return Ok(None),
        CutoverAttemptPlan::ReplayCommitted => {
            // Observed replay of the same committed cutover, not a second
            // activation: the durable terminal record already proves it
            // happened, so the registry is not mutated again.
            let committed = retained_intent
                .ok_or_else(|| note_cutover_error("execute", CutoverError::IdentityConflict))?;
            let evidence_refs = bounded_evidence(vec![
                admission_handle(&validated.request().admission)?,
                committed.target_generation.clone(),
            ]);
            observe_cutover_progress(
                "execute",
                "replay_observed",
                "committed",
                backup_cutover_count(evidence_refs.len()),
            );
            CutoverOutcome {
                disposition: CutoverDisposition::Committed,
                residual: CutoverResidual::None,
                operation: validated.sealed_operation()?,
                evidence_refs,
            }
        }
        CutoverAttemptPlan::SettleCommitted => {
            // The registry's operation-bound receipt proves this operation's
            // CAS committed, while the journal's terminal record never became
            // durable. Settle that record under the ORIGINAL identity and the
            // existing per-phase journal mutation identity, so a retry appends
            // byte-identical bytes and replays instead of forking a second
            // transaction.
            let intent = retained_intent
                .ok_or_else(|| note_cutover_error("execute", CutoverError::IdentityConflict))?;
            let outcome = settle_committed_pending_activation(host, validated, retirement, intent)?;
            observe_cutover_progress(
                "execute",
                "recovered_commit",
                "committed",
                backup_cutover_count(outcome.evidence_refs.len()),
            );
            outcome
        }
        CutoverAttemptPlan::RetainUnknown => {
            // The owners cannot establish whether this operation's activation
            // committed. The operation, its retained intent and its
            // predecessor requirement are preserved and the bounded unknown
            // state is returned for evidence-backed reconciliation; no effect
            // is inferred from the storage condition, nothing is rolled back,
            // and no new operation is created to escape it (I14.21).
            let intent = retained_intent
                .ok_or_else(|| note_cutover_error("execute", CutoverError::IdentityConflict))?;
            let outcome = unresolved_cutover_outcome(validated, intent)?;
            observe_cutover_progress(
                "execute",
                "retained_unknown",
                "unknown",
                backup_cutover_count(outcome.evidence_refs.len()),
            );
            outcome
        }
    };
    Ok(Some(outcome))
}

/// Settles a possibly-applied cutover activation under its ORIGINAL operation
/// identity, without a second registry mutation, a rollback, or a new
/// operation.
///
/// The registry's operation-bound receipt has already established that this
/// operation's CAS committed; only the journal's terminal record is missing,
/// because the append that follows the CAS failed. The terminal is written
/// through the same per-phase journal mutation identity
/// (`<cutover operation>:committed`) with the same idempotency key, so a retry
/// appends byte-identical record bytes and replays instead of forking a second
/// transaction. Retirement stays separately authorized: this records the
/// activation, it never retires the predecessor.
fn settle_committed_pending_activation(
    host: &HostComposition,
    validated: &ValidatedCutover,
    retirement: &GenerationRetirementFence,
    intent: &CutoverIntentRecord,
) -> Result<CutoverOutcome, CutoverError> {
    if intent.state != CutoverIntentState::Pending {
        return Err(note_cutover_error("settle", CutoverError::IdentityConflict));
    }
    let terminal = append_cutover_intent(
        host,
        validated,
        retirement,
        CutoverIntentState::Committed,
        &validated.request().admission,
    )?;
    Ok(CutoverOutcome {
        disposition: CutoverDisposition::Committed,
        residual: CutoverResidual::None,
        operation: validated.sealed_operation()?,
        evidence_refs: bounded_evidence(vec![
            admission_handle(&validated.request().admission)?,
            intent.target_generation.clone(),
            terminal,
        ]),
    })
}

/// The bounded recoverable state for an operation whose activation outcome the
/// owners cannot establish.
///
/// The original operation identity and the retained intent's own predecessor
/// and target are carried as evidence so the next reconciliation reads the
/// same owners under the same identity. Nothing here asserts an effect: the
/// disposition is `Unknown`, which is the documented bounded reconciliation
/// state for a lost response or a crash between the registry and the journal
/// (I14.21), and the residual names the preserved uncertainty explicitly.
fn unresolved_cutover_outcome(
    validated: &ValidatedCutover,
    intent: &CutoverIntentRecord,
) -> Result<CutoverOutcome, CutoverError> {
    Ok(CutoverOutcome {
        disposition: CutoverDisposition::Unknown,
        residual: CutoverResidual::ActivationOutcomeUnestablished,
        operation: validated.sealed_operation()?,
        evidence_refs: bounded_evidence(vec![
            intent.cutover_operation.clone(),
            intent.expected_predecessor.clone(),
            intent.target_generation.clone(),
        ]),
    })
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
    let presented = &validated.evidence().fenced_introductions;
    let live = super::introduction_readback::read_live_introductions(
        host,
        &validated.request().activation_fence,
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
        &validated.request().admission,
    )?;
    // The registry owner is re-opened here, after the durable intent, so the
    // handle is held only across the single bounded CAS. The operation binding
    // travels with the CAS so the registry durably records WHICH cutover
    // operation performed the flip: recovery resolves a possibly-applied
    // activation under the original identity from that record, and an
    // active-generation pointer alone attributes the flip to nobody.
    let store = host.open_registry_store()?;
    let capability = host.owner_lease.activation_capability();
    // The registry's operation binding is the sealed body's own identity, so a
    // recovery readback attributes the flip to this body and never to presented
    // text that a later attempt could restate.
    let operation = validated.sealed_operation()?;
    let committed = store.commit_cutover_activation(
        &capability,
        expected_revision,
        &validated.request().expected_predecessor,
        &validated.request().target_generation,
        &CommittedCutoverActivation {
            installation: operation.installation.clone(),
            operation_id: operation.operation_id.clone(),
            request_digest: operation.request_digest.clone(),
            expected_predecessor: validated.request().expected_predecessor.clone(),
            target_generation: validated.request().target_generation.clone(),
        },
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
        &validated.request().admission,
    );
    if let Some(refusal) = refusal {
        return Err(CutoverError::Registry(refusal));
    }
    terminal_receipt?;
    Ok(CutoverOutcome {
        disposition: CutoverDisposition::Committed,
        residual: CutoverResidual::None,
        operation,
        evidence_refs: bounded_evidence(vec![
            admission_handle(&validated.request().admission)?,
            activation_id.clone(),
            validated.request().target_generation.clone(),
            intent,
        ]),
    })
}

/// Reads the exact cutover disposition for one operation from the real owners.
///
/// This is the implementation behind
/// [`crate::HostComposition::backup_dispatch_cutover_disposition`]. It
/// re-reads the Host journal's own durable cutover projection, the
/// installation registry's active generation and operation-bound cutover
/// receipt, and — through `resolve_cutover_retirement` — the retirement record
/// this journal actually applied for this exact cutover operation. All of it is
/// projected through [`reconcile_cutover_outcome`], so the returned disposition
/// is the exact state the owners established for this operation rather than a
/// local assumption, and the returned `residual` names whatever uncertainty the
/// owners left behind. This function cannot return `Validated` or `Committed`
/// (see [`reconcile_cutover_outcome`]); an unqualified read answers `Requested`.
///
/// `retirement_receipt` is a LOOKUP HINT, never the proof — the retirement is
/// resolved through the journal owner, and the presented receipt only has to
/// agree with the owner's own transaction identity.
///
/// The Host journal and the installation registry are separate durable owners
/// with no shared transaction, so this read proves the pair it projects was one
/// moment: it samples the journal, loads the registry, re-reads the journal,
/// resolves the retirement through the journal owner, and re-reads the journal
/// once more, so the owner query is bracketed on BOTH sides as well and the pair
/// is re-sampled and the retirement re-resolved on every retry. A pair that will
/// not settle inside the bounded `CUTOVER_DISPOSITION_READ_ATTEMPTS` attempts
/// is reported as [`OwnerObservationCoherence::Moving`], which withholds every
/// effect- and history-bearing disposition instead of combining a torn read into
/// a state that never existed. A journal read that FAILS is an error and is
/// never reported as movement.
///
/// Strictly read-only: no journal append, no registry mutation, no activation,
/// no retirement, and no recovery settlement.
///
/// # Errors
///
/// Returns [`HostError`] when the durable Host journal or the installation
/// registry cannot be read, and when the journal owner cannot resolve the
/// queried retirement. A failed read is an error, never a disposition:
/// reporting a state the owners did not prove is exactly the local assumption
/// this function exists to remove.
pub fn read_cutover_disposition(
    host: &HostComposition,
    request: &CutoverRequest,
    retirement_receipt: Option<&AppendReceipt>,
) -> Result<CutoverOutcome, HostError> {
    let mut attempt = 0_u8;
    let (snapshot, registry, retirement, coherence) = loop {
        attempt = attempt.saturating_add(1);
        let first = host
            .journal
            .snapshot()
            .map_err(|error| note_cutover_read_error(super::HostError::from(error)))?;
        let loaded = host
            .open_registry_store()
            .map_err(note_cutover_read_error)?
            .load()
            .map_err(|error| HostError::Platform(error.to_string()))
            .map_err(note_cutover_read_error)?;
        // The cutover-relevant projection is the binding axis. The journal's
        // global sequence/last_checksum are deliberately NOT used: they advance
        // for every applied record of any kind, so they would report ordinary
        // Host traffic as owner movement.
        let second = host
            .journal
            .snapshot()
            .map_err(|error| note_cutover_read_error(super::HostError::from(error)))?;
        // The retirement is resolved by the SAME journal owner through a third
        // read, so it is bracketed on its far side too. Resolving it outside the
        // compared interval would let a record that landed after the second
        // sample be combined with a pair that never held it — the stale-currency
        // form of the same defect, and the one that would let a completed
        // retirement be read as still owed. The retirement is resolved FROM
        // `second`, and the third sample exists only to prove that `second` is
        // still current; the mapper therefore receives both journal-derived
        // inputs from one read.
        let retirement = resolve_cutover_retirement(host, &second, request, retirement_receipt)
            .map_err(note_cutover_read_error)?;
        let third = host
            .journal
            .snapshot()
            .map_err(|error| note_cutover_read_error(super::HostError::from(error)))?;
        if cutover_observation_unchanged(&first, &second)
            && cutover_observation_unchanged(&second, &third)
        {
            break (
                second,
                loaded,
                retirement,
                OwnerObservationCoherence::Coherent,
            );
        }
        observe_cutover_progress(
            "read_disposition",
            "recheck",
            "owner_moved",
            backup_cutover_count(usize::from(attempt)),
        );
        if attempt >= CUTOVER_DISPOSITION_READ_ATTEMPTS {
            // The last pair read is the one reported, and it is reported as
            // movement: the read is not discarded, and it is not presented as a
            // settled moment either. `second` is still the sample the retirement
            // was resolved from, so the reported pair and the reported evidence
            // come from the same read even while the interval is torn.
            break (
                second,
                loaded,
                retirement,
                OwnerObservationCoherence::Moving,
            );
        }
    };
    Ok(reconcile_cutover_outcome(
        request,
        snapshot.pending_cutover.as_ref(),
        registry.committed_cutover_activation(),
        registry.active_generation(),
        &retirement,
        coherence,
    ))
}

/// Resolves this operation's prior-generation retirement through the Host
/// journal owner and re-proves it against the request it is reported for.
///
/// The lookup identity is the cutover operation's own: the operation id with
/// the retained canonical request digest, which is exactly the
/// `IdempotencyIdentity` `retire_prior_generation` wrote into the durable
/// record. The journal owner selects the record from the log it replayed,
/// recomputes that record's transaction identity with its own algorithm, and
/// answers a typed absence, a typed contradiction, or the observation. Nothing
/// here selects a record from presented text.
///
/// A presented `AppendReceipt` is a hint and nothing more. It proves that SOME
/// append happened — a sequence, a disposition, a transaction id — and never
/// which record kind produced it, so it is believed only when it names the
/// owner's own transaction identity for this operation. A genuine receipt from
/// another append, or from another record kind, is explicit absence. That is
/// why an unrelated genuine receipt can never reach `Reconciled`.
///
/// The resolved record is then re-proved here against this request, from the
/// record's OWN durable fields: the exact operation it was applied under, the
/// installation/Host lineage, a genuinely prior epoch, the Host epoch whose
/// projection retained it, the target and approved facts the retirement
/// recorded, and — since #2868 — the stored predecessor-generation relation that
/// must map this request's exact `expected_predecessor` onto the exact retired
/// epoch. The single cutover-intent slot is a current-applicability pointer, so
/// it corroborates the retirement when it still holds this operation's own
/// intent and is otherwise ignored — it can never be the reason an authentic
/// past retirement is reported as somebody else's.
///
/// A record that fails any of those re-proofs is `Unbound` — a rejected
/// substitution, reported explicitly rather than read as this cutover's effect.
/// A record that passes every one of them but carries no predecessor relation is
/// the separate `RelationUnproven` state: not a substitution, and not an exact
/// completion either, because the retired epoch was never shown to be the one
/// the cutover consumed.
///
/// # Errors
///
/// Returns [`HostError`] when the journal owner cannot be read, cannot
/// recompute the resolved record's transaction identity, or when the query
/// names a malformed operation identity. A failed owner read is an error, never
/// a disposition.
pub(crate) fn resolve_cutover_retirement(
    host: &HostComposition,
    state: &HostState,
    request: &CutoverRequest,
    presented_receipt: Option<&AppendReceipt>,
) -> Result<CutoverRetirementEvidence, HostError> {
    let operation = IdempotencyIdentity {
        operation_id: request.operation.operation_id.clone(),
        idempotency_key: request.operation.request_digest.clone(),
    };
    let observation = match host.journal.query_epoch_retirement(&EpochRetirementQuery {
        operation: operation.clone(),
    }) {
        Ok(observation) => observation,
        Err(EpochRetirementQueryError::NotFound) => {
            return Ok(CutoverRetirementEvidence::Absent);
        }
        Err(EpochRetirementQueryError::Contradictory) => {
            return Ok(CutoverRetirementEvidence::Contradictory);
        }
        Err(EpochRetirementQueryError::Journal(error)) => {
            return Err(HostError::Journal(error));
        }
        Err(error @ EpochRetirementQueryError::Invalid(_)) => {
            return Err(HostError::Journal(JournalError::Invalid(error.to_string())));
        }
    };
    // The hint must name the identity the OWNER computed for the record it
    // resolved. A receipt naming anything else is explicit absence: it is not
    // this operation's retirement, however genuine the append behind it was.
    if presented_receipt
        .is_some_and(|receipt| receipt.transaction_id() != observation.transaction_id())
    {
        return Ok(CutoverRetirementEvidence::Absent);
    }
    match retirement_binds_request(state, request, &operation, &observation) {
        RetirementBinding::Exact => Ok(CutoverRetirementEvidence::Resolved(
            BoundRetirementEvidence::bind(
                &request.operation,
                observation.transaction_id(),
                observation.retirement_evidence_refs(),
            ),
        )),
        // A legacy record with every other binding in agreement is neither a
        // substitution nor an exact completion, and reporting it as either would
        // be a false claim in one direction or the other (#2868).
        RetirementBinding::WithoutPredecessorRelation => {
            Ok(CutoverRetirementEvidence::RelationUnproven)
        }
        RetirementBinding::NotThisRequestsRetirement => Ok(CutoverRetirementEvidence::Unbound),
    }
}

/// Re-proves one owner-resolved retirement against the request it is reported
/// for: the operation it was applied under, the installation and Host lineage,
/// the prior epoch it retired, the activation fence it was accepted under, and
/// the evidence it recorded.
///
/// The join is taken from the DURABLE RETIREMENT RECORD, not from the cutover
/// intent projection. `HostState::pending_cutover` is a single slot, and the
/// journal reducer replaces it with a later operation's intent as soon as the
/// previous intent is terminal (`eliot_host_state::journal`, the `CutoverIntent`
/// arm, `state.pending_cutover = Some(next)`), so a later LEGITIMATE cutover
/// erases this operation's intent from the projection while
/// `HostState::epoch_retirements` still retains the exact record. Reading the
/// intent slot as the proof of ownership therefore destroyed an authentic past
/// retirement the moment any later operation was admitted. The retirement
/// record itself is the history, and it is what this function proves.
///
/// What the record carries, and is proved here:
///
/// * the exact operation identity the owner resolved it under — the cutover
///   operation id AND the retained canonical request digest, so a record
///   applied under a different operation or a different canonical body is not
///   this request's retirement;
/// * the installation lineage and a genuinely prior Host epoch of that
///   installation, re-read from the same owner that refused an epoch it did not
///   retain when the record was appended;
/// * the Host epoch the record was accepted under, which the owner's reducer
///   already requires to equal the epoch that replayed the log
///   (`record.fence().host != state.host` is refused there);
/// * the target generation, `UserBroker` identity, and the approved build and
///   configuration digests the retirement was authorized with, so a record
///   applied under a reused operation identity but for different approved facts
///   is rejected;
/// * the stored predecessor-generation relation, which must map this request's
///   exact `expected_predecessor` onto the exact retired epoch (#2868).
///
/// A record written before that relation existed reports
/// [`RetirementBinding::WithoutPredecessorRelation`], never
/// [`RetirementBinding::Exact`]. Such a record is genuine history and is never
/// erased, but its proof ceiling is lower: it establishes that the retired
/// epoch was a prior outstanding epoch of this installation, and never that the
/// epoch was the one which carried the predecessor generation. Before #2868 the
/// relation had no representation at all, so this comparison simply did not
/// exist and every such record was read as exact.
///
/// The intent projection is consulted for two things, and never as proof that
/// THIS operation is foreign:
///
/// * when the slot still holds this operation's own intent, that record — a
///   second durable record written under the same operation identity — must
///   join the retirement on all five binding fields and on the same activation
///   fence, and a disagreement refuses the retirement;
/// * when the slot names THIS operation id with different content, that is an
///   `IDENTITY_CONFLICT` under one operation key (I5.27) and the retirement is
///   refused rather than reported.
///
/// A slot holding a DIFFERENT operation's intent is current applicability, not
/// this operation's history: it is neither corroboration nor refutation, and it
/// cannot erase the record. The mapper reports that the intent is no longer
/// retained through [`CutoverResidual::RetirementWithoutRetainedIntent`].
///
/// # Errors
///
/// This function cannot fail. Every answer it returns is a decision about
/// already-durable owner facts, so a storage failure is not something it can
/// observe and must not be modelled as one of its three states.
fn retirement_binds_request(
    state: &HostState,
    request: &CutoverRequest,
    operation: &IdempotencyIdentity,
    observation: &EpochRetirementObservation,
) -> RetirementBinding {
    // The record must name the exact identity it was looked up under: a
    // comparison between two different records, not a self-comparison. That
    // identity carries the cutover operation id AND the canonical request
    // digest, so this one comparison binds the operation and its body.
    if observation.operation() != operation {
        return RetirementBinding::NotThisRequestsRetirement;
    }
    let retired = observation.retired_host();
    if retired.installation != request.operation.installation
        || retired.installation != state.host.installation
        || retired.epoch == state.host.epoch
    {
        return RetirementBinding::NotThisRequestsRetirement;
    }
    if !state
        .retained_epochs
        .iter()
        .any(|retained| retained.host == *retired)
    {
        return RetirementBinding::NotThisRequestsRetirement;
    }
    // The fence the owner accepted the record under must belong to the Host
    // epoch that replayed this log. The owner's reducer already refuses any
    // record whose fence host is not the replaying epoch, so this re-reads the
    // same owner fact instead of introducing a second source of truth.
    if observation.fence().host != state.host {
        return RetirementBinding::NotThisRequestsRetirement;
    }
    if let Some(intent) = state.pending_cutover.as_ref() {
        if is_own_cutover_intent(
            intent,
            &request.operation,
            &request.target_generation,
            &request.expected_predecessor,
        ) {
            // Two records written under the same operation identity must name
            // the same activation, or one of them is not this cutover's.
            if intent.fence != *observation.fence() {
                return RetirementBinding::NotThisRequestsRetirement;
            }
        } else if intent.cutover_operation == request.operation.operation_id {
            // The retained intent names this operation id with different
            // content: an identity conflict, never this request's retirement.
            return RetirementBinding::NotThisRequestsRetirement;
        }
    }
    if !observation
        .retirement_evidence_refs()
        .contains(&request.target_generation)
        || !observation
            .retirement_evidence_refs()
            .contains(&request.user_broker_ref)
        || !observation
            .retirement_evidence_refs()
            .contains(&request.target_build_digest)
        || !observation
            .retirement_evidence_refs()
            .contains(&request.target_config_digest)
    {
        return RetirementBinding::NotThisRequestsRetirement;
    }
    // Every binding above is a property of the record's own fields and of this
    // Host journal. The one remaining question is the relation the effect itself
    // could not prove at write time: does the durable record state which
    // generation the retired epoch carried?
    //
    // Without it, the record proves the retired epoch was a genuinely prior
    // outstanding epoch of this installation - and nothing about which
    // generation it carried. That is exactly the reduced proof the retirement
    // effect itself documented, so reporting it as `Reconciled` would promote a
    // weaker fact to an exact completion. It is therefore a distinct,
    // lower-ceiling answer: history stays visible, and the disposition stays
    // `Unknown` (I5.13, I14.21, #2868).
    match observation.predecessor_relation() {
        Some(relation)
            if relation.maps_generation(
                &request.operation.installation,
                &request.expected_predecessor,
            ) && relation.retired_host == *retired =>
        {
            RetirementBinding::Exact
        }
        Some(_) => RetirementBinding::NotThisRequestsRetirement,
        None => RetirementBinding::WithoutPredecessorRelation,
    }
}

/// How far one owner-resolved retirement binds to the request it is reported for.
///
/// Three states, because "this is a substitution" and "this is the right record
/// with one binding missing" are different facts and must not share an answer
/// (#2868). A single boolean cannot express them: it would either report a
/// substitution that did not happen, or read a record whose retired epoch was
/// never shown to be the consumed predecessor as an exact completion.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RetirementBinding {
    /// Every binding agrees and the stored relation maps this request's exact
    /// expected predecessor generation onto the exact retired epoch.
    Exact,
    /// Every binding agrees except the predecessor-generation relation, which
    /// the durable record does not carry. Legacy history, lower proof ceiling.
    WithoutPredecessorRelation,
    /// The record is not this request's retirement: a substituted installation,
    /// epoch, fence, operation identity or evidence set. A journal holding MORE
    /// THAN ONE retirement for one operation identity is decided earlier, as
    /// [`CutoverRetirementEvidence::Contradictory`], because that is a
    /// contradiction about durable state rather than a substitution.
    NotThisRequestsRetirement,
}

/// Whether one durable cutover intent is this exact request's retained
/// commitment.
///
/// The join is explicit over all five identity and binding fields: the cutover
/// operation, the installation, the retained canonical request digest, the
/// retained TARGET generation, and the retained EXPECTED PREDECESSOR. Anything
/// less lets a substituted target or predecessor read as this operation's
/// progress, which is exactly the substitution this comparison exists to
/// reject (I5.27).
///
/// A `false` answer is NOT evidence that this operation is foreign. The only
/// place the journal owner retains a cutover intent is the single
/// `HostState::pending_cutover` slot, which a later legitimate operation
/// replaces once the previous intent is terminal, so `false` may equally mean
/// "this operation's intent is no longer retained". Callers must therefore never
/// read a `false` answer as a refutation of this operation's own durable
/// history; [`retirement_binds_request`] uses this join only to corroborate a
/// record that already binds on its own fields, and the mapper uses it only for
/// the current applicability of the pointer.
fn is_own_cutover_intent(
    intent: &CutoverIntentRecord,
    operation: &CutoverOperationIdentity,
    target_generation: &PlatformHandle,
    expected_predecessor: &PlatformHandle,
) -> bool {
    intent.cutover_operation == operation.operation_id
        && intent.installation == operation.installation
        && intent.request_digest == operation.request_digest
        && intent.target_generation == *target_generation
        && intent.expected_predecessor == *expected_predecessor
}

/// Whether the registry's own operation-bound receipt attributes the observed
/// active-generation flip to exactly this operation and target.
///
/// The registry's receipt, never its active-generation pointer, is what names
/// the operation that performed a flip (#2737). A pointer alone attributes
/// nothing: an installer commit and another operation's cutover to the same
/// target produce the same pointer.
fn registry_activation_binds_this_operation(
    committed_activation: Option<&CommittedCutoverActivation>,
    operation: &CutoverOperationIdentity,
    target_generation: &PlatformHandle,
) -> bool {
    committed_activation.is_some_and(|receipt| {
        receipt.operation_id == operation.operation_id
            && receipt.installation == operation.installation
            && receipt.request_digest == operation.request_digest
            && receipt.target_generation == *target_generation
    })
}

/// What the current durable owners can prove about which Host epoch carried one
/// cutover's exact expected predecessor generation (#2868).
///
/// The installation registry owns generations; the Host journal owns epochs.
/// Neither durable owner carries both, so this is a two-state answer and the
/// negative case is a first-class outcome rather than a fallback.
///
/// The relation is boxed because it is a full durable record and the other arm
/// carries nothing; keeping it inline would make every value of this enum as
/// large as the record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PredecessorRelationResolution {
    /// An owner-issued relation maps this cutover's exact expected predecessor
    /// generation onto one exact outstanding Host epoch of this installation.
    Bound(Box<PredecessorRetirementRelation>),
    /// No owner establishes the relation.
    Unavailable,
}

/// Resolves the predecessor-generation-to-Host-epoch relation for one cutover
/// from the durable owners, before any retirement record is written.
///
/// The epoch to retire is **derived here, never presented**. Before #2868 the
/// effect accepted a caller-selected `prior_host` and proved only that it was
/// *some* unretired prior epoch of the same installation, so with two
/// outstanding prior epochs the cutover could retire one and later report the
/// other as the consumed predecessor's completion. Nothing may be selected
/// independently, so the retired epoch is whatever the owners name and nothing
/// else.
///
/// # Why the answer is currently `Unavailable`
///
/// The owner that relates a generation to a Host epoch **does exist**, and it
/// is the approved-generation/Host-activation handoff #2868 item 1 asks to
/// reuse. In `crates/kernel/eliot-installation/src/approved_generation_registry.rs`:
///
/// * `ActivationCommitFence.generation` is the approved installation generation
///   as a `PlatformHandle` - the same handle a cutover presents;
/// * its `phase_b_live_binding: Option<PhaseBLiveBinding>` is **mandatory on
///   every committed activation** (`ActivationCommitFence::validate` returns
///   `IncompleteObservation` without it), and `PhaseBLiveBinding` carries
///   `host_owner_epoch`, `host_epoch_lineage`, `host_epoch_sequence` and
///   `host_process_nonce_digest`;
/// * `validate()` already proves the join internally:
///   `provisioned_supervision_authority.candidate_generation == generation`.
///
/// So the join is constructed and owner-checked - for the generation of the
/// activation being committed. It cannot answer a PREDECESSOR retirement, for
/// two reasons that are properties of the current owners rather than of this
/// function:
///
/// 1. **Retention.** The registry keeps exactly one such fence -
///    `last_terminal_activation.commit_fence`, read through
///    `last_committed_activation_fence()`, the only public reader of that slot.
///    Staging a new approved generation clears the slot, and staging the target
///    is a prerequisite of the cutover's registry CAS, so by the time
///    retirement is authorized the predecessor's generation-to-epoch join is no
///    longer retained anywhere. (`activate`, which performs the flip, does not
///    clear it - staging does, earlier.)
/// 2. **Shape.** The fence describes the activation being COMMITTED, so it
///    carries no activation id, activation lineage, issuer, or issuance instant
///    for the epoch being RETIRED. Filling those in would mean inventing values,
///    which is exactly what a proof-of-mapping record must never do.
///
/// The Host journal cannot supply the missing side either. Its one record that
/// names installation generations is `CutoverIntentRecord`
/// (`expected_predecessor`, `target_generation`), and that binding runs the
/// wrong way: its `RecordFence` ties those generations to the epoch that
/// PERFORMED the cutover, never to the epoch that CARRIED the predecessor
/// generation. `EpochEvidence` is rebuilt from replayed log bytes and reducer
/// state without access to any record body, so it cannot carry a generation
/// either.
///
/// The join therefore has no owner for this question, and this returns
/// [`PredecessorRelationResolution::Unavailable`]. That is #2868 item 6's
/// prescribed outcome, not a guess and not a storage error: the caller refuses
/// the effect, reports a typed residual and appends nothing (I5.13, A13.7,
/// I14.21). The `Bound` arm is the seam an owner correction fills - it needs a
/// per-generation activation fence (or a predecessor-retaining one), and no
/// further change to the effect.
///
/// The parameters are intentionally unused: reading an owner whose answer
/// cannot change the result, and calling that a measurement, would be exactly
/// the kind of claim this repository rejects.
pub fn resolve_predecessor_retirement_relation(
    _host: &HostComposition,
    _request: &CutoverRequest,
) -> PredecessorRelationResolution {
    PredecessorRelationResolution::Unavailable
}

/// Runs the separately authorized prior-generation retirement that completes
/// one committed cutover.
///
/// This is the implementation behind
/// [`crate::HostComposition::backup_dispatch_cutover_retire`]; it owns no
/// algorithm. Retirement is never automatic cleanup: the caller must present
/// the barrier returned by the cutover dispatch for the same operation and an
/// explicit non-empty retirement authorization. The epoch to retire is **not** a
/// parameter - it is derived from the owners by
/// [`resolve_predecessor_retirement_relation`].
///
/// The gate is the **durable committed cutover intent**, not the pre-activation
/// owner gate set: for a genuinely fresh activation
/// `validate_cutover_request` requires the active generation to still equal the
/// expected predecessor, which is by construction false once the activation
/// committed, so re-running it here could never succeed. The committed intent
/// is the owner's own record that the exact new state was applied.
///
/// The gate is therefore live only inside the Host epoch that performed the
/// cutover, because the intent record lives in that epoch's log. After a
/// restart the intent is gone and retirement must be re-authorized against the
/// registry readback by the owner surface; this function refuses rather than
/// inferring.
///
/// The presented request is **sealed** before any of that runs, and the seal
/// runs the authoritative admitted-payload check again: the body's canonical
/// content digest must equal the admitted envelope's `payload_sha256` under the
/// cutover payload schema, and the claimed operation request digest must be the
/// one that body derives. The durable intent is then matched against the sealed
/// body's own operation identity, not against presented text. A changed body
/// carrying the old admission or the old claimed digest is therefore refused
/// before the retirement record is read or appended, and no `ValidatedCutover`
/// can be built here or anywhere else without that check having succeeded.
///
/// # Relation unavailable
///
/// When the owners cannot relate the predecessor generation to a Host epoch, the
/// retirement effect is **refused before any record is appended** and a typed
/// `Unknown` + [`CutoverResidual::PredecessorEpochUnknown`] outcome is returned.
/// No outstanding epoch is retired and no journal or registry state changes, so
/// the pre-RETIREMENT state stays as it was; the cutover's own activation has
/// already committed, which is the earlier, separately authorized step (I5.13,
/// A13.7). This is the only honest outcome available while no owner retains
/// the relation: the previous gate accepted a caller-selected epoch and
/// reported `Reconciled` for a retirement whose retired epoch was never shown
/// to be the consumed predecessor's.
///
/// # Errors
///
/// Returns [`CutoverError`] when the presented body is not the body the
/// admitted envelope committed to, when this operation has no durable cutover
/// intent, when the intent has not committed (or was refused), when the
/// presented barrier does not belong to this cutover's activation, or when the
/// journal owner refuses the retirement record.
pub fn retire_authorized_generation(
    host: &HostComposition,
    request: &CutoverRequest,
    evidence: &IsolatedRecoveryEvidence,
    barrier: &GenerationRetirementBarrier,
    retirement_authorization: &PlatformHandle,
) -> Result<CutoverOutcome, CutoverError> {
    // Retirement is a protected transition, so it runs against a sealed body,
    // never against presented text. The seal re-proves the authoritative
    // admitted-payload join for the exact body presented here, so a changed
    // body carrying the old admission or the old claimed operation digest is
    // refused before the durable record is read and before the retirement
    // authorization is honoured. This replaces the previous fabrication of a
    // `ValidatedCutover` straight from unvalidated parameters: that value could
    // be built anywhere, and nothing in it had been checked against the owner's
    // admitted payload.
    let validated =
        ValidatedCutover::seal(request, evidence, bind_admitted_cutover_body(request)?)?;
    let operation = validated.sealed_operation()?;
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
            intent.cutover_operation == operation.operation_id
                && intent.installation == operation.installation
                && intent.request_digest == operation.request_digest
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
    // The epoch to retire is derived from the durable owners, never presented.
    // This runs BEFORE the outstanding-epoch scan below and before any record is
    // appended, because a scan cannot tell the owners apart: with two outstanding
    // prior epochs it is satisfied by either one, and picking the first match is
    // exactly the arbitrary retirement #2868 removes.
    let PredecessorRelationResolution::Bound(relation) =
        resolve_predecessor_retirement_relation(host, request)
    else {
        observe_cutover_progress("retire_authorize", "relation_unavailable", "unknown", 0);
        return Ok(CutoverOutcome {
            disposition: CutoverDisposition::Unknown,
            residual: CutoverResidual::PredecessorEpochUnknown,
            operation,
            evidence_refs: bounded_evidence(vec![
                intent.cutover_operation.clone(),
                request.expected_predecessor.clone(),
                request.target_generation.clone(),
            ]),
        });
    };
    let prior_host = relation.retired_host.clone();
    // The relation's epoch must still be one this Host journal retains,
    // unretired, and different from the epoch performing the cutover. The
    // relation establishes WHICH epoch carried the predecessor generation; this
    // re-reads the owner's own current retention state, and the journal reducer
    // re-checks the same condition on append.
    let outstanding = journal.retained_epochs.iter().any(|retained| {
        retained.host == prior_host
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
        &validated,
        barrier,
        &relation,
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
/// after it, all under the same operation identity. The record is built from
/// the retained validated body: its operation identity, idempotency key, and
/// carried bindings are the sealed body's own, and the evidence set includes
/// the body's checked canonical content digest, so a later reconciliation reads
/// the same body commitment from the durable owner instead of trusting a
/// console-presented value.
fn append_cutover_intent(
    host: &HostComposition,
    validated: &ValidatedCutover,
    retirement: &GenerationRetirementFence,
    state: CutoverIntentState,
    admission: &HostRequestAdmissionReceipt,
) -> Result<PlatformHandle, CutoverError> {
    let cutover_operation = validated.sealed_operation()?;
    // One journal mutation identity per disposition. The journal keys
    // `applied_operations` on this identity, so the intent and its terminal
    // record must not share one; a retry of the *same* disposition reuses it
    // and therefore replays byte-identically instead of forking a second
    // transaction (the same convention the Store-rebind seam uses). The base is
    // the body's own operation id, not a presented string.
    let mutation = PlatformHandle::new(format!(
        "{}:{}",
        cutover_operation.operation_id.as_str(),
        cutover_intent_state_spelling(state)
    ))
    .map_err(|_| CutoverError::BindingMismatch)?;
    let operation = IdempotencyIdentity {
        operation_id: mutation,
        idempotency_key: cutover_operation.request_digest.clone(),
    };
    let record = CutoverIntentRecord {
        fence: RecordFence {
            host: host.host.clone(),
            activation_id: retirement.activation_id.clone(),
            activation_generation: retirement.activation_generation.clone(),
        },
        operation,
        installation: cutover_operation.installation.clone(),
        cutover_operation: cutover_operation.operation_id.clone(),
        request_digest: cutover_operation.request_digest.clone(),
        expected_predecessor: validated.request().expected_predecessor.clone(),
        target_generation: validated.request().target_generation.clone(),
        target_build_digest: validated.request().target_build_digest.clone(),
        target_config_digest: validated.request().target_config_digest.clone(),
        user_broker_ref: validated.request().user_broker_ref.clone(),
        intent_evidence_refs: bounded_evidence(vec![
            admission_handle(admission)?,
            receipt_handle(validated.content_digest())?,
            validated.request().archive_digest.clone(),
            receipt_handle(&validated.evidence().restore_receipt.receipt_id)?,
            receipt_handle(&validated.evidence().restore_receipt.effect_receipt_sha256)?,
            receipt_handle(
                &validated
                    .evidence()
                    .operational_validation
                    .validation_digest,
            )?,
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
/// rejected, never defaulted), an owner-issued
/// [`PredecessorRetirementRelation`] naming the epoch to retire, and a live
/// barrier. The retired epoch is read from the relation, never from a parameter,
/// and the relation itself is persisted on the record so a later status read can
/// re-prove the same mapping. The source installation is retained until accepted
/// authorized retirement; source data destruction is a separate explicitly
/// authorized retention/erasure action, never automatic cleanup here.
///
/// # Errors
///
/// Fails closed on authorization, relation/prior-epoch binding, or journal
/// outcome; `OutcomeUnknown` reconciles through the choke and never forges
/// success.
///
/// Private on purpose. `PredecessorRetirementRelation` has public fields and no
/// restricted constructor, so a `pub` effect taking one would let any dependent
/// crate mint a relation naming any outstanding epoch and obtain a `Reconciled`
/// retirement of it - the same arbitrary selection #2868 removes, one level up.
/// Only [`retire_authorized_generation`], which receives the relation solely
/// from [`resolve_predecessor_retirement_relation`], can call this.
fn retire_prior_generation(
    host: &HostComposition,
    validated: &ValidatedCutover,
    barrier: &GenerationRetirementBarrier,
    relation: &PredecessorRetirementRelation,
    retirement_authorization: &PlatformHandle,
) -> Result<CutoverOutcome, CutoverError> {
    // Effect boundary: re-prove the retained body against the admitted envelope
    // immediately before the durable retirement record is appended, so the
    // effect runs only against a body the owner admitted. There is no
    // caller-controlled trusted flag; the check is the owner's own
    // cross-record join, repeated here rather than inferred from the seal.
    validated.recheck_admitted_body()?;
    host.ensure_material_admission_open_for_target(&validated.request().target_generation, false)
        .map_err(|error| note_cutover_error("retire", CutoverError::from(error)))?;
    if retirement_authorization.as_str().trim().is_empty() {
        return Err(note_cutover_error(
            "retire",
            CutoverError::AuthorityOrReadinessMissing,
        ));
    }
    let prior_host = &relation.retired_host;
    if prior_host.installation != host.host.installation {
        return Err(note_cutover_error("retire", CutoverError::BindingMismatch));
    }
    if prior_host.epoch == host.host.epoch {
        return Err(note_cutover_error("retire", CutoverError::BindingMismatch));
    }
    let cutover_operation = validated.sealed_operation()?;
    let operation = IdempotencyIdentity {
        operation_id: cutover_operation.operation_id.clone(),
        idempotency_key: cutover_operation.request_digest.clone(),
    };
    // The relation must be issued for exactly this cutover operation and must
    // map this body's expected predecessor generation onto the epoch being
    // retired. Without both, the record would again prove only "some prior epoch"
    // and the status binder would have to refuse to call it this cutover's
    // retirement.
    if relation.cutover_operation != operation
        || relation.installation != cutover_operation.installation
        || !relation.maps_generation(
            &cutover_operation.installation,
            &validated.request().expected_predecessor,
        )
    {
        return Err(note_cutover_error("retire", CutoverError::BindingMismatch));
    }
    // Deterministic per cutover operation and prior epoch: the journal
    // transaction id binds operation identity, Host epoch, and the full
    // record checksum (`journal.rs:126-145`), so a retry after
    // `OutcomeUnknown` must append byte-identical record bytes to replay
    // (`Replayed`) instead of duplicating the retirement. A fresh random
    // identity here would fork a second transaction on every retry. The
    // operation identity is the retained body's own, so the retirement can
    // only ever be bound to the cutover body that was actually admitted.
    let retired_digest = super::sha256_json(&(
        "cutover-retired-at-v1",
        &cutover_operation.operation_id,
        &cutover_operation.request_digest,
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
            admission_handle(&validated.request().admission)
                .map_err(|error| note_cutover_error("retire", error))?,
            receipt_handle(validated.content_digest())
                .map_err(|error| note_cutover_error("retire", error))?,
            validated.request().archive_digest.clone(),
            validated.request().target_generation.clone(),
            // The exact new authority this retirement completes: without it
            // the durable record would not name which `UserBroker` identity and
            // which approved build/config the surviving generation runs under.
            validated.request().user_broker_ref.clone(),
            validated.request().target_build_digest.clone(),
            validated.request().target_config_digest.clone(),
            // The predecessor generation this retirement consumed. It belongs in
            // the durable evidence set as well as in the typed relation: the
            // relation is the binding, and this makes the consumed generation
            // readable from the evidence list without parsing the relation.
            validated.request().expected_predecessor.clone(),
            receipt_handle(&validated.evidence().restore_receipt.receipt_id)
                .map_err(|error| note_cutover_error("retire", error))?,
            receipt_handle(&validated.evidence().restore_receipt.effect_receipt_sha256)
                .map_err(|error| note_cutover_error("retire", error))?,
            receipt_handle(
                &validated
                    .evidence()
                    .operational_validation
                    .validation_digest,
            )
            .map_err(|error| note_cutover_error("retire", error))?,
            retirement_authorization.clone(),
        ]),
        retired_at,
        // The owner-issued mapping itself, so a later status read can require
        // the exact predecessor-generation-to-Host-epoch relation instead of
        // accepting "some prior outstanding epoch" as this cutover's completion.
        predecessor_relation: Some(relation.clone()),
    });
    let receipt = super::journal_append::append_reconciled(&host.journal, record)
        .map_err(|error| note_cutover_error("retire", CutoverError::from(error)))?;
    let outcome = CutoverOutcome {
        disposition: CutoverDisposition::Reconciled,
        residual: CutoverResidual::None,
        operation: cutover_operation,
        evidence_refs: bounded_evidence(vec![
            receipt.transaction_id().clone(),
            admission_handle(&validated.request().admission)
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
/// Every input is a real read, and the three identity/target/predecessor
/// handles come from ONE `request` so they can no longer be supplied
/// independently of each other: `durable_intent` is the Host journal's own
/// `pending_cutover` projection (`None` when no intent is currently retained —
/// a later legitimate operation may hold that one slot instead, which is
/// current applicability and never this operation's history), `registry_active`
/// and `committed_activation` are the active generation and the operation-bound
/// cutover receipt freshly read back from the registry owner, and `retirement`
/// is what the JOURNAL OWNER resolved for this exact cutover operation by
/// `resolve_cutover_retirement` — a record selected from the log the journal
/// replayed, never from a presented receipt.
///
/// No caller-supplied assertion reaches this mapper. It is a pure function of
/// owner observations plus the coherence of the read that produced them, and the
/// one input that used to arrive as a bare caller `bool` is gone. No code in this
/// repository can mint [`CutoverDisposition::Validated`] any more: the mapper
/// does not, and there is no read wrapper holding a retained validation result
/// today. The variant stays in the closed result vocabulary because the issue
/// requires the vocabulary to be preserved and versioned rather than silently
/// narrowed, but it is currently unreachable, and nothing may cite it as a
/// reachable outcome. When no owner observation establishes anything, the honest
/// answer is `Requested` — qualification unavailable, not "validated".
///
/// (Do not confuse this variant with `ValidatedCutover`, which does exist and is
/// used on the execute path: that is a sealed pre-effect validation value the
/// execution flow carries, not a projected status.)
///
/// The dispositions are read off those observations, never assumed. In order: a
/// durable `Failed` intent that COEXISTS with an owner-resolved retirement for
/// this same operation is a contradiction between two owner observations and is
/// reported as such, because a terminal refusal is only the whole truth when no
/// retirement was actually resolved; a retirement the journal owner could
/// neither resolve to exactly one record nor bind to this request is preserved
/// as unknown with its own residual; a retirement the owner resolved and the
/// read wrapper proved against this request is the completed historical result;
/// a registry flip to the target **together with** this operation's own durable
/// intent and the registry's operation-bound receipt proves the activation
/// committed with retirement still owed; and only then does the intent
/// projection's own current applicability decide anything: a target pointer
/// with no such binding, a foreign or substituted intent, and an unexpected
/// active generation all stay `Unknown`. A durable `Pending` intent is
/// `Prepared` ONLY with the evidence that the required pre-effect state still
/// holds — the registry's active generation must still be this operation's
/// EXPECTED PREDECESSOR **and** the two owner observations must have been read
/// as one coherent moment. A `Pending` intent whose active generation is
/// something else, including a third generation that is neither the predecessor
/// nor the target, is unknown with its causal residual and is never read as
/// progress.
///
/// `coherence` gates the effect- and history-bearing dispositions
/// (`Reconciled`, `RetirementPending`, `Prepared`) and the one attribution
/// absence a torn read cannot honestly assert (a target pointer with no durable
/// intent at all). A refusal backed by a durable record of THIS operation is
/// still reported when the pair was torn, because such a refusal never claims an
/// effect; a positive claim is not, because the journal and the registry have no
/// shared transaction and a torn pair can combine into a state that never
/// existed.
///
/// Historical completion is preserved separately from current applicability.
/// `durable_intent` is ONE slot and describes the CURRENT pending operation,
/// not this operation's history: a later legitimate cutover replaces it in the
/// owner's own projection once the previous intent is terminal, and neither
/// this mapper nor [`retirement_binds_request`] may read that replacement as
/// evidence about this operation. An owner-resolved retirement therefore survives
/// any number of later legitimate operations, and is never reported as a current
/// activation of the old target:
///
/// * the slot still holds this operation's own intent and the registry's active
///   generation is this operation's target — `Reconciled` with no residual,
///   the owners agree;
/// * the slot still holds this operation's own intent and the active generation
///   has moved on — `Reconciled` with [`CutoverResidual::RetirementSuperseded`],
///   because a later authorized generation change does not undo the old
///   completed transition;
/// * the slot no longer holds this operation's intent at all — `Reconciled`
///   with [`CutoverResidual::RetirementWithoutRetainedIntent`], because the
///   retirement is durable history while the intent's own disposition is no
///   longer re-readable from the owner. Missing history is never manufactured:
///   a slot holding ANOTHER operation's intent with NO owner-resolved
///   retirement for this operation stays `Unknown` +
///   [`CutoverResidual::ForeignDurableIntent`], and a contradiction or a
///   substitution inside the retirement record itself stays `Unknown` +
///   [`CutoverResidual::ContradictoryRetirement`] or
///   [`CutoverResidual::UnboundRetirement`].
///
/// `Committed` is not produced here: it is the immediate post-CAS outcome
/// `execute_cutover` returns, and a later read of the same operation reports
/// `RetirementPending` until the owner resolves its retirement.
/// Cancellation/cleanup/diagnostic failure preserves the primary result and its
/// reconciliation path.
///
/// # Reachability of `Reconciled` on current source
///
/// The `Reconciled` arm is reachable in this mapper whenever
/// `retirement_binds_request` returns `Exact`, which requires the resolved
/// durable record to carry a `PredecessorRetirementRelation` naming this
/// request's `expected_predecessor` (#2868). No owner issues that relation
/// today - see [`resolve_predecessor_retirement_relation`] - so on current
/// source no record can carry one and this arm is not entered in production. It
/// is stated rather than left implicit, exactly as `Validated` is above. The
/// arm is retained because the durable record shape and the re-proof exist, and
/// an owner correction fills this without touching the mapper.
#[must_use]
#[allow(
    clippy::too_many_lines,
    reason = "the ordered owner-observation decision table stays in one boundary so no arm can be reordered past a neighbour that outranks it"
)]
pub fn reconcile_cutover_outcome(
    request: &CutoverRequest,
    durable_intent: Option<&CutoverIntentRecord>,
    committed_activation: Option<&CommittedCutoverActivation>,
    registry_active: Option<&PlatformHandle>,
    retirement: &CutoverRetirementEvidence,
    coherence: OwnerObservationCoherence,
) -> CutoverOutcome {
    let operation = &request.operation;
    let target_generation = &request.target_generation;
    let expected_predecessor = &request.expected_predecessor;
    let ours = durable_intent.filter(|intent| {
        is_own_cutover_intent(intent, operation, target_generation, expected_predecessor)
    });
    let foreign = durable_intent.is_some() && ours.is_none();
    let resolved_retirement = retirement.resolved_for(operation);
    let (disposition, residual) = if ours
        .is_some_and(|intent| intent.state == CutoverIntentState::Failed)
        && !matches!(retirement, CutoverRetirementEvidence::Absent)
    {
        // Two owner observations contradict each other: the durable intent for
        // this exact operation reached the terminal `Failed` state, AND the
        // journal owner holds non-absent retirement evidence for this same
        // operation identity — resolved, contradictory (more than one
        // `EpochRetirement`), or resolved-but-unbound. A terminal refusal is not
        // the whole truth when the journal also carries a retirement record for
        // the refused operation, and the completed history is not erased by the
        // refusal either. The contradiction is the result: nothing here retries,
        // repairs, or picks the convenient arm.
        //
        // The condition covers every non-absent state on purpose. Gating only on
        // `Resolved` left `Contradictory` and `Unbound` to be shadowed by the
        // refusal arm below, which is the same "choose the branch that appears
        // first" flattening this arm exists to stop, and it would have been a
        // false claim: `Contradictory` means the journal owner holds MORE than
        // one retirement for this exact operation. `RelationUnproven` is
        // included for the same reason - a legacy retirement record under a
        // refused operation is still a durable fact about that operation, and
        // `!matches!(retirement, Absent)` is what keeps it from being read as
        // "nothing happened".
        (
            CutoverDisposition::Unknown,
            CutoverResidual::FailedIntentWithResolvedRetirement,
        )
    } else if let Some(reason) = retirement.unresolved_residual() {
        // The journal owner could not establish exactly one retirement for
        // this operation, or the one it resolved is not this cutover's. The
        // operation and its retained intent are preserved and nothing is
        // retried or inferred (I14.21).
        (CutoverDisposition::Unknown, reason)
    } else if resolved_retirement.is_some() && coherence == OwnerObservationCoherence::Coherent {
        // The journal owner resolved exactly one `EpochRetirement` for this
        // exact operation and the read wrapper proved its bindings against this
        // request from the durable record itself. A later authorized generation
        // change does not erase that history, and it does not turn it into a
        // current activation either. This arm is reached even when the single
        // intent slot now holds a LATER operation's intent: the slot describes
        // current applicability, while the retirement is this operation's
        // history, and erasing the second because of the first is the
        // "historical completion is separate from current applicability" defect
        // this ordering exists to close.
        (
            CutoverDisposition::Reconciled,
            if ours.is_some() && registry_active == Some(target_generation) {
                CutoverResidual::None
            } else if ours.is_some() {
                // The registry's current active generation is no longer this
                // operation's target, so the historical retirement is not a
                // current activation of the old target.
                CutoverResidual::RetirementSuperseded
            } else {
                // The intent slot no longer retains this operation's intent, so
                // its own disposition cannot be re-read from the owner. The
                // retirement is still authentic history; the missing
                // applicability is named rather than assumed either way.
                CutoverResidual::RetirementWithoutRetainedIntent
            },
        )
    } else if resolved_retirement.is_some() {
        // The same resolved retirement, but the journal and the registry were
        // not read as one moment. The retirement itself is an owner fact, yet
        // the disposition paired with it would describe a state neither owner
        // ever held, so the movement is reported instead of the completion.
        (
            CutoverDisposition::Unknown,
            CutoverResidual::ConcurrentOwnerMovement,
        )
    } else if foreign {
        // No retirement of this operation is established, and the single intent
        // slot holds an outstanding intent that is not this exact operation,
        // target and predecessor: cross-operation confusion or a substituted
        // binding, never evidence about this one.
        (
            CutoverDisposition::Unknown,
            CutoverResidual::ForeignDurableIntent,
        )
    } else if ours.is_some_and(|intent| intent.state == CutoverIntentState::Failed) {
        (CutoverDisposition::Failed, CutoverResidual::None)
    } else if ours.is_some()
        && registry_active == Some(target_generation)
        && registry_activation_binds_this_operation(
            committed_activation,
            operation,
            target_generation,
        )
    {
        if coherence == OwnerObservationCoherence::Coherent {
            // The registry's own operation-bound receipt names this operation and
            // target, so the activation committed exactly once. Retirement
            // remains a separate explicitly authorized step that has not
            // happened yet.
            (
                CutoverDisposition::RetirementPending,
                CutoverResidual::RetirementOutstanding,
            )
        } else {
            // The binding matched, but the pair was torn. Falling through to the
            // next arm would report `UnattributedActivation` — "the registry's
            // own operation-bound receipt does not name this operation" — which
            // the predicate above just contradicted. The movement is reported
            // instead, so no affirmative attribution is claimed from a torn
            // read.
            (
                CutoverDisposition::Unknown,
                CutoverResidual::ConcurrentOwnerMovement,
            )
        }
    } else if ours.is_some() && registry_active == Some(target_generation) {
        // The target pointer is active but the registry's operation-bound
        // receipt does not name this operation, so nothing binds that flip to
        // this attempt: an installer commit, or another operation's cutover to
        // the same target. A pointer alone attributes an activation to nobody,
        // so this is never reported as this operation's commit with retirement
        // owed.
        (
            CutoverDisposition::Unknown,
            CutoverResidual::UnattributedActivation,
        )
    } else if ours.is_some_and(|intent| intent.state == CutoverIntentState::Pending) {
        // `Prepared` claims the effect has not been applied yet, so it needs
        // the evidence that the required pre-effect state still holds. Any
        // other active generation — absent, the target's successor, or a third
        // generation that is neither predecessor nor target — is preserved as
        // unknown instead of being read as an unapplied effect.
        if registry_active != Some(expected_predecessor) {
            (
                CutoverDisposition::Unknown,
                CutoverResidual::PredecessorNotActive,
            )
        } else if coherence != OwnerObservationCoherence::Coherent {
            // The predecessor was still active in the registry sample, but the
            // journal moved while that sample was taken. `Prepared` is the
            // strongest "nothing has happened yet" claim this mapper makes, and
            // a torn cross-store pair is exactly how that claim becomes false,
            // so the movement is reported instead.
            (
                CutoverDisposition::Unknown,
                CutoverResidual::ConcurrentOwnerMovement,
            )
        } else {
            (CutoverDisposition::Prepared, CutoverResidual::None)
        }
    } else if ours.is_some() {
        // A durable COMMITTED intent whose activation outcome neither the
        // registry receipt nor a retirement establishes: the owners disagree,
        // which is preserved rather than resolved (I14.21).
        (
            CutoverDisposition::Unknown,
            CutoverResidual::ActivationOutcomeUnestablished,
        )
    } else if registry_active == Some(target_generation) {
        // The target is active but nothing durable binds that flip to this
        // operation: an installer's commit, or a cutover from a Host epoch that
        // has since been re-based. Never reported as this operation's success.
        // When the pair was torn the missing intent may simply have landed after
        // the sampled journal read, so the movement is named rather than an
        // absence the read did not actually observe.
        if ours.is_none() && coherence != OwnerObservationCoherence::Coherent {
            (
                CutoverDisposition::Unknown,
                CutoverResidual::ConcurrentOwnerMovement,
            )
        } else {
            (
                CutoverDisposition::Unknown,
                CutoverResidual::UnattributedActivation,
            )
        }
    } else {
        // No owner observation establishes anything for this operation. The old
        // code returned `Validated` here whenever the caller passed a bare
        // `true`, which let an unconstrained caller assertion certify
        // qualification. The honest answer for an unqualified read is
        // `Requested`: not validated, not refused, not an effect — and the
        // `Validated` disposition is now unreachable from this mapper, so it
        // cannot be minted from a caller's word.
        (CutoverDisposition::Requested, CutoverResidual::None)
    };
    let outcome = CutoverOutcome {
        disposition,
        residual,
        operation: operation.clone(),
        // Only the observation that produced this disposition contributes
        // evidence. A presented, foreign, rejected or absent receipt is never
        // attached as if it supported the result.
        evidence_refs: bounded_evidence(match resolved_retirement {
            Some(evidence) => {
                let mut refs = Vec::with_capacity(evidence.evidence_refs().len() + 2);
                refs.push(evidence.transaction_id().clone());
                refs.push(target_generation.clone());
                refs.extend(evidence.evidence_refs().iter().cloned());
                refs
            }
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
