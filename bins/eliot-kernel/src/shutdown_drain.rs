//! Kernel-owned persisted safe-shutdown/drain state machine (I14.23).
//!
//! Architecture: A13.2 Kernel and failure domains; ARCH-RES-01 fail locally,
//! recover globally; ARCH-RES-04 degradation is visible and local.
//! Implementation: I14.23 safe shutdown; I1.5 drain linearization
//! (`DrainCommitRecord`); I14.21 unknown-commit recovery precedent (pending
//! work is retained, never discarded).
//!
//! This module owns the Kernel slice of the shutdown sequence named by
//! I14.23: ordered persisted phases, the `DrainCommit` linearization decision,
//! the receipt-reconciliation gate, the canonical-data lease-zero gate, the
//! reverse-dependency quiescence order, the intentional/incomplete durable
//! terminals, and the wake/attach race table. Effects stay with their existing
//! owners: the composition root drives service transitions, the ORS gateway
//! reconciles staged rows, Host persists the `DrainCommitRecord` into its
//! journal, and Watchdog observes through the journal.
//!
//! Boundary to `eliot-host-state` (which this binary must not depend on and
//! must not move types across): [`DrainWakeDisposition`] mirrors the
//! `WakeDisposition` wire vocabulary as evidence strings, and
//! [`DrainCommitDecision`] documents the exact field contract Host carries
//! into `DrainCommitRecord` through its journal helper. That contract is not
//! prose here: [`DrainCommitDecision::validate`] is the one rule set applied
//! both by the linearization point before it writes the decision and by the
//! recovery read path when it loads one, so a persisted `DrainCommitRecord`
//! boundary can never state something the commit would have refused, and
//! [`ShutdownDrainCoordinator::committed_decision`] is the production reader
//! that hands the persisted boundary back to be published. The phase
//! vocabulary here is Kernel-owned; `DrainState`
//! (`Requested`/`Draining`/`Cancelled`/`Failed`) stays Host-journal owned.
//!
//! # The activation fence is installation-scoped, not generation-scoped
//!
//! I1.5 pairs [`DrainCommitDecision::activation_generation_fenced`] with an
//! installation-scoped `activation_generation`, and I14.23 says "No caller may
//! 'rescue' shutdown by reviving an old lease or process handle". Those two
//! sentences together mean the revocation outlives the drain that made it. A
//! fence recorded only inside the current drain generation's [`Self::
//! DrainCommitDecision`] would be dropped by [`ShutdownDrainCoordinator::
//! request_shutdown`]'s rollover into a fresh generation, and by a process that
//! reloads the durable file with no drain in progress — and a wake presenting
//! exactly the generation a committed `DrainCommitRecord` states it fenced
//! would then be answered `Proceed`. The fence is therefore durable in its own
//! right ([`DurableDrainState::fenced_activation_generations`]), carried across
//! rollover, and consulted by [`ShutdownDrainCoordinator::classify_wake`]
//! *before* any per-generation drain state, so the property does not depend on
//! a drain being in progress. That ordering is the linearizability property,
//! not a check that reports on it.
//!
//! The production caller of that classification is named here so it can be
//! found by a symbol search rather than reconstructed:
//! [`ShutdownDrainCoordinator::on_activate_request`] is called from
//! `KernelComposition::apply_control_request_inner` in `control_plane.rs`,
//! gated on `KernelControlCommand::Activate(_)` and
//! `KernelControlCommand::ReconcileActivation(_)`, with the presented value
//! read from `request.candidate.supervision_incarnation.activation_generation`.
//! `ReconcileActivation` is in that family on purpose: it is the reconcile path
//! a post-linearization attach uses to *receive* a fresh generation, and
//! `KernelService::reconcile_activation` answers it by handing back the very
//! `KernelActivationReceipt` `activate_permit` minted before the drain, which
//! no drain transition clears. An attach that skipped this gate would therefore
//! leave with drained authority intact. The gate refuses whenever
//! [`DrainWakeDisposition::fences_old_authority`] holds.
//!
//! Handoffs (recorded, not implemented here): audit/outbox flush is
//! Governor/`eliotd`-owned — Kernel flushes ORS staged rows and records the
//! Governor flush as awaited via daemon quiescence; canonical-store internals
//! are store-bridge-owned — Kernel proves the lease-zero precondition and
//! records the store-stop request for Host to execute; job checkpoint
//! semantics are Governor-owned — Kernel observes the daemon contour and
//! closes admission through the existing `Draining` service gate.
//! I14.23 has no phase fields in `eliot-host-state` `DrainState`
//! (`Intentional`/`Incomplete` live here, kernel-side); no `model.rs` change
//! is made by this slice.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use eliot_runtime_contracts::SupervisionJournalEpoch;
use serde::{Deserialize, Serialize};

/// Bounded wait for in-flight receipt reconciliation before drain gives up
/// and records incomplete shutdown. Owns only drain timing; runtime task
/// grace stays with `RuntimeConfig::shutdown_grace`.
pub(crate) const DRAIN_RECEIPT_DEADLINE: Duration = Duration::from_secs(5);

/// Durable file carrying the Kernel drain state across restarts, so recovery
/// distinguishes an intentional stop (terminal persisted) from an interrupted
/// drain (requested without terminal; pending retained).
const DRAIN_STATE_FILE: &str = "kernel-shutdown-drain.json";
/// This file lives in the user's work root and outlives a build, so its
/// version is not a migration boundary but a compatibility boundary: it may
/// only advance when the on-disk shape stops being readable by the previous
/// version. `DrainCommitDecision::activation_generation_fenced` is optional
/// and `#[serde(default)]`, so the shape stayed backward compatible and the
/// version did not move. Refusing an older version instead would not be a
/// safe refusal here — `coordinator_for` does not cache a load failure, so one
/// unrecognized file would make the Kernel permanently unusable for that work
/// root, with no path back but a hand-deleted file.
const DRAIN_STATE_VERSION: u32 = 1;

/// Upper bound on the decoded durable state. The decoded shape is eight phase
/// evidences, one decision, one terminal and the pending identities, so this is
/// far above any state a drain can legitimately write. A larger file is
/// corruption, not an obligation, and is refused as unreadable rather than
/// decoded into an unbounded allocation.
const DRAIN_STATE_MAX_BYTES: u64 = 64 * 1024;

/// Poll interval for the bounded receipt-reconciliation wait.
const RECEIPT_POLL_INTERVAL: Duration = Duration::from_millis(10);

static DRAIN_TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

fn durable_replace(source: &Path, destination: &Path) -> io::Result<()> {
    fs::rename(source, destination)?;
    File::open(destination)?.sync_all()?;
    #[cfg(unix)]
    {
        let parent = destination.parent().unwrap_or_else(|| Path::new("."));
        File::open(parent)?.sync_all()?;
    }
    Ok(())
}

/// F-LOG-KERNEL-4 style observation for the shutdown boundary: fixed event
/// plus bounded outcome only, never digests, epochs, or owner error strings.
fn observe_shutdown(event: &'static str, outcome: &'static str) {
    use super::kernel_diagnostics::{KERNEL_DIAGNOSTICS_TARGET, bound_field};
    let event_bound = bound_field(event);
    let outcome_bound = bound_field(outcome);
    tracing::info!(
        target: KERNEL_DIAGNOSTICS_TARGET,
        event = event_bound.text(),
        outcome = outcome_bound.text(),
        "shutdown drain observation"
    );
}

/// Ordered I14.23 shutdown phases. Discriminant order is the execution order.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) enum ShutdownPhase {
    AdmissionsClosed,
    AuthorityRevoked,
    JobsCheckpointed,
    CanonicalDrainReceiptsReconciled,
    FlushesCompleted,
    ModulesQuiescedReverse,
    StoreStopLeaseZero,
    IntentionalPublished,
}

impl ShutdownPhase {
    /// Every phase in execution order.
    pub(crate) const ORDERED: [Self; 8] = [
        Self::AdmissionsClosed,
        Self::AuthorityRevoked,
        Self::JobsCheckpointed,
        Self::CanonicalDrainReceiptsReconciled,
        Self::FlushesCompleted,
        Self::ModulesQuiescedReverse,
        Self::StoreStopLeaseZero,
        Self::IntentionalPublished,
    ];

    /// Phases that must precede the [`ShutdownDrainCoordinator::commit_drain`]
    /// linearization point.
    pub(crate) const PRE_COMMIT: [Self; 7] = [
        Self::AdmissionsClosed,
        Self::AuthorityRevoked,
        Self::JobsCheckpointed,
        Self::CanonicalDrainReceiptsReconciled,
        Self::FlushesCompleted,
        Self::ModulesQuiescedReverse,
        Self::StoreStopLeaseZero,
    ];

    pub(crate) const fn order(self) -> u8 {
        match self {
            Self::AdmissionsClosed => 0,
            Self::AuthorityRevoked => 1,
            Self::JobsCheckpointed => 2,
            Self::CanonicalDrainReceiptsReconciled => 3,
            Self::FlushesCompleted => 4,
            Self::ModulesQuiescedReverse => 5,
            Self::StoreStopLeaseZero => 6,
            Self::IntentionalPublished => 7,
        }
    }

    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::AdmissionsClosed => "admissions-closed",
            Self::AuthorityRevoked => "authority-revoked",
            Self::JobsCheckpointed => "jobs-checkpointed",
            Self::CanonicalDrainReceiptsReconciled => "canonical-drain-receipts-reconciled",
            Self::FlushesCompleted => "flushes-completed",
            Self::ModulesQuiescedReverse => "modules-quiesced-reverse",
            Self::StoreStopLeaseZero => "store-stop-lease-zero",
            Self::IntentionalPublished => "intentional-published",
        }
    }
}

/// Wake/attach race disposition, mirroring the `WakeDisposition` wire
/// vocabulary (`CANCEL_DRAIN` / `QUEUE_NEXT_GENERATION` / `REJECT_STALE`)
/// owned by `eliot-host-state`. `Proceed` covers "no drain in progress" and
/// never reaches the journal.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub(crate) enum DrainWakeDisposition {
    Proceed,
    CancelDrain,
    QueueNextGeneration,
    RejectStale,
}

impl DrainWakeDisposition {
    /// True for the post-linearization dispositions that must never operate
    /// with a pre-drain lease or handle.
    pub(crate) const fn fences_old_authority(self) -> bool {
        matches!(self, Self::QueueNextGeneration | Self::RejectStale)
    }

    /// The exact `WakeDisposition` wire spelling this disposition mirrors, so a
    /// published boundary states the same vocabulary the durable
    /// `DrainCommitRecord` records. `Proceed` has no counterpart variant in
    /// `WakeDisposition` because it means "no drain in progress" and never
    /// reaches a durable record;
    /// [`DrainCommitDecision::validate`] is what enforces that, so this arm is
    /// reachable only from a projection that did not linearize.
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Proceed => "PROCEED",
            Self::CancelDrain => "CANCEL_DRAIN",
            Self::QueueNextGeneration => "QUEUE_NEXT_GENERATION",
            Self::RejectStale => "REJECT_STALE",
        }
    }
}

/// Durable terminal of one drain generation. `Incomplete` retains the pending
/// work that deadline expiry refused to discard.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) enum ShutdownTerminal {
    Intentional,
    Incomplete { pending: Vec<String> },
}

impl ShutdownTerminal {
    pub(crate) const fn as_str(&self) -> &'static str {
        match self {
            Self::Intentional => "intentional-shutdown",
            Self::Incomplete { .. } => "incomplete-shutdown",
        }
    }

    pub(crate) fn pending(&self) -> Vec<String> {
        match self {
            Self::Intentional => Vec::new(),
            Self::Incomplete { pending } => pending.clone(),
        }
    }
}

/// Kernel-owned `DrainCommit` linearization decision.
///
/// Field contract carried by Host into `DrainCommitRecord` through its journal
/// helper (no cross-binary type import): `generation` feeds
/// `drain_generation` correlation, `lease_and_pending_snapshot` feeds
/// `lease_and_pending_operation_snapshot` (empty here — the reconciliation
/// gate proved it; commit rejects a decision carrying unreconciled work),
/// `authority_epochs_fenced` feeds
/// `authority_epochs_fenced`, `branches_to_stop` feeds
/// `processes_modules_and_store_branches_to_stop`, `wake_disposition` feeds
/// `wake_during_drain_disposition`, `irreversible_stage` feeds
/// `irreversible_stage`, and `recovery_owner` feeds `recovery_owner`.
///
/// [`Self::activation_generation_fenced`] is deliberately *not* part of that
/// Host field contract: `generation` above is the `drain_generation`
/// correlation id this process mints, and it has no wire representation, so it
/// can never be what a waking `Activate` presents. The activation generation
/// the linearization point fenced is the identity I1.5 pairs with
/// `drain_generation` ("a trigger received after `DrainCommitRecord` creates a
/// new activation generation"), so it is persisted in the same
/// lineage-plus-sequence domain [`SupervisionJournalEpoch`] defines for the
/// activation generation the request carries, and the linearization point
/// promotes it into the installation-scoped fence
/// [`ShutdownDrainCoordinator::classify_wake`] compares against.
///
/// That value is `Option` and `#[serde(default)]` so the durable format stayed
/// backward compatible and `DRAIN_STATE_VERSION` did not have to move: a
/// committed state written by a build that predates the field decodes here as
/// `None`, meaning "this commit recorded no fenced activation generation"
/// rather than "any generation is fenced". `ShutdownDrainCoordinator::load`
/// re-derives the installation fence from a recovered decision, so a pre-field
/// state is fenced on read rather than revived. Refusing the whole file as an
/// unsupported version instead would be the one genuinely unsafe option: the
/// file survives the upgrade, `coordinator_for` does not cache its load
/// failure, and the Kernel would be unusable for that work root until someone
/// hand-deleted it.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DrainCommitDecision {
    pub(crate) generation: String,
    pub(crate) lease_and_pending_snapshot: Vec<String>,
    pub(crate) authority_epochs_fenced: Vec<String>,
    #[serde(default)]
    pub(crate) activation_generation_fenced: Option<SupervisionJournalEpoch>,
    pub(crate) branches_to_stop: Vec<String>,
    pub(crate) wake_disposition: DrainWakeDisposition,
    pub(crate) irreversible_stage: String,
    pub(crate) recovery_owner: String,
}

impl DrainCommitDecision {
    /// The durable `DrainCommitRecord` boundary contract, applied on the write
    /// path ([`ShutdownDrainCoordinator::commit_drain`]) *and* on the recovery
    /// read path ([`validate_durable_state`]), so a persisted linearization can
    /// never state something the linearization point itself would have refused.
    ///
    /// `HostState::DrainCommit(DrainCommitRecord)`'s own `validate` remains the
    /// Host-side authority for the wire shape, and this binary must not depend
    /// on `eliot-host-state`; these are the rules that shape already states,
    /// checked here over the Kernel-owned mirror that [`Self`] is. The fenced
    /// activation generation is validated with the runtime-contract owner of
    /// that identity ([`SupervisionJournalEpoch::validate`]), not with a local
    /// copy of it.
    ///
    /// # Errors
    ///
    /// Returns a reason when a boundary field is blank, when the decision
    /// carries a non-empty lease/pending snapshot, when it names no fenced
    /// authority, when it records `Proceed` as the post-linearization wake
    /// disposition (`Proceed` means "no drain in progress" and never reaches a
    /// durable record), or when a recorded fenced activation generation is not
    /// a complete journal identity.
    pub(crate) fn validate(&self) -> Result<(), String> {
        if self.generation.trim().is_empty() {
            return Err("drain decision generation is empty".to_owned());
        }
        // Linearization is admitted only on the reconciled-empty registry the
        // receipt gate proved, so a persisted snapshot that still carries work
        // is a contradiction of the commit, never an obligation.
        if !self.lease_and_pending_snapshot.is_empty() {
            return Err("drain decision carries unreconciled pending snapshot".to_owned());
        }
        if self.authority_epochs_fenced.is_empty()
            || self
                .authority_epochs_fenced
                .iter()
                .any(|epoch| epoch.trim().is_empty())
        {
            return Err("drain decision names no fenced authority epoch".to_owned());
        }
        if self
            .branches_to_stop
            .iter()
            .any(|branch| branch.trim().is_empty())
        {
            return Err("drain decision names a blank branch to stop".to_owned());
        }
        if self.wake_disposition == DrainWakeDisposition::Proceed {
            return Err("drain decision records a no-drain wake disposition".to_owned());
        }
        if self.irreversible_stage.trim().is_empty() {
            return Err("drain decision names no irreversible stage".to_owned());
        }
        if self.recovery_owner.trim().is_empty() {
            return Err("drain decision names no recovery owner".to_owned());
        }
        // `None` is the documented backward-compatible "this commit recorded no
        // fenced activation generation"; a recorded one is a full journal
        // identity, not a blank lineage at sequence zero.
        if let Some(fenced) = self.activation_generation_fenced.as_ref() {
            fenced
                .validate("drain.activation_generation_fenced")
                .map_err(|error| format!("fenced activation generation is invalid: {error}"))?;
        }
        Ok(())
    }
}

/// Early halt of the ordered drain: the reason plus every pending item the
/// incomplete-shutdown terminal must retain.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DrainHalt {
    pub(crate) reason: &'static str,
    pub(crate) pending: Vec<String>,
}

impl DrainHalt {
    pub(crate) const fn new(reason: &'static str) -> Self {
        Self {
            reason,
            pending: Vec::new(),
        }
    }

    pub(crate) fn with_pending(reason: &'static str, pending: Vec<String>) -> Self {
        Self { reason, pending }
    }
}

/// Read-only publication consumed by Host (into `DrainCommitRecord`) and by
/// Watchdog (through the Host journal) over their existing control paths.
#[allow(
    clippy::struct_excessive_bools,
    reason = "the publication is a coherent one-reader snapshot; splitting it would fork the observed state"
)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShutdownPublication {
    pub(crate) generation: String,
    pub(crate) requested: bool,
    pub(crate) phases_completed: Vec<String>,
    pub(crate) committed: bool,
    pub(crate) cancelled: bool,
    pub(crate) recovered_interrupted: bool,
    pub(crate) terminal: Option<String>,
    pub(crate) pending: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct DurableDrainState {
    version: u32,
    generation: String,
    requested: bool,
    cancelled: bool,
    phases: Vec<(u8, String)>,
    committed: Option<DrainCommitDecision>,
    terminal: Option<ShutdownTerminal>,
    pending: Vec<String>,
    /// Installation-scoped activation fence, keyed by journal lineage.
    ///
    /// `#[serde(default)]` for the same compatibility reason
    /// [`DrainCommitDecision::activation_generation_fenced`] is: the field is
    /// additive, so a state file written before it existed still decodes, and
    /// `DRAIN_STATE_VERSION` did not have to move. The absent-map case is
    /// repaired on load by re-deriving the fence from a recovered
    /// [`Self::committed`] decision, which only ever *adds* a fence, so the
    /// repair is one-directional and a pre-field file is fenced, not revived.
    #[serde(default)]
    fenced_activation_generations: BTreeMap<String, u64>,
}

#[derive(Clone)]
struct CoordinatorState {
    generation: String,
    requested: bool,
    recovered_interrupted: bool,
    cancelled: bool,
    phases: BTreeMap<u8, String>,
    committed: Option<DrainCommitDecision>,
    terminal: Option<ShutdownTerminal>,
    pending: BTreeSet<String>,
    /// Highest activation-generation sequence a linearized drain fenced per
    /// journal lineage. This is deliberately *not* drain-generation state: see
    /// [`Self::fresh`] and [`ShutdownDrainCoordinator::request_shutdown`].
    fenced_activation_generations: BTreeMap<String, u64>,
}

impl CoordinatorState {
    /// A fresh drain generation. The installation-scoped activation fence is
    /// deliberately NOT reset here, which is why this constructor takes only
    /// the new correlation id: a generation a committed drain already fenced
    /// stays fenced for the life of the installation, because I1.5 serializes
    /// activation and drain on one *installation-scoped*
    /// `activation_generation` ("Activation and drain are serialized by one
    /// installation-scoped `activation_generation`"). Tying the fence to the
    /// drain correlation id would let a fresh generation forget a revocation
    /// the durable `DrainCommitRecord` still states.
    fn fresh(generation: String) -> Self {
        Self {
            generation,
            requested: false,
            recovered_interrupted: false,
            cancelled: false,
            phases: BTreeMap::new(),
            committed: None,
            terminal: None,
            pending: BTreeSet::new(),
            fenced_activation_generations: BTreeMap::new(),
        }
    }
}

/// Whether the presented activation generation was already fenced by a
/// linearized drain in this installation.
///
/// The comparison is `sequence <= fenced_sequence` *within one lineage*, not
/// equality. I1.5 sequences a lineage's activation generations monotonically
/// ("A trigger received after `DrainCommitRecord` creates a new activation
/// generation"), so every generation at or below the fence is one the commit
/// already revoked, and only a strictly greater sequence is a fresh one. A
/// presented generation from a *different* lineage is not comparable at all
/// and is left to the per-generation rule rather than being guessed at.
fn fenced_activation_generation(
    fences: &BTreeMap<String, u64>,
    presented: &SupervisionJournalEpoch,
) -> bool {
    fences
        .get(&presented.lineage_id)
        .is_some_and(|fenced_sequence| presented.sequence <= *fenced_sequence)
}

/// Owner family of a drain-gate obligation. One family is read only by its own
/// owner, so a `StoreRebind` observation can never clear another family's
/// work.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ReceiptOwnerFamily {
    /// ORS store-rebind replay rows, the family the drain gate registers today.
    StoreRebind,
}

/// One obligation exactly as its owner recorded it.
///
/// The registered drain-gate identity names only the operation, so the request
/// binding, generation and revision are hydrated from the owner row rather
/// than invented from the identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ReceiptOwnerEvidence {
    /// The drain-gate identity this evidence is registered under.
    identity: String,
    /// The exact request digest the owner stored for the operation.
    request_digest: String,
    /// The owner's generation for this operation.
    generation: u64,
    /// The owner's monotonic commit-order revision, zero for a row the owner
    /// retained before the ordering field existed.
    revision: u64,
}

impl ReceiptOwnerEvidence {
    /// Binds one owner row to the drain-gate identity it is registered under.
    /// The caller supplies the identity in its owner's exact form so a
    /// projection and its evidence can never disagree.
    pub(crate) fn new(
        identity: String,
        request_digest: String,
        generation: u64,
        revision: u64,
    ) -> Self {
        Self {
            identity,
            request_digest,
            generation,
            revision,
        }
    }

    /// The drain-gate identity this evidence is registered under, in its
    /// owner family's exact form.
    pub(crate) fn identity(&self) -> String {
        self.identity.clone()
    }
}

/// One typed, fallible read of an owner family's durable replay rows.
///
/// The observation is the only thing that may subtract an obligation, so it
/// carries the coverage it actually has: a partial or foreign read, and a read
/// whose owner revision regressed, hold no removal authority at all.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ReceiptRescanObservation {
    /// Owner family this read observed.
    pub(crate) family: ReceiptOwnerFamily,
    /// The read covered the whole family in one consistent snapshot. A read
    /// that stops before the end of the family, because its bounded page walk
    /// reached the end of the remaining budget, reports incomplete rather than
    /// silently truncating: truncation can never clear an obligation.
    pub(crate) complete: bool,
    /// True only when the owner's own contract makes absence proof of
    /// resolution. The ORS store-rebind family has no such contract: an abort
    /// removes its row, so absence is a query miss, not success.
    pub(crate) absence_resolves: bool,
    /// The highest owner revision this read reported, zero when it reported no
    /// committed row.
    pub(crate) revision: u64,
    /// Obligations the owner still reports pending.
    pub(crate) pending: Vec<ReceiptOwnerEvidence>,
    /// Operations the owner proved terminal for the exact binding it read.
    pub(crate) resolved: Vec<ReceiptOwnerEvidence>,
}

/// Outcome of the bounded receipt-reconciliation wait. Only `Reconciled`
/// authorizes the next drain phase; a known-empty registry reached through an
/// incomplete or unavailable observation is never reconciled.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum ReceiptReconciliation {
    /// A current, complete observation proved the registry empty.
    Reconciled,
    /// Residuals remain, with the reason they were not cleared.
    Incomplete {
        pending: Vec<String>,
        reason: &'static str,
    },
    /// A required read or the durable publication failed; nothing was proven.
    Unavailable { reason: &'static str },
}

/// What one observation proves about one registered obligation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReceiptVerdict {
    /// The owner still reports the obligation pending.
    Pending,
    /// The owner reported terminal evidence for it and nothing contradicts it.
    Resolved,
    /// Pending and terminal evidence, or two different request bindings, for
    /// the same identity: a conflict, never a resolution.
    Conflict,
}

/// Folds one observation into one verdict per registered identity. Pending
/// evidence always wins over terminal evidence for the same identity, and two
/// different request bindings for one identity are a conflict rather than
/// whichever row was processed last.
fn fold_rescan_observation(
    observation: &ReceiptRescanObservation,
) -> BTreeMap<String, ReceiptVerdict> {
    let mut verdicts: BTreeMap<String, ReceiptVerdict> = BTreeMap::new();
    let mut bindings: BTreeMap<String, (String, u64)> = BTreeMap::new();
    for (evidence, observed_pending) in observation
        .pending
        .iter()
        .map(|evidence| (evidence, true))
        .chain(
            observation
                .resolved
                .iter()
                .map(|evidence| (evidence, false)),
        )
    {
        let identity = evidence.identity.clone();
        let binding = (evidence.request_digest.clone(), evidence.generation);
        let verdict = match (verdicts.get(&identity), bindings.get(&identity)) {
            (None, _) => {
                if observed_pending {
                    ReceiptVerdict::Pending
                } else {
                    ReceiptVerdict::Resolved
                }
            }
            (Some(_), Some(existing)) if *existing != binding => ReceiptVerdict::Conflict,
            (Some(ReceiptVerdict::Pending), _) if !observed_pending => ReceiptVerdict::Conflict,
            (Some(ReceiptVerdict::Resolved), _) if observed_pending => ReceiptVerdict::Conflict,
            (Some(verdict), _) => *verdict,
        };
        bindings.insert(identity.clone(), binding);
        verdicts.insert(identity, verdict);
    }
    verdicts
}

/// True when this observation proves the registered identity resolved. Absence
/// proves resolution only under the owner's explicit complete-snapshot
/// contract; otherwise a query miss preserves the obligation.
fn proven_resolved(
    verdicts: &BTreeMap<String, ReceiptVerdict>,
    identity: &str,
    absence_resolves: bool,
) -> bool {
    match verdicts.get(identity) {
        Some(ReceiptVerdict::Resolved) => true,
        Some(ReceiptVerdict::Pending | ReceiptVerdict::Conflict) => false,
        None => absence_resolves,
    }
}

/// Kernel-owned persisted shutdown/drain coordinator.
///
/// One instance per `work_root`, shared process-wide through
/// [`coordinator_for`] so the control plane (`request_shutdown`,
/// wake/attach race) and the composition root (`shutdown`) observe one
/// durable state without growing the composition struct.
pub(crate) struct ShutdownDrainCoordinator {
    path: PathBuf,
    state: Mutex<CoordinatorState>,
}

fn unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| {
            duration.as_millis().try_into().unwrap_or(u64::MAX)
        })
}

fn fresh_generation() -> String {
    format!("drain-{}-{}", unix_ms(), std::process::id())
}

fn registry() -> &'static Mutex<BTreeMap<PathBuf, Arc<ShutdownDrainCoordinator>>> {
    static REGISTRY: OnceLock<Mutex<BTreeMap<PathBuf, Arc<ShutdownDrainCoordinator>>>> =
        OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(BTreeMap::new()))
}

fn validate_durable_state(durable: &DurableDrainState) -> Result<(), String> {
    if durable.version != DRAIN_STATE_VERSION {
        return Err("shutdown state version is unsupported".to_owned());
    }
    if durable.generation.trim().is_empty() {
        return Err("shutdown state generation is empty".to_owned());
    }

    let mut phases = BTreeMap::new();
    for (order, evidence) in &durable.phases {
        if usize::from(*order) >= ShutdownPhase::ORDERED.len() || evidence.trim().is_empty() {
            return Err("shutdown state contains invalid phase evidence".to_owned());
        }
        if phases.insert(*order, evidence).is_some() {
            return Err("shutdown state contains duplicate phase evidence".to_owned());
        }
    }
    if let Some(last_order) = phases.keys().next_back().copied()
        && (0..=last_order).any(|order| !phases.contains_key(&order))
    {
        return Err("shutdown state phases are not an ordered prefix".to_owned());
    }
    if phases.contains_key(&ShutdownPhase::IntentionalPublished.order())
        && durable.committed.is_none()
    {
        return Err("shutdown state publishes before drain linearization".to_owned());
    }

    if let Some(committed) = &durable.committed {
        if !durable.requested
            || durable.cancelled
            || committed.generation != durable.generation
            || ShutdownPhase::PRE_COMMIT
                .iter()
                .any(|phase| !phases.contains_key(&phase.order()))
        {
            return Err("shutdown state has an invalid drain commit".to_owned());
        }
        // The recovered boundary is held to the same contract the
        // linearization point enforces, so recovery can never read a
        // `DrainCommitRecord` boundary the commit path would have refused.
        committed.validate()?;
        if durable.terminal.is_none() && !durable.pending.is_empty() {
            return Err("committed shutdown has pending work without a terminal".to_owned());
        }
    }

    // The installation-scoped fence must never name a lineage at sequence
    // zero: that is a blank identity, not a revocation. Every recorded fence
    // is a complete journal identity, held to the same rule the decision field
    // itself is.
    if durable
        .fenced_activation_generations
        .iter()
        .any(|(lineage, sequence)| {
            lineage.trim().is_empty()
                || *sequence == 0
                || SupervisionJournalEpoch {
                    lineage_id: lineage.clone(),
                    sequence: *sequence,
                }
                .validate("shutdown.fenced_activation_generations")
                .is_err()
        })
    {
        return Err("shutdown state contains an invalid activation fence".to_owned());
    }
    // Deliberately NO check that a recovered `committed` decision is covered by
    // the fence map: a state file written before the fence field existed
    // decodes with an empty map, so such a check would refuse exactly the
    // pre-field state the compatibility note above says must stay readable. The
    // one-directional repair in `load` covers that case by adding the fence,
    // and only a fence that is *behind* its own commit can be repaired, never
    // one that would un-fence an authority.

    // Pending identities are written only through the registration and
    // terminal paths, which refuse blank identities; a blank entry on disk
    // is corruption, never an obligation.
    if durable
        .pending
        .iter()
        .any(|identity| identity.trim().is_empty())
    {
        return Err("shutdown state contains invalid pending identity".to_owned());
    }

    if let Some(terminal) = &durable.terminal {
        if !durable.requested {
            return Err("shutdown state has a terminal without a request".to_owned());
        }
        if matches!(terminal, ShutdownTerminal::Intentional)
            && (durable.committed.is_none()
                || durable.cancelled
                || !durable.pending.is_empty()
                || ShutdownPhase::ORDERED
                    .iter()
                    .any(|phase| !phases.contains_key(&phase.order())))
        {
            return Err("shutdown state has an invalid intentional terminal".to_owned());
        }
    } else if !durable.requested
        && (durable.cancelled || durable.committed.is_some() || !phases.is_empty())
    {
        return Err("shutdown state has drain progress without a request".to_owned());
    }
    Ok(())
}

/// Returns the process-wide coordinator for one Kernel `work_root`,
/// recovering durable state from a previous process when present.
pub(crate) fn coordinator_for(work_root: &Path) -> Result<Arc<ShutdownDrainCoordinator>, String> {
    let path = work_root.join(".eliot").join(DRAIN_STATE_FILE);
    let mut guard = registry()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some(existing) = guard.get(&path) {
        return Ok(Arc::clone(existing));
    }
    let coordinator = Arc::new(ShutdownDrainCoordinator::load(path.clone())?);
    guard.insert(path, Arc::clone(&coordinator));
    Ok(coordinator)
}

impl ShutdownDrainCoordinator {
    fn load(path: PathBuf) -> Result<Self, String> {
        // The durable file is read through a bounded handle, so a corrupt or
        // hostile file is refused on its size instead of being read into an
        // unbounded buffer. Absent state is the only case that becomes fresh
        // state; every other read outcome stays an error the caller sees.
        let mut bounded = Vec::new();
        let mut state = match File::open(&path) {
            Ok(file) => {
                if let Err(error) = file
                    .take(DRAIN_STATE_MAX_BYTES + 1)
                    .read_to_end(&mut bounded)
                {
                    return Err(format!("shutdown state cannot be read: {error}"));
                }
                if bounded.len() as u64 > DRAIN_STATE_MAX_BYTES {
                    return Err("shutdown state exceeds the bounded decode limit".to_owned());
                }
                let durable: DurableDrainState = serde_json::from_slice(&bounded)
                    .map_err(|error| format!("shutdown state is unreadable: {error}"))?;
                validate_durable_state(&durable)?;
                let mut state = CoordinatorState::fresh(durable.generation);
                state.requested = durable.requested;
                state.cancelled = durable.cancelled;
                state.phases = durable.phases.into_iter().collect();
                state.committed = durable.committed;
                state.terminal = durable.terminal;
                state.pending = durable.pending.into_iter().collect();
                state.fenced_activation_generations = durable.fenced_activation_generations;
                // One-directional repair of a pre-field state: a recovered
                // linearization re-derives its own activation fence, because
                // the durable `DrainCommitRecord` it hands back still states
                // that revocation. Adding a fence can only refuse more, never
                // admit more, so a file written before the field existed is
                // fenced on read rather than revived.
                if let Some(fenced) = state
                    .committed
                    .as_ref()
                    .and_then(|committed| committed.activation_generation_fenced.clone())
                {
                    let recorded = state
                        .fenced_activation_generations
                        .entry(fenced.lineage_id)
                        .or_insert(0);
                    *recorded = (*recorded).max(fenced.sequence);
                }
                state
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                CoordinatorState::fresh(fresh_generation())
            }
            Err(error) => {
                return Err(format!("shutdown state cannot be read: {error}"));
            }
        };
        // Requested without a terminal means a previous process died
        // mid-drain: an interrupted drain, not an intentional stop.
        // Pending work is already retained above; nothing is discarded.
        state.recovered_interrupted = state.requested && state.terminal.is_none();
        if state.recovered_interrupted {
            observe_shutdown("kernel.shutdown.interrupted_recovered", "recovered");
        }
        Ok(Self {
            path,
            state: Mutex::new(state),
        })
    }

    fn persist_state(&self, state: &CoordinatorState) -> Result<(), String> {
        let durable = DurableDrainState {
            version: DRAIN_STATE_VERSION,
            generation: state.generation.clone(),
            requested: state.requested,
            cancelled: state.cancelled,
            phases: state
                .phases
                .iter()
                .map(|(order, evidence)| (*order, evidence.clone()))
                .collect(),
            committed: state.committed.clone(),
            terminal: state.terminal.clone(),
            pending: state.pending.iter().cloned().collect(),
            fenced_activation_generations: state.fenced_activation_generations.clone(),
        };
        // The write path is held to the same contract the recovery read path
        // enforces: a candidate the next process's `load` would refuse is
        // never written, so a reported success always names resumable durable
        // state instead of bricking the next resume.
        if let Err(reason) = validate_durable_state(&durable) {
            observe_shutdown("kernel.shutdown.persist_failed", "rejected");
            return Err(format!(
                "shutdown state candidate fails recovery validation: {reason}"
            ));
        }
        let payload = match serde_json::to_vec(&durable) {
            Ok(payload) => payload,
            Err(error) => {
                observe_shutdown("kernel.shutdown.persist_failed", "rejected");
                return Err(format!("shutdown state serialization failed: {error}"));
            }
        };
        // The bounded reader refuses files past `DRAIN_STATE_MAX_BYTES`; the
        // writer refuses to produce one, so no successful persist can brick
        // the next load through size alone.
        if payload.len() as u64 > DRAIN_STATE_MAX_BYTES {
            observe_shutdown("kernel.shutdown.persist_failed", "rejected");
            return Err("shutdown state payload exceeds the bounded decode limit".to_owned());
        }
        let parent = self.path.parent().unwrap_or_else(|| Path::new("."));
        if let Err(error) = fs::create_dir_all(parent) {
            observe_shutdown("kernel.shutdown.persist_failed", "rejected");
            return Err(format!(
                "shutdown state directory cannot be created: {error}"
            ));
        }

        let (temp_path, mut temp_file) = loop {
            let sequence = DRAIN_TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let temp_path = parent.join(format!(
                "kernel-shutdown-drain-{}-{sequence}.tmp",
                std::process::id()
            ));
            match OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&temp_path)
            {
                Ok(file) => break (temp_path, file),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => {
                    observe_shutdown("kernel.shutdown.persist_failed", "rejected");
                    return Err(format!("shutdown state staging failed: {error}"));
                }
            }
        };
        let write_result = temp_file
            .write_all(&payload)
            .and_then(|()| temp_file.sync_all());
        drop(temp_file);
        let stored = write_result.and_then(|()| durable_replace(&temp_path, &self.path));
        if let Err(error) = stored {
            let _ = fs::remove_file(&temp_path);
            observe_shutdown("kernel.shutdown.persist_failed", "rejected");
            return Err(format!("shutdown state persistence failed: {error}"));
        }
        Ok(())
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, CoordinatorState> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Records the shutdown request. Returns true for a new generation,
    /// including recovery of an interrupted drain; live repeats return false.
    pub(crate) fn request_shutdown(&self) -> Result<bool, String> {
        let mut state = self.lock();
        if state.requested && state.terminal.is_none() && !state.recovered_interrupted {
            return Ok(false);
        }
        // An interrupted generation cannot replay prior phase evidence as
        // current work. Start a fresh generation and retain unresolved work.
        let mut carried = state.pending.clone();
        if let Some(terminal) = &state.terminal {
            carried.extend(terminal.pending());
        }
        // The installation-scoped activation fence is carried forward across
        // the rollover, never reset. This is the point where a drain-generation
        // scoped fence would silently un-revoke: the previous generation's
        // `DrainCommitRecord` already fenced that activation generation, and
        // dropping the fence on rollover would let the very next wake/attach
        // present it and be answered `Proceed`. I1.5 scopes the fence to the
        // installation, not to a drain correlation id.
        let carried_fences = state.fenced_activation_generations.clone();
        let mut candidate = CoordinatorState::fresh(fresh_generation());
        candidate.requested = true;
        candidate.pending = carried;
        candidate.fenced_activation_generations = carried_fences;
        self.persist_state(&candidate)?;
        *state = candidate;
        observe_shutdown("kernel.shutdown.requested", "admitted");
        Ok(true)
    }

    /// Current drain generation identity (linearization correlation).
    pub(crate) fn drain_generation(&self) -> String {
        self.lock().generation.clone()
    }

    /// Records one ordered phase with its evidence. Phases must arrive in
    /// order; identical repeats are idempotent. Only
    /// `IntentionalPublished` may follow the linearization point.
    ///
    /// # Errors
    ///
    /// Returns a reason when no drain was requested, a terminal is already
    /// recorded, an earlier phase is missing, or a pre-commit phase arrives
    /// after linearization.
    pub(crate) fn record_phase(
        &self,
        phase: ShutdownPhase,
        evidence: String,
    ) -> Result<(), String> {
        let mut state = self.lock();
        if !state.requested {
            return Err("no shutdown requested".to_owned());
        }
        if state.terminal.is_some() {
            return Err("drain generation already terminated".to_owned());
        }
        if phase != ShutdownPhase::IntentionalPublished && state.committed.is_some() {
            return Err("pre-commit phase after drain linearization".to_owned());
        }
        for earlier in ShutdownPhase::ORDERED {
            if earlier.order() >= phase.order() {
                break;
            }
            if !state.phases.contains_key(&earlier.order()) {
                return Err(format!(
                    "phase {} missing before {}",
                    earlier.as_str(),
                    phase.as_str()
                ));
            }
        }
        if phase == ShutdownPhase::IntentionalPublished && state.committed.is_none() {
            return Err("intentional publication before drain linearization".to_owned());
        }
        if let Some(existing) = state.phases.get(&phase.order()) {
            if existing != &evidence {
                return Err("phase evidence cannot be rewritten".to_owned());
            }
            return Ok(());
        }
        let mut candidate = state.clone();
        candidate.phases.insert(phase.order(), evidence);
        self.persist_state(&candidate)?;
        *state = candidate;
        Ok(())
    }

    /// Registers one pending receipt/operation that must resolve before the
    /// canonical-drain gate completes.
    pub(crate) fn register_pending_receipt(&self, identity: String) -> Result<(), String> {
        let mut state = self.lock();
        if identity.trim().is_empty() {
            return Ok(());
        }
        if state.committed.is_some() || state.terminal.is_some() {
            return Err("pending receipt registration after drain commit".to_owned());
        }
        if state.pending.contains(&identity) {
            return Ok(());
        }
        let mut candidate = state.clone();
        candidate.pending.insert(identity);
        self.persist_state(&candidate)?;
        *state = candidate;
        Ok(())
    }

    /// Marks one pending receipt/operation resolved. Resolution normally
    /// arrives through [`Self::reconcile_pending_to_deadline`]'s rescan;
    /// this covers resolvers that already hold the exact identity.
    pub(crate) fn resolve_pending_receipt(&self, identity: &str) -> Result<(), String> {
        let mut state = self.lock();
        let terminal_pending = matches!(
            &state.terminal,
            Some(ShutdownTerminal::Incomplete { pending })
                if pending
                    .iter()
                    .any(|pending_identity| pending_identity == identity)
        );
        if !state.pending.contains(identity) && !terminal_pending {
            return Ok(());
        }
        let mut candidate = state.clone();
        candidate.pending.remove(identity);
        if let Some(ShutdownTerminal::Incomplete { pending }) = &mut candidate.terminal {
            pending.retain(|pending_identity| pending_identity != identity);
        }
        self.persist_state(&candidate)?;
        *state = candidate;
        Ok(())
    }

    /// Currently unresolved pending receipts/operations.
    pub(crate) fn pending_receipts(&self) -> Vec<String> {
        self.lock().pending.iter().cloned().collect()
    }

    /// Read-only projection of the durable `DrainCommitRecord` boundary: the
    /// linearization exactly as this coordinator persisted it, or `None` when
    /// this generation has not linearized.
    ///
    /// This is the production reader of the persisted decision. The commit
    /// path proves the boundary before writing it, and the recovery read path
    /// re-proves it on load, so a caller that needs to state the boundary must
    /// read it back here rather than reuse the value it happened to build:
    /// that is the whole content of the durable record, including after a
    /// restart, and it is what a downstream `DrainCommitRecord` has to agree
    /// with.
    pub(crate) fn committed_decision(&self) -> Option<DrainCommitDecision> {
        self.lock().committed.clone()
    }

    /// Requires the canonical-data lease-zero precondition before any
    /// store-stop request.
    pub(crate) const fn check_lease_zero(has_outstanding_lease: bool) -> Result<(), &'static str> {
        if has_outstanding_lease {
            Err("canonical-data lease outstanding")
        } else {
            Ok(())
        }
    }

    /// Bounded wait for pending receipts to resolve, driven by one typed
    /// owner observation per tick.
    ///
    /// The merge is `next = (current_pending UNION newly_observed_pending)
    /// MINUS exactly_proven_resolved`: the owner read runs without the
    /// coordinator mutex, removals are limited to the identities the
    /// observation proves resolved, and the drain generation and registered
    /// entries are rechecked under the lock before adoption. Only
    /// [`ReceiptReconciliation::Reconciled`] authorizes the next drain
    /// phase; a known-empty registry reached through an incomplete or
    /// unavailable observation is reported as a coverage failure instead.
    ///
    /// Each rescan receives the time still remaining on this one monotonic
    /// deadline, so an owner read that walks a family in several bounded pages
    /// is bounded by the same budget as the wait itself: a new scan resumes the
    /// remaining budget and can neither reset nor extend it.
    pub(crate) async fn reconcile_pending_observation(
        &self,
        deadline: Duration,
        family: ReceiptOwnerFamily,
        mut rescan: impl FnMut(Duration) -> Result<ReceiptRescanObservation, String>,
    ) -> ReceiptReconciliation {
        let start = Instant::now();
        // Highest owner revision already used to clear an obligation in this
        // wait. A later observation that reports an older revision must not
        // clear anything.
        let mut adopted_revision: Option<u64> = None;
        loop {
            // Snapshot the registered obligations and the drain generation
            // they are registered under. The owner read below runs without
            // the coordinator mutex, so a concurrent registration can only
            // land after this snapshot and is never a removal candidate.
            let (generation, baseline) = {
                let state = self.lock();
                (state.generation.clone(), state.pending.clone())
            };
            // A failed required read proves nothing in either direction and
            // can never authorize the next phase through an empty registry.
            let Ok(observation) = rescan(deadline.saturating_sub(start.elapsed())) else {
                observe_shutdown("kernel.shutdown.receipt_scan_unavailable", "unavailable");
                return ReceiptReconciliation::Unavailable {
                    reason: "receipt-owner-observation-unavailable",
                };
            };
            // Removal authority requires one current, complete observation of
            // the reconciled family. A partial read, a foreign family, or a
            // regressed owner revision retains every obligation.
            let covered = observation.family == family
                && observation.complete
                && adopted_revision.is_none_or(|seen| observation.revision >= seen);
            let verdicts = fold_rescan_observation(&observation);
            let merged = {
                let mut state = self.lock();
                if state.committed.is_some() || state.terminal.is_some() {
                    return ReceiptReconciliation::Unavailable {
                        reason: "receipt-reconciliation-after-drain-commit",
                    };
                }
                let mut candidate = state.clone();
                // A new drain generation owns a different obligation set, so
                // evidence read under the previous one is not adopted.
                if state.generation == generation {
                    if covered {
                        for identity in &baseline {
                            if proven_resolved(&verdicts, identity, observation.absence_resolves) {
                                candidate.pending.remove(identity);
                            }
                        }
                    }
                    for identity in observation
                        .pending
                        .iter()
                        .map(ReceiptOwnerEvidence::identity)
                    {
                        candidate.pending.insert(identity);
                    }
                }
                if candidate.pending != state.pending {
                    // Additions and valid removals reach the durable state
                    // owner before any progress is reported; a failed
                    // publication cannot be reported as reconciled-empty.
                    if self.persist_state(&candidate).is_err() {
                        observe_shutdown("kernel.shutdown.receipt_publish_failed", "unavailable");
                        return ReceiptReconciliation::Unavailable {
                            reason: "receipt-state-publication-failed",
                        };
                    }
                    *state = candidate;
                }
                state.pending.clone()
            };
            if !covered {
                // No subtraction is possible, so waiting cannot converge.
                observe_shutdown("kernel.shutdown.receipt_coverage_incomplete", "incomplete");
                return ReceiptReconciliation::Incomplete {
                    pending: merged.into_iter().collect(),
                    reason: "receipt-observation-incomplete-coverage",
                };
            }
            adopted_revision = Some(observation.revision.max(adopted_revision.unwrap_or(0)));
            if merged.is_empty() {
                return ReceiptReconciliation::Reconciled;
            }
            if start.elapsed() >= deadline {
                let reason = if merged
                    .iter()
                    .any(|identity| !verdicts.contains_key(identity))
                {
                    // A registered identity this owner family never reports
                    // stays pending: it is foreign or unparseable, and one
                    // family's scan can never clear another family's work.
                    "receipt-identity-not-observed-by-owner"
                } else {
                    "receipt-deadline-expired"
                };
                observe_shutdown("kernel.shutdown.receipt_deadline_expired", "incomplete");
                return ReceiptReconciliation::Incomplete {
                    pending: merged.into_iter().collect(),
                    reason,
                };
            }
            tokio::time::sleep(RECEIPT_POLL_INTERVAL).await;
        }
    }

    /// Untyped receipt-rescan boundary retained for the existing rescan
    /// call sites. It is a thin adapter over
    /// [`Self::reconcile_pending_observation`]: the legacy projection is one
    /// whole-family snapshot in which the caller asserts that anything it did
    /// not list is resolved, which the typed owner read never asserts.
    #[cfg(test)]
    pub(crate) async fn reconcile_pending_to_deadline(
        &self,
        deadline: Duration,
        mut rescan: impl FnMut() -> Result<Vec<String>, String>,
    ) -> Result<Vec<String>, String> {
        match self
            .reconcile_pending_observation(deadline, ReceiptOwnerFamily::StoreRebind, |_| {
                Ok(ReceiptRescanObservation {
                    family: ReceiptOwnerFamily::StoreRebind,
                    complete: true,
                    absence_resolves: true,
                    // The untyped projection carries no owner revision and no
                    // request binding, so it observes revision zero and binds
                    // nothing beyond the identity it was given.
                    revision: 0,
                    pending: rescan()?
                        .into_iter()
                        .filter(|identity| !identity.trim().is_empty())
                        .map(|identity| ReceiptOwnerEvidence {
                            identity,
                            request_digest: String::new(),
                            generation: 0,
                            revision: 0,
                        })
                        .collect(),
                    resolved: Vec::new(),
                })
            })
            .await
        {
            ReceiptReconciliation::Reconciled => Ok(Vec::new()),
            ReceiptReconciliation::Incomplete { pending, .. } => Ok(pending),
            ReceiptReconciliation::Unavailable { reason } => Err(reason.to_owned()),
        }
    }

    /// The `DrainCommit` linearization point: irrevocably fixes the drain
    /// generation, the reconciled (empty) snapshot, the fenced authority,
    /// and the branches to stop. Requires every pre-commit phase and an
    /// empty pending registry.
    ///
    /// Exact replay returns the same result: recommitting the identical
    /// decision is idempotent. A different decision for an already
    /// linearized generation conflicts instead of overwriting it. The
    /// decision's pending snapshot must itself be empty: linearization is
    /// admitted only on the reconciled-empty registry the receipt gate
    /// proved, so a decision carrying unreconciled work is rejected.
    ///
    /// # Errors
    ///
    /// Returns a reason when the drain was cancelled by a pre-linearization
    /// wake, a pre-commit phase is missing, pending work remains, the
    /// decision carries a foreign generation or an unreconciled snapshot,
    /// or a different decision is already linearized for this generation.
    pub(crate) fn commit_drain(&self, decision: DrainCommitDecision) -> Result<(), String> {
        let mut state = self.lock();
        if !state.requested {
            return Err("no shutdown requested".to_owned());
        }
        if state.terminal.is_some() {
            return Err("drain generation already terminated".to_owned());
        }
        if state.cancelled {
            return Err("drain cancelled by pre-linearization wake".to_owned());
        }
        if let Some(committed) = state.committed.as_ref() {
            return if committed == &decision {
                Ok(())
            } else {
                Err("drain decision conflicts with linearized commit".to_owned())
            };
        }
        for phase in ShutdownPhase::PRE_COMMIT {
            if !state.phases.contains_key(&phase.order()) {
                return Err(format!(
                    "phase {} missing before linearization",
                    phase.as_str()
                ));
            }
        }
        if !state.pending.is_empty() {
            return Err(format!(
                "{} pending receipts unresolved",
                state.pending.len()
            ));
        }
        if decision.generation != state.generation {
            return Err("drain decision carries a foreign generation".to_owned());
        }
        // The same boundary contract the recovery read path applies, so the
        // durable record can never be written in a shape it would refuse.
        decision.validate()?;
        let mut candidate = state.clone();
        // The linearization point and the activation-generation fence are
        // established together, under this one lock, and reach the durable
        // owner in this one write. A wake that acquires the lock first sets
        // `cancelled` and this commit refuses; a wake that acquires it after
        // reads the fence this write installed. There is no window in which a
        // commit is durable but its revocation is not, and none in which a
        // revocation is durable but the commit is not.
        if let Some(fenced) = decision.activation_generation_fenced.as_ref() {
            let recorded = candidate
                .fenced_activation_generations
                .entry(fenced.lineage_id.clone())
                .or_insert(0);
            *recorded = (*recorded).max(fenced.sequence);
        }
        candidate.committed = Some(decision);
        self.persist_state(&candidate)?;
        *state = candidate;
        observe_shutdown("kernel.shutdown.drain_committed", "committed");
        Ok(())
    }

    /// Classifies one wake/attach request against the linearization point:
    /// pre-linearization cancels the drain (`CancelDrain`); post-linearization
    /// the caller must await a fresh generation (`QueueNextGeneration`);
    /// a wake presenting an activation generation a linearized drain already
    /// fenced is stale (`RejectStale`). Without an active drain the request
    /// proceeds.
    ///
    /// The first thing this reads is the *installation-scoped* activation
    /// fence, before any per-generation drain state. That ordering is the
    /// linearizability property rather than a check on it: I1.5 pairs the
    /// drain correlation with an installation-scoped
    /// `activation_generation`, and "No caller may 'rescue' shutdown by
    /// reviving an old lease or process handle" holds across a drain
    /// generation rollover and across a process restart. Reading it after the
    /// `state.committed` check would scope the revocation to one drain
    /// correlation id, so a rollover into a fresh generation
    /// ([`Self::request_shutdown`]) or a process that starts with no drain in
    /// progress would answer `Proceed` to the exact activation generation a
    /// durable `DrainCommitRecord` states it fenced.
    ///
    /// The discriminator is the *activation generation*, not the drain
    /// correlation id. `DrainCommitDecision::generation` is minted by
    /// [`fresh_generation`] in this process and never crosses a wire boundary,
    /// so a waking `Activate` can never present it. Presenting an activation
    /// generation at or below a fenced sequence within the same lineage is
    /// reviving fenced authority (`RejectStale`); presenting one strictly
    /// beyond it is a caller establishing a *new* generation, so it is queued
    /// rather than rejected and no legitimate new-generation activation is
    /// refused.
    ///
    /// A wake presenting no activation generation at all is answered from the
    /// per-generation drain state alone: there is no identity to compare
    /// against a fence, and inventing one would let a caller that presents
    /// nothing pass a check that exists precisely to compare something.
    pub(crate) fn classify_wake(
        &self,
        presented_activation_generation: Option<&SupervisionJournalEpoch>,
    ) -> Result<DrainWakeDisposition, String> {
        let mut state = self.lock();
        if let Some(presented) = presented_activation_generation
            && fenced_activation_generation(&state.fenced_activation_generations, presented)
        {
            return Ok(DrainWakeDisposition::RejectStale);
        }
        if !state.requested {
            return Ok(DrainWakeDisposition::Proceed);
        }
        if state.committed.is_some() {
            // The installation fence above already rejected the fenced
            // generation, so everything reaching here is post-linearization
            // with an activation generation beyond the fence, and must wait
            // for a fresh one. A committed state whose
            // `activation_generation_fenced` is `None` — persisted by a build
            // that predates the field, and therefore carrying no fence to
            // reject against — is still refused here through
            // [`DrainWakeDisposition::fences_old_authority`], and it never has
            // to be migrated, quarantined, or repaired to be safe.
            return Ok(DrainWakeDisposition::QueueNextGeneration);
        }
        if state.terminal.is_some() {
            return Ok(DrainWakeDisposition::QueueNextGeneration);
        }
        if !state.cancelled {
            let mut candidate = state.clone();
            candidate.cancelled = true;
            self.persist_state(&candidate)?;
            *state = candidate;
            observe_shutdown("kernel.shutdown.drain_cancelled_by_wake", "cancelled");
        }
        Ok(DrainWakeDisposition::CancelDrain)
    }

    /// Handles one activation request arriving during shutdown: cancels
    /// pre-linearization drain and proceeds, or denies post-linearization
    /// activation so the caller re-establishes a fresh generation. The Kernel
    /// service independently fences `Activate` from `Draining`; this records
    /// the race disposition for evidence.
    ///
    /// The presented activation generation is the one the request's own
    /// candidate contour carries, so the post-linearization verdict is decided
    /// against a value that genuinely reached this call from the production
    /// `Activate` path and against the installation-scoped fence, not against
    /// this process's local drain correlation id.
    pub(crate) fn on_activate_request(
        &self,
        presented_activation_generation: &SupervisionJournalEpoch,
    ) -> Result<DrainWakeDisposition, String> {
        self.classify_wake(Some(presented_activation_generation))
    }

    /// Records the durable terminal. The first terminal wins; `Incomplete`
    /// retains its pending work. Intentional requires a prior linearization.
    pub(crate) fn complete_terminal(&self, terminal: ShutdownTerminal) -> Result<(), String> {
        let mut state = self.lock();
        if let Some(existing) = &state.terminal {
            return if existing == &terminal {
                Ok(())
            } else {
                Err("drain generation already has a different terminal".to_owned())
            };
        }
        if !state.requested {
            return Err("no shutdown requested".to_owned());
        }
        let mut candidate = state.clone();
        let (terminal, event) = match terminal {
            ShutdownTerminal::Intentional => {
                if candidate.committed.is_none() {
                    return Err("intentional terminal before drain linearization".to_owned());
                }
                if candidate.cancelled {
                    return Err("cancelled drain cannot complete intentionally".to_owned());
                }
                if !candidate
                    .phases
                    .contains_key(&ShutdownPhase::IntentionalPublished.order())
                {
                    return Err("intentional publication phase is missing".to_owned());
                }
                if !candidate.pending.is_empty() {
                    return Err("pending work prevents intentional terminal".to_owned());
                }
                (
                    ShutdownTerminal::Intentional,
                    "kernel.shutdown.terminal_intentional",
                )
            }
            ShutdownTerminal::Incomplete { pending } => {
                candidate.pending.extend(
                    pending
                        .into_iter()
                        .filter(|identity| !identity.trim().is_empty()),
                );
                let retained = candidate.pending.iter().cloned().collect();
                (
                    ShutdownTerminal::Incomplete { pending: retained },
                    "kernel.shutdown.terminal_incomplete",
                )
            }
        };
        candidate.terminal = Some(terminal);
        self.persist_state(&candidate)?;
        *state = candidate;
        observe_shutdown(event, "recorded");
        Ok(())
    }

    /// Read-only bounded drain disposition for the Kernel operational view.
    ///
    /// Unlike [`Self::classify_wake`] and [`Self::on_activate_request`] this
    /// never mutates the durable drain state: a diagnostic projection must not
    /// cancel a drain, and a reported disposition must be the one already
    /// recorded, not one produced by looking.
    ///
    /// The two terminals are reported distinctly, and a *persisted* incomplete
    /// terminal in particular. I14.23 requires that deadline expiry "produces
    /// visible incomplete-shutdown recovery state; it does not silently discard
    /// pending work", and this projection is the production reader
    /// ([`crate::KernelComposition::activation_operational_view`], re-exported
    /// through `crate::health_view`) that survives into the next process:
    /// collapsing both terminals into one `"terminated"` code made an
    /// interrupted-then-incomplete drain indistinguishable from a clean
    /// intentional stop to anyone reading the live view, which is the absence
    /// the requirement forbids.
    pub(crate) fn drain_disposition(&self) -> &'static str {
        let state = self.lock();
        if let Some(terminal) = &state.terminal {
            return match terminal {
                ShutdownTerminal::Intentional => "terminated-intentional",
                ShutdownTerminal::Incomplete { .. } => "terminated-incomplete",
            };
        }
        if state.committed.is_some() {
            return "queue-next-generation";
        }
        if state.cancelled {
            return "cancel-drain";
        }
        if state.requested {
            return "draining";
        }
        "proceed"
    }

    /// Reports whether a wake cancelled this generation's drain before the
    /// linearization point.
    ///
    /// Read-only, and deliberately not derived from
    /// [`Self::drain_disposition`]: the composition root needs to know
    /// whether the drain it must *not* finish was cancelled, which is a
    /// different question from what a diagnostic projection reports. A
    /// post-linearization wake never sets the flag (it resolves to
    /// `QueueNextGeneration`/`RejectStale` instead), and a recorded terminal
    /// ends the generation, so both are excluded here rather than reported as
    /// a cancellation.
    pub(crate) fn cancelled_by_wake(&self) -> bool {
        let state = self.lock();
        state.cancelled && state.committed.is_none() && state.terminal.is_none()
    }

    /// Read-only publication for Host and Watchdog over their existing
    /// control paths.
    pub(crate) fn publication(&self) -> ShutdownPublication {
        let state = self.lock();
        ShutdownPublication {
            generation: state.generation.clone(),
            requested: state.requested,
            phases_completed: ShutdownPhase::ORDERED
                .iter()
                .filter(|phase| state.phases.contains_key(&phase.order()))
                .map(|phase| phase.as_str().to_owned())
                .collect(),
            committed: state.committed.is_some(),
            cancelled: state.cancelled,
            recovered_interrupted: state.recovered_interrupted,
            terminal: state
                .terminal
                .as_ref()
                .map(ShutdownTerminal::as_str)
                .map(str::to_owned),
            pending: state.pending.iter().cloned().collect(),
        }
    }

    /// Emits the published terminal for Host/Watchdog observers: one fixed
    /// event with the durable outcome, never pending identities or digests.
    pub(crate) fn observe_published_state(&self) {
        let terminal = self.publication().terminal;
        let outcome = match terminal.as_deref() {
            Some("intentional-shutdown") => "intentional",
            Some("incomplete-shutdown") => "incomplete",
            _ => "unterminated",
        };
        observe_shutdown("kernel.shutdown.published", outcome);
    }
}

/// The canonical store branch of the composition contour.
pub(crate) const STORE_BRIDGE_BRANCH: &str = "store-bridge";
/// The supervised daemon branch of the composition contour.
pub(crate) const DAEMON_BRANCH: &str = "daemon";

/// One declared quiescence edge: `dependent` requires `dependency` to still be
/// running, so `dependent` must stop first.
///
/// This is a *declaration*, not an observation. The composition root states
/// which branch rides on which, and [`reverse_quiescence_order`] orders the
/// quiesce sequence from these edges alone. Deriving the order any other way —
/// from the order the branches were started, from the order this module
/// happens to check them in, or from a map iteration — re-states the startup
/// order as a shutdown order and is exactly the defect the declared edges
/// exist to remove (the same rule `ModuleCatalog::select_invalidation_dependents`
/// applies to restart selection: "selection walks the edges each dependent
/// *declared* ..., never the startup order, never iteration order").
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct QuiescenceEdge {
    pub(crate) dependent: &'static str,
    pub(crate) dependency: &'static str,
}

/// The composition root's declared dependency edges.
///
/// `eliotd` reaches canonical data only through the store bridge, so the
/// daemon is the dependent and the bridge is its dependency. That is a
/// structural fact about the contour, stated once here; the quiesce order is
/// computed from it rather than restated at each call site.
///
/// Scope note: the Governor's `eliot-module-registry` graph
/// (`ModuleDependency::invalidation_edges`, #1682) is the authority for
/// *optional* module dependencies, but `eliot-kernel` has no dependency edge
/// to that crate and the Kernel runtime root may not grow one, so these two
/// hard composition branches declare their own relation here. A branch with no
/// declared edge is refused rather than placed by assumption — see
/// [`reverse_quiescence_order`].
pub(crate) const KERNEL_QUIESCENCE_EDGES: [QuiescenceEdge; 1] = [QuiescenceEdge {
    dependent: DAEMON_BRANCH,
    dependency: STORE_BRIDGE_BRANCH,
}];

/// Returns the branches in quiescence order: every declared dependent before
/// the dependencies it requires, so a dependent stops before the store and
/// bridge it reads through.
///
/// `live_branches` is the contour the composition root actually observed, and
/// it is treated as a *set*: its input order carries no meaning and is not
/// consulted. The order is a topological order of the declared edges among the
/// live branches, with a lexical tie-break only so the result is deterministic
/// when no edge separates two branches — never a tie-break by startup order.
///
/// Completeness is proved against an expected set derived independently from
/// the declarations, not against the list being emitted: every live branch
/// must be named by a declared edge, and the emitted order must contain each
/// live branch exactly once.
///
/// # Errors
///
/// Returns a reason when the contour repeats a branch, when a live branch is
/// named by no declared edge (its position is unprovable, so it is refused
/// rather than ordered by assumption), or when the declared edges are cyclic
/// among the live branches and no quiescence order exists.
pub(crate) fn reverse_quiescence_order(live_branches: &[String]) -> Result<Vec<String>, String> {
    let live: BTreeSet<&str> = live_branches.iter().map(String::as_str).collect();
    if live.len() != live_branches.len() {
        return Err("quiescent contour contains duplicates".to_owned());
    }
    // The expected set comes from the declarations alone, independently of the
    // order this function will emit.
    let declared: BTreeSet<&str> = KERNEL_QUIESCENCE_EDGES
        .iter()
        .flat_map(|edge| [edge.dependent, edge.dependency])
        .collect();
    if live.iter().any(|branch| !declared.contains(*branch)) {
        return Err("quiescent contour has an undeclared branch".to_owned());
    }
    // Kahn's algorithm over the declared edges, keyed so that a branch is
    // emittable only once every branch that depends on it has already been
    // emitted: `outstanding[dependency]` holds the dependents still waiting on
    // that dependency. A dependency therefore never stops before the branches
    // that ride on it, which is the reverse of the startup order.
    let mut outstanding: BTreeMap<&str, BTreeSet<&str>> = live
        .iter()
        .map(|branch| (*branch, BTreeSet::new()))
        .collect();
    for edge in &KERNEL_QUIESCENCE_EDGES {
        if live.contains(edge.dependent)
            && live.contains(edge.dependency)
            && let Some(waited_on_by) = outstanding.get_mut(edge.dependency)
        {
            waited_on_by.insert(edge.dependent);
        }
    }
    let mut ordered: Vec<String> = Vec::with_capacity(live.len());
    while !outstanding.is_empty() {
        // The lexical minimum among the branches nothing depends on any more.
        // Deterministic, and it asserts no dependency the declarations did not
        // make.
        let Some(next) = outstanding
            .iter()
            .filter(|(_, waited_on_by)| waited_on_by.is_empty())
            .map(|(branch, _)| *branch)
            .min()
        else {
            return Err("declared quiescence edges are cyclic".to_owned());
        };
        outstanding.remove(next);
        ordered.push(next.to_owned());
        // This branch is stopped, so it no longer holds anything else back.
        for waited_on_by in outstanding.values_mut() {
            waited_on_by.remove(next);
        }
    }
    if ordered.len() != live.len() {
        return Err("quiescent contour was not fully ordered".to_owned());
    }
    Ok(ordered)
}

#[cfg(test)]
mod shutdown_drain_tests {
    #![allow(
        clippy::expect_used,
        reason = "focused drain proof uses expects for fixed-valid fixtures, matching the host-state test precedent"
    )]

    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn test_work_root(name: &str) -> PathBuf {
        let id = TEST_COUNTER.fetch_add(1, Ordering::AcqRel);
        let dir = std::env::temp_dir().join(format!(
            "eliot-shutdown-drain-test-{}-{}-{name}",
            std::process::id(),
            id
        ));
        let _ = std::fs::create_dir_all(&dir);
        dir
    }

    fn test_decision(generation: &str) -> DrainCommitDecision {
        DrainCommitDecision {
            generation: generation.to_owned(),
            lease_and_pending_snapshot: Vec::new(),
            authority_epochs_fenced: vec!["authority-epoch:1".to_owned()],
            activation_generation_fenced: Some(test_activation_generation()),
            branches_to_stop: vec!["daemon".to_owned(), "store-bridge".to_owned()],
            wake_disposition: DrainWakeDisposition::QueueNextGeneration,
            irreversible_stage: "authority-fenced".to_owned(),
            recovery_owner: "kernel-composition".to_owned(),
        }
    }

    fn test_activation_generation() -> SupervisionJournalEpoch {
        SupervisionJournalEpoch {
            lineage_id: "activation-lineage-1".to_owned(),
            sequence: 1,
        }
    }

    fn record_pre_commit(coordinator: &ShutdownDrainCoordinator) {
        for phase in ShutdownPhase::PRE_COMMIT {
            coordinator
                .record_phase(phase, format!("{}-evidence", phase.as_str()))
                .expect("ordered pre-commit phase records");
        }
    }

    #[tokio::test]
    async fn normal_shutdown_records_ordered_phases_and_linearizes_to_intentional() {
        let root = test_work_root("normal");
        let coordinator = coordinator_for(&root).expect("new drain coordinator loads");
        assert!(coordinator.request_shutdown().expect("shutdown persists"));

        // Out-of-order phases are rejected: the receipt gate cannot precede
        // admission closure.
        assert!(
            coordinator
                .record_phase(
                    ShutdownPhase::CanonicalDrainReceiptsReconciled,
                    "too-early".to_owned()
                )
                .is_err()
        );
        record_pre_commit(&coordinator);

        // Receipt reconciliation gate: a pending receipt blocks linearization
        // until the bounded wait proves it resolved.
        coordinator
            .register_pending_receipt("rebind-op-1".to_owned())
            .expect("pending receipt persists");
        assert!(
            coordinator
                .commit_drain(test_decision(&coordinator.drain_generation()))
                .is_err()
        );
        let held = coordinator
            .reconcile_pending_to_deadline(Duration::from_millis(20), || {
                Ok(vec!["rebind-op-1".to_owned()])
            })
            .await
            .expect("receipt rescan succeeds");
        assert_eq!(held, vec!["rebind-op-1".to_owned()]);
        coordinator
            .resolve_pending_receipt("rebind-op-1")
            .expect("resolved receipt persists");
        let cleared = coordinator
            .reconcile_pending_to_deadline(Duration::from_millis(20), || Ok(Vec::new()))
            .await;
        assert!(cleared.expect("receipt rescan succeeds").is_empty());

        coordinator
            .commit_drain(test_decision(&coordinator.drain_generation()))
            .expect("linearization after ordered phases and reconciled receipts");
        // Post-linearization phases other than publication are rejected.
        assert!(
            coordinator
                .record_phase(ShutdownPhase::FlushesCompleted, "late".to_owned())
                .is_err()
        );
        coordinator
            .record_phase(
                ShutdownPhase::IntentionalPublished,
                "poisoned-and-published".to_owned(),
            )
            .expect("publication follows linearization");

        // Reverse-dependency quiescence order used by the composition root,
        // derived from `KERNEL_QUIESCENCE_EDGES` rather than from the order
        // the branches are observed in: the same contour in either input
        // order quiesces daemon-before-store-bridge.
        assert_eq!(
            reverse_quiescence_order(&["store-bridge".to_owned(), "daemon".to_owned()])
                .expect("declared edges order both live branches"),
            vec!["daemon".to_owned(), "store-bridge".to_owned()]
        );
        assert_eq!(
            reverse_quiescence_order(&["daemon".to_owned(), "store-bridge".to_owned()])
                .expect("input order carries no meaning"),
            vec!["daemon".to_owned(), "store-bridge".to_owned()]
        );
        // A single live branch has no edge constraint left to satisfy.
        assert_eq!(
            reverse_quiescence_order(&["daemon".to_owned()])
                .expect("one live branch is fully ordered"),
            vec!["daemon".to_owned()]
        );
        assert!(reverse_quiescence_order(&["daemon".to_owned(), "daemon".to_owned()]).is_err());
        // A branch no declared edge names is refused rather than ordered by
        // assumption.
        assert!(reverse_quiescence_order(&["unrelated-module".to_owned()]).is_err());

        // Canonical-data lease-zero precondition used by the composition root.
        assert!(ShutdownDrainCoordinator::check_lease_zero(false).is_ok());
        assert!(ShutdownDrainCoordinator::check_lease_zero(true).is_err());

        coordinator
            .complete_terminal(ShutdownTerminal::Intentional)
            .expect("intentional terminal persists");
        let publication = coordinator.publication();
        assert_eq!(publication.phases_completed.len(), 8);
        assert!(publication.committed);
        assert_eq!(
            publication.terminal.as_deref(),
            Some("intentional-shutdown")
        );
        assert!(publication.pending.is_empty());

        // Durable evidence survives: terminal persisted, reload distinguishes
        // the intentional stop from an interrupted drain.
        let raw = std::fs::read(root.join(".eliot").join(DRAIN_STATE_FILE))
            .expect("drain state persisted");
        let durable: DurableDrainState =
            serde_json::from_slice(&raw).expect("durable drain state decodes");
        assert!(matches!(
            durable.terminal,
            Some(ShutdownTerminal::Intentional)
        ));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn deadline_expiry_yields_incomplete_and_wake_race_fenced() {
        let root = test_work_root("race");
        let coordinator = coordinator_for(&root).expect("new drain coordinator loads");
        assert!(coordinator.request_shutdown().expect("shutdown persists"));

        // A wake arriving before linearization cancels the drain.
        assert_eq!(
            coordinator
                .on_activate_request(&test_activation_generation())
                .expect("wake classification persists"),
            DrainWakeDisposition::CancelDrain
        );
        assert_eq!(
            coordinator
                .classify_wake(None)
                .expect("wake classification persists"),
            DrainWakeDisposition::CancelDrain
        );

        // Deadline expiry with pending work retains the pending list instead
        // of discarding it.
        coordinator
            .register_pending_receipt("rebind-op-9".to_owned())
            .expect("pending receipt persists");
        let remainder = coordinator
            .reconcile_pending_to_deadline(Duration::from_millis(30), || {
                Ok(vec!["rebind-op-9".to_owned()])
            })
            .await
            .expect("receipt rescan succeeds");
        assert_eq!(remainder, vec!["rebind-op-9".to_owned()]);
        coordinator
            .complete_terminal(ShutdownTerminal::Incomplete { pending: remainder })
            .expect("incomplete terminal persists");
        // Cancelled, unlinearized drain can never complete as intentional.
        let _ = coordinator.complete_terminal(ShutdownTerminal::Intentional);
        let publication = coordinator.publication();
        assert_eq!(publication.terminal.as_deref(), Some("incomplete-shutdown"));
        assert_eq!(publication.pending, vec!["rebind-op-9".to_owned()]);

        // Post-linearization race on a fresh drain: a wake carrying the
        // activation generation the commit fenced is stale; anything else
        // awaits a fresh generation.
        let root2 = test_work_root("race-committed");
        let committed = coordinator_for(&root2).expect("second drain coordinator loads");
        assert!(committed.request_shutdown().expect("shutdown persists"));
        record_pre_commit(&committed);
        let generation = committed.drain_generation();
        committed
            .commit_drain(test_decision(&generation))
            .expect("linearization");
        assert_eq!(
            committed
                .classify_wake(Some(&test_activation_generation()))
                .expect("wake classification is read-only after commit"),
            DrainWakeDisposition::RejectStale
        );
        assert_eq!(
            committed
                .classify_wake(Some(&SupervisionJournalEpoch {
                    lineage_id: "activation-lineage-foreign".to_owned(),
                    sequence: 9,
                }))
                .expect("wake classification is read-only after commit"),
            DrainWakeDisposition::QueueNextGeneration
        );
        assert_eq!(
            committed
                .on_activate_request(&SupervisionJournalEpoch {
                    lineage_id: "activation-lineage-foreign".to_owned(),
                    sequence: 9,
                })
                .expect("wake classification is read-only after commit"),
            DrainWakeDisposition::QueueNextGeneration
        );
        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_dir_all(&root2);
    }
}
