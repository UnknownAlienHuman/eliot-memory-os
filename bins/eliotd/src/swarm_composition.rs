//! Daemon swarm composition: Governor durable-job owner to native-worker dispatch.
//!
//! This module is the issue #1126 thin composition (slices W1/W4/W5, items
//! A1/A4/A5/A7, negative item A10, locality item A11) connecting one real
//! non-test path:
//!
//! Governor durable-job owner ([`SwarmAttachmentComposition`], owning one
//! [`SwarmPlanAttachmentService`] over the canonical
//! [`CanonicalSwarmPlanAttachmentStore`]) -> swarm consumer (vend port, pinned
//! handle, attach through the port) -> `AdapterRegistry` surface (route
//! adjudication: admitted, revoked, stale; first launch per class pins the
//! admitted generation, adapter-entry digest, and generation fingerprint,
//! and later drift is blocked with no silent substitution) -> native-worker
//! dispatch
//! (persist intent before executor call) -> reconciliation (rehydrate after
//! restart, reconcile nonterminal children before any relaunch, bounded
//! cancel drain to `terminal_ready`).
//!
//! # What this module does not do (candidate-only, A7)
//!
//! The composition emits execution *candidates* (launch intents, drain
//! decisions, rehydration reports) over caller-owned ports. It owns no task
//! lifecycle, no Finish path, no canonical-write path, no credential or
//! provider material, and no repair semantics: there is no `Finish`,
//! canonical-write-envelope, credential, or provider call anywhere in this
//! module. All durable decisions stay in their owner crates
//! (`eliot-coordination` attach-once decision, `eliot-swarm`
//! `durable_dispatch`/`durable_work`/`adapter_launch`); this module delegates
//! and enforces order, never re-decides.
//!
//! # Budget-exhaustion locality (A11)
//!
//! Budget exhaustion is observed at the child slot through
//! [`ChildRunner::observe`] as [`ChildExit::FailedExhausted`] and travels
//! through the drain as an exact terminal kind. The composition keeps no
//! budget counters, sums no spend, and never infers exhaustion: a slot is
//! exhausted only when its owner reports it.
//!
//! # Unknown stays unknown (A10-negative)
//!
//! [`ChildState::UnknownBlocked`] and [`ChildState::Stale`] children are
//! listed in the drain view and block the terminal aggregate; they never
//! become absent, failed, or safe-to-repeat by timeout. Rehydration compares
//! the rebuilt binding against the sealed attachment exactly: anything else
//! is refused.
//!
//! # Dependency note for the integrator
//!
//! `eliotd` depends on `eliot-governor` and `eliot-swarm` but not on
//! `eliot-coordination`, so:
//!
//! - Attachment calls go through the re-exported [`SwarmAttachmentComposition`]
//!   API. Binding fields are read through its public accessors and the store
//!   winner is recovered best-effort from the conflict rendering (see
//!   [`scrape_winner_job`]); once `eliot-coordination` is a direct dependency,
//!   replace [`SwarmCompositionError::AttachConflict`] classification with
//!   structural matching on `DurableAttachError` and read the winner binding
//!   directly.
//! - The swarm side ([`LaunchIntentLedger`], [`ChildRunner`], [`ChildState`],
//!   [`ChildExit`], [`plan_drain`]) mirrors the `eliot-swarm` owner shapes
//!   (`DurableWorkStore` append/load feeding seam, `WorkExecutor`
//!   launch/observe/cancel feeding seam, `ChildDisposition`, `TerminalKind`,
//!   `plan_cancellation_drain` with [`MAX_DRAIN_CANCELS_PER_PASS`]) field for
//!   field. The pass bound is build-pinned to the owner
//!   `eliot_swarm::durable_dispatch::MAX_PLAN_DRAIN_CANCELS` (see the `const _`
//!   assertion below), so owner drift fails the build. The integrator binds
//!   the real owner types with a small adapter;
//!   the order invariants enforced here (persist-before-launch,
//!   reconcile-before-relaunch, unknown-blocks-terminal, bounded passes) hold
//!   for any binding.
//!
//! # Activation (integrator one-liners)
//!
//! - `bins/eliotd/src/lib.rs`, after the `store_failure_projection` line:
//!   `pub mod swarm_composition;`
//! - Binary wiring (daemon owns exactly one composition over its one
//!   Governor attachment composition, one ledger owner, one runner owner):
//!   `let swarm = eliotd::swarm_composition::SwarmComposition::new(&attachment, &ledger, &runner);`
//!
//! [`SwarmAttachmentComposition`]: eliot_governor::SwarmAttachmentComposition
//! [`SwarmPlanAttachmentService`]: eliot_governor::SwarmPlanAttachmentService
//! [`CanonicalSwarmPlanAttachmentStore`]: eliot_governor::CanonicalSwarmPlanAttachmentStore

use std::collections::{BTreeMap, BTreeSet};

use eliot_governor::SwarmAttachmentComposition;
use eliot_swarm::durable_dispatch::MAX_PLAN_DRAIN_CANCELS;
use thiserror::Error;

/// Upper bound on exact active children named for cancellation in one drain
/// pass.
///
/// Bound to the `eliot-swarm` owner `MAX_PLAN_DRAIN_CANCELS`: termination is
/// structural, one pass names at most this many cancels and any further active
/// child waits for the next pass.
pub const MAX_DRAIN_CANCELS_PER_PASS: usize = 16;

/// Build-enforced binding between the daemon drain bound and the
/// `eliot-swarm` durable child owner bound (issue #1126 W5/A7: the daemon
/// drain follows the owner decision's structural bound instead of carrying a
/// free copy; owner drift fails the build, never the drain).
const _: () = assert!(MAX_DRAIN_CANCELS_PER_PASS == MAX_PLAN_DRAIN_CANCELS);

/// Upper bound on drain passes inside one [`SwarmComposition::drain_bounded`]
/// call.
///
/// The loop exits earlier on the terminal aggregate, an unknown block, a
/// shared-authority halt, or a bounded partial (zero allowance, or a pass
/// with no new cancel request and no newly observed terminal); the bound
/// additionally caps a runner whose cancels never take effect, so a drain
/// call always terminates.
pub const MAX_DRAIN_PASSES: u32 = 64;

/// Registry verdict for one route class, projected from the `AdapterRegistry`
/// surface by the caller that owns the registry.
///
/// Mirrors `eliot-swarm` `RegistryRouteDecision`: this module never touches
/// the registry itself and constructs no adapter or provider.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RegistryRouteStatus {
    /// The route class is currently admitted.
    Admitted,
    /// The route class was revoked; launch is blocked with no fallback.
    Revoked,
    /// The route class entry is stale; launch is blocked with no fallback.
    Stale,
}

/// Exact terminal outcome of one child slot.
///
/// Mirrors `eliot-swarm` `TerminalKind` variant for variant: proved-no-effect,
/// exhaustion, pre-launch versus post-effect cancellation, and partial
/// coverage stay separate. One terminal flag never erases these distinctions.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ChildExit {
    /// The child completed and its completion evidence is recorded.
    Completed,
    /// The child failed with proof it produced no effect.
    FailedProvedNoEffect,
    /// The child exhausted its budget at its own slot (see locality note in
    /// the module docs: observed, never inferred here).
    FailedExhausted,
    /// Cancellation won before launch; the child never executed.
    CancelledBeforeLaunch,
    /// Cancellation won after the child may have produced effects.
    CancelledAfterEffect,
    /// The child ended with partial coverage.
    Partial,
}

/// Child disposition derived from the live child record.
///
/// Mirrors `eliot-swarm` `ChildDisposition`: terminal kinds pass through,
/// live children stay open, and unreachable or possibly-effected children
/// stay blocked. [`ChildState::UnknownBlocked`] and [`ChildState::Stale`]
/// never become absent, failed, or safe-to-repeat.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ChildState {
    /// The child is live; drain names it for cancellation.
    Running,
    /// The child ended with its exact terminal kind.
    Terminal(ChildExit),
    /// The child is unreachable with possible effect; blocks the terminal.
    UnknownBlocked,
    /// The child observation is stale; blocks the terminal.
    Stale,
}

impl ChildState {
    /// Returns the exact terminal kind for terminal children, `None` while
    /// the child is still open or blocked.
    #[must_use]
    pub const fn terminal_kind(self) -> Option<ChildExit> {
        match self {
            Self::Terminal(kind) => Some(kind),
            Self::Running | Self::UnknownBlocked | Self::Stale => None,
        }
    }
}

/// Owned snapshot of one canonical plan-to-job binding.
///
/// Built only from the canonical attach decision through its public
/// accessors, so the snapshot echoes exactly what the Governor owner
/// committed: admission digest, plan revision, job handle, fence digest, and
/// the canonical binding digest. Rehydration compares a rebuilt snapshot
/// against the sealed one field for field.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AttachedPlan {
    /// Opaque Governor admission identity the plan was admitted under.
    pub admission_digest: String,
    /// Frozen swarm plan revision the binding was sealed against.
    pub plan_revision: String,
    /// Opaque Governor-owned durable job handle the plan is bound to.
    pub job_handle: String,
    /// State-fence digest pinned by the attachment.
    pub fence_digest: String,
    /// Canonical digest over the exact binding tuple above.
    pub binding_digest: String,
}

/// One child launch intent with stable derived identity.
///
/// The operation identity derives from `(job_handle, plan_revision, slot)`
/// and the attempt identity appends `-attempt`, mirroring the `eliot-swarm`
/// `dispatch_child` derivation: changed input requires a new slot identity,
/// never a silent relaunch under an existing one. The cancellation identity
/// appends `-cancel` to the operation identity (issue #1126 How-to-do: one
/// deterministic attempt and cancellation identity derived from the parent,
/// child slot, plan revision and State Fence). The fence is bound per child:
/// [`SwarmComposition::launch_child`] copies the fence digest the Governor
/// owner validated at attach into the intent, so the lineage survives restart
/// in the ledger itself; rehydration refuses a persisted intent whose fence
/// digest, operation derivation, or attempt derivation drifted from the
/// sealed attachment. The cancel path resolves the slot to this identity
/// from the ledger-persisted intent; rehydration refuses a persisted intent
/// whose cancellation identity does not match the derivation.
///
/// The registry half of the lineage travels as opaque caller-projected
/// material mirroring `eliot-swarm` `RegistryRouteAdjudication`: the
/// adapter-entry digest and the generation fingerprint pin per route class
/// exactly like `generation`, so a replaced backing adapter under an
/// admitted class cannot silently substitute a new result for the same
/// logical attempt. The Kernel `#22` one-shot permit itself never travels
/// here (opaque, non-`Clone`, consumed at the executor boundary); the
/// process receipt arrives after launch through runner observation, and the
/// result identity through the exact terminal kind, never as intent fields.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChildLaunchIntent {
    /// Stable operation identity `job_handle:plan_revision:slot`.
    pub operation_id: String,
    /// Stable attempt identity `operation_id-attempt`.
    pub attempt_id: String,
    /// Deterministic cancellation identity `operation_id-cancel`.
    pub cancellation_id: String,
    /// Child slot this intent dispatches.
    pub slot: String,
    /// Durable job handle the child derives from.
    pub job_handle: String,
    /// Admitted plan revision the child derives from.
    pub plan_revision: String,
    /// State-fence digest the Governor owner validated at attach, copied
    /// per child at launch so rehydration verifies fence lineage without
    /// trusting process memory.
    pub fence_digest: String,
    /// Registry-admitted route class sealing the dispatch envelope.
    pub route_class: String,
    /// Generation pinned to this launch by the generation-permit owner.
    pub generation: u64,
    /// Registry adapter-entry digest the launch was sealed against.
    ///
    /// Opaque caller-projected material: this module never touches the
    /// registry itself. Pinned per route class on first launch; later drift
    /// is refused with no silent substitution.
    pub adapter_entry_digest: [u8; 32],
    /// Opaque generation fingerprint bound to `generation` by the
    /// generation-permit owner. Pinned per route class like `generation`;
    /// drift is refused.
    pub generation_fingerprint: [u8; 32],
}

/// Bounded drain decision for one attached swarm plan denominator.
///
/// Mirrors `eliot-swarm` `PlanDrain`: the decision is pure, mints no dispatch,
/// performs no launch, and calls no executor. The caller executes each named
/// cancel through the owner-side path and re-runs the drain on the
/// re-observed dispositions until `terminal_ready`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlanDrainView {
    /// Exact active children to cancel through the owner-side path this pass.
    /// Requested, not observed-terminated: the caller services this set even
    /// when `unknown` is nonempty (issue #2652).
    pub cancel: Vec<String>,
    /// Active children beyond this pass's bound; cancel them on later passes.
    pub pending: Vec<String>,
    /// Unknown or stale children that block the terminal aggregate.
    pub unknown: Vec<String>,
    /// Accounted terminal children with their exact terminal kinds.
    pub terminal: Vec<(String, ChildExit)>,
    /// Whether a terminal aggregate may publish: every child accounted and
    /// no cancel outstanding or unknown.
    pub terminal_ready: bool,
}

/// Rehydration report after a daemon restart.
///
/// Every intent the ledger persisted is listed with its reconciled owner-side
/// state; unknown stays unknown. No launch happens during rehydration:
/// relaunch goes only through
/// [`SwarmComposition::launch_child`], which additionally requires the
/// reconcile flag this report sets.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RehydrationReport {
    /// The sealed plan binding the canonical owner re-confirmed.
    pub plan: AttachedPlan,
    /// Every persisted launch intent with its reconciled child state.
    pub children: Vec<(ChildLaunchIntent, ChildState)>,
}

/// Terminal outcome of [`SwarmComposition::drain_bounded`].
///
/// Progress and uncertainty travel together (issue #2652 step 5): exact
/// terminal kinds, requested-not-terminated cancels, retained unknown
/// children, and typed child-local failures. Cancellation never erases prior
/// effects and a request `Ok(())` never proves termination.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DrainOutcome {
    /// Accounted terminal children with their exact terminal kinds. Only an
    /// observed [`ChildState::Terminal`] lands here, so this list alone
    /// proves settlement.
    pub terminal: Vec<(String, ChildExit)>,
    /// Slots whose cancellation was requested through the owner-side path
    /// across all passes. Requested, NOT observed-terminated: the owner-side
    /// `cancel` port returns no acknowledgement detail, so no finer
    /// requested/acknowledged split is available here; re-observation through
    /// the runner reconciles each requested slot to terminal or retains it.
    /// Cancellation never claims rollback of already executed effect (I14.13).
    pub cancel_requested: Vec<String>,
    /// Active children beyond the pass bound at finish; empty once
    /// `terminal_ready` publishes.
    pub pending: Vec<String>,
    /// Unknown or stale children retained at finish; empty once
    /// `terminal_ready` publishes. Unknown is never cleared, never terminal.
    pub unknown: Vec<String>,
    /// Typed child-local observe/cancel failures recorded against their exact
    /// slots without stopping independently eligible siblings.
    pub local_failures: Vec<ChildLocalFailure>,
    /// Drain passes executed (at least one).
    pub passes: u32,
}

/// Scope of a failure observed through a slot-scoped drain call.
///
/// Narrow structural projection for the drain loops (issue #2652 step 2): no
/// message text is ever inspected for a safety decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FailureScope {
    /// Confined to one child slot. The shared authority (attached plan,
    /// ledger, fence, route pins) is untouched by the failed slot-scoped
    /// `observe`/`cancel` call, so independently eligible siblings stay
    /// eligible and the failure records against its exact slot instead of
    /// aborting the pass. A pass that records only child-local failures still
    /// ends without progress, so mass local failure surfaces as a bounded
    /// partial, never a false terminal.
    ChildLocal,
    /// Shared authority, identity, or plan state. Stops new effects
    /// immediately; everything completed before it stays reported.
    Global,
}

/// Slot-scoped drain operation that recorded a child-local failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DrainFailureOp {
    /// The failure came from the per-slot observation call.
    Observe,
    /// The failure came from the per-slot cancellation call.
    Cancel,
}

/// One child-local drain failure recorded against its exact child identity
/// (issue #2652 step 2).
///
/// The detail is opaque operator rendering carried for diagnosis; it is never
/// parsed for a safety decision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChildLocalFailure {
    /// Exact child slot that recorded the failure.
    pub slot: String,
    /// Whether observation or cancellation failed for the slot.
    pub op: DrainFailureOp,
    /// Opaque failure rendering; never inspected for scope.
    pub detail: String,
}

/// Reason a drain call stopped early with a bounded partial instead of
/// spinning (issue #2652 step 4).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DrainPartialReason {
    /// The caller allowed zero cancels per pass while live children remain:
    /// every live child parks in `pending` and the single observe+decide pass
    /// is the explicit partial outcome.
    ZeroCancelAllowance,
    /// A full pass requested no new cancel and observed no new terminal, so
    /// further passes within this call settle nothing; the caller re-invokes
    /// on its own cadence after the runner settles.
    NoProgress,
}

/// Fail-closed errors from the daemon swarm composition.
///
/// Candidate-only mapping: no variant finishes work, writes canonical state,
/// or mints credentials. Decision refusals surface the canonical winner
/// where recoverable; anything unrecognized fails closed with its detail.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum SwarmCompositionError {
    /// An input identity was blank or carried no usable value. Fails before
    /// any owner is contacted.
    #[error("invalid swarm composition field: {field}")]
    InvalidInput {
        /// Field that failed validation.
        field: &'static str,
    },
    /// The canonical decision refused the bind: the plan key is already bound
    /// to a different job. Final for the plan key; retrying the same second
    /// job cannot succeed.
    #[error("swarm plan already attached to a different durable job: {detail}")]
    AttachConflict {
        /// Canonical winner job handle, best-effort recovered (see
        /// [`scrape_winner_job`]); `None` when unrecoverable.
        winner_job: Option<String>,
        /// Full decision rendering for operators.
        detail: String,
    },
    /// The durable store failed underneath a load or commit attempt.
    #[error("swarm composition durable store failed: {detail}")]
    StoreFailure {
        /// Opaque store failure rendering; no provider payload crosses here.
        detail: String,
    },
    /// Every commit attempt contended with another committed writer. The bind
    /// was NOT committed; reloading observes the canonical winner.
    #[error("swarm composition commit contended: {detail}")]
    ContentionExhausted {
        /// Contention rendering for operators.
        detail: String,
    },
    /// The canonical decision refused the bind for a non-conflict reason
    /// (invalid snapshot, serialization, or an unrecognized decision shape).
    #[error("swarm composition attachment refused: {detail}")]
    AttachmentRefused {
        /// Decision rendering for operators.
        detail: String,
    },
    /// The rebuilt binding after restart did not equal the sealed attachment
    /// exactly. An unknown outcome never becomes absent, failed, or
    /// safe-to-repeat by timeout alone.
    #[error("swarm composition rehydration mismatch: {detail}")]
    InternalContract {
        /// What differed, for operators.
        detail: String,
    },
    /// The route class is not currently admitted (revoked, stale, or blank).
    /// Launch is blocked with no fallback and no direct provider
    /// construction.
    #[error("swarm composition route blocked: {detail}")]
    RouteBlocked {
        /// Route class and verdict, for operators.
        detail: String,
    },
    /// Plan, job, or fence identity drifted from the sealed attachment.
    #[error("swarm composition stale lineage: {detail}")]
    StaleLineage {
        /// What drifted, for operators.
        detail: String,
    },
    /// A launch was requested before reconciliation finished after a restart.
    /// Rehydrate first; nonterminal children reconcile before any relaunch.
    #[error("swarm composition requires reconciliation before launch")]
    ReconcileRequired,
    /// The slot already has a persisted launch intent. Changed input requires
    /// a new slot identity and an explicit parent revision, never a silent
    /// relaunch under an existing identity.
    #[error("swarm composition duplicate child slot: {slot}")]
    DuplicateSlot {
        /// Slot that already carries a persisted intent.
        slot: String,
    },
    /// No plan is attached yet; attach before launching or draining.
    #[error("swarm composition has no attached plan")]
    PlanNotAttached,
    /// The child denominator is empty; there is nothing to drain.
    #[error("swarm composition child denominator is empty")]
    EmptyDenominator,
    /// Unknown or stale children block the terminal aggregate. They never
    /// become absent, failed, or safe-to-repeat; reconcile them first.
    /// Carries the progress served before the block (requested cancels,
    /// observed terminals, pending, recorded local failures): the authorized
    /// `cancel` set is always served first, so unknown blocks only the
    /// terminal aggregate, never cancellation of known live siblings.
    #[error("swarm composition terminal blocked by unknown children")]
    TerminalBlocked {
        /// Slots that must reconcile before any terminal aggregate publishes.
        unknown: Vec<String>,
        /// Progress completed before the block; unknown children retained.
        progress: Box<DrainOutcome>,
    },
    /// The drain pass bound was exhausted, typically because cancels never
    /// take effect at the runner. No terminal aggregate published; everything
    /// completed across the executed passes stays reported.
    #[error("swarm composition drain pass bound exhausted after {passes} passes")]
    DrainBoundExhausted {
        /// Passes actually executed.
        passes: u32,
        /// Progress completed across the executed passes.
        progress: Box<DrainOutcome>,
    },
    /// The drain stopped early with an explicit bounded partial instead of
    /// spinning: zero cancel allowance, or a full pass with no new cancel
    /// request and no newly observed terminal. No terminal aggregate
    /// published; everything completed stays reported.
    #[error("swarm composition drain stopped early with a bounded partial: {reason:?}")]
    DrainBudgetPartial {
        /// Why the call stopped without spinning.
        reason: DrainPartialReason,
        /// Progress completed in the executed passes.
        progress: Box<DrainOutcome>,
    },
    /// A shared-authority failure stopped new effects mid-drain. Everything
    /// completed before it stays reported in `progress`; the exact failure
    /// stays typed in `cause`.
    #[error("swarm composition drain halted on a shared-authority failure: {cause}")]
    DrainHalted {
        /// The global failure that stopped new effects.
        cause: Box<SwarmCompositionError>,
        /// Progress completed before the halt.
        progress: Box<DrainOutcome>,
    },
    /// The persistence or runner owner failed underneath the composition.
    #[error("swarm composition owner failed: {detail}")]
    OwnerFailure {
        /// Opaque owner failure rendering.
        detail: String,
    },
}

impl SwarmCompositionError {
    /// Projects a drain-loop failure to its scope without inspecting message
    /// text (issue #2652 step 2).
    ///
    /// Only [`SwarmCompositionError::OwnerFailure`] returned from a
    /// slot-scoped [`ChildRunner::observe`]/[`ChildRunner::cancel`] call is
    /// child-local: the composition's shared authority (attached plan,
    /// ledger, fence, route pins) is untouched by that call, so the failure
    /// records against its exact slot and siblings continue. This projection
    /// is only consulted for those slot-scoped drain calls. Every other
    /// variant names shared authority, identity, or plan state — revoked
    /// authorization (`RouteBlocked`), identity or fence drift
    /// (`StaleLineage`, `InternalContract`, `DuplicateSlot`), an unavailable
    /// common owner (`StoreFailure`, `ContentionExhausted`,
    /// `AttachmentRefused`, `AttachConflict`), or plan state
    /// (`PlanNotAttached`, `ReconcileRequired`, `InvalidInput`,
    /// `EmptyDenominator`, and the drain exits themselves) — and stops new
    /// effects immediately with progress kept.
    #[must_use]
    pub const fn drain_failure_scope(&self) -> FailureScope {
        match self {
            Self::OwnerFailure { .. } => FailureScope::ChildLocal,
            _ => FailureScope::Global,
        }
    }
}

/// Persistence owner port for launch intents (durable staged-work store).
///
/// Mirrors the `eliot-swarm` `DurableWorkStore` append/load feeding seam:
/// restart safety belongs to the owner; the composition only enforces that
/// [`SwarmComposition::launch_child`] appends before calling the runner.
/// Deterministic fake owners prove the order protocol, not disk behavior.
pub trait LaunchIntentLedger: Send + Sync {
    /// Appends one immutable launch intent and echoes its durable sequence.
    fn append_intent(&self, intent: &ChildLaunchIntent) -> Result<u64, SwarmCompositionError>;
    /// Loads every persisted intent in append order.
    fn intents(&self) -> Vec<ChildLaunchIntent>;
}

/// External child-launch/observe/cancel owner (native-worker dispatch surface).
///
/// Mirrors the `eliot-swarm` `WorkExecutor` launch/observe/cancel feeding
/// seam over the AdapterRegistry-admitted route. The composition never forks
/// a process or invokes a provider itself; the owner behind this port does.
pub trait ChildRunner: Send + Sync {
    /// Attempts one launch for a previously persisted intent.
    fn launch(&self, intent: &ChildLaunchIntent) -> Result<(), SwarmCompositionError>;
    /// Observes one child by stable slot.
    ///
    /// Failure projection for the drain loops (issue #2652): return
    /// [`SwarmCompositionError::OwnerFailure`] for a failure confined to this
    /// slot; a shared-authority, identity, or plan-state failure uses its own
    /// structural variant so the drain stops new effects with progress kept.
    /// The composition never parses the detail text.
    fn observe(&self, slot: &str) -> Result<ChildState, SwarmCompositionError>;
    /// Requests cancellation through the external cancel owner.
    ///
    /// `Ok(())` reports request submission, never termination: the drain
    /// records it as requested-not-terminated and reconciles the same slot
    /// identity through re-observation. Resolve the slot to the
    /// ledger-persisted intent's cancellation identity in the owner. Same
    /// failure projection as [`ChildRunner::observe`].
    fn cancel(&self, slot: &str) -> Result<(), SwarmCompositionError>;
}

fn require_text(value: &str, field: &'static str) -> Result<(), SwarmCompositionError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(SwarmCompositionError::InvalidInput { field });
    }
    Ok(())
}

/// Derives the deterministic cancellation identity for one child launch
/// intent from its operation identity.
///
/// Issue #1126 How-to-do requires one deterministic attempt and cancellation
/// identity derived from the parent, child slot, plan revision and State
/// Fence. The operation identity already binds parent job, plan revision and
/// slot; the fence binds through the attached plan (launch requires an
/// attached plan whose fence digest the Governor owner validated at attach),
/// so appending the fixed `-cancel` discriminator keeps the derivation
/// exact with no invented material.
fn expected_cancellation_id(operation_id: &str) -> String {
    format!("{operation_id}-cancel")
}

/// Reads the admitted route pin for one route class, if any.
///
/// Returns `None` for a class with no launch yet under the attached plan;
/// the first launch pins generation, adapter digest, and generation
/// fingerprint together (see [`SwarmComposition::launch_child`]).
fn find_pin<'b>(bindings: &'b [RouteBindingPin], route_class: &str) -> Option<&'b RouteBindingPin> {
    bindings.iter().find(|pin| pin.class == route_class)
}

/// Verifies one launch intent's lineage against the sealed attachment.
///
/// Fail-closed, in order: an intent for another job or plan revision is
/// [`SwarmCompositionError::StaleLineage`]; an intent whose operation
/// identity does not re-derive from its own `(job_handle, plan_revision,
/// slot)` is `StaleLineage` (identity drift against the sealed attachment);
/// an intent whose attempt or cancellation identity does not match the
/// derivation is [`SwarmCompositionError::InternalContract`]; an intent
/// whose fence digest differs from the sealed fence digest is `StaleLineage`
/// (fence drift fails closed: a fence that moved under a persisted child is
/// refused, never re-pinned).
///
/// Shared by both directions: [`SwarmComposition::launch_child`] runs this
/// check on the fresh intent before the durable append (a drifted derivation
/// can neither persist nor reconcile later), and
/// [`reconcile_persisted_intent`] runs it on every ledger intent before any
/// relaunch is allowed.
fn check_intent_lineage(
    intent: &ChildLaunchIntent,
    sealed: &AttachedPlan,
) -> Result<(), SwarmCompositionError> {
    if intent.job_handle != sealed.job_handle || intent.plan_revision != sealed.plan_revision {
        return Err(SwarmCompositionError::StaleLineage {
            detail: format!(
                "launch intent for slot {} disagrees with sealed attachment",
                intent.slot
            ),
        });
    }
    let derived_operation = format!(
        "{}:{}:{}",
        intent.job_handle, intent.plan_revision, intent.slot
    );
    if intent.operation_id != derived_operation {
        return Err(SwarmCompositionError::StaleLineage {
            detail: format!(
                "launch intent for slot {} carries a drifted operation identity",
                intent.slot
            ),
        });
    }
    if intent.attempt_id != format!("{}-attempt", intent.operation_id) {
        return Err(SwarmCompositionError::InternalContract {
            detail: format!(
                "launch intent for slot {} carries a drifted attempt identity",
                intent.slot
            ),
        });
    }
    if intent.cancellation_id != expected_cancellation_id(&intent.operation_id) {
        return Err(SwarmCompositionError::InternalContract {
            detail: format!(
                "launch intent for slot {} carries a drifted cancellation identity",
                intent.slot
            ),
        });
    }
    if intent.fence_digest != sealed.fence_digest {
        return Err(SwarmCompositionError::StaleLineage {
            detail: format!(
                "launch intent for slot {} carries a drifted fence digest",
                intent.slot
            ),
        });
    }
    Ok(())
}

/// Admitted route pin for one route class under the attached plan.
///
/// The first launch per class pins the generation, the registry
/// adapter-entry digest, and the opaque generation fingerprint together: a
/// replaced backing route or adapter under an admitted class carries
/// different material, and launching it under the attached plan would
/// silently substitute a new result for the same logical scope. Pins rebuild
/// from the ledger on rehydration, so a restart cannot revive stale route
/// authority.
#[derive(Clone, Debug, Eq, PartialEq)]
struct RouteBindingPin {
    /// Registry-admitted route class this pin seals.
    class: String,
    /// Generation admitted for the class at pin time.
    generation: u64,
    /// Adapter-entry digest admitted for the class at pin time.
    adapter_digest: [u8; 32],
    /// Generation fingerprint admitted for the class at pin time.
    generation_fingerprint: [u8; 32],
}

/// Verifies one ledger-persisted intent against the sealed attachment and
/// folds its route binding into the rebuilt pins.
///
/// Runs [`check_intent_lineage`] first, then folds the route binding:
/// intents disagreeing on one class generation, adapter digest, or
/// generation fingerprint under the sealed attachment are `InternalContract`
/// (the ledger cannot have drifted through
/// [`SwarmComposition::launch_child`], so disagreement is refused rather
/// than narrowed).
fn reconcile_persisted_intent(
    intent: &ChildLaunchIntent,
    sealed: &AttachedPlan,
    bindings: &mut Vec<RouteBindingPin>,
) -> Result<(), SwarmCompositionError> {
    check_intent_lineage(intent, sealed)?;
    match bindings.iter().find(|pin| pin.class == intent.route_class) {
        Some(pinned)
            if pinned.generation != intent.generation
                || pinned.adapter_digest != intent.adapter_entry_digest
                || pinned.generation_fingerprint != intent.generation_fingerprint =>
        {
            Err(SwarmCompositionError::InternalContract {
                detail: format!(
                    "persisted intents disagree on route {:?} generation, adapter digest, or generation fingerprint under the sealed attachment",
                    intent.route_class
                ),
            })
        }
        Some(_) => Ok(()),
        None => {
            bindings.push(RouteBindingPin {
                class: intent.route_class.clone(),
                generation: intent.generation,
                adapter_digest: intent.adapter_entry_digest,
                generation_fingerprint: intent.generation_fingerprint,
            });
            Ok(())
        }
    }
}

/// Best-effort recovery of the canonical winner job handle from a conflict
/// rendering.
///
/// `eliotd` cannot name the coordination binding type (no direct dependency),
/// so the structured winner is unavailable here; the `Debug` rendering of the
/// conflict still carries `job_handle: "<winner>"` from the canonical
/// binding. This scraper returns that handle when the exact shape is present
/// and `None` otherwise — never a guess. The composition test pins the shape
/// against the real service, so upstream rendering drift fails loudly.
/// Replace with structural matching once `eliot-coordination` is a direct
/// dependency (see the module docs).
fn scrape_winner_job(rendering: &str) -> Option<String> {
    const MARKER: &str = "job_handle: \"";
    let start = rendering.find(MARKER)? + MARKER.len();
    let tail = rendering.get(start..)?;
    let mut handle = String::new();
    let mut chars = tail.chars();
    while let Some(char) = chars.next() {
        match char {
            '\\' => {
                let escaped = chars.next()?;
                handle.push(escaped);
            }
            '"' => {
                return if handle.trim().is_empty() {
                    None
                } else {
                    Some(handle)
                };
            }
            _ => handle.push(char),
        }
    }
    None
}

fn classify_inner_decision(inner: &str, debug: &str) -> SwarmCompositionError {
    if inner == "swarm plan is already attached to a different durable job" {
        return SwarmCompositionError::AttachConflict {
            winner_job: scrape_winner_job(debug),
            detail: debug.to_owned(),
        };
    }
    if let Some(field) = inner.strip_prefix("invalid swarm plan attachment field: ") {
        let _ = field;
        return SwarmCompositionError::InvalidInput {
            field: "attachment_identity",
        };
    }
    SwarmCompositionError::AttachmentRefused {
        detail: debug.to_owned(),
    }
}

/// Classifies an attach failure without naming the coordination error type.
///
/// `eliotd` has no direct `eliot-coordination` dependency, so structural
/// matching on `DurableAttachError` is unavailable here; classification runs
/// on the stable `Display` shapes (decision/store/contention prefixes) with
/// the full `Debug` rendering preserved in the detail. The composition test
/// exercises every arm against the real service, so upstream message drift
/// fails loudly instead of misclassifying.
fn classify_attach_error(
    display: &str,
    source_display: Option<&str>,
    debug: &str,
) -> SwarmCompositionError {
    const DECISION_PREFIX: &str = "swarm plan attachment decision failed: ";
    if display == "swarm plan attachment durable store failed" {
        return SwarmCompositionError::StoreFailure {
            detail: debug.to_owned(),
        };
    }
    if display.starts_with("swarm plan attachment commit contended after ") {
        return SwarmCompositionError::ContentionExhausted {
            detail: debug.to_owned(),
        };
    }
    if let Some(inner) = display.strip_prefix(DECISION_PREFIX) {
        return classify_inner_decision(inner, debug);
    }
    if let Some(source) = source_display {
        if let Some(inner) = source.strip_prefix(DECISION_PREFIX) {
            return classify_inner_decision(inner, debug);
        }
        return classify_inner_decision(source, debug);
    }
    SwarmCompositionError::AttachmentRefused {
        detail: debug.to_owned(),
    }
}

fn source_display_chain(error: &dyn std::error::Error) -> Option<String> {
    error.source().map(std::string::ToString::to_string)
}

/// Computes the bounded drain decision for one attached plan denominator.
///
/// Pure decision mirroring `eliot-swarm` `plan_cancellation_drain`: no
/// dispatch is minted, no process is launched, no executor is called. In
/// order: stop new admission by construction (only cancels for exact active
/// [`ChildState::Running`] children); cancel at most `max_cancels` (capped at
/// [`MAX_DRAIN_CANCELS_PER_PASS`]) running children per pass with the rest in
/// `pending`; [`ChildState::UnknownBlocked`] and [`ChildState::Stale`]
/// children land in `unknown` and block the terminal aggregate; terminal
/// children pass through with their exact [`ChildExit`]; `terminal_ready`
/// holds only when `cancel`, `pending`, and `unknown` are all empty.
///
/// A nonempty `cancel` set is independently authorized cleanup: the caller
/// services it even when `unknown` is nonempty — unknown children block only
/// `terminal_ready`, never cancellation of known live siblings. `cancel`
/// names requested, not observed-terminated, cancellations.
///
/// Frontier note: this pass names the first `bound` running children in the
/// presented denominator order. [`SwarmComposition::drain_bounded`] rotates
/// the presented order across passes; a caller that re-presents the same
/// order on every call starves later eligible children behind a slow first
/// group.
///
/// # Errors
///
/// Returns [`SwarmCompositionError::EmptyDenominator`] for an empty
/// denominator and [`SwarmCompositionError::DuplicateSlot`] for a repeated
/// child slot.
pub fn plan_drain(
    children: &[(String, ChildState)],
    max_cancels: usize,
) -> Result<PlanDrainView, SwarmCompositionError> {
    if children.is_empty() {
        return Err(SwarmCompositionError::EmptyDenominator);
    }
    let mut seen = BTreeSet::new();
    for (slot, _) in children {
        if !seen.insert(slot.clone()) {
            return Err(SwarmCompositionError::DuplicateSlot { slot: slot.clone() });
        }
    }
    let bound = max_cancels.min(MAX_DRAIN_CANCELS_PER_PASS);
    let mut view = PlanDrainView {
        cancel: Vec::new(),
        pending: Vec::new(),
        unknown: Vec::new(),
        terminal: Vec::new(),
        terminal_ready: false,
    };
    for (slot, disposition) in children {
        match disposition {
            ChildState::Running => {
                if view.cancel.len() < bound {
                    view.cancel.push(slot.clone());
                } else {
                    view.pending.push(slot.clone());
                }
            }
            ChildState::UnknownBlocked | ChildState::Stale => {
                view.unknown.push(slot.clone());
            }
            ChildState::Terminal(kind) => {
                view.terminal.push((slot.clone(), *kind));
            }
        }
    }
    view.terminal_ready =
        view.cancel.is_empty() && view.pending.is_empty() && view.unknown.is_empty();
    Ok(view)
}

/// Call-scoped drain budget for one [`SwarmComposition::drain_bounded`] call.
///
/// Accumulated settlement (`terminal`), outstanding cancellation requests
/// (`cancel_requested`), recorded child-local failures, the frontier cursor,
/// and the executed pass count. This is not a drain database: it dies with
/// the call, persists nothing, and never replaces the ledger or runner
/// owners — the ledger stays the source of truth for launched children and
/// re-observation through the runner stays the poll of outstanding requests.
struct DrainBudget {
    /// Exact terminal kinds observed so far, keyed by slot (sorted output).
    terminal: BTreeMap<String, ChildExit>,
    /// Slots with an outstanding requested-not-terminated cancel.
    cancel_requested: BTreeSet<String>,
    /// Typed child-local failures recorded against their exact slots.
    local_failures: Vec<ChildLocalFailure>,
    /// Frontier cursor: denominator offset the next pass presents first.
    cursor: usize,
    /// Passes executed so far.
    passes: u32,
}

impl DrainBudget {
    /// Builds the progress + uncertainty payload shared by the terminal
    /// outcome and every incomplete drain exit (issue #2652 step 5): exact
    /// terminal kinds, requested-not-terminated cancels, pending and retained
    /// unknown children from the exiting pass, and typed child-local
    /// failures. Cancellation never erases prior effects and never proves
    /// termination.
    fn snapshot(&self, pending: &[String], unknown: &[String]) -> DrainOutcome {
        DrainOutcome {
            terminal: self
                .terminal
                .iter()
                .map(|(slot, kind)| (slot.clone(), *kind))
                .collect(),
            cancel_requested: self.cancel_requested.iter().cloned().collect(),
            pending: pending.to_vec(),
            unknown: unknown.to_vec(),
            local_failures: self.local_failures.clone(),
            passes: self.passes,
        }
    }
}

/// The single daemon swarm composition.
///
/// Owns no store image and no executor: it borrows the one Governor
/// attachment composition (hence the one canonical owner), one
/// caller-owned intent ledger, and one caller-owned child runner. Share by
/// mutable reference through the daemon phases attach -> launch ->
/// (restart -> rehydrate) -> drain. The in-memory `launched` list is a
/// non-authoritative cache: the ledger is the source of truth and
/// [`SwarmComposition::rehydrate_after_restart`] rebuilds the cache from it.
pub struct SwarmComposition<'a, L: LaunchIntentLedger, R: ChildRunner> {
    attachment: &'a SwarmAttachmentComposition,
    ledger: &'a L,
    runner: &'a R,
    plan: Option<AttachedPlan>,
    launched: Vec<ChildLaunchIntent>,
    reconciled: bool,
    /// Route-class pins admitted by the first launch per class under the
    /// attached plan (stale-route gate, item A8).
    ///
    /// A replaced backing route under an admitted class carries a different
    /// generation, adapter digest, or generation fingerprint; launching it
    /// under the attached plan would silently substitute a new result for
    /// the same logical scope, so drift from the pin is
    /// [`SwarmCompositionError::RouteBlocked`]. Pins rebuild from the
    /// ledger on [`SwarmComposition::rehydrate_after_restart`], so a restart
    /// cannot revive stale route authority (A0.3 hard boundary: restoration
    /// of revoked influence after recovery fails closed).
    route_bindings: Vec<RouteBindingPin>,
}

impl<'a, L: LaunchIntentLedger, R: ChildRunner> SwarmComposition<'a, L, R> {
    /// Borrows the single Governor attachment composition plus the
    /// caller-owned ledger and runner.
    ///
    /// The composition starts unreconciled with no plan: attach (fresh boot)
    /// or rehydrate (restart) before launching.
    pub const fn new(
        attachment: &'a SwarmAttachmentComposition,
        ledger: &'a L,
        runner: &'a R,
    ) -> Self {
        Self {
            attachment,
            ledger,
            runner,
            plan: None,
            launched: Vec::new(),
            reconciled: false,
            route_bindings: Vec::new(),
        }
    }

    /// Returns the attached plan, if any.
    #[must_use]
    pub const fn plan(&self) -> Option<&AttachedPlan> {
        // `Option::as_ref` is not const-compatible on all pinned toolchains;
        // the borrow below serves the same read-only projection.
        match &self.plan {
            Some(plan) => Some(plan),
            None => None,
        }
    }

    /// Returns the in-memory launched intents (non-authoritative cache; the
    /// ledger is the source of truth).
    #[must_use]
    pub fn launched(&self) -> &[ChildLaunchIntent] {
        &self.launched
    }

    /// Returns whether launches are currently allowed: a plan is attached and
    /// (after a restart) reconciliation has run.
    #[must_use]
    pub const fn launch_allowed(&self) -> bool {
        self.plan.is_some() && self.reconciled
    }

    /// Vends a pinned consumer through the Governor port and attaches the
    /// pinned plan to one durable job handle through the same owner.
    ///
    /// Plan identity travels only inside the vended handle, so a caller
    /// cannot swap the admission digest, plan revision, or fence digest
    /// between acquisition and attach: the first job commits, an identical
    /// replay returns the identical binding, and a second job observes
    /// [`SwarmCompositionError::AttachConflict`] naming the canonical
    /// winner. A successful attach marks the composition reconciled (fresh
    /// boot has nothing to reconcile).
    ///
    /// # Errors
    ///
    /// Returns [`SwarmCompositionError::InvalidInput`] for blank identities
    /// (before any owner is contacted),
    /// [`SwarmCompositionError::AttachConflict`] for a second job,
    /// [`SwarmCompositionError::StoreFailure`] /
    /// [`SwarmCompositionError::ContentionExhausted`] for durable failures,
    /// and [`SwarmCompositionError::InternalContract`] when a replayed
    /// binding disagrees with the already-attached plan.
    pub fn attach_admitted_plan(
        &mut self,
        admission_digest: &str,
        plan_revision: &str,
        fence_digest: &str,
        job_handle: &str,
    ) -> Result<AttachedPlan, SwarmCompositionError> {
        require_text(admission_digest, "admission_digest")?;
        require_text(plan_revision, "plan_revision")?;
        require_text(fence_digest, "fence_digest")?;
        require_text(job_handle, "job_handle")?;
        let consumer = self
            .attachment
            .vend_consumer(admission_digest, plan_revision, fence_digest)
            .map_err(|error| {
                classify_inner_decision(
                    &strip_vend_prefix(&error.to_string()),
                    &format!("{error:?}"),
                )
            })?;
        let binding = self
            .attachment
            .attach(&consumer, job_handle)
            .map_err(|error| {
                classify_attach_error(
                    &error.to_string(),
                    source_display_chain(&error).as_deref(),
                    &format!("{error:?}"),
                )
            })?;
        let attached = AttachedPlan {
            admission_digest: binding.admission_digest().to_owned(),
            plan_revision: binding.plan_revision().to_owned(),
            job_handle: binding.job_handle().to_owned(),
            fence_digest: binding.fence_digest().to_owned(),
            binding_digest: binding.binding_digest().to_owned(),
        };
        if let Some(prior) = &self.plan {
            if *prior != attached {
                return Err(SwarmCompositionError::InternalContract {
                    detail: format!(
                        "replayed binding disagrees with attached plan for job {}",
                        prior.job_handle
                    ),
                });
            }
            return Ok(prior.clone());
        }
        self.plan = Some(attached.clone());
        self.reconciled = true;
        Ok(attached)
    }

    /// Dispatches one admitted child over the `AdapterRegistry` surface.
    ///
    /// Fail-closed order, enforced in code: the registry verdict must be
    /// [`RegistryRouteStatus::Admitted`] with a non-blank route class
    /// (revoked, stale, or blank is [`SwarmCompositionError::RouteBlocked`]
    /// with no fallback); a route class launched before under this attached
    /// plan keeps its admitted generation, adapter-entry digest, and
    /// generation fingerprint — drift in any of the three is
    /// [`SwarmCompositionError::RouteBlocked`] with no silent substitution
    /// (stale-route gate, item A8: provider/route replacement cannot revive
    /// stale child authority under the same plan); the launch intent,
    /// carrying the deterministic attempt and cancellation identities plus
    /// the Governor-validated fence digest and the pinned registry material,
    /// passes the shared lineage check (the same check rehydration applies
    /// to persisted intents) and is then appended to the durable ledger
    /// BEFORE the runner is called; the runner call happens exactly once per
    /// appended intent. A runner failure after a persisted
    /// append propagates as [`SwarmCompositionError::OwnerFailure`] while
    /// the intent stays persisted with unknown outcome — it reconciles
    /// through [`SwarmComposition::rehydrate_after_restart`], never by
    /// timeout. Launching requires an attached plan and, after a restart,
    /// reconciliation ([`SwarmCompositionError::ReconcileRequired`]).
    /// Reusing a slot that already carries a persisted intent is
    /// [`SwarmCompositionError::DuplicateSlot`].
    ///
    /// # Errors
    ///
    /// Returns [`SwarmCompositionError::PlanNotAttached`],
    /// [`SwarmCompositionError::ReconcileRequired`],
    /// [`SwarmCompositionError::InvalidInput`],
    /// [`SwarmCompositionError::RouteBlocked`],
    /// [`SwarmCompositionError::DuplicateSlot`], or
    /// [`SwarmCompositionError::OwnerFailure`].
    pub fn launch_child(
        &mut self,
        slot: &str,
        route: RegistryRouteStatus,
        route_class: &str,
        generation: u64,
        adapter_entry_digest: [u8; 32],
        generation_fingerprint: [u8; 32],
    ) -> Result<ChildLaunchIntent, SwarmCompositionError> {
        let plan = self
            .plan
            .clone()
            .ok_or(SwarmCompositionError::PlanNotAttached)?;
        if !self.reconciled {
            return Err(SwarmCompositionError::ReconcileRequired);
        }
        require_text(slot, "child_slot")?;
        match route {
            RegistryRouteStatus::Admitted => {}
            RegistryRouteStatus::Revoked | RegistryRouteStatus::Stale => {
                return Err(SwarmCompositionError::RouteBlocked {
                    detail: format!("route {route_class:?} is not admitted: {route:?}"),
                });
            }
        }
        require_text(route_class, "route_class")?;
        if let Some(pinned) = find_pin(&self.route_bindings, route_class)
            && (pinned.generation != generation
                || pinned.adapter_digest != adapter_entry_digest
                || pinned.generation_fingerprint != generation_fingerprint)
        {
            return Err(SwarmCompositionError::RouteBlocked {
                detail: format!(
                    "route {route_class:?} generation, adapter digest, or generation fingerprint drift under the attached plan: admitted generation {pinned_generation}, requested {generation}",
                    pinned_generation = pinned.generation,
                ),
            });
        }
        if self.launched.iter().any(|intent| intent.slot == slot) {
            return Err(SwarmCompositionError::DuplicateSlot {
                slot: slot.to_owned(),
            });
        }
        let operation_id = format!("{}:{}:{slot}", plan.job_handle, plan.plan_revision);
        require_text(&operation_id, "operation_id")?;
        let intent = ChildLaunchIntent {
            attempt_id: format!("{operation_id}-attempt"),
            cancellation_id: expected_cancellation_id(&operation_id),
            operation_id,
            slot: slot.to_owned(),
            job_handle: plan.job_handle.clone(),
            plan_revision: plan.plan_revision.clone(),
            fence_digest: plan.fence_digest.clone(),
            route_class: route_class.to_owned(),
            generation,
            adapter_entry_digest,
            generation_fingerprint,
        };
        // Lineage self-check before anything persists: the fresh intent runs
        // the same [`check_intent_lineage`] rehydration applies to persisted
        // intents, so a drifted derivation fails here — before the ledger
        // append — and can neither persist nor reconcile later.
        check_intent_lineage(&intent, &plan)?;
        // Persist BEFORE the runner call: a crash between the two leaves a
        // persisted intent with unknown outcome, which rehydration reconciles.
        // No runner call happens before this append returns.
        let _sequence = self.ledger.append_intent(&intent)?;
        // Pin the admitted route binding once the intent is durable: later
        // launches under this plan must present the same generation, adapter
        // digest, and generation fingerprint for the class, and rehydration
        // rebuilds the pins from the ledger.
        if find_pin(&self.route_bindings, route_class).is_none() {
            self.route_bindings.push(RouteBindingPin {
                class: route_class.to_owned(),
                generation,
                adapter_digest: adapter_entry_digest,
                generation_fingerprint,
            });
        }
        self.launched.push(intent.clone());
        self.runner.launch(&intent).map_err(|error| match error {
            SwarmCompositionError::OwnerFailure { detail } => {
                SwarmCompositionError::OwnerFailure { detail }
            }
            other => SwarmCompositionError::OwnerFailure {
                detail: other.to_string(),
            },
        })?;
        Ok(intent)
    }

    /// Reloads the sealed attachment and reconciles every persisted intent
    /// after a daemon restart.
    ///
    /// The caller drops every in-memory attachment on restart and presents
    /// its sealed [`AttachedPlan`]: the consumer is re-vended from the sealed
    /// identities and re-attached with the sealed job handle, so the
    /// canonical decision (not process memory) is the source of truth. The
    /// rebuilt binding must equal the sealed one exactly (job, revision,
    /// fence, digest); a plan revision or fence that drifted is
    /// [`SwarmCompositionError::StaleLineage`], a canon bound to a different
    /// job is [`SwarmCompositionError::AttachConflict`], and any other
    /// inequality is [`SwarmCompositionError::InternalContract`].
    ///
    /// Every ledger intent is then re-observed through the runner before any
    /// relaunch is allowed: nonterminal children reconcile here, unknown
    /// stays unknown, and only after all intents are accounted for does the
    /// composition allow launches again. This method performs no launch.
    ///
    /// # Errors
    ///
    /// Returns the attach-class errors on canonical disagreement plus
    /// [`SwarmCompositionError::StaleLineage`],
    /// [`SwarmCompositionError::InternalContract`], or
    /// [`SwarmCompositionError::OwnerFailure`] from the runner.
    pub fn rehydrate_after_restart(
        &mut self,
        sealed: &AttachedPlan,
    ) -> Result<RehydrationReport, SwarmCompositionError> {
        if sealed.plan_revision.trim().is_empty() || sealed.job_handle.trim().is_empty() {
            return Err(SwarmCompositionError::InvalidInput {
                field: "sealed_attachment",
            });
        }
        self.reconciled = false;
        // A sealed attachment that drifted from the already-attached plan is
        // stale lineage: refuse before the owner is contacted, so no stray
        // binding commits and no unknown outcome changes shape.
        if let Some(prior) = &self.plan
            && (prior.admission_digest != sealed.admission_digest
                || prior.plan_revision != sealed.plan_revision
                || prior.job_handle != sealed.job_handle
                || prior.fence_digest != sealed.fence_digest)
        {
            return Err(SwarmCompositionError::StaleLineage {
                detail: "sealed attachment drifted from the attached plan".to_owned(),
            });
        }
        let consumer = self
            .attachment
            .vend_consumer(
                &sealed.admission_digest,
                &sealed.plan_revision,
                &sealed.fence_digest,
            )
            .map_err(|error| {
                classify_inner_decision(
                    &strip_vend_prefix(&error.to_string()),
                    &format!("{error:?}"),
                )
            })?;
        let binding = self
            .attachment
            .attach(&consumer, &sealed.job_handle)
            .map_err(|error| {
                classify_attach_error(
                    &error.to_string(),
                    source_display_chain(&error).as_deref(),
                    &format!("{error:?}"),
                )
            })?;
        let rebuilt = AttachedPlan {
            admission_digest: binding.admission_digest().to_owned(),
            plan_revision: binding.plan_revision().to_owned(),
            job_handle: binding.job_handle().to_owned(),
            fence_digest: binding.fence_digest().to_owned(),
            binding_digest: binding.binding_digest().to_owned(),
        };
        if rebuilt.plan_revision != sealed.plan_revision
            || rebuilt.fence_digest != sealed.fence_digest
        {
            return Err(SwarmCompositionError::StaleLineage {
                detail: "sealed plan revision or fence digest drifted from canonical".to_owned(),
            });
        }
        if rebuilt != *sealed {
            return Err(SwarmCompositionError::InternalContract {
                detail: "rebuilt binding differs from sealed attachment".to_owned(),
            });
        }
        // Reconcile-before-relaunch: reload every persisted intent (the ledger
        // is the source of truth, so no launched child is lost) and observe
        // each through the runner. Unknown stays unknown. Route-binding pins
        // rebuild from the same persisted intents, so a restart cannot revive
        // stale route authority; a persisted intent whose operation, attempt,
        // cancellation, or fence lineage does not match the sealed
        // attachment is refused rather than reconciled under drifted
        // lineage.
        let persisted = self.ledger.intents();
        let mut children = Vec::with_capacity(persisted.len());
        let mut bindings: Vec<RouteBindingPin> = Vec::new();
        for intent in &persisted {
            reconcile_persisted_intent(intent, sealed, &mut bindings)?;
            let state = self.runner.observe(&intent.slot)?;
            children.push((intent.clone(), state));
        }
        self.plan = Some(rebuilt.clone());
        self.launched = persisted;
        self.route_bindings = bindings;
        self.reconciled = true;
        Ok(RehydrationReport {
            plan: rebuilt,
            children,
        })
    }

    /// Re-observes the whole denominator through the owner for one drain pass.
    ///
    /// This is the poll/reconcile of outstanding cancel requests: nothing is
    /// reminted here. Child-local observation failures record against their
    /// exact slot and retain that slot as blocked for the pass; a
    /// shared-authority failure halts with progress kept.
    fn observe_drain_denominator(
        &self,
        budget: &mut DrainBudget,
    ) -> Result<Vec<(String, ChildState)>, SwarmCompositionError> {
        let mut observed = Vec::with_capacity(self.launched.len());
        for intent in &self.launched {
            match self.runner.observe(&intent.slot) {
                Ok(state) => observed.push((intent.slot.clone(), state)),
                Err(error) => match error.drain_failure_scope() {
                    FailureScope::ChildLocal => {
                        budget.local_failures.push(ChildLocalFailure {
                            slot: intent.slot.clone(),
                            op: DrainFailureOp::Observe,
                            detail: error.to_string(),
                        });
                        // Unobserved this pass: retain as blocked (never
                        // terminal, never cleared) so the aggregate stays
                        // incomplete with the reason recorded above.
                        observed.push((intent.slot.clone(), ChildState::UnknownBlocked));
                    }
                    FailureScope::Global => {
                        return Err(SwarmCompositionError::DrainHalted {
                            cause: Box::new(error),
                            progress: Box::new(budget.snapshot(&[], &[])),
                        });
                    }
                },
            }
        }
        Ok(observed)
    }

    /// Serves one pass's authorized cancel set through the owner, skipping
    /// slots with an outstanding request (polled by re-observation, never
    /// reminted). Returns the count of newly requested cancels.
    ///
    /// Child-local cancel failures record against their exact slot without
    /// stopping siblings; a shared-authority failure halts with progress
    /// kept. `pending`/`unknown` describe the exiting pass for the halt
    /// payload only.
    fn serve_drain_cancels(
        &self,
        cancel: &[String],
        pending: &[String],
        unknown: &[String],
        budget: &mut DrainBudget,
    ) -> Result<usize, SwarmCompositionError> {
        let mut served_new = 0_usize;
        for slot in cancel {
            if budget.cancel_requested.contains(slot) {
                // Already requested on an earlier pass: the re-observation
                // already polled that same cancellation identity through the
                // owner, so poll again next pass rather than reminting.
                continue;
            }
            match self.runner.cancel(slot) {
                Ok(()) => {
                    // Submission only: requested-not-terminated.
                    budget.cancel_requested.insert(slot.clone());
                    served_new += 1;
                }
                Err(error) => match error.drain_failure_scope() {
                    FailureScope::ChildLocal => {
                        budget.local_failures.push(ChildLocalFailure {
                            slot: slot.clone(),
                            op: DrainFailureOp::Cancel,
                            detail: error.to_string(),
                        });
                    }
                    FailureScope::Global => {
                        return Err(SwarmCompositionError::DrainHalted {
                            cause: Box::new(error),
                            progress: Box::new(budget.snapshot(pending, unknown)),
                        });
                    }
                },
            }
        }
        Ok(served_new)
    }

    /// Drains one attached plan to its terminal aggregate through bounded
    /// passes (issue #2652).
    ///
    /// Each pass re-observes the dispositions of every launched intent through
    /// the owner-side [`ChildRunner::observe`] path — this re-observation is
    /// the poll/reconcile of already-requested cancels: a slot whose cancel
    /// was requested on an earlier pass is never reminted while its request
    /// is outstanding — runs the pure [`plan_drain`] decision over the
    /// frontier-rotated denominator, then executes the named cancels through
    /// the owner-side [`ChildRunner::cancel`] path:
    /// - the authorized `cancel` set is served even when `unknown` is
    ///   nonempty; unknown or stale children block only the terminal
    ///   aggregate ([`SwarmCompositionError::TerminalBlocked`]: retained,
    ///   never cleared, never terminal), never cancellation of known live
    ///   siblings;
    /// - a slot-scoped observe/cancel failure
    ///   ([`FailureScope::ChildLocal`]) records against its exact slot and
    ///   spares independently eligible siblings, while a shared-authority
    ///   failure ([`FailureScope::Global`]) stops new effects immediately and
    ///   everything completed stays reported
    ///   ([`SwarmCompositionError::DrainHalted`]);
    /// - a `cancel` `Ok(())` records request submission only
    ///   (`cancel_requested`, requested-not-terminated); only an observed
    ///   [`ChildState::Terminal`] with its exact [`ChildExit`] proves
    ///   settlement, so a lost acknowledgement stays possibly applied until
    ///   re-observation settles that same slot identity;
    /// - the presented denominator rotates across passes past newly served
    ///   slots and already-requested slots are polled rather than reminted,
    ///   so a slow first group cannot starve later eligible children; a zero
    ///   allowance, or a pass with no new request and no newly observed
    ///   terminal, returns an explicit bounded partial
    ///   ([`SwarmCompositionError::DrainBudgetPartial`]) instead of spinning.
    ///
    /// The loop is additionally bounded by [`MAX_DRAIN_PASSES`]
    /// ([`SwarmCompositionError::DrainBoundExhausted`]). A terminal aggregate
    /// publishes only after every child is accounted for — and even then it
    /// is a candidate for the parent scope, never a task finish.
    ///
    /// # Errors
    ///
    /// Returns [`SwarmCompositionError::PlanNotAttached`] or
    /// [`SwarmCompositionError::EmptyDenominator`] before any owner contact.
    /// Mid-loop, [`SwarmCompositionError::TerminalBlocked`],
    /// [`SwarmCompositionError::DrainBudgetPartial`], and
    /// [`SwarmCompositionError::DrainBoundExhausted`] all carry the completed
    /// progress, and any other owner failure stops effects as
    /// [`SwarmCompositionError::DrainHalted`] with progress kept.
    pub fn drain_bounded(
        &self,
        max_cancels_per_pass: usize,
    ) -> Result<DrainOutcome, SwarmCompositionError> {
        if self.plan.is_none() {
            return Err(SwarmCompositionError::PlanNotAttached);
        }
        if self.launched.is_empty() {
            return Err(SwarmCompositionError::EmptyDenominator);
        }
        let bound = max_cancels_per_pass.min(MAX_DRAIN_CANCELS_PER_PASS);
        let denominator = self.launched.len();
        let mut budget = DrainBudget {
            terminal: BTreeMap::new(),
            cancel_requested: BTreeSet::new(),
            local_failures: Vec::new(),
            cursor: 0,
            passes: 0,
        };
        loop {
            let mut observed = self.observe_drain_denominator(&mut budget)?;
            budget.passes += 1;
            let terminals_before = budget.terminal.len();
            // Frontier rotation: present the denominator from the cursor so
            // later eligible children are visited even when an earlier group
            // stays live across passes.
            observed.rotate_left(budget.cursor % denominator);
            let view = plan_drain(&observed, bound).map_err(|error| {
                SwarmCompositionError::DrainHalted {
                    cause: Box::new(error),
                    progress: Box::new(budget.snapshot(&[], &[])),
                }
            })?;
            for (slot, kind) in &view.terminal {
                budget.terminal.insert(slot.clone(), *kind);
            }
            if view.terminal_ready {
                return Ok(budget.snapshot(&[], &[]));
            }
            // A zero allowance parks every live child in `pending`: that is
            // the explicit bounded partial outcome, not a signal to spin.
            if bound == 0 {
                return Err(SwarmCompositionError::DrainBudgetPartial {
                    reason: DrainPartialReason::ZeroCancelAllowance,
                    progress: Box::new(budget.snapshot(&view.pending, &view.unknown)),
                });
            }
            let served_new =
                self.serve_drain_cancels(&view.cancel, &view.pending, &view.unknown, &mut budget)?;
            budget.cursor = (budget.cursor + served_new) % denominator;
            // Unknown blocks only the terminal aggregate: the authorized
            // cancels above were already served, so the incomplete aggregate
            // returns with every unknown child retained and progress kept.
            if !view.unknown.is_empty() {
                return Err(SwarmCompositionError::TerminalBlocked {
                    unknown: view.unknown.clone(),
                    progress: Box::new(budget.snapshot(&view.pending, &view.unknown)),
                });
            }
            // A full pass with no new request and no newly observed terminal
            // settles nothing further within this call: bounded partial, not
            // a spin.
            if served_new == 0 && budget.terminal.len() == terminals_before {
                return Err(SwarmCompositionError::DrainBudgetPartial {
                    reason: DrainPartialReason::NoProgress,
                    progress: Box::new(budget.snapshot(&view.pending, &view.unknown)),
                });
            }
            if budget.passes >= MAX_DRAIN_PASSES {
                return Err(SwarmCompositionError::DrainBoundExhausted {
                    passes: budget.passes,
                    progress: Box::new(budget.snapshot(&view.pending, &view.unknown)),
                });
            }
        }
    }
}

fn strip_vend_prefix(display: &str) -> String {
    const DECISION_PREFIX: &str = "swarm plan attachment decision failed: ";
    display
        .strip_prefix(DECISION_PREFIX)
        .map_or_else(|| display.to_owned(), str::to_owned)
}
