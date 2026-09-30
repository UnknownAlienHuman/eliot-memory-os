//! I12.14 runtime binding and bound enforcement for the Kernel hot spine.
//!
//! Three jobs, all at the real owner, none a declaration:
//!
//! 1. **Load and bind at runtime without build tooling** (I12.14 step 4).
//!    [`KernelHotSpine::bind`] reads this crate's own `hot-path.toml` bytes once
//!    during composition assembly, admits them through the shared loader, and
//!    binds the admitted set against the queue settings *this running build*
//!    registered. No Cargo, no filesystem discovery and no dependency analysis
//!    happens here or on any later request: the only inputs are the
//!    compiled-in declaration bytes and the already-registered transport and
//!    queue limits. A changed queue, profile or operation revision therefore
//!    cannot keep an old binding, because the binding is recomputed from those
//!    exact values and refuses a mismatch in either direction.
//!
//! 2. **Enforce the declared bounds at the real owner** (I12.14 step 5).
//!    [`KernelHotSpine`] holds the one [`HotPathQueueCapacity`] for the Kernel's
//!    bounded local-read queue. The queue admits through
//!    [`KernelHotSpine::acquire_local_read_capacity`] before any pair is staged,
//!    and the charge is retained until the owner retires the pair — not released
//!    on receipt, and not released on claim, so a claimed or in-flight item
//!    still occupies its slot. Release happens exactly at the owner's
//!    safe-release points (completion retire, deadline-expiry retire, and both
//!    fencing paths that take a whole connection or the whole index out of the
//!    index), so a saturated queue returns the existing typed
//!    `TransportError::Backpressure` rather than growing a waiter list, a
//!    detached retry or a silent eviction. Every release returns the byte count
//!    recorded at that pair's own admission, never a recomputed one, so the
//!    ledger cannot drift away from the index it bounds.
//!
//!    That ledger is built from the identity `bind_hot_path_manifest_set`
//!    returned, not from a second spelling of the queue identity written here.
//!    One queue identity per enforced ledger is the point: a queue the bind
//!    never certified cannot be the queue this process bounds.
//!
//! The request-byte bound is checked here, at admission, from the exact bytes
//! the owner received — before the expensive decode of the retained tool payload
//! happens — and a refusal never partially acquires, so the owner is never
//! charged for work it did not admit.
//!
//! 3. **Carry one authenticated owner's non-mutating decision to the daemon**
//!    (I12.24:65, "decision owner selects reject / investigate / work item /
//!    experiment"). A [`QueuedOwnerDecision`] is what an authenticated
//!    `UserAutomation` operator request leaves behind when its disposition is
//!    `reject` or `investigate`: the brief the selection was made over, the
//!    closed disposition, the owner's note, and the principal the front-door
//!    Session proved. The entry waits in this operation's own bounded queue and
//!    is returned only by `KernelComposition::claim_owner_decision`, so no
//!    other operation can read it or be attributed it.
//!
//!    Two limits of that claim are deliberate. It is a record and no effect:
//!    only the two dispositions `OwnerDecisionKind::is_non_mutating` admits are
//!    queued, and the entry names no automation, schedule, task, scope or
//!    provider, so nothing it carries can reach an execution owner. And it is
//!    Kernel-owned queue memory of exactly the same class as the bounded
//!    local-read pairs above, not a durable store: the durable `Candidate`
//!    document belongs to the improvement owner's own commit seam, and
//!    `bins/AGENTS.md` forbids this composition root from acquiring one.

use std::collections::VecDeque;
use std::sync::Mutex;

use eliot_ipc::PeerIdentity;
use eliot_kernel_core::UserAutomationOperation;
use eliot_protocol::RequestIdentity;
use eliot_runtime_contracts::{
    AdmittedHotPathManifest, HotPathDegradation, HotPathQueueCapacity, RegisteredOperation,
    RegisteredQueueSettings, RunningBuildRegistration, admit_hot_path_manifest,
    bind_hot_path_manifest_set, hot_path_manifest_path,
};

use super::kernel_diagnostics::{EntrypointStage, KERNEL_DIAGNOSTICS_TARGET, bound_field};
use super::{IpcImplementation, Session, TransportError};

/// The compiled-in bytes of this crate's own service-local I12.14 declaration.
///
/// `include_str!` resolves at compile time, so a running Kernel never locates
/// or discovers the file: the declaration travels with the binary and the
/// digest the admission records is the digest of exactly these bytes. A
/// deployment that replaced the file on disk therefore cannot change what this
/// process believes it declared, and a caller cannot upload a permissive
/// manifest to a running build.
const KERNEL_HOT_PATH_MANIFEST: &str = include_str!("../hot-path.toml");

/// Exact service identity the running Kernel registers itself as.
const KERNEL_HOT_SPINE_SERVICE: &str = "eliot-kernel";

/// The bounded queue identity the Kernel's local-read pairs are admitted against.
const LOCAL_READ_QUEUE_ID: &str = "local_read_claim";

/// The declared operation whose registered queue this process bounds.
///
/// This is the operation identity, not a second spelling of the queue
/// identity: the queue identity is read back off the bind result, so the two
/// cannot drift into checking one thing and enforcing another.
const LOCAL_READ_OPERATION: &str = "local_read_claim";

/// The declared operation an authenticated owner's non-mutating improvement
/// decision is queued under, and the bounded queue identity it waits in.
///
/// One operation, one queue, one ledger: the two spellings are the same string
/// because they are the same object, and the identity this process enforces is
/// read back off the bind result rather than taken from the declaration.
const OWNER_DECISION_OPERATION: &str = "improvement_decision_claim";
const OWNER_DECISION_QUEUE_ID: &str = "improvement_decision_claim";

/// The only dispositions this queue admits.
///
/// I12.24:65 names four. `reject` and `investigate` are the two
/// `OwnerDecisionKind::is_non_mutating` admits and they change nothing, so a
/// queued selection is a record and no effect. `work_item` and `experiment`
/// reach effect only through the normal work-item/canary/rollback flow of
/// I12.24:90-91, never through this shape, so admitting them here would make
/// this queue an effect path it is not. They are spelled as literals for the
/// same reason `IMPROVEMENT_BRIEF_DECISIONS` is: this crate must not acquire an
/// `eliot-improvement` edge to name a Meta-owned enum on a Kernel boundary.
const NON_MUTATING_OWNER_DECISIONS: [&str; 2] = ["reject", "investigate"];

/// Observed hot-spine outcomes. Closed, bounded control codes — never prose,
/// never a claim about a bound this process did not actually hit.
const OUTCOME_BOUND: &str = "bound";
const OUTCOME_REFUSED: &str = "refused";
const OUTCOME_ADMITTED: &str = "admitted";
const OUTCOME_RELEASED: &str = "released";

/// Publishes one bounded hot-spine observation.
fn observe_hot_spine(operation: &str, outcome: &'static str, limit: u64, held: u64) {
    tracing::info!(
        target: KERNEL_DIAGNOSTICS_TARGET,
        event = "kernel.hot_spine.bound",
        operation = bound_field(operation).text(),
        outcome = bound_field(outcome).text(),
        limit = limit,
        held = held,
        "hot-spine bound observation"
    );
}

/// The failure a runtime hot-spine bind or capacity acquisition produces.
///
/// Both cases are refusals of the same shape and the same size, so the error
/// carries no large variant: a bind failure names only its own case and a
/// saturated capacity names only its own case.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum HotSpineError {
    /// The approved declaration is not admissible against the running build.
    DeclarationRefused,
    /// The declared byte or item bound is saturated, or the request is larger
    /// than the bound permits.
    BoundSaturated,
}

impl HotSpineError {
    /// The bounded wire code for this refusal.
    const fn as_str(self) -> &'static str {
        match self {
            Self::DeclarationRefused => "declaration_refused",
            Self::BoundSaturated => "bound_saturated",
        }
    }
}

impl From<HotSpineError> for TransportError {
    /// Maps a hot-spine refusal onto the route's existing typed backpressure.
    ///
    /// An unbound declaration and a saturated bound are the same bounded
    /// outcome to a caller: this operation is not admitted right now and the
    /// caller retries through its own existing recovery directive. Neither is
    /// degraded to a success, and neither starts a module, a waiter list or a
    /// detached retry.
    fn from(error: HotSpineError) -> Self {
        match error {
            HotSpineError::DeclarationRefused | HotSpineError::BoundSaturated => {
                TransportError::Backpressure
            }
        }
    }
}

/// One authenticated owner's non-mutating decision over an improvement brief,
/// retained for the daemon that will commit it.
///
/// The entry is typed and closed: it carries the exact admitted request
/// identity that produced it, the principal the front-door Session
/// authenticated, the brief, the closed disposition and the owner's note. It
/// carries nothing else — no automation identity, no schedule, no task, no
/// scope, no provider — because there is nothing here that could start work.
///
/// The retained charge is the byte count this exact entry serialized to when it
/// was admitted. It is recorded once and returned verbatim when the claim
/// removes the entry, never recomputed, so the I12.14 ledger cannot drift away
/// from the queue it bounds.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct QueuedOwnerDecision {
    /// The exact admitted request identity that produced this entry.
    pub identity: RequestIdentity,
    /// The principal the front-door Session authenticated for that request.
    pub principal: String,
    /// Stable brief identity the owner selected a disposition over.
    pub brief_id: String,
    /// The closed disposition spelling the owner selected.
    pub decision: String,
    /// The owner's own note on the disposition.
    pub note: String,
    /// The exact byte count this entry's admission charged.
    ///
    /// This is the queue's own retained charge, not part of the payload, so it
    /// is skipped in the serialization the charge is measured from. Measuring a
    /// value that then changes would make the recorded charge a number the
    /// retained entry no longer has.
    #[serde(skip)]
    pub held_bytes: u64,
}

/// The bounded queue one operation's owner decisions wait in.
///
/// This is the second enforced ledger, over its own queue identity and its own
/// entries. Nothing else in the composition holds a reference to it, so an entry
/// cannot be read by, completed by, or attributed to any other operation.
struct OwnerDecisionQueue {
    /// The I12.14 capacity this queue is admitted against.
    capacity: HotPathQueueCapacity,
    /// The retained entries, oldest first.
    entries: VecDeque<QueuedOwnerDecision>,
}

/// The Kernel's live I12.14 binding plus the capacity it enforces.
///
/// Construction happens once, during composition assembly, and requires the
/// declaration to bind against the real registered settings. A composition that
/// could not bind is never constructed, so no later request can observe an
/// unbound hot spine.
pub(crate) struct KernelHotSpine {
    /// The admitted declaration set with the digest of its exact bytes.
    admitted: AdmittedHotPathManifest,
    /// The bound operation identities, one per admitted supported operation.
    bound_operations: Vec<String>,
    /// The one capacity ledger the bounded local-read queue is admitted against.
    local_read: Mutex<HotPathQueueCapacity>,
    /// The one capacity ledger and entry set the owner-decision queue is
    /// admitted against. Independent of the local-read ledger above, so a
    /// saturated query queue can never make an owner's selection unreadable and
    /// a claimed decision can never occupy a query slot.
    owner_decision: Mutex<OwnerDecisionQueue>,
}

impl KernelHotSpine {
    #[cfg(test)]
    pub(crate) fn held_local_read_capacity(&self) -> Result<(u64, u64), HotSpineError> {
        let capacity = self
            .local_read
            .lock()
            .map_err(|_| HotSpineError::BoundSaturated)?;
        Ok((capacity.held_items(), capacity.held_bytes()))
    }

    /// Binds this crate's own declaration against the running build's settings.
    ///
    /// The registration is built from values this process actually enforces —
    /// the transport limits the front-door session selected and the constant the
    /// local-read queue is bounded by — and never from the declaration itself,
    /// so a declaration that claims a looser or tighter bound than the build
    /// really uses is refused instead of being taken at its word.
    ///
    /// The queue identity the ledger is later built from is read back off the
    /// binder's own result rather than off the constant this file registers
    /// with. Those two spellings can only agree after `bind_hot_path_manifest_set`
    /// has compared every declared `queue_id` against this build's registered
    /// queue, so the identity this process enforces is the identity that bind
    /// certified. A declaration carrying a foreign queue identity under the same
    /// operation and the same numbers — or an extra such row alongside the
    /// genuine one — has nowhere left to attach: the binder refuses it, and a
    /// refused bind refuses composition assembly outright.
    pub(crate) fn bind() -> Result<Self, HotSpineError> {
        let path = hot_path_manifest_path(std::path::Path::new(env!("CARGO_MANIFEST_DIR")))
            .map_err(|_| HotSpineError::DeclarationRefused)?;
        let admitted = admit_hot_path_manifest(&path, KERNEL_HOT_PATH_MANIFEST.as_bytes())
            .map_err(|_| HotSpineError::DeclarationRefused)?;
        let registration = kernel_running_registration();
        let bound = bind_hot_path_manifest_set(&admitted.set, &registration)
            .map_err(|_| HotSpineError::DeclarationRefused)?;
        let bound_operations = bound
            .iter()
            .map(|identity| identity.operation.clone())
            .collect::<Vec<_>>();
        // I12.14 step 4/5: the enforced ledger exists only over a queue the bind
        // above certified by exact identity. `LOCAL_READ_OPERATION` names the
        // declared operation this process bounds; a bind result without it, or
        // with a different registered queue identity, is a refusal rather than a
        // fallback onto whatever the running-build constant happens to spell.
        let bound_queue = bound
            .iter()
            .find(|identity| identity.operation == LOCAL_READ_OPERATION)
            .map(|identity| &identity.registered_queue)
            .ok_or(HotSpineError::DeclarationRefused)?;
        if bound_queue.queue_id != LOCAL_READ_QUEUE_ID {
            return Err(HotSpineError::DeclarationRefused);
        }
        let local_read = Mutex::new(HotPathQueueCapacity::new(
            &bound_queue.queue_id,
            bound_queue.max_items,
            bound_queue.max_bytes,
        ));
        // The same rule for the owner-decision ledger: a bind result without
        // `OWNER_DECISION_OPERATION`, or with a different registered queue
        // identity under it, refuses composition assembly rather than falling
        // back onto a queue the bind never certified.
        let bound_owner_queue = bound
            .iter()
            .find(|identity| identity.operation == OWNER_DECISION_OPERATION)
            .map(|identity| &identity.registered_queue)
            .ok_or(HotSpineError::DeclarationRefused)?;
        if bound_owner_queue.queue_id != OWNER_DECISION_QUEUE_ID {
            return Err(HotSpineError::DeclarationRefused);
        }
        let owner_decision = Mutex::new(OwnerDecisionQueue {
            capacity: HotPathQueueCapacity::new(
                &bound_owner_queue.queue_id,
                bound_owner_queue.max_items,
                bound_owner_queue.max_bytes,
            ),
            entries: VecDeque::new(),
        });
        Ok(Self {
            admitted,
            bound_operations,
            local_read,
            owner_decision,
        })
    }

    /// The exact operation identities this running build bound.
    pub(crate) fn bound_operations(&self) -> &[String] {
        &self.bound_operations
    }

    /// The digest of the exact declaration bytes this process admitted.
    pub(crate) fn manifest_digest(&self) -> &str {
        &self.admitted.manifest_file_digest
    }

    /// The bounded degradation this process returns for a saturated queue.
    ///
    /// The value is the *declared* degradation of the operation whose queue
    /// saturated, read from the admitted set, so the caller never spells the
    /// result itself and a changed declaration changes what is returned.
    pub(crate) fn saturated_degradation(&self) -> HotPathDegradation {
        self.admitted
            .set
            .supported_operations
            .iter()
            .find(|manifest| {
                manifest
                    .queues_and_capacity
                    .iter()
                    .any(|queue| queue.queue_id == LOCAL_READ_QUEUE_ID)
            })
            .map_or(HotPathDegradation::Unknown, |manifest| {
                manifest.fallback_or_degradation.clone()
            })
    }

    /// Admits one local-read request of `bytes`, or refuses it.
    ///
    /// The byte bound is checked against the exact request size before any
    /// capacity is acquired, so an oversized request never partially acquires
    /// and never reaches the expensive decode that would follow. A refusal is
    /// the owner's typed backpressure: the caller retries through its own
    /// existing directive, and nothing is queued, detached or evicted here.
    ///
    /// Success returns no permit: the ledger itself is the retained capacity and
    /// it is returned only at the owner's safe-release points through
    /// [`KernelHotSpine::release_local_read`], from the byte count the owner
    /// recorded at this very admission. That is what makes the bound cover
    /// pending *plus* claimed/in-flight items rather than pending only.
    pub(crate) fn acquire_local_read_capacity(&self, bytes: u64) -> Result<(), HotSpineError> {
        let mut capacity = self
            .local_read
            .lock()
            .map_err(|_| HotSpineError::BoundSaturated)?;
        capacity
            .acquire(bytes)
            .map_err(|_| HotSpineError::BoundSaturated)?;
        observe_hot_spine(
            LOCAL_READ_QUEUE_ID,
            OUTCOME_ADMITTED,
            capacity.max_bytes(),
            capacity.held_bytes(),
        );
        Ok(())
    }

    /// Releases one retained local-read permit at an owner-safe release point.
    ///
    /// Releasing is idempotent at zero: a double release saturates rather than
    /// wrapping, so an over-release can never manufacture extra capacity.
    pub(crate) fn release_local_read(&self, bytes: u64) {
        let Ok(mut capacity) = self.local_read.lock() else {
            return;
        };
        capacity.release(bytes);
        observe_hot_spine(
            LOCAL_READ_QUEUE_ID,
            OUTCOME_RELEASED,
            capacity.max_items(),
            capacity.held_items(),
        );
    }
}

/// The running build's own registration for the bounded hot operations.
///
/// Every value here is read from a constant or selected limit this process
/// actually enforces, never from the declaration file. That makes the running
/// build the authoritative side of the bind: a manifest can only bind an
/// operation this list already contains, and only at the settings this list
/// already carries.
fn kernel_running_registration() -> RunningBuildRegistration {
    let queued_items = super::host_request_route::MAX_QUEUED_LOCAL_READS as u64;
    RunningBuildRegistration {
        service: KERNEL_HOT_SPINE_SERVICE.to_owned(),
        operations: vec![
            RegisteredOperation {
                operation: LOCAL_READ_OPERATION.to_owned(),
                queue: RegisteredQueueSettings {
                    queue_id: LOCAL_READ_QUEUE_ID.to_owned(),
                    max_items: queued_items,
                    max_bytes: IpcImplementation::registered_queue_bytes() as u64,
                },
            },
            // The read leg uses the same retained-attempt bound and the
            // single-frame limit enforced by the front-door transport. Do not
            // derive these settings from the declaration being checked.
            RegisteredOperation {
                operation: "local_read".to_owned(),
                queue: RegisteredQueueSettings {
                    queue_id: "local_read".to_owned(),
                    max_items: queued_items,
                    max_bytes: IpcImplementation::registered_frame_bytes() as u64,
                },
            },
            RegisteredOperation {
                operation: "local_read_result".to_owned(),
                queue: RegisteredQueueSettings {
                    queue_id: "local_read_result".to_owned(),
                    max_items: queued_items,
                    max_bytes: IpcImplementation::registered_frame_bytes() as u64,
                },
            },
            // The owner-decision claim is a claim leg, so it is registered
            // against the same retained-item ceiling and the same in-flight
            // queue byte bound the other claim leg registers. Those are the
            // values `admit_owner_decision` actually enforces through its own
            // ledger, and they are read from the constants this process
            // enforces rather than from the declaration being checked.
            RegisteredOperation {
                operation: OWNER_DECISION_OPERATION.to_owned(),
                queue: RegisteredQueueSettings {
                    queue_id: OWNER_DECISION_QUEUE_ID.to_owned(),
                    max_items: queued_items,
                    max_bytes: IpcImplementation::registered_queue_bytes() as u64,
                },
            },
        ],
    }
}

impl super::KernelComposition {
    /// Binds the I12.14 hot spine once, during composition assembly.
    ///
    /// Assembly fails closed when the approved declaration does not bind against
    /// the running build's real registered settings, so a composition that
    /// exists is one whose hot spine is genuinely bound. This is the only place
    /// the declaration is read; no request path re-reads it, re-validates it or
    /// performs any build-time analysis.
    pub(crate) fn bind_hot_spine() -> Result<KernelHotSpine, super::KernelBuildError> {
        super::kernel_diagnostics::observe_entrypoint_with_detail(
            EntrypointStage::Composition,
            "kernel.hot_spine.bind_started",
        );
        let hot_spine = KernelHotSpine::bind().map_err(|error| {
            observe_hot_spine(LOCAL_READ_QUEUE_ID, OUTCOME_REFUSED, 0, 0);
            tracing::error!(
                target: KERNEL_DIAGNOSTICS_TARGET,
                outcome = error.as_str(),
                "the approved hot-path declaration does not bind against the running build"
            );
            super::KernelBuildError::Service(
                "the approved hot-path declaration does not bind against the running build"
                    .to_owned(),
            )
        })?;
        observe_hot_spine(LOCAL_READ_QUEUE_ID, OUTCOME_BOUND, 0, 0);
        // I12.14 step 7: the binding is auditable from the running process
        // itself. The record carries the exact operation identities this build
        // bound, the digest of the exact declaration bytes it admitted and the
        // degradation the declaration names for the bounded queue, so a later
        // status read can tell WHICH declaration is live without re-reading the
        // file and without a build-time inventory.
        let degradation = bound_field(&format!("{:?}", hot_spine.saturated_degradation()));
        for operation in hot_spine.bound_operations() {
            tracing::info!(
                target: KERNEL_DIAGNOSTICS_TARGET,
                event = "kernel.hot_spine.binding",
                operation = bound_field(operation).text(),
                manifest_digest = bound_field(hot_spine.manifest_digest()).text(),
                degradation = degradation.text(),
                "the approved hot-path declaration bound against this running build"
            );
        }
        super::kernel_diagnostics::observe_entrypoint_with_detail(
            EntrypointStage::Composition,
            "kernel.hot_spine.bound",
        );
        Ok(hot_spine)
    }

    /// Admits one authenticated owner's non-mutating disposition over an
    /// improvement brief into this operation's bounded claim queue
    /// (I12.24:65).
    ///
    /// The principal is proved against the Session, not taken on trust. It must
    /// be exactly the identity this front-door Session's authenticated peer
    /// carries, which is what `authenticated_user_automation_principal(session)`
    /// reads on the operator route; a request that cannot bind that identity is
    /// refused, so a queued decision can never carry a self-declared string.
    ///
    /// Only `reject` and `investigate` are admitted. They are the two
    /// dispositions `OwnerDecisionKind::is_non_mutating` admits, so the entry is
    /// a record and no effect: I12.24:3 ("never silently rewrites code, policy
    /// or memory authority") and I12.24:82's advisory class ("changes nothing
    /// until owner acts") both hold. `work_item` and `experiment` are refused
    /// rather than queued, because they reach effect only through the
    /// work-item/canary/rollback flow of I12.24:90-91 and admitting them here
    /// would turn this queue into an effect path it is not.
    ///
    /// The capacity is charged from the exact bytes this entry serializes to,
    /// measured here and retained on the entry, so the claim returns the
    /// recorded charge rather than a fresh measurement that could differ. A
    /// refusal acquires nothing: nothing is queued, nothing is dropped, and
    /// nothing is evicted.
    pub fn admit_owner_decision(
        &self,
        session: &Session,
        identity: &RequestIdentity,
        principal: &str,
        operation: &UserAutomationOperation,
    ) -> Result<(), TransportError> {
        let UserAutomationOperation::DecideImprovementBrief {
            brief_id,
            decision,
            note,
        } = operation
        else {
            return Err(TransportError::SessionFenced);
        };
        if !NON_MUTATING_OWNER_DECISIONS.contains(&decision.as_str()) {
            return Err(TransportError::SessionFenced);
        }
        identity
            .validate()
            .map_err(|_| TransportError::SessionFenced)?;
        if !identity
            .request
            .state_fence
            .is_compatible_with(&session.module_generation.state_fence)
            || identity.request.state_fence.authority_epoch != session.authority_epoch
        {
            return Err(TransportError::SessionFenced);
        }
        let session_principal = match &session.peer {
            PeerIdentity::Authenticated { user_identity, .. } => user_identity.as_str(),
            PeerIdentity::Unavailable { .. } => {
                return Err(TransportError::PeerIdentityUnavailable);
            }
        };
        if session_principal != principal {
            return Err(TransportError::PeerIdentityUnavailable);
        }
        let mut entry = QueuedOwnerDecision {
            identity: identity.clone(),
            principal: principal.to_owned(),
            brief_id: brief_id.clone(),
            decision: decision.clone(),
            note: note.clone(),
            held_bytes: 0,
        };
        let serialized = serde_json::to_vec(&entry).map_err(|_| TransportError::SessionFenced)?;
        entry.held_bytes =
            u64::try_from(serialized.len()).map_err(|_| TransportError::SessionFenced)?;
        let mut queue = self
            .hot_spine
            .owner_decision
            .lock()
            .map_err(|_| HotSpineError::BoundSaturated)?;
        queue
            .capacity
            .acquire(entry.held_bytes)
            .map_err(|_| HotSpineError::BoundSaturated)?;
        observe_hot_spine(
            OWNER_DECISION_QUEUE_ID,
            OUTCOME_ADMITTED,
            queue.capacity.max_bytes(),
            queue.capacity.held_bytes(),
        );
        queue.entries.push_back(entry);
        Ok(())
    }

    /// Claims the oldest queued owner decision, or `None` when the queue is
    /// empty.
    ///
    /// This is the only reader of the owner-decision queue, so an entry cannot
    /// be returned by, or attributed to, any other operation. An entry whose
    /// State Fence no longer admits this Session's generation, or whose
    /// authority epoch has rotated, is skipped and left queued rather than
    /// served stale, and the walk ends on the first entry this Session may
    /// claim.
    ///
    /// The retained charge is returned as recorded at that entry's own
    /// admission, so a claim is also the safe-release point for the slot. The
    /// ledger's permit is not held any longer than the entry is: this queue has
    /// one leg only, and after the claim the entry belongs to the daemon, not to
    /// a Kernel-held result the Kernel is still waiting on.
    pub fn claim_owner_decision(
        &self,
        session: &Session,
    ) -> Result<Option<QueuedOwnerDecision>, TransportError> {
        let mut queue = self
            .hot_spine
            .owner_decision
            .lock()
            .map_err(|_| HotSpineError::BoundSaturated)?;
        let Some(position) = queue.entries.iter().position(|entry| {
            entry
                .identity
                .request
                .state_fence
                .is_compatible_with(&session.module_generation.state_fence)
                && entry.identity.request.state_fence.authority_epoch == session.authority_epoch
        }) else {
            // An empty queue is a null result, not a wait and not an error: the
            // declared degradation for this operation is `Unknown`.
            return Ok(None);
        };
        let entry = queue
            .entries
            .remove(position)
            .ok_or(TransportError::SessionFenced)?;
        queue.capacity.release(entry.held_bytes);
        observe_hot_spine(
            OWNER_DECISION_QUEUE_ID,
            OUTCOME_RELEASED,
            queue.capacity.max_items(),
            queue.capacity.held_items(),
        );
        Ok(Some(entry))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shipped_declaration_binds_to_running_kernel() -> Result<(), String> {
        let spine = KernelHotSpine::bind().map_err(|error| format!("{error:?}"))?;
        assert_eq!(
            spine.bound_operations(),
            [
                "local_read_claim",
                "local_read",
                "local_read_result",
                "improvement_decision_claim",
            ],
        );
        assert_eq!(
            spine.manifest_digest(),
            eliot_contracts::sha256_hex(KERNEL_HOT_PATH_MANIFEST.as_bytes()),
        );
        Ok(())
    }

    #[test]
    fn missing_or_changed_runtime_registration_remains_refused() -> Result<(), String> {
        let spine = KernelHotSpine::bind().map_err(|error| format!("{error:?}"))?;
        let mut missing = kernel_running_registration();
        missing
            .operations
            .retain(|row| row.operation != "local_read");
        assert!(bind_hot_path_manifest_set(&spine.admitted.set, &missing).is_err());
        for row in kernel_running_registration().operations {
            let mut changed = kernel_running_registration();
            for changed_row in &mut changed.operations {
                if changed_row.operation == row.operation {
                    changed_row.queue.max_bytes += 1;
                }
            }
            assert!(bind_hot_path_manifest_set(&spine.admitted.set, &changed).is_err());
        }
        Ok(())
    }
}
