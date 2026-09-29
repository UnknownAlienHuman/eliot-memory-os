//! Runtime binding and capacity enforcement for the I12.14 hot spine.
//!
//! `bins/eliot-kernel/hot-path.toml` is the declaration and
//! `eliot_runtime_contracts::admit_hot_path_manifest` is its only loader, but a
//! declaration that merely parses admits nothing. This module is the running
//! side: it binds the approved declaration against the queue and port settings
//! this process actually enforces
//! ([`bind_hot_path_manifest_set`](eliot_runtime_contracts::bind_hot_path_manifest_set)),
//! and it owns the per-queue capacity the real admission points charge and the
//! real owner-safe release points return.
//!
//! Three properties this module exists to hold:
//!
//! - **A bound must not heal itself shut.** The ledger's limits come from the
//!   bound declaration and from nothing else, and a failed bind is a refusal
//!   to advertise rather than a relaxed bound. A poisoned ledger keeps refusing
//!   rather than being reset into an empty one that would report free capacity
//!   the process does not have.
//! - **A charge is released with the value recorded at that pair's own
//!   admission.** [`HotPathCharge`] is minted once, at admission, and travels
//!   with the queued pair. Release returns the bytes that charge recorded,
//!   never a fresh computation of the body.
//! - **A missing or invalid profile is not permission to skip work.** An
//!   operation whose #1734 profile is absent still enforces its bound; it
//!   simply reports as unqualified
//!   ([`KernelHotSpine::declared_profile_refs`]). Qualification is a claim and
//!   the bound is a guarantee, so the bound never depends on the claim.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::{Mutex, MutexGuard, PoisonError};

use eliot_runtime_contracts::{
    AdmittedHotPathManifest, HotPathBindingIdentity, HotPathBoundStatus, HotPathManifestFileError,
    HotPathQueueCapacity, RegisteredOperation, RegisteredQueueSettings, RunningBuildRegistration,
    RuntimeContractError, admit_hot_path_manifest, bind_hot_path_manifest_set,
    hot_path_bound_status,
};

use super::{IpcImplementation, host_request_route::MAX_QUEUED_LOCAL_READS};
use crate::KernelComposition;

/// The service identity this composition registers its own hot operations
/// under. The declaration file spells `owning_service = "eliot-kernel"`, so
/// the running-build side must use the same name or the bind refuses.
const KERNEL_HOT_PATH_SERVICE: &str = "eliot-kernel";

/// The checked-in service-local declaration, read once at compile time.
///
/// The declaration is a build input of the Kernel binary, not a file this
/// process discovers: `include_str!` names the one authoritative source the
/// manifest owner already maintains, so admission never touches the
/// filesystem and never runs Cargo or dependency analysis. The path is
/// retained only so the admitted record can name the exact file its bytes
/// came from.
const DECLARED_MANIFEST_PATH: &str = "bins/eliot-kernel/hot-path.toml";

/// The exact bytes of the service-local declaration this binary was built
/// from.
const DECLARED_MANIFEST_BYTES: &[u8] = include_bytes!("../hot-path.toml");

/// The declaration row a single admitted queue is registered under.
///
/// The ids are the declaration's own queue ids. Interning them keeps a
/// [`HotPathCharge`] `Copy` and comparable without borrowing the ledger, and
/// a charge can only ever name a queue the bound declaration already declared.
///
/// The type itself is crate-visible because [`LOCAL_READ_CLAIM_QUEUE`] names
/// one of its variants in a signature the real admission point calls; the
/// variants stay private, so the only queue a caller can name is the one the
/// declaration wired to that admission point.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) enum HotPathQueueId {
    /// The retained queued local-read pairs the daemon claim leg drains.
    Claim,
    /// The in-flight bounded named read.
    Read,
    /// The retained result leg that binds a daemon result to its caller.
    Result,
}

/// The retained queued local-read queue the claim leg charges its admission
/// against.
///
/// The real admission point names this one queue, so it is the only
/// `pub(crate)` name on the enumeration: the other two queue ids are reached
/// through the registration this spine builds, not by a caller picking a
/// bound out of thin air. Exposing all three here would let any holder charge
/// a bound the declaration never wired to the point that spent it.
pub(crate) const LOCAL_READ_CLAIM_QUEUE: HotPathQueueId = HotPathQueueId::Claim;

/// The declared operation ids the registration binds, in declaration order.
///
/// These are the exact strings `hot-path.toml` declares as `operation`, and
/// the registration below registers under the same three. Naming them once
/// keeps the registration and the diagnostics projection from drifting apart:
/// a projection row keyed by a misspelled id would silently read as
/// "unregistered" instead of reporting the queue the process really enforces.
const LOCAL_READ_CLAIM_OPERATION: &str = "local_read_claim";
const LOCAL_READ_OPERATION: &str = "local_read";
const LOCAL_READ_RESULT_OPERATION: &str = "local_read_result";

impl HotPathQueueId {
    /// The exact queue id the declaration and the running build both spell.
    const fn as_str(self) -> &'static str {
        match self {
            Self::Claim => "local_read_claim",
            Self::Read => "local_read",
            Self::Result => "local_read_result",
        }
    }

    /// Every queue the Kernel hot spine owns, in declaration order.
    const ALL: [Self; 3] = [Self::Claim, Self::Read, Self::Result];
}

/// A charge against one bound hot-path queue, minted at admission.
///
/// The recorded byte count is the value the queue reserved at that pair's own
/// admission. Release returns exactly this value, so the ledger cannot drift
/// when the retained body is later re-validated against a different count.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct HotPathCharge {
    queue: HotPathQueueId,
    bytes: u64,
}

/// A hot-path request this composition cannot admit or cannot advertise.
///
/// Every variant is a *refusal to proceed*, never a relaxation: a spine that
/// cannot be built yields no spine at all, so nothing downstream can read a
/// bound that was never enforced. `Display` is written by hand rather than
/// derived because this crate does not depend on a derive-error crate, and the
/// owner-side reason is already a bounded message the contract owns.
#[derive(Clone, Debug)]
pub(crate) enum HotPathError {
    /// The service-local declaration could not be read, parsed or bound
    /// against the running build's real registration.
    UnboundDeclaration {
        /// The owner's own reason. Bounded, and never a payload from the file.
        reason: String,
    },
}

impl std::fmt::Display for HotPathError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnboundDeclaration { reason } => {
                write!(
                    formatter,
                    "the hot-path declaration is not bound to this running build: {reason}"
                )
            }
        }
    }
}

impl std::error::Error for HotPathError {}

impl From<RuntimeContractError> for HotPathError {
    fn from(error: RuntimeContractError) -> Self {
        Self::UnboundDeclaration {
            reason: error.to_string(),
        }
    }
}

/// The declaration loader reports a file-level failure, which the contract
/// deliberately does not funnel into [`RuntimeContractError`] because a
/// malformed declaration file is a different class of refusal from a
/// contract-invalid value. Both refuse to bind, so both land on the one
/// `HotPathError` variant and neither is downgraded to a laxer bound.
impl From<HotPathManifestFileError> for HotPathError {
    fn from(error: HotPathManifestFileError) -> Self {
        Self::UnboundDeclaration {
            reason: error.to_string(),
        }
    }
}

/// The capacity of every bound hot-path queue, keyed by the declared queue id.
///
/// This is a thin owner-side map over [`HotPathQueueCapacity`], which already
/// refuses an over-large request without partially acquiring and saturates a
/// double release at zero. The map adds only the queue-id lookup the real
/// owners need; it holds no limit of its own, so it cannot widen a bound.
#[derive(Debug, Default)]
struct HotPathCapacityLedger {
    queues: BTreeMap<HotPathQueueId, HotPathQueueCapacity>,
}

impl HotPathCapacityLedger {
    /// Builds the ledger from the bound declaration's own limits.
    ///
    /// A queue the declaration does not declare is not created, so an
    /// admission against it is refused rather than bounded by a default. A
    /// declared queue that is missing *either* the item or the byte dimension
    /// is likewise not created: coercing an absent bound to zero would look
    /// like a live queue with a zero limit in the diagnostics surface, and it
    /// would refuse every admission for a reason the declaration never gave.
    /// Refusing the queue outright reports the real reason — the declaration
    /// did not bound this queue — instead of inventing a bound.
    fn from_manifest(manifest_set: &eliot_runtime_contracts::HotPathManifestSetV1) -> Self {
        let mut queues = BTreeMap::new();
        for manifest in &manifest_set.supported_operations {
            for declared in &manifest.queues_and_capacity {
                let Some(queue) = queue_id_for(declared.queue_id.as_str()) else {
                    continue;
                };
                let (Some(max_items), Some(max_bytes)) =
                    (declared.bounds.max_items, declared.bounds.max_bytes)
                else {
                    continue;
                };
                // A queue declared twice keeps the tighter bound: `min` cannot
                // loosen a limit, so a later row can only ever tighten it.
                let capacity = HotPathQueueCapacity::new(queue.as_str(), max_items, max_bytes);
                queues
                    .entry(queue)
                    .and_modify(|existing: &mut HotPathQueueCapacity| {
                        let tightened = HotPathQueueCapacity::new(
                            queue.as_str(),
                            existing.max_items().min(capacity.max_items()),
                            existing.max_bytes().min(capacity.max_bytes()),
                        );
                        *existing = tightened;
                    })
                    .or_insert(capacity);
            }
        }
        Self { queues }
    }

    /// Charges one admission, or refuses it leaving the ledger untouched.
    ///
    /// The refusal names the exact unbound queue, so the reason is owned text
    /// rather than a fixed literal: the queue is the caller's own admission
    /// point, and a refusal that cannot name which declared queue it lost would
    /// report the same condition for all three legs. [`HotPathError`] is the
    /// owner-side refusal this module already funnels every other bind failure
    /// through, so an unbound queue refuses on the same path as a bound one
    /// that cannot admit the requested bytes — never more weakly.
    fn acquire(&mut self, queue: HotPathQueueId, bytes: u64) -> Result<(), HotPathError> {
        let capacity =
            self.queues
                .get_mut(&queue)
                .ok_or_else(|| HotPathError::UnboundDeclaration {
                    reason: format!("no declared queue '{}' is bound", queue.as_str()),
                })?;
        capacity.acquire(bytes)?;
        Ok(())
    }

    /// Returns one admission's recorded bytes at its owner-safe release point.
    fn release(&mut self, queue: HotPathQueueId, bytes: u64) {
        if let Some(capacity) = self.queues.get_mut(&queue) {
            capacity.release(bytes);
        }
    }

    /// The current held item/byte count, for the audit surface.
    fn held(&self, queue: HotPathQueueId) -> (u64, u64) {
        self.queues.get(&queue).map_or((0, 0), |capacity| {
            (capacity.held_items(), capacity.held_bytes())
        })
    }
}

/// Maps a declared queue id onto the owner-side enumeration.
///
/// A queue id the Kernel hot spine does not own has no mapping, which is what
/// makes an undeclared queue a refusal instead of a silently bounded default.
fn queue_id_for(declared: &str) -> Option<HotPathQueueId> {
    HotPathQueueId::ALL
        .into_iter()
        .find(|queue| queue.as_str() == declared)
}

/// The running hot spine: the admitted declaration, the registration it was
/// bound against, and the capacity the real owners hold.
pub(crate) struct KernelHotSpine {
    admitted: AdmittedHotPathManifest,
    registration: RunningBuildRegistration,
    capacity: Mutex<HotPathCapacityLedger>,
}

impl KernelHotSpine {
    /// Binds the checked-in service-local declaration against the settings
    /// `registration` reports as actually enforced, and builds the capacity
    /// ledger from the bound declaration.
    ///
    /// The registration is the authoritative side: a declaration that parses
    /// but names an operation the running build does not register, or a queue
    /// bound the running build does not enforce, is refused here rather than
    /// advertised. A caller that cannot produce a registration therefore never
    /// gets a spine.
    pub(crate) fn bind(
        declaration_bytes: &[u8],
        registration: RunningBuildRegistration,
    ) -> Result<Self, HotPathError> {
        let admitted =
            admit_hot_path_manifest(Path::new(DECLARED_MANIFEST_PATH), declaration_bytes)?;
        // A bind failure means this process cannot advertise the declaration
        // it was given. It is surfaced, never downgraded to a laxer bound.
        bind_hot_path_manifest_set(&admitted.set, &registration)?;
        let capacity = HotPathCapacityLedger::from_manifest(&admitted.set);
        Ok(Self {
            admitted,
            registration,
            capacity: Mutex::new(capacity),
        })
    }

    /// The exact identities the bind produced, for status and diagnostics.
    ///
    /// Re-deriving them is cheap and re-checks the registration each call, so
    /// a registration that changed after the bind cannot be reported as
    /// still bound.
    pub(crate) fn bound_identities(&self) -> Result<Vec<HotPathBindingIdentity>, HotPathError> {
        Ok(bind_hot_path_manifest_set(
            &self.admitted.set,
            &self.registration,
        )?)
    }

    /// The #1734 profile reference each declared operation carries, keyed by
    /// operation id.
    ///
    /// This is the declaration's own *reference*, never a qualification
    /// decision: at this base no kernel operation declares a profile, so the
    /// map is empty and the diagnostics surface reports "unqualified" rather
    /// than inventing a pass. It is read straight off the admitted manifest
    /// instead of being re-validated here, because a qualification verdict
    /// requires profile evidence (#1734) that this process does not produce —
    /// deriving one from an absent reference would be a fabricated
    /// measurement, and an absent measurement is not a qualification. The
    /// bound itself is enforced regardless of what this map says.
    #[must_use]
    pub(crate) fn declared_profile_refs(
        &self,
    ) -> BTreeMap<&str, &eliot_runtime_contracts::HotPathProfileRef> {
        self.admitted
            .set
            .supported_operations
            .iter()
            .map(|manifest| (manifest.operation.as_str(), &manifest.hot_path_profile_ref))
            .collect()
    }

    /// The queue registration this process actually enforces, so a caller can
    /// read the physical bound rather than the declared one.
    pub(crate) fn registered(&self, operation: &str) -> Option<&RegisteredQueueSettings> {
        self.registration.queue_for(operation)
    }

    /// Charges one admission against the named queue's bound.
    ///
    /// This is the single admission-time charge point. The caller passes the
    /// *wire* byte count, taken before any expensive decoding, so a request
    /// larger than the bound is refused before the work happens. A refusal
    /// leaves the ledger untouched, so a saturated queue never partially
    /// acquires and a refused request is never charged for.
    pub(crate) fn charge(
        &self,
        queue: HotPathQueueId,
        wire_bytes: u64,
    ) -> Result<HotPathCharge, HotPathError> {
        self.lock_capacity().acquire(queue, wire_bytes)?;
        Ok(HotPathCharge {
            queue,
            bytes: wire_bytes,
        })
    }

    /// Returns one admission's charge at its owner-safe release point.
    ///
    /// The bytes come from the charge, never from a recomputation of the body.
    /// A double release cannot manufacture capacity: the ledger saturates at
    /// zero, and the caller spends the charge it returns.
    pub(crate) fn release(&self, charge: HotPathCharge) {
        self.lock_capacity().release(charge.queue, charge.bytes);
    }

    /// The auditable binding status of every declared operation.
    ///
    /// Each row names the operation, the bound manifest revision, the queue
    /// settings the *running build* actually enforces, the declared snapshot
    /// dependencies and the operation's declared degradation — so a reader
    /// can audit which bound is in force rather than inferring it. A
    /// registration that no longer matches the declaration fails the re-bind
    /// here, which is what keeps a changed queue or operation revision from
    /// being reported as still bound.
    pub(crate) fn bound_status(&self) -> Result<Vec<HotPathBoundStatus>, HotPathError> {
        Ok(hot_path_bound_status(
            &self.admitted.set,
            &self.registration,
        )?)
    }

    /// The live held item/byte gauges for the queues the claim leg spends.
    ///
    /// Read at request time from the ledger itself, never accumulated into a
    /// second counter store, so the reported occupancy cannot disagree with
    /// the bound that is actually enforced. Both members of the pair are
    /// always read under one lock, so a reader never sees a held-item count
    /// paired with a held-byte count from two different instants.
    #[must_use]
    pub(crate) fn claim_queue_held(&self) -> (u64, u64) {
        self.lock_capacity().held(LOCAL_READ_CLAIM_QUEUE)
    }

    /// Locks the capacity ledger without ever healing a poisoned one.
    ///
    /// A poisoned ledger is recovered *in place*, so the counts stay truthful
    /// and release keeps working, but it is never reset to empty: admission
    /// continues to be governed by the same declared limits. Restarting the
    /// process is what clears the poison.
    fn lock_capacity(&self) -> MutexGuard<'_, HotPathCapacityLedger> {
        self.capacity.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// Builds the running-build registration for this composition's own hot
/// operations, from the settings the real owners enforce.
///
/// The values are the owners', not the declaration's: the frame and queue byte
/// limits come from the front door's own transport registered accessors, and
/// the retained queued local-read count comes from the host-request route's own
/// bound. Both are read through the owners themselves rather than through a
/// second copy of the number, so the running build is the authoritative side of
/// the comparison and cannot drift from what the process really enforces. The
/// declaration is compared against these, so a declaration that drifts from the
/// running build is refused rather than silently enforced.
pub(crate) fn kernel_running_build_registration() -> RunningBuildRegistration {
    let queued_items = MAX_QUEUED_LOCAL_READS as u64;
    let frame_bytes = IpcImplementation::registered_frame_bytes() as u64;
    let queue_bytes = IpcImplementation::registered_queue_bytes() as u64;
    RunningBuildRegistration {
        service: KERNEL_HOT_PATH_SERVICE.to_owned(),
        operations: vec![
            RegisteredOperation {
                operation: LOCAL_READ_CLAIM_OPERATION.to_owned(),
                queue: RegisteredQueueSettings {
                    queue_id: HotPathQueueId::Claim.as_str().to_owned(),
                    max_items: queued_items,
                    max_bytes: queue_bytes,
                },
            },
            RegisteredOperation {
                operation: LOCAL_READ_OPERATION.to_owned(),
                queue: RegisteredQueueSettings {
                    queue_id: HotPathQueueId::Read.as_str().to_owned(),
                    max_items: queued_items,
                    max_bytes: frame_bytes,
                },
            },
            RegisteredOperation {
                operation: LOCAL_READ_RESULT_OPERATION.to_owned(),
                queue: RegisteredQueueSettings {
                    queue_id: HotPathQueueId::Result.as_str().to_owned(),
                    max_items: queued_items,
                    max_bytes: frame_bytes,
                },
            },
        ],
    }
}

/// Binds the Kernel's own hot spine at composition assembly.
///
/// The registration is built from the real owners' own settings — the front
/// door's transport limits and the host-request route's retained queue bound —
/// so the declaration is compared against what this process actually enforces.
/// A failure returns `None` rather than an unbounded substitute: a Kernel
/// that cannot bind its declaration advertises no validated hot path.
#[cfg(windows)]
pub(crate) fn bind_kernel_hot_spine() -> Option<KernelHotSpine> {
    KernelHotSpine::bind(DECLARED_MANIFEST_BYTES, kernel_running_build_registration()).ok()
}

/// The service name the Kernel hot spine binds under, for diagnostics.
#[cfg(windows)]
pub(crate) const fn kernel_hot_path_service() -> &'static str {
    KERNEL_HOT_PATH_SERVICE
}

impl KernelComposition {
    /// The auditable I12.14 hot-spine binding projection (issue #1733, step 7).
    ///
    /// This is the single status/diagnostics surface the health view consumes
    /// (`health_view`'s `hot_path_binding_projection` on `KernelComposition`).
    /// It reports what the running process actually enforces rather than what
    /// the declaration asked for: the bound identities and per-operation
    /// bound-status rows come from a re-bind against the live registration, so
    /// a queue or operation revision that changed after the bind is reported
    /// as `unbound` instead of as still valid. The live held gauges are read
    /// from the ledger itself, so the reported occupancy cannot drift from the
    /// bound being enforced.
    ///
    /// Every field is bounded and privacy-safe: identities are operation names
    /// and the contract's own version, the registered settings are the numeric
    /// bounds this process enforces, and a degradation reason is the owner's
    /// closed-vocabulary code. A refused bind projects the contract's own
    /// reason text rather than a synthesized "degraded", so a reader can see
    /// *which* check failed. An unbound spine projects `"status": "unbound"`
    /// — never a zeroed, valid-looking binding.
    #[must_use]
    #[cfg(windows)]
    pub(crate) fn bound_hot_path_binding(&self) -> serde_json::Value {
        let service = kernel_hot_path_service();
        let Some(spine) = self.hot_spine.as_ref() else {
            return serde_json::json!({
                "status": "unbound",
                "service": service,
            });
        };
        let identities = match spine.bound_identities() {
            Ok(identities) => serde_json::to_value(&identities).unwrap_or(serde_json::Value::Null),
            Err(error) => {
                return serde_json::json!({
                    "status": "unbound",
                    "service": service,
                    "reason": error.to_string(),
                });
            }
        };
        let status_rows = match spine.bound_status() {
            Ok(rows) => serde_json::to_value(&rows).unwrap_or(serde_json::Value::Null),
            Err(error) => serde_json::json!({"status": "unbound", "reason": error.to_string()}),
        };
        // The declared admission and result limits are read from the
        // registration, so the projection names the *physical* bound rather
        // than the declared one for each leg the claim path actually uses.
        let (held_items, held_bytes) = spine.claim_queue_held();
        let claim_queue = spine.registered(LOCAL_READ_CLAIM_OPERATION);
        let read_queue = spine.registered(LOCAL_READ_OPERATION);
        let result_queue = spine.registered(LOCAL_READ_RESULT_OPERATION);
        // Qualification is reported, never inferred. Every declared operation
        // carries an absent #1734 profile reference at this base, so this
        // projects `unqualified` rather than a pass — an absent measurement is
        // not a qualification, and the bound below is enforced either way.
        let qualified = spine
            .declared_profile_refs()
            .values()
            .all(|profile_ref| profile_ref.is_available());
        serde_json::json!({
            "status": "bound",
            "service": service,
            "qualified": qualified,
            "identities": identities,
            "operations": status_rows,
            "claim_queue_held": {
                "items": held_items,
                "bytes": held_bytes,
            },
            "registered_queues": {
                LOCAL_READ_CLAIM_OPERATION: claim_queue,
                LOCAL_READ_OPERATION: read_queue,
                LOCAL_READ_RESULT_OPERATION: result_queue,
            },
        })
    }
}
