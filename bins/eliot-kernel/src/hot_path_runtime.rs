//! I12.14 runtime binding and bound enforcement for the Kernel hot spine.
//!
//! Two jobs, both at the real owner, neither a declaration:
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

use std::sync::Mutex;

use eliot_runtime_contracts::{
    AdmittedHotPathManifest, HotPathDegradation, HotPathQueueCapacity, RegisteredOperation,
    RegisteredQueueSettings, RunningBuildRegistration, admit_hot_path_manifest,
    bind_hot_path_manifest_set, hot_path_manifest_path,
};

use super::kernel_diagnostics::{EntrypointStage, KERNEL_DIAGNOSTICS_TARGET, bound_field};
use super::{IpcImplementation, TransportError};

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
        Ok(Self {
            admitted,
            bound_operations,
            local_read,
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shipped_declaration_binds_to_running_kernel() -> Result<(), String> {
        let spine = KernelHotSpine::bind().map_err(|error| format!("{error:?}"))?;
        assert_eq!(
            spine.bound_operations(),
            ["local_read_claim", "local_read", "local_read_result"],
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
