//! R0 Host physical launch ordering for the independent Store and Kernel branches.
//!
//! This cell implements the strict R0-to-R1 boundary: Host launches the Store,
//! proves Store liveness, and only then invokes Kernel launch. A failed launch,
//! failed observation, or unknown cleanup remains an explicit fail-closed result;
//! Kernel is never invoked without the Store liveness barrier.
//!
//! Architecture anchors: `A2.2` (`docs/architecture/A02-02-roles.md`,
//! Host Supervisor) and `A2.3`
//! (`docs/architecture/A02-03-modular-architecture.md`, Host physical
//! lifecycle). Implementation anchors: `I0.1`
//! (`docs/architecture/I00-01-three-development-contours.md`, R0/R1 layer
//! boundary), `I1.2`
//! (`docs/architecture/I01-02-required-processes-of-the-first-complete-runtime.md`,
//! `eliot-host.exe` ownership), and `I1.4`
//! (`docs/architecture/I01-04-supervision-tree.md`, separate Host-owned process
//! branches and fail-closed lineage handling).
//!
//! This cell owns no Store semantic or canonical authority, Kernel fencing or
//! semantic readiness, or Governor types; those concerns remain in their owning
//! layers.

use thiserror::Error;

use crate::HostError;

// F-LOG-HOST-3 (#978) Store-before-Kernel sequence observation helpers.
//
// Through the #889 facade only
// (`crate::host_diagnostics::observe_entrypoint_with_detail`); the Event Log
// seam stays typed-Unavailable
// (`crate::windows_event_log::event_log_sink_status`), never implemented here
// (#984 still open). This leaf is phase-only: it arms no terminal guard and
// emits no terminal record. The single terminal for a failed physical launch
// stays with the outermost #891 contour (`BOUNDARY_START_TERMINAL` in
// `lib.rs`); the leaf-vs-outer guard interaction lives in #891-owned files.
// Every failure here propagates with its exact typed disposition, so the one
// designated owner — and only that owner — can emit the one terminal record.
// Subordinate phase observations below correlate by stage order only, never by
// a dedup cache.
//
// Readiness is never emitted here (I01.10 health vector; I14.20 lifecycle
// vocabulary): the post-barrier record projects Store liveness only — exact
// Job membership plus a running process — never Store semantic readiness,
// which stays with its owner. The post-launch record projects launch success
// only; Kernel readiness is emitted solely on owner evidence in
// `kernel_activation_driver::active` (permit, activation receipt, ready
// receipt).
//
// Observation-only contract: every helper projects facts already produced by
// the semantic owner. Records carry the already-held bounded non-secret
// outcome identities — the launch phase and the liveness outcome class
// (`Dead` vs `Unknown`) — and mark correlation this layer does not retain as
// explicitly unavailable instead of implying it by stage order (I07.20
// same-operation identity is carried only when held; operation,
// installation, artifact digest, process-start, generation, fence and reason
// payloads stay with their owners). Arguments are static literals only —
// never PIDs, paths, digests, or arbitrary error text — so bounding limits
// size, not sensitivity (I15.4, I07.20). Sink outcome never alters
// result/order/status/cleanup. There is no mutable global dedup cache.
#[cfg(windows)]
fn store_kernel_note_event_log_unavailable() {
    let _ = crate::windows_event_log::event_log_sink_status();
}

#[cfg(windows)]
fn store_kernel_observe(detail: &str) {
    store_kernel_note_event_log_unavailable();
    crate::host_diagnostics::observe_entrypoint_with_detail(
        crate::host_diagnostics::EntrypointStage::Startup,
        detail,
    );
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum StoreLivenessEvidence {
    #[error("dead")]
    Dead,
    #[error("unknown: {0}")]
    Unknown(String),
}

#[cfg(windows)]
pub(super) enum StoreKernelLaunchError<S> {
    Launch(HostError),
    StoreNotLive { evidence: StoreLivenessEvidence },
    CleanupRequired { store: S, reason: String },
    Kernel { error: HostError },
}

#[cfg(windows)]
pub(super) fn launch_store_then_kernel<S, K, LF, OF, KF, CF>(
    launch_store: LF,
    observe_store: OF,
    launch_kernel: KF,
    cleanup_store: CF,
) -> Result<(S, K), StoreKernelLaunchError<S>>
where
    LF: FnOnce() -> Result<S, HostError>,
    OF: FnOnce(&S) -> Result<(), StoreLivenessEvidence>,
    KF: FnOnce() -> Result<K, HostError>,
    CF: FnOnce(S) -> Result<(), Box<(S, String)>>,
{
    // WORK_UNIT_CASE: 978/6 — Store launch requested before any Kernel work;
    // Store-before-Kernel ordering is observed, never reordered.
    store_kernel_observe("host.store-launch requested");
    // WORK_UNIT_CASE: 978/6 — Store launch failure is a subordinate phase
    // observation only; the failure disposition propagates unchanged to the
    // single designated terminal owner. No terminal is emitted here.
    let store = launch_store().map_err(|error| {
        store_kernel_observe("host.store-launch launch-failed observed");
        StoreKernelLaunchError::Launch(error)
    })?;
    if let Err(evidence) = observe_store(&store) {
        // WORK_UNIT_CASE: 978/6 — Store liveness outcome observed separately
        // from Kernel launch; the already-held outcome class (dead vs
        // unknown) is carried in the record while exact evidence propagates
        // unchanged. The unknown payload stays with its owner and never
        // enters a record (I15.4, I07.20).
        match &evidence {
            StoreLivenessEvidence::Dead => {
                store_kernel_observe("host.store-launch store-dead observed");
            }
            StoreLivenessEvidence::Unknown(_) => {
                store_kernel_observe("host.store-launch store-unknown observed");
            }
        }
        return match cleanup_store(store) {
            Ok(()) => Err(StoreKernelLaunchError::StoreNotLive { evidence }),
            Err(boxed) => {
                let (store, reason) = *boxed;
                Err(StoreKernelLaunchError::CleanupRequired { store, reason })
            }
        };
    }
    // WORK_UNIT_CASE: 978/6 — Store-live observed (liveness only: exact Job
    // membership plus a running process, never semantic readiness); Kernel is
    // invoked only after this barrier. No process-start identity is retained
    // at this layer, so the record marks it explicitly unavailable rather
    // than implying operation correlation by stage order.
    store_kernel_observe(
        "host.store-launch store-live observed; process-start identity unavailable",
    );
    // WORK_UNIT_CASE: 978/6 — Kernel launch requested only after Store-live.
    store_kernel_observe("host.kernel-launch requested");
    let kernel = match launch_kernel() {
        Ok(kernel) => kernel,
        Err(error) => {
            // WORK_UNIT_CASE: 978/6 — Kernel launch failure is a subordinate
            // phase observation only; the failure disposition propagates
            // unchanged to the single designated terminal owner.
            store_kernel_observe("host.kernel-launch launch-failed observed");
            return match cleanup_store(store) {
                Ok(()) => Err(StoreKernelLaunchError::Kernel { error }),
                Err(boxed) => {
                    let (store, reason) = *boxed;
                    Err(StoreKernelLaunchError::CleanupRequired {
                        store,
                        reason: format!(
                            "Kernel launch failed ({error}); Store cleanup is unknown: {reason}"
                        ),
                    })
                }
            };
        }
    };
    // WORK_UNIT_CASE: 978/6 — Kernel-launched observed distinctly from
    // Store-live: launch success only, never readiness. Activation evidence
    // (permit, activation receipt, ready receipt) is not held here, so the
    // record marks it explicitly unavailable; Kernel readiness is emitted
    // solely on owner evidence in `kernel_activation_driver::active`.
    store_kernel_observe(
        "host.kernel-launch kernel-launched observed; activation evidence unavailable",
    );
    Ok((store, kernel))
}
