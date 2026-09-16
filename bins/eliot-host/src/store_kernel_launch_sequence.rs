//! R0 Host physical launch ordering for the independent Store and Kernel branches.
//!
//! This cell implements the strict R0-to-R1 boundary: Host launches the Store,
//! proves Store liveness, and only then invokes Kernel launch. A failed launch,
//! failed observation, or unknown cleanup remains an explicit fail-closed result;
//! Kernel is never invoked without the Store liveness barrier.
//!
//! Architecture anchors: `docs/architecture/ELIOT_ARCHITECTURE.md` §A2.2
//! (Host Supervisor) and §A2.3 (Host physical lifecycle). Implementation anchors:
//! `docs/architecture/ELIOT_IMPLEMENTATION.md` §I0.1 (R0/R1 layer boundary),
//! §I1.2 (`eliot-host.exe` ownership), and §I1.4 (separate Host-owned process
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
// (#984 still open). No terminal is owned here: the single terminal for a
// failed launch stays with the outermost #891 contour (`host-start-failed` in
// `lib.rs`); this sequence correlates Store-ready vs Kernel-ready by stage
// order only.
//
// Observation-only contract: every helper projects facts already produced by
// the semantic owner. Arguments are static literals only — never process
// identities, PIDs, paths, digests, or arbitrary error text — so bounding
// limits size, not sensitivity (I15.4). Sink outcome never alters
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
    let store = launch_store().map_err(StoreKernelLaunchError::Launch)?;
    if let Err(evidence) = observe_store(&store) {
        // WORK_UNIT_CASE: 978/6 — Store liveness outcome observed separately
        // from Kernel readiness; exact evidence propagates unchanged.
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
    // WORK_UNIT_CASE: 978/6 — Store-ready observed; Kernel is invoked only
    // after this barrier.
    store_kernel_observe("host.store-launch store-ready observed");
    // WORK_UNIT_CASE: 978/6 — Kernel launch requested only after Store-ready.
    store_kernel_observe("host.kernel-launch requested");
    let kernel = match launch_kernel() {
        Ok(kernel) => kernel,
        Err(error) => {
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
    // WORK_UNIT_CASE: 978/6 — Kernel-ready observed distinctly from
    // Store-ready; readiness still requires its own owner proof downstream.
    store_kernel_observe("host.kernel-launch kernel-ready observed");
    Ok((store, kernel))
}
