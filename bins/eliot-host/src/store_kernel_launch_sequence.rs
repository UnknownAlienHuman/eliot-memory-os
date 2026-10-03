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
//! Kernel semantic acceptance, or Governor types; those concerns remain in their
//! owning layers.

use thiserror::Error;

use crate::HostError;
#[cfg(windows)]
use crate::host_job_launch::LaunchPhaseCorrelation;

// F-LOG-HOST-3 (#978) Store-before-Kernel sequence observation helpers.
//
// Through the #889 facade only
// (`crate::host_diagnostics::observe_entrypoint_with_detail`); the Event Log
// seam stays typed-Unavailable
// (`crate::windows_event_log::event_log_sink_status`), never implemented here
// (#984 still open). No terminal is owned here: the single terminal for a
// failed launch stays with the outermost #891 contour (`host-start-failed` in
// `lib.rs`).
//
// Physical truth only, never semantic acceptance (audit 5910159678 defect 1).
// The Store barrier this cell observes is the caller's `StoreLivenessEvidence`
// (exact Job membership plus a running process), so the record proves liveness
// and nothing more. The Kernel record fires immediately after `launch_kernel`
// returned its child handle, so it proves a launch and nothing more. Kernel
// acceptance belongs solely to the owner-evidence path in
// `kernel_activation_driver::DurableKernelActivationDriver::active`, after the
// permit, the activation receipt and the ready receipt are validated.
//
// Observation-only contract: every helper projects facts already produced by
// the semantic owner. A call site passes a static phase token plus a bounded
// `LaunchPhaseCorrelation`. This sequence owns no operation id, installation,
// artifact, process-start identity, generation or fence: it receives only opaque
// `S`/`K` values and closures, while the contour identities stay with the
// caller that holds them, so those sites bind `LaunchPhaseCorrelation::NONE`.
// The one typed fact it does hold is the already-classified
// `StoreLivenessEvidence`, whose kind name is bound as `reason` while its
// `Unknown` payload text never is. An absent identity renders as the
// renderer's own explicit absence marker instead of being invented by logging,
// so bounding limits size, not sensitivity (I15.4). Sink outcome never alters
// result/order/status/cleanup. There is no mutable global dedup cache.
#[cfg(windows)]
fn store_kernel_note_event_log_unavailable() {
    let _ = crate::windows_event_log::event_log_sink_status();
}

#[cfg(windows)]
fn store_kernel_observe(phase: &str, correlation: &LaunchPhaseCorrelation<'_>) {
    store_kernel_note_event_log_unavailable();
    let detail = correlation.render(phase);
    crate::host_diagnostics::observe_entrypoint_with_detail(
        crate::host_diagnostics::EntrypointStage::Startup,
        &detail,
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
    store_kernel_observe("host.store-launch requested", &LaunchPhaseCorrelation::NONE);
    let store = launch_store().map_err(StoreKernelLaunchError::Launch)?;
    if let Err(evidence) = observe_store(&store) {
        // WORK_UNIT_CASE: 978/6 — Store liveness outcome observed separately
        // from Kernel launch and activation; exact evidence propagates
        // unchanged. The classified liveness kind is the one typed reason this
        // sequence already holds, so it is named as `reason`; the `Unknown`
        // payload text stays out of every record.
        match &evidence {
            StoreLivenessEvidence::Dead => {
                store_kernel_observe(
                    "host.store-launch store-dead observed",
                    &LaunchPhaseCorrelation::NONE.with_reason("dead"),
                );
            }
            StoreLivenessEvidence::Unknown(_) => {
                store_kernel_observe(
                    "host.store-launch store-unknown observed",
                    &LaunchPhaseCorrelation::NONE.with_reason("unknown"),
                );
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
    // WORK_UNIT_CASE: 978/6 — Store liveness barrier passed: exact Job membership
    // plus a running process. That is a physical observation, never Store
    // semantic acceptance; Kernel is invoked only after this barrier.
    store_kernel_observe(
        "host.store-launch store-liveness-proven observed",
        &LaunchPhaseCorrelation::NONE,
    );
    // WORK_UNIT_CASE: 978/6 — Kernel launch requested only after Store liveness.
    store_kernel_observe(
        "host.kernel-launch requested",
        &LaunchPhaseCorrelation::NONE,
    );
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
    // WORK_UNIT_CASE: 978/6 — Kernel launch observed distinctly from Store
    // liveness: a returned child handle is not Kernel acceptance, which needs
    // the owner evidence validated in `DurableKernelActivationDriver::active`.
    store_kernel_observe(
        "host.kernel-launch kernel-launched observed",
        &LaunchPhaseCorrelation::NONE,
    );
    Ok((store, kernel))
}

#[cfg(all(test, windows))]
mod tests {
    use std::io::Write;
    use std::sync::{Arc, Mutex};

    use super::{
        HostError, StoreKernelLaunchError, StoreLivenessEvidence, launch_store_then_kernel,
    };

    /// Bounded facade output captured from the live instrumented sequence.
    #[derive(Clone, Default)]
    struct CapturedRecords {
        bytes: Arc<Mutex<Vec<u8>>>,
    }

    impl Write for CapturedRecords {
        fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
            self.bytes
                .lock()
                .unwrap_or_else(|_| unreachable!())
                .extend_from_slice(buffer);
            Ok(buffer.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// Runs `sequence` under a scoped subscriber and returns what the #889
    /// facade actually emitted while it executed.
    fn captured(sequence: impl FnOnce()) -> String {
        let records = CapturedRecords::default();
        let writer = records.clone();
        let bytes = {
            let subscriber = tracing_subscriber::fmt()
                .with_ansi(false)
                .with_writer(move || writer.clone())
                .finish();
            tracing::subscriber::with_default(subscriber, sequence);
            records
                .bytes
                .lock()
                .unwrap_or_else(|_| unreachable!())
                .clone()
        };
        String::from_utf8_lossy(&bytes).into_owned()
    }

    // WORK_UNIT_CASE: 978/6 — the live sequence proves Store liveness and a
    // Kernel launch, in that order, and claims neither semantic acceptance.
    #[test]
    fn live_sequence_records_liveness_and_launch_but_no_acceptance() {
        let steps = std::cell::RefCell::new(Vec::new());
        let text = captured(|| {
            let result = launch_store_then_kernel(
                || {
                    steps.borrow_mut().push("store");
                    Ok::<_, HostError>("store-handle")
                },
                |store| {
                    steps.borrow_mut().push("observe");
                    assert_eq!(*store, "store-handle");
                    Ok(())
                },
                || {
                    steps.borrow_mut().push("kernel");
                    Ok::<_, HostError>("kernel-handle")
                },
                |store| -> Result<(), Box<(&str, String)>> {
                    steps.borrow_mut().push("cleanup");
                    Err(Box::new((store, "cleanup unknown".to_owned())))
                },
            );
            // Store-before-Kernel order is unchanged and the successful
            // sequence never reaches cleanup.
            assert!(matches!(result, Ok(("store-handle", "kernel-handle"))));
            assert_eq!(*steps.borrow(), ["store", "observe", "kernel"]);
        });
        let liveness = text
            .find("phase=host.store-launch store-liveness-proven observed")
            .unwrap_or_else(|| unreachable!());
        let kernel_launch = text
            .find("phase=host.kernel-launch requested")
            .unwrap_or_else(|| unreachable!());
        let launched = text
            .find("phase=host.kernel-launch kernel-launched observed")
            .unwrap_or_else(|| unreachable!());
        assert!(
            liveness < kernel_launch && kernel_launch < launched,
            "records must keep Store-before-Kernel order, got: {text}"
        );
        // No Store identity is held here, so every correlation slot stays
        // explicitly absent instead of being invented. The exact absent-value
        // spelling is the shared renderer's contract, so either its
        // `<slot>_missing` marker or `<slot>=missing` satisfies this case.
        assert!(
            text.contains("generation_missing") || text.contains("generation=missing"),
            "an unheld identity must stay explicitly absent, got: {text}"
        );
        assert!(!text.contains("ready"), "no acceptance claim, got: {text}");
    }

    // Supporting negative for the same case: the liveness barrier is fail-closed
    // and emits no Kernel phase at all.
    #[test]
    fn dead_store_barrier_records_no_kernel_phase() {
        let steps = std::cell::RefCell::new(Vec::new());
        let text = captured(|| {
            let result = launch_store_then_kernel(
                || {
                    steps.borrow_mut().push("store");
                    Ok::<_, HostError>(7_u8)
                },
                |_| {
                    steps.borrow_mut().push("observe");
                    Err(StoreLivenessEvidence::Dead)
                },
                || {
                    steps.borrow_mut().push("kernel");
                    Ok::<_, HostError>(())
                },
                |store| -> Result<(), Box<(u8, String)>> {
                    steps.borrow_mut().push("cleanup");
                    assert_eq!(store, 7);
                    Ok(())
                },
            );
            assert!(matches!(
                result,
                Err(StoreKernelLaunchError::StoreNotLive {
                    evidence: StoreLivenessEvidence::Dead
                })
            ));
            assert_eq!(*steps.borrow(), ["store", "observe", "cleanup"]);
        });
        assert!(text.contains("phase=host.store-launch store-dead observed"));
        assert!(text.contains("reason=dead"), "got: {text}");
        assert!(!text.contains("host.kernel-launch"), "got: {text}");
        assert!(!text.contains("ready"), "no acceptance claim, got: {text}");
    }

    // WORK_UNIT_CASE: 978/12 — the classified liveness kind is named, while the
    // opaque `Unknown` payload a caller supplied never reaches a record.
    #[test]
    fn unknown_store_evidence_names_its_kind_and_not_its_payload() {
        const EVIDENCE_CANARY: &str = "canary-store-reap-timeout-978";
        let steps = std::cell::RefCell::new(Vec::new());
        let text = captured(|| {
            let result = launch_store_then_kernel(
                || {
                    steps.borrow_mut().push("store");
                    Ok::<_, HostError>(7_u8)
                },
                |_| {
                    steps.borrow_mut().push("observe");
                    Err(StoreLivenessEvidence::Unknown(EVIDENCE_CANARY.to_owned()))
                },
                || {
                    steps.borrow_mut().push("kernel");
                    Ok::<_, HostError>(())
                },
                |store| -> Result<(), Box<(u8, String)>> {
                    steps.borrow_mut().push("cleanup");
                    assert_eq!(store, 7);
                    Ok(())
                },
            );
            assert!(matches!(
                result,
                Err(StoreKernelLaunchError::StoreNotLive {
                    evidence: StoreLivenessEvidence::Unknown(_)
                })
            ));
            // The unknown liveness barrier still blocks Kernel exactly as the
            // dead barrier does.
            assert_eq!(*steps.borrow(), ["store", "observe", "cleanup"]);
        });
        assert!(text.contains("phase=host.store-launch store-unknown observed"));
        assert!(text.contains("reason=unknown"), "got: {text}");
        assert!(
            !text.contains(EVIDENCE_CANARY),
            "caller evidence text must stay out of the record: {text}"
        );
        assert!(!text.contains("ready"), "no acceptance claim, got: {text}");
    }
}
