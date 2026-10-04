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
// (`crate::windows_event_log::event_log_sink_status`), never implemented here (#984
// still open). No terminal is owned here: the single terminal for a failed launch
// stays with the outermost #891 contour in `lib.rs` — the startup path arms
// `BOUNDARY_OPEN_TERMINAL` ("host-open-failed"), a cutover-path launch
// `BOUNDARY_BACKUP_CUTOVER_TERMINAL`, a phase-B resume `BOUNDARY_RESUME_PENDING_TERMINAL`.
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
// caller that holds them, so each site binds the correlation its caller forwards.
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
pub(super) fn launch_store_then_kernel_with_correlation<S, K, LF, OF, KF, CF>(
    correlation: &LaunchPhaseCorrelation<'_>,
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
    store_kernel_observe("host.store-launch requested", correlation);
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
                    &correlation.with_reason("dead"),
                );
            }
            StoreLivenessEvidence::Unknown(_) => {
                store_kernel_observe(
                    "host.store-launch store-unknown observed",
                    &correlation.with_reason("unknown"),
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
        correlation,
    );
    // WORK_UNIT_CASE: 978/6 — Kernel launch requested only after Store liveness.
    store_kernel_observe("host.kernel-launch requested", correlation);
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
    store_kernel_observe("host.kernel-launch kernel-launched observed", correlation);
    Ok((store, kernel))
}

/// The Store-before-Kernel sequence for a call site that holds no identity.
///
/// This delegates to [`launch_store_then_kernel_with_correlation`] with
/// [`LaunchPhaseCorrelation::NONE`], so an identity-free call site keeps the
/// exact same records in the exact same order, the same typed results, the same
/// launch count and the same cleanup/drop behaviour, with every unproven
/// identity rendered as the shared renderer's absence marker. A call site that
/// already holds bounded identities calls
/// [`launch_store_then_kernel_with_correlation`] directly, so no record on that
/// path renders an identity the caller held as missing.
///
/// Its only callers are the test-only callers in `src/tests.rs` and this
/// module's own `#[cfg(all(test, windows))]` tests, because the production
/// contour calls [`launch_store_then_kernel_with_correlation`] instead; this
/// `#[cfg(all(test, windows))]` attribute is therefore what keeps a non-test
/// build free of a dead-code finding without `#[allow(dead_code)]`.
#[cfg(all(test, windows))]
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
    launch_store_then_kernel_with_correlation(
        &LaunchPhaseCorrelation::NONE,
        launch_store,
        observe_store,
        launch_kernel,
        cleanup_store,
    )
}

#[cfg(all(test, windows))]
mod tests {
    use std::io::Write;
    use std::sync::{Arc, Mutex};

    use super::{
        HostError, LaunchPhaseCorrelation, StoreKernelLaunchError, StoreLivenessEvidence,
        launch_store_then_kernel, launch_store_then_kernel_with_correlation,
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

    // A call site that already holds bounded identities forwards them into the
    // sequence, so each of the four success-path phases asserted below carries
    // them instead of the renderer's absence marker. This case carries no
    // `WORK_UNIT_CASE` marker of its own: case 978/6 is already carried by
    // `live_sequence_records_liveness_and_launch_but_no_acceptance` above, and
    // the declared 1..14 denominator belongs to
    // `tests/host_launch_diagnostics.rs`. The `store-dead` and `store-unknown`
    // refusal arms are covered by the sibling case
    // `forwarded_correlation_carries_the_callers_identities_on_the_refusal_arms`.
    // The identity values below are composed BY THIS CASE, not held by this cell:
    // the sequence owns no operation id, installation, generation, artifact,
    // process-start identity or fence of its own, so it cannot read one off the
    // opaque `S`/`K` values it receives. They are therefore named as what they
    // are - forwarded labels a caller would hold - and deliberately NOT named
    // after the Store or Kernel handle, so no record can be misread as this cell
    // having derived an installation from its Store handle. Nothing is probed,
    // re-derived or read from the environment here.
    const FORWARDED_INSTALLATION: &str = "forwarded-installation-label";
    const FORWARDED_GENERATION: u64 = 978;
    const FORWARDED_FENCE: &str = "forwarded-fence-label";
    #[test]
    fn forwarded_correlation_carries_the_callers_identities_on_every_phase() {
        let correlation = LaunchPhaseCorrelation::NONE
            .with_installation(FORWARDED_INSTALLATION)
            .with_generation(FORWARDED_GENERATION)
            .with_fence(FORWARDED_FENCE);
        let text = captured(|| {
            let result = launch_store_then_kernel_with_correlation(
                &correlation,
                || Ok::<_, HostError>("store-handle"),
                |store| {
                    assert_eq!(*store, "store-handle");
                    Ok(())
                },
                || Ok::<_, HostError>("kernel-handle"),
                |store| -> Result<(), Box<(&str, String)>> {
                    Err(Box::new((store, "cleanup unknown".to_owned())))
                },
            );
            // The forwarded correlation changes only what a record carries:
            // same result, same launch count, same untouched cleanup behaviour.
            assert!(matches!(result, Ok(("store-handle", "kernel-handle"))));
        });
        // The exact frozen slot order `render` emits: the three identities this
        // caller already held keep their real values, and every identity it did
        // not bind still spells the renderer's explicit absence marker.
        let slots = "installation=forwarded-installation-label generation=978 operation=missing \
                     artifact=missing process_start=missing fence=forwarded-fence-label \
                     reason=missing";
        for phase in [
            "host.store-launch requested",
            "host.store-launch store-liveness-proven observed",
            "host.kernel-launch requested",
            "host.kernel-launch kernel-launched observed",
        ] {
            assert!(
                text.contains(&format!("phase={phase} {slots}")),
                "the forwarded correlation must reach {phase}, got: {text}"
            );
        }
        assert!(!text.contains("ready"), "no acceptance claim, got: {text}");
    }

    // Refusal-arm proof for the same forwarded correlation. When the caller's
    // own `observe_store` classifies the Store as dead or unknown, the sequence
    // still forwards the identities that caller already held into the refusal
    // record instead of dropping them for the renderer's absence marker, still
    // names the classified kind as `reason`, and still keeps the `Unknown`
    // payload text out of the record. The forwarded correlation is the one the
    // sibling case composes, from the same three labels: nothing is probed,
    // re-derived or read from the environment here.
    #[test]
    fn forwarded_correlation_carries_the_callers_identities_on_the_refusal_arms() {
        const EVIDENCE_CANARY: &str = "canary-store-reap-timeout-978";
        let correlation = LaunchPhaseCorrelation::NONE
            .with_installation(FORWARDED_INSTALLATION)
            .with_generation(FORWARDED_GENERATION)
            .with_fence(FORWARDED_FENCE);
        let dead_text = captured(|| {
            let result = launch_store_then_kernel_with_correlation(
                &correlation,
                || Ok::<_, HostError>("store-handle"),
                |store| {
                    assert_eq!(*store, "store-handle");
                    Err(StoreLivenessEvidence::Dead)
                },
                || Ok::<_, HostError>("kernel-handle"),
                |store| -> Result<(), Box<(&str, String)>> {
                    assert_eq!(store, "store-handle");
                    Ok(())
                },
            );
            // The forwarded correlation changes only what the refusal record
            // carries: the refusal stays the same typed error either way.
            assert!(matches!(
                result,
                Err(StoreKernelLaunchError::StoreNotLive {
                    evidence: StoreLivenessEvidence::Dead
                })
            ));
        });
        // The exact frozen slot order `render` emits: the identities this caller
        // already held keep their real values on a refusal record too, the
        // classified kind is the one typed reason this sequence holds, and every
        // identity the caller did not bind still spells the renderer's explicit
        // absence marker.
        let dead_slots = "installation=forwarded-installation-label generation=978 operation=missing \
                          artifact=missing process_start=missing fence=forwarded-fence-label \
                          reason=dead";
        assert!(
            dead_text.contains(&format!(
                "phase=host.store-launch store-dead observed {dead_slots}"
            )),
            "the forwarded correlation must reach the refusal record, got: {dead_text}"
        );
        let unknown_text = captured(|| {
            let result = launch_store_then_kernel_with_correlation(
                &correlation,
                || Ok::<_, HostError>("store-handle"),
                |store| {
                    assert_eq!(*store, "store-handle");
                    Err(StoreLivenessEvidence::Unknown(EVIDENCE_CANARY.to_owned()))
                },
                || Ok::<_, HostError>("kernel-handle"),
                |store| -> Result<(), Box<(&str, String)>> {
                    assert_eq!(store, "store-handle");
                    Ok(())
                },
            );
            assert!(matches!(
                result,
                Err(StoreKernelLaunchError::StoreNotLive {
                    evidence: StoreLivenessEvidence::Unknown(_)
                })
            ));
        });
        let unknown_slots = "installation=forwarded-installation-label generation=978 operation=missing \
                              artifact=missing process_start=missing fence=forwarded-fence-label \
                              reason=unknown";
        assert!(
            unknown_text.contains(&format!(
                "phase=host.store-launch store-unknown observed {unknown_slots}"
            )),
            "the forwarded correlation must reach the refusal record, got: {unknown_text}"
        );
        assert!(
            !unknown_text.contains(EVIDENCE_CANARY),
            "caller evidence text must stay out of the record: {unknown_text}"
        );
    }
}
