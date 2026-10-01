//! R0 Host physical launch ordering for the independent Store and Kernel branches.
//!
//! This cell implements the strict R0-to-R1 boundary: Host launches the Store,
//! proves Store liveness, and only then invokes Kernel launch. A failed launch,
//! failed observation, or unknown cleanup remains an explicit fail-closed
//! result; Kernel is never invoked without the Store liveness barrier.
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

#[cfg(windows)]
use std::cell::Cell;

use thiserror::Error;

use crate::HostError;

// F-LOG-HOST-3 (#978) Store-before-Kernel sequence observation helpers.
//
// Through the #889 facade only
// (`crate::host_diagnostics::observe_entrypoint_with_detail`,
// `crate::host_diagnostics::bound_field`); the Event Log seam stays
// typed-Unavailable (`crate::windows_event_log::event_log_sink_status`), never
// implemented here (#984 still open). This leaf is phase-only with respect to
// terminals: it arms no terminal guard and emits no terminal record. The single
// terminal for a failed physical launch stays with the outermost #891 contour
// (`BOUNDARY_START_TERMINAL` in `lib.rs`); the leaf-vs-outer guard interaction
// lives in #891-owned files. Every failure here propagates with its exact typed
// disposition, so the one designated owner — and only that owner — can emit the
// one terminal record. Subordinate phase observations below carry no dedup
// cache.
//
// Identity binding (audit #5910159678 defect 3): stage order alone cannot prove
// which owner operation produced a record, so a Store launch and a Kernel
// launch, or two attempts of the same generation, were indistinguishable. This
// leaf is generic over the child types and therefore holds no identity of its
// own; the identity it projects is the one its caller
// (`HostJobBranches::start_approved`) already holds as approved launch
// bindings, handed in through [`StoreKernelLaunchIdentity`]. The Store process
// start identity is additionally filled in by the caller's own liveness
// closure, which has already read it from the retained child evidence; the
// Kernel process start identity is not obtainable here (the Kernel child is an
// opaque type parameter) and stays explicitly unavailable in this leaf — the
// caller binds both real process identities on its own
// `host.launch start admitted` record, where it actually holds them.
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
// the semantic owner. The liveness outcome class (`Dead` vs `Unknown`) and the
// already-observed Store process start identity are carried; the exact
// `Unknown` evidence payload and every path, digest payload, command-line
// value and environment value stay with their owners and never enter a record
// (I15.4, I07.20). Sink outcome never alters
// result/order/status/cleanup. There is no mutable global dedup cache.
#[cfg(windows)]
fn store_kernel_note_event_log_unavailable() {
    let _ = crate::windows_event_log::event_log_sink_status();
}

#[cfg(windows)]
fn store_kernel_observe_bound(detail: &str, identity: &StoreKernelLaunchIdentity<'_>) {
    identity.emit(detail);
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum StoreLivenessEvidence {
    #[error("dead")]
    Dead,
    #[error("unknown: {0}")]
    Unknown(String),
}

/// The bounded, non-secret launch identity this leaf projects, owned and filled
/// in by the calling contour.
///
/// Every field is an approved binding the caller already holds: the
/// installation identity, the Host authority epoch sequence, the approved
/// generation, the approved config/source digest, and the two approved branch
/// artifact digests. `store_process` holds the Store child's already-observed
/// process start identity as `pid/creation-time` — the pair that distinguishes
/// one process incarnation from a later process reusing the same PID. It is a
/// [`Cell`] because the caller's liveness closure reads it from the retained
/// child evidence between this leaf's records; nothing here opens, queries, or
/// re-observes a process, and the slot stays explicitly unavailable until the
/// owner has actually observed one.
#[cfg(windows)]
pub(super) struct StoreKernelLaunchIdentity<'a> {
    installation: &'a str,
    authority_epoch: u64,
    generation: &'a str,
    config_digest: &'a str,
    store_artifact_digest: &'a str,
    kernel_artifact_digest: &'a str,
    store_process: Cell<Option<String>>,
}

#[cfg(windows)]
impl<'a> StoreKernelLaunchIdentity<'a> {
    /// Builds the identity from the approved bindings the caller holds.
    #[must_use]
    pub(super) const fn new(
        installation: &'a str,
        authority_epoch: u64,
        generation: &'a str,
        config_digest: &'a str,
        store_artifact_digest: &'a str,
        kernel_artifact_digest: &'a str,
    ) -> Self {
        Self {
            installation,
            authority_epoch,
            generation,
            config_digest,
            store_artifact_digest,
            kernel_artifact_digest,
            store_process: Cell::new(None),
        }
    }

    /// Records the Store child's already-observed process start identity.
    ///
    /// The caller passes the exact `pid/creation-time` string it read from the
    /// retained child evidence during its own liveness proof. This setter
    /// stores that value; it never derives, guesses, or probes one.
    pub(super) fn set_store_process(&self, process_start: String) {
        self.store_process.set(Some(process_start));
    }

    /// Emits one phase record bound to this identity through the #889 facade.
    ///
    /// The stored Store process identity is borrowed for the duration of this
    /// render only, so it cannot outlive the record, and a phase emitted before
    /// the caller's liveness proof still reports it as explicitly unavailable
    /// rather than as an empty or invented value.
    fn emit(&self, detail: &str) {
        store_kernel_note_event_log_unavailable();
        let store_process = self.store_process.borrow();
        let fields = vec![
            (
                "installation",
                crate::host_job_launch::LaunchIdentityField::Text(self.installation),
            ),
            (
                "authority_epoch",
                crate::host_job_launch::LaunchIdentityField::Number(self.authority_epoch),
            ),
            (
                "generation",
                crate::host_job_launch::LaunchIdentityField::Text(self.generation),
            ),
            (
                "config_digest",
                crate::host_job_launch::LaunchIdentityField::Text(self.config_digest),
            ),
            (
                "store_artifact",
                crate::host_job_launch::LaunchIdentityField::Text(self.store_artifact_digest),
            ),
            (
                "kernel_artifact",
                crate::host_job_launch::LaunchIdentityField::Text(self.kernel_artifact_digest),
            ),
            (
                "store_process",
                match store_process.as_deref() {
                    Some(process) => crate::host_job_launch::LaunchIdentityField::Text(process),
                    None => crate::host_job_launch::LaunchIdentityField::Unavailable,
                },
            ),
            (
                "kernel_process",
                crate::host_job_launch::LaunchIdentityField::Unavailable,
            ),
        ];
        crate::host_diagnostics::observe_entrypoint_with_detail(
            crate::host_diagnostics::EntrypointStage::Startup,
            &crate::host_job_launch::render_launch_identity(detail, &fields),
        );
    }
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
    identity: &StoreKernelLaunchIdentity<'_>,
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
    store_kernel_observe_bound("host.store-launch requested", identity);
    // WORK_UNIT_CASE: 978/6 — Store launch failure is a subordinate phase
    // observation only; the failure disposition propagates unchanged to the
    // single designated terminal owner. No terminal is emitted here.
    let store = launch_store().map_err(|error| {
        store_kernel_observe_bound("host.store-launch launch-failed observed", identity);
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
                store_kernel_observe_bound("host.store-launch store-dead observed", identity);
            }
            StoreLivenessEvidence::Unknown(_) => {
                store_kernel_observe_bound("host.store-launch store-unknown observed", identity);
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
    // invoked only after this barrier. The Store process start identity the
    // caller's liveness closure already observed is bound, so this record names
    // the exact process incarnation that passed the barrier.
    store_kernel_observe_bound("host.store-launch store-live observed", identity);
    // WORK_UNIT_CASE: 978/6 — Kernel launch requested only after Store-live.
    store_kernel_observe_bound("host.kernel-launch requested", identity);
    let kernel = match launch_kernel() {
        Ok(kernel) => kernel,
        Err(error) => {
            // WORK_UNIT_CASE: 978/6 — Kernel launch failure is a subordinate
            // phase observation only; the failure disposition propagates
            // unchanged to the single designated terminal owner.
            store_kernel_observe_bound("host.kernel-launch launch-failed observed", identity);
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
    // record states that it is unavailable; Kernel readiness is emitted solely
    // on owner evidence in `kernel_activation_driver::active`.
    store_kernel_observe_bound(
        "host.kernel-launch kernel-launched observed; activation evidence unavailable",
        identity,
    );
    Ok((store, kernel))
}
