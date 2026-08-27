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
    let store = launch_store().map_err(StoreKernelLaunchError::Launch)?;
    if let Err(evidence) = observe_store(&store) {
        return match cleanup_store(store) {
            Ok(()) => Err(StoreKernelLaunchError::StoreNotLive { evidence }),
            Err(boxed) => {
                let (store, reason) = *boxed;
                Err(StoreKernelLaunchError::CleanupRequired { store, reason })
            }
        };
    }
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
    Ok((store, kernel))
}
