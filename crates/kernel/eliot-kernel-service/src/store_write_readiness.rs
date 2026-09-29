//! Canonical-store write-admission join (I1.9).
//!
//! Architecture: A13.2 Kernel and failure domains, A12.3 one governed write
//! path; Implementation I1.9 three registries/three owners.
//!
//! I1.9 requires that neither observation can substitute for the other: process
//! liveness comes from the Host/Watchdog observation of a Host-managed process,
//! and semantic readiness comes independently from the store bridge's
//! version/schema/transaction probes. This module is the single final join. It
//! starts no process, runs no probe, and holds no authority of its own: it
//! decides, from two already-authenticated observations, whether normal
//! canonical writes may open.
//!
//! It is deliberately not a pair of booleans. The Host half is compared by
//! content — the admitted instance binding (store generation, launch
//! nonce/start identity, approved executable and config hashes, bridge session
//! connection identity, required state fence) plus the exact PID/start/image and
//! owner Job of the process actually observed on the authenticated connection —
//! and the bridge half is the bridge's own typed per-dimension result. Every
//! failure keeps its own dimension: a live process with an incompatible schema,
//! a responsive bridge answered by a foreign process, and an unobserved
//! dimension are three different results, not one "store healthy" boolean.

use eliot_store_api::{SemanticDimension, StoreSemanticReadiness};

use crate::protocol::{HostProcessBinding, StoreBootstrapHandoff};

/// Why normal canonical-store writes stay closed.
///
/// Host failures and the bridge's typed semantic causes are kept side by side
/// rather than collapsed into a first-failure-only health state, so a front-door
/// or recovery status can name the dimension that actually failed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CanonicalStoreWriteRefusal {
    /// The Host-issued handoff is not a valid admitted Store instance.
    HandoffInvalid,
    /// The process answering the authenticated bridge session is not the
    /// Host-managed process of the admitted Store instance.
    ForeignProcess,
    /// The observed process is not inside the Host-owned Job Object.
    ForeignJobObject,
    /// The bridge reported no live, admitted process to observe at all.
    NoProcessObserved,
    /// The bridge's version-compatibility probe did not pass.
    VersionIncompatible,
    /// The bridge's schema-compatibility probe did not pass. The process may be
    /// live; normal canonical writes stay closed anyway.
    SchemaIncompatible,
    /// The bridge's transaction-execution-viability probe did not pass.
    TransactionNotViable,
    /// The bridge could not observe the named dimension at all, so its state
    /// is unknown rather than failed.
    SemanticUnobserved,
    /// The qualified instance changed before write readiness was published.
    /// Current qualification is invalidated; this is not a process failure and
    /// discards no historical receipt.
    ObservationLost,
}

/// The exact admitted canonical-store instance that qualified for writes.
///
/// Held so the caller can re-check the instance immediately before publishing,
/// and so a later call cannot qualify a replacement generation by reusing it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanonicalStoreWriteReadiness {
    /// The exact admitted instance binding both observations answered for.
    instance: StoreBootstrapHandoff,
}

impl CanonicalStoreWriteReadiness {
    /// The exact admitted Store instance these writes are bound to.
    #[must_use]
    pub const fn instance(&self) -> &StoreBootstrapHandoff {
        &self.instance
    }
}

/// Joins the authenticated Host observation of the admitted Store instance with
/// the store bridge's current typed semantic readiness receipt.
///
/// `handoff` is the Host-issued instance binding plus Host's post-launch
/// process/Job identity. `observed_process` and `observed_job` are the Kernel's
/// own live re-observation of the peer on the authenticated bridge session, so
/// a responsive bridge answered by an unmanaged or foreign process is refused
/// here. `semantic` is the bridge's own version/schema/transaction result for
/// that same session; it is never inferred from the process observation, and the
/// process observation is never inferred from it.
pub fn qualify_canonical_store_writes(
    handoff: &StoreBootstrapHandoff,
    observed_process: &HostProcessBinding,
    observed_job: &str,
    semantic: &StoreSemanticReadiness,
) -> Result<CanonicalStoreWriteReadiness, CanonicalStoreWriteRefusal> {
    handoff
        .validate()
        .map_err(|_| CanonicalStoreWriteRefusal::HandoffInvalid)?;
    let bound = &handoff.process_binding;
    if observed_process.process_id == 0 || observed_process.start_time_100ns == 0 {
        return Err(CanonicalStoreWriteRefusal::NoProcessObserved);
    }
    if bound.process.process_id != observed_process.process_id
        || bound.process.start_time_100ns != observed_process.start_time_100ns
        || bound.process.image_path != observed_process.image_path
    {
        return Err(CanonicalStoreWriteRefusal::ForeignProcess);
    }
    if bound.job.as_str() != observed_job {
        return Err(CanonicalStoreWriteRefusal::ForeignJobObject);
    }
    if !semantic.is_ready() {
        return Err(
            match (semantic.version, semantic.schema, semantic.transaction) {
                (SemanticDimension::Incompatible, _, _) => {
                    CanonicalStoreWriteRefusal::VersionIncompatible
                }
                (_, SemanticDimension::Incompatible, _) => {
                    CanonicalStoreWriteRefusal::SchemaIncompatible
                }
                (_, _, SemanticDimension::Incompatible) => {
                    CanonicalStoreWriteRefusal::TransactionNotViable
                }
                _ => CanonicalStoreWriteRefusal::SemanticUnobserved,
            },
        );
    }
    Ok(CanonicalStoreWriteReadiness {
        instance: handoff.clone(),
    })
}

/// Re-checks the qualified instance immediately before publishing write
/// readiness, and publishes it only when it is still the exact current one.
///
/// A changed instance invalidates the current qualification
/// ([`CanonicalStoreWriteRefusal::ObservationLost`]) without manufacturing a
/// process failure and without deleting the qualification that was already
/// earned.
pub fn publish_canonical_store_write_readiness(
    qualified: &CanonicalStoreWriteReadiness,
    current: &StoreBootstrapHandoff,
) -> Result<(), CanonicalStoreWriteRefusal> {
    if qualified.instance != *current {
        return Err(CanonicalStoreWriteRefusal::ObservationLost);
    }
    Ok(())
}
