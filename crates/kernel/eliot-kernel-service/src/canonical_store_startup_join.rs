//! Canonical-store startup join (I1.9, I1.11 step 5, issue #1887 W-startup).
//!
//! Architecture: I1.9 three registries/three owners; Implementation I1.11
//! startup algorithm step 5 ("When canonical access is required, Kernel
//! requests Host to start/reuse the canonical-store Job Object, then
//! starts/reconnects the store bridge and waits for independent
//! readiness/schema probes").
//!
//! The startup path must wait for both evidence categories before enabling
//! canonical writes: Host/Watchdog process liveness from the Host-owned
//! [`ManagedDependencyRecord`], and semantic readiness from the store
//! bridge's independent version/schema/transaction probes
//! ([`StoreSemanticReadiness`]). Neither observation substitutes for the
//! other. This module evaluates that exact current two-owner join for one
//! required canonical-store lineage and projects the typed
//! [`CanonicalStoreWriteStatus`]; any refusal keeps normal canonical writes
//! closed through the existing `StoreSchemaProbe` startup gate.
//!
//! It starts no process, runs no probe, and holds no authority of its own:
//! the Host record half arrives from the Host-owned journal delivery and the
//! bridge receipt half arrives from the bridge's own probes, each evaluated
//! by its owner before this join reads them. Both halves are bound to the
//! same required lineage in this one call, so a healthy probe for a
//! predecessor process can never qualify its replacement.

use eliot_contracts::EpochTransition;
use eliot_host_state::{ImmutableProcessManifest, ManagedDependencyRecord};
use eliot_platform::PlatformHandle;
use eliot_store_api::StoreSemanticReadiness;

use crate::store_write_status::{CanonicalStoreWriteStatus, project_canonical_store_write_status};

/// Evaluates the I1.11 step 5 startup join for one required canonical-store
/// lineage.
///
/// `record` is the current Host-managed dependency observation for the
/// admitted store process; `semantic` is the store bridge's current typed
/// version/schema/transaction receipt for that same observation. The
/// required manifest, process generation, artifact/config hashes and Job
/// Object/PID lineage refs name the exact admitted lineage both halves must
/// describe. The Host half is decided with the bridge receipt's own combined
/// verdict (`semantic.is_ready()`), and the outcome is projected through
/// [`project_canonical_store_write_status`] so a semantic refusal resolves
/// to the exact bridge dimension that failed.
///
/// A `Ready` result is the only outcome that may record the I1.11 step 5
/// probe; every refusal leaves canonical writes closed.
#[must_use]
pub fn join_canonical_store_startup_readiness(
    record: &ManagedDependencyRecord,
    required_process_manifest: &ImmutableProcessManifest,
    required_process_generation: &EpochTransition,
    required_artifact_hash: &PlatformHandle,
    required_config_hash: &PlatformHandle,
    required_pid_job_lineage_refs: &[PlatformHandle],
    semantic: &StoreSemanticReadiness,
) -> CanonicalStoreWriteStatus {
    let host = record.canonical_store_write_readiness(
        required_process_manifest,
        required_process_generation,
        required_artifact_hash,
        required_config_hash,
        required_pid_job_lineage_refs,
        semantic.is_ready(),
    );
    project_canonical_store_write_status(host, semantic)
}
