//! Canonical-store write status projection (I1.9, issue #1887).
//!
//! Architecture: A13.2 Kernel and failure domains, A12.3 one governed write
//! path; Implementation I1.9 three registries/three owners.
//!
//! I1.9 requires that neither observation can substitute for the other:
//! process liveness comes from the Host-managed process observation and
//! semantic readiness comes independently from the store bridge's
//! version/schema/transaction probes. This module is the consumer projection
//! over those two already-evaluated halves: the Host half arrives as the
//! `ManagedDependencyRecord` readiness decision from `eliot-host-state` and
//! the bridge half arrives as the bridge's own typed
//! per-dimension result. It starts no process, runs no probe, and holds no
//! authority of its own.
//!
//! Host failures and the bridge's typed semantic causes are kept side by side
//! rather than collapsed into a first-failure-only health state, so a
//! front-door or recovery status names the dimension that actually failed:
//! a live process with an incompatible schema, a responsive bridge answered
//! without valid lineage, and an unobserved dimension are different results,
//! not one "store healthy" boolean.

use eliot_contracts::EpochTransition;
use eliot_host_state::{CanonicalStoreWriteRefusal, HostState, ImmutableProcessManifest};
use eliot_platform::PlatformHandle;
use eliot_store_api::{SemanticDimension, StoreSemanticReadiness};

/// Front-door/recovery status for canonical-store write readiness.
///
/// `Ready` opens normal canonical writes only for the exact current two-owner
/// join the caller evaluated: valid Host-managed lineage/liveness plus the
/// bridge's version, schema and transaction probes. Every other case names
/// its failing dimension through [`CanonicalStoreWriteStatusRefusal`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CanonicalStoreWriteStatus {
    /// Both evidence categories hold for the current join.
    Ready,
    /// Normal canonical writes stay closed for the named reason.
    Refused(CanonicalStoreWriteStatusRefusal),
}

/// Why canonical-store writes stay closed, with the failing dimension named.
///
/// Host failures keep their exact [`CanonicalStoreWriteRefusal`] instead of
/// being reduced to one health bit, and the bridge's version, schema and
/// transaction causes keep their own arms alongside them. When both halves
/// fail together neither is chosen as the entire health state: the
/// [`CanonicalStoreWriteStatusRefusal::HostAndSemantic`] arm carries both.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CanonicalStoreWriteStatusRefusal {
    /// The Host-managed process half refused while the bridge half passed:
    /// installation/launch lineage, process approval, Job Object/PID lineage
    /// or observed liveness. Restart budget and semantic verdicts never refuse
    /// writes through this arm: restart exhaustion is decided by
    /// [`ManagedDependencyRecord::restart_permitted`](eliot_host_state::ManagedDependencyRecord::restart_permitted),
    /// and bridge dimensions have their own arms below.
    Host(CanonicalStoreWriteRefusal),
    /// The bridge's version-compatibility probe did not pass. The process may
    /// be live; normal canonical writes stay closed anyway.
    VersionIncompatible,
    /// The bridge's schema-compatibility probe did not pass. The process may
    /// be live; normal canonical writes stay closed anyway.
    SchemaIncompatible,
    /// The bridge's transaction-execution-viability probe did not pass.
    TransactionNotViable,
    /// No bridge dimension failed, but the bridge result is not fully
    /// observed, so the current join cannot open normal writes.
    SemanticUnobserved,
    /// Both halves failed together. The Host refusal and the bridge's current
    /// typed [`StoreSemanticReadiness`] receipt are kept side by side so the
    /// front-door/recovery status names each failing dimension instead of
    /// reporting only the first failure.
    HostAndSemantic {
        /// Host-side refusal, kept alongside the bridge receipt.
        host: CanonicalStoreWriteRefusal,
        /// Bridge-side typed semantic readiness receipt.
        semantic: StoreSemanticReadiness,
    },
}

/// Projects the front-door/recovery status from the two evaluated halves.
///
/// `host` is the Host-managed record's readiness decision for the single
/// required admitted-store instance, evaluated with no semantic input: no
/// boolean crosses the Host/bridge boundary in either direction. `semantic`
/// is the bridge's current typed version/schema/transaction result for that
/// same instance. A Host refusal with a passing bridge is reported unchanged;
/// a passing Host half with a failing bridge resolves the exact failing
/// dimension in version/schema/transaction probe order; when both halves fail
/// the result keeps both alongside in
/// [`CanonicalStoreWriteStatusRefusal::HostAndSemantic`] rather than choosing
/// only the first failure. A refused join whose bridge result names no failed
/// dimension is reported as unobserved rather than ready.
#[must_use]
pub fn project_canonical_store_write_status(
    host: Result<(), CanonicalStoreWriteRefusal>,
    semantic: &StoreSemanticReadiness,
) -> CanonicalStoreWriteStatus {
    let bridge_ready = semantic.is_ready();
    match (host, bridge_ready) {
        (Ok(()), true) => CanonicalStoreWriteStatus::Ready,
        (Err(refusal), true) => {
            CanonicalStoreWriteStatus::Refused(CanonicalStoreWriteStatusRefusal::Host(refusal))
        }
        (Ok(()), false) => CanonicalStoreWriteStatus::Refused(resolve_semantic_refusal(*semantic)),
        (Err(refusal), false) => {
            CanonicalStoreWriteStatus::Refused(CanonicalStoreWriteStatusRefusal::HostAndSemantic {
                host: refusal,
                semantic: *semantic,
            })
        }
    }
}

/// Resolves the exact failing bridge dimension in version/schema/transaction
/// probe order. A result that is not ready but names no failed dimension is
/// unobserved, never ready.
fn resolve_semantic_refusal(semantic: StoreSemanticReadiness) -> CanonicalStoreWriteStatusRefusal {
    match (semantic.version, semantic.schema, semantic.transaction) {
        (SemanticDimension::Incompatible, _, _) => {
            CanonicalStoreWriteStatusRefusal::VersionIncompatible
        }
        (_, SemanticDimension::Incompatible, _) => {
            CanonicalStoreWriteStatusRefusal::SchemaIncompatible
        }
        (_, _, SemanticDimension::Incompatible) => {
            CanonicalStoreWriteStatusRefusal::TransactionNotViable
        }
        _ => CanonicalStoreWriteStatusRefusal::SemanticUnobserved,
    }
}

/// Front-door/recovery write-admission join over the journal and the bridge
/// receipt (issue #1887 audit repair: the final join lives here, in the
/// Kernel/store-readiness consumer).
///
/// One required admitted-store instance identity — installation, launch
/// manifest, process generation, approved artifact/config hashes and Job
/// Object/PID lineage — feeds both halves, so matching two healthy booleans
/// can never qualify a mismatched pair: a valid probe from predecessor A
/// cannot qualify replacement B because B's descriptor fails the Host half
/// (installation, generation, lineage and liveness are rechecked against B's
/// own carried observation) unless B itself was observed, and the typed
/// receipt is consumed only as the current receipt for that same instance.
/// The Host half is re-read from the caller's current [`HostState`] journal
/// view through [`HostState::managed_dependency`] on every call and evaluated
/// with [`ManagedDependencyRecord::canonical_store_write_readiness`](eliot_host_state::ManagedDependencyRecord::canonical_store_write_readiness),
/// then projected with the bridge's current typed [`StoreSemanticReadiness`].
/// No boolean crosses the Host/bridge boundary in either direction.
///
/// Receipt provenance — the bridge session the receipt was observed on and the
/// fence it was observed under — is owned by the bridge receipt producer
/// (W-bridge follow-up in the bridge files, which this writer must not touch):
/// the journal stores no bridge-session or probe-fence counterpart
/// (`ServiceProcessRecord` carries process lineage, owner, state, health and
/// start authority epoch only), so this consumer binds every half the journal
/// stores and requires the caller to present the current receipt observed on
/// the same admitted instance. It manufactures no provenance it was not given.
///
/// Exit states stay distinct: alive with a bad schema is
/// [`CanonicalStoreWriteStatusRefusal::SchemaIncompatible`]; a valid probe
/// with a foreign process is `Host` lineage refusal; a lost observation is
/// `Host(ObservationUnknown)` — or `HostAndSemantic` with the bridge receipt
/// when the bridge half also fails — never a manufactured process failure and
/// with no receipt deleted; a healthy running process with no future restart
/// budget is [`CanonicalStoreWriteStatus::Ready`] while another restart stays
/// forbidden through [`ManagedDependencyRecord::restart_permitted`](eliot_host_state::ManagedDependencyRecord::restart_permitted);
/// only the exact current two-owner join is `Ready`, and only `Ready` opens
/// normal writes.
///
/// A responsive bridge with no Host-managed record for `dependency` is refused
/// as [`CanonicalStoreWriteRefusal::MissingPidJobLineage`], never accepted.
///
/// This entry starts no process, runs no probe, holds no authority and deletes
/// no receipt. The caller supplies the authenticated journal view and the
/// bridge receipt for the same current observation.
///
/// Caller: STITCH — the front-door/recovery owners call this instead of
/// reading [`StoreHealth`](eliot_store_api::StoreHealth): the Kernel
/// recovery/status projections in `bins/eliot-kernel/src/health_view.rs` and
/// `bins/eliot-kernel/src/kernel_unavailability.rs` (`RecoveryView`,
/// `admit_canonical_write`; running #1972 writer) and the Kernel front-door
/// write gate in `store_gateway.rs`. The bridge's current typed receipt is
/// produced by the W-bridge owner (bridge files). This crate does not call
/// into `bins/`.
#[allow(clippy::too_many_arguments)]
#[must_use]
pub fn project_canonical_store_write_status_from_journal(
    journal: &HostState,
    dependency: &PlatformHandle,
    required_installation: &PlatformHandle,
    required_process_manifest: &ImmutableProcessManifest,
    required_process_generation: &EpochTransition,
    required_artifact_hash: &PlatformHandle,
    required_config_hash: &PlatformHandle,
    required_pid_job_lineage_refs: &[PlatformHandle],
    semantic: &StoreSemanticReadiness,
) -> CanonicalStoreWriteStatus {
    let host = match journal.managed_dependency(dependency) {
        Some(record) => record.canonical_store_write_readiness(
            required_installation,
            required_process_manifest,
            required_process_generation,
            required_artifact_hash,
            required_config_hash,
            required_pid_job_lineage_refs,
        ),
        None => Err(CanonicalStoreWriteRefusal::MissingPidJobLineage),
    };
    project_canonical_store_write_status(host, semantic)
}
