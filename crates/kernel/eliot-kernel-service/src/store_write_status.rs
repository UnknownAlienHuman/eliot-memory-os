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

use eliot_host_state::CanonicalStoreWriteRefusal;
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
/// transaction causes keep their own arms alongside them.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CanonicalStoreWriteStatusRefusal {
    /// The Host-managed process half refused: launch lineage, process
    /// approval, Job Object/PID lineage, observed liveness, restart budget,
    /// or the semantic verdict the Host decision was given.
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
}

/// Projects the front-door/recovery status from the two evaluated halves.
///
/// `host` is the Host-managed record's readiness decision for the required
/// lineage, evaluated with `semantic.is_ready()` as its semantic verdict.
/// `semantic` is the bridge's current typed version/schema/transaction
/// result for that same observation. A Host refusal on non-semantic grounds
/// is reported unchanged; a semantic refusal is resolved into the exact
/// bridge dimension that failed, in version/schema/transaction probe order.
/// A refused join whose bridge result names no failed dimension is reported
/// as unobserved rather than ready.
#[must_use]
pub fn project_canonical_store_write_status(
    host: Result<(), CanonicalStoreWriteRefusal>,
    semantic: &StoreSemanticReadiness,
) -> CanonicalStoreWriteStatus {
    if let Err(refusal) = host {
        if !matches!(refusal, CanonicalStoreWriteRefusal::SemanticallyNotReady) {
            return CanonicalStoreWriteStatus::Refused(
                CanonicalStoreWriteStatusRefusal::Host(refusal),
            );
        }
    } else if semantic.is_ready() {
        return CanonicalStoreWriteStatus::Ready;
    }
    CanonicalStoreWriteStatus::Refused(match (
        semantic.version,
        semantic.schema,
        semantic.transaction,
    ) {
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
    })
}
