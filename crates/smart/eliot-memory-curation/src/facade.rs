//! One-call screen adapter over the frozen curation compatibility surface (#40).
//!
//! Current owners are `eliot-memory-curation-contracts` (A-19c vocabulary)
//! and `eliot-memory-curation-screen` (A-20 read-only screening). The adapter
//! below invokes exactly one owner exactly once, checks that the owner result
//! echoes the request identity, and returns the owner result unchanged. Owner
//! errors pass through untouched with no fallback.
//!
//! The legacy crate-root surface (`MemoryCurationOwner::preview` and its DTOs)
//! keeps byte-identical behavior and must not be extended. New callers use the
//! re-exported neutral vocabulary plus the adapter. This crate owns no
//! lifecycle, action, writer-utility, or semantic-kind authority.
//!
//! ## Facade disposition table (exact; every public item has one row)
//!
//! Dispositions form a closed set: `LegacyFrozen`, `ReexportOwner`,
//! `AdapterEntry`, `FacadeSurface`, `MigratedOwner`.
//!
//! ## Bounded removal plan (#40 A4)
//!
//! 1. Legacy rows are frozen: no behavior change, no extension, no new callers.
//! 2. Delete the preview rows after the #929 inventory is regenerated and the
//!    A2 equivalence battery runs against the screen cell.
//! 3. The lifecycle/action admission rows are already migrated (#40 W5): the
//!    vocabulary and its rules moved to the Kernel-local owner
//!    `eliot-kernel-service::lifecycle_admission`, and the Kernel
//!    `lifecycle_persist` seam plus its #1905 proof tests consume that owner
//!    directly. The donor no longer ships an `admission` or
//!    `candidate_admission` module at all.
//! 4. Delete this crate after every consumer migrates, per issue #40 A4.

use thiserror::Error;

/// Closed refusal vocabulary for the facade.
///
/// Owner failures pass through untouched (transparent variant); the only
/// facade-side refusal names the exact failed identity check.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum FacadeError {
    /// An owner response does not echo the request identity.
    #[error("owner response identity check failed at {what}")]
    ResponseIdentityMismatch {
        /// Stable check name, never caller payload.
        what: &'static str,
    },
    /// The A-20 screen cell rejected the input or result.
    #[error(transparent)]
    Screen(#[from] eliot_memory_curation_screen::CurationScreenError),
}

/// Every public facade item with its exact disposition.
///
/// `(item, disposition, owner-or-replacement)`. Legacy rows are frozen
/// compatibility material with the removal plan from the module docs;
/// re-export rows resolve by type identity to the current owner.
pub const FACADE_DISPOSITIONS: [(&str, &str, &str); 38] = [
    ("CONTRACT_NAME", "LegacyFrozen", "frozen wire name"),
    ("CONTRACT_VERSION", "LegacyFrozen", "frozen wire revision"),
    ("RULESET_VERSION", "LegacyFrozen", "frozen ruleset pin"),
    ("MAX_SCAN_RECORDS", "LegacyFrozen", "frozen scan bound"),
    ("MAX_PAGE_SIZE", "LegacyFrozen", "frozen page bound"),
    (
        "MAX_REFERENCE_COUNT",
        "LegacyFrozen",
        "frozen reference bound",
    ),
    (
        "CurationError",
        "LegacyFrozen",
        "frozen vocabulary; screen owner errors are Contract/Screen",
    ),
    (
        "CurationRecord",
        "LegacyFrozen",
        "frozen DTO; owner is contracts SourceSnapshot members",
    ),
    (
        "LifecycleState",
        "LegacyFrozen",
        "frozen DTO; lifecycle vocabulary lives with its owners",
    ),
    (
        "CurationMetadata",
        "LegacyFrozen",
        "frozen DTO; owner is contracts ProtectionEvidence",
    ),
    (
        "ProtectionRole",
        "LegacyFrozen",
        "frozen DTO; owner is contracts protection vocabulary",
    ),
    (
        "FindingKind",
        "LegacyFrozen",
        "frozen DTO; owner is contracts FindingClass",
    ),
    (
        "ReversibleAction",
        "LegacyFrozen",
        "frozen DTO; no action authority is retained here",
    ),
    (
        "CurationCandidate",
        "LegacyFrozen",
        "frozen DTO; owner is contracts CurationFinding",
    ),
    (
        "CorpusProfile",
        "LegacyFrozen",
        "frozen DTO; owner is contracts ScreenCoverage",
    ),
    (
        "CurationPreview",
        "LegacyFrozen",
        "frozen DTO; owner is contracts CurationScreenResult",
    ),
    (
        "PreviewRequest",
        "LegacyFrozen",
        "frozen DTO; owner is contracts CurationScreenRequest",
    ),
    (
        "MemoryCurationOwner",
        "LegacyFrozen",
        "DEPRECATED; screening owner is eliot-memory-curation-screen",
    ),
    (
        "CurationMutationOperation",
        "MigratedOwner",
        "eliot-kernel-service::lifecycle_admission::LifecycleMutationOperation (#40 W5)",
    ),
    (
        "AdmissionError",
        "MigratedOwner",
        "eliot-kernel-service::lifecycle_admission::LifecycleAdmissionError (#40 W5)",
    ),
    (
        "CurationAdmission",
        "MigratedOwner",
        "eliot-kernel-service::lifecycle_admission::LifecycleAdmission (#40 W5)",
    ),
    (
        "AdmissionChainView",
        "MigratedOwner",
        "eliot-kernel-service::lifecycle_admission::LifecycleAdmissionChainView (#40 W5)",
    ),
    (
        "verify_admission_chain",
        "MigratedOwner",
        "eliot-kernel-service::lifecycle_admission::verify_lifecycle_admission_chain (#40 W5)",
    ),
    (
        "ObservationGenesisParams",
        "MigratedOwner",
        "eliot-kernel-service::lifecycle_admission::ObservationGenesisParams (#40 W5)",
    ),
    (
        "ForwardRevisionParams",
        "MigratedOwner",
        "eliot-kernel-service::lifecycle_admission::ForwardRevisionParams (#40 W5)",
    ),
    (
        "admit_observation_genesis",
        "MigratedOwner",
        "eliot-kernel-service::lifecycle_admission::admit_observation_genesis (#40 W5)",
    ),
    (
        "admit_forward_revision",
        "MigratedOwner",
        "eliot-kernel-service::lifecycle_admission::admit_forward_revision (#40 W5)",
    ),
    (
        "bind_emitted_audit_events",
        "MigratedOwner",
        "eliot-kernel-service::lifecycle_admission::bind_emitted_audit_events (#40 W5)",
    ),
    (
        "EmittedAuditLink",
        "MigratedOwner",
        "eliot-kernel-service::lifecycle_admission::EmittedAuditLink (#40 W5)",
    ),
    (
        "StoreProjection",
        "MigratedOwner",
        "eliot-kernel-service::lifecycle_admission::StoreProjection (#40 W5)",
    ),
    (
        "project_for_store",
        "MigratedOwner",
        "eliot-kernel-service::lifecycle_admission::project_for_store (#40 W5)",
    ),
    (
        "CurationScreenRequest",
        "ReexportOwner",
        "eliot-memory-curation-contracts",
    ),
    (
        "CurationScreenResult",
        "ReexportOwner",
        "eliot-memory-curation-contracts",
    ),
    (
        "SourceSnapshot",
        "ReexportOwner",
        "eliot-memory-curation-contracts",
    ),
    (
        "ProtectionEvidence",
        "ReexportOwner",
        "eliot-memory-curation-contracts",
    ),
    ("adapt_screen", "AdapterEntry", "one A-20 call"),
    ("FacadeError", "FacadeSurface", "closed refusal vocabulary"),
    (
        "FACADE_DISPOSITIONS",
        "FacadeSurface",
        "this table, machine-counted",
    ),
];

/// Runs one bounded, read-only screen through A-20 exactly once.
///
/// The caller supplies the complete owner-typed request, source snapshot, and
/// protection evidence; the facade invents no record, evidence, or finding.
/// The returned result must echo the exact request and source before it is
/// handed back unchanged.
///
/// # Errors
///
/// Returns [`FacadeError::Screen`] when the owner rejects the screen, and
/// [`FacadeError::ResponseIdentityMismatch`] when the echoed request or source
/// differs from the supplied one.
pub fn adapt_screen(
    request: &eliot_memory_curation_contracts::CurationScreenRequest,
    source: &eliot_memory_curation_contracts::SourceSnapshot,
    evidence: &[eliot_memory_curation_contracts::ProtectionEvidence],
) -> Result<eliot_memory_curation_contracts::CurationScreenResult, FacadeError> {
    let result = eliot_memory_curation_screen::screen_memory_curation(request, source, evidence)?;
    if result.request != *request || result.source != *source {
        return Err(FacadeError::ResponseIdentityMismatch {
            what: "screen.request/source",
        });
    }
    Ok(result)
}
