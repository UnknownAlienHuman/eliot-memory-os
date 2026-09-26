//! One-call screen adapter over the frozen curation compatibility surface (#40).
//!
//! Current owners are `eliot-memory-curation-contracts` (A-19c vocabulary)
//! and `eliot-memory-curation-screen` (A-20 read-only screening). The adapter
//! below invokes exactly one owner exactly once, checks that the owner result
//! echoes the request identity, and returns the owner result unchanged. Owner
//! errors pass through untouched with no fallback.
//!
//! The legacy crate-root surface (`MemoryCurationOwner::preview` and its DTOs)
//! keeps byte-identical behavior and must not be extended; `admission` and
//! `candidate_admission` are frozen #1905 compatibility retained for the
//! kernel persist seam and its proof tests. New callers use the re-exported
//! neutral vocabulary plus the adapter. This facade owns no lifecycle,
//! action, writer-utility, or semantic-kind authority.
//!
//! ## Facade disposition table (exact; every public item has one row)
//!
//! Dispositions form a closed set: `LegacyFrozen`, `ReexportOwner`,
//! `AdapterEntry`, `FacadeSurface`.
//!
//! ## Bounded removal plan (#40 A4)
//!
//! 1. Legacy rows are frozen: no behavior change, no extension, no new callers.
//! 2. Delete the preview rows after the #929 inventory is regenerated and the
//!    A2 equivalence battery runs against the screen cell.
//! 3. Delete `admission`/`candidate_admission` after the #1905 kernel proof
//!    tests and `lifecycle_persist.rs` migrate to the neutral owners
//!    (`eliot-epistemic` receipts plus the kernel-local persist seam); the
//!    `lifecycle_persist.rs` import is the last live product edge.
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
        "LegacyFrozen",
        "DEPRECATED module; linkage moves to the kernel-local seam",
    ),
    (
        "AdmissionError",
        "LegacyFrozen",
        "DEPRECATED module; linkage moves to the kernel-local seam",
    ),
    (
        "CurationAdmission",
        "LegacyFrozen",
        "DEPRECATED module; receipts stay owned by eliot-epistemic",
    ),
    (
        "AdmissionChainView",
        "LegacyFrozen",
        "DEPRECATED module; linkage moves to the kernel-local seam",
    ),
    (
        "verify_admission_chain",
        "LegacyFrozen",
        "DEPRECATED module; receipt chain owner is eliot-epistemic",
    ),
    (
        "ObservationGenesisParams",
        "LegacyFrozen",
        "DEPRECATED module; drivers move with the #1905 tests",
    ),
    (
        "ForwardRevisionParams",
        "LegacyFrozen",
        "DEPRECATED module; drivers move with the #1905 tests",
    ),
    (
        "admit_observation_genesis",
        "LegacyFrozen",
        "DEPRECATED module; drivers move with the #1905 tests",
    ),
    (
        "admit_forward_revision",
        "LegacyFrozen",
        "DEPRECATED module; drivers move with the #1905 tests",
    ),
    (
        "bind_emitted_audit_events",
        "LegacyFrozen",
        "DEPRECATED module; drivers move with the #1905 tests",
    ),
    (
        "EmittedAuditLink",
        "LegacyFrozen",
        "DEPRECATED module; drivers move with the #1905 tests",
    ),
    (
        "StoreProjection",
        "LegacyFrozen",
        "DEPRECATED module; drivers move with the #1905 tests",
    ),
    (
        "project_for_store",
        "LegacyFrozen",
        "DEPRECATED module; drivers move with the #1905 tests",
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
