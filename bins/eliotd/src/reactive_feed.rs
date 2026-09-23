//! O1-owned daemon retrieval drive: supplier bundle → plan validation →
//! revision check → traced admission, once per bundle (issues #1942/#1947).
//!
//! Owner wiring: the retrieval-plan compiler owns plan shapes
//! (`eliot-reactive-context-plan` compiler), the closure assembler owns
//! input closures (`eliot-context-admission` closure), and the admission
//! owner owns selection plus traces (`admit_context_traced_with_warnings`).
//! This drive owns only the invocation sequencing between them: it builds
//! nothing admission-side and mints no identities, routes, revisions, or
//! warnings. Every load-bearing value arrives as a typed owner artifact
//! (plan, input, owner-minted warnings) and every agreement is checked by
//! the owning comparator before firing.
//!
//! Call order with live checks before authoritative use (join contract v3,
//! `eliot-context-admission/src/lib.rs::admit_context_traced` docs):
//!
//! 1. Suppliers resolve from their owners only. Absent suppliers idle with
//!    an exact missing-owner [`Pending`](RetrievalDriveOutcome::Pending)
//!    outcome — never fabricated at the call site, never defaulted into a
//!    final delivery.
//! 2. The plan re-validates through its canonical digest, then the
//!    plan-against-input revision comparison (`check_plan_revisions`) runs
//!    before firing: every fence-matching candidate source needs a plan
//!    expectation carrying the actual revision, or the drive probes
//!    (optional) or stales (floor) instead of admitting. A refused plan or
//!    an unresolvable closure never reaches selection.
//! 3. Exactly one admission runs per supplied bundle and the returned pair
//!    binds verbatim (result digest, selection digest, every trace with its
//!    decision anchor and handle). Warnings join as derived
//!    (`derive_input_warnings`: candidate-owned epistemic qualifications)
//!    plus supplied (owner-minted, opaque); atom collisions fail closed as
//!    `Duplicate` inside the trace join rather than merging silently.
//! 4. `ContextError::InvalidFence` maps to the packet-refresh arm
//!    ([`RefreshRequired`](RetrievalDriveOutcome::RefreshRequired)); every
//!    other boundary refusal keeps its refusing stage in
//!    [`Failed`](RetrievalDriveOutcome::Failed), never coerced into an
//!    admission outcome.
//! 5. Staleness, capacity pressure, suppression, and warning text are read
//!    only from the trace fields; none reclassifies the outcome, which the
//!    classifier alone determines. Governor risk tiers never authorise
//!    warnings: risk evidence stays factual and separate (M1-owned
//!    `AtomRiskBinding`), warning text comes only from candidate-owned
//!    epistemic derivation or owner-minted records.
//!
//! True-revision threading: the plan's `source_projection_fences[]`
//! `expected_revision` slots carry the retrieval owner's true observed
//! revisions (opaque source-owner namespace — never task counters, never
//! rendered numerics; see the no-equivalence rule on
//! `check_plan_revisions`). The drive threads those actual values through
//! validation and comparison unmodified: a `None` entry carries no revision
//! opinion (the strict comparison then probes/stales instead of admitting),
//! and unknown revisions are never defaulted into a final delivery.
//!
//! Unknown/replay/cancellation preservation: the drive mutates nothing
//! itself; repeated calls over one unchanged bundle re-evaluate
//! deterministically (admission is pure); cancellation paths are untouched;
//! unknown outcomes keep their identities in `Failed` without collapse into
//! pending. Execution-plane failures must never fail the activation loop
//! that hosts this drive.

use eliot_context_admission::{
    MaterialRankTrace, RetrievalStaleness, SuppliedWarning, admit_context_traced_with_warnings,
    check_plan_revisions, derive_input_warnings,
};
use eliot_context_contracts::{AdmissionInput, ContextError};
use eliot_reactive_context_plan::RetrievalPlan;

use crate::attempt_execution_chain::MissingOwner;

/// Outcome of one retrieval drive evaluation: admitted with a bound
/// attestation pair, pended with the exact missing suppliers, refreshed on
/// fence movement, or failed with identities preserved. Debug-only: the
/// `Failed` payload carries owner errors without clone/equality semantics.
#[derive(Debug)]
pub enum RetrievalDriveOutcome {
    /// The bundle admitted with verbatim-bound digests and traces, cleared
    /// for authoritative use downstream.
    Admitted {
        /// Canonical digest of the admitted result.
        result_digest: String,
        /// Canonical digest of the admitted selection.
        selection_digest: String,
        /// One handle-bound trace per evaluated candidate.
        traces: Vec<MaterialRankTrace>,
    },
    /// No admission: the exact suppliers absent at evaluation time, in
    /// deterministic supplier order. Normal idle, never an error.
    Pending {
        /// Missing-supplier inventory.
        missing: Vec<MissingOwner>,
    },
    /// The closure was compiled under another fence: reopen the packet
    /// under the current fence instead of admitting across fences.
    RefreshRequired,
    /// A plan, revision, or admission refusal with identities preserved,
    /// never collapsed into pending. Never fails the activation loop that
    /// hosts this drive.
    Failed(RetrievalDriveError),
}

/// Fail-closed retrieval-drive errors. Each preserves the exact refusing
/// stage; staleness and probe obligations are named, never inferred.
#[derive(Debug)]
pub enum RetrievalDriveError {
    /// The plan failed its canonical digest validation.
    PlanDigest(ContextError),
    /// A mandatory (floor) candidate source has no resolvable revision
    /// expectation: the projection cannot satisfy the Safety Floor.
    StaleProjection,
    /// An optional candidate source has no resolvable revision expectation:
    /// a targeted revalidation probe for that atom is required first (probe
    /// mechanism pending with the projection owners).
    ProbeRequired,
    /// A non-fence admission boundary refusal, stage-named by the owner.
    Admission(ContextError),
}

/// Drive one retrieval evaluation over an explicit supplier bundle.
///
/// Evaluated in the daemon binary flow (see the run-loop dispatch arm):
/// absent plan/input suppliers idle as [`Pending`](RetrievalDriveOutcome::Pending)
/// with the exact missing owners; otherwise the plan digest validates, the
/// revision comparison runs, derived plus supplied warnings join, and one
/// traced admission fires with the pair bound verbatim. Deterministic and
/// side-effect free; one call corresponds to one supplied bundle.
pub fn drive_retrieval_once(
    plan: Option<&RetrievalPlan>,
    input: Option<&AdmissionInput>,
    warnings: &[SuppliedWarning],
) -> RetrievalDriveOutcome {
    let _span = tracing::info_span!("eliotd.retrieval_drive_poll").entered();
    let Some(plan) = plan else {
        return RetrievalDriveOutcome::Pending {
            missing: vec![MissingOwner {
                owner: "retrieval-plan compiler",
                artifact: "RetrievalPlan",
                absent_read: "no compiled retrieval plan retained; PlanParts factors are M1/M2-coordinated planning-owner inputs, compiler eliot-reactive-context-plan/src/compiler.rs",
            }],
        };
    };
    let Some(input) = input else {
        return RetrievalDriveOutcome::Pending {
            missing: vec![MissingOwner {
                owner: "admission closure assembler",
                artifact: "AdmissionInput",
                absent_read: "no assembled admission closure retained; ClosureParts selected by M1/M2-coordinated owners, assembler eliot-context-admission/src/closure.rs",
            }],
        };
    };
    if let Err(error) = plan.canonical_digest() {
        return RetrievalDriveOutcome::Failed(RetrievalDriveError::PlanDigest(error));
    }
    match check_plan_revisions(plan, input) {
        Ok(()) => {}
        Err(RetrievalStaleness::StaleProjection) => {
            return RetrievalDriveOutcome::Failed(RetrievalDriveError::StaleProjection);
        }
        Err(RetrievalStaleness::ProbeRequired) => {
            return RetrievalDriveOutcome::Failed(RetrievalDriveError::ProbeRequired);
        }
        Err(RetrievalStaleness::PacketRefreshRequired) => {
            return RetrievalDriveOutcome::RefreshRequired;
        }
    }
    // Warning join: derived (candidate-owned epistemic qualifications,
    // canonical wire spellings) plus supplied (owner-minted, fully opaque).
    // Both channels are legitimate evidence; an atom warned twice is a
    // genuine conflict and fails closed as Duplicate inside the trace join
    // rather than merging or dropping either text. Sorted for a
    // deterministic bundle order.
    let mut joined = derive_input_warnings(input);
    joined.extend(warnings.iter().cloned());
    joined.sort_by(|left, right| left.atom_id.cmp(&right.atom_id));
    match admit_context_traced_with_warnings(input, &joined) {
        Ok((result, traces)) => {
            tracing::info!(
                traces = traces.len(),
                "retrieval drive admitted with bound traces"
            );
            RetrievalDriveOutcome::Admitted {
                result_digest: result.result_digest.clone(),
                selection_digest: result.selection_digest.clone(),
                traces,
            }
        }
        Err(ContextError::InvalidFence) => RetrievalDriveOutcome::RefreshRequired,
        Err(error) => RetrievalDriveOutcome::Failed(RetrievalDriveError::Admission(error)),
    }
}
