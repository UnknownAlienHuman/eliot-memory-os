//! Daemon-side retrieval/admission drive (Implements #1947).
//!
//! Thin composition wiring over the retrieval/admission owner crates: the
//! daemon validates one owner-supplied [`RetrievalPlan`], runs traced
//! admission ([`admit_context_traced`]) over one owner-supplied
//! [`AdmissionInput`], and projects a typed [`RetrievalDriveOutcome`] that
//! binds the plan digest, the decision anchor, the result digests, and the
//! per-material rank-trace handles with their staleness obligations. Every
//! candidate yields exactly one trace or the drive fails closed; nothing is
//! silently dropped.
//!
//! Authority boundaries (this module invents nothing):
//!
//! ```text
//! retrieval/admission owners hold: plan shape and validation, the admission
//!                 gate and selection, trace derivation and handles;
//! this module owns: supplier resolution against the daemon composition,
//!                 outcome projection for the daemon response, tick wiring.
//!                 No retained state, no ledger, no minted identities, no
//!                 planning or admission semantics.
//! ```
//!
//! Absent runtime suppliers (named exactly, never built here):
//!
//! ```text
//! - RetrievalPlan: no live plan compiler exists. Needed: a retrieval owner
//!   implementation compiling task/corpus/risk/freshness/coverage/latency
//!   into RetrievalPlan records.
//! - AdmissionInput: no live candidate/input assembler exists. Needed: the
//!   candidate mapper plus measurement/floor/priority owners assembling the
//!   complete closure.
//! ```
//!
//! Until those owners land, supplier resolution returns an explicit
//! [`RetrievalDriveOutcome::SuppliersPending`]; the drive idles with a typed
//! outcome and never fabricates inputs.

use eliot_context_admission::{
    MaterialRankTrace, RetrievalStaleness, admit_context_traced,
};
use eliot_context_contracts::{AdmissionDisposition, AdmissionInput, ContextError};
use eliot_contracts::{ArtifactId, DecisionId};
use eliot_reactive_context_plan::RetrievalPlan;
use serde::{Deserialize, Serialize};

use crate::DaemonComposition;

/// Owner-supplied retrieval bundle. Both members arrive fully formed from
/// their owners; the daemon validates and drives them but never builds them.
pub struct RetrievalSuppliers {
    /// Compiled retrieval plan from the retrieval owner.
    pub plan: RetrievalPlan,
    /// Complete admission closure from the candidate/measurement owners.
    pub input: AdmissionInput,
}

/// Supplier resolution against the daemon composition.
pub enum SupplierResolution {
    /// Both owners delivered; the drive may run. Boxed: the owner bundle is
    /// a large inline closure next to the unit-like pending arm.
    Ready(Box<RetrievalSuppliers>),
    /// Named absent suppliers; the drive idles with a typed outcome.
    Pending {
        /// No live retrieval-plan compiler exists yet.
        missing_plan: bool,
        /// No live admission-input assembler exists yet.
        missing_input: bool,
    },
}

/// Resolve the retrieval suppliers from the daemon composition.
///
/// Both suppliers are absent on the current composition: no plan compiler and
/// no input assembler exist yet. The pending outcome names exactly that, so
/// M1/M2 owner landings plug in here without changing the drive or the tick
/// wiring. Composition is taken (not omitted) so the port shape is already
/// the real one.
pub fn resolve_retrieval_suppliers(
    _composition: &DaemonComposition,
) -> SupplierResolution {
    SupplierResolution::Pending {
        missing_plan: true,
        missing_input: true,
    }
}

/// One staleness obligation routing a material to its exact trichotomy
/// outcome with its resolving trace handle attached.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetrievalObligation {
    /// Stable identity of the obligated material.
    pub atom_id: ArtifactId,
    /// Exact trichotomy outcome this material routes to.
    pub staleness: RetrievalStaleness,
    /// Handle resolving to the material trace carrying the full evidence.
    pub trace_handle: String,
}

/// Typed outcome of one retrieval/admission drive. Local only; the daemon
/// response projection and telemetry account every variant, so no outcome is
/// a silent drop.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", deny_unknown_fields)]
pub enum RetrievalDriveOutcome {
    /// Admission completed with per-material traces bound.
    Admitted {
        /// Canonical digest of the validated plan that drove retrieval.
        plan_digest: String,
        /// Decision anchor locating the materials in their compilation.
        decision_id: DecisionId,
        /// Canonical digest of the admission result envelope.
        result_digest: String,
        /// Canonical digest of the admitted selection.
        selection_digest: String,
        /// Materials admitted for direct or handle use.
        admitted: u32,
        /// Materials withheld with explicit reasons in their traces.
        suppressed: u32,
        /// Exactly one handle-bound trace per evaluated candidate.
        traces: Vec<MaterialRankTrace>,
        /// Staleness obligations for materials that must refresh or probe.
        obligations: Vec<RetrievalObligation>,
    },
    /// The closure was compiled under another fence: refresh the packet
    /// under the current fence instead of admitting across fences.
    RefreshRequired {
        /// Canonical digest of the validated plan, for correlation.
        plan_digest: String,
        /// Decision anchor of the refused closure.
        decision_id: DecisionId,
        /// Always [`RetrievalStaleness::PacketRefreshRequired`] from this
        /// path; carried so the obligation survives projection.
        staleness: RetrievalStaleness,
    },
    /// Fail-closed refusal with the refusing stage named.
    Rejected {
        /// `"plan"` when plan validation refused, `"admission"` when the
        /// admission boundary refused.
        stage: String,
        /// Owner error text; identities only, never payload.
        detail: String,
    },
    /// Named absent suppliers; the drive idled without fabricating inputs.
    SuppliersPending {
        /// No live retrieval-plan compiler exists yet.
        missing_plan: bool,
        /// No live admission-input assembler exists yet.
        missing_input: bool,
    },
}

impl RetrievalDriveOutcome {
    /// Stable outcome family name for daemon telemetry accounting.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::Admitted { .. } => "admitted",
            Self::RefreshRequired { .. } => "refresh_required",
            Self::Rejected { .. } => "rejected",
            Self::SuppliersPending { .. } => "suppliers_pending",
        }
    }
}

/// Drive one retrieval plan with traced admission and bound the outcome.
///
/// Validates the plan, runs [`admit_context_traced`] over the supplied
/// input, and binds the plan digest, decision anchor, result digests, and
/// per-material trace handles with their staleness obligations into one
/// typed outcome. A fence-disagreeing closure routes to the refresh path
/// ([`RetrievalStaleness::PacketRefreshRequired`]); any other boundary
/// refusal is named by stage. Pure over its inputs: no I/O, no retention.
pub fn drive_retrieval_admission(
    plan: &RetrievalPlan,
    input: &AdmissionInput,
) -> RetrievalDriveOutcome {
    let plan_digest = match plan.canonical_digest() {
        Ok(digest) => digest,
        Err(error) => {
            return RetrievalDriveOutcome::Rejected {
                stage: "plan".to_owned(),
                detail: error.to_string(),
            };
        }
    };
    let decision_id = input.binding.decision_id.clone();
    match admit_context_traced(input) {
        Err(ContextError::InvalidFence) => RetrievalDriveOutcome::RefreshRequired {
            plan_digest,
            decision_id,
            staleness: RetrievalStaleness::PacketRefreshRequired,
        },
        Err(error) => RetrievalDriveOutcome::Rejected {
            stage: "admission".to_owned(),
            detail: error.to_string(),
        },
        Ok((result, traces)) => {
            let mut admitted: u32 = 0;
            let mut suppressed: u32 = 0;
            let mut obligations = Vec::new();
            for trace in &traces {
                match trace.disposition {
                    AdmissionDisposition::Include | AdmissionDisposition::HandleOnly => {
                        admitted = admitted.saturating_add(1);
                    }
                    _ => {
                        suppressed = suppressed.saturating_add(1);
                    }
                }
                if let Some(staleness) = trace.staleness {
                    obligations.push(RetrievalObligation {
                        atom_id: trace.atom_id.clone(),
                        staleness,
                        trace_handle: trace.trace_handle.clone(),
                    });
                }
            }
            RetrievalDriveOutcome::Admitted {
                plan_digest,
                decision_id,
                result_digest: result.result_digest.clone(),
                selection_digest: result.selection_digest.clone(),
                admitted,
                suppressed,
                traces,
                obligations,
            }
        }
    }
}

/// Poll one retrieval drive from the daemon composition for this tick.
///
/// Resolves the owner suppliers and either idles with an explicit
/// [`RetrievalDriveOutcome::SuppliersPending`] or drives the resolved bundle
/// through [`drive_retrieval_admission`]. Synchronous and bounded; the caller
/// accounts the returned outcome (see [`RetrievalDriveOutcome::kind`]).
pub fn poll_retrieval_drive(composition: &DaemonComposition) -> RetrievalDriveOutcome {
    let _span = tracing::info_span!("eliotd.retrieval_drive").entered();
    match resolve_retrieval_suppliers(composition) {
        SupplierResolution::Pending {
            missing_plan,
            missing_input,
        } => RetrievalDriveOutcome::SuppliersPending {
            missing_plan,
            missing_input,
        },
        SupplierResolution::Ready(suppliers) => {
            drive_retrieval_admission(&suppliers.plan, &suppliers.input)
        }
    }
}
