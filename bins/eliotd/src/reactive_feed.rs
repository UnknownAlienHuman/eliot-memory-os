//! Daemon-side retrieval/admission drive (Implements #1947).
//!
//! Thin composition wiring over the retrieval/admission owner crates: the
//! daemon validates one owner-supplied [`RetrievalPlan`], runs traced
//! admission ([`admit_context_traced`]) over one owner-supplied
//! [`AdmissionInput`], and projects a typed [`RetrievalDriveOutcome`] that
//! binds the plan digest, the decision anchor, the result digests, the
//! admitted packet slots, and the per-material rank-trace handles with their
//! staleness obligations. Every candidate yields exactly one trace or the
//! drive fails closed; nothing is silently dropped.
//!
//! Supplier state lives in [`RetrievalDriveState`], retained by the daemon
//! composition and injected by the retrieval owners (M1/M2 coordinate the
//! plan compiler and input assembler landings): plans and inputs arrive
//! fully formed via [`compile_retrieval_plan`] and [`assemble_closure`],
//! never fabricated here. The tick re-drives only on a changed bundle
//! digest; repeat ticks return the retained outcome. Until the owners land,
//! resolution returns an explicit [`RetrievalDriveOutcome::SuppliersPending`].
//!
//! Authority boundaries (this module invents nothing):
//!
//! ```text
//! retrieval/admission owners hold: plan shape, compilation, closure
//!                 assembly and validation, the admission gate and
//!                 selection, trace derivation and handles;
//! this module owns: supplier retention against the daemon composition,
//!                 outcome projection for the daemon response, tick wiring.
//!                 No ledger, no minted identities, no planning or admission
//!                 semantics.
//! ```

use std::sync::MutexGuard;

use eliot_context_admission::{MaterialRankTrace, RetrievalStaleness, admit_context_traced};
use eliot_context_contracts::{AdmissionDisposition, AdmissionInput, ContextError};
use eliot_contracts::{ArtifactId, DecisionId};
use eliot_reactive_context_plan::RetrievalPlan;
use serde::{Deserialize, Serialize};

use crate::DaemonComposition;

/// Owner-supplied retrieval bundle. Both members arrive fully formed from
/// their owners; the daemon validates and drives them but never builds them.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetrievalSuppliers {
    /// Compiled retrieval plan from the retrieval owner.
    pub plan: RetrievalPlan,
    /// Complete admission closure from the candidate/measurement owners.
    pub input: AdmissionInput,
}

/// Retained supplier postures. `None` members name exactly which owner has
/// not landed yet; the drive idles on any absence.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetrievalSupplierState {
    /// Latest compiled plan, when the retrieval owner delivered one.
    pub plan: Option<RetrievalPlan>,
    /// Latest assembled closure, when the input owners delivered one.
    pub input: Option<AdmissionInput>,
}

/// Retained retrieval drive state for idempotent ticks.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetrievalDriveState {
    /// Latest owner postures.
    pub suppliers: RetrievalSupplierState,
    /// Bundle digest of the last fired drive, if any.
    pub last_bundle_digest: Option<String>,
    /// Outcome of the last fired drive, returned verbatim on unchanged ticks.
    pub last_outcome: Option<RetrievalDriveOutcome>,
}

impl RetrievalDriveState {
    /// Empty supplier postures with no fired drive.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

/// Supplier resolution against retained postures.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SupplierResolution {
    /// Both owners delivered; the drive may run. Boxed: the owner bundle is
    /// a large inline closure next to the unit-like pending arm.
    Ready(Box<RetrievalSuppliers>),
    /// Named absent suppliers; the drive idles with a typed outcome.
    Pending {
        /// No live retrieval-plan compiler output exists yet.
        missing_plan: bool,
        /// No live admission-input assembly exists yet.
        missing_input: bool,
    },
}

/// Resolve the retrieval suppliers from retained postures.
///
/// Returns the owned bundle only when both owners delivered; otherwise names
/// exactly which side is absent. Pure over the postures: no I/O, no
/// fabrication.
pub fn resolve_retrieval_suppliers(state: &RetrievalSupplierState) -> SupplierResolution {
    match (&state.plan, &state.input) {
        (Some(plan), Some(input)) => SupplierResolution::Ready(Box::new(RetrievalSuppliers {
            plan: plan.clone(),
            input: input.clone(),
        })),
        (plan, input) => SupplierResolution::Pending {
            missing_plan: plan.is_none(),
            missing_input: input.is_none(),
        },
    }
}

/// One admitted packet slot binding a material to its packet position.
///
/// Slots cover admitted materials only, in trace (atom-identity) order, so
/// `offset` is the deterministic packet position and `trace_handle` resolves
/// the full selection evidence for exactly that position.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PacketSlot {
    /// Deterministic position inside the admitted packet.
    pub offset: u32,
    /// Stable identity of the slotted material.
    pub atom_id: ArtifactId,
    /// Handle resolving to the material trace carrying the full evidence.
    pub trace_handle: String,
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
    /// Admission completed with packet slots and traces bound.
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
        /// Admitted materials reporting zero remaining headroom in the
        /// admission economy receipt.
        capacity_constrained_materials: u32,
        /// Admitted packet slots in deterministic order.
        packet: Vec<PacketSlot>,
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
        /// `"suppliers"`, `"plan"`, `"admission"`, or `"drive"`.
        stage: String,
        /// Owner error text; identities only, never payload.
        detail: String,
    },
    /// Named absent suppliers; the drive idled without fabricating inputs.
    SuppliersPending {
        /// No live retrieval-plan compiler output exists yet.
        missing_plan: bool,
        /// No live admission-input assembly exists yet.
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

/// Compute the identity of one supplier bundle.
///
/// Canonical digests re-validate both members fail-closed, so a malformed
/// bundle refuses here with stage attribution instead of reaching selection.
fn bundle_digest(bundle: &RetrievalSuppliers) -> Result<String, ContextError> {
    Ok(format!(
        "{}:{}",
        bundle.plan.canonical_digest()?,
        bundle.input.canonical_digest()?
    ))
}

/// Drive one retrieval plan with traced admission and bound the outcome.
///
/// Validates the plan, runs [`admit_context_traced`] over the supplied
/// input, and binds the plan digest, decision anchor, result digests, packet
/// slots, and per-material trace handles with their staleness obligations
/// into one typed outcome. A fence-disagreeing closure routes to the refresh
/// path ([`RetrievalStaleness::PacketRefreshRequired`]); any other boundary
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
            let mut capacity_constrained_materials: u32 = 0;
            let mut packet = Vec::new();
            let mut obligations = Vec::new();
            for trace in &traces {
                match trace.disposition {
                    AdmissionDisposition::Include | AdmissionDisposition::HandleOnly => {
                        packet.push(PacketSlot {
                            offset: u32::try_from(packet.len()).unwrap_or(u32::MAX),
                            atom_id: trace.atom_id.clone(),
                            trace_handle: trace.trace_handle.clone(),
                        });
                        admitted = admitted.saturating_add(1);
                        if trace.capacity_constrained {
                            capacity_constrained_materials =
                                capacity_constrained_materials.saturating_add(1);
                        }
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
                capacity_constrained_materials,
                packet,
                traces,
                obligations,
            }
        }
    }
}

/// Poll one retrieval drive from the daemon composition for this tick.
///
/// Resolves the retained owner postures and either idles with an explicit
/// [`RetrievalDriveOutcome::SuppliersPending`], returns the retained outcome
/// when the bundle digest is unchanged, or drives the resolved bundle
/// through [`drive_retrieval_admission`] and retains the outcome.
/// Synchronous and bounded; the caller accounts the returned outcome (see
/// [`RetrievalDriveOutcome::kind`]). A poisoned drive mutex fails closed
/// without panicking.
pub fn poll_retrieval_drive(composition: &DaemonComposition) -> RetrievalDriveOutcome {
    let _span = tracing::info_span!("eliotd.retrieval_drive").entered();
    let mut drive: MutexGuard<'_, RetrievalDriveState> = match composition.retrieval_drive.lock() {
        Ok(guard) => guard,
        Err(_) => {
            return RetrievalDriveOutcome::Rejected {
                stage: "drive".to_owned(),
                detail: "retrieval drive state unavailable".to_owned(),
            };
        }
    };
    match resolve_retrieval_suppliers(&drive.suppliers) {
        SupplierResolution::Pending {
            missing_plan,
            missing_input,
        } => RetrievalDriveOutcome::SuppliersPending {
            missing_plan,
            missing_input,
        },
        SupplierResolution::Ready(bundle) => {
            let digest = match bundle_digest(&bundle) {
                Ok(digest) => digest,
                Err(error) => {
                    return RetrievalDriveOutcome::Rejected {
                        stage: "suppliers".to_owned(),
                        detail: error.to_string(),
                    };
                }
            };
            if drive.last_bundle_digest.as_deref() == Some(digest.as_str())
                && let Some(outcome) = drive.last_outcome.clone()
            {
                return outcome;
            }
            let outcome = drive_retrieval_admission(&bundle.plan, &bundle.input);
            drive.last_bundle_digest = Some(digest);
            drive.last_outcome = Some(outcome.clone());
            outcome
        }
    }
}
