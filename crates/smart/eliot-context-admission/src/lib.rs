//! Pure, deterministic Context membership admission.
//!
//! This prototype consumes the complete A-15 input closure. It only admits
//! already validated whole units or exact handles and accounts for qualified
//! UTF-8 contributions. Providers, renderers, tokenizers, stores and runtime
//! effects remain outside this crate.
//!
//! Privacy is refused HERE, by the contracts cell's own rule and not only
//! downstream: `AdmissionInput::validate` calls
//! `ContextCandidate::validate_public_privacy` on every candidate, so an atom whose
//! `PrivacyClass` is not `Public` fails admission input with
//! `ContextError::InvalidField("candidate.privacy")` and never reaches an admitted set.
//! The wider A00.3 question — which routes a non-public atom may then reach — belongs to
//! `crates/governor/eliot-workscope` (`PrivacyProfile::admits`, `WorkScopeError::PrivacyDenied`).
//! An earlier version of this note claimed the opposite ("never refused by admission");
//! it was wrong, and the rule it denied is two calls away in `admission_input.rs`.
//!
//! Issue #1862 adds the campaign learning-state join this cell owns:
//! [`check_campaign_view_for_admission`] refuses an immutable
//! `CampaignLearningStateView` whose State Fence, task/scope identity or
//! load-bearing Context recipe owner revision does not join the exact binding
//! the admission decision is made under, and refuses a substituted
//! `SafetyFloorIdentity` by content-comparing every relation
//! `AdmissionInput::validate_contract` states about it. It re-derives that join
//! from this cell's own binding and inherits no other cell's verdict. The
//! #40-frozen `eliot_context::ContextCompiler` decides nothing on this route.

#![forbid(unsafe_code)]

pub mod campaign_view;
pub mod closure;
pub mod decision;
#[cfg(not(target_arch = "wasm32"))]
pub mod learning_gate;
#[cfg(not(target_arch = "wasm32"))]
pub mod material_floor;
pub mod unit_group;

pub use campaign_view::check_campaign_view_for_admission;
pub use closure::{ClosureParts, assemble_closure};
pub use unit_group::UnitGroupContext;

pub use decision::{
    ClassificationEvidence, ClassifiedAdmission, MaterialRankTrace, RetrievalAdmissionDecision,
    RetrievalStaleness, SuppliedWarning, check_plan_revisions, check_retrieval_freshness,
    classify_admission, derive_candidate_warnings, derive_input_warnings, trace_material,
    trace_material_with_warnings,
};

#[cfg(not(target_arch = "wasm32"))]
pub use learning_gate::{
    LearningSubject, admit_context_traced_with_learning_and_headroom, admit_context_with_learning,
    screen_admission_input_learning, screen_learning_subjects,
};

#[cfg(not(target_arch = "wasm32"))]
pub use material_floor::{
    AdmittedDecisionFloor, AffectedLineageReference, AllowedFloorAction, ApplicableFloor,
    BoundSourceRevision, DecisionFloorRefusal, DispatchOwnerState, FloorAtomPolicy,
    FloorEvidenceStatus, MaterialDecisionRefusal, MaterialDispatchBinding, MaterialEntrypointKind,
    OperationOwnerInputs, RequiredFloorAtom, ResumeHistoryInputs, admit_material_decision,
    admit_material_resume, bind_material_dispatch, derive_applicable_floor,
    revalidate_material_dispatch,
};

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use eliot_context_contracts::{
    AdmissionDisposition, AdmissionInput, AdmissionMeasuredCost, AdmissionRecord, AdmissionResult,
    AdmittedAtom, AdmittedContextSet, AtomAvailability, ContextBinding, ContextEconomyReceipt,
    ContextError, ContextOutcome, DecisionContextIncomplete, DownstreamHeadroomRequest,
    DownstreamHeadroomResult, EconomyAllocations, HeadroomAllocationLedger, HeadroomDimension,
    HeadroomRefusal, MeasurementRef, OmissionReason, OmissionRecord, RepresentationKind,
};
use eliot_receipts::ProofCeiling;

use crate::unit_group::UnitGroupBinding;

const UNKNOWN_AVAILABILITY_CONSTRAINT: &str =
    "candidate availability is unknown; admission deferred until availability is known";

/// Admit one immutable candidate set under one exact recipe and route profile.
///
/// Selection is floor-first and deterministic. Every candidate receives one
/// disposition, and optional omissions retain the supplied reversible handle
/// or non-recoverable reason. No source is fetched and no representation is
/// generated here.
///
/// I12.24/#1869 plain-path rule: learning-marked or ticketed inputs are
/// refused fail-closed here; governed influence must use
/// `admit_context_with_learning`.
pub fn admit_context(input: &AdmissionInput) -> Result<AdmissionResult, ContextError> {
    refuse_ungoverned_learning(input)?;
    admit_context_inner(input)
}

fn refuse_ungoverned_learning(input: &AdmissionInput) -> Result<(), ContextError> {
    let marked = input
        .candidates
        .candidates
        .iter()
        .any(|c| c.learning.is_some());
    if marked || !input.learning_tickets.is_empty() {
        return Err(ContextError::InvalidField(
            "learning.governed_path_required",
        ));
    }
    Ok(())
}

pub(crate) fn admit_context_inner(input: &AdmissionInput) -> Result<AdmissionResult, ContextError> {
    admit_context_inner_with_boundaries(input, None, None)
}

/// The validated owner evidence the pure compiler receives before optional
/// filling.
///
/// This is plain data, never an IO client: the request the runtime caller
/// submitted and the owner-issued result it received. The compiler reads the
/// owner-issued permit bindings out of the result and never contacts an owner.
pub struct HeadroomContext<'a> {
    /// The exact bounded request the caller submitted for this compilation.
    pub request: &'a DownstreamHeadroomRequest,
    /// The owner-issued answer to that request.
    pub result: &'a DownstreamHeadroomResult,
    /// The no-double-counting ledger over this recipe's declared reserves.
    pub ledger: &'a HeadroomAllocationLedger,
    /// The caller's observed clock, in Unix milliseconds.
    ///
    /// Staleness is decided against this value, never against a timestamp the
    /// evidence carries about itself.
    pub now_ms: u64,
}

/// Why the compiler withheld dependent action-ready publication.
///
/// I12.13 requires the attempted recipe and the exact omissions to survive the
/// refusal, so a dependent operation is blocked without the packet reading as
/// nominally complete.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HeadroomRefusalRecord {
    /// Why publication is withheld.
    pub reason: HeadroomRefusal,
    /// The contract-level failure that produced the refusal, kept typed.
    pub error: ContextError,
    /// The recipe revision this compilation actually attempted.
    pub attempted_recipe_digest: String,
    /// The exact task/attempt/scope/decision/fence the attempt was made under.
    pub attempted_binding: ContextBinding,
}

/// The compiler's bounded headroom decision before optional filling.
///
/// The granted dimensions are proven by owner-issued permit bindings inside
/// `result`; this record reports only what the compiler concluded from them, so
/// it can never read as a reservation on its own.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HeadroomCheck {
    /// The owner reserved every demanded dimension and the declared reserves
    /// leave room for the required floor.
    Admitted {
        /// Occupancy left for admitted material after the declared fixed
        /// overhead and the referenced output and review reserves.
        occupancy_available: u64,
    },
    /// A demanded dimension was not reserved, or its reservation is stale.
    Refused(HeadroomRefusal),
}

impl HeadroomCheck {
    /// Return the refusal, when this decision withheld publication.
    #[must_use]
    pub fn refusal(&self) -> Option<&HeadroomRefusal> {
        match self {
            Self::Admitted { .. } => None,
            Self::Refused(refusal) => Some(refusal),
        }
    }
}

/// The bounded headroom decision and the admission it gates.
///
/// `Admitted` carries the admission that ran under the granted reservation;
/// `Refused` carries the attempted recipe and binding with no admitted set, so
/// a dependent operation can never observe a nominally complete view.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HeadroomAdmissionOutcome {
    /// Every demanded dimension is reserved and the admission ran.
    Admitted {
        /// The admission result produced under the granted reservation.
        result: Box<AdmissionResult>,
        /// The per-material rank traces of that same result.
        traces: Vec<MaterialRankTrace>,
        /// The bounded headroom decision that admitted the optional fill.
        check: HeadroomCheck,
    },
    /// The reservation was withheld; no admitted set exists.
    ///
    /// The record is boxed for the same reason the admitted arm boxes its
    /// result: it carries the whole attempted binding and typed refusal, which
    /// is far wider than the traces and the bounded check. Boxing it keeps a
    /// refusal from charging the admitted arm that width on every packet.
    Refused(Box<HeadroomRefusalRecord>),
}

/// Reject a demanded dimension the owner did not reserve.
///
/// A refused, unknown or not-applicable dimension is named explicitly, so the
/// caller receives the exact limiting dimensions instead of a truncated packet
/// that looks complete.
fn headroom_limiting_dimensions(
    request: &DownstreamHeadroomRequest,
    result: &DownstreamHeadroomResult,
) -> Vec<HeadroomDimension> {
    request
        .demands
        .iter()
        .map(|demand| demand.dimension)
        .filter(|dimension| result.reservation(*dimension).is_none())
        .collect()
}

/// The bounded headroom check the pure compiler runs before optional filling.
///
/// Four things are proved here, all from owner evidence and the recipe's own
/// declared reserves:
///
/// 1. The owner result is valid against the exact request, the live fence and
///    the caller's clock, so a stale or revoked reservation cannot be granted.
/// 2. Every demanded dimension reached a grant. A dimension the owner could
///    not determine is `Unknown`, never an empty demand that fits.
/// 3. The ledger reconciles: each purpose is bound once, and `Output` and
///    `ReviewReasoning` reference the recipe's existing reserves rather than
///    adding them a second time.
/// 4. The declared fixed overhead plus the required floor fit inside the
///    occupancy those referenced reserves leave, with checked arithmetic.
///
/// A failure returns the typed contract error; the caller turns it into the
/// typed [`HeadroomRefusalRecord`].
fn check_headroom(
    input: &AdmissionInput,
    headroom: &HeadroomContext<'_>,
) -> Result<HeadroomCheck, ContextError> {
    if headroom.ledger.capacity != input.recipe.capacity {
        return Err(ContextError::EconomyMismatch);
    }
    headroom.ledger.reconcile()?;
    headroom
        .result
        .validate_against(headroom.request, &input.binding, headroom.now_ms)?;
    let limiting = headroom_limiting_dimensions(headroom.request, headroom.result);
    if !limiting.is_empty() {
        return Ok(HeadroomCheck::Refused(HeadroomRefusal::Unavailable {
            dimensions: limiting,
        }));
    }
    Ok(HeadroomCheck::Admitted {
        occupancy_available: headroom.ledger.occupancy_available()?,
    })
}

/// Require the required floor cost to fit the occupancy the referenced reserves
/// leave.
///
/// This is the reservation-aware form of the pre-existing floor-plus-overhead
/// fit: it reserves the recipe's own `output_reserve` and `review_reserve`
/// before optional filling rather than only the nominal route capacity.
///
/// Only `required_cost` is compared, because
/// [`HeadroomAllocationLedger::occupancy_available`] already has the declared
/// `fixed_overhead`, `output_reserve` and `review_reserve` subtracted once from
/// the route capacity. Adding `fixed_cost(input)` — which re-adds exactly those
/// same three terms — would charge every reserve and the fixed overhead twice
/// and refuse packets that fit inside the envelope they were compiled under.
fn check_reserved_occupancy(
    headroom: &HeadroomContext<'_>,
    required_cost: u64,
) -> Result<(), ContextError> {
    if required_cost > headroom.ledger.occupancy_available()? {
        return Err(ContextError::CapacityExceeded);
    }
    Ok(())
}

/// Admit one candidate set under one granted downstream reservation.
///
/// I12.13: "Before filling optional context, Context Compiler requests the
/// applicable `DownstreamHeadroomReservation`." The runtime caller submits the
/// bounded request through the existing Kernel resource/lease owner and receives
/// the owner-issued answer; this entry receives both as validated owner evidence,
/// performs no I/O, and contacts no owner. The owner stays the only party that
/// can release or reconcile a granted reservation: the assembly owner's
/// `recheck_headroom_handoff` returns the release instructions rather than
/// releasing anything itself.
///
/// A withheld reservation returns
/// [`HeadroomAdmissionOutcome::Refused`] with the attempted recipe and binding
/// and no admitted set, so a dependent operation can never observe a nominally
/// complete view built without its headroom.
pub fn admit_context_traced_with_headroom(
    input: &AdmissionInput,
    headroom: &HeadroomContext<'_>,
) -> Result<HeadroomAdmissionOutcome, ContextError> {
    // Holding a reservation is not learning authority. A marked or ticketed
    // input still needs the governed learning checks, which this entry does not
    // run, so the same existing guard `admit_context` applies refuses it here
    // rather than treating learning-derived material as ordinary context. The
    // mark is never stripped and the ticket is never ignored to make it pass;
    // the caller uses `admit_context_traced_with_learning_and_headroom` to carry
    // both authorities instead.
    refuse_ungoverned_learning(input)?;
    run_with_headroom(input, headroom, None)
}

/// The one bounded headroom orchestration both headroom entries share.
///
/// The refusal constructor, the headroom check, the refused-dimension arm and
/// the single selection call are defined once here so the
/// indivisible-unit entry cannot grow a second reservation scheme or a second
/// selection pass. `units` is `None` when the caller presented no owner
/// unit/member metadata; it is never synthesised here.
pub(crate) fn run_with_headroom(
    input: &AdmissionInput,
    headroom: &HeadroomContext<'_>,
    units: Option<&UnitGroupBinding>,
) -> Result<HeadroomAdmissionOutcome, ContextError> {
    // The refusal names an existing owner record, never a minted placeholder:
    // the recipe's own invalidation identity when it declared one, otherwise
    // the admission rule evidence that produced the failure.
    let reason_ref = input
        .recipe
        .invalidation
        .clone()
        .unwrap_or_else(|| input.floor.floor.rule_evidence.clone());
    let refusal = |error: ContextError| {
        HeadroomAdmissionOutcome::Refused(Box::new(HeadroomRefusalRecord {
            reason: match &error {
                ContextError::StaleFloor | ContextError::InvalidFence => HeadroomRefusal::Stale {
                    reason: reason_ref.clone(),
                },
                ContextError::MissingFloor | ContextError::OversizedFloor => {
                    HeadroomRefusal::Unavailable {
                        dimensions: headroom_limiting_dimensions(headroom.request, headroom.result),
                    }
                }
                ContextError::CapacityExceeded | ContextError::Overflow => {
                    HeadroomRefusal::PostRenderOverflow {
                        reason: reason_ref.clone(),
                    }
                }
                _ => HeadroomRefusal::IdentityChanged {
                    reason: reason_ref.clone(),
                },
            },
            error,
            attempted_recipe_digest: input.recipe.recipe_sha256.clone(),
            attempted_binding: input.binding.clone(),
        }))
    };
    // A headroom failure is a TYPED REFUSAL, not a transport error, so it is
    // returned as `Ok(Refused(..))` on the same footing as the floor-path
    // refusal below - never as `Err(..)`, which would erase the limiting
    // dimensions the caller needs in order to narrow or decompose.
    let check = match check_headroom(input, headroom) {
        Ok(check) => check,
        Err(error) => return Ok(refusal(error)),
    };
    // A refused dimension means no optional filling happened at all, so the
    // typed refusal carries the same exact error the floor path reports for an
    // unsatisfiable required floor, plus the limiting dimensions.
    if let HeadroomCheck::Refused(reason) = &check {
        return Ok(HeadroomAdmissionOutcome::Refused(Box::new(
            HeadroomRefusalRecord {
                reason: reason.clone(),
                error: ContextError::MissingFloor,
                attempted_recipe_digest: input.recipe.recipe_sha256.clone(),
                attempted_binding: input.binding.clone(),
            },
        )));
    }
    match admit_context_inner_with_boundaries(input, Some(headroom), units) {
        Ok(result) => {
            let traces = trace_material(input, &result)?;
            Ok(HeadroomAdmissionOutcome::Admitted {
                result: Box::new(result),
                traces,
                check,
            })
        }
        Err(error) => Ok(refusal(error)),
    }
}

/// Admit one candidate set under one granted downstream reservation and the
/// owner-issued indivisible-unit metadata.
///
/// I12.13 "Bind indivisible groups": a tool call/result pair or an evidence edge
/// may span several records, so the closure this decision selects is expanded to
/// every member the owner declared for each indivisible unit, and a group whose
/// closure cannot be admitted whole receives the whole group's disposition
/// instead of a partial one. Group membership and each member's unit kind come
/// from the owner's own [`UnitGroupContext`] metadata; nothing here reads a unit
/// kind off a content string, and a candidate the metadata does not describe is
/// never admitted as a whole unit.
///
/// The same decision also runs the I12.13 headroom rule before optional filling.
/// This entry receives validated owner evidence only, performs no I/O, and
/// contacts no owner.
///
/// A withheld reservation returns [`HeadroomAdmissionOutcome::Refused`] with the
/// attempted recipe and binding and no admitted set, so a dependent operation
/// can never observe a nominally complete view built without its headroom.
pub fn admit_context_traced_with_boundaries(
    input: &AdmissionInput,
    headroom: &HeadroomContext<'_>,
    units: &UnitGroupContext<'_>,
) -> Result<HeadroomAdmissionOutcome, ContextError> {
    // Same rule as `admit_context_traced_with_headroom`: unit metadata is not
    // learning authority, so learning-derived material still requires the
    // governed learning checks this entry does not run.
    refuse_ungoverned_learning(input)?;
    let units = UnitGroupBinding::bind(input, units)?;
    run_with_headroom(input, headroom, Some(&units))
}

fn admit_context_inner_with_boundaries(
    input: &AdmissionInput,
    headroom: Option<&HeadroomContext<'_>>,
    units: Option<&UnitGroupBinding>,
) -> Result<AdmissionResult, ContextError> {
    // I12.26 stale-projection fence arm, enforced before exact cue firing: a
    // candidate closure compiled under another fence must refresh the packet
    // and can never silently admit. Today's boundary refusal for exactly this
    // case is `InvalidFence`, so the mapping is exact rather than a new
    // meaning. Floor/optional staleness keeps flowing through the existing
    // typed incomplete/omission paths below; erroring there would change the
    // boundary contract those paths own.
    if matches!(
        check_retrieval_freshness(input),
        Err(RetrievalStaleness::PacketRefreshRequired)
    ) {
        return Err(ContextError::InvalidFence);
    }
    validate_admission_contract(input)?;
    let input_digest = input.canonical_digest()?;
    let profile_digest = input.measurement_profile.canonical_digest()?;
    let candidates: BTreeMap<_, _> = input
        .candidates
        .candidates
        .iter()
        .map(|candidate| (candidate.atom_id.clone(), candidate))
        .collect();
    let priorities: BTreeMap<_, _> = input
        .priority
        .priorities
        .iter()
        .map(|priority| (priority.atom_id.clone(), priority))
        .collect();
    let supplied: BTreeMap<_, _> = input
        .supplied_omissions
        .iter()
        .map(|binding| (binding.atom_id.clone(), binding))
        .collect();

    // Capacity validation is deliberately before any candidate selection.
    input.recipe.capacity.validate()?;
    let floor_ids = match prepare_floor(input, &candidates, &supplied, units)? {
        Ok(floor_ids) => floor_ids,
        Err(incomplete) => {
            return incomplete_result(input, input_digest, profile_digest, &incomplete);
        }
    };
    let (mut admitted, required_cost, fixed) =
        match select_required(input, &candidates, &floor_ids)? {
            Ok(selection) => selection,
            Err(incomplete) => {
                return incomplete_result(input, input_digest, profile_digest, &incomplete);
            }
        };

    // Before optional filling: the required floor must fit the occupancy the
    // referenced output and review reserves leave. Without a granted reservation
    // the pre-existing nominal-capacity fit above already applies; with one, the
    // reserves are actually held back.
    if let Some(headroom) = headroom {
        check_reserved_occupancy(headroom, required_cost)?;
    }

    let (optional_cost, failure_causes) = select_optional(OptionalSelectionInput {
        input,
        candidates: &candidates,
        priorities: &priorities,
        supplied: &supplied,
        floor_ids: &floor_ids,
        admitted: &mut admitted,
        fixed,
        required_cost,
        units,
    })?;
    let omissions = build_omissions(
        input,
        &candidates,
        &floor_ids,
        &admitted,
        &supplied,
        &failure_causes,
    )?;
    assemble_result(ResultAssemblyInput {
        input,
        input_digest,
        profile_digest,
        candidates: &candidates,
        admitted,
        omissions: &omissions,
        supplied: &supplied,
        required_cost,
        optional_cost,
        fixed,
    })
}

fn validate_admission_contract(input: &AdmissionInput) -> Result<(), ContextError> {
    input.validate_additive_measurements()?;
    validate_selection_contract(input)
}

/// Admit one immutable candidate set and return the per-material rank traces.
///
/// This is the live runtime entrypoint combining [`admit_context`] with
/// [`trace_material`]: the caller receives the admission result together
/// with exactly one handle-bound [`MaterialRankTrace`] per evaluated
/// candidate, carrying the typed six-outcome slot, the freshness signal,
/// and the explicit suppression evidence. The traces re-validate the result
/// against the input closure fail-closed, so the pair always corresponds;
/// no separate join by the caller can drift.
///
/// ## Runtime join contract (M2/O1 daemon feed callee)
///
/// This entrypoint is the sole supplier-side callee the daemon retrieval
/// drive joins against; the drive builds nothing admission-side and mints
/// no identities. Caller obligations, in order:
///
/// 1. Resolve both suppliers from their owners only: the retrieval plan
///    through the retrieval-plan compiler
///    (`eliot-reactive-context-plan` compiler) and the [`AdmissionInput`]
///    through the closure assembler ([`assemble_closure`]). Absent
///    suppliers idle with a named pending outcome; they are never
///    fabricated at the call site.
/// 2. Validate the plan fail-closed through its canonical digest, then run
///    the plan-against-input revision comparison
///    ([`check_plan_revisions`]) before calling: every fence-matching
///    candidate source needs a plan expectation with the actual revision,
///    or the drive probes (optional) or stales (floor) instead of
///    admitting; a refused plan or an unresolvable closure never reaches
///    selection.
/// 3. Call exactly once per changed supplier bundle and bind the returned
///    pair verbatim: the result and selection digests, the decision
///    anchor, and every trace handle with its staleness obligation.
/// 4. Map an [`ContextError::InvalidFence`] return to the packet-refresh arm
///    ([`RetrievalStaleness::PacketRefreshRequired`]); it names a closure
///    compiled under another fence and can never admit. Every other
///    boundary refusal is named by its refusing stage, never coerced into
///    an admission outcome.
/// 5. Read per-material staleness only from
///    [`MaterialRankTrace::staleness`], capacity pressure only from
///    [`MaterialRankTrace::capacity_constrained`], suppression text only
///    from [`MaterialRankTrace::suppression_reason`], and owner warning
///    text only from [`MaterialRankTrace::warning`]; none of these signals
///    reclassifies the trace outcome, which [`classify_admission`] alone
///    determines.
/// 6. To admit with owner warning evidence, derive it with
///    [`derive_input_warnings`] (candidate-owned epistemic qualifications
///    under the canonical candidate coherence rule) and join through
///    [`admit_context_traced_with_warnings`], optionally with additional
///    owner-minted [`SuppliedWarning`] records (projection owners and
///    successors); warning text is never synthesized at the call site,
///    and Governor risk tiers never authorise warnings.
///
/// Supplier anchors (this crate): fence arm in [`admit_context`], the
/// trichotomy gate in [`check_retrieval_freshness`], the plan revision
/// comparison in [`check_plan_revisions`], the total classifier in
/// [`classify_admission`], and the trace joins in [`trace_material`] and
/// [`trace_material_with_warnings`].
/// Decided contract: unresolved revision compares reject
/// (`StaleProjection` floor, `ProbeRequired` optional) with fence-mismatch
/// priority to the refresh arm.
///
/// # Runtime consumer status (measured, not inherited)
///
/// Measured on `origin/main@0488753d` (2026-09-26) by walking every call
/// site upward, because an earlier revision of this note asserted a consumer
/// that does not exist; re-measured on `origin/main@a1555930` (2026-09-28), and
/// re-measured again on `origin/main@9232715b` (2026-09-29) because the
/// `#1862` rework removed the donor leg this note named. The state of this
/// join is:
///
/// - The production call site of the traced join is
///   `bins/eliotd/src/kernel_context_read_client.rs::admit_packet_candidates`,
///   which joins [`admit_context`] with this join and hands the closed
///   [`MaterialRankTraceDelivery`] to the packet composition.
/// - That call site is not itself reachable from `fn main` yet:
///   `KernelContextReadClient::compile_context_packet` has no call site in
///   the tree. It is also uncallable by construction: its closure parameters
///   include the admission-closure supplier, and that closure's four identity
///   fields (`SafetyFloorIdentity`, `PriorityPolicyIdentity`,
///   `AdmissionRuleIdentity`, `MeasurementCompositionProfile`) are minted
///   nowhere outside `tests/` fixtures. The live `eliot.packet` daemon poller
///   (`daemon_runtime::run_campaign_packet_poll` ->
///   `campaign_packet::serve_campaign_packet_pair`) never reaches any context
///   admission *decision*: it compiles through the learning-state view owner
///   `eliot_learning_state_view::compile_campaign_learning_state_view`, not
///   through this crate, and `eliot-context` does not depend on this crate.
///   #1862 reaches this crate twice without making the decision callable: the
///   candidate cell
///   (`eliot_context_candidates::check_campaign_learning_state_view`, called
///   from `bins/eliotd/src/campaign_packet.rs`) owns the candidate-stage join,
///   and this crate's own
///   [`check_campaign_view_for_admission`] now owns the admission-stage join
///   against the binding an admission decision would be made under, called
///   from the same route and from
///   `kernel_context_read_client::compile_context_packet`. The two are separate
///   comparisons against different bindings, so neither inherits the other.
///   Neither makes [`admit_context_traced`] reachable, and of the four
///   admission-closure identities above exactly one now has a production
///   construction site: `SafetyFloorIdentity` is resolved on the live route by
///   the Context owner's own publication
///   (`eliot_context::campaign_publication::context_safety_floor_identity`) and
///   is content-compared by [`check_campaign_view_for_admission`] against the
///   binding and recipe it admits under.
///   `PriorityPolicyIdentity`, `AdmissionRuleIdentity` and
///   `MeasurementCompositionProfile` are still minted nowhere outside `tests/`
///   fixtures, and the per-identity account of what each lacks — each is a
///   genuinely absent owner record, not an unminted call — is stated on
///   `eliot_context::campaign_publication::context_safety_floor_identity` and
///   recorded on
///   `bins/eliotd/src/campaign_packet.rs::CampaignPacketGapCode::AdmissionClosureUnbound`.
///   The `#40`-frozen
///   `eliot_context::ContextCompiler::compile_with_campaign_learning_state`
///   named by an earlier revision of this note has NO call site either, so it
///   is not on the live path.
/// - `bins/eliot-wasm-host`'s `admit_governed_host` reaches
///   `admit_context_with_learning` but has no call site either.
///
/// So the join is owned, and the composition that would carry it is itself
/// blocked on the missing admission-bundle owner; the missing link is that
/// owner, not a supplier here. Read this as a measured absence, not as a
/// scheduled M2/O1 tick.
pub fn admit_context_traced(
    input: &AdmissionInput,
) -> Result<(AdmissionResult, Vec<MaterialRankTrace>), ContextError> {
    let result = admit_context(input)?;
    let traces = trace_material(input, &result)?;
    Ok((result, traces))
}

/// Admit with owner-issued warning evidence and return rank traces.
///
/// Same join as [`admit_context_traced`], except the caller additionally
/// threads owner-minted [`SuppliedWarning`] records; admitted candidates
/// carrying non-blank warning evidence classify to
/// `include_with_warning` through the unchanged [`classify_admission`]
/// arm, and the text is bound into the trace handle. See the join
/// contract on [`admit_context_traced`]; all obligations apply unchanged.
///
/// I12.13 headroom rule: a pipeline that can consume all currently free
/// capacity reserves its downstream headroom through the existing Kernel
/// resource/lease owner *before* optional filling. That owner join lives on
/// [`admit_context_traced_with_headroom`], which additionally requires the
/// owner-issued reservation evidence. This entry remains the unbounded
/// reservation-free path and is not the one a production packet composition
/// uses; see the measured runtime-consumer status on
/// [`admit_context_traced`].
pub fn admit_context_traced_with_warnings(
    input: &AdmissionInput,
    warnings: &[SuppliedWarning],
) -> Result<(AdmissionResult, Vec<MaterialRankTrace>), ContextError> {
    let result = admit_context(input)?;
    let traces = trace_material_with_warnings(input, &result, warnings)?;
    Ok((result, traces))
}

/// The I12.26 rank-trace delivery record bound to one admission result.
///
/// I12.26 requires the recall result to report visible and suppressed counts
/// and a full rank-trace handle beside the per-material traces. This closed
/// record is exactly that summary, derived only from the admission owner's own
/// per-material [`MaterialRankTrace`] set: it counts each evaluated material by
/// the disposition the decision actually reached, requires every suppressed
/// material of a complete decision to carry its owner-authored reason
/// explicitly (suppression is never inferred from absence), and binds a
/// content-addressed handle over the delivered per-material handles, so a
/// swapped trace, count or decision anchor invalidates it exactly like a
/// swapped per-material fact.
///
/// The handle is transitively content-addressed: each per-material
/// `material-trace:<sha256>` already commits to the whole delivered record for
/// that material, so the canonical digest over the ordered handle list commits
/// to the delivered trace set. No provider reasoning is stored here or in the
/// traces it carries: only the permitted selection evidence and reasons the
/// admission owner already bound.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MaterialRankTraceDelivery {
    /// Decision anchor every delivered trace is bound to.
    pub decision_id: eliot_contracts::DecisionId,
    /// One trace per evaluated material, ordered by material identity.
    pub traces: Vec<MaterialRankTrace>,
    /// Count of materials the decision delivered into the packet.
    pub visible: usize,
    /// Count of materials the decision withheld; each carries its explicit
    /// owner-authored suppression reason in its own trace.
    pub suppressed: usize,
    /// Content-addressed handle (`rank-trace:<sha256>`) resolving to exactly
    /// this delivered trace set.
    pub rank_trace_handle: String,
    /// Selection-time dependency references, each joined to the material
    /// trace that recorded it.
    pub dependency_trace_bindings: Vec<MaterialTraceDependencyBinding>,
    /// Selection-time invalidation references, each joined to the material
    /// trace that recorded it.
    pub invalidation_trace_bindings: Vec<MaterialTraceInvalidationBinding>,
}

/// Reverse association from one selected material dependency to its trace.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MaterialTraceDependencyBinding {
    /// Material whose selection recorded this dependency.
    pub atom_id: eliot_contracts::ArtifactId,
    /// Dependency recorded at selection time.
    pub dependency_id: eliot_contracts::ArtifactId,
    /// Per-material trace handle carrying the dependency fact.
    pub trace_handle: String,
}

/// Reverse association from one selected material invalidation to its trace.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MaterialTraceInvalidationBinding {
    /// Material whose selection recorded this invalidation.
    pub atom_id: eliot_contracts::ArtifactId,
    /// Invalidation handle recorded at selection time.
    pub invalidation_id: eliot_contracts::ArtifactId,
    /// Per-material trace handle carrying the invalidation fact.
    pub trace_handle: String,
}

impl MaterialRankTraceDelivery {
    /// Derive the delivery record from one admission result and its traces.
    ///
    /// Counts each material by the disposition the decision reached, requires
    /// every suppressed material of a complete decision to name its explicit
    /// reason, and mints the full rank-trace handle over the ordered
    /// per-material handles. The result must already be the one the traces were
    /// joined against, so the pair cannot drift.
    pub fn new(
        result: &AdmissionResult,
        mut traces: Vec<MaterialRankTrace>,
    ) -> Result<Self, ContextError> {
        traces.sort_by(|left, right| left.atom_id.cmp(&right.atom_id));
        let mut visible = 0_usize;
        let mut suppressed = 0_usize;
        for trace in &traces {
            if matches!(
                trace.disposition,
                AdmissionDisposition::Include | AdmissionDisposition::HandleOnly
            ) {
                visible = visible.checked_add(1).ok_or(ContextError::Overflow)?;
            } else {
                suppressed = suppressed.checked_add(1).ok_or(ContextError::Overflow)?;
            }
        }
        let handles: Vec<String> = traces
            .iter()
            .map(|trace| trace.trace_handle.clone())
            .collect();
        let (dependency_trace_bindings, invalidation_trace_bindings) =
            selection_trace_bindings(&traces)?;
        let delivery = Self {
            decision_id: result.binding.decision_id.clone(),
            traces,
            visible,
            suppressed,
            rank_trace_handle: format!(
                "rank-trace:{}",
                eliot_context_contracts::canonical_digest(&handles)?
            ),
            dependency_trace_bindings,
            invalidation_trace_bindings,
        };
        delivery.validate(result)?;
        Ok(delivery)
    }

    /// Conserve the evaluated materials and re-resolve every bound handle.
    ///
    /// Fails closed when the delivered set does not cover exactly the decided
    /// materials, when a per-material trace handle no longer resolves, when the
    /// reported counts do not add up, or when a suppressed material of a
    /// complete decision carries no explicit reason.
    pub fn validate(&self, result: &AdmissionResult) -> Result<(), ContextError> {
        if self.decision_id != result.binding.decision_id {
            return Err(ContextError::InvalidField(
                "material_trace_delivery.decision_id",
            ));
        }
        if self.traces.len() != result.evidence.decisions.len() {
            return Err(ContextError::DenominatorMismatch);
        }
        if self
            .traces
            .windows(2)
            .any(|pair| pair[0].atom_id >= pair[1].atom_id)
        {
            return Err(ContextError::InvalidField(
                "material_trace_delivery.trace_order",
            ));
        }
        let complete = matches!(result.outcome, ContextOutcome::Complete(_));
        let mut visible = 0_usize;
        let mut suppressed = 0_usize;
        let mut seen = BTreeSet::new();
        for trace in &self.traces {
            trace.validate()?;
            if trace.decision_id != self.decision_id {
                return Err(ContextError::InvalidField(
                    "material_trace_delivery.trace_decision_id",
                ));
            }
            if !seen.insert(trace.atom_id.clone()) {
                return Err(ContextError::Duplicate("material_trace_delivery.atom_id"));
            }
            if !result
                .evidence
                .decisions
                .iter()
                .any(|decision| decision.atom_id == trace.atom_id)
            {
                return Err(ContextError::DenominatorMismatch);
            }
            if matches!(
                trace.disposition,
                AdmissionDisposition::Include | AdmissionDisposition::HandleOnly
            ) {
                visible = visible.checked_add(1).ok_or(ContextError::Overflow)?;
            } else {
                suppressed = suppressed.checked_add(1).ok_or(ContextError::Overflow)?;
                if complete
                    && trace
                        .suppression_reason
                        .as_deref()
                        .is_none_or(|reason| reason.trim().is_empty())
                {
                    return Err(ContextError::InvalidField(
                        "material_trace_delivery.suppression_reason",
                    ));
                }
            }
        }
        if self.visible != visible || self.suppressed != suppressed {
            return Err(ContextError::DenominatorMismatch);
        }
        let handles: Vec<String> = self
            .traces
            .iter()
            .map(|trace| trace.trace_handle.clone())
            .collect();
        if self.rank_trace_handle
            != format!(
                "rank-trace:{}",
                eliot_context_contracts::canonical_digest(&handles)?
            )
        {
            return Err(ContextError::InvalidField(
                "material_trace_delivery.rank_trace_handle",
            ));
        }
        let (dependency_trace_bindings, invalidation_trace_bindings) =
            selection_trace_bindings(&self.traces)?;
        if self.dependency_trace_bindings != dependency_trace_bindings {
            return Err(ContextError::InvalidField(
                "material_trace_delivery.dependency_trace_bindings",
            ));
        }
        if self.invalidation_trace_bindings != invalidation_trace_bindings {
            return Err(ContextError::InvalidField(
                "material_trace_delivery.invalidation_trace_bindings",
            ));
        }
        Ok(())
    }
}

fn selection_trace_bindings(
    traces: &[MaterialRankTrace],
) -> Result<
    (
        Vec<MaterialTraceDependencyBinding>,
        Vec<MaterialTraceInvalidationBinding>,
    ),
    ContextError,
> {
    let mut dependencies = Vec::new();
    let mut invalidations = Vec::new();
    for trace in traces {
        let mut seen_dependencies = BTreeSet::new();
        for dependency in &trace.dependencies {
            if !seen_dependencies.insert(dependency) {
                return Err(ContextError::Duplicate("material_trace.dependencies"));
            }
        }
        dependencies.extend(trace.dependencies.iter().cloned().map(|dependency_id| {
            MaterialTraceDependencyBinding {
                atom_id: trace.atom_id.clone(),
                dependency_id,
                trace_handle: trace.trace_handle.clone(),
            }
        }));
        if let Some(invalidation_id) = &trace.invalidation {
            invalidations.push(MaterialTraceInvalidationBinding {
                atom_id: trace.atom_id.clone(),
                invalidation_id: invalidation_id.clone(),
                trace_handle: trace.trace_handle.clone(),
            });
        }
    }
    dependencies.sort_by(|left, right| {
        (&left.atom_id, &left.dependency_id, &left.trace_handle).cmp(&(
            &right.atom_id,
            &right.dependency_id,
            &right.trace_handle,
        ))
    });
    invalidations.sort_by(|left, right| {
        (&left.atom_id, &left.invalidation_id, &left.trace_handle).cmp(&(
            &right.atom_id,
            &right.invalidation_id,
            &right.trace_handle,
        ))
    });
    Ok((dependencies, invalidations))
}

fn build_omissions(
    input: &AdmissionInput,
    candidates: &BTreeMap<eliot_contracts::ArtifactId, &eliot_context_contracts::ContextCandidate>,
    floor_ids: &BTreeSet<eliot_contracts::ArtifactId>,
    admitted: &BTreeMap<eliot_contracts::ArtifactId, AdmittedAtom>,
    supplied: &BTreeMap<
        eliot_contracts::ArtifactId,
        &eliot_context_contracts::SuppliedOmissionBinding,
    >,
    failure_causes: &BTreeMap<eliot_contracts::ArtifactId, (OmissionReason, String)>,
) -> Result<Vec<OmissionRecord>, ContextError> {
    let mut omissions = Vec::new();
    for (atom_id, candidate) in candidates {
        if floor_ids.contains(atom_id) || admitted.contains_key(atom_id) {
            continue;
        }
        let item_cost = exact_cost(input, candidate).ok();
        let failure = failure_causes.get(atom_id).cloned();
        omissions.push(make_omission(
            input, candidate, supplied, item_cost, failure,
        )?);
    }
    omissions.sort_by(|left, right| left.atom_id.cmp(&right.atom_id));
    Ok(omissions)
}

struct ResultAssemblyInput<'a> {
    input: &'a AdmissionInput,
    input_digest: String,
    profile_digest: String,
    candidates:
        &'a BTreeMap<eliot_contracts::ArtifactId, &'a eliot_context_contracts::ContextCandidate>,
    admitted: BTreeMap<eliot_contracts::ArtifactId, AdmittedAtom>,
    omissions: &'a [OmissionRecord],
    supplied: &'a BTreeMap<
        eliot_contracts::ArtifactId,
        &'a eliot_context_contracts::SuppliedOmissionBinding,
    >,
    required_cost: u64,
    optional_cost: u64,
    fixed: u64,
}

fn assemble_result(assembly: ResultAssemblyInput<'_>) -> Result<AdmissionResult, ContextError> {
    let ResultAssemblyInput {
        input,
        input_digest,
        profile_digest,
        candidates,
        admitted,
        omissions,
        supplied,
        required_cost,
        optional_cost,
        fixed,
    } = assembly;
    let (admitted_set, selection_digest) = assemble_admitted_set(
        input,
        candidates,
        admitted,
        omissions,
        required_cost,
        optional_cost,
        fixed,
    )?;
    let evidence = eliot_context_contracts::AdmissionDecisionEvidence {
        binding: input.binding.clone(),
        decisions: all_decisions(input, &admitted_set, omissions),
        omissions: omissions.to_owned(),
        supplied_omissions: omissions
            .iter()
            .filter_map(|omission| supplied.get(&omission.atom_id).copied().cloned())
            .collect(),
        incomplete: None,
        economy: Some(admitted_set.economy.clone()),
        proof_ceiling: proof_ceiling(input),
    };
    let mut result = AdmissionResult {
        schema_version: eliot_context_contracts::CONTEXT_CONTRACT_VERSION,
        binding: input.binding.clone(),
        input_digest,
        recipe_digest: input.recipe.recipe_sha256.clone(),
        profile_digest,
        floor_id: input.floor.floor_id.clone(),
        outcome: ContextOutcome::Complete(admitted_set),
        evidence,
        selection_digest,
        result_digest: "0".repeat(64),
    };
    result.result_digest = eliot_context_contracts::canonical_digest(&result)?;
    result.validate_for(input)?;
    Ok(result)
}

fn assemble_admitted_set(
    input: &AdmissionInput,
    candidates: &BTreeMap<eliot_contracts::ArtifactId, &eliot_context_contracts::ContextCandidate>,
    admitted: BTreeMap<eliot_contracts::ArtifactId, AdmittedAtom>,
    omissions: &[OmissionRecord],
    required_cost: u64,
    optional_cost: u64,
    fixed: u64,
) -> Result<(AdmittedContextSet, String), ContextError> {
    let records: Vec<_> = admitted.into_values().collect();
    let admissions = records
        .iter()
        .map(|record| AdmissionRecord {
            atom_id: record.candidate.atom_id.clone(),
            provider_role: record.candidate.provider_role.clone(),
            disposition: record.disposition,
            rule_evidence: record.rule_evidence.clone(),
        })
        .collect::<Vec<_>>();
    let admitted_ids = records
        .iter()
        .map(|record| record.candidate.atom_id.clone())
        .collect::<Vec<_>>();
    let requested = candidates.keys().cloned().collect::<Vec<_>>();
    let displaced = omissions
        .iter()
        .map(|omission| omission.atom_id.clone())
        .collect::<Vec<_>>();
    let allocations = EconomyAllocations {
        fixed_overhead: input.recipe.capacity.fixed_overhead,
        output_reserve: input.recipe.capacity.output_reserve,
        review_reserve: input.recipe.capacity.review_reserve,
        admitted_required: required_cost,
        admitted_optional: optional_cost,
        remaining_headroom: input
            .recipe
            .capacity
            .route_capacity
            .checked_sub(fixed)
            .and_then(|value| value.checked_sub(required_cost))
            .and_then(|value| value.checked_sub(optional_cost))
            .ok_or(ContextError::Overflow)?,
        route_capacity: input.recipe.capacity.route_capacity,
    };
    let economy = ContextEconomyReceipt {
        binding: input.binding.clone(),
        decision_id: input.binding.decision_id.clone(),
        measurement: MeasurementRef {
            digest: "0".repeat(64),
            serializer: input.measurement_profile.serializer_id.clone(),
        },
        requested,
        admitted: admitted_ids,
        displaced,
        omissions: omissions.to_owned(),
        applied_rule: input.rule.rule_id.clone(),
        allocations,
        recipe_digest: input.recipe.recipe_sha256.clone(),
        // #1724 W5: the approved reusable policy revision this admission ran
        // under, read unchanged from the instance's own recorded
        // `DecisionRevision` after `validate_admission_contract` has run that
        // instance through the contract owner's own `ContextRecipe::validate`.
        // It is the value `ContextRecipePolicy::binds_recipe` compares with the
        // approved revision's `policy_sha256`, so the receipt is identifiable
        // from the approved policy alone and the View can be cross-compared
        // against this value rather than each record hashing itself.
        policy_sha256: input.recipe.decision.policy_sha256.clone(),
        receipt_digest: "0".repeat(64),
    };
    let mut admitted_set = AdmittedContextSet {
        binding: input.binding.clone(),
        records,
        admissions: admissions.clone(),
        floor: input.floor.floor.clone(),
        economy,
    };
    {
        let mut intermediate = admitted_set.economy.clone();
        let mut unsigned = intermediate.clone();
        unsigned.receipt_digest = "0".repeat(64);
        intermediate.receipt_digest = eliot_context_contracts::canonical_digest(&unsigned)?;
        admitted_set.economy.receipt_digest = intermediate.receipt_digest;
    }
    let selection_digest = admitted_set.canonical_payload_digest()?;
    admitted_set
        .economy
        .measurement
        .digest
        .clone_from(&selection_digest);
    let mut economy = admitted_set.economy.clone();
    let mut unsigned_economy = economy.clone();
    unsigned_economy.receipt_digest = "0".repeat(64);
    economy.receipt_digest = eliot_context_contracts::canonical_digest(&unsigned_economy)?;
    admitted_set
        .economy
        .receipt_digest
        .clone_from(&economy.receipt_digest);
    admitted_set.validate()?;
    Ok((admitted_set, selection_digest))
}

struct OptionalSelectionInput<'a> {
    input: &'a AdmissionInput,
    candidates:
        &'a BTreeMap<eliot_contracts::ArtifactId, &'a eliot_context_contracts::ContextCandidate>,
    priorities:
        &'a BTreeMap<eliot_contracts::ArtifactId, &'a eliot_context_contracts::CandidatePriority>,
    supplied: &'a BTreeMap<
        eliot_contracts::ArtifactId,
        &'a eliot_context_contracts::SuppliedOmissionBinding,
    >,
    floor_ids: &'a BTreeSet<eliot_contracts::ArtifactId>,
    admitted: &'a mut BTreeMap<eliot_contracts::ArtifactId, AdmittedAtom>,
    fixed: u64,
    required_cost: u64,
    units: Option<&'a UnitGroupBinding>,
}

enum OptionalDecision {
    Include(u64),
    Omit((OmissionReason, String)),
}

type FailureCauses = BTreeMap<eliot_contracts::ArtifactId, (OmissionReason, String)>;
type RequiredSelection = Result<
    (
        BTreeMap<eliot_contracts::ArtifactId, AdmittedAtom>,
        u64,
        u64,
    ),
    DecisionContextIncomplete,
>;

fn select_optional(
    selection: OptionalSelectionInput<'_>,
) -> Result<(u64, FailureCauses), ContextError> {
    let OptionalSelectionInput {
        input,
        candidates,
        priorities,
        supplied,
        floor_ids,
        admitted,
        fixed,
        required_cost,
        units,
    } = selection;
    let mut failure_causes = BTreeMap::new();
    let mut optional_ids: Vec<_> = candidates
        .keys()
        .filter(|id| !floor_ids.contains(*id))
        .cloned()
        .collect();
    optional_ids.sort_by(|left, right| {
        let Some(l) = priorities.get(left) else {
            return std::cmp::Ordering::Equal;
        };
        let Some(r) = priorities.get(right) else {
            return std::cmp::Ordering::Equal;
        };
        (l.class, l.ordinal, left).cmp(&(r.class, r.ordinal, right))
    });
    let available = input
        .recipe
        .capacity
        .route_capacity
        .checked_sub(fixed)
        .and_then(|value| value.checked_sub(required_cost))
        .ok_or(ContextError::Overflow)?;
    let mut selection = OptionalSelection {
        input,
        candidates,
        supplied,
        floor_ids,
        admitted,
        available,
        optional_cost: 0,
        units,
    };
    for atom_id in optional_ids {
        if selection.admitted.contains_key(&atom_id) {
            continue;
        }
        match selection.consider(&atom_id)? {
            OptionalDecision::Include(value) => {
                selection.optional_cost = selection
                    .optional_cost
                    .checked_add(value)
                    .ok_or(ContextError::Overflow)?;
            }
            OptionalDecision::Omit(failure) => {
                failure_causes.insert(atom_id, failure);
            }
        }
    }
    Ok((selection.optional_cost, failure_causes))
}

struct OptionalSelection<'a> {
    input: &'a AdmissionInput,
    candidates:
        &'a BTreeMap<eliot_contracts::ArtifactId, &'a eliot_context_contracts::ContextCandidate>,
    supplied: &'a BTreeMap<
        eliot_contracts::ArtifactId,
        &'a eliot_context_contracts::SuppliedOmissionBinding,
    >,
    floor_ids: &'a BTreeSet<eliot_contracts::ArtifactId>,
    admitted: &'a mut BTreeMap<eliot_contracts::ArtifactId, AdmittedAtom>,
    available: u64,
    optional_cost: u64,
    units: Option<&'a UnitGroupBinding>,
}

impl OptionalSelection<'_> {
    fn consider(
        &mut self,
        atom_id: &eliot_contracts::ArtifactId,
    ) -> Result<OptionalDecision, ContextError> {
        let candidate = self
            .candidates
            .get(atom_id)
            .ok_or(ContextError::DenominatorMismatch)?;
        let mut closure = optional_closure(atom_id, self.floor_ids, self.candidates)?;
        // I12.13 "Bind indivisible groups": an optional member of an indivisible
        // unit is selected with every member the owner declared for that unit, so
        // the existing all-or-nothing `fits` decision below already covers the
        // whole group. A group that cannot fit is omitted whole, never partially.
        if let Some(units) = self.units {
            closure = units.group_closure(&closure)?;
        }
        let closure_candidates = closure
            .iter()
            .filter_map(|id| self.candidates.get(id).copied())
            .filter(|candidate| !self.admitted.contains_key(&candidate.atom_id))
            .collect::<Vec<_>>();
        let closure_missing = closure.iter().any(|id| !self.candidates.contains_key(id));
        let cost = match candidate.availability {
            AtomAvailability::PresentCurrent => match exact_cost(self.input, candidate) {
                Ok(value) => Some(value),
                Err(ContextError::UnknownMeasurement) => None,
                Err(error) => return Err(error),
            },
            _ => None,
        };
        let closure_cost = closure_candidates.iter().try_fold(0_u64, |total, item| {
            exact_cost(self.input, item)
                .and_then(|value| total.checked_add(value).ok_or(ContextError::Overflow))
        });
        let closure_current = closure_candidates
            .iter()
            .all(|item| item.availability == AtomAvailability::PresentCurrent);
        // A candidate the owner metadata does not describe, or whose degraded
        // envelope names no exact handle of its own, is not an established whole
        // unit. Folding this into `fits` gives the whole group its allowed
        // disposition instead of admitting part of one.
        let closure_established = self.units.is_none_or(|units| {
            closure_candidates
                .iter()
                .all(|item| units.admits_representation(item))
        });
        let fits = !closure_missing
            && closure_current
            && closure_established
            && candidate.availability == AtomAvailability::PresentCurrent
            && cost.is_some()
            && closure_cost.as_ref().is_ok_and(|value| {
                self.optional_cost
                    .checked_add(*value)
                    .is_some_and(|total| total <= self.available)
            });
        if fits {
            let value = closure_cost?;
            for item in closure_candidates {
                validate_representation(self.input, item, self.supplied, false)?;
                let disposition = if item.representation.kind() == RepresentationKind::Handle {
                    AdmissionDisposition::HandleOnly
                } else {
                    AdmissionDisposition::Include
                };
                self.admitted.insert(
                    item.atom_id.clone(),
                    AdmittedAtom {
                        candidate: item.clone(),
                        disposition,
                        rule_evidence: self.input.rule.rule_id.clone(),
                    },
                );
            }
            Ok(OptionalDecision::Include(value))
        } else {
            // An unestablished whole unit is reported under its own reason
            // rather than falling through to the capacity default, so a truthful
            // optional omission never claims a group was crowded out when it was
            // actually rejected for lacking owner-issued unit evidence.
            let unestablished = self.units.and_then(|units| {
                closure_candidates
                    .iter()
                    .find(|item| !units.admits_representation(item))
                    .map(|item| {
                        (
                            OmissionReason::Policy,
                            format!(
                                "candidate {} has no owner-issued complete unit metadata or owner-named exact handle",
                                item.atom_id
                            ),
                        )
                    })
            });
            let failure = unestablished.or(optional_failure_cause(
                self.input,
                atom_id,
                &closure,
                self.candidates,
                &closure_candidates,
                closure_missing,
            )?);
            Ok(OptionalDecision::Omit(failure.unwrap_or((
                OmissionReason::Capacity,
                "optional allocation exceeds remaining capacity".to_owned(),
            ))))
        }
    }
}

fn prepare_floor(
    input: &AdmissionInput,
    candidates: &BTreeMap<eliot_contracts::ArtifactId, &eliot_context_contracts::ContextCandidate>,
    supplied: &BTreeMap<
        eliot_contracts::ArtifactId,
        &eliot_context_contracts::SuppliedOmissionBinding,
    >,
    units: Option<&UnitGroupBinding>,
) -> Result<Result<BTreeSet<eliot_contracts::ArtifactId>, DecisionContextIncomplete>, ContextError>
{
    let mut floor_ids = floor_closure(input, candidates)?;
    // I12.13 "Bind indivisible groups": a required member of an indivisible unit
    // makes every member the owner declared for that unit required too. The
    // group is therefore admitted as its required closure or it is not admitted
    // at all; a member absent from this candidate set is reported by the
    // unchanged `floor_gap` below as an explicit gap, never dropped quietly.
    if let Some(units) = units {
        floor_ids = units.group_closure(&floor_ids)?;
    }
    for candidate in candidates.values() {
        if !floor_ids.contains(&candidate.atom_id)
            && (candidate.protected
                || candidate.loss_policy == eliot_context_contracts::LossPolicy::NonDroppable)
        {
            return Err(ContextError::MissingFloor);
        }
        validate_representation(
            input,
            candidate,
            supplied,
            floor_ids.contains(&candidate.atom_id),
        )?;
        // A candidate the owner metadata does not describe is not an established
        // whole unit, and a degraded unit may only stand as the exact handle its
        // own envelope names. `WHOLE` on a content string establishes neither.
        if let Some(units) = units
            && !units.admits_representation(candidate)
        {
            return Err(ContextError::WholeUnitRequired);
        }
    }
    if let Some(incomplete) = floor_gap(input, candidates, &floor_ids)? {
        return Ok(Err(incomplete));
    }
    Ok(Ok(floor_ids))
}

fn select_required(
    input: &AdmissionInput,
    candidates: &BTreeMap<eliot_contracts::ArtifactId, &eliot_context_contracts::ContextCandidate>,
    floor_ids: &BTreeSet<eliot_contracts::ArtifactId>,
) -> Result<RequiredSelection, ContextError> {
    let mut admitted = BTreeMap::new();
    let mut required_cost = 0_u64;
    for atom_id in floor_ids {
        let candidate = candidates.get(atom_id).ok_or(ContextError::MissingFloor)?;
        let cost = exact_cost(input, candidate)?;
        required_cost = if let Some(total) = required_cost.checked_add(cost) {
            total
        } else {
            let mut incomplete =
                DecisionContextIncomplete::new(input.floor.floor.rule_evidence.clone());
            incomplete.oversized.extend(floor_ids.iter().cloned());
            incomplete
                .measurements
                .extend(floor_measurement_ids(input, floor_ids));
            incomplete.reopening_requirements.push(
                "reopen with a qualified route envelope that can hold the exact Safety Floor"
                    .to_owned(),
            );
            return Ok(Err(incomplete));
        };
        let disposition = if candidate.representation.kind() == RepresentationKind::Handle {
            AdmissionDisposition::HandleOnly
        } else {
            AdmissionDisposition::Include
        };
        admitted.insert(
            atom_id.clone(),
            AdmittedAtom {
                candidate: (*candidate).clone(),
                disposition,
                rule_evidence: input.rule.rule_id.clone(),
            },
        );
    }
    let fixed = fixed_cost(input)?;
    let Some(floor_total) = fixed.checked_add(required_cost) else {
        let mut incomplete =
            DecisionContextIncomplete::new(input.floor.floor.rule_evidence.clone());
        incomplete.oversized.extend(floor_ids.iter().cloned());
        incomplete
            .measurements
            .extend(floor_measurement_ids(input, floor_ids));
        incomplete.reopening_requirements.push(
            "reopen with a qualified route envelope that can hold the exact Safety Floor"
                .to_owned(),
        );
        return Ok(Err(incomplete));
    };
    if floor_total > input.recipe.capacity.route_capacity {
        let mut incomplete =
            DecisionContextIncomplete::new(input.floor.floor.rule_evidence.clone());
        incomplete.oversized.extend(floor_ids.iter().cloned());
        incomplete
            .measurements
            .extend(floor_measurement_ids(input, floor_ids));
        incomplete.reopening_requirements.push(
            "reopen with a qualified route envelope that can hold the exact Safety Floor"
                .to_owned(),
        );
        incomplete.validate()?;
        return Ok(Err(incomplete));
    }
    Ok(Ok((admitted, required_cost, fixed)))
}

pub(crate) fn floor_closure(
    input: &AdmissionInput,
    candidates: &BTreeMap<eliot_contracts::ArtifactId, &eliot_context_contracts::ContextCandidate>,
) -> Result<BTreeSet<eliot_contracts::ArtifactId>, ContextError> {
    let mut queue = VecDeque::new();
    queue.extend(input.floor.floor.mandatory_atoms.iter().cloned());
    queue.extend(
        input
            .floor
            .floor
            .interpretation_dependencies
            .iter()
            .cloned(),
    );
    queue.extend(
        input
            .floor
            .floor
            .members
            .iter()
            .flat_map(|member| member.required_dependencies.iter().cloned()),
    );
    let mut visited = BTreeSet::new();
    while let Some(atom_id) = queue.pop_front() {
        if !visited.insert(atom_id.clone()) {
            continue;
        }
        if let Some(candidate) = candidates.get(&atom_id) {
            queue.extend(candidate.dependencies.iter().cloned());
        }
        if visited.len() > 4096 {
            return Err(ContextError::Bounds {
                field: "floor.closure",
            });
        }
    }
    Ok(visited)
}

fn validate_selection_contract(input: &AdmissionInput) -> Result<(), ContextError> {
    let recipe_slots: BTreeSet<_> = input.recipe.denominator.requested.iter().collect();
    let candidate_slots: BTreeSet<_> = input.candidates.denominator.requested.iter().collect();
    if recipe_slots != candidate_slots {
        return Err(ContextError::DenominatorMismatch);
    }
    let recipe_roles: BTreeSet<_> = input.recipe.mandatory_roles.iter().collect();
    let floor_roles: BTreeSet<_> = input.floor.floor.mandatory_roles.iter().collect();
    if recipe_roles != floor_roles {
        return Err(ContextError::DenominatorMismatch);
    }
    Ok(())
}

fn floor_gap(
    input: &AdmissionInput,
    candidates: &BTreeMap<eliot_contracts::ArtifactId, &eliot_context_contracts::ContextCandidate>,
    floor_ids: &BTreeSet<eliot_contracts::ArtifactId>,
) -> Result<Option<DecisionContextIncomplete>, ContextError> {
    let mut gap = DecisionContextIncomplete::new(input.floor.floor.rule_evidence.clone());
    for atom_id in floor_ids {
        let expected = input
            .floor
            .floor
            .members
            .iter()
            .find(|member| member.atom_id == *atom_id);
        let Some(candidate) = candidates.get(atom_id) else {
            gap.missing.push(atom_id.clone());
            continue;
        };
        let state = expected.map_or(candidate.availability, |member| member.availability);
        match state {
            AtomAvailability::PresentCurrent => {
                if candidate.availability != AtomAvailability::PresentCurrent {
                    gap.stale.push(atom_id.clone());
                } else if let Err(error) = exact_cost(input, candidate) {
                    if error != ContextError::UnknownMeasurement {
                        return Err(error);
                    }
                    let measurement = input
                        .measurement(&candidate.atom_id, candidate.representation.kind())
                        .ok_or(ContextError::DenominatorMismatch)?;
                    match measurement.cost {
                        AdmissionMeasuredCost::Unavailable => gap.unavailable.push(atom_id.clone()),
                        AdmissionMeasuredCost::Unknown => gap.unknown.push(atom_id.clone()),
                        _ => return Err(ContextError::UnknownMeasurement),
                    }
                    gap.measurements.push(measurement.measurement_id.clone());
                    gap.reopening_requirements.push(format!(
                        "reopen measurement {} for exact UTF-8 contribution",
                        measurement.measurement_id
                    ));
                }
            }
            AtomAvailability::Missing => gap.missing.push(atom_id.clone()),
            AtomAvailability::Stale => gap.stale.push(atom_id.clone()),
            AtomAvailability::Blocked => gap.blocked.push(atom_id.clone()),
            AtomAvailability::Unavailable => gap.unavailable.push(atom_id.clone()),
            AtomAvailability::Omitted => gap.omitted.push(atom_id.clone()),
            AtomAvailability::Exhausted => gap.exhausted.push(atom_id.clone()),
            AtomAvailability::Unknown => gap.unknown.push(atom_id.clone()),
            AtomAvailability::KnownEmpty => gap.known_empty.push(atom_id.clone()),
            AtomAvailability::Partial => gap.partial.push(atom_id.clone()),
        }
        if state != AtomAvailability::PresentCurrent {
            if let Some(measurement) =
                input.measurement(&candidate.atom_id, candidate.representation.kind())
            {
                gap.measurements.push(measurement.measurement_id.clone());
            }
            gap.reopening_requirements.push(format!(
                "reopen mandatory atom {atom_id} after its floor gap is resolved"
            ));
        }
    }
    for disposition in &input.floor.floor.providers.dispositions {
        if disposition.state != AtomAvailability::PresentCurrent {
            gap.provider_gaps
                .push(eliot_context_contracts::ProviderRoleGap {
                    slot: disposition.slot.clone(),
                    state: disposition.state,
                });
        }
    }
    for values in [
        &mut gap.missing,
        &mut gap.stale,
        &mut gap.blocked,
        &mut gap.unavailable,
        &mut gap.omitted,
        &mut gap.exhausted,
        &mut gap.unknown,
        &mut gap.known_empty,
        &mut gap.partial,
    ] {
        values.sort();
        values.dedup();
    }
    gap.provider_gaps.sort_by(|a, b| a.slot.cmp(&b.slot));
    gap.provider_gaps.dedup_by(|a, b| a.slot == b.slot);
    gap.measurements.sort();
    gap.measurements.dedup();
    if gap.missing.is_empty()
        && gap.stale.is_empty()
        && gap.blocked.is_empty()
        && gap.unavailable.is_empty()
        && gap.omitted.is_empty()
        && gap.exhausted.is_empty()
        && gap.unknown.is_empty()
        && gap.known_empty.is_empty()
        && gap.partial.is_empty()
        && gap.provider_gaps.is_empty()
    {
        Ok(None)
    } else {
        gap.validate()?;
        Ok(Some(gap))
    }
}

fn optional_closure(
    root: &eliot_contracts::ArtifactId,
    floor_ids: &BTreeSet<eliot_contracts::ArtifactId>,
    candidates: &BTreeMap<eliot_contracts::ArtifactId, &eliot_context_contracts::ContextCandidate>,
) -> Result<BTreeSet<eliot_contracts::ArtifactId>, ContextError> {
    let mut queue = VecDeque::from([root.clone()]);
    let mut closure = BTreeSet::new();
    while let Some(atom_id) = queue.pop_front() {
        if floor_ids.contains(&atom_id) || !closure.insert(atom_id.clone()) {
            continue;
        }
        if let Some(candidate) = candidates.get(&atom_id) {
            queue.extend(candidate.dependencies.iter().cloned());
        }
        if closure.len() > 4096 {
            return Err(ContextError::Bounds {
                field: "optional.closure",
            });
        }
    }
    Ok(closure)
}

fn floor_measurement_ids(
    input: &AdmissionInput,
    floor_ids: &BTreeSet<eliot_contracts::ArtifactId>,
) -> Vec<eliot_contracts::ArtifactId> {
    let mut ids = input
        .measurements
        .iter()
        .filter(|measurement| floor_ids.contains(&measurement.atom_id))
        .map(|measurement| measurement.measurement_id.clone())
        .collect::<Vec<_>>();
    ids.sort();
    ids.dedup();
    ids
}

fn fixed_cost(input: &AdmissionInput) -> Result<u64, ContextError> {
    input
        .recipe
        .capacity
        .fixed_overhead
        .checked_add(input.recipe.capacity.output_reserve)
        .and_then(|value| value.checked_add(input.recipe.capacity.review_reserve))
        .ok_or(ContextError::Overflow)
}

fn exact_cost(
    input: &AdmissionInput,
    candidate: &eliot_context_contracts::ContextCandidate,
) -> Result<u64, ContextError> {
    let measurement = input
        .measurement(&candidate.atom_id, candidate.representation.kind())
        .ok_or(ContextError::DenominatorMismatch)?;
    match measurement.cost {
        AdmissionMeasuredCost::ExactUtf8Bytes { value } => Ok(value),
        AdmissionMeasuredCost::Unknown | AdmissionMeasuredCost::Unavailable => {
            Err(ContextError::UnknownMeasurement)
        }
        AdmissionMeasuredCost::ConservativeStu { .. }
        | AdmissionMeasuredCost::ExactTokenizer { .. } => Err(ContextError::UnknownMeasurement),
    }
}

fn optional_failure_cause(
    input: &AdmissionInput,
    root: &eliot_contracts::ArtifactId,
    closure: &BTreeSet<eliot_contracts::ArtifactId>,
    candidates: &BTreeMap<eliot_contracts::ArtifactId, &eliot_context_contracts::ContextCandidate>,
    closure_candidates: &[&eliot_context_contracts::ContextCandidate],
    closure_missing: bool,
) -> Result<Option<(OmissionReason, String)>, ContextError> {
    if closure_missing {
        let missing = closure
            .iter()
            .find(|atom_id| !candidates.contains_key(*atom_id))
            .map_or_else(|| "unknown".to_owned(), ToString::to_string);
        return Ok(Some((
            OmissionReason::Blocked,
            format!("required dependency closure is missing atom {missing}"),
        )));
    }
    for candidate in closure_candidates {
        let cause = match candidate.availability {
            AtomAvailability::PresentCurrent => match exact_cost(input, candidate) {
                Ok(_) => None,
                Err(ContextError::UnknownMeasurement) => {
                    let measurement = input
                        .measurement(&candidate.atom_id, candidate.representation.kind())
                        .ok_or(ContextError::DenominatorMismatch)?;
                    Some(match measurement.cost {
                        AdmissionMeasuredCost::Unavailable => (
                            OmissionReason::MeasurementUnavailable,
                            format!("measurement {} is unavailable", measurement.measurement_id),
                        ),
                        AdmissionMeasuredCost::Unknown => (
                            OmissionReason::UnknownMeasurement,
                            format!(
                                "measurement {} has unknown exact UTF-8 contribution",
                                measurement.measurement_id
                            ),
                        ),
                        _ => return Err(ContextError::UnknownMeasurement),
                    })
                }
                Err(error) => return Err(error),
            },
            AtomAvailability::Stale => Some((
                OmissionReason::Stale,
                format!("candidate {} is stale", candidate.atom_id),
            )),
            AtomAvailability::Blocked => Some((
                OmissionReason::Blocked,
                format!("candidate {} is blocked", candidate.atom_id),
            )),
            AtomAvailability::Unavailable
            | AtomAvailability::Missing
            | AtomAvailability::KnownEmpty
            | AtomAvailability::Partial
            | AtomAvailability::Exhausted => Some((
                if candidate.atom_id == *root {
                    OmissionReason::Unavailable
                } else {
                    OmissionReason::Blocked
                },
                if candidate.atom_id == *root {
                    format!(
                        "candidate {} is {:?}",
                        candidate.atom_id, candidate.availability
                    )
                } else {
                    format!(
                        "required dependency {} is {:?}",
                        candidate.atom_id, candidate.availability
                    )
                },
            )),
            AtomAvailability::Unknown => Some((
                if candidate.atom_id == *root {
                    OmissionReason::Policy
                } else {
                    OmissionReason::Blocked
                },
                if candidate.atom_id == *root {
                    UNKNOWN_AVAILABILITY_CONSTRAINT.to_owned()
                } else {
                    format!("candidate {} state is unknown", candidate.atom_id)
                },
            )),
            AtomAvailability::Omitted => Some((
                OmissionReason::Policy,
                format!(
                    "candidate {} was already omitted by policy",
                    candidate.atom_id
                ),
            )),
        };
        if cause.is_some() {
            return Ok(cause);
        }
    }
    Ok(None)
}

fn validate_representation(
    input: &AdmissionInput,
    candidate: &eliot_context_contracts::ContextCandidate,
    supplied: &BTreeMap<
        eliot_contracts::ArtifactId,
        &eliot_context_contracts::SuppliedOmissionBinding,
    >,
    required: bool,
) -> Result<(), ContextError> {
    let Some(policy) = input
        .recipe
        .role_policies
        .iter()
        .find(|policy| policy.role == candidate.provider_role.role)
    else {
        return Err(ContextError::WholeUnitRequired);
    };
    if !policy
        .allowed_representations
        .contains(&candidate.representation.kind())
    {
        return Err(ContextError::WholeUnitRequired);
    }
    // Selection only: every supplied representation kind already passed
    // `ContextCandidate::validate` (loss-policy compatibility, non-empty
    // extract manifest, well-formed summary source digest) and the exact
    // measurement closure. EXTRACTIVE and SUMMARY forms issued by the
    // producer are therefore selectable here exactly like WHOLE; nothing is
    // generated, rewritten, or truncated by this gate. A missing, stale, or
    // incompatible measurement makes the option unavailable at costing time.
    if let eliot_context_contracts::AtomRepresentation::Handle { handle } =
        &candidate.representation
    {
        let Some(binding) = supplied.get(&candidate.atom_id) else {
            if required {
                return Err(ContextError::OmissionHandleInvalid);
            }
            return Ok(());
        };
        let Some(expansion) = &binding.expansion else {
            return Err(ContextError::OmissionHandleInvalid);
        };
        if expansion.handle_id != *handle
            || expansion.context != candidate.binding
            || expansion.atom_id != candidate.atom_id
            || expansion.source_id.as_str() != candidate.source.source_id.as_str()
            || expansion.source_revision != candidate.source.revision
            || expansion.decision != input.recipe.decision
            || expansion.provider_role != candidate.provider_role
        {
            return Err(ContextError::OmissionHandleInvalid);
        }
    }
    Ok(())
}

fn make_omission(
    input: &AdmissionInput,
    candidate: &eliot_context_contracts::ContextCandidate,
    supplied: &BTreeMap<
        eliot_contracts::ArtifactId,
        &eliot_context_contracts::SuppliedOmissionBinding,
    >,
    cost: Option<u64>,
    cause: Option<(OmissionReason, String)>,
) -> Result<OmissionRecord, ContextError> {
    let binding = supplied
        .get(&candidate.atom_id)
        .ok_or(ContextError::OmissionHandleInvalid)?;
    let (reason, constraint) = cause.unwrap_or_else(|| match candidate.availability {
        AtomAvailability::Stale => (OmissionReason::Stale, "candidate is stale".to_owned()),
        AtomAvailability::Blocked => (OmissionReason::Blocked, "candidate is blocked".to_owned()),
        AtomAvailability::Unavailable => (
            OmissionReason::Unavailable,
            "provider unavailable".to_owned(),
        ),
        AtomAvailability::Missing => (
            OmissionReason::Unavailable,
            "candidate is missing".to_owned(),
        ),
        AtomAvailability::Unknown => (
            OmissionReason::Policy,
            UNKNOWN_AVAILABILITY_CONSTRAINT.to_owned(),
        ),
        AtomAvailability::KnownEmpty => (
            OmissionReason::Unavailable,
            "provider has authoritative empty coverage".to_owned(),
        ),
        AtomAvailability::Partial => (
            OmissionReason::Unavailable,
            "provider coverage is partial".to_owned(),
        ),
        AtomAvailability::Omitted => (
            OmissionReason::Policy,
            "candidate was already omitted by policy".to_owned(),
        ),
        AtomAvailability::Exhausted => (
            OmissionReason::Unavailable,
            "provider source is exhausted".to_owned(),
        ),
        AtomAvailability::PresentCurrent if cost.is_none() => {
            let unavailable = input
                .measurement(&candidate.atom_id, candidate.representation.kind())
                .is_some_and(|measurement| {
                    matches!(measurement.cost, AdmissionMeasuredCost::Unavailable)
                });
            if unavailable {
                (
                    OmissionReason::MeasurementUnavailable,
                    "measurement owner could not provide an exact contribution".to_owned(),
                )
            } else {
                (
                    OmissionReason::UnknownMeasurement,
                    "exact UTF-8 contribution is unknown".to_owned(),
                )
            }
        }
        AtomAvailability::PresentCurrent => (
            OmissionReason::Capacity,
            "optional allocation exceeds remaining capacity".to_owned(),
        ),
    });
    let task_revision = input
        .binding
        .state_fence
        .task_revision
        .ok_or(ContextError::OmissionHandleInvalid)?;
    let mut omission = OmissionRecord {
        atom_id: candidate.atom_id.clone(),
        source_id: eliot_contracts::ArtifactId::new(candidate.source.source_id.as_str())
            .map_err(|_| ContextError::InvalidField("omission.source_id"))?,
        provider_role: candidate.provider_role.clone(),
        decision: input.recipe.decision.clone(),
        task_revision,
        reason,
        competing_constraint: constraint,
        measured_cost: cost,
        allowed_representation: binding.policy,
        expansion: binding.expansion.clone(),
        non_recoverable_reason: binding.non_recoverable_reason,
        authorization_requirement: binding.authorization_requirement.clone(),
        privacy_requirement: binding.privacy_requirement.clone(),
        proof_requirement: binding.proof_requirement.clone(),
        expires: binding.expires.clone(),
        invalidation: binding.invalidation.clone(),
        digest: "0".repeat(64),
    };
    omission.digest = eliot_context_contracts::canonical_digest(&omission)?;
    Ok(omission)
}

fn all_decisions(
    input: &AdmissionInput,
    admitted: &AdmittedContextSet,
    omissions: &[OmissionRecord],
) -> Vec<AdmissionRecord> {
    let mut decisions = input
        .candidates
        .candidates
        .iter()
        .map(|candidate| {
            if let Some(record) = admitted
                .records
                .iter()
                .find(|record| record.candidate.atom_id == candidate.atom_id)
            {
                AdmissionRecord {
                    atom_id: candidate.atom_id.clone(),
                    provider_role: candidate.provider_role.clone(),
                    disposition: record.disposition,
                    rule_evidence: record.rule_evidence.clone(),
                }
            } else {
                let disposition = omissions
                    .iter()
                    .find(|omission| omission.atom_id == candidate.atom_id)
                    .map_or(
                        AdmissionDisposition::Unavailable,
                        |omission| match omission.reason {
                            OmissionReason::Stale | OmissionReason::UnknownMeasurement => {
                                AdmissionDisposition::Revalidate
                            }
                            OmissionReason::Blocked => AdmissionDisposition::Blocked,
                            OmissionReason::Unavailable
                            | OmissionReason::MeasurementUnavailable => {
                                AdmissionDisposition::Unavailable
                            }
                            OmissionReason::Capacity | OmissionReason::ProtectedReserve => {
                                AdmissionDisposition::OverBudget
                            }
                            OmissionReason::Privacy
                            | OmissionReason::Authority
                            | OmissionReason::Policy => {
                                if omission.competing_constraint == UNKNOWN_AVAILABILITY_CONSTRAINT
                                {
                                    AdmissionDisposition::Revalidate
                                } else {
                                    AdmissionDisposition::Suppress
                                }
                            }
                        },
                    );
                AdmissionRecord {
                    atom_id: candidate.atom_id.clone(),
                    provider_role: candidate.provider_role.clone(),
                    disposition,
                    rule_evidence: input.rule.rule_id.clone(),
                }
            }
        })
        .collect::<Vec<_>>();
    decisions.sort_by(|left, right| left.atom_id.cmp(&right.atom_id));
    decisions
}

fn proof_ceiling(input: &AdmissionInput) -> ProofCeiling {
    let _ = input;
    ProofCeiling::Observation
}

fn incomplete_result(
    input: &AdmissionInput,
    input_digest: String,
    profile_digest: String,
    incomplete: &DecisionContextIncomplete,
) -> Result<AdmissionResult, ContextError> {
    let mut decisions = input
        .candidates
        .candidates
        .iter()
        .map(|candidate| AdmissionRecord {
            atom_id: candidate.atom_id.clone(),
            provider_role: candidate.provider_role.clone(),
            disposition: AdmissionDisposition::Blocked,
            rule_evidence: input.rule.rule_id.clone(),
        })
        .collect::<Vec<_>>();
    decisions.sort_by(|left, right| left.atom_id.cmp(&right.atom_id));
    let evidence = eliot_context_contracts::AdmissionDecisionEvidence {
        binding: input.binding.clone(),
        decisions,
        omissions: Vec::new(),
        supplied_omissions: Vec::new(),
        incomplete: Some(incomplete.clone()),
        economy: None,
        proof_ceiling: proof_ceiling(input),
    };
    let mut result = AdmissionResult {
        schema_version: eliot_context_contracts::CONTEXT_CONTRACT_VERSION,
        binding: input.binding.clone(),
        input_digest,
        recipe_digest: input.recipe.recipe_sha256.clone(),
        profile_digest,
        floor_id: input.floor.floor_id.clone(),
        outcome: ContextOutcome::Incomplete(incomplete.clone()),
        evidence,
        selection_digest: eliot_context_contracts::canonical_digest(&incomplete)?,
        result_digest: "0".repeat(64),
    };
    result.result_digest = eliot_context_contracts::canonical_digest(&result)?;
    result.validate_for(input)?;
    Ok(result)
}
