//! Production construction site for the A-14b -> A-05 grounding receipt
//! carrier that this functional cell owns.
//!
//! Ownership. `crates/smart/cognitive-wave-10.toml` records
//! `[[ownership]] public_type = "GroundingValidationInput"`,
//! `rust_owner = "eliot-dreamer-claim-grounding"`, and this module's
//! `module.toml` declares the cell
//! (`smart.dreamer.claim_grounding`, `agent_order = 14`) whose declared output
//! is the `GroundedDreamDraft` handoff value and whose declared consumer is
//! `eliot-dreamer-candidate-validation`. The carrier type itself is a frozen
//! contracts-crate value
//! (`crates/smart/eliot-dreamer-contracts/src/validation/structured/mod.rs`),
//! so this crate owns the single production *construction* site for it, and
//! `A2.3`/`ARCH-MOD-03` ("one causal responsibility, one owner") keeps that
//! site here instead of in a composition root.
//!
//! Data provenance. Every field of the carrier is either owner-computed by
//! grounding in this crate or explicitly supplied by the A-05 caller
//! ([`ValidationAttachment`]). Nothing is synthesised here: the grounded leg is
//! passed through unchanged, the A-05 leg is never filled from grounding prose,
//! ledger residues, or model text, and an absent optional attachment stays
//! absent instead of becoming a fabricated empty value.
//!
//! Authority ceiling. Issue #262 hard boundary: "model output never
//! self-certifies grounding". `I9.5` states the same rule for the sibling
//! packet: "Sections `resolved` and `evidence` are populated/checked from
//! Governor records. Model text cannot declare them confirmed." This cell's own
//! declared invariant is "grounding does not promote epistemic status". The
//! producer therefore refuses any grounded value whose retained ledger records
//! claim an epistemic position above the candidate-only ceiling, so a
//! self-consistent but self-certified ledger cannot be sealed as a grounding
//! receipt.
//!
//! The ceiling has exactly one declaration in this crate:
//! `evidence::CANDIDATE_ONLY_CEILING`. It is not restated here, and this
//! module claims nothing about what a bare cap call implies on its own. The
//! value is enforced by these sites, all of which read that one symbol:
//!
//! - `evidence::evaluate_claim`, the unconditional cap applied to every record
//!   this crate produces;
//! - `grounding::ground_draft_with_controls`, the curation-screen cap;
//! - `grounding::aggregate_parent_record`, the aggregation finalize cap;
//! - `refuse_self_certified_grounding` below, which refuses a retained record
//!   that claims a position above the same ceiling.
//!
//! If any one of the first three were relaxed on its own, that divergence would
//! now be visible as a mismatch against the single constant rather than hidden
//! behind a private copy here. The refusal is not a semantic gate: A-05
//! (`eliot-dreamer-candidate-validation`) remains the acceptance owner, and the
//! carrier never becomes a receipt, a promotion, or current truth.

use eliot_dreamer_contracts::grounding::GroundedDreamDraft;
use eliot_dreamer_contracts::validation::error::summarize_contract;
use eliot_dreamer_contracts::{
    BudgetUsage, DreamDraftValidationError, GroundingValidationInput, PreservationReport,
    RivalDeclarationSet, ValidationPolicy,
};

use crate::evidence;
use crate::grounding::{GroundingRequest, ground_draft_with_controls};

/// Refusal field for a self-certified epistemic position.
const SELF_CERTIFIED_FIELD: &str = "grounding.assertability_ceiling";

/// Independently supplied A-05 data for one grounding handoff.
///
/// Every field is explicit supplied data. The attachment carries no claim
/// material and no grounding material: it cannot assert, restate, or substitute
/// for a grounded disposition, which is why nothing here can self-certify
/// grounding. The two optional fields are the frozen contract's own optional
/// supplied values; their absence is recorded as absence and never filled from
/// the grounded value, the ledger, or model text.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidationAttachment {
    /// A-05 validation policy, required to be bound to this job's
    /// `policy_ref` by the carrier's own validation.
    pub policy: ValidationPolicy,
    /// A-05 budget usage observation, required to fit the retained job budget.
    pub usage: BudgetUsage,
    /// Seven-dimension preservation report supplied to A-05.
    pub preservation: PreservationReport,
    /// Explicit observation time used for the A-05 deadline comparison.
    pub observation_time_ms: Option<u64>,
    /// Explicit cancellation observation supplied to A-05.
    pub cancellation_requested: bool,
    /// Optional supplied rival declarations, retained before receipt binding.
    pub rival_declarations: Option<RivalDeclarationSet>,
}

/// Complete owned input for the production A-14b -> A-05 handoff.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroundingValidationRequest {
    /// The complete A03 v2 grounding context, bound by this crate.
    pub grounding: GroundingRequest,
    /// Independently supplied A-05 data.
    pub validation: ValidationAttachment,
}

impl GroundingValidationRequest {
    /// Creates a handoff request from the two independently owned halves.
    #[must_use]
    pub fn new(grounding: GroundingRequest, validation: ValidationAttachment) -> Self {
        Self {
            grounding,
            validation,
        }
    }
}

/// Production entry for the A-14b -> A-05 handoff.
///
/// Grounds the supplied A03 v2 context through this crate's own production
/// grounding entry ([`ground_draft_with_controls`]) and then binds the A-05
/// carrier through the production construction site
/// ([`bind_validation_input`]). This performs grounding and carrier binding
/// only: it issues no receipt, runs no A-05 semantic gate, retrieves nothing,
/// and promotes nothing.
pub fn ground_for_validation(
    request: GroundingValidationRequest,
) -> Result<GroundingValidationInput, DreamDraftValidationError> {
    let GroundingValidationRequest {
        grounding,
        validation,
    } = request;
    let grounded = ground_draft_with_controls(grounding)
        .map_err(|error| summarize_contract("claim grounding", &error))?;
    bind_validation_input(grounded, validation)
}

/// Production construction site of the A-14b -> A-05 carrier.
///
/// Binds the complete grounded handoff value, including its input preimage, to
/// the independently supplied A-05 data. The identity, scope, fence, and task
/// binding required by a grounding receipt is not restated here: the frozen
/// carrier contract already owns it, and this function routes every outcome
/// through that owner validation
/// ([`GroundingValidationInput::new`], which calls
/// [`GroundingValidationInput::validate`]) instead of duplicating or weakening
/// it. The job, task, scope, state fence, manifest, policy, and ledger
/// identities are read from the grounded value and are never taken from the
/// attachment, so the attachment cannot claim a context it was not built for.
///
/// The one guarantee this owner adds is the authority ceiling documented in
/// the module header and declared once as
/// `evidence::CANDIDATE_ONLY_CEILING`: a grounded value whose own retained
/// records assert a position above that ceiling is refused before any carrier
/// exists, so no model-authored or self-certified text can be sealed as
/// validated grounding.
pub fn bind_validation_input(
    grounded: GroundedDreamDraft,
    attachment: ValidationAttachment,
) -> Result<GroundingValidationInput, DreamDraftValidationError> {
    refuse_self_certified_grounding(&grounded)?;
    GroundingValidationInput::new(
        grounded,
        attachment.policy,
        attachment.usage,
        attachment.preservation,
        attachment.observation_time_ms,
        attachment.cancellation_requested,
        attachment.rival_declarations,
    )
}

/// Refuses a grounded value whose retained records claim a position above the
/// candidate-only ceiling.
///
/// The comparison reuses this crate's own owner weakening function
/// (`evidence::cap_record_assertability`) and the crate's single ceiling
/// declaration (`evidence::CANDIDATE_ONLY_CEILING`) instead of a second
/// ordering or a private copy of the policy value, so the refused set is
/// exactly the set the producer caps name.
fn refuse_self_certified_grounding(
    grounded: &GroundedDreamDraft,
) -> Result<(), DreamDraftValidationError> {
    for record in grounded.ledger.records.values() {
        let mut capped = record.clone();
        evidence::cap_record_assertability(&mut capped, evidence::CANDIDATE_ONLY_CEILING);
        if capped.assertability_ceiling != record.assertability_ceiling {
            return Err(DreamDraftValidationError::InvalidContract {
                phase: "grounding validation carrier",
                field: SELF_CERTIFIED_FIELD,
            });
        }
    }
    Ok(())
}
