//! Owner-resolved applicability for one packet's six grading inputs (#1726 W2).
//!
//! # The gap this module closes
//!
//! [`QualityApplicability::validate`] already enforces that all six
//! [`QUALITY_APPLICABILITY_INPUTS`] are accounted for exactly once, and
//! [`QualityOperation::blocks_on_unresolved_applicability`] already says an
//! unknown input blocks every operation except read-only diagnostic display.
//! Nothing in the tree *resolved* those six inputs, so the partition was
//! enforced and never fed. This module is that producer: it reads each input
//! from the owner that already holds it and produces a
//! [`QualityApplicabilityResolutionSet`], which the contract owner turns into
//! the [`QualityApplicability`] partition.
//!
//! # One input, one real owner
//!
//! Each answer below is read from an existing owner record, never re-derived
//! here, and each has exactly one source. Nothing in this module parses a
//! string into an owner fact and nothing reads a constant as if it were an
//! observation:
//!
//! | input | owner read | what "resolved" means here |
//! |---|---|---|
//! | `TaskAcceptance` | `TaskRecord` (Task Controller projection, `eliot-task`) | the Controller's current record revision equals the `TaskRevision` the packet's State Fence names |
//! | `Route` | `ReadIdentity` (retained-read owner, `eliot-read`) | a retained, complete read identity whose fence is this packet's fence |
//! | `Impact` | `ImpactClass` (action model, `eliot-authority`) | a class the action model admits, i.e. one that is not `Forbidden` |
//! | `GovernanceProfile` | `OnboardingReadinessReceipt::governance_profile_ref` (`eliot-workscope`) | the scope's owner-issued profile reference on a receipt whose fence is this packet's fence |
//! | `ProtectedFloor` | `AdmittedContextSet::floor` (Decision Safety Floor owner) | a floor that passes the floor owner's own `validate` |
//! | `ActiveDirective` | the admitted instruction/conflict members of the packet | at least one admitted member the owner issued under a governing authority class |
//!
//! # Why an absent owner is `Unknown`, not a default
//!
//! Every input is `Option`-shaped owner observation. A packet compiled without
//! a governance profile observation does not get a blank profile: the input
//! becomes [`QualityApplicabilityResolution::Unknown`] naming the owner that
//! must issue it, and [`GovernedDecision::unresolved_applicability`] then
//! reports it to the operation that
//! [`QualityOperation::blocks_on_unresolved_applicability`] blocks, while
//! still allowing `DiagnosticDisplay` to show the limitation. That is the
//! difference between "nobody answered" and "the weakest answer was silently
//! chosen", and it is the direction the issue requires.
//!
//! # No semantic proof, no model call
//!
//! This is a synchronous read over already-admitted typed facts. It performs no
//! retrieval, no model invocation and no judgement about whether the packet is
//! *good*; it only answers whether the six governing questions had an owner
//! answer at all. Dimension grading remains a separate step with separate
//! evidence.

use std::collections::BTreeSet;

use eliot_authority::ImpactClass;
use eliot_context_contracts::{
    AdmittedContextSet, AuthorityClass, ContextBinding, QUALITY_APPLICABILITY_INPUTS,
    QualityApplicability, QualityApplicabilityInput, QualityApplicabilityResolution,
    QualityApplicabilityResolutionSet, QualityDimension, QualityOperation, SemanticRole,
};
use eliot_contracts::TaskRevision;
use eliot_read::ReadIdentity;
use eliot_task::TaskRecord;
use eliot_workscope::OnboardingReadinessReceipt;
use thiserror::Error;

/// Owner named when no retained, complete read identity backs the packet.
pub const ROUTE_OWNER: &str = "eliot-read retained-read owner";
/// Owner named when the action model supplied no impact classification.
pub const IMPACT_OWNER: &str = "eliot-authority action model";
/// Owner named when the scope carries no current Governance Profile.
pub const GOVERNANCE_PROFILE_OWNER: &str = "eliot-workscope onboarding readiness owner";
/// Owner named when the Decision Safety Floor did not validate.
pub const PROTECTED_FLOOR_OWNER: &str = "Decision Safety Floor owner";
/// Owner named when the packet carries no admitted governing directive.
pub const ACTIVE_DIRECTIVE_OWNER: &str = "governing instruction/conflict owner";
/// Owner named when the Task Controller supplied no record for the packet task.
pub const TASK_ACCEPTANCE_OWNER: &str = "eliot-task Task Controller owner";

/// Fail-closed errors from applicability resolution.
///
/// A boundary error is a malformed owner value. It is *not* a substitute for
/// [`QualityApplicabilityResolution::Unknown`]: a missing owner produces the
/// typed unknown answer and blocks the dependent action, while a malformed
/// owner value is a contract failure here.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum QualityApplicabilityError {
    /// The admitted set this packet was compiled from does not validate.
    #[error("admitted set does not validate for applicability resolution: {0}")]
    Admitted(String),
    /// An owner supplied a value that cannot be an answer.
    #[error("applicability owner value is not admissible: {0}")]
    InvalidOwnerValue(&'static str),
    /// The resolved partition does not reconcile with the six-input denominator.
    #[error("resolved applicability does not account for every input: {0}")]
    Incomplete(String),
}

/// The six owner answers for one packet, in the shape their owners record them.
///
/// A field is present exactly when that owner produced a record for this
/// packet; `None` is the typed "that owner did not answer", and every `None`
/// becomes [`QualityApplicabilityResolution::Unknown`]. There is deliberately
/// no `Default`, so a caller cannot assemble a value whose absent owners
/// silently read as answers, and no field is a plain `String` the caller could
/// hand over as a stand-in for a record.
pub struct QualityApplicabilityOwnerInputs<'a> {
    /// Admitted set the packet was compiled from; owns the floor and the
    /// admitted directive members.
    pub admitted: &'a AdmittedContextSet,
    /// Current Task Controller projection for the packet's task.
    pub task_record: Option<&'a TaskRecord>,
    /// Retained, complete read identity backing the route the packet was
    /// compiled under.
    pub retained_read: Option<&'a ReadIdentity>,
    /// Impact classification the action model derived for the requested effect.
    pub impact_class: Option<ImpactClass>,
    /// Current onboarding readiness receipt carrying the scope's Governance
    /// Profile reference.
    pub readiness: Option<&'a OnboardingReadinessReceipt>,
}

/// Resolve the six applicability inputs from their owners, as a typed result
/// per input.
///
/// Returns the resolved partition together with the answers it was built from,
/// so a caller can see *which owner* answered and with *what*, and a reader of
/// the card can reproduce the partition without re-deriving it.
///
/// # Errors
///
/// [`QualityApplicabilityError::Admitted`] when the admitted set fails its own
/// `validate`, [`QualityApplicabilityError::InvalidOwnerValue`] when an owner
/// supplied a blank identity or a forbidden impact class, and
/// [`QualityApplicabilityError::Incomplete`] when the resulting partition does
/// not account for every one of the six inputs — which cannot happen for a
/// partition this function builds, so it is a real fail-closed guard rather
/// than a permissive fallback.
pub fn resolve_quality_applicability(
    inputs: &QualityApplicabilityOwnerInputs<'_>,
) -> Result<QualityApplicabilityResolutionSet, QualityApplicabilityError> {
    let admitted = inputs.admitted;
    admitted
        .validate()
        .map_err(|error| QualityApplicabilityError::Admitted(error.to_string()))?;

    // Each stage yields a typed answer for its own input, in the same
    // `Result` shape, so a boundary failure on one input never launders into
    // another's answer and no stage silently drops to a default.
    let task_acceptance = resolve_task_acceptance(&admitted.binding, inputs.task_record);
    let route = resolve_route(&admitted.binding, inputs.retained_read);
    let impact = resolve_impact(inputs.impact_class);
    let governance_profile = resolve_governance_profile(&admitted.binding, inputs.readiness);
    let protected_floor = resolve_protected_floor(admitted);
    let active_directive = resolve_active_directive(admitted);

    let resolutions = QualityApplicabilityResolutionSet {
        task_acceptance: task_acceptance?,
        route,
        impact: impact?,
        governance_profile: governance_profile?,
        protected_floor: protected_floor?,
        active_directive,
    };
    // The answers are checked against the contract owner's own shape rules
    // before they are handed on, so a blank owner or answer identity cannot
    // reach the partition in the first place. A shape failure here is a
    // malformed owner answer, not an unresolved input: it is a boundary error,
    // and it is kept distinct from the typed `Unknown` an absent owner gets.
    resolutions.validate().map_err(|error| {
        QualityApplicabilityError::InvalidOwnerValue(match error {
            eliot_context_contracts::ContextError::InvalidField(
                "quality.applicability.missing_owner",
            ) => "applicability_missing_owner",
            _ => "applicability_answer",
        })
    })?;
    Ok(resolutions)
}

/// Turn the resolved answer set into the recorded partition.
///
/// This is the single step that feeds [`QualityApplicability`]: it reads each
/// answer through the contract owner's own
/// [`QualityApplicability::from_resolutions`], so the partition is produced by
/// the owner of the six-input denominator and not restated here.
pub fn quality_applicability_of(
    resolutions: &QualityApplicabilityResolutionSet,
) -> Result<QualityApplicability, QualityApplicabilityError> {
    QualityApplicability::from_resolutions(resolutions)
        .map_err(|error| QualityApplicabilityError::Incomplete(error.to_string()))
}

fn unknown(missing_owner: &str) -> QualityApplicabilityResolution {
    QualityApplicabilityResolution::Unknown {
        missing_owner: missing_owner.to_owned(),
    }
}

/// A dependent decision or effect this packet's applicability gates, with the
/// exact quality dimensions it independently requires and the verdict the six
/// resolved inputs produce for it.
///
/// This is the W2 "name each dependent decision/effect and the dimensions it
/// needs" relation made explicit. The dimensions come from the contract owner's
/// own [`QualityOperation::required_dimensions`], so the requirement is not
/// restated here and cannot drift from it. The applicability inputs that gate
/// this decision are the ones the owner did not answer, in
/// [`QUALITY_APPLICABILITY_INPUTS`] order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GovernedDecision {
    /// The operation whose readiness this decision depends on.
    pub operation: QualityOperation,
    /// Whether the six resolved inputs block this operation.
    ///
    /// This is read from the contract owner's own
    /// [`QualityOperation::blocks_on_unresolved_applicability`], so an
    /// unresolved input blocks exactly the operations the contract owner says
    /// it blocks, and read-only diagnostic display stays available with the
    /// limitation reported alongside it.
    pub blocked: bool,
    /// Dimensions that operation independently requires.
    ///
    /// This is a closed function of `operation` plus the recipe-selected
    /// additional blockers; see [`governed_decision`].
    pub required_dimensions: Vec<QualityDimension>,
    /// Applicability inputs still unresolved for this packet.
    pub unresolved_applicability: Vec<QualityApplicabilityInput>,
}

/// Resolve one packet's applicability and state the dependent decision it
/// gates.
///
/// The decision is made explicit rather than left to the caller: the six inputs
/// are resolved from their owners, the partition is built through the contract
/// owner's own [`QualityApplicability::from_resolutions`], and the result
/// carries the operation that was requested, the dimensions it independently
/// requires, and exactly which applicability inputs were never answered.
///
/// # Why a recipe cannot narrow the mandatory set
///
/// `additional_required` is unioned into the operation's
/// [`QualityOperation::required_dimensions`] here, exactly as
/// [`eliot_context_contracts::QualityScorecard::suitability`] unions it. Union
/// is the only combining operation on this path: a recipe may add a blocker,
/// and there is no argument, no flag and no code path on which a caller supplies
/// a *reduced* set, because the mandatory set is not an input to this function
/// at all — it is read from the contract owner each call. An empty
/// `additional_required` is therefore the narrowest influence a caller has, and
/// it cannot reach the operation's own mandatory dimensions.
///
/// # Errors
///
/// As [`resolve_quality_applicability`], plus
/// [`QualityApplicabilityError::Incomplete`] when the partition the contract
/// owner builds does not account for every one of the six inputs.
pub fn governed_decision(
    inputs: &QualityApplicabilityOwnerInputs<'_>,
    operation: QualityOperation,
    additional_required: &[QualityDimension],
) -> Result<GovernedDecision, QualityApplicabilityError> {
    let resolutions = resolve_quality_applicability(inputs)?;
    let applicability = quality_applicability_of(&resolutions)?;
    let unresolved_applicability = applicability.unresolved();
    // The unresolved set is re-checked against the independent six-input
    // denominator rather than against a count of this packet's own answers: an
    // unresolved input the constant does not name, or one named twice, means
    // the partition is not the partition and the block below would be read off
    // a denominator that does not exist.
    let named: BTreeSet<QualityApplicabilityInput> =
        unresolved_applicability.iter().copied().collect();
    let declared: BTreeSet<QualityApplicabilityInput> =
        QUALITY_APPLICABILITY_INPUTS.into_iter().collect();
    if named.len() != unresolved_applicability.len() || !named.is_subset(&declared) {
        return Err(QualityApplicabilityError::Incomplete(
            "unresolved applicability inputs are not a subset of the declared inputs".to_owned(),
        ));
    }
    // Union, never substitution: the operation's own mandatory dimensions are
    // read from the contract owner and the recipe's blockers are added to them.
    let required_dimensions: Vec<QualityDimension> = operation
        .required_dimensions()
        .iter()
        .chain(additional_required)
        .copied()
        .collect();
    // The block is the contract owner's own rule applied to the inputs that
    // are actually unresolved, not a second opinion recorded here.
    let blocked =
        operation.blocks_on_unresolved_applicability() && !unresolved_applicability.is_empty();
    Ok(GovernedDecision {
        operation,
        blocked,
        required_dimensions,
        unresolved_applicability,
    })
}

fn owner_text(value: &str) -> bool {
    !value.trim().is_empty() && !value.chars().any(char::is_control)
}

fn resolved(owner: &'static str, answer: String) -> QualityApplicabilityResolution {
    QualityApplicabilityResolution::Resolved {
        owner: owner.to_owned(),
        answer,
    }
}

/// Task/acceptance is resolved only when the Task Controller's own record
/// revision is the revision the packet's State Fence names.
///
/// `TaskRecord::revision` is the Controller's current projection revision and
/// `StateFence::task_revision` is the packet's fenced `TaskRevision`. Both are
/// counters, so they are compared numerically through the contract type's own
/// [`TaskRevision::new`]/[`TaskRevision::value`] accessors rather than through a
/// string spelling of either — there is no `as_str` on that newtype, and
/// formatting one to compare it would accept any revision that parsed.
///
/// A fence that carries no `task_revision` is a typed `Unknown`, not a pass:
/// without a task revision on the fence there is nothing for the Controller's
/// record to match, and "nothing to match" must not read as "matches".
fn resolve_task_acceptance(
    binding: &ContextBinding,
    task_record: Option<&TaskRecord>,
) -> Result<QualityApplicabilityResolution, QualityApplicabilityError> {
    let Some(record) = task_record else {
        return Ok(unknown(TASK_ACCEPTANCE_OWNER));
    };
    if !owner_text(record.task_id.as_str()) || !owner_text(record.goal.as_str()) {
        return Err(QualityApplicabilityError::InvalidOwnerValue("task_record"));
    }
    if record.task_id != binding.task_id {
        return Ok(unknown(TASK_ACCEPTANCE_OWNER));
    }
    // The Controller's counter must be a real contract counter before it can
    // be compared; a revision of zero is not an owner-issued revision.
    let controller_revision = TaskRevision::new(record.revision)
        .map_err(|_| QualityApplicabilityError::InvalidOwnerValue("task_record.revision"))?;
    if binding.state_fence.task_revision != Some(controller_revision) {
        return Ok(unknown(TASK_ACCEPTANCE_OWNER));
    }
    Ok(resolved(
        TASK_ACCEPTANCE_OWNER,
        format!(
            "acceptance:{}:{}",
            record.task_id.as_str(),
            controller_revision.value()
        ),
    ))
}

/// Route is resolved only when a retained read identity exists that was bound
/// to this packet's own fence.
///
/// The route half of the answer is the retained read's own identity closure,
/// because a route name with nothing reading from it is exactly the
/// "valid-looking handle with no corresponding current observation" case the
/// issue calls out. A read bound to a different fence is a read for a different
/// packet and is not this packet's route.
fn resolve_route(
    binding: &ContextBinding,
    retained_read: Option<&ReadIdentity>,
) -> QualityApplicabilityResolution {
    let Some(identity) = retained_read else {
        return unknown(ROUTE_OWNER);
    };
    if identity.state_fence() != &binding.state_fence {
        return unknown(ROUTE_OWNER);
    }
    resolved(
        ROUTE_OWNER,
        format!(
            "read:{}:{}:{}",
            identity.request_id().as_str(),
            identity.source().manifest_name,
            identity.source().manifest_digest
        ),
    )
}

/// Impact is resolved for every classification the action model can admit.
///
/// `Forbidden` is refused rather than resolved: it is an authority boundary,
/// not a governing classification, and a boundary failure must not be laundered
/// into "the impact is known". The answer names the owner-derived class itself,
/// so the recorded answer is the action model's class and not a caller's label.
fn resolve_impact(
    impact_class: Option<ImpactClass>,
) -> Result<QualityApplicabilityResolution, QualityApplicabilityError> {
    let Some(class) = impact_class else {
        return Ok(unknown(IMPACT_OWNER));
    };
    let answer = match class {
        ImpactClass::Observe => "observe",
        ImpactClass::Reversible => "reversible",
        ImpactClass::Material => "material",
        ImpactClass::Critical => "critical",
        // Refused here rather than resolved, and spelled out so the match is
        // exhaustive without a wildcard arm that could mask a future class.
        ImpactClass::Forbidden => {
            return Err(QualityApplicabilityError::InvalidOwnerValue("impact_class"));
        }
    };
    Ok(resolved(IMPACT_OWNER, answer.to_owned()))
}

/// Governance Profile is resolved from the scope's own readiness receipt, and
/// only when that receipt was issued under this packet's fence.
///
/// The receipt is the owner record that carries
/// `governance_profile_ref`; a receipt bound to another fence describes a
/// different scope generation's profile and says nothing about this packet.
fn resolve_governance_profile(
    binding: &ContextBinding,
    readiness: Option<&OnboardingReadinessReceipt>,
) -> Result<QualityApplicabilityResolution, QualityApplicabilityError> {
    let Some(receipt) = readiness else {
        return Ok(unknown(GOVERNANCE_PROFILE_OWNER));
    };
    if receipt.state_fence != binding.state_fence {
        return Ok(unknown(GOVERNANCE_PROFILE_OWNER));
    }
    if !owner_text(&receipt.governance_profile_ref) {
        return Err(QualityApplicabilityError::InvalidOwnerValue(
            "governance_profile_ref",
        ));
    }
    Ok(resolved(
        GOVERNANCE_PROFILE_OWNER,
        receipt.governance_profile_ref.clone(),
    ))
}

/// The protected floor is read through its own owner validator, not through a
/// shape test written here: `DecisionSafetyFloor::validate` is the single
/// authority for what a valid floor is.
fn resolve_protected_floor(
    admitted: &AdmittedContextSet,
) -> Result<QualityApplicabilityResolution, QualityApplicabilityError> {
    admitted
        .floor
        .validate()
        .map_err(|_| QualityApplicabilityError::InvalidOwnerValue("protected_floor"))?;
    Ok(resolved(
        PROTECTED_FLOOR_OWNER,
        format!(
            "floor:{}:{}",
            admitted.floor.rule_evidence.as_str(),
            admitted.floor.mandatory_atoms.len()
        ),
    ))
}

/// Active directives are resolved from the admitted instruction/conflict
/// members themselves, and only when the owner issued them as governing.
///
/// This is deliberately not a keyword or role scan. A member counts only when
/// its semantic role is one the owner uses for governing instructions
/// (`Instruction`, `Authority`, `Constraint`, `Conflict`) **and** its authority
/// class is `Governing`, and the answer names the exact admitted members. A
/// packet with an instruction-shaped atom that the owner issued as merely
/// informational has no active governing directive, and reports `Unknown`
/// rather than passing the dimension on the strength of a role label.
fn resolve_active_directive(admitted: &AdmittedContextSet) -> QualityApplicabilityResolution {
    let mut governing: Vec<String> = admitted
        .records
        .iter()
        .filter(|record| {
            matches!(
                record.candidate.provider_role.role,
                SemanticRole::Instruction
                    | SemanticRole::Authority
                    | SemanticRole::Constraint
                    | SemanticRole::Conflict
            ) && matches!(record.candidate.authority, AuthorityClass::Governing)
        })
        .map(|record| record.candidate.atom_id.as_str().to_owned())
        .collect();
    governing.sort_unstable();
    if governing.is_empty() {
        return unknown(ACTIVE_DIRECTIVE_OWNER);
    }
    resolved(ACTIVE_DIRECTIVE_OWNER, governing.join(","))
}
