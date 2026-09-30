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
//! # One input, one owner
//!
//! Each answer below is read from the existing owner of that fact, not
//! re-derived here, and each has exactly one source:
//!
//! | input | owner read | what "resolved" means here |
//! |---|---|---|
//! | `TaskAcceptance` | [`GoverningTaskAcceptance`] (Task Controller) | an owner-issued acceptance revision equal to the packet's fenced task revision |
//! | `Route` | [`AssemblyPolicy::route_id`](eliot_context_assembly::AssemblyPolicy) + the retained `ReadIdentity` of the route's role acquisition | a non-blank route identity on a retained, complete read |
//! | `Impact` | [`GoverningImpactClassification`] (action model) | a non-`Forbidden` owner impact class |
//! | `GovernanceProfile` | [`GoverningSourceSet::governance_profile_ref`](eliot_workscope::GoverningSourceSet) | the scope's current profile reference |
//! | `ProtectedFloor` | [`AdmittedContextSet::floor`] (Decision Safety Floor owner) | a floor that passes its own `validate` |
//! | `ActiveDirective` | the admitted instruction/conflict members of the packet | at least one admitted member the owner issued under a governing authority class |
//!
//! # Why an absent owner is `Unknown`, not a default
//!
//! Every input is an `Option`-shaped owner observation. A packet compiled
//! without a governance profile observation does not get a blank profile: the
//! input becomes [`QualityApplicabilityResolution::Unknown`] naming the owner
//! that must issue it, and `suitability` then blocks `Compile` and
//! `DependentAction` while still allowing `DiagnosticDisplay` to show the
//! limitation. That is the difference between "nobody answered" and "the
//! weakest answer was silently chosen", and it is the direction the issue
//! requires.
//!
//! # No semantic proof, no model call
//!
//! This is a synchronous read over already-admitted typed facts. It performs no
//! retrieval, no model invocation and no judgement about whether the packet is
//! *good*; it only answers whether the six governing questions had an owner
//! answer at all. Dimension grading remains a separate step with separate
//! evidence.

use eliot_context_contracts::{
    AdmittedContextSet, AuthorityClass, ContextBinding, QualityApplicability,
    QualityApplicabilityResolution, QualityApplicabilityResolutionSet, SemanticRole,
};
use thiserror::Error;

/// Owner named when no route/serializer identity was retained for the packet.
pub const ROUTE_OWNER: &str = "eliot-context-assembly route owner";
/// Owner named when the action model supplied no impact classification.
pub const IMPACT_OWNER: &str = "Governor action model (eliot-authority)";
/// Owner named when the scope carries no current Governance Profile.
pub const GOVERNANCE_PROFILE_OWNER: &str = "eliot-workscope governing-source owner";
/// Owner named when the Decision Safety Floor did not validate.
pub const PROTECTED_FLOOR_OWNER: &str = "Decision Safety Floor owner";
/// Owner named when the packet carries no admitted governing directive.
pub const ACTIVE_DIRECTIVE_OWNER: &str = "governing instruction/conflict owner";
/// Owner named when the Task Controller supplied no acceptance revision.
pub const TASK_ACCEPTANCE_OWNER: &str = "Task Controller acceptance owner";

/// The Task Controller's answer for the task and its acceptance criteria.
///
/// This is the owner's own record, presented verbatim: the acceptance revision
/// the Controller holds for the task the packet is compiled under. It is
/// compared against the packet's fenced `task_revision` rather than being
/// accepted on its own, because an acceptance revision for a different
/// revision of the task governs nothing about this packet.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GoverningTaskAcceptance {
    /// Owner-issued task identity the acceptance is issued for.
    pub task_id: String,
    /// Owner-issued acceptance/task revision the Controller currently holds.
    pub acceptance_revision: String,
}

/// The action model's answer for the impact classification of the effect.
///
/// The classification is the action model's, never the caller's: a caller that
/// declares a smaller effect class does not reach this type, because the
/// Governor admitted the operation under the class its own action model
/// derived.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GoverningImpactClassification {
    /// Owner-derived impact class token (`OBSERVE`, `REVERSIBLE`, `MATERIAL`,
    /// `CRITICAL`). A `FORBIDDEN` classification is refused by
    /// [`resolve_quality_applicability`]: it is a boundary failure, not an
    /// applicability answer.
    pub impact_class: String,
}

/// Owner observations of one packet's route identity.
///
/// The route is resolved from the two independent records that already carry
/// it: the assembly policy the packet was rendered under, and the retained
/// read identity of a role acquisition that actually completed. A route string
/// with no retained complete read behind it is `Unknown`, because a route name
/// with nothing reading from it is exactly the "valid-looking handle with no
/// corresponding current observation" case the issue calls out.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GoverningRouteObservation {
    /// Route identity the assembly policy used for the rendered bytes.
    pub route_id: String,
    /// Owner that issued the retained role read backing this route, when a
    /// role acquisition under that route completed.
    pub retained_read_source: Option<String>,
}

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

/// Resolve the six applicability inputs for one packet from their owners.
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
    admitted: &AdmittedContextSet,
    task_acceptance: Option<&GoverningTaskAcceptance>,
    route: Option<&GoverningRouteObservation>,
    impact: Option<&GoverningImpactClassification>,
    governance_profile_ref: Option<&str>,
) -> Result<QualityApplicabilityResolutionSet, QualityApplicabilityError> {
    admitted
        .validate()
        .map_err(|error| QualityApplicabilityError::Admitted(error.to_string()))?;

    let task_acceptance_answer = task_acceptance.map_or_else(
        || unknown(TASK_ACCEPTANCE_OWNER),
        |acceptance| resolve_task_acceptance(&admitted.binding, acceptance),
    );
    let route_answer = route.map_or_else(|| unknown(ROUTE_OWNER), resolve_route);
    let impact_answer = impact.map_or_else(
        || {
            Ok(QualityApplicabilityResolution::Unknown {
                missing_owner: IMPACT_OWNER.to_owned(),
            })
        },
        resolve_impact,
    );
    let governance_answer = match governance_profile_ref {
        Some(profile) => owner_text(profile)
            .then(|| QualityApplicabilityResolution::Resolved {
                owner: GOVERNANCE_PROFILE_OWNER.to_owned(),
                answer: profile.to_owned(),
            })
            .ok_or(QualityApplicabilityError::InvalidOwnerValue(
                "governance_profile_ref",
            )),
        None => Ok(unknown(GOVERNANCE_PROFILE_OWNER)),
    };
    // The protected floor is read through its own owner validator, not through
    // a shape test written here: `DecisionSafetyFloor::validate` is the single
    // authority for what a valid floor is.
    let floor_answer = admitted
        .floor
        .validate()
        .map_err(|_| QualityApplicabilityError::InvalidOwnerValue("protected_floor"))?;
    let protected_answer = floor_answer.and_then(|()| {
        Ok(QualityApplicabilityResolution::Resolved {
            owner: PROTECTED_FLOOR_OWNER.to_owned(),
            answer: format!(
                "floor:{}:{}",
                admitted.floor.rule_evidence.as_str(),
                admitted.floor.mandatory_atoms.len()
            ),
        })
    });
    let directive_answer = resolve_active_directive(admitted);

    let resolutions = QualityApplicabilityResolutionSet {
        task_acceptance: task_acceptance_answer?,
        route: route_answer?,
        impact: impact_answer?,
        governance_profile: governance_answer?,
        protected_floor: protected_answer?,
        active_directive: directive_answer?,
    };
    resolutions
        .validate()
        .map_err(|error| QualityApplicabilityError::InvalidOwnerValue(match error {
            eliot_context_contracts::ContextError::InvalidField(
                "quality.applicability.missing_owner",
            ) => "applicability_missing_owner",
            _ => "applicability_answer",
        }))?;
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

fn owner_text(value: &str) -> bool {
    !value.trim().is_empty() && !value.chars().any(char::is_control)
}

/// Task/acceptance is resolved only when the Controller's own acceptance
/// revision is the revision the packet's State Fence names.
///
/// A fence that carries no `task_revision` is a typed `Unknown`, not a pass:
/// without a task revision on the fence there is nothing for the Controller's
/// answer to match, and "nothing to match" must not read as "matches".
fn resolve_task_acceptance(
    binding: &ContextBinding,
    acceptance: &GoverningTaskAcceptance,
) -> QualityApplicabilityResolution {
    if !owner_text(&acceptance.task_id)
        || !owner_text(&acceptance.acceptance_revision)
        || acceptance.task_id != binding.task_id.as_str()
    {
        return unknown(TASK_ACCEPTANCE_OWNER);
    }
    match binding.state_fence.task_revision {
        Some(revision) if revision.as_str() == acceptance.acceptance_revision => {
            QualityApplicabilityResolution::Resolved {
                owner: TASK_ACCEPTANCE_OWNER.to_owned(),
                answer: format!(
                    "acceptance:{}:{}",
                    acceptance.task_id, acceptance.acceptance_revision
                ),
            }
        }
        _ => unknown(TASK_ACCEPTANCE_OWNER),
    }
}

/// Route is resolved only when the assembly route identity and a retained,
/// complete role read behind it are both present.
fn resolve_route(
    route: &GoverningRouteObservation,
) -> Result<QualityApplicabilityResolution, QualityApplicabilityError> {
    if !owner_text(&route.route_id) {
        return Err(QualityApplicabilityError::InvalidOwnerValue("route_id"));
    }
    let Some(retained) = route
        .retained_read_source
        .as_deref()
        .filter(|source| owner_text(source))
    else {
        return Ok(unknown(ROUTE_OWNER));
    };
    Ok(QualityApplicabilityResolution::Resolved {
        owner: ROUTE_OWNER.to_owned(),
        answer: format!("route:{}:{retained}", route.route_id),
    })
}

/// Impact is resolved for every classification the action model can admit.
///
/// `FORBIDDEN` is refused rather than resolved: it is an authority boundary,
/// not a governing classification, and a boundary failure must not be
/// laundered into "the impact is known".
fn resolve_impact(
    impact: &GoverningImpactClassification,
) -> Result<QualityApplicabilityResolution, QualityApplicabilityError> {
    if !owner_text(&impact.impact_class) {
        return Err(QualityApplicabilityError::InvalidOwnerValue("impact_class"));
    }
    if impact.impact_class.eq_ignore_ascii_case("FORBIDDEN") {
        return Err(QualityApplicabilityError::InvalidOwnerValue("impact_class"));
    }
    Ok(QualityApplicabilityResolution::Resolved {
        owner: IMPACT_OWNER.to_owned(),
        answer: impact.impact_class.to_owned(),
    })
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
fn resolve_active_directive(
    admitted: &AdmittedContextSet,
) -> Result<QualityApplicabilityResolution, QualityApplicabilityError> {
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
        return Ok(unknown(ACTIVE_DIRECTIVE_OWNER));
    }
    Ok(QualityApplicabilityResolution::Resolved {
        owner: ACTIVE_DIRECTIVE_OWNER.to_owned(),
        answer: governing.join(","),
    })
}
