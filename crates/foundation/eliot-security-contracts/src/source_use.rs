//! Use-time source authorization: instruction/data separation and revision
//! revalidation at the source-use/action boundary.
//!
//! This module owns the pure decision only. It retrieves no source, calls no
//! model, executes no probe, admits no quarantine, and grants no authority. A
//! denied decision is a bounded refusal of one subject, never a state change to
//! any other subject, source, or work.

use std::collections::{BTreeMap, BTreeSet};

use eliot_contracts::StateFence;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{
    EffectCeiling, EpistemicUse, InfluenceDependencyClosure, InfluenceState, IndependenceLevel,
    InstructionTaint, QuarantineState, SecurityContractError, SourceAssurance,
    TransformationLineage,
};

/// What a proposed use of a source or of a source-derived subject would change.
///
/// The authority surfaces are separated from the data surfaces on purpose: an
/// untrusted source field can never carry a decision that changes standing
/// instructions, tool definitions, policy, credentials, or effect grants,
/// whatever any detector, model, or confidence label reports about it.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SourceUseTarget {
    /// Read the source and its derived subject as retained inert evidence.
    Observation,
    /// Produce or consume a derived summary, compiled view, or model artifact.
    DerivedArtifact,
    /// Execute a procedure or an effect from the derived subject.
    ProcedureOrAction,
    /// Change standing instructions.
    StandingInstruction,
    /// Change a tool definition or tool schema.
    ToolDefinition,
    /// Change policy.
    Policy,
    /// Change credentials.
    Credential,
    /// Change an effect grant.
    EffectGrant,
}

impl SourceUseTarget {
    /// True when this target is an authority surface a source may never change.
    fn is_authority_surface(self) -> bool {
        matches!(
            self,
            Self::StandingInstruction
                | Self::ToolDefinition
                | Self::Policy
                | Self::Credential
                | Self::EffectGrant
        )
    }
}

/// One source revision read directly at the use boundary.
///
/// The revision is carried beside the assurance because the use-time check
/// compares the current revision against the revision the diagnosis observed;
/// an assurance record alone does not state which revision was read.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SourceUseInputSource {
    pub source_ref: String,
    pub revision: String,
    pub assurance: SourceAssurance,
}

/// One exact source revision inside a revision binding.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SourceRevisionRef {
    pub source_ref: String,
    pub revision: String,
}

/// Source, closure, policy, and profile revisions observed at one point in time.
///
/// The policy snapshot and profile revision are named separately: a profile
/// change between diagnosis and execution is a different event from a source
/// revision change, and neither is inferred from the other.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SourceUseRevisions {
    pub source_revisions: Vec<SourceRevisionRef>,
    pub closure_ref: String,
    pub closure_revision: u64,
    pub policy_snapshot_id: String,
    pub profile_revision: String,
}

/// A proposed use of one source-derived subject at the source-use/action
/// boundary.
///
/// The caller supplies the current inputs, the derivations that connect them to
/// the subject, the influence closure, and the revisions observed at diagnosis
/// time and at use time. Completeness of the input set is checked against the
/// lineage roots derived from those derivations, not against a second
/// caller-supplied list.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SourceUseRequest {
    pub request_ref: String,
    pub subject_ref: String,
    pub target: SourceUseTarget,
    pub requested_use: EpistemicUse,
    pub requested_effect: EffectCeiling,
    pub inputs: Vec<SourceUseInputSource>,
    pub derivations: Vec<TransformationLineage>,
    /// Independence the derived subject claims for itself.
    ///
    /// A derived subject cannot be more independent than the weakest source it
    /// actually reads, so a fluent summary or a second model restating one
    /// source cannot manufacture independence it does not have.
    pub subject_independence_claim: IndependenceLevel,
    pub influence_closure: InfluenceDependencyClosure,
    pub diagnosis: SourceUseRevisions,
    pub use_time: SourceUseRevisions,
    pub state_fence: StateFence,
}

/// Outcome of one use-time decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SourceUseDisposition {
    /// The requested use and effect are permitted for this subject now.
    Admitted,
    /// The requested use or effect is refused for this subject now.
    Denied,
}

/// Every reason this decision refused the request.
#[derive(
    Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SourceUseDenialReason {
    /// A source or source-derived subject may not carry an authority change.
    InstructionDataSeparation,
    /// A contributing source is quarantined.
    SourceQuarantined,
    /// A contributing source carries instruction taint for an action use.
    UntrustedActionUse,
    /// The requested epistemic use is outside a contributing source's uses.
    UseNotPermitted,
    /// The requested effect is outside a contributing source's ceilings.
    EffectNotPermitted,
    /// The subject's influence closure is not currently active.
    InfluenceNotActive,
    /// The subject claims more independence than its sources support.
    IndependenceOverstated,
    /// Source, closure, policy, or profile revisions changed or are unbound.
    RevisionsChanged,
}

/// The bounded decision for one request.
///
/// `restricted_source_refs` names only sources of this subject's own lineage.
/// A subject whose lineage roots are all unrestricted is unaffected work and
/// remains eligible; a restriction on one source never reaches beyond the
/// lineage that actually contains it.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SourceUseDecision {
    pub request_ref: String,
    pub subject_ref: String,
    pub target: SourceUseTarget,
    pub disposition: SourceUseDisposition,
    /// Sorted and deduplicated; empty when the disposition is `Admitted`.
    pub denials: Vec<SourceUseDenialReason>,
    /// Sorted and deduplicated; empty when the disposition is `Admitted`.
    pub restricted_source_refs: Vec<String>,
    pub permitted_use: Option<EpistemicUse>,
    pub permitted_effect: Option<EffectCeiling>,
    pub effective_taint: InstructionTaint,
    pub state_fence: StateFence,
}

fn use_text(value: &str, field: &'static str) -> Result<(), SecurityContractError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(SecurityContractError::InvalidText { field });
    }
    Ok(())
}

fn use_fence(value: &StateFence, field: &'static str) -> Result<(), SecurityContractError> {
    value
        .validate()
        .map_err(|_| SecurityContractError::InvalidFence { field })
}

fn validate_revisions(revisions: &SourceUseRevisions) -> Result<(), SecurityContractError> {
    use_text(&revisions.closure_ref, "source_use.closure_ref")?;
    use_text(&revisions.policy_snapshot_id, "source_use.policy_snapshot_id")?;
    use_text(&revisions.profile_revision, "source_use.profile_revision")?;
    if revisions.source_revisions.is_empty() {
        return Err(SecurityContractError::EmptyCollection {
            field: "source_use.source_revisions",
        });
    }
    let mut seen = BTreeSet::new();
    for revision in &revisions.source_revisions {
        use_text(&revision.source_ref, "source_use.source_revision.source_ref")?;
        use_text(&revision.revision, "source_use.source_revision.revision")?;
        if !seen.insert(revision.source_ref.as_str()) {
            return Err(SecurityContractError::DuplicateReference {
                field: "source_use.source_revisions",
            });
        }
    }
    Ok(())
}

fn revision_map(revisions: &SourceUseRevisions) -> BTreeMap<&str, &str> {
    revisions
        .source_revisions
        .iter()
        .map(|item| (item.source_ref.as_str(), item.revision.as_str()))
        .collect()
}

/// Derivation chain of one subject, root-most first, with its lineage roots.
struct LineageWalk<'a> {
    order: Vec<&'a TransformationLineage>,
    roots: BTreeSet<String>,
}

/// Walks the supplied derivations backwards from `subject_ref`.
///
/// Every derivation is validated through its own `validate()`, which already
/// refuses taint laundering. Each output reference may have exactly one
/// producer, which bounds the walk: a node is visited once, so a cycle
/// terminates instead of looping.
fn walk_lineage<'a>(
    subject_ref: &str,
    derivations: &'a [TransformationLineage],
) -> Result<LineageWalk<'a>, SecurityContractError> {
    let mut producer: BTreeMap<&'a str, &'a TransformationLineage> = BTreeMap::new();
    for derivation in derivations {
        derivation.validate()?;
        if producer.insert(derivation.output_ref.as_str(), derivation).is_some() {
            return Err(SecurityContractError::InvalidText {
                field: "source_use.derivation.output_binding",
            });
        }
    }

    let mut visited: BTreeSet<&str> = BTreeSet::new();
    let mut order: Vec<&'a TransformationLineage> = Vec::new();
    let mut roots: BTreeSet<String> = BTreeSet::new();
    let mut frontier: Vec<&str> = Vec::new();
    visited.insert(subject_ref);
    frontier.push(subject_ref);
    while let Some(node) = frontier.pop() {
        let Some(derivation) = producer.get(node) else {
            roots.insert(node.to_owned());
            continue;
        };
        order.push(*derivation);
        for input in &derivation.input_refs {
            if visited.insert(input.as_str()) {
                frontier.push(input.as_str());
            }
        }
    }
    order.reverse();
    Ok(LineageWalk { order, roots })
}

/// Strength of an independence claim; `Independent` is the strongest.
fn independence_rank(level: IndependenceLevel) -> u8 {
    match level {
        IndependenceLevel::Independent => 3,
        IndependenceLevel::Related => 2,
        IndependenceLevel::CommonMode => 1,
        IndependenceLevel::Unknown => 0,
    }
}

/// Weakest independence any actually-read source supports.
fn weakest_input_independence(inputs: &[SourceUseInputSource]) -> IndependenceLevel {
    inputs
        .iter()
        .map(|input| input.assurance.independence)
        .min_by_key(|level| independence_rank(*level))
        .unwrap_or(IndependenceLevel::Unknown)
}

/// Highest taint carried by the sources this request actually read.
fn input_taint(inputs: &[SourceUseInputSource]) -> InstructionTaint {
    inputs
        .iter()
        .map(|input| input.assurance.instruction_taint)
        .max()
        .unwrap_or(InstructionTaint::Cleared)
}

/// Propagates taint along the subject's derivation chain.
///
/// Taint never decreases along the chain unless the step carries its own
/// declassification receipt, so a fluent summary or a second model restating
/// the same source cannot clear a restriction.
fn propagated_taint(
    order: &[&TransformationLineage],
    initial: InstructionTaint,
) -> Result<InstructionTaint, SecurityContractError> {
    let mut propagated = initial;
    for derivation in order {
        if derivation.output_taint < propagated
            && derivation.declassification_receipt_ref.is_none()
        {
            return Err(SecurityContractError::TaintLaundering);
        }
        propagated = propagated.max(derivation.output_taint);
    }
    Ok(propagated)
}

/// Accumulates denial reasons together with the sources that caused them.
struct Denials {
    reasons: BTreeSet<SourceUseDenialReason>,
    restricted: BTreeSet<String>,
}

impl Denials {
    fn new() -> Self {
        Self {
            reasons: BTreeSet::new(),
            restricted: BTreeSet::new(),
        }
    }

    /// Records a reason scoped to this subject's whole lineage.
    fn for_all_roots(&mut self, reason: SourceUseDenialReason, roots: &BTreeSet<String>) {
        self.reasons.insert(reason);
        self.restricted.extend(roots.iter().cloned());
    }

    /// Records a reason scoped to one contributing source.
    fn for_source(&mut self, reason: SourceUseDenialReason, source_ref: &str) {
        self.reasons.insert(reason);
        self.restricted.insert(source_ref.to_owned());
    }
}

/// Validates the input records and returns their distinct source references.
fn validate_inputs(request: &SourceUseRequest) -> Result<BTreeSet<&str>, SecurityContractError> {
    if request.inputs.is_empty() {
        return Err(SecurityContractError::EmptyCollection {
            field: "source_use.inputs",
        });
    }
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    for input in &request.inputs {
        use_text(&input.source_ref, "source_use.input.source_ref")?;
        use_text(&input.revision, "source_use.input.revision")?;
        if input.assurance.source_ref != input.source_ref {
            return Err(SecurityContractError::InvalidText {
                field: "source_use.input.assurance_binding",
            });
        }
        input.assurance.validate()?;
        if input.assurance.state_fence != request.state_fence {
            return Err(SecurityContractError::FenceMismatch);
        }
        if !seen.insert(input.source_ref.as_str()) {
            return Err(SecurityContractError::DuplicateReference {
                field: "source_use.inputs",
            });
        }
    }
    Ok(seen)
}

/// Validates that the closure names this subject, this lineage, and this fence.
fn validate_closure(
    request: &SourceUseRequest,
    roots: &BTreeSet<String>,
) -> Result<(), SecurityContractError> {
    let closure = &request.influence_closure;
    closure.validate()?;
    if closure.state_fence != request.state_fence {
        return Err(SecurityContractError::FenceMismatch);
    }
    if closure.closure_id != request.use_time.closure_ref
        || closure.closure_id != request.diagnosis.closure_ref
    {
        return Err(SecurityContractError::InvalidText {
            field: "source_use.influence_closure.closure_binding",
        });
    }
    if !roots.contains(&closure.root_ref) {
        return Err(SecurityContractError::InvalidText {
            field: "source_use.influence_closure.root_binding",
        });
    }
    if !closure.dependent_refs.iter().any(|item| item == &request.subject_ref) {
        return Err(SecurityContractError::InvalidText {
            field: "source_use.influence_closure.dependent_binding",
        });
    }
    Ok(())
}

/// Records a revision-staleness denial when diagnosis and use time disagree.
fn check_revisions(request: &SourceUseRequest, roots: &BTreeSet<String>, denials: &mut Denials) {
    let use_time_map = revision_map(&request.use_time);
    let input_map: BTreeMap<&str, &str> = request
        .inputs
        .iter()
        .map(|input| (input.source_ref.as_str(), input.revision.as_str()))
        .collect();
    // The revisions the request claims to read now must be the revisions the
    // current input records carry, and the diagnosis binding must equal the
    // use-time binding for closure, policy snapshot, and profile revision. A
    // source or profile change between diagnosis and execution lands here.
    if use_time_map != input_map
        || request.diagnosis != request.use_time
        || request.influence_closure.revision != request.use_time.closure_revision
    {
        denials.for_all_roots(SourceUseDenialReason::RevisionsChanged, roots);
    }
}

/// Records the per-source use, effect, quarantine, and taint denials.
fn check_inputs(request: &SourceUseRequest, denials: &mut Denials) {
    for input in &request.inputs {
        if !input.assurance.allowed_epistemic_use.contains(&request.requested_use) {
            denials.for_source(SourceUseDenialReason::UseNotPermitted, &input.source_ref);
        }
        if !input.assurance.allowed_effects.contains(&request.requested_effect) {
            denials.for_source(SourceUseDenialReason::EffectNotPermitted, &input.source_ref);
        }
        if request.target != SourceUseTarget::ProcedureOrAction {
            continue;
        }
        if input.assurance.quarantine == QuarantineState::Quarantined {
            denials.for_source(SourceUseDenialReason::SourceQuarantined, &input.source_ref);
        }
        if matches!(
            input.assurance.instruction_taint,
            InstructionTaint::Untrusted | InstructionTaint::CommandLike
        ) {
            denials.for_source(SourceUseDenialReason::UntrustedActionUse, &input.source_ref);
        }
    }
}

/// Decides one proposed use of one source-derived subject.
///
/// Allowed uses and effects are resolved from the current `SourceAssurance` of
/// every source this subject actually reads, so a derived artifact cannot widen
/// what its sources permit. The decision refuses only this subject; it mutates
/// no source, assessment, quarantine, incident, or authority state.
///
/// # Errors
///
/// Returns an error when the request shape, its inputs, its derivations, or its
/// closure are malformed or unbound to the current state fence.
pub fn authorize_source_use(
    request: &SourceUseRequest,
) -> Result<SourceUseDecision, SecurityContractError> {
    use_text(&request.request_ref, "source_use.request_ref")?;
    use_text(&request.subject_ref, "source_use.subject_ref")?;
    use_fence(&request.state_fence, "source_use.state_fence")?;
    validate_revisions(&request.diagnosis)?;
    validate_revisions(&request.use_time)?;
    let seen_inputs = validate_inputs(request)?;
    let walk = walk_lineage(&request.subject_ref, &request.derivations)?;

    // Completeness is checked against the roots the lineage actually contains,
    // so omitting a source from `inputs` cannot widen the decision.
    for root in &walk.roots {
        if !seen_inputs.contains(root.as_str()) {
            return Err(SecurityContractError::EmptyCollection {
                field: "source_use.inputs",
            });
        }
    }
    validate_closure(request, &walk.roots)?;

    let mut denials = Denials::new();
    check_revisions(request, &walk.roots, &mut denials);
    if request.target.is_authority_surface() {
        denials.for_all_roots(SourceUseDenialReason::InstructionDataSeparation, &walk.roots);
    }
    if independence_rank(request.subject_independence_claim)
        > independence_rank(weakest_input_independence(&request.inputs))
    {
        denials.for_all_roots(SourceUseDenialReason::IndependenceOverstated, &walk.roots);
    }
    check_inputs(request, &mut denials);
    if request.influence_closure.current_influence != InfluenceState::Active {
        denials.for_source(
            SourceUseDenialReason::InfluenceNotActive,
            &request.influence_closure.root_ref,
        );
    }

    let effective_taint = propagated_taint(&walk.order, input_taint(&request.inputs))?;
    let admitted = denials.reasons.is_empty();
    Ok(SourceUseDecision {
        request_ref: request.request_ref.clone(),
        subject_ref: request.subject_ref.clone(),
        target: request.target,
        disposition: if admitted {
            SourceUseDisposition::Admitted
        } else {
            SourceUseDisposition::Denied
        },
        denials: denials.reasons.into_iter().collect(),
        restricted_source_refs: denials.restricted.into_iter().collect(),
        permitted_use: admitted.then_some(request.requested_use),
        permitted_effect: admitted.then_some(request.requested_effect),
        effective_taint,
        state_fence: request.state_fence.clone(),
    })
}
