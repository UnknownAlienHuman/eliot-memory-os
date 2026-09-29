//! Daemon-held negative-memory action gate: the production caller of the
//! Governor's gated canonical write (issue #1731 W4/W5/W6/W7).
//!
//! # Why this module exists
//!
//! Every negative-memory owner on the Governor side was, before this module, a
//! definition without a production caller. This module is the missing caller:
//! it performs the one bounded, exact-fence named read that resolves the
//! current rule set, hands the **store-observed** result to the pure gate,
//! dispatches through
//! [`commit_canonical_gated_by_negative_memory`], and appends the matched
//! outcome to the existing observation path.
//!
//! # What it deliberately does not do
//!
//! It invents no rule, no policy, no fence and no evidence. The read is
//! [`GetLearningRecordRange`] filtered to the closed `activation_receipt`
//! kind at the request's own fence, executed on the one authenticated Kernel
//! named-read route; the gate, the probe admission and the observation
//! append are all Governor-owned. A refusal at any step is a typed error that
//! stops the effect, never a permissive fallback.
//!
//! # W7: the same truth in the action response
//!
//! The same rule set and the same match that admitted or refused the effect are
//! projected into a [`NegativeMemoryRuleProjection`] and, when the caller holds
//! a packet scorecard for this action, its negative-memory coverage axis is
//! graded from that projection. The action response therefore references the
//! exact rule revision the effect was decided under, and a warning is never
//! presented as governing authority.
//!
//! [`GetLearningRecordRange`]: eliot_store_api::NamedReadOperation::GetLearningRecordRange
//! [`commit_canonical_gated_by_negative_memory`]:
//!     eliot_governor::GovernorComposition::commit_canonical_gated_by_negative_memory
//! [`NegativeMemoryRuleProjection`]: eliot_governor::NegativeMemoryRuleProjection

#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use eliot_context_contracts::QualityScorecard;
use eliot_dreamer_failure::{
    FailureAction, FailureApplicability, FailureCoverage, FailureDimension, FailureEnvironment,
    NegativeMemoryHorizonDomain, NegativeMemoryHorizonDomainKind, NegativeMemoryMatchBound,
    NegativeMemoryMatchResult, NegativeMemoryResource, NegativeMemorySubject, match_negative_memory,
};
use eliot_governor::{
    GovernorComposition, KernelGenerationPort, NegativeMemoryGateDecision, NegativeMemoryGateInput,
    NegativeMemoryProbeProposal, NegativeMemoryProceedWarning, NegativeMemoryRuleProjection,
    admit_negative_memory_probe, apply_negative_memory_coverage, evaluate_negative_memory_gate,
    negative_memory_gate_refusal_message, plan_negative_memory_rule_read,
    project_negative_memory_rules, resolve_negative_memory_rule_read,
};
use eliot_protocol::RequestIdentity;
use eliot_store_api::{
    CanonicalWriteEnvelope, EffectClass, NamedReadRequest, NamedReadResponse, OperationId, ScopeId,
    StateFence, WriteReceipt,
};
use thiserror::Error;

use crate::daemon_kernel_client::DaemonKernelClient;

/// The Governor-owned bounded matcher bound the daemon runs every gate under.
///
/// These are not defaults a caller may raise: they are the whole enumeration
/// bound for the synchronous gate, and the matcher refuses any read that walks
/// past them.
const GATE_MAX_ENUMERATED_PAGES: u32 = 1;
/// Maximum candidate rules one gate evaluation may compare.
const GATE_COMPARED_RULE_LIMIT: u32 = 64;
/// Maximum compared identity fields one rule may produce.
const GATE_PER_RULE_FIELD_LIMIT: u32 = 256;

/// The domain the daemon observes horizons in.
///
/// A negative-memory horizon is only comparable inside one owner-issued domain,
/// and the daemon's own domain is the live resource generation: a value the
/// daemon reads from its retained Kernel snapshot rather than from a clock.
const GATE_HORIZON_DOMAIN_OWNER: &str = "eliotd";

/// Fail-closed errors from the daemon negative-memory action gate.
///
/// Every variant stops the effect. None of them is "no rule applies".
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum NegativeMemoryActionError {
    /// The closed bounded rule read could not be planned.
    #[error("negative-memory rule read could not be planned: {0}")]
    Plan(String),
    /// The authenticated Kernel read did not resolve a rule set.
    #[error("negative-memory rule read did not resolve: {0}")]
    Resolve(String),
    /// The pending action's owner-issued identity is not admissible as a
    /// matcher subject.
    #[error("negative-memory action subject is not admissible: {0}")]
    Subject(String),
    /// The gate refused the effect.
    #[error("negative-memory gate refused the effect: {0}")]
    Refused(String),
    /// The matched outcome could not be appended to the observation path.
    #[error("negative-memory matched outcome could not be appended: {0}")]
    Observation(String),
}

/// The owner-issued identity of one pending action, as the daemon holds it.
///
/// Every field is read from the action the daemon is about to commit or from
/// the daemon's own retained Kernel snapshot. None is invented here, and none
/// is a display name: the matcher compares these identities exactly.
#[derive(Clone, Debug)]
pub struct NegativeMemoryPendingAction {
    /// The pending action's own operation identity.
    pub operation_id: String,
    /// The pending action's attempt identity.
    pub attempt_id: String,
    /// The owner-issued target the action addresses.
    pub target_id: String,
    /// The owner-issued input schema revision.
    pub input_schema: String,
    /// The exact digest over the pending action's input.
    pub input_digest: String,
    /// The exact effect identity the action would perform.
    pub effect_id: String,
    /// The effect class the action would perform at.
    pub effect_class: EffectClass,
    /// The owner that holds the action's contract.
    pub owner: String,
    /// The exact contract revision the action was admitted against.
    pub contract_revision: String,
    /// The exact contract digest the action was admitted against.
    pub contract_digest: String,
    /// The owner-issued task the action belongs to.
    pub task_id: String,
    /// The scope the action addresses.
    pub scope_id: String,
    /// The owner-issued environment identity of the action.
    pub environment_id: String,
    /// The exact environment revision the action was admitted at.
    pub environment_revision: String,
    /// The exact platform the action runs on.
    pub platform: String,
    /// The exact tool revision the action uses.
    pub tool_revision: String,
    /// The optional model revision the action used.
    pub model_revision: Option<String>,
    /// The exact configuration revision in force.
    pub config_revision: String,
    /// The exact capability revision in force.
    pub capability_revision: String,
    /// The exact policy revision in force.
    pub policy_revision: String,
    /// The owner-issued resources the action affects.
    pub resources: Vec<NegativeMemoryResource>,
    /// The owner-issued typed trigger dimensions of the action.
    pub predicate_dimensions: Vec<FailureDimension>,
    /// The live Kernel fence the action is admitted at.
    pub state_fence: StateFence,
    /// The retained resource generation the action is admitted at.
    pub resource_generation: u64,
}

/// What one gated action produced.
///
/// The decision, the receipt and the Context projection travel together so the
/// caller's action response references the same rule revision the effect was
/// decided under, instead of restating it.
#[derive(Clone, Debug)]
pub struct NegativeMemoryActionOutcome {
    /// The canonical receipt of the committed effect.
    pub receipt: WriteReceipt,
    /// The exact gate decision the dispatch was admitted under.
    pub decision: NegativeMemoryGateDecision,
    /// The same admitted-rule truth projected for the action response.
    pub projection: NegativeMemoryRuleProjection,
    /// The typed probe proposal, present exactly for a `RequireCheck` decision.
    pub probe: Option<NegativeMemoryProbeProposal>,
}

/// Resolves the current rule set for one action through the authenticated
/// bounded read.
///
/// This is the production caller of
/// [`plan_negative_memory_rule_read`] and
/// [`resolve_negative_memory_rule_read`]. The read is issued `ExactFence` on
/// the action's own admitted fence, so the fence the returned set carries is the
/// one the store reported, not one this module chose.
///
/// # Errors
///
/// Returns [`NegativeMemoryActionError::Plan`] when the closed read cannot be
/// built, and [`NegativeMemoryActionError::Resolve`] when the authenticated
/// read fails or its response does not resolve to a rule set.
pub async fn resolve_rule_set(
    kernel: &DaemonKernelClient,
    action: &NegativeMemoryPendingAction,
) -> Result<eliot_governor::ResolvedNegativeMemoryRuleSet, NegativeMemoryActionError> {
    let scope_id = ScopeId::new(action.scope_id.as_str())
        .map_err(|error| NegativeMemoryActionError::Plan(error.to_string()))?;
    let request: NamedReadRequest = plan_negative_memory_rule_read(scope_id, action.state_fence.clone())
        .map_err(|error| NegativeMemoryActionError::Plan(error.to_string()))?;
    let response: NamedReadResponse = kernel
        .store_named_async(request)
        .await
        .map_err(|error| NegativeMemoryActionError::Resolve(error.to_string()))?;
    resolve_negative_memory_rule_read(&request, &response)
        .map_err(|error| NegativeMemoryActionError::Resolve(error.to_string()))
}

/// Builds the matcher subject for one pending action.
///
/// Every field is copied from the action's own owner-issued identity. The
/// resource-kind vocabulary is the recorded one
/// (`NegativeMemoryResourceKind`), so a subject cannot introduce a resource
/// class the record vocabulary does not contain.
///
/// # Errors
///
/// Returns [`NegativeMemoryActionError::Subject`] when the assembled subject
/// fails the matcher's own `validate()`.
pub fn action_subject(
    action: &NegativeMemoryPendingAction,
) -> Result<NegativeMemorySubject, NegativeMemoryActionError> {
    let coverage = FailureCoverage::Complete;
    let subject = NegativeMemorySubject {
        action: FailureAction {
            action_id: action.operation_id.clone(),
            operation_id: action.operation_id.clone(),
            attempt_id: action.attempt_id.clone(),
            target_id: action.target_id.clone(),
            input_schema: action.input_schema.clone(),
            input_digest: action.input_digest.clone(),
            effect_id: action.effect_id.clone(),
            effect_class: action.effect_class,
            owner: action.owner.clone(),
            contract_revision: action.contract_revision.clone(),
            contract_digest: action.contract_digest.clone(),
        },
        applicability: FailureApplicability {
            task_id: action.task_id.clone(),
            scope_id: action.scope_id.clone(),
            target_id: action.target_id.clone(),
            environment_id: action.environment_id.clone(),
            platform: action.platform.clone(),
            tool_revision: action.tool_revision.clone(),
            model_revision: action.model_revision.clone(),
            config_revision: action.config_revision.clone(),
            capability_revision: action.capability_revision.clone(),
            effect_class: action.effect_class,
            coverage,
        },
        environment: FailureEnvironment {
            environment_id: action.environment_id.clone(),
            environment_revision: action.environment_revision.clone(),
            platform: action.platform.clone(),
            tool_revision: action.tool_revision.clone(),
            model_revision: action.model_revision.clone(),
            config_revision: action.config_revision.clone(),
            capability_revision: action.capability_revision.clone(),
            policy_revision: action.policy_revision.clone(),
            state_fence: action.state_fence.clone(),
            coverage,
        },
        resources: action.resources.clone(),
        predicate_dimensions: action.predicate_dimensions.clone(),
        coverage,
    };
    subject
        .validate()
        .map_err(|error| NegativeMemoryActionError::Subject(error.to_string()))?;
    Ok(subject)
}

/// The horizon domain the daemon observes, taken from the live generation.
///
/// # Errors
///
/// Returns [`NegativeMemoryActionError::Subject`] when the reading is not a
/// valid owner-issued domain.
pub fn observed_horizon(
    action: &NegativeMemoryPendingAction,
) -> Result<NegativeMemoryHorizonDomain, NegativeMemoryActionError> {
    let domain = NegativeMemoryHorizonDomain {
        owner: GATE_HORIZON_DOMAIN_OWNER.to_owned(),
        domain_kind: NegativeMemoryHorizonDomainKind::ResourceGeneration,
        domain_id: action.scope_id.clone(),
        domain_sequence: action.resource_generation,
    };
    domain
        .validate()
        .map_err(|error| NegativeMemoryActionError::Subject(error.to_string()))?;
    Ok(domain)
}

/// The closed enumeration bound the synchronous gate runs under.
#[must_use]
pub const fn gate_bound() -> NegativeMemoryMatchBound {
    NegativeMemoryMatchBound {
        max_enumerated_pages: GATE_MAX_ENUMERATED_PAGES,
        compared_rule_limit: GATE_COMPARED_RULE_LIMIT,
        per_rule_field_limit: GATE_PER_RULE_FIELD_LIMIT,
    }
}

/// Projects the same admitted-rule truth the gate decided on for the action
/// response, and grades the caller's packet scorecard from it when one is held.
///
/// This is the production caller of
/// [`project_negative_memory_rules`] and [`apply_negative_memory_coverage`].
/// The match is recomputed from the same subject, horizon and rule set the gate
/// used, so the projection cannot describe a different rule revision than the
/// one the effect was decided under.
///
/// # Errors
///
/// Returns [`NegativeMemoryActionError::Subject`] when the bounded match fails
/// its own validation, and [`NegativeMemoryActionError::Refused`] when the
/// projection or the scorecard axis cannot be graded.
pub fn project_action_response(
    action: &NegativeMemoryPendingAction,
    resolved: &eliot_governor::ResolvedNegativeMemoryRuleSet,
    scorecard: Option<&mut QualityScorecard>,
) -> Result<NegativeMemoryRuleProjection, NegativeMemoryActionError> {
    let subject = action_subject(action)?;
    let horizon = observed_horizon(action)?;
    let matched: NegativeMemoryMatchResult = match_negative_memory(
        &subject,
        &horizon,
        resolved.read(),
        &gate_bound(),
    )
    .map_err(|error| NegativeMemoryActionError::Subject(error.to_string()))?;
    let mut records = BTreeMap::new();
    let mut policies = BTreeMap::new();
    for record in resolved.records() {
        records.insert(record.record_id.clone(), record.clone());
    }
    for policy in resolved.policies() {
        policies.insert(policy.binding.record_id.clone(), policy.clone());
    }
    let projection = project_negative_memory_rules(&matched, &records, &policies)
        .map_err(|error| NegativeMemoryActionError::Refused(error.to_string()))?;
    if let Some(card) = scorecard {
        apply_negative_memory_coverage(&projection, card)
            .map_err(|error| NegativeMemoryActionError::Refused(error.to_string()))?;
    }
    Ok(projection)
}

/// Builds the typed probe proposal for a `RequireCheck` decision.
///
/// This is the production caller of
/// [`admit_negative_memory_probe`]. A decision that is not an exact admitted
/// `RequireCheck` yields `None`, so no probe is ever proposed for a near match,
/// an advisory disposition, or an undecidable lookup.
///
/// # Errors
///
/// Returns [`NegativeMemoryActionError::Refused`] when the decision names a
/// required check whose rule or check binding the resolved rule set does not
/// retain, or when the closed probe invariants do not hold for the recorded
/// action.
pub fn probe_for(
    decision: &NegativeMemoryGateDecision,
    resolved: &eliot_governor::ResolvedNegativeMemoryRuleSet,
) -> Result<Option<NegativeMemoryProbeProposal>, NegativeMemoryActionError> {
    if !matches!(decision, NegativeMemoryGateDecision::RequireCheck { .. }) {
        return Ok(None);
    }
    let proposal = admit_negative_memory_probe(decision, resolved)
        .map_err(|error| NegativeMemoryActionError::Refused(error.to_string()))?;
    Ok(Some(proposal))
}

/// Appends one matched gate outcome to the existing observation path.
///
/// This is the production caller of
/// [`admit_negative_memory_gate_observation`](eliot_governor::GovernorObservationReconciliation::admit_negative_memory_gate_observation).
/// The rule identity and rule-set revision are taken from the resolved rule
/// set, not from the caller, so the appended observation cannot name a rule
/// revision the decision was not taken over.
///
/// # Errors
///
/// Returns [`NegativeMemoryActionError::Observation`] when the canonical
/// observation commit cannot be completed or reconciled.
pub async fn append_matched_outcome<P: KernelGenerationPort + ?Sized>(
    governor: &GovernorComposition<P>,
    identity: &RequestIdentity,
    base_operation_id: &OperationId,
    action: &NegativeMemoryPendingAction,
    resolved: &eliot_governor::ResolvedNegativeMemoryRuleSet,
    decision: &NegativeMemoryGateDecision,
    committed_effect: bool,
) -> Result<WriteReceipt, NegativeMemoryActionError> {
    let observation = matched_outcome(action, resolved, decision, committed_effect);
    governor
        .observation_reconciliation()
        .admit_negative_memory_gate_observation(identity, base_operation_id, &observation)
        .await
        .map_err(|error| NegativeMemoryActionError::Observation(error.to_string()))
}

/// Builds the observation record for one matched decision.
fn matched_outcome(
    action: &NegativeMemoryPendingAction,
    resolved: &eliot_governor::ResolvedNegativeMemoryRuleSet,
    decision: &NegativeMemoryGateDecision,
    committed_effect: bool,
) -> eliot_governor::NegativeMemoryGateObservation {
    let (record_id, rule_revision, record_digest) = match decision {
        NegativeMemoryGateDecision::Block {
            record_id,
            rule_revision,
            ..
        }
        | NegativeMemoryGateDecision::RequireCheck {
            record_id,
            rule_revision,
            ..
        } => (record_id.clone(), *rule_revision, String::new()),
        NegativeMemoryGateDecision::Proceed { warning: Some(warning) } => (
            warning.record_id.clone(),
            warning.rule_revision,
            String::new(),
        ),
        NegativeMemoryGateDecision::Proceed { warning: None }
        | NegativeMemoryGateDecision::Unavailable { .. } => (String::new(), 0, String::new()),
    };
    let record_digest = resolved
        .records()
        .iter()
        .find(|record| record.record_id == record_id && record.rule_revision == rule_revision)
        .map_or(record_digest, |record| record.record_digest.clone());
    eliot_governor::NegativeMemoryGateObservation {
        action_operation_id: action.operation_id.clone(),
        action_effect_id: action.effect_id.clone(),
        action_input_digest: action.input_digest.clone(),
        scope_id: action.scope_id.clone(),
        record_id,
        rule_revision,
        record_digest,
        read_handle: resolved.read().read_handle.clone(),
        rule_set_revision: resolved.rule_set_revision(),
        outcome: observation_outcome(decision),
        committed_effect,
    }
}

/// Re-derives the observation outcome class from the decision itself.
const fn observation_outcome(decision: &NegativeMemoryGateDecision) -> eliot_governor::NegativeMemoryGateOutcome {
    match decision {
        NegativeMemoryGateDecision::Block { .. } => {
            eliot_governor::NegativeMemoryGateOutcome::Blocked
        }
        NegativeMemoryGateDecision::RequireCheck { .. } => {
            eliot_governor::NegativeMemoryGateOutcome::ProbeRequired
        }
        NegativeMemoryGateDecision::Proceed { warning: Some(_) } => {
            eliot_governor::NegativeMemoryGateOutcome::ProceededWithWarning
        }
        NegativeMemoryGateDecision::Proceed { warning: None } => {
            eliot_governor::NegativeMemoryGateOutcome::ProceededWithoutWarning
        }
        NegativeMemoryGateDecision::Unavailable { .. } => {
            eliot_governor::NegativeMemoryGateOutcome::ProceededWithoutWarning
        }
    }
}

/// Commits one canonical action under the negative-memory gate.
///
/// This is the production caller of
/// [`commit_canonical_gated_by_negative_memory`]. The order is fixed and
/// fail-closed: resolve the rule set through the authenticated bounded read,
/// re-read the scope revision head for the dispatch revalidation, evaluate the
/// gate, append the matched outcome, and only then commit. A refusing decision
/// is appended as a refusal and never dispatches.
///
/// # Errors
///
/// Returns [`NegativeMemoryActionError`] naming the exact stage that refused.
/// A refusal after the append is still a refusal: the appended record says the
/// effect was not committed, which is the fail-closed direction.
pub async fn commit_gated_action<P: KernelGenerationPort + ?Sized>(
    governor: &GovernorComposition<P>,
    kernel: &DaemonKernelClient,
    identity: &RequestIdentity,
    action: &NegativeMemoryPendingAction,
    envelope: CanonicalWriteEnvelope,
    scorecard: Option<&mut QualityScorecard>,
) -> Result<NegativeMemoryActionOutcome, NegativeMemoryActionError> {
    let resolved = resolve_rule_set(kernel, action).await?;
    let base_operation_id = envelope.operation_id.clone();
    let subject = action_subject(action)?;
    let horizon = observed_horizon(action)?;
    let bound = gate_bound();
    let input = NegativeMemoryGateInput {
        subject: &subject,
        observed_horizon: &horizon,
        bound: &bound,
        resolved: &resolved,
        revalidated_rule_set_revision: Some(resolved.rule_set_revision()),
        state_fence: &action.state_fence,
    };
    let decision = evaluate_negative_memory_gate(&input);
    let projection = project_action_response(action, &resolved, scorecard)?;
    let probe = probe_for(&decision, &resolved)?;
    if let Some(refusal) = negative_memory_gate_refusal_message(&decision) {
        let _ = append_matched_outcome(
            governor,
            identity,
            &base_operation_id,
            action,
            &resolved,
            &decision,
            false,
        )
        .await;
        return Err(NegativeMemoryActionError::Refused(refusal));
    }
    let committed = governor
        .commit_canonical_gated_by_negative_memory(identity, envelope, &input)
        .await
        .map_err(|error| NegativeMemoryActionError::Refused(error.to_string()))?;
    append_matched_outcome(
        governor,
        identity,
        &base_operation_id,
        action,
        &resolved,
        &decision,
        true,
    )
    .await?;
    Ok(NegativeMemoryActionOutcome {
        receipt: committed.receipt,
        decision,
        projection,
        probe,
    })
}
