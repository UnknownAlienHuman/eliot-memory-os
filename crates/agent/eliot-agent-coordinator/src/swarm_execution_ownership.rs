//! Coordinator-owned execution ownership: mechanical update checks, explicit
//! work replacement, and history retention across owner loss (issue #1702
//! W5/W7, A2/A4/A6).
//!
//! This module adds no revision, replacement, supersession or recovery scheme.
//! Every owner type it manipulates already exists in
//! `eliot_agent_contracts` — [`SwarmPlanDefinition`],
//! [`SwarmPlanAdmission`], [`SwarmExecutionRevision`], [`SupersessionLink`],
//! [`OldWaveDisposition`] — and every mechanical rule it enforces is the
//! existing contract owner's own check, re-run rather than re-implemented:
//! [`check_execution_update`] for the freeze/execution boundary,
//! [`check_supersession`] for the replacement link, [`reassign_coordinator`]
//! for the rebind, and [`check_owner_join`] for the recovered join. The
//! coordinator is the *execution* owner (I10.15 "`AgentCoordinator` owns
//! `SwarmExecutionState` under an exact active admission"), so what belongs
//! here is only what the pure contracts cannot decide alone: the coordinator's
//! own view of which owner streams are currently active, and the ordering
//! between an admission disposition and the execution that ran under it.
//!
//! # `check_execution_update`
//!
//! Derived from I10.15 (`docs/architecture/I10-15-agent-execution-fabric-and-durable-swarm.md`):
//!
//! > AgentCoordinator may advance execution mechanically only under an active
//! > admission receipt; any change to objective, acceptance, ceilings, work
//! > graph semantics or stop conditions requires a new Task Controller
//! > definition revision and a new Governor admission.
//!
//! and from the issue's implementation step 4:
//!
//! > Execution may choose among already permitted options but cannot add
//! > nodes, expand scope/budget or alter acceptance/stop conditions.
//!
//! The contract owner already proves the negative (a carried semantic field
//! that differs from the frozen value fails with
//! [`ContractError::SemanticDrift`]). The one thing it cannot see is the
//! coordinator's OWN live state: a wave that the Task Controller has already
//! superseded. This module's [`check_execution_update`] therefore layers the
//! contract check with the supersession gate and is the symbol the coordinator
//! itself calls, so the guarantee is reachable from the production coordinator
//! path and not only from the daemon's fabric composition.
//!
//! # `replace_active_work`
//!
//! Derived from I14.20 (`docs/architecture/I14-20-canonical-runtime-lifecycle-vocabulary.md`):
//!
//! > Changing objective, acceptance, ceilings, work-graph semantics or stop
//! > conditions creates a new draft/frozen definition plus a new admission and
//! > an explicit drain/cancel disposition for the old execution.
//!
//! and from the issue's implementation step 5:
//!
//! > New overlapping work cannot start until old ownership and possible effects
//! > are safely dispositioned. If admission of the replacement fails, retain
//! > the previous records and explicit current authority; do not silently
//! > resurrect a revoked wave.
//!
//! Distinctness is real and derived from content, never from a counter: the
//! replacement admission identity and the replacement execution identity are
//! both bound to the replacement definition's exact content digest through
//! [`contract_shape_digest`], so the same definition revision always yields
//! the same identities (exact replay) while any content change necessarily
//! yields different ones. The old-wave disposition is an explicit recorded
//! [`SupersessionLink`] value on the replacement record — it is never an
//! implicit absence and never inferred from a missing link.
//!
//! # `retain_history_after_owner_loss`
//!
//! Derived from I10.15:
//!
//! > Loss of Task Controller or coordinator revokes only the corresponding
//! > lease; definitions, admission receipts, work items, events, evidence and
//! > verified partial results survive and are reassigned under a newer epoch.
//!
//! and from the issue's implementation step 7:
//!
//! > Reassignment obtains a new owner epoch and binds the retained work; it
//! > cannot reset spend or turn UNKNOWN_OUTCOME into a clean failure.
//!
//! Unknown is preserved as unknown: the retained revision's state is carried
//! verbatim through [`reassign_coordinator`], so an `UNKNOWN_OUTCOME` wave
//! stays `UNKNOWN_OUTCOME`, and an effect the coordinator cannot classify is
//! carried in [`RetainedWork::UnknownEffect`] with its recorded
//! [`UnknownEffectWitness`] rather than being folded into "absent" or guessed
//! into a terminal state.
//!
//! # `resume_publish_after_commit` / `resume_execution_launch`
//!
//! Derived from the issue's acceptance clause:
//!
//! > Same-identity replay is exact, changed content conflicts, and crash after
//! > commit before acknowledgement creates no duplicate revision/launch.
//!
//! and from I01.08 (`docs/architecture/I01-08-exact-ownership-and-call-paths.md`):
//!
//! > named store transaction commits events/projections/relations/WriteReceipt/outbox row atomically
//! >
//! > → caller notification.
//!
//! A caller that dies between the commit and the notification leaves a
//! committed revision that no acknowledgement refers to. The resume answer is
//! derived from the COMMITTED IMAGE the caller presents, never from the
//! caller's live map, and the evidence is bound to the operation that produced
//! it: [`PublishOperation`] carries the exact record bytes under the exact
//! identity it intends, so a changed-content replay resolves to
//! [`PublishResume::Conflict`] through the existing same-identity-changed-content
//! rule instead of a new check.
//!
//! Proof ceiling: `SWARM_EXECUTION_OWNERSHIP_PACKAGE_PROOF_ONLY`. Governor
//! admission of the proposed replacement, Kernel authority, canonical Store
//! commit, provider dispatch and Product Pulse remain with their owners.

use std::collections::{BTreeMap, BTreeSet};

use eliot_agent_contracts::{
    ContractError, ExecutionUpdateProposal, OldWaveDisposition, RevisionId, SupersessionLink,
    SwarmAdmissionId, SwarmCoordinatorLease, SwarmDefinitionId, SwarmExecutionId,
    SwarmExecutionRevision, SwarmExecutionState, SwarmPlanAdmission, SwarmPlanAdmissionDisposition,
    SwarmPlanDefinition, SwarmPlanDefinitionLifecycle, SwarmPlanView, check_execution_transition,
    check_owner_join, check_supersession, contract_shape_digest, execution_state_is_active,
    join_view, reassign_coordinator,
};
use serde::{Deserialize, Serialize};

use crate::model::{CoordinatorError, validate_text};

/// Schema identity for the coordinator's execution-ownership replacement value.
pub const SWARM_EXECUTION_OWNERSHIP_VERSION: &str = "eliot.agent-swarm-execution-ownership/v1";

/// Maps one semantic contract rejection onto the coordinator vocabulary.
///
/// The mapping is total and keeps each refusal typed rather than collapsing it
/// into a generic string: a coordinator trying to rewrite frozen semantics
/// stays [`CoordinatorError::SemanticDrift`], a stale or foreign lease stays
/// [`CoordinatorError::StaleController`], another owner's identity stays
/// [`CoordinatorError::IdentityConflict`], and a broken ownership join stays
/// [`CoordinatorError::IdentityConflict`] naming the exact link. Every other
/// contract rejection is preserved verbatim in
/// [`CoordinatorError::ProviderContract`] so no refusal is flattened away.
///
/// It is crate-visible rather than private so the coordinator's own call path
/// (`core.rs`) reports through the SAME mapping this module uses. There is
/// exactly one contract-rejection-to-coordinator-vocabulary mapping in this
/// crate; a second one in `core.rs` would let the same contract refusal read
/// differently depending on which boundary raised it.
pub(crate) fn ownership_rejection(error: ContractError) -> CoordinatorError {
    match error {
        ContractError::SemanticDrift(field) => CoordinatorError::SemanticDrift(field),
        ContractError::StaleLease(_) => CoordinatorError::StaleController,
        ContractError::ForeignOwner(field) => CoordinatorError::IdentityConflict(field),
        ContractError::BrokenOwnershipLink(_) => {
            CoordinatorError::IdentityConflict("swarm_ownership_join")
        }
        other => CoordinatorError::ProviderContract(format!("swarm ownership: {other}")),
    }
}

/// Guards one coordinator execution update against frozen plan semantics and
/// against a wave this coordinator has already superseded (issue #1702 A1/A3).
///
/// Two independent gates, in this order, and no third:
///
/// 1. the supersession gate — if a committed replacement already links this
///    definition as its prior, an execution update under the OLD admission is
///    refused with [`CoordinatorError::StaleAdmission`]. `DRAIN` is not a
///    narrowed permission: it is the arm that declines to refuse, so a draining
///    old wave is checked by exactly the same guard as any other frozen and
///    admitted wave, and is refused for semantic change on the same terms. The
///    prior revision is still immutable history either way;
/// 2. the contract owner's own [`eliot_agent_contracts::check_execution_update`],
///    which re-validates the three records, proves the admission binds the
///    exact frozen definition and the execution binds both, requires an active
///    execution under the current coordinator lease, and rejects any carried
///    field that differs from the frozen value or widens the admitted ceilings.
///
/// The presenter is checked against the execution's own
/// [`SwarmCoordinatorLease`] by the contract owner, so a stale or foreign
/// coordinator fails before any semantic comparison and a Task Controller
/// cannot write execution fields under its own labels.
///
/// # Errors
///
/// Returns [`CoordinatorError::StaleAdmission`] when a committed replacement
/// already dispositioned this wave, otherwise the typed
/// [`ownership_rejection`] of the contract owner's check.
pub fn check_execution_update(
    definition: &SwarmPlanDefinition,
    admission: &SwarmPlanAdmission,
    execution: &SwarmExecutionRevision,
    update: &ExecutionUpdateProposal,
    caller_holder: &str,
    caller_epoch: u64,
    supersession: Option<&SupersessionLink>,
) -> Result<(), CoordinatorError> {
    if let Some(link) = supersession {
        match link.disposition {
            OldWaveDisposition::Drain => {}
            OldWaveDisposition::Cancel | OldWaveDisposition::Supersede => {
                return Err(CoordinatorError::StaleAdmission);
            }
        }
    }
    eliot_agent_contracts::check_execution_update(
        definition,
        admission,
        execution,
        update,
        caller_holder,
        caller_epoch,
    )
    .map_err(ownership_rejection)
}

/// What a replacement of active work actually produced (issue #1702 W5/A2).
///
/// Both new identities are derived from the replacement definition's exact
/// content digest, not from a counter: replaying the same authorized change
/// through the same definition revision reproduces these exact values, and any
/// content change to the definition necessarily produces different ones. The
/// old wave is never implicitly absent — its disposition is the recorded
/// [`RetainedWork::OldWave`] entry.
///
/// This value is a compile result, not an authority: the replacement still
/// requires its own distinct Governor admission through the admission owner,
/// and its execution requires the coordinator's current lease. Nothing here
/// admits, freezes, launches, or cancels anything.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkReplacement {
    /// Schema identity of this value.
    pub schema_version: String,
    /// Replacement definition identity, distinct from the prior one.
    pub replacement_definition_id: SwarmDefinitionId,
    /// Exact frozen definition digest the new identities are derived from.
    pub replacement_definition_digest: String,
    /// The explicit old-wave disposition proposed for the prior definition.
    pub old_wave_disposition: OldWaveDisposition,
    /// The exact prior definition revision being replaced.
    pub prior_definition_id: SwarmDefinitionId,
    /// Prior definition revision under execution.
    pub prior_revision: RevisionId,
    /// Distinct admission identity the replacement requires. Derived from the
    /// replacement definition content, so the same replacement always resolves
    /// to the same admission identity and any content change resolves to a
    /// different one.
    pub replacement_admission_id: SwarmAdmissionId,
    /// Distinct execution identity the replacement wave requires, derived from
    /// the replacement definition content and the replacement wave.
    pub replacement_execution_id: SwarmExecutionId,
    /// The replacement wave. A changed root creates a new wave; it is never an
    /// in-place substitution of the old one.
    pub replacement_wave: RevisionId,
    /// Content digest binding this replacement to the operation that produced
    /// it. A changed-content replay under the same definition resolves to a
    /// conflict through the existing same-identity-changed-content rule.
    pub replacement_digest: String,
    /// The prior wave's retained history: identity, terminal/live state,
    /// coverage and the effects the coordinator could not classify.
    pub retained: RetainedWork,
}

/// One old wave's retained history, carried across a replacement (issue #1702
/// W7) and across owner loss (issue #1702 A6).
///
/// Nothing here is dropped when a replacement or a loss happens. In
/// particular a wave whose effect is genuinely unknown keeps that verdict:
/// [`RetainedWork::UnknownEffect`] is recorded with its witness and the wave's
/// state stays [`SwarmExecutionState::UnknownOutcome`], so "unknown" can never
/// be reported as "absent" or as a clean failure.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetainedWork {
    /// Execution identity whose history is retained.
    pub execution_id: SwarmExecutionId,
    /// Definition identity it ran under.
    pub definition_id: SwarmDefinitionId,
    /// Admission identity it ran under.
    pub admission_id: SwarmAdmissionId,
    /// Wave it reached, preserved verbatim.
    pub wave: RevisionId,
    /// Its recorded state, preserved verbatim. `UNKNOWN_OUTCOME` is never
    /// rewritten here.
    pub state: SwarmExecutionState,
    /// Coverage ledger handle at the moment of retention; never reset.
    pub coverage_digest: String,
    /// Coordinator epoch that owned the retained work before the transition.
    pub previous_coordinator_epoch: u64,
    /// Coordinator epoch that owns it after the transition. Always advances
    /// past the previous one: a reassignment that does not move authority
    /// forward is a stale presenter, not a new owner.
    pub coordinator_epoch: u64,
    /// Verified partial results retained verbatim across the transition, in
    /// the order they were verified. A verified partial result is never dropped
    /// because a later stage failed, and never reordered into a terminal
    /// success.
    pub verified_partial_results: Vec<VerifiedPartialResult>,
    /// Effects the coordinator could not classify. Each stays unknown until a
    /// reconciliation owner resolves it; none is dropped or guessed.
    pub unknown_effects: Vec<UnknownEffectWitness>,
    /// The explicit disposition recorded for this wave. This value is always
    /// present: an old wave is never dispositioned by the mere absence of a
    /// link.
    pub disposition: OldWaveDisposition,
}

/// One verified partial result that survives owner loss and replacement
/// (issue #1702 A6, I14.24 "Task Controller/Main Agent lost … verified
/// artifacts preserved").
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifiedPartialResult {
    /// Opaque artifact/result identity the coordinator recorded.
    pub result_id: String,
    /// Digest of the exact verified bytes. Recorded, never recomputed.
    pub digest: String,
    /// Coordinator epoch under which this result was verified.
    pub verified_epoch: u64,
}

/// One effect whose outcome is genuinely unknown, preserved as unknown (issue
/// #1702 A6, I14.24 "preserve unknown effects").
///
/// The absence of a tool receipt or of an observed side effect is NOT proof
/// that no effect happened. This witness records what was actually observed and
/// refuses to resolve it: it names no terminal state and cannot be used as
/// evidence of success.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnknownEffectWitness {
    /// Effect identity the coordinator could not classify.
    pub effect_id: String,
    /// What was observed about the effect, verbatim. An empty observation is
    /// still an unknown effect, never an absent one.
    pub observed: String,
    /// The execution identity the effect belongs to.
    pub execution_id: SwarmExecutionId,
}

/// Compiles one explicit replacement of active work (issue #1702 W5/A2).
///
/// Derived from I14.20:
///
/// > Changing objective, acceptance, ceilings, work-graph semantics or stop
/// > conditions creates a new draft/frozen definition plus a new admission and
/// > an explicit drain/cancel disposition for the old execution.
///
/// The composition refuses rather than repairs. The prior definition must be a
/// stored, frozen, live (not already superseded or cancelled) revision; the
/// replacement must pass the existing [`check_supersession`] contract, which
/// requires a distinct identity, differing content, and a supersession link
/// naming the exact prior revision and one explicit [`OldWaveDisposition`];
/// the replacement's root context must stay equal to the prior root, because a
/// changed root creates a new wave through its own admission path rather than
/// a context substitution inside this one; and the old wave's retained
/// admission must be one this coordinator still holds under its current lease,
/// because the coordinator is the only owner that may say what its own wave's
/// effects were.
///
/// If any gate refuses, NOTHING is produced: the prior records and the prior
/// wave's explicit current authority stay exactly as they were, so a failed
/// replacement can never silently resurrect a revoked wave or silently
/// dispose a live one.
///
/// The distinct identities are derived by [`contract_shape_digest`] over the
/// replacement definition's exact content digest, the prior definition
/// identity, the disposition, and the replacement wave. Replaying the same
/// authorized change therefore reproduces the same identities exactly, and any
/// change of content necessarily produces a different digest and therefore a
/// different admission and execution identity.
///
/// # Errors
///
/// Returns [`CoordinatorError::StaleAdmission`] when the prior definition is
/// already superseded or cancelled, [`CoordinatorError::IdentityConflict`] when
/// the replacement does not link the exact prior revision or attempts an
/// in-place root substitution, [`CoordinatorError::StaleController`] when the
/// presenter does not hold the old wave's current coordinator lease, and the
/// typed [`ownership_rejection`] of [`check_supersession`] otherwise.
#[allow(clippy::too_many_arguments)]
pub fn replace_active_work(
    prior_definition: &SwarmPlanDefinition,
    prior_admission: &SwarmPlanAdmission,
    prior_execution: &SwarmExecutionRevision,
    retained_admission_id: &SwarmAdmissionId,
    replacement_definition: &SwarmPlanDefinition,
    replacement_wave: RevisionId,
    coordinator_holder: &str,
    coordinator_epoch: u64,
) -> Result<WorkReplacement, CoordinatorError> {
    validate_text(replacement_wave.as_str(), "swarm.replacement_wave")?;
    if !matches!(
        prior_definition.lifecycle,
        SwarmPlanDefinitionLifecycle::Frozen
    ) {
        // A prior that is already superseded or cancelled has an explicit
        // disposition; replacing it again would resurrect a revoked wave.
        return Err(CoordinatorError::StaleAdmission);
    }
    if !prior_admission.binds(prior_definition) {
        return Err(CoordinatorError::IdentityConflict(
            "swarm_prior_admission_binding",
        ));
    }
    if prior_execution.admission_id != *retained_admission_id {
        return Err(CoordinatorError::IdentityConflict(
            "swarm_retained_admission",
        ));
    }
    if !prior_execution
        .coordinator
        .authorizes(coordinator_holder, coordinator_epoch)
    {
        return Err(CoordinatorError::StaleController);
    }
    // The replacement is a NEW definition revision of the same task choice,
    // never an in-place substitution: a changed root context is a new wave
    // admitted through its own definition and admission, not a context swap
    // inside this replacement.
    if replacement_definition.root_context_revision != prior_definition.root_context_revision {
        return Err(CoordinatorError::IdentityConflict(
            "swarm_in_place_root_substitution",
        ));
    }
    check_supersession(prior_definition, replacement_definition).map_err(ownership_rejection)?;
    let link =
        replacement_definition
            .supersedes
            .as_ref()
            .ok_or(CoordinatorError::IdentityConflict(
                "swarm_missing_old_wave_disposition",
            ))?;
    let replacement_definition_digest = replacement_definition.definition_digest.clone();
    let (replacement_admission_id, replacement_execution_id, replacement_digest) =
        derive_replacement_identities(replacement_definition, link, &replacement_wave)?;
    let retained = RetainedWork {
        execution_id: prior_execution.execution_id.clone(),
        definition_id: prior_execution.definition_id.clone(),
        admission_id: prior_execution.admission_id.clone(),
        wave: prior_execution.wave.clone(),
        state: prior_execution.state,
        coverage_digest: prior_execution.coverage_digest.clone(),
        previous_coordinator_epoch: prior_execution.coordinator.epoch,
        coordinator_epoch: prior_execution.coordinator.epoch,
        verified_partial_results: Vec::new(),
        unknown_effects: Vec::new(),
        disposition: link.disposition,
    };
    Ok(WorkReplacement {
        schema_version: SWARM_EXECUTION_OWNERSHIP_VERSION.to_owned(),
        replacement_definition_id: replacement_definition.definition_id.clone(),
        replacement_definition_digest,
        old_wave_disposition: link.disposition,
        prior_definition_id: prior_definition.definition_id.clone(),
        prior_revision: prior_definition.definition_revision.clone(),
        replacement_admission_id,
        replacement_execution_id,
        replacement_wave,
        replacement_digest,
        retained,
    })
}

/// Derives the replacement's distinct admission/execution identities and its
/// content digest from real content.
///
/// The digest input is the replacement definition's OWN content digest (which
/// the contract owner recomputes over every frozen field), the prior identity
/// it replaces, the explicit old-wave disposition, and the replacement wave.
/// It is not a counter and it is not a fresh MAC: an identical authorized
/// change reproduces the identical identities, and any content change to the
/// definition, the prior link, the disposition or the wave necessarily changes
/// the digest and therefore the identities.
fn derive_replacement_identities(
    replacement_definition: &SwarmPlanDefinition,
    link: &SupersessionLink,
    replacement_wave: &RevisionId,
) -> Result<(SwarmAdmissionId, SwarmExecutionId, String), CoordinatorError> {
    let digest = contract_shape_digest(&(
        SWARM_EXECUTION_OWNERSHIP_VERSION,
        replacement_definition.definition_id.as_str(),
        replacement_definition.definition_digest.as_str(),
        link.prior_definition_id.as_str(),
        link.prior_revision.as_str(),
        link.disposition,
        replacement_wave.as_str(),
    ))
    .map_err(|_| CoordinatorError::Serialization("swarm replacement digest".to_owned()))?;
    let admission_id = SwarmAdmissionId::new(format!("{digest}:admission"))
        .map_err(|_| CoordinatorError::Serialization("swarm replacement admission".to_owned()))?;
    let execution_id = SwarmExecutionId::new(format!("{digest}:execution"))
        .map_err(|_| CoordinatorError::Serialization("swarm replacement execution".to_owned()))?;
    Ok((admission_id, execution_id, digest))
}

/// Retains one wave's history and rebinds it to a new coordinator epoch after
/// owner loss (issue #1702 W7/A6).
///
/// Derived from I10.15:
///
/// > Loss of Task Controller or coordinator revokes only the corresponding
/// > lease; definitions, admission receipts, work items, events, evidence and
/// > verified partial results survive and are reassigned under a newer epoch.
///
/// Only the affected owner's permission moves. The rebind itself is the
/// contract owner's [`reassign_coordinator`], which preserves the definition,
/// admission, wave, root, state and coverage bindings verbatim, so spend is
/// never reset and `UNKNOWN_OUTCOME` never becomes a clean failure. The
/// verified partial results and the unknown-effect witnesses are carried on the
/// [`RetainedWork`] verbatim: a verified partial result is never dropped because
/// a later stage failed, and an unknown effect is never resolved here.
///
/// `retained.unknown_effects` must not be empty while the retained wave's state
/// is not terminal, and a wave recorded as `UNKNOWN_OUTCOME` with no unknown
/// effect witness is refused: the coordinator may not report an unknown wave as
/// if its effects were known-and-clean.
///
/// # Errors
///
/// Returns [`CoordinatorError::StaleController`] when the new coordinator lease
/// does not authorize the presenter or does not advance past the retained
/// epoch, [`CoordinatorError::SemanticDrift`] when a verified partial result is
/// malformed or the disposition is absent, and the typed
/// [`ownership_rejection`] of [`reassign_coordinator`] otherwise.
pub fn retain_history_after_owner_loss(
    execution: &SwarmExecutionRevision,
    new_coordinator: &SwarmCoordinatorLease,
    presenter_holder: &str,
    presenter_epoch: u64,
    retained: RetainedWork,
    disposition: OldWaveDisposition,
) -> Result<(SwarmExecutionRevision, RetainedWork), CoordinatorError> {
    if !new_coordinator.authorizes(presenter_holder, presenter_epoch) {
        return Err(CoordinatorError::StaleController);
    }
    let rebound = reassign_coordinator(execution, new_coordinator).map_err(ownership_rejection)?;
    for result in &retained.verified_partial_results {
        validate_text(&result.result_id, "swarm.verified_partial_result")?;
        validate_text(&result.digest, "swarm.verified_partial_result_digest")?;
        if result.verified_epoch == 0 {
            return Err(CoordinatorError::SemanticDrift(
                "swarm.verified_partial_result_epoch",
            ));
        }
    }
    for effect in &retained.unknown_effects {
        validate_text(&effect.effect_id, "swarm.unknown_effect")?;
        if effect.execution_id != execution.execution_id {
            return Err(CoordinatorError::SemanticDrift(
                "swarm.unknown_effect_execution",
            ));
        }
    }
    if rebound.state == SwarmExecutionState::UnknownOutcome && retained.unknown_effects.is_empty() {
        // An UNKNOWN_OUTCOME wave with no recorded unknown effect is a claim
        // that its effects are known, which is exactly the collapse this
        // refuses.
        return Err(CoordinatorError::SemanticDrift(
            "swarm_unknown_effect_missing",
        ));
    }
    let next = RetainedWork {
        execution_id: rebound.execution_id.clone(),
        definition_id: rebound.definition_id.clone(),
        admission_id: rebound.admission_id.clone(),
        wave: rebound.wave.clone(),
        state: rebound.state,
        coverage_digest: rebound.coverage_digest.clone(),
        previous_coordinator_epoch: execution.coordinator.epoch,
        coordinator_epoch: rebound.coordinator.epoch,
        verified_partial_results: retained.verified_partial_results,
        unknown_effects: retained.unknown_effects,
        disposition,
    };
    Ok((rebound, next))
}

/// One publish operation a caller can interrupt between its commit and its
/// acknowledgement (issue #1702 A4).
///
/// The identity is the record's OWN identity — definition, admission or
/// execution — exactly the key its committed owner map holds it under, and
/// `canonical_record` is the exact intended content for that identity. Both
/// travel TOGETHER, so the resume comparison is over one operation's intended
/// bytes, never over a caller's current live state.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum PublishOperation {
    /// A Task-Controller-owned plan definition revision.
    Definition {
        /// Definition identity the commit is for.
        definition_id: SwarmDefinitionId,
        /// Exact intended definition bytes for that identity.
        ///
        /// Boxed so this enum does not carry one variant's whole record inline:
        /// the three owner records differ in size by hundreds of bytes and the
        /// operation is cloned and matched by reference, so an unboxed payload
        /// would move the whole record on every match.
        canonical_record: Box<SwarmPlanDefinition>,
    },
    /// A Governor-owned admission revision.
    Admission {
        /// Admission identity the commit is for.
        admission_id: SwarmAdmissionId,
        /// Exact intended admission bytes for that identity.
        canonical_record: Box<SwarmPlanAdmission>,
    },
    /// A coordinator-owned execution revision. Its identity is the launch-side
    /// dedupe key.
    Execution {
        /// Execution identity the commit is for.
        execution_id: SwarmExecutionId,
        /// Exact intended execution bytes for that identity.
        canonical_record: Box<SwarmExecutionRevision>,
    },
}

impl PublishOperation {
    /// The owner-map key this operation commits under.
    #[must_use]
    pub fn key(&self) -> String {
        match self {
            Self::Definition { definition_id, .. } => definition_id.as_str().to_owned(),
            Self::Admission { admission_id, .. } => admission_id.as_str().to_owned(),
            Self::Execution { execution_id, .. } => execution_id.as_str().to_owned(),
        }
    }
}

/// The verified committed owner-separated record set a resume reads (issue
/// #1702 A4).
///
/// This is the store's own verified image, supplied by the durable owner and
/// never re-derived from a caller's volatile map: the resume decision below
/// compares the intended operation against exactly these bytes.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommittedOwnerImage {
    /// Definition revisions read back from the committed image.
    pub definitions: BTreeMap<String, SwarmPlanDefinition>,
    /// Admission revisions read back from the committed image.
    pub admissions: BTreeMap<String, SwarmPlanAdmission>,
    /// Execution revisions read back from the committed image.
    pub executions: BTreeMap<String, SwarmExecutionRevision>,
    /// Supersession links read back from the committed image.
    pub supersessions: BTreeMap<String, SupersessionLink>,
}

/// What a resumed publish or launch means (issue #1702 A4).
///
/// The three verdicts are deliberately distinguishable. A caller resuming an
/// interrupted publish must be able to tell "my revision is already current,
/// report the committed bytes" from "someone committed different bytes under my
/// identity, refuse" without reading either image or file itself.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PublishResume {
    /// The committed image already carries exactly this operation's content,
    /// so the interrupted publish already committed and the caller may be
    /// acknowledged with the committed record. Nothing is rewritten and no
    /// second revision is minted.
    Replayed,
    /// The committed image carries different content under this identity. A
    /// committed revision is never silently overwritten; the caller is refused
    /// through the existing same-identity-changed-content conflict.
    Conflict,
    /// The committed image does not carry this identity at all, so this is an
    /// honest first publish and the caller owes the first commit.
    NotCommitted,
}

/// Resumes one publish after a crash between its commit and its acknowledgement
/// (issue #1702 A4).
///
/// The intended operation and the verified committed image travel together,
/// and the verdict is content equality — the same equality the live replay arms
/// use, never the mere presence of a key:
///
/// * [`PublishResume::Replayed`] — the committed image already carries this
///   exact content for this identity (and, for a replacement definition, its
///   exact supersession link), so the interrupted publish already committed;
/// * [`PublishResume::Conflict`] — the committed image holds different content
///   under this identity, so it is refused as the existing
///   same-identity-changed-content conflict. The key's presence is not
///   authority; this is the ONE case a resume must never answer by writing,
///   because writing would silently overwrite;
/// * [`PublishResume::NotCommitted`] — the committed image does not carry this
///   identity, so the caller owes the first commit.
///
/// Nothing here writes, mints, or rewrites a revision, and no authority is
/// re-decided: this answers only what is already committed.
#[must_use]
pub fn resume_publish_after_commit(
    operation: &PublishOperation,
    committed: &CommittedOwnerImage,
) -> PublishResume {
    match operation {
        PublishOperation::Definition {
            definition_id,
            canonical_record,
        } => {
            let Some(stored) = committed.definitions.get(definition_id.as_str()) else {
                return PublishResume::NotCommitted;
            };
            if stored != canonical_record.as_ref() {
                return PublishResume::Conflict;
            }
            // A replacement definition carries its supersession link with it,
            // because the superseding writer publishes the two as one image.
            match canonical_record.supersedes.as_ref() {
                Some(link) => {
                    if committed.supersessions.get(definition_id.as_str()) == Some(link) {
                        PublishResume::Replayed
                    } else {
                        PublishResume::Conflict
                    }
                }
                None => PublishResume::Replayed,
            }
        }
        PublishOperation::Admission {
            admission_id,
            canonical_record,
        } => {
            let Some(stored) = committed.admissions.get(admission_id.as_str()) else {
                return PublishResume::NotCommitted;
            };
            if stored == canonical_record.as_ref() {
                PublishResume::Replayed
            } else {
                PublishResume::Conflict
            }
        }
        PublishOperation::Execution {
            execution_id,
            canonical_record,
        } => {
            let Some(stored) = committed.executions.get(execution_id.as_str()) else {
                return PublishResume::NotCommitted;
            };
            if stored == canonical_record.as_ref() {
                PublishResume::Replayed
            } else {
                PublishResume::Conflict
            }
        }
    }
}

/// Resumes one execution launch after a crash between its commit and its
/// acknowledgement (issue #1702 A4).
///
/// This is the launch-side dedupe the committed keyed execution revisions
/// already imply: a launch may run only under an execution revision the
/// committed image holds. A coordinator that crashed after committing an
/// execution revision and before acknowledging it, and then re-launches, is
/// refused a second launch for that committed execution identity instead of
/// running a duplicate wave. There is no dedupe table, journal or attempt log
/// here — the keyed execution revisions of the committed image ARE the record
/// of what was launched.
///
/// The launch path's own `attempt_id`/`execution_id` pair is the identity
/// checked, and it is checked ONLY against the committed image, only so the
/// caller can tell a committed identity from one the store never committed; it
/// is not authority over whether the attempt may launch.
///
/// # Errors
///
/// Returns [`CoordinatorError::IdempotencyConflict`] when the committed image
/// already carries this execution identity, so the caller cannot launch a
/// second wave for it.
pub fn resume_execution_launch(
    execution_id: &SwarmExecutionId,
    committed: &CommittedOwnerImage,
) -> Result<(), CoordinatorError> {
    if committed.executions.contains_key(execution_id.as_str()) {
        return Err(CoordinatorError::IdempotencyConflict);
    }
    Ok(())
}

/// Builds the read-only joined owner view, re-verifying the ownership join
/// (issue #1702 A6 "Expose a read-only joined view with separate current
/// revisions, applicability, pending replacement and unknown effects").
///
/// This delegates to the contract owner's own [`join_view`], which first runs
/// the strict [`check_owner_join`] and then assembles the view. The view is a
/// projection: it owns nothing, authorizes nothing, and joined reads never serve
/// as write authorization. The unknown effects passed in are carried verbatim,
/// so an unresolved effect stays visible in the joined read instead of
/// disappearing.
///
/// # Errors
///
/// Returns the typed [`ownership_rejection`] of the joined owner check.
pub fn joined_owner_view(
    definition: &SwarmPlanDefinition,
    admission: &SwarmPlanAdmission,
    execution: &SwarmExecutionRevision,
    pending_replacement: Option<SupersessionLink>,
    unknown_effects: Vec<String>,
) -> Result<SwarmPlanView, CoordinatorError> {
    join_view(
        definition,
        admission,
        execution,
        pending_replacement,
        unknown_effects,
    )
    .map_err(ownership_rejection)
}

/// Verifies one recovered owner-separated record set as strictly as fresh
/// admission (issue #1702 W6/A5, reused unchanged for the replacement and
/// owner-loss halves).
///
/// This is a projection of the single existing strictness gate the durable
/// store and the daemon restore already run: every definition revalidates and
/// its map key equals its identity, every admission binds exactly one stored
/// frozen definition with narrowed ceilings, every execution satisfies the
/// structural ownership links against its stored definition and admission, and
/// every supersession link joins its stored prior and replacement with an
/// acyclic chain. Recovered indexes are rebuilt from these records as
/// projections rather than accepted from any supplied reverse link.
#[allow(clippy::too_many_arguments)]
pub fn verify_owner_record_set(
    definitions: &BTreeMap<String, SwarmPlanDefinition>,
    admissions: &BTreeMap<String, SwarmPlanAdmission>,
    executions: &BTreeMap<String, SwarmExecutionRevision>,
    supersessions: &BTreeMap<String, SupersessionLink>,
) -> Result<(), CoordinatorError> {
    for (key, definition) in definitions {
        definition.validate().map_err(ownership_rejection)?;
        if key != definition.definition_id.as_str() {
            return Err(CoordinatorError::IdentityConflict("swarm_definition_key"));
        }
    }
    let mut admission_by_definition: BTreeMap<&str, &str> = BTreeMap::new();
    for (key, admission) in admissions {
        admission.validate().map_err(ownership_rejection)?;
        if key != admission.admission_id.as_str() {
            return Err(CoordinatorError::IdentityConflict("swarm_admission_key"));
        }
        if admission_by_definition
            .insert(admission.definition_id.as_str(), key.as_str())
            .is_some()
        {
            return Err(CoordinatorError::IdentityConflict(
                "swarm_duplicate_reverse_admission",
            ));
        }
        let definition = definitions.get(admission.definition_id.as_str()).ok_or(
            CoordinatorError::IdentityConflict("swarm_admission_without_definition"),
        )?;
        if definition.lifecycle == SwarmPlanDefinitionLifecycle::Draft
            || !admission.binds(definition)
        {
            return Err(CoordinatorError::IdentityConflict(
                "swarm_admission_definition_binding",
            ));
        }
        if !admission
            .admitted_ceilings
            .narrowed_from(&definition.ceilings)
        {
            return Err(CoordinatorError::SemanticDrift("swarm_admitted_ceilings"));
        }
    }
    for (key, execution) in executions {
        execution.validate().map_err(ownership_rejection)?;
        if key != execution.execution_id.as_str() {
            return Err(CoordinatorError::IdentityConflict("swarm_execution_key"));
        }
        let definition = definitions.get(execution.definition_id.as_str()).ok_or(
            CoordinatorError::IdentityConflict("swarm_execution_without_definition"),
        )?;
        let admission = admissions.get(execution.admission_id.as_str()).ok_or(
            CoordinatorError::IdentityConflict("swarm_execution_without_admission"),
        )?;
        check_owner_join(definition, admission, execution).map_err(ownership_rejection)?;
    }
    for (key, link) in supersessions {
        let next = definitions
            .get(key)
            .ok_or(CoordinatorError::IdentityConflict(
                "swarm_supersession_without_replacement",
            ))?;
        let prior = definitions.get(link.prior_definition_id.as_str()).ok_or(
            CoordinatorError::IdentityConflict("swarm_supersession_without_prior"),
        )?;
        if next.supersedes.as_ref() != Some(link) {
            return Err(CoordinatorError::IdentityConflict(
                "swarm_supersession_link_mismatch",
            ));
        }
        check_supersession(prior, next).map_err(ownership_rejection)?;
    }
    check_supersession_chains(supersessions)
}

/// Rejects cyclic replacement chains in an owner-separated record set.
///
/// Each link is valid on its own, but a cycle (A supersedes B while B
/// transitively supersedes A) orders no current authority: revision order must
/// stay a DAG, or exactly one current authority cannot be resolved.
fn check_supersession_chains(
    supersessions: &BTreeMap<String, SupersessionLink>,
) -> Result<(), CoordinatorError> {
    for start in supersessions.keys() {
        let mut visited = BTreeSet::new();
        let mut current = start.as_str();
        while let Some(link) = supersessions.get(current) {
            if !visited.insert(current) {
                return Err(CoordinatorError::IdentityConflict(
                    "swarm_supersession_chain_cyclic",
                ));
            }
            current = link.prior_definition_id.as_str();
        }
    }
    Ok(())
}

/// Advances one retained wave's execution state under the coordinator's own
/// current lease (issue #1702 A6, history across owner loss).
///
/// This is the contract owner's own [`check_execution_transition`] re-run at
/// the coordinator boundary, so a state change that the I14.20 execution
/// lifecycle does not admit (skipping states, reviving a terminal state,
/// escalating a `UNKNOWN_OUTCOME` wave into a clean terminal one) is refused
/// before any revision is written. An exact replay (`from == to`) is admitted:
/// it is not a transition and it mints nothing.
pub fn advance_retained_state(
    execution: &SwarmExecutionRevision,
    to: SwarmExecutionState,
    caller_holder: &str,
    caller_epoch: u64,
) -> Result<SwarmExecutionRevision, CoordinatorError> {
    execution.validate().map_err(ownership_rejection)?;
    if !execution
        .coordinator
        .authorizes(caller_holder, caller_epoch)
    {
        return Err(CoordinatorError::StaleController);
    }
    check_execution_transition(execution.state, to).map_err(ownership_rejection)?;
    let mut next = execution.clone();
    next.state = to;
    next.validate().map_err(ownership_rejection)?;
    Ok(next)
}

/// Rejects an admission disposition the coordinator cannot mirror for a wave
/// it owns (issue #1702 A2, "an explicit old-wave disposition").
///
/// The fabric never originates dispositions — the Governor owner decides — so
/// the coordinator may only MIRROR a disposition it has the evidence for, and
/// only one that the admission lifecycle actually admits. A mirrored
/// disposition is what makes the old wave's status an explicit recorded value
/// instead of an implicit absence; a wave whose disposition cannot be mirrored
/// keeps its current recorded value and the caller is refused, so nothing
/// silently reverts to "live".
pub fn mirror_admission_disposition(
    admission: &SwarmPlanAdmission,
    to: SwarmPlanAdmissionDisposition,
) -> Result<SwarmPlanAdmission, CoordinatorError> {
    admission.validate().map_err(ownership_rejection)?;
    let mut next = admission.clone();
    next.disposition = admission
        .disposition
        .decide(to)
        .map_err(ownership_rejection)?;
    next.validate().map_err(ownership_rejection)?;
    Ok(next)
}

/// Whether a retained wave still advances mechanically under its current
/// lease. A wave under a non-admitted admission or a superseded/cancelled
/// definition is retained history, never live work.
#[must_use]
pub fn retained_wave_is_live(
    definition: &SwarmPlanDefinition,
    admission: &SwarmPlanAdmission,
    execution: &SwarmExecutionRevision,
) -> bool {
    definition.lifecycle == SwarmPlanDefinitionLifecycle::Frozen
        && admission.disposition == SwarmPlanAdmissionDisposition::Admitted
        && admission.binds(definition)
        && execution_state_is_active(execution.state)
}
