//! Named Problem owner transitions through the existing canonical boundary
//! (issue #1759 I2, I13.9/I13.7).
//!
//! Nine named transitions — `create`, `update`, `assign`, `unassign`,
//! `escalate`, `resolve`, `waive`, `supersede`, `reopen` — each prepare exactly
//! one `CanonicalWriteEnvelope`, which converts to exactly one
//! [`PreparedTransition`](eliot_store_api::PreparedTransition) and commits
//! through the existing [`crate::CanonicalAdmissionOwner::commit`] boundary.
//! There is no second preparation path and no second transaction API here: the
//! envelope, its digests, the revision-head expectations and the receipt
//! reconciliation are all the existing ones.
//!
//! Each transition binds four things, and each is compared rather than carried:
//!
//! 1. **Source Signal.** The admitted [`Signal`] is validated and must be bound
//!    to the transition's state fence, and its identity must be retained in the
//!    candidate record's `signal_refs`.
//! 2. **Operation and hash.** The verb is a closed wire discriminator inside the
//!    canonical request hash, so one change can never be replayed under another
//!    verb's name, and the candidate record travels with a `record_digest` over
//!    its exact canonical bytes.
//! 3. **Expected record revision.** The caller's expectation is compared with
//!    the committed record's own revision *here*, before anything is prepared,
//!    and the same value is carried as the `problem:{problem_id}` revision-head
//!    expectation, which the store compares against the live head and refuses
//!    with `RevisionConflict` on a mismatch. It is a compare-and-swap, never an
//!    assertion.
//! 4. **Current authorization.** The only thing that can authorize a transition
//!    is an [`AuthenticatedOwnerLease`], whose fields are private and whose sole
//!    construction path re-derives the lease owner's own durable commitment.
//!    This module re-derives that commitment again here, and the candidate
//!    record is then required to retain exactly the resulting lease identity, so
//!    the binding is a comparison against owner-held state and not a value the
//!    caller restated.
//!
//! Pure and effect-separated: the state machine runs on a **candidate copy** of
//! the record and is validated before it replaces anything, so a refused
//! transition leaves the live record byte-identical. The effect is the single
//! canonical commit of the envelope the candidate produced, and the store
//! derives that transition's outbox row from the one declared event id inside
//! the same transaction that writes the command's durable record, so the history
//! write and the required outbox intent cannot diverge. A readback through the
//! committed-only `GetAttentionAndProblems` projection therefore reflects
//! exactly the transitions that committed.
//!
//! Honesty about reachability: no production
//! [`OwnerLeaseIssuer`](eliot_problem::OwnerLeaseIssuer) exists in this tree, so
//! [`AuthenticatedOwnerLease`] is unreachable from the Governor and every
//! transition here is type-sound but production-unreachable until the lease owner
//! supplies one. That is the designed state, not a gap worked around: no
//! principal string is accepted anywhere on this path.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use eliot_canonical::CanonicalWriteEnvelope;
use eliot_contracts::{ArtifactId, EpochId, canonical_json_bytes, sha256_hex};
use eliot_problem::{
    AuthenticatedOwnerLease, AuthorizedWaiver, ClosureEvidence, OwnerLeaseLoss, Problem,
    ProblemClass, ProblemHypothesis, ProblemId, ProblemState, RepairRecord, Signal, Supersession,
    SupersessionRecord, WaiverRecord,
};
use eliot_store_api::{
    EffectClass, EventId, EventProjectionRelationIntents, OperationManifestDigest,
    OrderingHeadExpectation, OrderingScopeId, PROBLEM_PARAM_AUTHORIZATION_DIGEST,
    PROBLEM_PARAM_EXPECTED_REVISION, PROBLEM_PARAM_PROBLEM_ID, PROBLEM_PARAM_RECORD_DIGEST,
    PROBLEM_PARAM_RECORD_JSON, PROBLEM_PARAM_SOURCE_SIGNAL_ID, PROBLEM_PARAM_TRANSITION,
    ProblemOwnerTransition, RevisionHeadExpectation, ScopeId, SecurityContext, StateFence,
    TransitionClass, problem_owner_state_mutation_request, problem_revision_key,
};

use crate::composition::CompositionError;

/// Governor canonical scope addressed by every owner transition.
const PROBLEM_SCOPE_ID: &str = "governor";
/// Ordering scope carried on every owner transition. The store enforces the live
/// sequence; the constant mirrors the existing problem/recovery legs so all
/// canonical writes share one conflict-serialization scope.
const PROBLEM_ORDERING_SCOPE: &str = "scope:governor";
/// Domain separator for the re-proved current-authorization digest.
const AUTHORIZATION_DOMAIN: &str = "eliot.problem.owner-transition-authorization.v1";

fn owner_refused(detail: impl Into<String>) -> CompositionError {
    CompositionError::Owner(detail.into())
}

fn problem_refused(error: eliot_problem::ProblemError) -> CompositionError {
    CompositionError::Owner(format!("problem state machine refused the transition: {error}"))
}

/// The closed per-verb bodies of the nine named transitions.
///
/// One arm per verb, so a caller that can spell `Reopen` cannot reach
/// `Update`'s body and vice versa: the verb is chosen by which body it holds,
/// and the body it must hold is checked against what that verb means.
#[derive(Clone, Debug)]
pub enum ProblemOwnerTransitionBody {
    /// The I13.9 fields a new Problem is opened with.
    Create {
        /// Identity of the Problem being opened.
        problem_id: ProblemId,
        /// I13.9 `class`, which also selects the I13.8 owner route.
        class: ProblemClass,
        /// Record title.
        title: String,
        /// I13.9 `symptom`.
        symptom: String,
        /// I13.9 `scope`.
        scope_id: String,
        /// I13.9 `scope/affected_dependencies`, the exact dependencies hit.
        affected_dependencies: Vec<String>,
        /// I13.9 `hypotheses`, never counted as evidence.
        hypotheses: Vec<ProblemHypothesis>,
        /// I13.9 `next_probe_or_action`.
        next_probe: String,
        /// I13.9 `resolution_condition`, fixed before anyone can close it.
        resolution_condition: String,
        /// The independently expected observables a resolution must cover.
        expected_resolution: Vec<ArtifactId>,
        /// I13.9 `containment` already in force at open.
        containment: Vec<ArtifactId>,
    },
    /// The I13.9 fields an ordinary non-terminal advance may restate.
    Update {
        /// Restated title.
        title: String,
        /// Restated symptom.
        symptom: String,
        /// Restated hypotheses.
        hypotheses: Vec<ProblemHypothesis>,
        /// Restated next discriminative action.
        next_probe: String,
        /// Newly applied containment evidence.
        containment: Vec<ArtifactId>,
        /// A repair attempt to retain in `repair_history`, when one happened.
        repair: Option<RepairRecord>,
        /// The declared non-terminal lifecycle state this advance reaches.
        next: ProblemState,
    },
    /// Assign an eligible successor under the request's new ownership lease.
    Assign,
    /// Record a fenced owner loss and leave the obligation visible.
    Unassign(OwnerLeaseLoss),
    /// Escalate the outstanding reassignment/escalation obligation.
    Escalate {
        /// Evidence that the escalation was actually raised.
        evidence: Vec<ArtifactId>,
    },
    /// Resolve against the independently expected observable set.
    Resolve(ClosureEvidence),
    /// Accept risk under an authorized, scoped, expiring waiver.
    Waive(AuthorizedWaiver),
    /// Reach `superseded` under an accepted replacement obligation.
    Supersede(Supersession),
    /// Reopen a terminal Problem against actual recurrence evidence.
    Reopen {
        /// Evidence that the problem actually recurred.
        evidence: Vec<ArtifactId>,
    },
}

impl ProblemOwnerTransitionBody {
    /// The named transition this body spells.
    ///
    /// Closed and total: each body maps to exactly one verb, so no body can be
    /// committed under another verb's name. `Update` is the one body with two
    /// parts — the restated I13.9 fields and the declared lifecycle edge —
    /// because an ordinary advance is exactly those two things together, while
    /// every terminal edge (`Resolve`, `Waive`, `Supersede`) has its own body and
    /// therefore its own authority.
    #[must_use]
    pub const fn transition(&self) -> ProblemOwnerTransition {
        match self {
            Self::Create { .. } => ProblemOwnerTransition::Create,
            Self::Update { .. } => ProblemOwnerTransition::Update,
            Self::Assign => ProblemOwnerTransition::Assign,
            Self::Unassign(_) => ProblemOwnerTransition::Unassign,
            Self::Escalate { .. } => ProblemOwnerTransition::Escalate,
            Self::Resolve(_) => ProblemOwnerTransition::Resolve,
            Self::Waive(_) => ProblemOwnerTransition::Waive,
            Self::Supersede(_) => ProblemOwnerTransition::Supersede,
            Self::Reopen { .. } => ProblemOwnerTransition::Reopen,
        }
    }
}

/// The retained record a closure transition returns, exactly as the state
/// machines issue it. `Problem` has no waiver or supersession field — the
/// committed transition history is where both are read back from — so this is
/// carried beside the candidate rather than inside it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProblemOwnerClosure {
    /// The authority, limits, expiry and residual risk an accepted risk rests on.
    Waived(WaiverRecord),
    /// The accepted replacement obligation a supersession points at.
    SupersededBy(SupersessionRecord),
}

/// One named owner transition, prepared and ready to commit.
pub struct PreparedProblemOwnerTransition {
    /// The named transition this is.
    pub transition: ProblemOwnerTransition,
    /// The candidate record: already validated, already the checked successor of
    /// the expected revision, and already carrying every binding.
    pub candidate: Problem,
    /// The retained closure of a `Waive` or `Supersede` transition, when that
    /// verb produced one.
    pub closure: Option<ProblemOwnerClosure>,
    /// The envelope carrying every binding. Commit it through the existing
    /// canonical owner; never re-derive or widen it.
    pub envelope: CanonicalWriteEnvelope,
}

/// Re-proves the current authorization and returns its digest.
///
/// The digest is over the lease owner's own commitment as this crate re-derives
/// it, bound to the exact fence and ownership epoch the transition runs under.
/// It is *derived here*, never taken from the caller.
fn authorization_digest(
    lease: &AuthenticatedOwnerLease,
    epoch: &EpochId,
) -> Result<String, CompositionError> {
    let commitment = lease
        .grant()
        .expected_commitment()
        .map_err(problem_refused)?;
    if !lease.grant().authority_epoch.is_same_authority(epoch) {
        return Err(owner_refused(
            "presented ownership lease is not bound to the admitted authority epoch".to_owned(),
        ));
    }
    let bytes = canonical_json_bytes(&(
        AUTHORIZATION_DOMAIN,
        &commitment,
        &lease.identity().lease_id,
        lease.ownership_epoch(),
        &lease.grant().state_fence,
    ))
    .map_err(|error| owner_refused(format!("cannot canonicalize authorization: {error}")))?;
    Ok(sha256_hex(&bytes))
}

/// Validates the admitting Signal and its binding to the transition's fence.
///
/// The Signal is the transition's source, so it is compared, not restated: a
/// Signal from another fence cannot admit a transition under this one.
fn checked_source_signal<'a>(
    source: &'a Signal,
    fence: &StateFence,
) -> Result<&'a Signal, CompositionError> {
    source.validate().map_err(problem_refused)?;
    if source.state_fence != *fence {
        return Err(owner_refused(
            "source Signal is not bound to the transition's state fence".to_owned(),
        ));
    }
    Ok(source)
}

/// Requires the candidate to retain exactly the authorization it was admitted
/// under.
///
/// The lease identity is compared field for field — lease id, commitment and
/// ownership epoch — so an assignment under a newly issued lease, a renewal that
/// moved the commitment on, and a record whose owner was fenced all resolve
/// correctly here instead of committing a history entry that describes an
/// authorization the store never saw.
fn check_retained_authorization(
    candidate: &Problem,
    lease: &AuthenticatedOwnerLease,
) -> Result<(), CompositionError> {
    match &candidate.ownership {
        eliot_problem::Ownership::Unassigned(unassigned) => {
            // An owner loss, or an escalation of one: the record deliberately has
            // no live owner, so the transition's authority is the exact lease
            // identity the loss observed, and it must be the presented one.
            match &unassigned.lost_lease {
                Some(lost) if lost.is_exactly(lease.identity()) => Ok(()),
                Some(_) => Err(owner_refused(
                    "owner transition does not name the presented ownership lease".to_owned(),
                )),
                None => Err(owner_refused(
                    "an unassigned record with no lost lease is not the product of an owner transition"
                        .to_owned(),
                )),
            }
        }
        eliot_problem::Ownership::Assigned(assigned) => {
            if assigned.lease.is_exactly(lease.identity()) {
                Ok(())
            } else {
                Err(owner_refused(
                    "candidate record does not retain the presented ownership lease identity"
                        .to_owned(),
                ))
            }
        }
    }
}

/// Builds the canonical envelope for one validated candidate record.
///
/// The four bindings all live here and all travel inside the canonical request
/// hash, so a post-admission edit to any of them is a typed digest mismatch at
/// every downstream recompute gate rather than a silently executed plan.
///
/// The one declared event id is what makes the history write and the outbox
/// intent one atomic unit: the store derives the transition's outbox row from
/// the emitted event id inside the same transaction that writes the command's
/// durable record and the receipt, so a transition can never leave history
/// without its outbox intent or publish an intent for a transition that did not
/// commit.
#[allow(
    clippy::too_many_arguments,
    reason = "the envelope binds every named-transition input explicitly"
)]
fn problem_owner_envelope(
    identity: &eliot_protocol::RequestIdentity,
    operation_id: &eliot_contracts::OperationId,
    manifest_digest: &OperationManifestDigest,
    candidate: &Problem,
    expected_revision: u64,
    source_signal: &Signal,
    transition: ProblemOwnerTransition,
    authorization: &str,
) -> Result<CanonicalWriteEnvelope, CompositionError> {
    let fence = &identity.request.metadata.state_fence;
    if candidate.state_fence != *fence {
        return Err(owner_refused(
            "candidate record is not bound to the admitted request fence".to_owned(),
        ));
    }
    let record_json = serde_json::to_value(candidate)
        .map_err(|error| owner_refused(format!("cannot render the candidate record: {error}")))?;
    let record_bytes = canonical_json_bytes(&record_json)
        .map_err(|error| owner_refused(format!("cannot canonicalize the record bytes: {error}")))?;
    let record_digest = sha256_hex(&record_bytes);
    let mut parameters = BTreeMap::new();
    for (name, value) in [
        (
            PROBLEM_PARAM_TRANSITION,
            serde_json::Value::String(transition.as_str().to_owned()),
        ),
        (
            PROBLEM_PARAM_PROBLEM_ID,
            serde_json::Value::String(candidate.problem_id.as_str().to_owned()),
        ),
        (
            PROBLEM_PARAM_EXPECTED_REVISION,
            serde_json::Value::String(expected_revision.to_string()),
        ),
        (
            PROBLEM_PARAM_SOURCE_SIGNAL_ID,
            serde_json::Value::String(source_signal.signal_id.as_str().to_owned()),
        ),
        (
            PROBLEM_PARAM_AUTHORIZATION_DIGEST,
            serde_json::Value::String(authorization.to_owned()),
        ),
        (
            PROBLEM_PARAM_RECORD_DIGEST,
            serde_json::Value::String(record_digest.clone()),
        ),
        (PROBLEM_PARAM_RECORD_JSON, record_json),
    ] {
        parameters.insert(name.to_owned(), value);
    }
    let envelope = CanonicalWriteEnvelope {
        operation_id: operation_id.clone(),
        request: identity.request.metadata.clone(),
        idempotency_key: identity.idempotency_key.clone(),
        scope_id: ScopeId::new(PROBLEM_SCOPE_ID)
            .map_err(|error| owner_refused(error.to_string()))?,
        task_id: identity
            .request
            .metadata
            .task_id
            .as_ref()
            .map(|task| task.as_str().to_owned()),
        transition_class: TransitionClass::RecoverySchema,
        requested_effect_ceiling: EffectClass::ReversibleMutation,
        // The admission digest binds the exact candidate bytes: the decision
        // this transition commits is the record it produced, not a restatement
        // of the request that asked for it.
        admission_contract_set_digest: record_digest.clone(),
        operation_manifest_digest: manifest_digest.clone(),
        semantic_commands: vec![problem_owner_state_mutation_request(parameters)],
        event_projection_relation_intents: EventProjectionRelationIntents {
            event_ids: vec![EventId::new(format!(
                "event-problem-owner-{}-{}",
                candidate.problem_id.as_str(),
                candidate.revision
            ))
            .map_err(|error| owner_refused(error.to_string()))?],
            projection_kinds: Vec::new(),
            relation_kinds: Vec::new(),
        },
        security: SecurityContext::default(),
        // The proof this transition itself rests on: the admitted source Signal
        // and the candidate record it produced.
        required_proof_and_approval_refs: vec![
            source_signal.signal_id.as_str().to_owned(),
            record_digest,
        ],
        expected_revision_heads: vec![RevisionHeadExpectation {
            key: problem_revision_key(candidate.problem_id.as_str())
                .map_err(|error| owner_refused(error.to_string()))?,
            expected_revision,
            state_fence: fence.clone(),
        }],
        expected_ordering_heads: vec![OrderingHeadExpectation {
            scope: OrderingScopeId::new(PROBLEM_ORDERING_SCOPE)
                .map_err(|error| owner_refused(error.to_string()))?,
            expected_sequence: 1,
            state_fence: fence.clone(),
        }],
    };
    envelope.validate()?;
    Ok(envelope)
}

/// Prepares one named owner transition on a validated candidate copy.
///
/// `current` is the committed record the caller read. `Create` is the only verb
/// that has none and therefore the only one that takes `None`; for every other
/// verb a missing record is refused rather than treated as an empty predecessor.
#[allow(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "the admission binds every named transition input explicitly, and the nine verb arms stay side by side for review"
)]
pub fn prepare_problem_owner_transition(
    identity: &eliot_protocol::RequestIdentity,
    operation_id: &eliot_contracts::OperationId,
    manifest_digest: &OperationManifestDigest,
    current: Option<&Problem>,
    expected_revision: u64,
    source_signal: &Signal,
    lease: &AuthenticatedOwnerLease,
    now_ms: u64,
    body: &ProblemOwnerTransitionBody,
) -> Result<PreparedProblemOwnerTransition, CompositionError> {
    let fence = &identity.request.metadata.state_fence;
    let transition = body.transition();
    // The expected record revision is compared here, before anything is prepared,
    // and the same value travels as the revision-head expectation the store
    // compares against the live head. A caller that read a moved record is
    // refused rather than allowed to write a history entry describing a
    // predecessor that was never committed. `Create` replaces no predecessor, so
    // its expectation is the absent-or-genesis head the store's own CAS treats as
    // revision one.
    match (transition, current) {
        (ProblemOwnerTransition::Create, None) => {
            if expected_revision != 1 {
                return Err(owner_refused(
                    "create must expect the absent-or-genesis problem revision head".to_owned(),
                ));
            }
        }
        (ProblemOwnerTransition::Create, Some(_)) => {
            return Err(owner_refused(
                "create cannot be prepared against an existing problem record".to_owned(),
            ));
        }
        (_, None) => {
            return Err(owner_refused(
                "only create may be prepared without a committed problem record".to_owned(),
            ));
        }
        (_, Some(record)) if record.revision != expected_revision => {
            return Err(owner_refused(format!(
                "problem {} is at revision {} but the transition expected {expected_revision}",
                record.problem_id, record.revision
            )));
        }
        (_, Some(_)) => {}
    }
    let source_signal = checked_source_signal(source_signal, fence)?;
    let authorization = authorization_digest(lease, &fence.authority_epoch)?;
    if !lease.is_bound_to(fence) {
        return Err(owner_refused(
            "presented ownership lease is not bound to the transition's state fence".to_owned(),
        ));
    }
    // The state machine runs on a candidate copy. A refused transition throws the
    // copy away, so the caller's committed record is never partially mutated.
    let (candidate, closure) = match (current, body) {
        (None, ProblemOwnerTransitionBody::Create {
            problem_id,
            class,
            title,
            symptom,
            scope_id,
            affected_dependencies,
            hypotheses,
            next_probe,
            resolution_condition,
            expected_resolution,
            containment,
        }) => (
            Problem::new(
                problem_id.clone(),
                source_signal,
                *class,
                title.clone(),
                symptom.clone(),
                scope_id.clone(),
                affected_dependencies.clone(),
                hypotheses.clone(),
                lease,
                containment.clone(),
                next_probe.clone(),
                resolution_condition.clone(),
                expected_resolution.clone(),
                fence.clone(),
            )
            .map_err(problem_refused)?,
            None,
        ),
        (Some(record), body) => {
            let mut candidate = record.clone();
            match body {
                ProblemOwnerTransitionBody::Create { .. } => {
                    return Err(owner_refused(
                        "create cannot be prepared against an existing problem record".to_owned(),
                    ));
                }
                ProblemOwnerTransitionBody::Update {
                    title,
                    symptom,
                    hypotheses,
                    next_probe,
                    containment,
                    repair,
                    next,
                } => {
                    candidate.title = title.clone();
                    candidate.symptom = symptom.clone();
                    candidate.hypotheses = hypotheses.clone();
                    candidate.next_probe = next_probe.clone();
                    for artifact in containment {
                        if !candidate.containment.contains(artifact) {
                            candidate.containment.push(artifact.clone());
                        }
                    }
                    if let Some(record) = repair {
                        if record.revision != expected_revision {
                            return Err(owner_refused(
                                "a retained repair must be bound to the revision it was attempted at"
                                    .to_owned(),
                            ));
                        }
                        candidate.repair_history.push(record.clone());
                    }
                    candidate.transition(fence, *next).map_err(problem_refused)?;
                    None
                }
                ProblemOwnerTransitionBody::Assign => {
                    candidate
                        .assign_owner(fence, lease, now_ms)
                        .map_err(problem_refused)?;
                    None
                }
                ProblemOwnerTransitionBody::Unassign(loss) => {
                    candidate
                        .record_owner_loss(fence, loss)
                        .map_err(problem_refused)?;
                    None
                }
                ProblemOwnerTransitionBody::Escalate { evidence } => {
                    candidate
                        .escalate_obligation(fence, evidence.clone())
                        .map_err(problem_refused)?;
                    None
                }
                ProblemOwnerTransitionBody::Resolve(evidence) => {
                    candidate.resolve(fence, evidence).map_err(problem_refused)?;
                    None
                }
                ProblemOwnerTransitionBody::Waive(waiver) => {
                    let record = candidate
                        .accept_risk(fence, waiver)
                        .map_err(problem_refused)?;
                    Some(ProblemOwnerClosure::Waived(record))
                }
                ProblemOwnerTransitionBody::Supersede(supersession) => {
                    let record = candidate
                        .supersede(fence, supersession)
                        .map_err(problem_refused)?;
                    Some(ProblemOwnerClosure::SupersededBy(record))
                }
                ProblemOwnerTransitionBody::Reopen { evidence } => {
                    candidate
                        .reopen(fence, evidence.clone())
                        .map_err(problem_refused)?;
                    None
                }
            }
            (candidate, closure)
        }
        (None, _) => {
            return Err(owner_refused(
                "only create may be prepared without a committed problem record".to_owned(),
            ));
        }
    };
    candidate.validate().map_err(problem_refused)?;
    // The candidate must be the checked successor of the revision this
    // transition expected, so the persisted history and the readback can never
    // describe a state at a revision nothing replaced.
    let required_revision = match transition {
        ProblemOwnerTransition::Create => 1,
        _ => expected_revision.checked_add(1),
    };
    if required_revision != Some(candidate.revision) {
        return Err(owner_refused(
            "candidate record is not the checked successor of the expected revision".to_owned(),
        ));
    }
    if !candidate.signal_refs.contains(&source_signal.signal_id) {
        return Err(owner_refused(
            "candidate record is not bound to the admitted source Signal".to_owned(),
        ));
    }
    check_retained_authorization(&candidate, lease)?;
    let envelope = problem_owner_envelope(
        identity,
        operation_id,
        manifest_digest,
        &candidate,
        expected_revision,
        source_signal,
        transition,
        &authorization,
    )?;
    Ok(PreparedProblemOwnerTransition {
        transition,
        candidate,
        closure,
        envelope,
    })
}

/// What one committed named owner transition produced.
///
/// The `problem` field is the exact candidate the store committed, so a caller
/// never has to re-derive the post-state; the `receipt` is the store's own,
/// returned unchanged.
#[derive(Clone, Debug)]
pub struct ProblemOwnerTransitionOutcome {
    /// The named transition that committed.
    pub transition: ProblemOwnerTransition,
    /// The committed candidate record.
    pub problem: Problem,
    /// The retained closure of a `Waive` or `Supersede` transition, when that
    /// verb produced one.
    pub closure: Option<ProblemOwnerClosure>,
    /// The store's own commit receipt.
    pub receipt: eliot_store_api::WriteReceipt,
}

/// The operation identity a named transition commits under.
///
/// Derived from the base operation, the Problem it addresses, its source Signal
/// and the revision it replaces — never from retry time — so an identical replay
/// reconciles the existing receipt through the store's
/// `(operation_id, canonical_request_hash)` identity while the same operation
/// with changed bytes fails closed.
pub fn problem_owner_operation_id(
    base: &eliot_contracts::OperationId,
    problem_id: &str,
    source_signal_id: &str,
    transition: ProblemOwnerTransition,
    expected_revision: u64,
) -> Result<eliot_contracts::OperationId, CompositionError> {
    eliot_contracts::OperationId::new(format!(
        "{base}/problem-{problem_id}-{source_signal_id}-{transition_word}-{expected_revision}",
        transition_word = transition.as_str().to_ascii_lowercase(),
    ))
    .map_err(|error| owner_refused(error.to_string()))
}
