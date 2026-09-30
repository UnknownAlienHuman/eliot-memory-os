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
//! write and the required outbox intent cannot diverge. A closure record — the
//! admitted waiver or the accepted replacement obligation — is committed in that
//! same transition as its state change, so neither is durable only in a caller's
//! return value. A readback through the committed-only `GetAttentionAndProblems`
//! projection therefore reflects exactly the transitions that committed.
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
    OrderingHeadExpectation, OrderingScopeId, PROBLEM_CLOSURE_SUPERSEDED_BY,
    PROBLEM_CLOSURE_WAIVED, PROBLEM_PARAM_AUTHORIZATION_DIGEST, PROBLEM_PARAM_CLOSURE_JSON,
    PROBLEM_PARAM_EXPECTED_REVISION, PROBLEM_PARAM_PROBLEM_ID, PROBLEM_PARAM_RECORD_DIGEST,
    PROBLEM_PARAM_RECORD_JSON, PROBLEM_PARAM_SOURCE_SIGNAL_ID, PROBLEM_PARAM_TRANSITION,
    ProblemOwnerTransition, RevisionHeadExpectation, ScopeId, SecurityContext, StateFence,
    TransitionClass, problem_owner_state_mutation_request, problem_revision_key,
};
use serde_json::Value;

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

/// Projects a state-machine refusal onto the Governor's owner error.
///
/// Takes the error by reference: it is only ever formatted here, and
/// `ProblemError` is `Clone` but not `Copy`, so taking it by value would clone a
/// typed failure on every refused transition just to read its `Display`.
fn problem_refused(error: &eliot_problem::ProblemError) -> CompositionError {
    CompositionError::Owner(format!(
        "problem state machine refused the transition: {error}"
    ))
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

/// The retained record a closure transition produces, exactly as the state
/// machines issue it.
///
/// `Problem` carries no waiver or supersession field, so the committed
/// transition is where both closures are durable: this value is rendered into
/// the transition's `closure_json` parameter, travels inside the canonical
/// request hash, and is read back from the committed transition through
/// `GetAttentionAndProblems`. It is also returned to the caller so a reader does
/// not have to re-derive it.
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
    /// The request identity this transition commits under, derived from the
    /// caller's so the envelope, the receipt binding and the commit all agree on
    /// one per-transition idempotency key.
    pub identity: eliot_protocol::RequestIdentity,
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

/// The bindings of one named owner transition, named once.
///
/// These are the inputs that describe *this transition* and nothing else: the
/// admitted request it commits under, the base operation its own identity
/// derives from, the committed record it replaces, the revision it expects to
/// replace, the Signal it is bound to, the authorization that permits it, the
/// clock its lease window is checked against, and the closed per-verb body.
/// Passing them as one value rather than eight parameters keeps the four
/// bindings the transition must compare together — the Signal, the
/// operation/hash, the expected revision and the current authorization — in one
/// place, so a new parameter cannot be added to one call path and forgotten on
/// the other.
pub struct ProblemOwnerTransitionRequest<'a> {
    /// The admitted request identity this transition commits under.
    pub identity: &'a eliot_protocol::RequestIdentity,
    /// The base operation identity the transition's own identity derives from.
    pub base_operation_id: &'a eliot_contracts::OperationId,
    /// The committed record the caller read, or `None` for `Create` and only for
    /// `Create`.
    pub current: Option<&'a Problem>,
    /// The record revision this transition expects to replace.
    pub expected_revision: u64,
    /// The Signal this transition is bound to.
    pub source_signal: &'a Signal,
    /// The current authorization. Only an [`AuthenticatedOwnerLease`] can appear
    /// here, so no caller can present a principal string instead.
    pub lease: &'a AuthenticatedOwnerLease,
    /// Current time in Unix milliseconds, for the assignment lease's validity
    /// window.
    pub now_ms: u64,
    /// The closed per-verb body, which selects the named transition.
    pub body: &'a ProblemOwnerTransitionBody,
}

impl ProblemOwnerTransitionRequest<'_> {
    /// The Problem this transition addresses, whether it opens one or advances a
    /// committed one.
    fn problem_id(&self) -> Result<String, CompositionError> {
        match (self.current, self.body) {
            (Some(record), _) => Ok(record.problem_id.as_str().to_owned()),
            (None, ProblemOwnerTransitionBody::Create { problem_id, .. }) => {
                Ok(problem_id.as_str().to_owned())
            }
            (None, _) => Err(owner_refused(
                "a problem owner transition needs the committed record it advances, or a create body"
                    .to_owned(),
            )),
        }
    }

    /// The operation identity this transition commits under.
    ///
    /// Derived from the base operation, the Problem, its source Signal, the verb
    /// and the revision it replaces — never from retry time — so an identical
    /// replay reconciles the existing receipt through the store's
    /// `(operation_id, canonical_request_hash)` identity while the same operation
    /// with changed bytes fails closed.
    pub(crate) fn operation_id(&self) -> Result<eliot_contracts::OperationId, CompositionError> {
        let problem_id = self.problem_id()?;
        eliot_contracts::OperationId::new(format!(
            "{base}/problem-{problem_id}-{signal}-{verb}-{revision}",
            base = self.base_operation_id.as_str(),
            signal = self.source_signal.signal_id.as_str(),
            verb = self.body.transition().as_str().to_ascii_lowercase(),
            revision = self.expected_revision,
        ))
        .map_err(|error| owner_refused(error.to_string()))
    }

    /// The admitted request identity this transition commits under.
    ///
    /// A per-transition idempotency key derived from the caller's, the Problem,
    /// the verb and the expected revision, so each transition commits under its
    /// own identity and an identical retry reconciles rather than writing a
    /// second Problem or a second escalation. `prepare` produces this and
    /// publishes it on [`PreparedProblemOwnerTransition`], so the envelope, the
    /// receipt binding and the commit cannot each hold a different one.
    pub(crate) fn transition_identity(
        &self,
    ) -> Result<eliot_protocol::RequestIdentity, CompositionError> {
        Ok(eliot_protocol::RequestIdentity {
            request: self.identity.request.clone(),
            idempotency_key: format!(
                "{}:problem-owner:{}:{}:{}",
                self.identity.idempotency_key,
                self.problem_id()?,
                self.body.transition().as_str(),
                self.expected_revision,
            ),
            deadline_unix_ms: self.identity.deadline_unix_ms,
            cancellation_id: self.identity.cancellation_id.clone(),
        })
    }
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
        .map_err(|error| problem_refused(&error))?;
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
    source.validate().map_err(|error| problem_refused(&error))?;
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

/// Renders the retained closure record as its committed wire value.
///
/// `Problem` carries no waiver or supersession field, so the committed
/// transition is where both closures are durable: the record the state machine
/// returned is rendered here, verbatim from the state machine's own output, and
/// travels inside the canonical request hash. The `kind` member is added so the
/// bridge can hold the record to exactly the member set its verb admitted, and
/// so the readback can tell an accepted risk from a supersession.
fn closure_value(closure: &ProblemOwnerClosure) -> Result<Value, CompositionError> {
    let (mut value, kind) = match closure {
        ProblemOwnerClosure::Waived(record) => (
            serde_json::to_value(record).map_err(|error| {
                owner_refused(format!("cannot render the waiver record: {error}"))
            })?,
            PROBLEM_CLOSURE_WAIVED,
        ),
        ProblemOwnerClosure::SupersededBy(record) => (
            serde_json::to_value(record).map_err(|error| {
                owner_refused(format!("cannot render the supersession record: {error}"))
            })?,
            PROBLEM_CLOSURE_SUPERSEDED_BY,
        ),
    };
    let object = value.as_object_mut().ok_or_else(|| {
        owner_refused("a retained closure record did not render as a JSON object".to_owned())
    })?;
    object.insert("kind".to_owned(), Value::String(kind.to_owned()));
    Ok(value)
}

/// Assembles the closed `ApplyProblemOwnerState` parameter map for one
/// validated candidate.
///
/// Split out of [`problem_owner_envelope`] because the parameter map is what
/// the four bindings *are*, and it is the part that has a rule of its own: the
/// retained closure record is conditional on the verb. Naming it says "these are
/// the bindings, assembled and gated", separately from "this is the envelope
/// they travel in".
fn problem_owner_parameters(
    candidate: &Problem,
    expected_revision: u64,
    source_signal: &Signal,
    transition: ProblemOwnerTransition,
    authorization: &str,
    closure: Option<&ProblemOwnerClosure>,
) -> Result<(BTreeMap<String, Value>, String), CompositionError> {
    let record_json = serde_json::to_value(candidate)
        .map_err(|error| owner_refused(format!("cannot render the candidate record: {error}")))?;
    let record_bytes = canonical_json_bytes(&record_json)
        .map_err(|error| owner_refused(format!("cannot canonicalize the record bytes: {error}")))?;
    let record_digest = sha256_hex(&record_bytes);
    let mut parameters = BTreeMap::new();
    for (name, value) in [
        (
            PROBLEM_PARAM_TRANSITION,
            Value::String(transition.as_str().to_owned()),
        ),
        (
            PROBLEM_PARAM_PROBLEM_ID,
            Value::String(candidate.problem_id.as_str().to_owned()),
        ),
        (
            PROBLEM_PARAM_EXPECTED_REVISION,
            Value::String(expected_revision.to_string()),
        ),
        (
            PROBLEM_PARAM_SOURCE_SIGNAL_ID,
            Value::String(source_signal.signal_id.as_str().to_owned()),
        ),
        (
            PROBLEM_PARAM_AUTHORIZATION_DIGEST,
            Value::String(authorization.to_owned()),
        ),
        (
            PROBLEM_PARAM_RECORD_DIGEST,
            Value::String(record_digest.clone()),
        ),
        (PROBLEM_PARAM_RECORD_JSON, record_json),
    ] {
        parameters.insert(name.to_owned(), value);
    }
    // The retained closure record travels with the transition it was produced
    // by, so an accepted risk or a supersession is durable in the committed
    // history rather than only in the caller's return value. The store gate
    // holds it to exactly the two verbs that may carry one.
    if let Some(closure) = closure {
        parameters.insert(
            PROBLEM_PARAM_CLOSURE_JSON.to_owned(),
            closure_value(closure)?,
        );
    } else if matches!(
        transition,
        ProblemOwnerTransition::Waive | ProblemOwnerTransition::Supersede
    ) {
        return Err(owner_refused(
            "a waive or supersede transition must commit its retained closure record".to_owned(),
        ));
    }
    Ok((parameters, record_digest))
}

/// Builds the canonical envelope for one validated candidate record.
///
/// The four bindings were assembled and gated by [`problem_owner_parameters`];
/// they all travel inside the canonical request hash, so a post-admission edit
/// to any of them is a typed digest mismatch at every downstream recompute gate
/// rather than a silently executed plan.
///
/// The one declared event id is what makes the history write and the outbox
/// intent one atomic unit: the store derives the transition's outbox row from
/// the emitted event id inside the same transaction that writes the command's
/// durable record and the receipt, so a transition can never leave history
/// without its outbox intent or publish an intent for a transition that did not
/// commit.
fn problem_owner_envelope(
    identity: &eliot_protocol::RequestIdentity,
    operation_id: &eliot_contracts::OperationId,
    manifest_digest: &OperationManifestDigest,
    candidate: &Problem,
    expected_revision: u64,
    source_signal: &Signal,
    bindings: (BTreeMap<String, Value>, String),
) -> Result<CanonicalWriteEnvelope, CompositionError> {
    let fence = &identity.request.metadata.state_fence;
    if candidate.state_fence != *fence {
        return Err(owner_refused(
            "candidate record is not bound to the admitted request fence".to_owned(),
        ));
    }
    let (parameters, record_digest) = bindings;
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
            event_ids: vec![
                EventId::new(format!(
                    "event-problem-owner-{}-{}",
                    candidate.problem_id.as_str(),
                    candidate.revision
                ))
                .map_err(|error| owner_refused(error.to_string()))?,
            ],
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
/// The bindings arrive as one [`ProblemOwnerTransitionRequest`], so the four
/// things this transition must compare are held together rather than spread
/// across a parameter list a caller could populate inconsistently. `current` is
/// the committed record the caller read: `Create` is the only verb that has none
/// and therefore the only one that takes `None`; for every other verb a missing
/// record is refused rather than treated as an empty predecessor.
#[allow(
    clippy::too_many_lines,
    reason = "the nine verb arms stay side by side for review"
)]
pub fn prepare_problem_owner_transition(
    manifest_digest: &OperationManifestDigest,
    request: &ProblemOwnerTransitionRequest<'_>,
) -> Result<PreparedProblemOwnerTransition, CompositionError> {
    let identity = request.identity;
    let operation_id = &request.operation_id()?;
    // The transition commits under its own request identity, derived from the
    // caller's so each transition has its own idempotency key. It is produced
    // here rather than by the caller because the envelope, the receipt binding
    // and the commit all have to agree on it, and deriving it in one place is
    // what keeps them from disagreeing.
    let transition_identity = request.transition_identity()?;
    let identity = &transition_identity;
    // Every remaining field is individually `Copy` (a reference, a `u64`, or an
    // `Option<&Problem>`), so the bindings are read out by value once and the
    // rest of the admission reads plain locals rather than `request.` prefixes.
    let current = request.current;
    let expected_revision = request.expected_revision;
    let source_signal = request.source_signal;
    let lease = request.lease;
    let now_ms = request.now_ms;
    let body = request.body;
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
        (
            None,
            ProblemOwnerTransitionBody::Create {
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
            },
        ) => (
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
            .map_err(|error| problem_refused(&error))?,
            None,
        ),
        (Some(record), body) => {
            let mut candidate = record.clone();
            // Only `Waive` and `Supersede` produce a retained closure record, so
            // only those two arms bind it. Every other verb leaves it `None`
            // because it has no closure to retain.
            let mut closure: Option<ProblemOwnerClosure> = None;
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
                    candidate.title.clone_from(title);
                    candidate.symptom.clone_from(symptom);
                    candidate.hypotheses.clone_from(hypotheses);
                    candidate.next_probe.clone_from(next_probe);
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
                    candidate
                        .transition(fence, *next)
                        .map_err(|error| problem_refused(&error))?;
                }
                ProblemOwnerTransitionBody::Assign => {
                    candidate
                        .assign_owner(fence, lease, now_ms)
                        .map_err(|error| problem_refused(&error))?;
                }
                ProblemOwnerTransitionBody::Unassign(loss) => {
                    candidate
                        .record_owner_loss(fence, loss)
                        .map_err(|error| problem_refused(&error))?;
                }
                ProblemOwnerTransitionBody::Escalate { evidence } => {
                    candidate
                        .escalate_obligation(fence, evidence)
                        .map_err(|error| problem_refused(&error))?;
                }
                ProblemOwnerTransitionBody::Resolve(evidence) => {
                    candidate
                        .resolve(fence, evidence)
                        .map_err(|error| problem_refused(&error))?;
                }
                ProblemOwnerTransitionBody::Waive(waiver) => {
                    let record = candidate
                        .accept_risk(fence, waiver)
                        .map_err(|error| problem_refused(&error))?;
                    closure = Some(ProblemOwnerClosure::Waived(record));
                }
                ProblemOwnerTransitionBody::Supersede(supersession) => {
                    let record = candidate
                        .supersede(fence, supersession)
                        .map_err(|error| problem_refused(&error))?;
                    closure = Some(ProblemOwnerClosure::SupersededBy(record));
                }
                ProblemOwnerTransitionBody::Reopen { evidence } => {
                    candidate
                        .reopen(fence, evidence.clone())
                        .map_err(|error| problem_refused(&error))?;
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
    candidate
        .validate()
        .map_err(|error| problem_refused(&error))?;
    // The candidate must be the checked successor of the revision this
    // transition expected, so the persisted history and the readback can never
    // describe a state at a revision nothing replaced. `Create` establishes
    // revision 1 and replaces no predecessor; every other verb derives its
    // successor from the revision it read, and a revision that cannot be
    // incremented is refused rather than panicked on or replaced by a
    // fabricated one. The value came from a committed record, so it is
    // record-controlled input, not an internal invariant.
    let required_revision = match transition {
        ProblemOwnerTransition::Create => Some(1),
        _ => expected_revision.checked_add(1),
    };
    let Some(required_revision) = required_revision else {
        return Err(owner_refused(format!(
            "problem {} is at revision {expected_revision}, which cannot be advanced without reusing a revision",
            current.map_or_else(String::new, |record| record.problem_id.to_string()),
        )));
    };
    if required_revision != candidate.revision {
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
    let bindings = problem_owner_parameters(
        &candidate,
        expected_revision,
        source_signal,
        transition,
        &authorization,
        closure.as_ref(),
    )?;
    let envelope = problem_owner_envelope(
        identity,
        operation_id,
        manifest_digest,
        &candidate,
        expected_revision,
        source_signal,
        bindings,
    )?;
    Ok(PreparedProblemOwnerTransition {
        transition,
        identity: transition_identity,
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
