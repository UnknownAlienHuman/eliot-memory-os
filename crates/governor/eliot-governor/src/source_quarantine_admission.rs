//! Owner-bound admission of an external-source quarantine (issue #1760 item 5).
//!
//! A candidate source assessment may *propose* a restriction, and the finite
//! indicator-to-source map is what lets one reach this module at all: only an
//! independent observation carrying a deterministic rule binding, over complete
//! comparison inputs, resolves to
//! [`IndicatorResolution::BoundedRestriction`]. A model proposal resolves to
//! [`IndicatorResolution::CandidateOnly`], which carries no restriction payload,
//! so it cannot be named here — and even if one were constructed, it would still
//! need a [`PromotionAuthority`], whose closed pair of a deterministic policy
//! rule and an authorized Human decision has no model member to name itself
//! with. A model-only assessment therefore produces zero quarantine, Incident
//! and authority mutations, structurally rather than by a threshold.
//!
//! What a quarantine admission binds, and where each fact is compared rather
//! than restated:
//!
//! 1. **The affected source revision** comes from the admitted restriction's own
//!    [`AssessedSourceRevision`] and is checked against the source owner read
//!    for this operation: `ProposedSourceRestriction::resolve_use` refuses a
//!    moved fence, a different source, and a moved profile, so a decision taken
//!    against a predecessor revision cannot quarantine its successor.
//! 2. **The exact dependency closure** is the affected set of a bounded
//!    revocation outcome that has been re-bound here through
//!    [`BoundedRevocationOutcome::verify_binding`], which recomputes the closure
//!    from the request's own qualified edges and compares by content. That is
//!    the difference between a closure proven against the edges and one checked
//!    against a copy of its own list: a member the graph cannot reach from the
//!    origin, a repeated member, or a missing origin refuses. The affected set
//!    is then carried verbatim inside the transition's own canonical request
//!    hash, so a later readback compares the committed closure itself rather
//!    than a claim about it.
//! 3. **The permitted effect** is the narrowed effect set `resolve_use` computed
//!    from the assurance in force, never the class's static table.
//! 4. **The expected state revision** is the caller's expectation, compared here
//!    with the committed record's own revision and compared again inside
//!    [`Problem::open_for_revocation`], then carried as the `problem:{id}`
//!    revision-head expectation the store arbitrates.
//! 5. **The owner** is compared with the quarantined record's live assigned
//!    holder, so a restriction cannot be admitted against a record whose owner
//!    was fenced — there is nobody accountable to release it.
//! 6. **The release/rebuild condition** is the admitted restriction's own
//!    discriminating-evidence condition, so what lifts the restriction is the
//!    rule's statement and not a caller's prose.
//!
//! Division of labour: this module *prepares*. It runs the state machine on a
//! candidate copy, so a refused admission leaves the live record byte-identical,
//! and it hands the caller exactly one [`CanonicalWriteEnvelope`] on the existing
//! `ApplyProblemOwnerState` leg — the same envelope builder, the same named
//! mutation, the same revision-head compare-and-set and the same digest gates
//! the nine named owner transitions use. The store bridge decodes that mutation,
//! compares the retained restriction against the presented Problem identity and
//! expected revision, checks the record it commits is actually quarantined, and
//! receipts it. Nothing here executes a write, and no second preparation path or
//! transaction API is introduced.

#![forbid(unsafe_code)]

use eliot_canonical::CanonicalWriteEnvelope;
use eliot_contracts::{ArtifactId, StateFence, canonical_json_bytes, sha256_hex};
use eliot_influence::{BoundedRevocationOutcome, BoundedRevocationRequest, RevocationBounds};
use eliot_problem::{
    OwnerRef, Problem, ProblemError, PromotionAuthority, RevocationQuarantine,
    RevocationRebuildOrder, Signal,
};
use eliot_security_contracts::{
    AssessedSourceRevision, EffectCeiling, IndicatorResolution, SourceAssurance,
};
use eliot_store_api::{OperationManifestDigest, ProblemOwnerTransition};
use serde_json::{Map, Value};

use crate::composition::CompositionError;
use crate::problem_owner_transitions::{
    ProblemOwnerClosure, checked_source_signal, problem_owner_envelope, problem_owner_parameters,
};

/// Domain separator for the re-proved admission authorization of a quarantine.
///
/// Derived here over the deterministic rule or authorized decision, the admitted
/// source revision, the verified affected closure, the accountable owner and the
/// expected revision. It is never read back from the caller: a restriction
/// admitted under another authority, another source revision, another closure or
/// another owner computes a different digest and cannot be replayed under the
/// same identity.
const QUARANTINE_AUTHORIZATION_DOMAIN: &str = "eliot.governor.source-quarantine-authorization.v1";

fn refused(detail: impl Into<String>) -> CompositionError {
    CompositionError::Owner(detail.into())
}

fn problem_refused(error: &ProblemError) -> CompositionError {
    refused(format!("problem state machine refused the quarantine: {error}"))
}

fn influence_refused(error: &eliot_influence::InfluenceError) -> CompositionError {
    refused(format!("influence closure refused the quarantine: {error}"))
}

/// The retained, owner-bound source restriction one admitted quarantine commits.
///
/// This is the record the store keeps and a later reader compares against, so it
/// carries the whole admitted restriction rather than only the rebuild
/// condition: which exact source revision and digest, which exact affected
/// closure, which bounded permitted effect, which expected state revision, which
/// accountable owner, which deterministic rule or authorized decision, and which
/// release/rebuild condition lifted it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceQuarantineDecision {
    /// The Problem this restriction quarantines.
    pub problem_id: String,
    /// The record revision the admission replaced.
    pub expected_problem_revision: u64,
    /// The exact affected source revision, digest and declared scope.
    pub assessed_source: AssessedSourceRevision,
    /// The exact affected dependency closure.
    pub dependency_closure: Vec<String>,
    /// Dependents the bounded traversal retained in its frontier rather than
    /// propagating. Empty when the traversal was complete; never a silent
    /// expansion to "everything reachable".
    pub retained_frontier: Vec<String>,
    /// The bounded quarantined scope, consumed verbatim from the closure.
    pub impacted_scopes: Vec<String>,
    /// The bounded effect the restricted scope may still cause.
    pub permitted_effects: Vec<EffectCeiling>,
    /// The accountable owner of the restricted scope.
    pub owner: OwnerRef,
    /// The deterministic rule or authorized decision that admitted it.
    pub authority: PromotionAuthority,
    /// The discriminating evidence that releases the restriction.
    pub release_condition: String,
    /// The rebuild-from-clean-inputs requirement, which is the same admitted
    /// condition: the quarantined record is rebuilt from clean inputs
    /// satisfying `release_condition`, never from the restricted source.
    pub rebuild_condition: String,
}

impl SourceQuarantineDecision {
    /// Renders the retained record, without the wire `kind` discriminator the
    /// shared closure assembler adds.
    ///
    /// # Errors
    ///
    /// Returns [`CompositionError::Owner`] when a member cannot be rendered as
    /// canonical JSON.
    pub fn render(&self) -> Result<Map<String, Value>, CompositionError> {
        let source = serde_json::to_value(&self.assessed_source)
            .map_err(|error| refused(format!("cannot render the assessed source: {error}")))?;
        let authority = serde_json::to_value(&self.authority)
            .map_err(|error| refused(format!("cannot render the admitting authority: {error}")))?;
        let owner = serde_json::to_value(&self.owner)
            .map_err(|error| refused(format!("cannot render the accountable owner: {error}")))?;
        let effects = self
            .permitted_effects
            .iter()
            .map(|effect| {
                serde_json::to_value(effect).map_err(|error| {
                    refused(format!("cannot render a permitted effect: {error}"))
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let strings = |values: &[String]| {
            values
                .iter()
                .map(|value| Value::String(value.clone()))
                .collect::<Vec<_>>()
        };
        let mut members = Map::new();
        for (name, value) in [
            ("problem_id", Value::String(self.problem_id.clone())),
            (
                "expected_problem_revision",
                Value::String(self.expected_problem_revision.to_string()),
            ),
            ("assessed_source", source),
            (
                "dependency_closure",
                Value::Array(strings(&self.dependency_closure)),
            ),
            (
                "retained_frontier",
                Value::Array(strings(&self.retained_frontier)),
            ),
            ("impacted_scopes", Value::Array(strings(&self.impacted_scopes))),
            ("permitted_effects", Value::Array(effects)),
            ("owner", owner),
            ("authority", authority),
            (
                "release_condition",
                Value::String(self.release_condition.clone()),
            ),
            (
                "rebuild_condition",
                Value::String(self.rebuild_condition.clone()),
            ),
        ] {
            members.insert(name.to_owned(), value);
        }
        Ok(members)
    }
}

/// Everything one quarantine admission binds, named once.
///
/// These are the inputs that describe *this* admission and nothing else. The
/// affected source revision, the permitted effect and the release condition are
/// not fields here on purpose: they are read out of the admitted resolution, so
/// a caller cannot restate a restriction its own indicator map did not produce.
#[derive(Clone, Copy)]
pub struct SourceQuarantineAdmissionRequest<'a> {
    /// The admitted request identity this admission commits under.
    pub identity: &'a eliot_protocol::RequestIdentity,
    /// The base operation identity the admission's own identity derives from.
    pub base_operation_id: &'a eliot_contracts::OperationId,
    /// The committed Problem the caller read.
    pub current: &'a Problem,
    /// The record revision this admission expects to replace.
    pub expected_revision: u64,
    /// The Signal this transition is bound to, as the nine named verbs are.
    pub source_signal: &'a Signal,
    /// The indicator resolution the finite map produced for this source
    /// revision. `CandidateOnly` refuses here, which is what makes a model-only
    /// assessment unable to admit a quarantine.
    pub resolution: &'a IndicatorResolution,
    /// The assurance the source owner resolves for this exact operation.
    pub current_assurance: &'a SourceAssurance,
    /// The bounded revocation request whose qualified edges the closure is
    /// proven against.
    pub closure_request: &'a BoundedRevocationRequest,
    /// The bounds that traversal ran under.
    pub closure_bounds: &'a RevocationBounds,
    /// The bounded traversal outcome carrying the affected closure.
    pub closure_outcome: &'a BoundedRevocationOutcome,
    /// The deterministic rule or authorized decision that admits the
    /// restriction.
    pub authority: &'a PromotionAuthority,
    /// The accountable owner, compared with the record's live holder.
    pub owner: &'a OwnerRef,
    /// The retained evidence the restriction rests on.
    pub revocation_evidence: &'a [ArtifactId],
}

impl SourceQuarantineAdmissionRequest<'_> {
    /// The operation identity this admission commits under.
    ///
    /// Derived from the base operation, the Problem, the verb and the revision
    /// it replaces — never from retry time — so an identical replay reconciles
    /// the existing receipt through the store's
    /// `(operation_id, canonical_request_hash)` identity while the same
    /// operation with changed bytes fails closed.
    fn operation_id(&self) -> Result<eliot_contracts::OperationId, CompositionError> {
        eliot_contracts::OperationId::new(format!(
            "{base}/problem-{problem_id}-{verb}-{revision}",
            base = self.base_operation_id.as_str(),
            problem_id = self.current.problem_id.as_str(),
            verb = ProblemOwnerTransition::Quarantine
                .as_str()
                .to_ascii_lowercase(),
            revision = self.expected_revision,
        ))
        .map_err(|error| refused(error.to_string()))
    }

    /// The admitted request identity this admission commits under.
    ///
    /// A per-transition idempotency key derived from the caller's, the Problem,
    /// the verb and the expected revision, so an identical retry reconciles
    /// rather than quarantining twice.
    fn admission_identity(&self) -> Result<eliot_protocol::RequestIdentity, CompositionError> {
        Ok(eliot_protocol::RequestIdentity {
            request: self.identity.request.clone(),
            idempotency_key: format!(
                "{}:source-quarantine:{problem_id}:{revision}",
                self.identity.idempotency_key,
                problem_id = self.current.problem_id.as_str(),
                revision = self.expected_revision,
            ),
            deadline_unix_ms: self.identity.deadline_unix_ms,
            cancellation_id: self.identity.cancellation_id.clone(),
        })
    }
}

/// One admitted quarantine, prepared and ready to commit.
pub struct PreparedSourceQuarantineAdmission {
    /// The named transition this is.
    pub transition: ProblemOwnerTransition,
    /// The request identity it commits under.
    pub identity: eliot_protocol::RequestIdentity,
    /// The operation identity it commits under.
    pub operation_id: eliot_contracts::OperationId,
    /// The quarantined candidate Problem, already validated.
    pub candidate: Problem,
    /// The typed rebuild-from-clean-inputs order the state machine issued.
    pub order: RevocationRebuildOrder,
    /// The retained owner-bound restriction.
    pub decision: SourceQuarantineDecision,
    /// The envelope carrying every binding. Commit it through the existing
    /// canonical owner; never re-derive or widen it.
    pub envelope: CanonicalWriteEnvelope,
}

/// Re-proves the admitting authority against the restriction's own rule
/// binding, and returns its digest.
///
/// The two authorities the closed enum admits are bound differently, because
/// they are different facts: a deterministic policy rule must be the *same*
/// rule the indicator map bound when it produced the restriction, so a decision
/// under one rule cannot carry a restriction another rule proposed; an
/// authorized Human decision names its own admitted record and is not tied to
/// an indicator rule, but it must still be present and non-blank.
fn quarantine_authorization(
    authority: &PromotionAuthority,
    restriction: &eliot_security_contracts::ProposedSourceRestriction,
    digest_input: &str,
) -> Result<String, CompositionError> {
    authority
        .validate()
        .map_err(|error| problem_refused(&error))?;
    if let PromotionAuthority::DeterministicPolicy { rule_id } = authority
        && rule_id != &restriction.rule_ref
    {
        return Err(refused(
            "the admitting deterministic rule is not the rule this restriction was produced by"
                .to_owned(),
        ));
    }
    let bytes = canonical_json_bytes(&(
        QUARANTINE_AUTHORIZATION_DOMAIN,
        authority,
        &restriction.rule_ref,
        &restriction.rule_revision,
        digest_input,
    ))
    .map_err(|error| refused(format!("cannot canonicalize the quarantine authorization: {error}")))?;
    Ok(sha256_hex(&bytes))
}

/// Prepares one owner-bound source quarantine on a candidate copy of the record.
///
/// Every comparison below runs before the envelope is built, so a refusal leaves
/// the caller's committed record byte-identical and produces no transition.
///
/// # Errors
///
/// Returns [`CompositionError`] when the identity fence, the record revision,
/// the source Signal, the admitting authority, the accountable owner, the
/// source revision or the dependency closure does not hold, or when the Problem
/// state machine refuses the quarantine.
#[allow(
    clippy::too_many_lines,
    reason = "the six bound facts are checked side by side so each refusal names the binding it refused"
)]
pub fn prepare_source_quarantine_admission(
    manifest_digest: &OperationManifestDigest,
    request: &SourceQuarantineAdmissionRequest<'_>,
) -> Result<PreparedSourceQuarantineAdmission, CompositionError> {
    let operation_id = request.operation_id()?;
    let identity = request.admission_identity()?;
    let fence: &StateFence = &identity.request.metadata.state_fence;

    let current = request.current;
    if current.revision != request.expected_revision {
        return Err(refused(format!(
            "problem {} is at revision {} but the quarantine expected {}",
            current.problem_id, current.revision, request.expected_revision
        )));
    }
    let source_signal = checked_source_signal(request.source_signal, fence)?;
    // The owner is compared with the record's own live holder rather than
    // restated: a record whose owner was fenced has no accountable party to
    // release a restriction, so the obligation stays outstanding on the record
    // until it is reassigned.
    if &current.ownership.assigned().map_err(|error| problem_refused(&error))?.holder != request.owner
    {
        return Err(refused(
            "the accountable owner is not the quarantined record's live owner".to_owned(),
        ));
    }

    // The proposal itself: a candidate-only resolution has no restriction
    // payload to name, so a model-only assessment stops here with zero
    // quarantine, Incident and authority mutations.
    let restriction = match request.resolution {
        IndicatorResolution::BoundedRestriction(restriction) => restriction,
        IndicatorResolution::CandidateOnly { indicator, .. } => {
            return Err(refused(format!(
                "indicator {} resolved to candidate evidence only and may propose but never admit a quarantine",
                indicator.name()
            )));
        }
    };
    // The affected source revision, checked against the assurance in force: a
    // fence that moved, a source that changed, or a profile that no longer
    // matches refuses instead of quarantining a later revision.
    let narrowed = restriction
        .resolve_use(request.current_assurance, fence)
        .map_err(|error| {
            refused(format!(
                "the admitted restriction no longer resolves against the source in force: {error}"
            ))
        })?;

    // The exact dependency closure, proven against the traversal's own edges.
    request
        .closure_outcome
        .verify_binding(request.closure_request, request.closure_bounds)
        .map_err(|error| influence_refused(&error))?;
    if request.closure_request.root_ref != restriction.assessed_source.source_ref {
        return Err(refused(
            "the revocation closure is rooted at a different source than the restriction binds"
                .to_owned(),
        ));
    }
    if request.closure_request.state_fence != *fence {
        return Err(refused(
            "the revocation closure was computed under a different state fence".to_owned(),
        ));
    }
    let dependency_closure = request.closure_outcome.affected_refs.clone();
    if !dependency_closure
        .iter()
        .any(|member| member == &restriction.assessed_source.source_ref)
    {
        return Err(refused(
            "the affected closure does not contain the restricted source itself".to_owned(),
        ));
    }

    let permitted_effects = narrowed.permitted_effects.clone();
    if permitted_effects.is_empty() {
        return Err(refused(
            "an admitted restriction must leave at least one bounded permitted effect".to_owned(),
        ));
    }

    // The revocation request is derived, not restated: the scope, the closure,
    // the permitted effect, the source revision and the release condition all
    // come from what was verified above.
    let quarantine = RevocationQuarantine {
        impacted_scopes: dependency_closure.clone(),
        revocation_evidence: request.revocation_evidence.to_vec(),
        revoked_source_ref: restriction.assessed_source.source_ref.clone(),
        rebuild_condition: restriction.release_condition.clone(),
        assessed_source: restriction.assessed_source.clone(),
        dependency_closure: dependency_closure.clone(),
        permitted_effects: permitted_effects.clone(),
        expected_state_revision: request.expected_revision,
        owner: request.owner.clone(),
        authority: request.authority.clone(),
    };

    // The state machine runs on a candidate copy: a refused quarantine throws
    // the copy away and the caller's committed record is untouched.
    let mut candidate = current.clone();
    let order = candidate
        .open_for_revocation(fence, &quarantine)
        .map_err(|error| problem_refused(&error))?;
    if !candidate.signal_refs.contains(&source_signal.signal_id) {
        return Err(refused(
            "the quarantined candidate is not bound to the admitted source Signal".to_owned(),
        ));
    }

    let decision = SourceQuarantineDecision {
        problem_id: candidate.problem_id.as_str().to_owned(),
        expected_problem_revision: request.expected_revision,
        assessed_source: restriction.assessed_source.clone(),
        dependency_closure: dependency_closure.clone(),
        retained_frontier: request.closure_outcome.frontier.clone(),
        impacted_scopes: dependency_closure.clone(),
        permitted_effects,
        owner: request.owner.clone(),
        authority: request.authority.clone(),
        release_condition: restriction.release_condition.clone(),
        rebuild_condition: order.rebuild_condition.clone(),
    };
    let authorization = quarantine_authorization(
        request.authority,
        restriction,
        &format!(
            "{}|{}|{}|{}|{}",
            decision.problem_id,
            decision.dependency_closure.join(","),
            decision.expected_problem_revision,
            decision.owner.principal,
            decision.release_condition,
        ),
    )?;
    let closure = ProblemOwnerClosure::QuarantinedForRebuild(decision.render()?);
    let bindings = problem_owner_parameters(
        &candidate,
        request.expected_revision,
        source_signal,
        ProblemOwnerTransition::Quarantine,
        &authorization,
        Some(&closure),
    )?;
    let envelope = problem_owner_envelope(
        &identity,
        &operation_id,
        manifest_digest,
        &candidate,
        request.expected_revision,
        source_signal,
        bindings,
    )?;
    Ok(PreparedSourceQuarantineAdmission {
        transition: ProblemOwnerTransition::Quarantine,
        identity,
        operation_id,
        candidate,
        order,
        decision,
        envelope,
    })
}

/// What one committed source quarantine produced.
#[derive(Clone, Debug)]
pub struct SourceQuarantineOutcome {
    /// The named transition that committed.
    pub transition: ProblemOwnerTransition,
    /// The committed quarantined candidate record.
    pub problem: Problem,
    /// The retained rebuild-from-clean-inputs order the state machine issued.
    pub order: RevocationRebuildOrder,
    /// The retained owner-bound restriction.
    pub decision: SourceQuarantineDecision,
    /// The store's own commit receipt.
    pub receipt: eliot_store_api::WriteReceipt,
}