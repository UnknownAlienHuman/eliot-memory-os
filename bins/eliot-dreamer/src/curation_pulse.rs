//! Curation Product Pulse: the narrow observed record of one real admitted
//! Curation route (issue #233).
//!
//! [`CurationProductPulse`] is composed exactly once per admitted Curation job
//! from the records that run actually produced — the A-20 owner screen binding,
//! the Governor-injected validated batch, and the A-31 routed candidate set —
//! and is carried verbatim into the [`crate::DreamResult::Curation`] receipt
//! that the result stage renders as one JSONL line. It records the route that
//! ran, the source/policy/fence identities the run was bound to, the result
//! disposition, the explicit omissions, and the proof ceiling this narrow edge
//! result carries.
//!
//! The composer is pure and read-only. It takes three shared references, holds
//! no `&mut`, reaches no store, invokes no model, tool, or agent, and mutates
//! nothing: it is a projection over owner output, never a decision of its own.
//!
//! Completeness is judged against an INDEPENDENT expected set. The A-20 owner
//! screen binding (`ScreenBinding::screened_targets`) and the admitted batch
//! denominator (`ValidatedCurationBatch::denominator`) are two member lists
//! produced by two different upstream owners, and the composer compares them
//! against each other and against the A-31 routed set — never against a second
//! copy of the list it was handed. A run that leaves any declared member
//! omitted, unprocessed, or refused is `Partial`, never `Complete`, so absence
//! of evidence can never read as safe completeness.
//!
//! Proof ceiling is recorded on two independent fields. [`CURATION_EDGE_PROOF_CEILING`]
//! is what this narrow edge result proves; [`CURATION_PACKAGE_PROOF_CEILING`] is
//! the package-level ceiling, carried separately and never merged into the edge
//! claim. Neither is a real provider/consumer proof, and neither is a Product
//! Pulse promotion: those remain separate gates (W5).

use eliot_contracts::StateFence;
use eliot_dreamer_contracts::{AtomicityMode, CurationRejectionCode, ScreenBinding};
use eliot_dreamer_curation::{CurationCandidateSet, ValidatedCurationBatch};
use serde::{Deserialize, Serialize};

use crate::DreamerError;

/// Exact schema version accepted by [`CurationProductPulse`].
pub const CURATION_PULSE_SCHEMA_VERSION: u32 = 1;

/// Route identity this pulse observes, in the order the run executed it.
///
/// Names the real product entries, not a package name: the A-20 screen stage
/// that admitted the target set, the Dreamer Curation dispatch that proved the
/// binding and the carrier, and the A-31 owner fan-in that routed the batch.
pub const CURATION_PULSE_ROUTE: &str = "eliot-dreamer:curation_screen_stage::resolve_screen_inputs \
-> dispatch_stage::dispatch_curation \
-> eliot_dreamer_curation::route_validated_curation";

/// Proof ceiling of this narrow edge result: a read-only, candidate-only,
/// reversible routing record. It is not lifecycle or influence execution, not a
/// canonical mutation, and not an applied transformation.
pub const CURATION_EDGE_PROOF_CEILING: &str = "candidate_only_read_only_local_edge";

/// Package-level proof ceiling, carried as a separate value and never folded
/// into [`CURATION_EDGE_PROOF_CEILING`]. Package/build proof, real
/// provider/consumer Edge Proof, and Product Pulse promotion stay independent
/// gates; this field records the package ceiling without claiming the others.
pub const CURATION_PACKAGE_PROOF_CEILING: &str = "LOCAL_EXACT_TREE_PACKAGE_PROOF";

/// Fail-closed reason when the routed set, the admitted batch denominator, and
/// the owner screen binding do not describe the same operation.
const CURATION_PULSE_BINDING_REFUSAL: &str = "curation product pulse binding invalid";

/// Returns the closed wire spelling of one routing-only rejection hint.
///
/// Exhaustive with no wildcard arm: extending the owner rejection taxonomy
/// breaks compilation here until the new code is given its wire spelling, so a
/// newly reported reason can never be silently narrated as another one. The
/// hint is a routing classification, never an authority verdict.
fn rejection_hint_spelling(hint: CurationRejectionCode) -> String {
    let spelling = match hint {
        CurationRejectionCode::IdentityMismatch => "identity_mismatch",
        CurationRejectionCode::LineageMismatch => "lineage_mismatch",
        CurationRejectionCode::UnsupportedPrecision => "unsupported_precision",
        CurationRejectionCode::BudgetExceeded => "budget_exceeded",
        CurationRejectionCode::DeadlineExceeded => "deadline_exceeded",
        CurationRejectionCode::Cancelled => "cancelled",
        CurationRejectionCode::PreservationFailed => "preservation_failed",
        CurationRejectionCode::UnsupportedJobShape => "unsupported_job_shape",
    };
    spelling.to_owned()
}

/// One screen finding for one exact routed member.
///
/// The A-31 owner returns exactly one outcome per batch member; this record
/// carries that outcome verbatim plus its routing-only rejection hint. It is a
/// finding, not a verdict: nothing here authorizes a lifecycle transition, and
/// a protected, blocked, or unprocessed member is reported, never discarded.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CurationMemberFinding {
    /// Exact routed member identity the finding names.
    pub member_id: String,
    /// Zero-based batch index the member accounts for.
    pub item_index: u32,
    /// Owner handler identity the member was dispatched to, or `unresolved`.
    pub handler_id: String,
    /// Owner disposition for this member.
    pub disposition: String,
    /// Routing-only rejection hint; absent exactly for a live candidate.
    pub rejection_hint: Option<String>,
    /// Handler calls performed for this member: exactly zero or one.
    pub calls: u32,
    /// Digest of the dispatched request; absent when never dispatched.
    pub request_digest: Option<String>,
    /// Digest carried by the preserved result; absent when never dispatched.
    pub result_digest: Option<String>,
    /// Denominator targets the member was dispatched over, in batch order.
    pub targets: Vec<String>,
}

/// Closed overall disposition of one observed Curation route.
///
/// `Complete` is reachable only when the run was not partial-allowed, no
/// declared denominator member was omitted, and no member was unprocessed or
/// refused. Anything else is `Partial`, so a partial sample can never be
/// reported as a complete one.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CurationPulseDisposition {
    /// Every declared denominator member produced exactly one live candidate.
    Complete,
    /// At least one declared member is omitted, unprocessed, or refused.
    Partial,
}

/// Narrow observed record of one real admitted Curation route.
///
/// Every field is copied from a record the run produced; none is computed from
/// a caller-supplied list that the run itself supplied. The pulse grants no
/// authority: it observes a candidate-only, reversible routing result.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CurationProductPulse {
    /// Exact schema version; must be [`CURATION_PULSE_SCHEMA_VERSION`].
    pub schema_version: u32,
    /// Real route the observation came from.
    pub route: String,
    /// Owning job identity echoed from the routed set.
    pub job_id: String,
    /// Curation request identity echoed from the routed set.
    pub request_id: String,
    /// Owning task identity echoed from the routed set.
    pub task_id: String,
    /// Decision scope identity echoed from the routed set.
    pub scope_id: String,
    /// Dispatch attempt number echoed from the routed set.
    pub attempt: u32,
    /// State fence the whole run was bound to.
    pub state_fence: StateFence,
    /// A-20 owner source snapshot name the binding was screened under.
    pub source_snapshot: String,
    /// A-20 owner source revision the binding was screened under.
    pub source_revision: String,
    /// A-20 owner screen result digest, re-proved against the routed set.
    pub screen_result_digest: String,
    /// A-20 owner screen item digest, re-proved against the routed set.
    pub screen_item_digest: String,
    /// Closed owner registry digest the batch was routed against.
    pub registry_digest: String,
    /// Sealed input digest the batch was routed against.
    pub input_digest: String,
    /// Routing policy identity applied by the run.
    pub policy_id: String,
    /// Routing policy revision applied by the run.
    pub policy_revision: u32,
    /// Aggregation mode applied (`all_or_nothing` or `per_member`).
    pub atomicity: String,
    /// Whether the applied policy admitted partial aggregation.
    pub allow_partial: bool,
    /// Overall observed disposition.
    pub disposition: CurationPulseDisposition,
    /// Denominator total declared by the admitted batch.
    pub expected_total: u32,
    /// Denominator members the A-20 owner screen bound, in binding order.
    pub screened_targets: Vec<String>,
    /// Denominator members the admitted batch declared, in batch order.
    pub denominator_members: Vec<String>,
    /// Identities of the members that produced a live candidate.
    pub candidate_ids: Vec<String>,
    /// One screen finding per routed batch member, in batch order. Every
    /// member is present, including protected, blocked, and unprocessed ones,
    /// so no member is silently dropped from the record.
    pub findings: Vec<CurationMemberFinding>,
    /// Denominator members no routed item covered, sorted.
    pub omitted_targets: Vec<String>,
    /// Member identities never attempted, in batch order.
    pub unprocessed_frontier: Vec<String>,
    /// Members with a live candidate disposition.
    pub accepted: u32,
    /// Members with a duplicate, conflict, abstention, or unsupported result.
    pub rejected: u32,
    /// Members with a blocked, partial, or internal-defect result.
    pub blocked: u32,
    /// Members never attempted.
    pub unprocessed: u32,
    /// Total handler calls performed across all members.
    pub total_handler_calls: u32,
    /// Deterministic routed-set digest the owner sealed.
    pub set_digest: String,
    /// Proof ceiling of this narrow edge result.
    pub proof_ceiling: String,
    /// Package-level proof ceiling, kept separate from the edge ceiling.
    pub package_proof_ceiling: String,
}

/// Whether the routed candidate set is the same operation the screen binding
/// and the admitted batch describe, field for field.
///
/// A rehashed or foreign set fails here instead of being narrated into a
/// receipt: the receipt's whole value is that its denials, findings and
/// promoted candidates belong to exactly the screened operation.
fn echoes_binding(
    set: &CurationCandidateSet,
    screen: &ScreenBinding,
    batch: &ValidatedCurationBatch,
) -> bool {
    set.screen_result_digest == screen.result_digest
        && set.screen_item_digest == screen.item_digest
        && set.request_id == screen.request_id.as_str()
        && set.task_id == screen.task_id
        && set.scope_id == screen.scope_id
        && set.state_fence == screen.state_fence
        && set.state_fence == batch.state_fence
        && set.request_id == batch.request_id
        && set.scope_id == batch.scope_id
        && set.task_id == batch.task_id
        && set.attempt == batch.attempt
        && set.denominator.expected_total == batch.denominator.expected_total
        && set.denominator.members == batch.denominator.members
        && set.denominator.mode == batch.denominator.mode
}

/// Composes the Curation Product Pulse for one completed admitted Curation run.
///
/// Binds the receipt to the operation by CONTENT, never by a second copy of a
/// caller-supplied list: the A-20 owner screen binding, the admitted batch
/// envelope, and the A-31 routed set must agree on request, task, scope, fence,
/// both screen digests, and the exact denominator. Disagreement refuses
/// fail-closed; the composer never repairs, fills, or reorders a set.
///
/// `Complete` requires an all-or-nothing run with an empty omission list, an
/// empty unprocessed frontier, and zero rejected, blocked, or unprocessed
/// members. Partial aggregation, any omission, and any non-candidate member all
/// read as [`CurationPulseDisposition::Partial`].
///
/// # Errors
///
/// Returns [`DreamerError::InvalidAdmission`] when the three owner records do
/// not describe the same operation, or when a denominator total cannot be
/// represented for comparison.
pub(crate) fn compose_curation_pulse(
    screen: &ScreenBinding,
    batch: &ValidatedCurationBatch,
    set: &CurationCandidateSet,
) -> Result<CurationProductPulse, DreamerError> {
    let refused = || DreamerError::InvalidAdmission(CURATION_PULSE_BINDING_REFUSAL);

    // Independent expected set: the A-20 owner screen binding and the admitted
    // batch denominator are produced by two different upstream owners, so
    // comparing them is a genuine cross-check rather than a restatement.
    let mut screened: Vec<&str> = screen.screened_targets.iter().map(String::as_str).collect();
    screened.sort_unstable();
    let mut declared: Vec<&str> = batch
        .denominator
        .members
        .iter()
        .map(String::as_str)
        .collect();
    declared.sort_unstable();
    let expected = usize::try_from(batch.denominator.expected_total).map_err(|_| refused())?;
    // An empty admitted target set refuses rather than producing a vacuously
    // "complete" record: completeness over zero declared members is not
    // evidence of a complete screen.
    if screened.is_empty() || screened != declared || expected != declared.len() {
        return Err(refused());
    }

    // The routed set must echo the same operation the binding and the batch
    // describe; a rehashed or foreign set refuses instead of being narrated.
    if !echoes_binding(set, screen, batch) {
        return Err(refused());
    }

    // Every routed member is reported, not only the live candidates: a
    // protected, refused, or unprocessed member is recorded as a finding so no
    // member disappears from the receipt between the denominator and the
    // promoted candidates.
    let findings: Vec<CurationMemberFinding> = set
        .members
        .iter()
        .map(|member| CurationMemberFinding {
            member_id: member.member_id.clone(),
            item_index: member.item_index,
            handler_id: member.handler_id.clone(),
            disposition: member.disposition.as_str().to_owned(),
            rejection_hint: member.rejection_hint.map(rejection_hint_spelling),
            calls: member.calls,
            request_digest: member.request_digest.clone(),
            result_digest: member.result_digest.clone(),
            targets: member.targets.clone(),
        })
        .collect();
    let candidate_ids: Vec<String> = findings
        .iter()
        .filter(|finding| finding.disposition == "candidate" && finding.calls == 1)
        .map(|finding| finding.member_id.clone())
        .collect();
    let complete = !set.allow_partial
        && set.omitted_targets.is_empty()
        && set.unprocessed_frontier.is_empty()
        && set.rejected == 0
        && set.blocked == 0
        && set.unprocessed == 0;
    let atomicity = match set.atomicity {
        AtomicityMode::AllOrNothing => "all_or_nothing",
        AtomicityMode::PerMember => "per_member",
    };
    Ok(CurationProductPulse {
        schema_version: CURATION_PULSE_SCHEMA_VERSION,
        route: CURATION_PULSE_ROUTE.to_owned(),
        job_id: set.job_id.clone(),
        request_id: set.request_id.clone(),
        task_id: set.task_id.clone(),
        scope_id: set.scope_id.clone(),
        attempt: set.attempt,
        state_fence: set.state_fence.clone(),
        source_snapshot: screen.source_snapshot.clone(),
        source_revision: screen.source_revision.clone(),
        screen_result_digest: screen.result_digest.clone(),
        screen_item_digest: screen.item_digest.clone(),
        registry_digest: set.registry_digest.clone(),
        input_digest: set.input_digest.clone(),
        policy_id: set.policy_id.clone(),
        policy_revision: set.policy_revision,
        atomicity: atomicity.to_owned(),
        allow_partial: set.allow_partial,
        disposition: if complete {
            CurationPulseDisposition::Complete
        } else {
            CurationPulseDisposition::Partial
        },
        expected_total: batch.denominator.expected_total,
        screened_targets: screen.screened_targets.clone(),
        denominator_members: batch.denominator.members.clone(),
        candidate_ids,
        findings,
        omitted_targets: set.omitted_targets.clone(),
        unprocessed_frontier: set.unprocessed_frontier.clone(),
        accepted: set.accepted,
        rejected: set.rejected,
        blocked: set.blocked,
        unprocessed: set.unprocessed,
        total_handler_calls: set.total_handler_calls,
        set_digest: set.set_digest.clone(),
        proof_ceiling: CURATION_EDGE_PROOF_CEILING.to_owned(),
        package_proof_ceiling: CURATION_PACKAGE_PROOF_CEILING.to_owned(),
    })
}

/// Builds a shape-valid pulse for fixtures that assemble a
/// [`crate::DreamResult::Curation`] without running a real admitted route.
///
/// Only the shape, the route identity, and the two proof ceilings carry
/// meaning here; every identity and count is an explicit fixture value, and the
/// disposition is [`CurationPulseDisposition::Partial`] because a fixture run
/// covers none of its declared denominator members honestly.
#[cfg(test)]
pub(crate) fn fixture_pulse(
    job_id: &str,
    request_id: &str,
    task_id: &str,
    scope_id: &str,
    state_fence: &StateFence,
    screened_targets: Vec<String>,
    candidate_ids: Vec<String>,
) -> CurationProductPulse {
    let denominator_members = screened_targets.clone();
    let expected_total = u32::try_from(denominator_members.len()).unwrap_or(u32::MAX);
    let findings: Vec<CurationMemberFinding> = candidate_ids
        .iter()
        .map(|member_id| CurationMemberFinding {
            member_id: member_id.clone(),
            item_index: 0,
            handler_id: "fixture".to_owned(),
            disposition: "candidate".to_owned(),
            rejection_hint: None,
            calls: 1,
            request_digest: None,
            result_digest: None,
            targets: screened_targets.clone(),
        })
        .collect();
    CurationProductPulse {
        schema_version: CURATION_PULSE_SCHEMA_VERSION,
        route: CURATION_PULSE_ROUTE.to_owned(),
        job_id: job_id.to_owned(),
        request_id: request_id.to_owned(),
        task_id: task_id.to_owned(),
        scope_id: scope_id.to_owned(),
        attempt: 1,
        state_fence: state_fence.clone(),
        source_snapshot: format!("job:{job_id}:evidence"),
        source_revision: "r1".to_owned(),
        screen_result_digest: eliot_contracts::sha256_hex(format!("{job_id}:screen").as_bytes()),
        screen_item_digest: eliot_contracts::sha256_hex(format!("{job_id}:item").as_bytes()),
        registry_digest: eliot_contracts::sha256_hex(b"fixture-registry"),
        input_digest: eliot_contracts::sha256_hex(format!("{job_id}:input").as_bytes()),
        policy_id: "eliot-dreamer-dispatch".to_owned(),
        policy_revision: 1,
        atomicity: "all_or_nothing".to_owned(),
        allow_partial: false,
        disposition: CurationPulseDisposition::Partial,
        expected_total,
        screened_targets,
        denominator_members,
        candidate_ids,
        findings,
        omitted_targets: Vec::new(),
        unprocessed_frontier: Vec::new(),
        accepted: 0,
        rejected: 0,
        blocked: 0,
        unprocessed: 0,
        total_handler_calls: 0,
        set_digest: eliot_contracts::sha256_hex(format!("{job_id}:set").as_bytes()),
        proof_ceiling: CURATION_EDGE_PROOF_CEILING.to_owned(),
        package_proof_ceiling: CURATION_PACKAGE_PROOF_CEILING.to_owned(),
    }
}
