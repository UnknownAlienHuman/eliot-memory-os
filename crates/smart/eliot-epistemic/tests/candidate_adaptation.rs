//! Cell-declared package proof entrypoint for the owner-local observation
//! adaptation (`smart.epistemic.position`, implementation
//! `src/candidate_adaptation.rs`).
//!
//! `src/lib.rs:9` declares `mod candidate_adaptation;` privately and both of
//! that module's functions are `pub(crate)`, so neither
//! `candidate_adaptation::propose_observed_candidate` nor
//! `candidate_adaptation::observed_candidate` is nameable from an integration
//! test. Every proof below therefore reaches that private module *only* through
//! its public wrapper `eliot_epistemic::propose_observed_candidate`, which is the
//! surface Governor actually consumes
//! (`crates/governor/eliot-governor/src/epistemic_composition.rs:410` and
//! `:596`). Fixtures are shaped like that real call - one acquired
//! `ObservationRecord`, one wire `PositionRequest`, one `CoverageDenominator`,
//! one `ClaimMap`, and an explicit predecessor and travel tuple - rather than
//! like whatever is easiest to build.
//!
//! `src/candidate_adaptation.rs` is outside this work unit's write scope, so it
//! is deliberately left untouched: no inline `#[cfg(test)] mod tests` is added,
//! no `pub(crate)` is widened to `pub`, and no public API, authority ceiling or
//! state owner is changed. That file carries no inline test module to duplicate,
//! so this entrypoint is the cell's executable `ModuleTestCapsule` for that
//! implementation and the only proof of it.
//!
//! Coverage boundary, stated rather than padded. The wrapper contains three
//! private construction steps - `SupportRecord::new`,
//! `EpistemicPositionCandidate::new`, and the defensive re-checks the closure
//! performs on the candidate the wrapper itself built. Reaching them would
//! require a caller-supplied candidate the wrapper never accepts, so they are
//! declared `known_uncovered_behavior` here instead of being faked with an
//! invented constructor. Every *reachable* refusal is proved below: the three
//! input validations in their real order, the claim-map arity/grade gate, the
//! observation closure's status, lifecycle, authority, fence, subject and
//! admitted-record conditions, its private-resolver refusal, and its own
//! capture-validation refusal.

#![allow(clippy::expect_used)]
#![allow(clippy::unwrap_used)]

use std::collections::{BTreeMap, BTreeSet};
use std::num::NonZeroU64;

use eliot_contracts::{
    ArtifactId, ClockReading, EpochId, EpochLineageId, OperationId, ProductId, RequestId,
    ResourceGeneration, SourceId, StateFence, TaskId, TaskRevision, canonical_json_bytes,
    sha256_hex,
};
use eliot_epistemic::propose_observed_candidate;
use eliot_epistemic_contracts::{
    ClaimAuditOutcome, ClaimEntry, ClaimEntryParams, ClaimId, ClaimMap, ClaimVerdict,
    ContractError, CoverageDenominator, CoverageDenominatorParams, DenominatorKind,
    DisclosureClass, EpistemicPositionCandidate, EvidenceGrade, GradeAssignment, ManifestId,
    PaginationBounds, PositionAssertability, PositionRequest, PositionRequestParams, Precision,
    PredecessorId, PrivacyHandling, PropositionId, SnapshotRef, SupportResult, ValidityBounds,
};
use eliot_evidence::{
    Assertability, EpistemicStatus, EvidenceAuthority, EvidenceCoverage, EvidenceEnvelope,
    EvidenceFreshness, LifecycleState, ObservationRecord, Provenance,
};

const SCOPE: &str = "scope-a";
const OTHER_SCOPE: &str = "scope-b";
const QUESTION: &str = "sensor reports a warm room";
const CONTENT: &str = "reported reading: 26 C; calibration not verified";
const RESTATED: &str = "reported reading: 27 C; calibration not verified";
const PROPOSITION: &str = "the room is warm";
const OBSERVED: &str = "observed-source";
const CLAIM: &str = "claim:warm-room";
const MANIFEST: &str = "manifest:position";
const VERSION: &str = "source-v1";
const PRECISION: &str = "file";

/// The one field the module's observation closure reports its refusals under.
const OBSERVED_CANDIDATE: &str = "observed_candidate";
/// The distinct field the claim-map arity/grade gate reports under.
const OBSERVED_CANDIDATE_CLAIMS: &str = "observed_candidate.claims";

/// The four inputs Governor hands the wrapper for one observed proposal.
#[derive(Clone)]
struct Inputs {
    observation: ObservationRecord,
    request: PositionRequest,
    coverage: CoverageDenominator,
    claims: ClaimMap,
}

fn test_epoch(sequence: u64) -> EpochId {
    let lineage = EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000")
        .expect("canonical test lineage-A");
    EpochId::new(
        lineage,
        NonZeroU64::new(sequence).expect("non-zero test sequence"),
    )
    .expect("valid test epoch")
}

fn fence() -> StateFence {
    StateFence::new(test_epoch(1), ResourceGeneration::genesis())
}

fn id(value: &str) -> ArtifactId {
    ArtifactId::new(value).expect("valid fixture artifact id")
}

fn source_id(value: &str) -> SourceId {
    SourceId::new(value).expect("valid fixture source id")
}

/// Digest of one value over its canonical JSON bytes: the same route the module
/// uses for its proof and statement digests.
fn canonical_digest<T: serde::Serialize>(value: &T) -> String {
    sha256_hex(&canonical_json_bytes(value).expect("canonical fixture bytes"))
}

fn validity() -> ValidityBounds {
    ValidityBounds::new(
        SCOPE,
        Some(1_000),
        Some(2_000),
        VERSION,
        Precision(PRECISION.to_owned()),
    )
    .expect("valid fixture validity bounds")
}

/// `WorkScope` is owned by `eliot-receipts`, which this package deliberately
/// does not depend on, so the binding is decoded from its own wire shape instead
/// of being named here. `PositionRequest::validate` still checks it in full:
/// scope identity, generation/fence agreement and fence compatibility.
fn work_scope_wire() -> serde_json::Value {
    serde_json::json!({
        "scope_id": SCOPE,
        "product_id": ProductId::new("fixture-product").expect("valid fixture product id"),
        "resource_generation": ResourceGeneration::genesis(),
        "state_fence": fence(),
    })
}

fn observation() -> ObservationRecord {
    ObservationRecord {
        observation_id: id(OBSERVED),
        source_id: source_id("source"),
        subject: QUESTION.to_owned(),
        content: CONTENT.to_owned(),
        observed_at: ClockReading {
            valid_time_ms: Some(1_000),
            known_time_ms: Some(1_000),
            transaction_sequence: None,
            monotonic_ns: None,
        },
        evidence: EvidenceEnvelope {
            authority: EvidenceAuthority::SourceIdentity,
            freshness: EvidenceFreshness::ExactCandidate,
            coverage: EvidenceCoverage::CompleteForScope,
            status: EpistemicStatus::Observed,
            assertability: Assertability::NonAssertableUnverified,
            provenance: Provenance {
                source_id: source_id("source"),
                capture_route: "fixture.observed-source".to_owned(),
                scope: SCOPE.to_owned(),
                raw_handle: Some(OBSERVED.to_owned()),
                revision: Some(VERSION.to_owned()),
            },
            verification: None,
            state_fence: fence(),
        },
        lifecycle: LifecycleState::Active,
    }
}

fn request_for(records: BTreeSet<ArtifactId>) -> PositionRequest {
    let work_scope =
        serde_json::from_value(work_scope_wire()).expect("valid fixture work-scope binding");
    PositionRequest::new(PositionRequestParams {
        question: QUESTION.to_owned(),
        request_id: RequestId::new("request:observed-1").expect("valid fixture request id"),
        operation_id: OperationId::new("operation:observed-1").expect("valid fixture operation id"),
        idempotency_key: "idem:observed-1".to_owned(),
        work_scope,
        proposition: PropositionId::new(PROPOSITION).expect("valid fixture proposition id"),
        task_id: TaskId::new("task:observed-1").expect("valid fixture task id"),
        attempt_id: "attempt-1".to_owned(),
        revision: TaskRevision::new(1).expect("valid fixture task revision"),
        scope: SCOPE.to_owned(),
        validity: validity(),
        fence: fence(),
        records,
    })
    .expect("valid fixture position request")
}

fn coverage_for(request: &PositionRequest) -> CoverageDenominator {
    CoverageDenominator::new(CoverageDenominatorParams {
        class: "ObservationRecord".to_owned(),
        schema: "eliot.evidence.observation.v1".to_owned(),
        revision: VERSION.to_owned(),
        scope: request.scope.clone(),
        fence: request.fence.clone(),
        members: request.records.clone(),
        roles: BTreeSet::from([OBSERVED.to_owned()]),
        query: None,
        frontier: None,
        snapshot: SnapshotRef::new("fixture-source-snapshot", source_id("source"))
            .expect("valid fixture snapshot reference"),
        exclusions: Vec::new(),
        bounds: PaginationBounds::new(0, 1, 1, false).expect("valid fixture pagination bounds"),
        validity: request.validity.clone(),
        kind: DenominatorKind::CompleteScope,
    })
    .expect("valid fixture coverage denominator")
}

fn claim_entry(
    request: &PositionRequest,
    coverage: &CoverageDenominator,
    claim: &str,
    grade: GradeAssignment,
) -> ClaimEntry {
    ClaimEntry::new(ClaimEntryParams {
        claim: ClaimId::new(claim).expect("valid fixture claim id"),
        statement_digest: canonical_digest(&observation().subject),
        verdict: ClaimVerdict::Withheld,
        audit: ClaimAuditOutcome::NotVerifiableInScope,
        counterevidence: BTreeSet::new(),
        conflict: None,
        authority: EvidenceAuthority::SourceIdentity,
        grade,
        dependencies: BTreeSet::new(),
        bounds: request.validity.clone(),
        temporal: None,
        coverage_digest: coverage.digest.clone(),
        support: request.records.clone(),
        components: BTreeMap::new(),
        unresolved_support: BTreeSet::new(),
        ceiling: EvidenceGrade::Orienting,
        assumptions: BTreeSet::new(),
        discriminators: BTreeSet::new(),
    })
    .expect("valid fixture claim entry")
}

fn claim_map(entries: Vec<ClaimEntry>) -> ClaimMap {
    let admitted = entries.iter().map(|entry| entry.claim.clone()).collect();
    ClaimMap::new(
        ManifestId::new(MANIFEST).expect("valid fixture manifest id"),
        admitted,
        entries,
        Vec::new(),
        BTreeSet::new(),
    )
    .expect("valid fixture claim map")
}

fn unknown_grade() -> GradeAssignment {
    GradeAssignment::unknown("observation without a verifier").expect("valid unknown grade")
}

/// The admitted Governor shape: one acquired observation bound to one inquiry.
fn inputs() -> Inputs {
    let observation = observation();
    let request = request_for(BTreeSet::from([observation.observation_id.clone()]));
    let coverage = coverage_for(&request);
    let claims = claim_map(vec![claim_entry(
        &request,
        &coverage,
        CLAIM,
        unknown_grade(),
    )]);
    Inputs {
        observation,
        request,
        coverage,
        claims,
    }
}

/// The Governor call: open disclosure, unrestricted privacy, no predecessor.
fn propose(inputs: &Inputs) -> Result<EpistemicPositionCandidate, ContractError> {
    propose_for(inputs, &inputs.observation, &inputs.claims, None)
}

fn propose_for(
    inputs: &Inputs,
    observation: &ObservationRecord,
    claims: &ClaimMap,
    predecessor: Option<PredecessorId>,
) -> Result<EpistemicPositionCandidate, ContractError> {
    propose_observed_candidate(
        &inputs.request,
        observation,
        &inputs.coverage,
        claims,
        predecessor,
        (DisclosureClass::Open, PrivacyHandling::Unrestricted),
    )
}

/// Asserts the module's single refusal field, so a differently-typed refusal
/// cannot pass as the one this proof claims.
fn refused(result: Result<EpistemicPositionCandidate, ContractError>, field: &'static str) {
    let refusal = result.expect_err("this adaptation input must be refused");
    assert_eq!(
        refusal,
        ContractError::ImpossibleCombination { field },
        "the module refused under a different typed error than this proof claims"
    );
}

/// The admitted path, asserted field by field against what Governor's
/// `validate_semantics` expects of the candidate the wrapper returns.
#[test]
fn observed_source_evidence_is_admitted_as_a_withheld_quarantined_candidate() {
    let inputs = inputs();
    inputs
        .observation
        .validate()
        .expect("the fixture observation is itself valid");
    inputs
        .request
        .validate()
        .expect("the fixture request is itself valid");
    inputs
        .coverage
        .validate()
        .expect("the fixture denominator is itself valid");
    inputs
        .claims
        .validate()
        .expect("the fixture claim map is itself valid");

    let candidate = propose(&inputs).expect("source-identity evidence is admitted");

    assert_eq!(candidate.proposition, inputs.request.proposition);
    assert_eq!(candidate.scope, inputs.request.scope);
    assert_eq!(candidate.fence, inputs.request.fence);
    assert_eq!(candidate.authority, EvidenceAuthority::SourceIdentity);
    assert_eq!(
        candidate.proposed_assertability,
        PositionAssertability::UnknownWithheldQuarantined
    );
    assert_eq!(
        candidate.unknowns,
        BTreeSet::from(["proposition-unverified".to_owned()])
    );
    assert!(candidate.grade.is_unknown());
    assert!(candidate.verifier.is_none());
    assert!(candidate.invalidation.is_none());
    assert!(candidate.rivals.is_empty());
    assert!(candidate.conflict_digests.is_empty());
    assert!(candidate.temporal_digests.is_empty());

    assert_eq!(candidate.claims.len(), 1);
    let claim = &candidate.claims[0];
    assert_eq!(claim.verdict, ClaimVerdict::Withheld);
    assert_eq!(claim.audit, ClaimAuditOutcome::NotVerifiableInScope);
    assert_eq!(claim.authority, EvidenceAuthority::SourceIdentity);
    assert!(claim.grade.is_unknown());
    assert_eq!(claim.support, inputs.request.records);
    assert!(claim.counterevidence.is_empty());
    assert!(claim.conflict.is_none());
    assert!(claim.assumptions.is_empty());
    assert_eq!(
        claim.statement_digest,
        canonical_digest(&inputs.observation.subject),
        "the claim audits the exact observed subject text"
    );

    assert_eq!(candidate.support.len(), 1);
    let support = &candidate.support[0];
    assert_eq!(support.proposition, inputs.request.proposition);
    assert_eq!(support.result, SupportResult::Unknown);
    assert_eq!(support.handles, inputs.request.records);
    assert_eq!(support.validity, inputs.request.validity);
    assert_eq!(support.task_id, inputs.request.task_id);
    assert_eq!(support.fence, inputs.request.fence);
    assert!(support.grade.is_unknown());
    assert!(support.temporal.is_none());
    assert!(support.assurance.is_none());
    assert!(support.reopen_reason.is_none());

    let proof = canonical_digest(&inputs.observation);
    assert_eq!(support.proof_digest, proof);
    assert_eq!(candidate.proof_digest, proof);
    assert_eq!(candidate.manifest, inputs.claims.manifest);
    assert_eq!(candidate.claim_map_digest, inputs.claims.digest);
    assert_eq!(candidate.coverage_digest, inputs.coverage.digest);
    candidate
        .validate()
        .expect("the admitted candidate satisfies its own frozen digest");
}

/// Everything Governor hands the wrapper comes back out of it unchanged: no
/// normalisation, no dropped field, and a deterministic result for one input.
#[test]
fn governor_input_values_survive_the_wrapper_boundary_unchanged() {
    let inputs = inputs();
    let predecessor =
        PredecessorId::new(canonical_digest(&"prior-candidate")).expect("valid predecessor id");

    let candidate = propose_observed_candidate(
        &inputs.request,
        &inputs.observation,
        &inputs.coverage,
        &inputs.claims,
        Some(predecessor.clone()),
        (DisclosureClass::Quarantined, PrivacyHandling::Purged),
    )
    .expect("a withheld claim survives the narrowest declared travel class");

    assert_eq!(candidate.proposition, inputs.request.proposition);
    assert_eq!(candidate.revision, inputs.request.revision);
    assert_eq!(candidate.request_id, inputs.request.request_id);
    assert_eq!(candidate.operation_id, inputs.request.operation_id);
    assert_eq!(candidate.idempotency_key, inputs.request.idempotency_key);
    assert_eq!(candidate.work_scope, inputs.request.work_scope);
    assert_eq!(candidate.predecessor, Some(predecessor));
    assert_eq!(candidate.task_id, inputs.request.task_id);
    assert_eq!(candidate.attempt_id, inputs.request.attempt_id);
    assert_eq!(candidate.scope, inputs.request.scope);
    assert_eq!(candidate.fence, inputs.request.fence);
    assert_eq!(candidate.manifest, inputs.claims.manifest);
    assert_eq!(candidate.claim_map_digest, inputs.claims.digest);
    assert_eq!(candidate.coverage_digest, inputs.coverage.digest);
    assert_eq!(
        candidate.window_start_ms,
        inputs.request.validity.window_start_ms
    );
    assert_eq!(
        candidate.window_end_ms,
        inputs.request.validity.window_end_ms
    );
    assert_eq!(candidate.version, inputs.request.validity.version);
    assert_eq!(candidate.precision, inputs.request.validity.precision);
    assert_eq!(candidate.disclosure, DisclosureClass::Quarantined);
    assert_eq!(candidate.privacy, PrivacyHandling::Purged);
    assert_eq!(
        candidate.proposed_assertability,
        PositionAssertability::UnknownWithheldQuarantined,
        "the travel class is a ceiling, never a promotion"
    );
    assert!(candidate.grade.is_unknown());

    let first = propose(&inputs).expect("the same input proposes again");
    let second = propose(&inputs).expect("and again");
    assert_eq!(first, second, "one input yields one frozen candidate");
    assert_ne!(
        first.digest, candidate.digest,
        "the travel class and the predecessor are part of the frozen bytes"
    );

    let mut changed = inputs.observation.clone();
    changed.content = RESTATED.to_owned();
    let restated = propose_for(&inputs, &changed, &inputs.claims, None)
        .expect("a restated reading is still an observation");
    assert_ne!(restated.proof_digest, first.proof_digest);
    assert_ne!(restated.digest, first.digest);
    assert_eq!(restated.support[0].result, SupportResult::Unknown);
}

/// The three input validations run first, in that order, and are reported with
/// their own typed fields; the wrapper neither swallows nor remaps them.
#[test]
fn a_tampered_request_denominator_or_claim_map_is_refused_with_its_own_error() {
    let inputs = inputs();

    propose(&inputs).expect("the untampered control is admitted");

    let mut request = inputs.request.clone();
    request.question = "a different question".to_owned();
    assert_eq!(
        propose_observed_candidate(
            &request,
            &inputs.observation,
            &inputs.coverage,
            &inputs.claims,
            None,
            (DisclosureClass::Open, PrivacyHandling::Unrestricted),
        )
        .expect_err("a request whose frozen digest no longer matches is refused"),
        ContractError::DigestMismatch {
            field: "request.digest"
        }
    );

    let mut coverage = inputs.coverage.clone();
    coverage.revision = "source-v2".to_owned();
    assert_eq!(
        propose_observed_candidate(
            &inputs.request,
            &inputs.observation,
            &coverage,
            &inputs.claims,
            None,
            (DisclosureClass::Open, PrivacyHandling::Unrestricted),
        )
        .expect_err("a denominator whose frozen digest no longer matches is refused"),
        ContractError::DigestMismatch {
            field: "coverage.digest"
        }
    );

    let mut claims = inputs.claims.clone();
    claims.digest = canonical_digest(&"not-the-claim-map-digest");
    assert_eq!(
        propose_for(&inputs, &inputs.observation, &claims, None)
            .expect_err("a claim map whose frozen digest no longer matches is refused"),
        ContractError::DigestMismatch {
            field: "claim.digest"
        }
    );
}

/// The wrapper admits exactly one claim, and that claim's grade must be
/// unknown: a known grade would be a rigour claim the observation never made.
#[test]
fn a_claim_map_that_is_not_one_unknown_claim_is_refused() {
    let inputs = inputs();
    let second = claim_entry(
        &inputs.request,
        &inputs.coverage,
        "claim:second",
        unknown_grade(),
    );
    let pair = claim_map(vec![inputs.claims.entries[0].clone(), second]);
    pair.validate()
        .expect("a two-claim map is itself well formed");
    refused(
        propose_for(&inputs, &inputs.observation, &pair, None),
        OBSERVED_CANDIDATE_CLAIMS,
    );

    let graded = claim_entry(
        &inputs.request,
        &inputs.coverage,
        CLAIM,
        GradeAssignment::known(EvidenceGrade::Orienting),
    );
    let graded = claim_map(vec![graded]);
    graded
        .validate()
        .expect("a known-grade map is itself well formed");
    refused(
        propose_for(&inputs, &inputs.observation, &graded, None),
        OBSERVED_CANDIDATE_CLAIMS,
    );
}

/// `Accepted` and `Countered` verdicts are refused by the observation closure
/// itself, not by the claim-map gate: both maps are arity- and grade-legal, and
/// the refusal names the module's own observation field.
#[test]
fn an_accepted_or_countered_claim_cannot_launder_a_withheld_observation() {
    let inputs = inputs();

    let mut accepted_entry = inputs.claims.entries[0].clone();
    accepted_entry.verdict = ClaimVerdict::Accepted;
    accepted_entry.audit = ClaimAuditOutcome::Supported;
    let accepted = claim_map(vec![accepted_entry]);
    accepted
        .validate()
        .expect("an accepted claim map is itself well formed");
    refused(
        propose_for(&inputs, &inputs.observation, &accepted, None),
        OBSERVED_CANDIDATE,
    );

    let mut countered_entry = inputs.claims.entries[0].clone();
    countered_entry.verdict = ClaimVerdict::Countered;
    countered_entry.audit = ClaimAuditOutcome::Contradicted;
    countered_entry.counterevidence = BTreeSet::from([id("counter:reading")]);
    let countered = claim_map(vec![countered_entry]);
    countered
        .validate()
        .expect("a countered claim map is itself well formed");
    refused(
        propose_for(&inputs, &inputs.observation, &countered, None),
        OBSERVED_CANDIDATE,
    );
}

/// The closure admits exactly one observation shape: active, source-identity,
/// fence-matched evidence whose subject is the asked question and whose handle
/// is the single admitted record.
#[test]
fn only_an_active_source_identity_observation_matching_its_inquiry_is_admitted() {
    let inputs = inputs();

    let mut supported = inputs.observation.clone();
    supported.evidence.status = EpistemicStatus::Supported;
    refused(
        propose_for(&inputs, &supported, &inputs.claims, None),
        OBSERVED_CANDIDATE,
    );

    let mut archived = inputs.observation.clone();
    archived.lifecycle = LifecycleState::Quarantined;
    refused(
        propose_for(&inputs, &archived, &inputs.claims, None),
        OBSERVED_CANDIDATE,
    );

    let mut modelled = inputs.observation.clone();
    modelled.evidence.authority = EvidenceAuthority::ModelInterpretation;
    refused(
        propose_for(&inputs, &modelled, &inputs.claims, None),
        OBSERVED_CANDIDATE,
    );

    let mut later_fence = inputs.observation.clone();
    later_fence.evidence.state_fence =
        StateFence::new(test_epoch(2), ResourceGeneration::genesis());
    refused(
        propose_for(&inputs, &later_fence, &inputs.claims, None),
        OBSERVED_CANDIDATE,
    );

    let mut other_subject = inputs.observation.clone();
    other_subject.subject = "a different proposition".to_owned();
    refused(
        propose_for(&inputs, &other_subject, &inputs.claims, None),
        OBSERVED_CANDIDATE,
    );

    let elsewhere = propose_observed_candidate(
        &request_for(BTreeSet::from([id("another-source")])),
        &inputs.observation,
        &inputs.coverage,
        &inputs.claims,
        None,
        (DisclosureClass::Open, PrivacyHandling::Unrestricted),
    );
    refused(elsewhere, OBSERVED_CANDIDATE);

    let widened = propose_observed_candidate(
        &request_for(BTreeSet::from([
            inputs.observation.observation_id.clone(),
            id("a-second-source"),
        ])),
        &inputs.observation,
        &inputs.coverage,
        &inputs.claims,
        None,
        (DisclosureClass::Open, PrivacyHandling::Unrestricted),
    );
    refused(widened, OBSERVED_CANDIDATE);
}

/// The wrapper resolves the acquired observation through the crate's private
/// resolver and refuses whatever that resolver does not call observed.
#[test]
fn a_stale_observation_is_refused_by_the_private_resolver_behind_the_wrapper() {
    let inputs = inputs();
    propose(&inputs).expect("the exact-candidate control is admitted");

    let mut older = inputs.observation.clone();
    older.evidence.freshness = EvidenceFreshness::KnownOlderSnapshot;
    refused(
        propose_for(&inputs, &older, &inputs.claims, None),
        OBSERVED_CANDIDATE,
    );

    let mut stale = inputs.observation.clone();
    stale.evidence.freshness = EvidenceFreshness::Stale;
    refused(
        propose_for(&inputs, &stale, &inputs.claims, None),
        OBSERVED_CANDIDATE,
    );

    let mut unestablished = inputs.observation.clone();
    unestablished.evidence.freshness = EvidenceFreshness::Unknown;
    refused(
        propose_for(&inputs, &unestablished, &inputs.claims, None),
        OBSERVED_CANDIDATE,
    );
}

/// The audited A/A/B counterexample: evidence captured for another scope cannot
/// be relabelled into this inquiry, and the resolver's own scope refusal is
/// reported under the module's observation field.
#[test]
fn evidence_captured_for_another_scope_is_refused() {
    let inputs = inputs();

    let mut foreign = inputs.observation.clone();
    foreign.evidence.provenance.scope = OTHER_SCOPE.to_owned();
    refused(
        propose_for(&inputs, &foreign, &inputs.claims, None),
        OBSERVED_CANDIDATE,
    );
    assert_eq!(
        inputs.observation.evidence.provenance.scope, SCOPE,
        "the refusal relabelled no provenance"
    );
}

/// An observation that fails its own capture validation is refused before it
/// can reach the resolver, whatever its status, lifecycle or authority say.
#[test]
fn an_observation_that_fails_its_own_validation_is_refused() {
    let inputs = inputs();

    let mut blank = inputs.observation.clone();
    blank.content = "   ".to_owned();
    assert!(blank.validate().is_err());
    refused(
        propose_for(&inputs, &blank, &inputs.claims, None),
        OBSERVED_CANDIDATE,
    );

    let mut inverted = inputs.observation.clone();
    inverted.observed_at = ClockReading {
        valid_time_ms: Some(2_000),
        known_time_ms: Some(1_000),
        transaction_sequence: None,
        monotonic_ns: None,
    };
    assert!(inverted.validate().is_err());
    refused(
        propose_for(&inputs, &inverted, &inputs.claims, None),
        OBSERVED_CANDIDATE,
    );
}
