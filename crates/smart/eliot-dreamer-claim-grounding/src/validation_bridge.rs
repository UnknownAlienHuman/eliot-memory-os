//! Production construction site for the A-14b -> A-05 grounding receipt
//! carrier that this functional cell owns.
//!
//! Ownership. `crates/smart/cognitive-wave-10.toml` records
//! `[[ownership]] public_type = "GroundingValidationInput"`,
//! `rust_owner = "eliot-dreamer-claim-grounding"`, and `module.toml` declares
//! the cell (`smart.dreamer.claim_grounding`, `agent_order = 14`) whose
//! declared output is the `GroundedDreamDraft` handoff value and whose
//! declared consumer is `eliot-dreamer-candidate-validation`. The carrier
//! type itself is a frozen contracts-crate value
//! (`crates/smart/eliot-dreamer-contracts/src/validation/structured/mod.rs`),
//! so this crate owns the single production *construction* site for it within
//! this crate's own published surface, and `A2.3`/`ARCH-MOD-03` ("one causal
//! responsibility, one owner") keeps that site here instead of in a
//! composition root.
//!
//! Scope of that ownership. "Single production construction site" is a claim
//! about THIS crate's production surface, not a crate-external monopoly, and
//! the difference is a contracts-crate fact rather than a choice this cell
//! made: `GroundingValidationInput::new` is `pub` in
//! `crates/smart/eliot-dreamer-contracts/src/validation/structured/mod.rs`
//! and its first parameter is a `GroundedDreamDraft` from any source, so any
//! crate depending on `eliot-dreamer-contracts` can construct the carrier from
//! an arbitrary draft and skip `refuse_self_certified_grounding` entirely. That
//! upstream constructor is a path this cell does not own and cannot close from
//! here; the `pub(crate)` boundary on `bind_validation_input` is what keeps the
//! ceiling refusal on the path this crate does publish.
//!
//! Data provenance. Every field of the carrier is either owner-computed by
//! grounding in this crate or explicitly supplied by the A-05 caller
//! ([`ValidationAttachment`]). Nothing is synthesised here: the grounded leg is
//! passed through unchanged, the A-05 leg is never filled from grounding prose,
//! ledger residues, or model text, and an absent optional attachment stays
//! absent instead of becoming a fabricated empty value.
//!
//! Authority ceiling. Issue #262 hard boundary: "model output never
//! self-certifies grounding". `I9.5` states the same rule for the sibling
//! packet: "Sections `resolved` and `evidence` are populated/checked from
//! Governor records. Model text cannot declare them confirmed." This cell's own
//! declared invariant is "grounding does not promote epistemic status". The
//! producer therefore refuses any grounded value whose retained ledger records
//! claim an epistemic position above their own declared ceiling on either axis,
//! so a self-consistent but self-certified ledger cannot be sealed as a grounding
//! receipt. This applies to producer output too, on BOTH axes and not only
//! through this refusal:
//!
//! - the assertability axis: every record this crate produces is capped at
//!   `evidence::CANDIDATE_ONLY_CEILING`;
//! - the grade axis: `grounding::aggregate_parent_record` re-pins a parent's
//!   `grade_ceiling` to the parent's own `grade` once that grade is known, so a
//!   `grade` can never sit above its own `grade_ceiling` no matter which subclaim
//!   contributed a grade and which did not.
//!
//! A record whose grade is absent or unknown certifies no rigour, so neither
//! axis can carry a claim above its ceiling out of this crate's producer.
//!
//! The ceiling has exactly one declaration in this crate:
//! `evidence::CANDIDATE_ONLY_CEILING`. It is not restated here, and this
//! module claims nothing about what a bare cap call implies on its own. The
//! value is enforced by these sites, all of which read that one symbol:
//!
//! - `evidence::evaluate_claim`, the unconditional cap applied to every record
//!   this crate produces;
//! - `grounding::ground_draft_with_controls`, the curation-screen cap;
//! - `grounding::aggregate_parent_record`, the aggregation finalize cap;
//! - `refuse_self_certified_grounding` below, which refuses a retained record
//!   on either epistemic axis whose claim sits above its own declared ceiling:
//!   the assertability axis against `evidence::CANDIDATE_ONLY_CEILING`, and the
//!   grade axis against the record's own `grade_ceiling`.
//!
//! If any one of the first three were relaxed on its own, that divergence would
//! now be visible as a mismatch against the single constant rather than hidden
//! behind a private copy here. The grade axis has no equivalent shared constant
//! to drift from: its invariant is relational (`grade` never above
//! `grade_ceiling`), so it is owned by the producer that establishes it and
//! re-checked by the refusal. The refusal is not a semantic gate: A-05
//! (`eliot-dreamer-candidate-validation`) remains the acceptance owner, and the
//! carrier never becomes a receipt, a promotion, or current truth.

use eliot_dreamer_contracts::grounding::GroundedDreamDraft;
use eliot_dreamer_contracts::grounding::canonical::{
    EvidenceGrade, GradeAssignment, PositionAssertability,
};
use eliot_dreamer_contracts::validation::error::summarize_contract;
use eliot_dreamer_contracts::{
    BudgetUsage, DreamDraftValidationError, GroundingValidationInput, PreservationReport,
    RivalDeclarationSet, ValidationPolicy,
};

use crate::evidence;
use crate::grounding::{GroundingRequest, ground_draft_with_controls};

/// Refusal field for a self-certified assertability position.
const SELF_CERTIFIED_FIELD: &str = "grounding.assertability_ceiling";

/// Refusal field for a grade axis that certifies rigour above its own ceiling.
///
/// Distinct from [`SELF_CERTIFIED_FIELD`] so a caller can tell WHICH epistemic
/// axis self-certified, and it names the record field that carries the grade
/// axis claim (`ClaimGroundingRecord::grade`) under the same `grounding.`
/// prefix the assertability refusal uses, rather than restating a grade name or
/// introducing a new vocabulary item.
const SELF_CERTIFIED_GRADE_FIELD: &str = "grounding.grade";

/// Independently supplied A-05 data for one grounding handoff.
///
/// Every field is explicit supplied data. The attachment carries no claim
/// material and no grounding material: it cannot assert, restate, or substitute
/// for a grounded disposition, which is why nothing here can self-certify
/// grounding. The two optional fields are the frozen contract's own optional
/// supplied values; their absence is recorded as absence and never filled from
/// the grounded value, the ledger, or model text.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidationAttachment {
    /// A-05 validation policy, required to be bound to this job's
    /// `policy_ref` by the carrier's own validation.
    pub policy: ValidationPolicy,
    /// A-05 budget usage observation, required to fit the retained job budget.
    pub usage: BudgetUsage,
    /// Seven-dimension preservation report supplied to A-05.
    pub preservation: PreservationReport,
    /// Explicit observation time used for the A-05 deadline comparison.
    pub observation_time_ms: Option<u64>,
    /// Explicit cancellation observation supplied to A-05.
    pub cancellation_requested: bool,
    /// Optional supplied rival declarations, retained before receipt binding.
    pub rival_declarations: Option<RivalDeclarationSet>,
}

/// Complete owned input for the production A-14b -> A-05 handoff.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroundingValidationRequest {
    /// The complete A03 v2 grounding context, bound by this crate.
    pub grounding: GroundingRequest,
    /// Independently supplied A-05 data.
    pub validation: ValidationAttachment,
}

impl GroundingValidationRequest {
    /// Creates a handoff request from the two independently owned halves.
    #[must_use]
    pub fn new(grounding: GroundingRequest, validation: ValidationAttachment) -> Self {
        Self {
            grounding,
            validation,
        }
    }
}

/// Production entry for the A-14b -> A-05 handoff.
///
/// Grounds the supplied A03 v2 context through this crate's own production
/// grounding entry ([`ground_draft_with_controls`]) and then binds the A-05
/// carrier through the production construction site
/// (`bind_validation_input`). This performs grounding and carrier binding
/// only: it issues no receipt, runs no A-05 semantic gate, retrieves nothing,
/// and promotes nothing.
pub fn ground_for_validation(
    request: GroundingValidationRequest,
) -> Result<GroundingValidationInput, DreamDraftValidationError> {
    let GroundingValidationRequest {
        grounding,
        validation,
    } = request;
    let grounded = ground_draft_with_controls(grounding)
        .map_err(|error| summarize_contract("claim grounding", &error))?;
    bind_validation_input(grounded, validation)
}

/// Production construction site of the A-14b -> A-05 carrier.
///
/// Crate-internal on purpose. The only production caller is
/// [`ground_for_validation`], which grounds the supplied context through
/// [`ground_draft_with_controls`] first, so keeping the constructor
/// `pub(crate)` means the public surface of this crate cannot bind a carrier
/// from a `GroundedDreamDraft` that never passed through this crate's grounding
/// entry. An external consumer that reaches this function with a
/// caller-authored grounded value would bypass every producer cap the ceiling
/// below depends on.
///
/// Binds the complete grounded handoff value, including its input preimage, to
/// the independently supplied A-05 data. The identity, scope, fence, and task
/// binding required by a grounding receipt is not restated here: the frozen
/// carrier contract already owns it, and this function routes every outcome
/// through that owner validation
/// ([`GroundingValidationInput::new`], which calls
/// [`GroundingValidationInput::validate`]) instead of duplicating or weakening
/// it. The job, task, scope, state fence, manifest, policy, and ledger
/// identities are read from the grounded value and are never taken from the
/// attachment, so the attachment cannot claim a context it was not built for.
///
/// The one guarantee this owner adds is the authority ceiling documented in
/// the module header and declared once as
/// `evidence::CANDIDATE_ONLY_CEILING`: a grounded value whose own retained
/// records assert a position above that ceiling on EITHER epistemic axis is
/// refused before any carrier exists, so no model-authored or self-certified
/// text can be sealed as validated grounding.
pub(crate) fn bind_validation_input(
    grounded: GroundedDreamDraft,
    attachment: ValidationAttachment,
) -> Result<GroundingValidationInput, DreamDraftValidationError> {
    refuse_self_certified_grounding(&grounded)?;
    GroundingValidationInput::new(
        grounded,
        attachment.policy,
        attachment.usage,
        attachment.preservation,
        attachment.observation_time_ms,
        attachment.cancellation_requested,
        attachment.rival_declarations,
    )
}

/// Refuses a grounded value whose retained records claim an epistemic position
/// above the candidate-only ceiling on either axis.
///
/// A `ClaimGroundingRecord` carries TWO epistemic-position pairs, not one: the
/// `assertability_ceiling`/`grade` side and the `grade_ceiling` side. Both are
/// read here, because a self-consistent value can put the self-certification on
/// whichever field the producer forgot to check. Measured on this crate's own
/// contracts: `ClaimGroundingRecord::validate` checks `grade` only for shape
/// (exactly one side present) and never compares the two axes to each other, and
/// `validate_grounded_record` never mentions `grade`, `grade_ceiling` or
/// assertability at all. Checking one axis and calling that the ceiling check
/// therefore leaves the other axis free to certify a position the crate forbids.
///
/// The two axes are compared with the vocabulary this crate already owns, so no
/// second ordering or rank table appears here:
///
/// - the assertability axis reuses the crate's own weakening function
///   ([`evidence::cap_record_assertability`]) and the single ceiling declaration
///   ([`evidence::CANDIDATE_ONLY_CEILING`]), exactly as before;
/// - the grade axis maps each grade through the frozen
///   [`PositionAssertability::grade_cap`] — the same vocabulary the downstream
///   acceptance owner reads — and compares the two mapped positions with the
///   crate's one ordering [`evidence::weaker`]. A grade ceiling only ever claims
///   a position, so the refusal never compares `EvidenceGrade` values directly
///   and never ranks grades on its own.
///
/// An absent or unknown `grade` claims no rigour and is therefore not a
/// self-certification; `grade.validate()` already owns the shape of that side.
///
/// This refusal is the CHECK, not the invariant's owner, and it is not the only
/// thing standing between producer output and a carrier. The producer
/// establishes the same grade-axis relation it is checked against:
/// `grounding::aggregate_parent_record` re-pins `record.grade_ceiling` to the
/// parent's own `grade` whenever that grade is known, so the ceiling a record
/// declares always renders the grade the record certifies, and
/// `evidence::evaluate_claim` establishes the same relation for every leaf by
/// lowering `grade_ceiling` to the weakest retained grade. That is why this
/// function is not expected to fire on legitimate producer output: it exists to
/// refuse a grounded value that arrived by some other route carrying the two
/// sides out of relation, not to correct a producer that emits them so.
fn refuse_self_certified_grounding(
    grounded: &GroundedDreamDraft,
) -> Result<(), DreamDraftValidationError> {
    for record in grounded.ledger.records.values() {
        let mut capped = record.clone();
        evidence::cap_record_assertability(&mut capped, evidence::CANDIDATE_ONLY_CEILING);
        if capped.assertability_ceiling != record.assertability_ceiling {
            return Err(DreamDraftValidationError::InvalidContract {
                phase: "grounding validation carrier",
                field: SELF_CERTIFIED_FIELD,
            });
        }
        if record
            .grade
            .as_ref()
            .and_then(GradeAssignment::known_grade)
            .is_some_and(|claimed| grade_ceiling_is_below(claimed, record.grade_ceiling))
        {
            return Err(DreamDraftValidationError::InvalidContract {
                phase: "grounding validation carrier",
                field: SELF_CERTIFIED_GRADE_FIELD,
            });
        }
    }
    Ok(())
}

/// Reports whether a record's grade ceiling sits BELOW the position its own
/// claimed grade certifies, i.e. whether the grade axis self-certifies rigour
/// above the ceiling it declares.
///
/// Both grades are projected into assertability through the frozen
/// [`PositionAssertability::grade_cap`] and then compared with this crate's one
/// ordering ([`evidence::weaker`]), so the refused set is exactly the set whose
/// grade axis cannot be rendered as declared. `grade_cap` is monotone over the
/// frozen grade ladder (`Orienting` -> `PlanningOnly`, `Grounded` ->
/// `QualifiedInference`, `Corroborated` -> `ObservedFact`, `ScienceGrade` ->
/// `MaterialEffect`), so this comparison and a grade-ceiling comparison agree
/// on every pair; projecting first means the crate reuses the downstream
/// owner's vocabulary instead of restating the ladder here.
fn grade_ceiling_is_below(claimed: EvidenceGrade, ceiling: EvidenceGrade) -> bool {
    let claimed_position = PositionAssertability::grade_cap(claimed);
    let ceiling_position = PositionAssertability::grade_cap(ceiling);
    evidence::weaker(claimed_position, ceiling_position) != claimed_position
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};
    use std::num::NonZeroU64;

    use eliot_dreamer_contracts::grounding::canonical::{
        ArtifactId, EpochId, EpochLineageId, EvidenceAuthority, EvidenceFreshness, EvidenceGrade,
        GradeAssignment, PositionAssertability, ResourceGeneration, SourceId, SourceLineage,
        SourceRevisionId, StateFence, SupportResult, TaskId, ValidityBounds,
    };
    use eliot_dreamer_contracts::grounding::{
        AllowedReferenceManifest, AttemptIdentity, AuthorizedReference, ClaimKind, GroundingPolicy,
        MaterialClaim, PrecisionPayload, RouteIdentity, StructuredModelDraft,
        TypedEvidenceAssertion,
    };
    use eliot_dreamer_contracts::{
        BudgetLimits, BundleCompleteness, DreamDraftValidationError, DreamInputBundle,
        DreamJobAdmission, JobClass, Requester, RequesterOrigin,
    };

    use super::{GroundingValidationRequest, ValidationAttachment, bind_validation_input};
    use crate::grounding::GroundingRequest;

    const DIGEST: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    // One rule covers all three refusal axes below: `phase` and both `field`s are
    // re-typed test-local literals, and the production `SELF_CERTIFIED_FIELD` /
    // `SELF_CERTIFIED_GRADE_FIELD` constants are deliberately not imported,
    // because a test-local expectation must not move with the thing it checks.
    // Comparing `field` against an imported production constant would make that
    // axis self-satisfying: renaming the identifier is a compile error either
    // way, but changing the string a constant carries would move the
    // expectation with it and pass silently. Restating the strings here keeps
    // every axis an external expectation, so a change to either refusal field or
    // to the phase is a test failure rather than a silent pass against a stale
    // expectation.

    /// The phase every refusal from this construction site reports.
    const REFUSAL_PHASE: &str = "grounding validation carrier";

    /// The refusal field a self-certified grade axis reports.
    const REFUSAL_GRADE_FIELD: &str = "grounding.grade";

    /// The refusal field a self-certified assertability position reports.
    const REFUSAL_ASSERTABILITY_FIELD: &str = "grounding.assertability_ceiling";

    /// Unwraps a fixture construction result or fails the test loudly.
    ///
    /// Every call site builds a bounded literal from this module, so a failure
    /// is a broken fixture, never an expected outcome. This is the crate's
    /// existing in-src test idiom (`evidence.rs`): a `panic!` in a `let ... else`
    /// keeps the test free of `expect`/`unwrap` without an allowance.
    fn required<T, E: std::fmt::Debug>(result: Result<T, E>, label: &str) -> T {
        match result {
            Ok(value) => value,
            Err(error) => panic!("the {label} fixture is a bounded literal: {error:?}"),
        }
    }

    fn artifact(value: &str) -> ArtifactId {
        required(ArtifactId::new(value), "artifact")
    }

    fn fence() -> StateFence {
        let lineage = required(
            EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000"),
            "lineage",
        );
        let epoch = required(EpochId::new(lineage, NonZeroU64::MIN), "epoch");
        StateFence::new(epoch, ResourceGeneration::genesis())
    }

    fn task() -> TaskId {
        required(TaskId::new("grade-axis-test-task"), "task")
    }

    fn payload() -> PrecisionPayload {
        PrecisionPayload::NumericQuantified {
            value: "42".into(),
            unit: "items".into(),
            denominator: Some("100".into()),
            interval: None,
            rounding: None,
            uncertainty: Some("exact".into()),
        }
    }

    /// A `Supported` typed support relation whose grade is `Grounded`, so a
    /// legitimately grounded record starts with `grade == grade_ceiling`.
    fn supported_record() -> eliot_dreamer_contracts::grounding::canonical::SupportRecord {
        eliot_dreamer_contracts::grounding::canonical::SupportRecord {
            proposition: required(
                eliot_dreamer_contracts::grounding::PropositionId::new("proposition-grade-axis"),
                "proposition",
            ),
            result: SupportResult::Supported,
            handles: BTreeSet::from([artifact("evidence-1")]),
            validity: ValidityBounds {
                scope: "grade-axis-scope".into(),
                window_start_ms: None,
                window_end_ms: None,
                version: "revision-grade-axis".into(),
                precision: "file".into(),
            },
            grade: GradeAssignment::known(EvidenceGrade::Grounded),
            task_id: task(),
            fence: fence(),
            temporal: None,
            assurance: None,
            reopen_reason: None,
            proof_digest: DIGEST.into(),
        }
    }

    fn claim() -> MaterialClaim {
        let proposition_id = required(
            eliot_dreamer_contracts::grounding::PropositionId::new("proposition-grade-axis"),
            "proposition",
        );
        let precision = payload();
        let mut claim = MaterialClaim {
            claim_id: "claim-grade-axis".into(),
            proposition: proposition_id.clone(),
            proposition_digest: required(
                eliot_dreamer_contracts::grounding::proposition_content_digest(
                    &ClaimKind::NumericQuantified,
                    &precision,
                ),
                "proposition digest",
            ),
            kind: ClaimKind::NumericQuantified,
            payload: precision,
            subclaim_ids: BTreeSet::new(),
            proposed_support: BTreeSet::from([artifact("evidence-1")]),
            proposed_counterevidence: BTreeSet::new(),
            component_digests: BTreeMap::from([(
                "value".to_owned(),
                required(
                    eliot_dreamer_contracts::grounding::component_content_digest(
                        &proposition_id,
                        "value",
                    ),
                    "component digest",
                ),
            )]),
            screen_target: None,
            source_preimage_digest: String::new(),
        };
        claim.source_preimage_digest = required(claim.computed_digest(), "claim preimage digest");
        claim
    }

    fn manifest() -> AllowedReferenceManifest {
        let proposition_id = required(
            eliot_dreamer_contracts::grounding::PropositionId::new("proposition-grade-axis"),
            "proposition",
        );
        let kind = ClaimKind::NumericQuantified;
        let precision = payload();
        let source = required(SourceId::new("grade-axis-source"), "source");
        let revision = required(
            SourceRevisionId::new("revision-grade-axis"),
            "source revision",
        );
        let lineage = required(
            SourceLineage::new(source, revision, DIGEST, None, BTreeSet::new(), None),
            "source lineage",
        );
        let assertion = TypedEvidenceAssertion {
            assertion_id: "assertion-grade-axis".into(),
            proposition: proposition_id.clone(),
            proposition_digest: required(
                eliot_dreamer_contracts::grounding::proposition_content_digest(&kind, &precision),
                "assertion proposition digest",
            ),
            component: "value".into(),
            precision,
            source_span_digest: DIGEST.into(),
            support: Some(Box::new(supported_record())),
        };
        let mut manifest = AllowedReferenceManifest {
            schema_version: 2,
            manifest_id: "manifest-grade-axis".into(),
            run_id: "run-grade-axis".into(),
            task_id: task(),
            scope_id: "grade-axis-scope".into(),
            state_fence: fence(),
            source_snapshot: "snapshot-grade-axis".into(),
            source_revision: "revision-grade-axis".into(),
            references: BTreeMap::from([(
                artifact("evidence-1"),
                AuthorizedReference {
                    handle: artifact("evidence-1"),
                    source_lineage: Some(lineage),
                    support: None,
                    provenance: None,
                    content_digest: DIGEST.into(),
                    source_revision: "revision-grade-axis".into(),
                    authority_digest: DIGEST.into(),
                    authority: EvidenceAuthority::SourceIdentity,
                    freshness: EvidenceFreshness::ExactCommit,
                    source_assurance: None,
                    grade_ceiling: EvidenceGrade::Grounded,
                    assertability_ceiling: PositionAssertability::ObservedFact,
                    privacy:
                        eliot_dreamer_contracts::grounding::canonical::PrivacyHandling::Unrestricted,
                    disclosure:
                        eliot_dreamer_contracts::grounding::canonical::DisclosureClass::Open,
                    origin: "fixture".into(),
                    invalidated: false,
                    revocation_reason: None,
                    assertions: vec![assertion],
                    stale: false,
                },
            )]),
            coverage_denominators: BTreeMap::new(),
            coverage_receipts: BTreeMap::new(),
            dependence_groups: BTreeSet::new(),
            digest: String::new(),
        };
        manifest.digest = required(manifest.computed_digest(), "manifest digest");
        manifest
    }

    fn job(manifest_digest: String) -> DreamJobAdmission {
        DreamJobAdmission {
            schema_version: 1,
            job_class: JobClass::Orientation,
            requester: Requester {
                origin: RequesterOrigin::Human,
                principal: "grade-axis-test".into(),
                session: None,
            },
            operation_id: "grade-axis-operation".into(),
            idempotency_key: "grade-axis-idempotency".into(),
            task_id: task().to_string(),
            scope_id: "grade-axis-scope".into(),
            state_fence: fence(),
            privacy_profile: "local_only".into(),
            contract_ref: "grounding-v2".into(),
            policy_ref: "grade-axis-policy".into(),
            budget: BudgetLimits {
                input_bytes: Some(1_048_576),
                output_bytes: Some(1_048_576),
                source_width: Some(64),
                reference_width: Some(64),
                model_calls: Some(1),
                attempts: Some(1),
                candidates: Some(1),
                wall_ms: Some(1_000),
                work_fan_out: Some(1),
                report_bytes: Some(1_024),
                max_stu: Some(10),
            },
            deadline_ms: None,
            frozen_manifest_digest: manifest_digest,
        }
    }

    fn policy() -> GroundingPolicy {
        let mut policy = GroundingPolicy {
            schema_version: 2,
            policy_id: "grade-axis-policy".into(),
            revision: "policy-revision".into(),
            permitted_kinds: BTreeSet::from([ClaimKind::NumericQuantified]),
            permitted_nonmaterial_classes: BTreeSet::from(["unresolved".into()]),
            max_claims: 4_096,
            max_subclaims_per_claim: 16_384,
            max_support_handles_per_claim: 64,
            max_output_bytes: 1_048_576,
            digest: String::new(),
        };
        policy.digest = required(policy.computed_digest(), "policy digest");
        policy
    }

    fn bundle(manifest: &AllowedReferenceManifest) -> DreamInputBundle {
        DreamInputBundle {
            schema_version: 1,
            job_id: job(manifest.digest.clone()).canonical_id(),
            scope_id: "grade-axis-scope".into(),
            task_id: task().to_string(),
            state_fence: fence(),
            manifest_digest: manifest.digest.clone(),
            materials: Vec::new(),
            omissions: Vec::new(),
            completeness: BundleCompleteness::Unknown,
            authoritative_denominator: None,
        }
    }

    fn draft(manifest: &AllowedReferenceManifest) -> StructuredModelDraft {
        let provisional_job = job(manifest.digest.clone());
        let bundle = bundle(manifest);
        let route = RouteIdentity {
            provider: "fixture".into(),
            model: "fixture-model".into(),
            route_revision: "route-1".into(),
            fingerprint: String::new(),
        };
        let mut draft = StructuredModelDraft {
            schema_version: 2,
            job_id: provisional_job.canonical_id(),
            task_id: task(),
            scope_id: "grade-axis-scope".into(),
            state_fence: fence(),
            job: provisional_job.clone(),
            bundle: bundle.clone(),
            raw_output_digest: DIGEST.into(),
            requester_digest: required(
                eliot_dreamer_contracts::grounding::requester_digest(&provisional_job),
                "requester digest",
            ),
            attempt: AttemptIdentity {
                attempt_id: "attempt-1".into(),
                attempt_number: 1,
                maximum_attempts: 1,
            },
            route: RouteIdentity {
                fingerprint: required(
                    eliot_dreamer_contracts::grounding::route_fingerprint(&route),
                    "route fingerprint",
                ),
                ..route
            },
            budget_digest: required(
                eliot_dreamer_contracts::grounding::budget_digest(&provisional_job),
                "budget digest",
            ),
            bundle_digest: required(
                eliot_dreamer_contracts::grounding::bundle_digest(&bundle),
                "bundle digest",
            ),
            input_manifest_digest: manifest.digest.clone(),
            claims: vec![claim()],
            non_material_claims: Vec::new(),
            screen: None,
            draft_digest: String::new(),
        };
        draft.draft_digest = required(draft.computed_digest(), "draft digest");
        draft
    }

    fn validation_attachment() -> ValidationAttachment {
        let mut policy = eliot_dreamer_contracts::ValidationPolicy::new(
            "grade-axis-policy",
            1,
            required(
                u64::try_from(eliot_dreamer_contracts::validation::MAX_CANONICAL_BYTES),
                "canonical byte ceiling",
            ),
        );
        required(policy.seal(), "validation policy seal");
        let verdicts = eliot_dreamer_contracts::PRESERVATION_DIMENSIONS
            .iter()
            .map(
                |spelling| eliot_dreamer_contracts::candidate::DimensionVerdict {
                    dimension: required(
                        eliot_dreamer_contracts::PreservationDimension::parse(spelling),
                        "preservation dimension",
                    ),
                    passed: true,
                    known: true,
                    note: "candidate-only grounding handoff; verbatim retention, no fact promoted"
                        .to_owned(),
                },
            )
            .collect();
        ValidationAttachment {
            policy,
            usage: eliot_dreamer_contracts::BudgetUsage::default(),
            preservation: eliot_dreamer_contracts::PreservationReport { verdicts },
            observation_time_ms: None,
            cancellation_requested: false,
            rival_declarations: None,
        }
    }

    /// One complete owner grounding request over the single retained claim.
    fn grounding_request() -> GroundingRequest {
        let manifest_value = manifest();
        GroundingRequest::new(
            job(manifest_value.digest.clone()),
            bundle(&manifest_value),
            manifest_value.clone(),
            draft(&manifest_value),
            policy(),
        )
    }

    /// DEFECT A, refusal: a self-consistent grounded value whose ledger record
    /// claims a grade ceiling above the candidate-only position is refused at
    /// the construction site and NO carrier is produced.
    ///
    /// All three digests are resealed exactly as the integration target's
    /// assertability-axis case does, and `validate()` is asserted to pass, so
    /// the refusal is proven semantic: the value is fully self-consistent, the
    /// frozen contract accepts it, and only this owner's grade-axis check
    /// refuses it. Without the reseal the same input would be refused as a
    /// digest mismatch, which would prove nothing about the grade axis.
    #[test]
    fn grade_axis_self_certification_is_refused_at_the_construction_site() {
        let mut forged = required(
            crate::grounding::ground_draft_with_controls(grounding_request()),
            "owner grounding",
        );
        let Some(record) = forged.ledger.records.get_mut("claim-grade-axis") else {
            panic!("the grounded claim retains a record");
        };
        record.grade = Some(GradeAssignment::known(EvidenceGrade::ScienceGrade));
        record.grade_ceiling = EvidenceGrade::Corroborated;
        record.record_digest = required(record.computed_digest(), "record digest");
        let ledger_digest = required(forged.ledger.computed_digest(), "ledger digest");
        forged.ledger.ledger_digest = ledger_digest;
        let output_digest = required(forged.computed_digest(), "output digest");
        forged.output_digest = output_digest;
        required(
            forged.validate(),
            "the forged value is internally self-consistent",
        );
        let Err(error) = bind_validation_input(forged, validation_attachment()) else {
            panic!("a self-certified grade axis is not a grounding receipt");
        };
        assert!(
            matches!(
                error,
                DreamDraftValidationError::InvalidContract {
                    phase: REFUSAL_PHASE,
                    field: REFUSAL_GRADE_FIELD,
                }
            ),
            "unexpected refusal: {error}"
        );
    }

    /// The positive control for the same axis: the crate's own grounded record
    /// carries `grade == grade_ceiling`, so the grade axis claims nothing above
    /// the ceiling and the legitimate path still binds a carrier the frozen
    /// contract accepts.
    #[test]
    fn grade_axis_at_or_below_its_ceiling_still_binds_a_validated_carrier() {
        let grounded = required(
            crate::grounding::ground_draft_with_controls(grounding_request()),
            "owner grounding",
        );
        let Some(record) = grounded.ledger.records.get("claim-grade-axis") else {
            panic!("the grounded claim retains a record");
        };
        assert_eq!(
            record.grade_ceiling,
            EvidenceGrade::Grounded,
            "measured: the producer leaves grade_ceiling at the weakest retained grade"
        );
        assert_eq!(
            record.grade,
            Some(GradeAssignment::known(EvidenceGrade::Grounded)),
            "measured: the producer sets grade to the same weakest grade, so the grade axis self-certifies nothing"
        );
        let carrier = required(
            bind_validation_input(grounded, validation_attachment()),
            "carrier construction",
        );
        required(carrier.validate(), "carrier contract acceptance");
    }

    /// DEFECT A, the other axis, still refused: a self-consistent grounded value
    /// whose record claims an assertability position above the candidate-only
    /// ceiling is refused at the same construction site, and the two axes
    /// report distinct fields so a caller can tell which one self-certified.
    ///
    /// This is the case that previously lived in the integration target. It
    /// moved here because it must forge a grounded value, which requires
    /// reaching the constructor directly, and the constructor is `pub(crate)`.
    #[test]
    fn assertability_axis_self_certification_is_refused_at_the_construction_site() {
        let mut forged = required(
            crate::grounding::ground_draft_with_controls(grounding_request()),
            "owner grounding",
        );
        let Some(record) = forged.ledger.records.get_mut("claim-grade-axis") else {
            panic!("the grounded claim retains a record");
        };
        record.assertability_ceiling = PositionAssertability::ObservedFact;
        record.record_digest = required(record.computed_digest(), "record digest");
        let ledger_digest = required(forged.ledger.computed_digest(), "ledger digest");
        forged.ledger.ledger_digest = ledger_digest;
        let output_digest = required(forged.computed_digest(), "output digest");
        forged.output_digest = output_digest;
        required(
            forged.validate(),
            "the forged value is internally self-consistent",
        );
        let Err(error) = bind_validation_input(forged, validation_attachment()) else {
            panic!("a self-certified assertability position is not a grounding receipt");
        };
        assert!(
            matches!(
                error,
                DreamDraftValidationError::InvalidContract {
                    phase: REFUSAL_PHASE,
                    field: REFUSAL_ASSERTABILITY_FIELD,
                }
            ),
            "unexpected refusal: {error}"
        );
    }

    /// The public entry reaches the same construction site, so the legitimate
    /// grade axis binds through the only path an external consumer can reach.
    #[test]
    fn public_entry_binds_the_same_grade_axis() {
        let carrier = required(
            super::ground_for_validation(GroundingValidationRequest::new(
                grounding_request(),
                validation_attachment(),
            )),
            "public entry carrier",
        );
        required(carrier.validate(), "carrier contract acceptance");
    }
}
