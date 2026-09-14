//! Private Governor-owned reconciliation of observations and independently
//! verified Doctor results.
//!
//! The single [`GovernorObservationReconciliation`] addresses one serialized
//! Governor owner triple (the recovered [`ObservationJournal`], the recovered
//! `ProblemOwner` revision map, and the [`CanonicalAdmissionOwner`]) plus the
//! retained neutral [`KernelTransitionPort`]. It never creates an independent
//! journal, problem map, or canonical owner per caller: replay/conflict checks
//! read the current owners, scratch clones prove domain legality without
//! publishing authority, and persistence flows only through the existing
//! canonical path.
//!
//! Validation order (fail-closed):
//! - admitted [`RequestIdentity`] shape, composition readiness, and exact
//!   fence agreement: the request binding fence, the envelope metadata fence,
//!   and the canonical owner fence must coincide;
//! - the canonical fence is projected to the scalar doctor echo whose digest
//!   is the lowercase hex SHA-256 over the canonical JSON bytes of the exact
//!   admitted [`StateFence`](eliot_contracts::StateFence) (the canonical fence
//!   carries no digest field of its own; the derivation is deterministic and
//!   documented so an external verifier computes the identical echo);
//! - [`VerificationReport::validate`](eliot_doctor_core::VerificationReport::validate),
//!   explicit attempt/effect identity shape checks, and non-empty validated
//!   [`EvidenceHandle`](eliot_doctor_core::EvidenceHandle) evidence;
//! - [`VerificationReport::endorse`](eliot_doctor_core::VerificationReport::endorse)
//!   against the projected echo, which enforces every verifier axis at once:
//!   executed (never simulated) verification, passing evaluation, exact
//!   artifact binding re-derived against the effect digest, a current scope
//!   under the expected fence digest, and an independent failure-domain owner
//!   (self-reports, same-path, same-route-new-prompt, and
//!   distinct-model-same-evidence profiles fail here);
//! - problem binding: the report carries no problem identifier by design, so
//!   the independent verifier names the exact verified problem as one
//!   [`EvidenceHandle`](eliot_doctor_core::EvidenceHandle) reference whose
//!   paired digest binds the raw evidence bytes. The Governor resolves that
//!   name against its admitted `ProblemOwner` revisions and requires exactly
//!   one match: zero matches (unknown problem) and several matches
//!   (ambiguous binding) both fail closed without a commit;
//! - domain legality on scratch copies only: the verification is admitted to
//!   a cloned journal through [`ObservationJournal::admit`] (same key plus
//!   same bytes replays, changed bytes conflict), and a scratch
//!   [`Problem`](eliot_problem::Problem) assembled in `Verifying` state at
//!   the expected revision is transitioned to `Resolved` through
//!   [`Problem::transition`](eliot_problem::Problem::transition). Neither
//!   scratch result is published; revision bumps are never hand-rolled.
//!
//! Canonical persistence is two sequential commits through
//! [`CanonicalAdmissionOwner::commit`]:
//! - (a) `CaptureObservation` / `CaptureCandidate` recording the verified
//!   repair as an observation under a derived child operation identity
//!   (`{base}/observation`);
//! - (b) `ReconcileRecovery` / `RecoverySchema` / `ReversibleMutation`
//!   carrying `{problem_id, expected_problem_revision, attempt_digest,
//!   effect_digest, operation manifest digest, artifact binding digest, fence
//!   digest, observation operation/record/request digests}` with
//!   `required_proof` refs equal to the deduplicated verifier evidence refs
//!   and a `problem:{problem_id}` revision-head expectation for compare-and-
//!   swap against the admitted problem revision.
//!
//! Only [`WriteReceiptStatus::Committed`] authorizes downstream publication;
//! every terminal receipt is still returned exactly as issued so the caller
//! observes the true store verdict. A lost acknowledgement reconciles the
//! same operation's receipt through the neutral port (the T1.2 exact-receipt
//! pattern), never a second execution: a proactive same-operation receipt
//! check precedes any commit, an `Unknown` commit outcome falls back to the
//! same receipt lookup, and the store-level `(operation_id,
//! canonical_request_hash)` identity makes a retried commit with identical
//! bytes idempotent while the same operation with different bytes fails
//! closed.
//!
//! Failure mapping reuses the existing [`CompositionError`] variants (no new
//! variant is introduced so the closed matches elsewhere in this crate keep
//! compiling): request-identity, fence, and operation-identity mismatches are
//! [`CompositionError::Provider`]; every other deterministic admission
//! refusal — false verification, unknown/ambiguous problem binding, empty or
//! invalid evidence, scratch legality failure, journal conflict, malformed
//! store receipt — is [`CompositionError::Owner`]. Detail strings name the
//! refused property; they are diagnostics, never control flow.
//!
//! Honest gaps: the `problem:{problem_id}` revision-head key namespace is a
//! Governor-to-Store compare-and-swap contract proposal owned by the store
//! boundary (T3); the verifier fence-echo digest derivation above is the
//! interim binding until the lineaged epoch migration (T6/#64) lands. No
//! verifier is implemented here and no repair is executed: endorsement
//! consumes evidence produced outside the effect executor.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};

use eliot_canonical::CanonicalWriteEnvelope;
use eliot_contracts::{
    ArtifactId, ClockReading, OperationId, StateFence, canonical_json_bytes, sha256_hex,
};
use eliot_doctor_core::{IndependentVerification, VerificationReport};
use eliot_observation::{
    CaptureRoute, CoverageDisposition, CoverageEvidence, CoverageGap, Durability, GapDisposition,
    ObservationAdmissionResult, ObservationEventCore, ObservationEventIdentity, ObservationJournal,
    ObservationKind, ObservationRecordEnvelope, ObservationRecordKind, ObservationScope,
    ObservationSubmission, PrivacyRetentionDisclosure, ProducerTrace, RejectionDisposition,
};
use eliot_problem::{
    DeliveryState, OwnerRef, Problem, ProblemId, ProblemState, Signal, SignalAttribution,
    SignalDisposition, SignalId, SignalProcessingState, SignalSeverity,
};
use eliot_receipts::WorkScopeId;
use eliot_store_api::{
    CONTRACT_VERSION, EffectClass, EventProjectionRelationIntents, NamedMutationOperation,
    NamedMutationRequest, NamedOperationManifest, OperationManifestDigest, OrderingHeadExpectation,
    OrderingScopeId, RevisionHeadExpectation, RevisionKey, ScopeId, SecurityContext,
    TransitionClass, WriteReceipt, WriteReceiptStatus,
};

use crate::{
    CanonicalAdmissionOwner, CompositionError, CompositionReadiness, KernelPortError,
    KernelTransitionPort,
};

/// Production adapter manifest name from the Surreal adapter.
const PRODUCTION_MANIFEST_NAME: &str = "eliot.storage.store-surreal-adapter";
/// Governor ordering scope carried on every envelope (the store enforces the
/// live sequence; the expectation shape mirrors the T1.5 lifecycle path).
const GOVERNOR_ORDERING_SCOPE: &str = "scope:governor";
/// Governor canonical scope addressed by both envelopes.
const GOVERNOR_SCOPE_ID: &str = "governor";

/// Governor-owned observation/verified-repair reconciliation over one
/// serialized owner triple plus the retained neutral Kernel port.
pub struct GovernorObservationReconciliation<'a, P: ?Sized> {
    observation: &'a ObservationJournal,
    problem_revisions: &'a BTreeMap<String, u64>,
    canonical: &'a CanonicalAdmissionOwner,
    kernel: &'a P,
    readiness: CompositionReadiness,
}

impl<'a, P: ?Sized> GovernorObservationReconciliation<'a, P> {
    /// Borrows the single Governor owner triple. No per-caller journal,
    /// problem map, or canonical owner is created; scratch clones in
    /// [`Self::admit_doctor_verification`] never publish authority. The
    /// readiness value is exact for the returned borrow: the composition can
    /// only leave `Ready` through `&mut` methods excluded by this borrow.
    pub(crate) fn new(
        observation: &'a ObservationJournal,
        problem_revisions: &'a BTreeMap<String, u64>,
        canonical: &'a CanonicalAdmissionOwner,
        kernel: &'a P,
        readiness: CompositionReadiness,
    ) -> Self {
        Self {
            observation,
            problem_revisions,
            canonical,
            kernel,
            readiness,
        }
    }
}

/// Projects the canonical fence to the scalar doctor echo.
///
/// The digest is the lowercase hex SHA-256 over the canonical JSON bytes of
/// the exact admitted fence, so an external verifier holding the same fence
/// computes the identical echo without trusting caller-supplied text.
fn doctor_fence_echo(
    fence: &StateFence,
) -> Result<eliot_doctor_core::StateFence, CompositionError> {
    let bytes = canonical_json_bytes(fence).map_err(|error| {
        CompositionError::Owner(format!("cannot canonicalize active fence: {error}"))
    })?;
    eliot_doctor_core::StateFence::new(
        fence.authority_epoch.clone(),
        fence.resource_generation.value(),
        sha256_hex(&bytes),
    )
    .map_err(|_| {
        CompositionError::Owner("active fence does not project to a doctor echo".to_owned())
    })
}

/// Canonical digest helper for admission-contract digests.
fn canonical_digest(value: &impl serde::Serialize) -> Result<String, CompositionError> {
    let bytes = canonical_json_bytes(value).map_err(|error| {
        CompositionError::Owner(format!("cannot canonicalize admission bytes: {error}"))
    })?;
    Ok(sha256_hex(&bytes))
}

/// Reconstructs the production adapter manifest digest.
///
/// The shape mirrors `default_manifest` exactly (same adapter name, contract
/// version, admitted transition classes, reversible-mutation ceiling, and
/// byte/timeout bounds) so the digest equals the digest enforced by the
/// store adapter.
fn production_manifest_digest() -> Result<OperationManifestDigest, CompositionError> {
    let manifest = NamedOperationManifest::new(
        PRODUCTION_MANIFEST_NAME,
        CONTRACT_VERSION,
        vec![
            TransitionClass::CaptureCandidate,
            TransitionClass::Epistemic,
            TransitionClass::TaskControl,
            TransitionClass::LifecyclePolicy,
            TransitionClass::RecoverySchema,
        ],
        EffectClass::ReversibleMutation,
        1024 * 1024,
        1024 * 1024,
        30_000,
    )
    .map_err(|error| CompositionError::Owner(error.to_string()))?;
    Ok(manifest.digest)
}

fn owner_refused(detail: impl Into<String>) -> CompositionError {
    CompositionError::Owner(detail.into())
}

fn identity_refused(detail: impl Into<String>) -> CompositionError {
    CompositionError::Provider(detail.into())
}

/// Resolves the verified problem: exactly one verifier evidence reference
/// must name an admitted problem revision.
fn resolve_problem(
    problem_revisions: &BTreeMap<String, u64>,
    report: &VerificationReport,
) -> Result<(String, u64), CompositionError> {
    let mut candidates = BTreeSet::new();
    for handle in &report.evidence.evidence {
        if problem_revisions.contains_key(&handle.reference) {
            candidates.insert(handle.reference.clone());
        }
    }
    if candidates.len() != 1 {
        return Err(owner_refused(format!(
            "doctor verification binds {} admitted problems; exactly one verifier evidence reference must name the verified problem",
            candidates.len()
        )));
    }
    let problem_id = candidates.into_iter().next().ok_or_else(|| {
        owner_refused(
            "doctor verification problem binding is empty after uniqueness check".to_owned(),
        )
    })?;
    let expected = problem_revisions.get(&problem_id).copied().unwrap_or(0);
    if expected == 0 {
        return Err(owner_refused(format!(
            "admitted problem {problem_id} carries a zero revision; compare-and-swap cannot be formed"
        )));
    }
    Ok((problem_id, expected))
}

/// Builds the deterministic observation submission recording one verified
/// repair. The submission is a pure function of the admitted identity and
/// the endorsed report, so a retry carries identical canonical bytes and a
/// changed report under the same idempotency key conflicts instead of
/// overwriting.
fn verification_submission(
    operation_id: &OperationId,
    identity: &eliot_protocol::RequestIdentity,
    report: &VerificationReport,
    problem_id: &str,
    evidence_refs: &[String],
) -> Result<ObservationSubmission, CompositionError> {
    let fence = identity.request.metadata.state_fence.clone();
    let attempt_digest = report.attempt.digest().to_owned();
    let effect_digest = report.effect.digest().to_owned();
    let record = ObservationRecordEnvelope {
        record_id: format!("doctor-verification:{effect_digest}"),
        kind: ObservationRecordKind::Telemetry,
        event: Some(ObservationEventCore {
            event_id_and_time: ObservationEventIdentity {
                event_id: format!("doctor-verification-event:{effect_digest}"),
                clock: eliot_contracts::ClockReading::default(),
            },
            producer_generation_and_trace: ProducerTrace {
                producer: "doctor-independent-verifier".to_owned(),
                generation: fence.resource_generation.value().to_string(),
                trace_ref: Some(attempt_digest.clone()),
            },
            kind: ObservationKind::FailureOrRepair,
            affected_scope: ObservationScope {
                work_scope: WorkScopeId::new(GOVERNOR_SCOPE_ID)
                    .map_err(|error| owner_refused(error.to_string()))?,
                task_ref: None,
                attempt_ref: Some(attempt_digest.clone()),
                module_or_route_ref: Some("doctor".to_owned()),
            },
            observed_delta: format!(
                "independently verified repair for problem {problem_id}: attempt {attempt_digest} effect {effect_digest}"
            ),
            expected_baseline: None,
            evidence_and_raw_handles: evidence_refs.to_vec(),
            coverage_and_blind_intervals: CoverageEvidence {
                disposition: CoverageDisposition::Complete,
                denominator_source_ref: "doctor-verifier-evidence".to_owned(),
                interval: None,
                blind_intervals: Vec::new(),
                observed_count: u64::try_from(evidence_refs.len()).unwrap_or(u64::MAX),
            },
            privacy_retention_and_disclosure: PrivacyRetentionDisclosure {
                privacy_domain_ref: "governor-verification".to_owned(),
                retention_policy_ref: "governor-retention".to_owned(),
                disclosure_class: "internal".to_owned(),
            },
            candidate_importance: 1,
            dedup_key: effect_digest.clone(),
        }),
        coverage_gap: None,
        journal_control_event: false,
        parent_record_id: None,
    };
    Ok(ObservationSubmission {
        operation_id: operation_id.as_str().to_owned(),
        idempotency_key: identity.idempotency_key.clone(),
        state_fence: fence,
        record,
        record_v2: None,
        capture_route: CaptureRoute::CanonicalJournal,
        durability: Durability::Durable,
        plan: None,
        task_selection: None,
        evidence: None,
    })
}

/// Proves the `Verifying -> Resolved` edge is legal for the bound problem
/// through the production domain entry point on a scratch copy. The scratch
/// problem is discarded; its revision is never written back.
fn check_problem_transition(
    fence: &StateFence,
    problem_id: &str,
    expected_revision: u64,
    attempt_digest: &str,
    effect_digest: &str,
    evidence_refs: &[String],
) -> Result<(), CompositionError> {
    let mut evidence = Vec::with_capacity(evidence_refs.len());
    for reference in evidence_refs {
        evidence.push(
            eliot_contracts::ArtifactId::new(reference)
                .map_err(|error| owner_refused(error.to_string()))?,
        );
    }
    let mut scratch = Problem {
        problem_id: ProblemId::new(problem_id).map_err(|error| owner_refused(error.to_string()))?,
        signal_refs: vec![
            SignalId::new(format!("doctor-attempt:{attempt_digest}"))
                .map_err(|error| owner_refused(error.to_string()))?,
        ],
        title: format!("verified doctor repair for {problem_id}"),
        scope_id: GOVERNOR_SCOPE_ID.to_owned(),
        owner: OwnerRef {
            principal: GOVERNOR_SCOPE_ID.to_owned(),
            generation: fence.resource_generation.value().to_string(),
        },
        state: ProblemState::Verifying,
        evidence_refs: evidence,
        resolution_condition: format!("independent verification of effect {effect_digest}"),
        acknowledged_by: None,
        state_fence: fence.clone(),
        revision: expected_revision,
        reopen_count: 0,
    };
    scratch.validate().map_err(|error| {
        owner_refused(format!(
            "verified problem scratch state is not admissible: {error}"
        ))
    })?;
    scratch
        .transition(fence, ProblemState::Resolved)
        .map_err(|error| {
            owner_refused(format!("verified problem cannot legally resolve: {error}"))
        })?;
    Ok(())
}

/// Builds the observation-leg envelope under the derived child operation
/// identity. The child identity keeps the two legs' store identities
/// disjoint while the submission itself (and its digest) stays a pure
/// function of the base operation, so journal replay still matches.
fn observation_envelope(
    identity: &eliot_protocol::RequestIdentity,
    observation_operation: &OperationId,
    submission: &ObservationSubmission,
    attempt_digest: &str,
    effect_digest: &str,
    manifest_digest: &OperationManifestDigest,
    evidence_refs: &[String],
) -> Result<CanonicalWriteEnvelope, CompositionError> {
    let fence = &identity.request.metadata.state_fence;
    let request_digest = submission
        .request_digest()
        .map_err(|error| owner_refused(error.to_string()))?;
    let mut parameters = BTreeMap::new();
    for (name, value) in [
        ("record_id", submission.record.record_id.clone()),
        ("request_digest", request_digest),
        ("operation_id", submission.operation_id.clone()),
        ("idempotency_key", submission.idempotency_key.clone()),
        ("attempt_digest", attempt_digest.to_owned()),
        ("effect_digest", effect_digest.to_owned()),
    ] {
        parameters.insert(name.to_owned(), serde_json::Value::String(value));
    }
    let envelope = CanonicalWriteEnvelope {
        operation_id: observation_operation.clone(),
        request: identity.request.metadata.clone(),
        idempotency_key: identity.idempotency_key.clone(),
        scope_id: ScopeId::new(GOVERNOR_SCOPE_ID)
            .map_err(|error| owner_refused(error.to_string()))?,
        task_id: identity
            .request
            .metadata
            .task_id
            .as_ref()
            .map(|task| task.as_str().to_owned()),
        transition_class: TransitionClass::CaptureCandidate,
        requested_effect_ceiling: EffectClass::Candidate,
        admission_contract_set_digest: canonical_digest(submission)?,
        operation_manifest_digest: manifest_digest.clone(),
        semantic_commands: vec![NamedMutationRequest {
            operation: NamedMutationOperation::CaptureObservation,
            parameters,
        }],
        event_projection_relation_intents: EventProjectionRelationIntents {
            event_ids: Vec::new(),
            projection_kinds: Vec::new(),
            relation_kinds: Vec::new(),
        },
        security: SecurityContext::default(),
        required_proof_and_approval_refs: evidence_refs.to_vec(),
        expected_revision_heads: Vec::new(),
        expected_ordering_heads: vec![OrderingHeadExpectation {
            scope: OrderingScopeId::new(GOVERNOR_ORDERING_SCOPE)
                .map_err(|error| owner_refused(error.to_string()))?,
            expected_sequence: 1,
            state_fence: fence.clone(),
        }],
    };
    envelope.validate()?;
    Ok(envelope)
}

/// Builds the problem-leg envelope under the base operation identity,
/// binding the already-admitted observation by its digests and the problem
/// by its compare-and-swap revision head.
#[allow(
    clippy::too_many_arguments,
    reason = "the recovery envelope binds every verified identity explicitly"
)]
fn recovery_envelope(
    identity: &eliot_protocol::RequestIdentity,
    operation_id: &OperationId,
    verified: &IndependentVerification,
    problem_id: &str,
    expected_revision: u64,
    observation_operation: &OperationId,
    observation_record_id: &str,
    observation_request_digest: &str,
    fence_digest: &str,
    manifest_digest: &OperationManifestDigest,
    evidence_refs: &[String],
) -> Result<CanonicalWriteEnvelope, CompositionError> {
    let fence = &identity.request.metadata.state_fence;
    let mut parameters = BTreeMap::new();
    for (name, value) in [
        ("problem_id", problem_id.to_owned()),
        ("expected_problem_revision", expected_revision.to_string()),
        ("attempt_digest", verified.attempt().digest().to_owned()),
        ("effect_digest", verified.effect().digest().to_owned()),
        (
            "operation_manifest_digest",
            manifest_digest.as_str().to_owned(),
        ),
        (
            "artifact_binding_digest",
            verified.effect().digest().to_owned(),
        ),
        ("fence_digest", fence_digest.to_owned()),
        (
            "observation_operation_id",
            observation_operation.as_str().to_owned(),
        ),
        ("observation_record_id", observation_record_id.to_owned()),
        (
            "observation_request_digest",
            observation_request_digest.to_owned(),
        ),
    ] {
        parameters.insert(name.to_owned(), serde_json::Value::String(value));
    }
    let envelope = CanonicalWriteEnvelope {
        operation_id: operation_id.clone(),
        request: identity.request.metadata.clone(),
        idempotency_key: identity.idempotency_key.clone(),
        scope_id: ScopeId::new(GOVERNOR_SCOPE_ID)
            .map_err(|error| owner_refused(error.to_string()))?,
        task_id: identity
            .request
            .metadata
            .task_id
            .as_ref()
            .map(|task| task.as_str().to_owned()),
        transition_class: TransitionClass::RecoverySchema,
        requested_effect_ceiling: EffectClass::ReversibleMutation,
        admission_contract_set_digest: canonical_digest(verified.report())?,
        operation_manifest_digest: manifest_digest.clone(),
        semantic_commands: vec![NamedMutationRequest {
            operation: NamedMutationOperation::ReconcileRecovery,
            parameters,
        }],
        event_projection_relation_intents: EventProjectionRelationIntents {
            event_ids: Vec::new(),
            projection_kinds: Vec::new(),
            relation_kinds: Vec::new(),
        },
        security: SecurityContext::default(),
        required_proof_and_approval_refs: evidence_refs.to_vec(),
        expected_revision_heads: vec![RevisionHeadExpectation {
            key: RevisionKey::new(format!("problem:{problem_id}"))
                .map_err(|error| owner_refused(error.to_string()))?,
            expected_revision,
            state_fence: fence.clone(),
        }],
        expected_ordering_heads: vec![OrderingHeadExpectation {
            scope: OrderingScopeId::new(GOVERNOR_ORDERING_SCOPE)
                .map_err(|error| owner_refused(error.to_string()))?,
            expected_sequence: 1,
            state_fence: fence.clone(),
        }],
    };
    envelope.validate()?;
    Ok(envelope)
}

/// Validates that a receipt is well-formed and bound to the expected
/// canonical identity. The canonical request hash comparison is what makes a
/// same-operation retry return the identical receipt instead of executing a
/// second transition.
fn check_receipt(
    receipt: &WriteReceipt,
    operation_id: &OperationId,
    identity: &eliot_protocol::RequestIdentity,
    expected_hash: &str,
    expected_class: TransitionClass,
    expected_manifest: &OperationManifestDigest,
) -> Result<(), CompositionError> {
    receipt
        .validate()
        .map_err(|error| owner_refused(format!("canonical receipt is malformed: {error}")))?;
    if receipt.operation_id != *operation_id
        || receipt.idempotency_key != identity.idempotency_key
        || receipt.canonical_request_hash != expected_hash
        || receipt.state_fence != identity.request.metadata.state_fence
    {
        return Err(identity_refused(
            "canonical receipt is not bound to the admitted operation identity".to_owned(),
        ));
    }
    if receipt.transition_class != expected_class
        || receipt.operation_manifest_digest != *expected_manifest
    {
        return Err(owner_refused(
            "canonical receipt does not match the admitted transition".to_owned(),
        ));
    }
    Ok(())
}

/// Exactly one verified problem plus its deduplicated verifier evidence refs.
struct ResolvedDoctorBinding {
    problem_id: String,
    expected_revision: u64,
    evidence_refs: Vec<String>,
}

/// Scratch-admitted observation leg plus its store-binding digests.
struct ScratchAdmittedLeg {
    submission: ObservationSubmission,
    observation_record_id: String,
    observation_request_digest: String,
}

/// Both canonical envelopes plus the recovery hash and shared manifest digest.
///
/// The observation hash is derived after the proactive receipt check, matching
/// the original two-commit order: an identical retry reconciles without
/// touching the observation leg.
struct PreparedDoctorLegs {
    manifest_digest: OperationManifestDigest,
    observation_operation: OperationId,
    observation_envelope: CanonicalWriteEnvelope,
    recovery_envelope: CanonicalWriteEnvelope,
    recovery_hash: String,
}

/// Validates the endorsed report and its independence under the active fence.
///
/// The caller supplies evidence, never a verdict: endorsement enforces every
/// verifier axis at once, and the artifact binding must be exact for the
/// verified effect.
fn validate_report_independence(
    report: &VerificationReport,
    doctor_fence: &eliot_doctor_core::StateFence,
) -> Result<IndependentVerification, CompositionError> {
    report.validate().map_err(|error| {
        owner_refused(format!("doctor verification report is malformed: {error}"))
    })?;
    report
        .attempt
        .validate()
        .map_err(|error| owner_refused(format!("doctor attempt identity is malformed: {error}")))?;
    report
        .effect
        .validate()
        .map_err(|error| owner_refused(format!("doctor effect identity is malformed: {error}")))?;
    if report.evidence.evidence.is_empty() {
        return Err(owner_refused(
            "doctor verification carries no evidence handles".to_owned(),
        ));
    }
    for handle in &report.evidence.evidence {
        handle.validate().map_err(|error| {
            owner_refused(format!("doctor evidence handle is malformed: {error}"))
        })?;
    }
    let verified = report.endorse(doctor_fence).map_err(|_| {
        owner_refused(
            "doctor verification is not independently verified under the active fence".to_owned(),
        )
    })?;
    if verified
        .report()
        .evidence
        .artifact_binding
        .bound_exact_digest()
        != Some(verified.effect().digest())
    {
        return Err(owner_refused(
            "doctor artifact binding is not exact for the verified effect".to_owned(),
        ));
    }
    Ok(verified)
}

/// Builds both canonical envelopes and their hashes from scratch-admitted legs.
fn build_doctor_leg_envelopes(
    identity: &eliot_protocol::RequestIdentity,
    operation_id: &OperationId,
    verified: &IndependentVerification,
    binding: &ResolvedDoctorBinding,
    scratch: &ScratchAdmittedLeg,
    doctor_fence_digest: &str,
) -> Result<PreparedDoctorLegs, CompositionError> {
    let manifest_digest = production_manifest_digest()?;
    let observation_operation = OperationId::new(format!("{operation_id}/observation"))
        .map_err(|error| owner_refused(error.to_string()))?;
    let observation_envelope = observation_envelope(
        identity,
        &observation_operation,
        &scratch.submission,
        verified.attempt().digest(),
        verified.effect().digest(),
        &manifest_digest,
        &binding.evidence_refs,
    )?;
    let recovery_envelope = recovery_envelope(
        identity,
        operation_id,
        verified,
        &binding.problem_id,
        binding.expected_revision,
        &observation_operation,
        &scratch.observation_record_id,
        &scratch.observation_request_digest,
        doctor_fence_digest,
        &manifest_digest,
        &binding.evidence_refs,
    )?;
    let recovery_hash = recovery_envelope
        .canonical_request_hash()
        .map_err(CompositionError::Canonical)?;
    Ok(PreparedDoctorLegs {
        manifest_digest,
        observation_operation,
        observation_envelope,
        recovery_envelope,
        recovery_hash,
    })
}

impl<P: KernelTransitionPort + ?Sized> GovernorObservationReconciliation<'_, P> {
    /// Validates readiness, request identity shape, and exact fence agreement,
    /// projecting the canonical fence to the scalar doctor echo.
    fn validate_identity_fence(
        &self,
        identity: &eliot_protocol::RequestIdentity,
    ) -> Result<eliot_doctor_core::StateFence, CompositionError> {
        if self.readiness != CompositionReadiness::Ready {
            return Err(CompositionError::NotReady);
        }
        identity
            .validate()
            .map_err(|error| identity_refused(error.to_string()))?;
        let fence = &identity.request.metadata.state_fence;
        if identity.request.state_fence != *fence {
            return Err(identity_refused(
                "admitted request fence does not match the request binding fence".to_owned(),
            ));
        }
        if self.canonical.state_fence() != fence {
            return Err(identity_refused(
                "admitted request fence does not match the active canonical fence".to_owned(),
            ));
        }
        doctor_fence_echo(fence)
    }

    /// Resolves the verified problem to exactly one admitted revision plus
    /// deduplicated verifier evidence refs.
    fn resolve_problem_binding(
        &self,
        report: &VerificationReport,
    ) -> Result<ResolvedDoctorBinding, CompositionError> {
        let (problem_id, expected_revision) = resolve_problem(self.problem_revisions, report)?;
        let evidence_refs: Vec<String> = report
            .evidence
            .evidence
            .iter()
            .map(|handle| handle.reference.clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        Ok(ResolvedDoctorBinding {
            problem_id,
            expected_revision,
            evidence_refs,
        })
    }

    /// Admits the verification to a scratch journal clone and proves the
    /// `Verifying -> Resolved` edge is legal, without publishing authority.
    fn admit_scratch_observation(
        &self,
        operation_id: &OperationId,
        identity: &eliot_protocol::RequestIdentity,
        report: &VerificationReport,
        verified: &IndependentVerification,
        binding: &ResolvedDoctorBinding,
    ) -> Result<ScratchAdmittedLeg, CompositionError> {
        let submission = verification_submission(
            operation_id,
            identity,
            report,
            &binding.problem_id,
            &binding.evidence_refs,
        )?;
        let mut scratch = self.observation.clone();
        let observation_receipt = match scratch
            .admit(submission.clone())
            .map_err(|error| owner_refused(error.to_string()))?
        {
            ObservationAdmissionResult::Accepted { receipt }
            | ObservationAdmissionResult::Replayed { receipt } => receipt,
            ObservationAdmissionResult::Rejected { rejection } => {
                if rejection.disposition == RejectionDisposition::Conflict {
                    return Err(owner_refused(format!(
                        "observation identity conflict: {}",
                        rejection.all_contract_errors.join("; ")
                    )));
                }
                return Err(owner_refused(format!(
                    "verified observation is not admissible: {}",
                    rejection.all_contract_errors.join("; ")
                )));
            }
        };
        check_problem_transition(
            &identity.request.metadata.state_fence,
            &binding.problem_id,
            binding.expected_revision,
            verified.attempt().digest(),
            verified.effect().digest(),
            &binding.evidence_refs,
        )?;
        Ok(ScratchAdmittedLeg {
            submission,
            observation_record_id: observation_receipt.record_id,
            observation_request_digest: observation_receipt.request_digest,
        })
    }

    /// Returns the already-committed recovery receipt for an identical retry,
    /// or fails closed when the same operation carries different bytes.
    async fn reconcile_existing_receipt(
        &self,
        identity: &eliot_protocol::RequestIdentity,
        operation_id: &OperationId,
        recovery_hash: &str,
        manifest_digest: &OperationManifestDigest,
    ) -> Result<Option<WriteReceipt>, CompositionError> {
        if let Some(receipt) = self.kernel.receipt(operation_id.clone()).await? {
            if receipt.idempotency_key == identity.idempotency_key
                && receipt.canonical_request_hash == recovery_hash
            {
                check_receipt(
                    &receipt,
                    operation_id,
                    identity,
                    recovery_hash,
                    TransitionClass::RecoverySchema,
                    manifest_digest,
                )?;
                return Ok(Some(receipt));
            }
            return Err(identity_refused(format!(
                "operation {operation_id} is already committed with different canonical bytes"
            )));
        }
        Ok(None)
    }

    /// Commits the observation leg, reconciling an unknown outcome through the
    /// neutral receipt route instead of a second execution.
    async fn commit_observation_leg(
        &self,
        identity: &eliot_protocol::RequestIdentity,
        observation_operation: &OperationId,
        envelope: CanonicalWriteEnvelope,
        expected_hash: &str,
        manifest_digest: &OperationManifestDigest,
    ) -> Result<WriteReceipt, CompositionError> {
        let receipt = match self.canonical.commit(self.kernel, identity, envelope).await {
            Ok(receipt) => receipt,
            Err(CompositionError::Kernel(KernelPortError::Unknown(_))) => {
                match self.kernel.receipt(observation_operation.clone()).await? {
                    Some(receipt) => receipt,
                    None => {
                        return Err(CompositionError::Kernel(KernelPortError::Unknown(
                            "observation commit outcome is unknown and no receipt reconciled"
                                .to_owned(),
                        )));
                    }
                }
            }
            Err(other) => return Err(other),
        };
        check_receipt(
            &receipt,
            observation_operation,
            identity,
            expected_hash,
            TransitionClass::CaptureCandidate,
            manifest_digest,
        )?;
        Ok(receipt)
    }

    /// Commits the problem leg, reconciling an unknown outcome through the
    /// neutral receipt route instead of a second execution.
    async fn commit_problem_leg(
        &self,
        identity: &eliot_protocol::RequestIdentity,
        operation_id: &OperationId,
        envelope: CanonicalWriteEnvelope,
        expected_hash: &str,
        manifest_digest: &OperationManifestDigest,
    ) -> Result<WriteReceipt, CompositionError> {
        let receipt = match self.canonical.commit(self.kernel, identity, envelope).await {
            Ok(receipt) => receipt,
            Err(CompositionError::Kernel(KernelPortError::Unknown(_))) => {
                match self.kernel.receipt(operation_id.clone()).await? {
                    Some(receipt) => receipt,
                    None => {
                        return Err(CompositionError::Kernel(KernelPortError::Unknown(
                            "recovery commit outcome is unknown and no receipt reconciled"
                                .to_owned(),
                        )));
                    }
                }
            }
            Err(other) => return Err(other),
        };
        check_receipt(
            &receipt,
            operation_id,
            identity,
            expected_hash,
            TransitionClass::RecoverySchema,
            manifest_digest,
        )?;
        Ok(receipt)
    }
}

/// Watchdog spool entry kind for Governor admission.
///
/// Mirrors `eliot-watchdog-core::WatchdogSpoolPayloadKind` without depending
/// on the Watchdog crate: the Governor must not depend on the Watchdog (the
/// daemon adapter owns that boundary). Deferred: add an
/// `eliot-watchdog-core` dependency and replace this view with the canonical
/// type when the composition claim widens (see PR residual).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WatchdogEntryKind {
    Heartbeat,
    Gap,
    Recovery,
}

impl WatchdogEntryKind {
    /// True for gap-like entries that lower coverage instead of evidencing
    /// liveness.
    const fn is_gap_like(self) -> bool {
        matches!(self, Self::Gap | Self::Recovery)
    }
}

/// One spool entry view for Governor admission: sequence plus opaque digests,
/// no semantics. Timestamps never enter canonical digests.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WatchdogEntryAdmission {
    pub sequence: u64,
    pub kind: WatchdogEntryKind,
    pub record_digest: String,
    pub payload_digest: String,
    pub observed_at_ms: u64,
}

/// Per-entry canonical outcome for one Watchdog batch, in batch order. A
/// `None` receipt means the canonical outcome is unknown (store unavailable);
/// the daemon maps it to `Unknown`/`Durable` so the Watchdog cursor stays
/// put.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WatchdogAdmittedEntry {
    pub sequence: u64,
    pub record_digest: String,
    pub receipt: Option<WriteReceipt>,
}

/// Watchdog batch admission through the sole Governor transition path.
///
/// - Heartbeat becomes a non-semantic system observation (`Telemetry`,
///   supervision evidence, explicitly not health truth) via
///   `ObservationSubmission { capture_route: WatchdogSpool }`.
/// - Gap/Recovery becomes a lowered-coverage candidate (`CoverageGap` with
///   `DegradeDependentGuarantees`) plus a scratch `Signal
///   { disposition: ProblemCandidate }` and a scratch `Problem`
///   `Open -> Triaged` legality check. Severity is fixed `Info`; disposition
///   is fixed `ProblemCandidate`; the transition is fixed to `Triaged` —
///   never `Incident`, never from model prose.
/// - Idempotent replay on the same batch id/digest returns the same receipts
///   with no second observation per spool sequence (per-entry operation
///   `{base}/watchdog-{sequence}` plus per-entry idempotency
///   `{caller}:watchdog:{batch_id}:{sequence}`; same key with different bytes
///   conflicts instead of overwriting).
/// - Store-unavailable yields a `None` receipt per affected entry; the daemon
///   maps that stage-honestly to `Durable`/`Unknown` and the Watchdog cursor
///   stays unchanged (core refuses non-terminal).
/// - No semantic severity is read from any prose; no direct store write
///   happens outside [`CanonicalAdmissionOwner::commit`]. The full
///   Problem-leg canonical commit and the `composition.rs`/`lib.rs` accessor
///   are deferred (direct owner construction as the tests do; see PR
///   residual). The EBP `payload_type` binding is likewise deferred (protocol
///   file out of scope).
fn watchdog_digest_shape(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

/// Validates the batch identity shape (non-blank id, 64-hex digest).
fn validate_watchdog_batch_identity(
    batch_id: &str,
    batch_digest: &str,
) -> Result<(), CompositionError> {
    if batch_id.trim().is_empty() || batch_id.chars().any(char::is_control) {
        return Err(owner_refused(
            "watchdog batch identity is blank or contains control characters".to_owned(),
        ));
    }
    if !watchdog_digest_shape(batch_digest) {
        return Err(owner_refused(
            "watchdog batch digest must be a 64-character hex string".to_owned(),
        ));
    }
    Ok(())
}

/// Validates one entry view shape (nonzero sequence, 64-hex digests).
fn validate_watchdog_entry(entry: &WatchdogEntryAdmission) -> Result<(), CompositionError> {
    if entry.sequence == 0 {
        return Err(owner_refused("watchdog spool sequence is zero".to_owned()));
    }
    if !watchdog_digest_shape(&entry.record_digest) {
        return Err(owner_refused(
            "watchdog entry record digest must be a 64-character hex string".to_owned(),
        ));
    }
    if !watchdog_digest_shape(&entry.payload_digest) {
        return Err(owner_refused(
            "watchdog entry payload digest must be a 64-character hex string".to_owned(),
        ));
    }
    Ok(())
}

/// Builds the deterministic per-entry submission. Heartbeat is `Telemetry`
/// supervision evidence; gap-like entries are `CoverageGap` candidates that
/// lower coverage without self-certifying an incident.
#[allow(
    clippy::too_many_lines,
    reason = "the heartbeat/gap submission shapes stay side by side for review"
)]
fn watchdog_submission(
    per_entry_operation: &OperationId,
    per_entry_idempotency: &str,
    identity: &eliot_protocol::RequestIdentity,
    batch_id: &str,
    batch_digest: &str,
    entry: &WatchdogEntryAdmission,
) -> Result<ObservationSubmission, CompositionError> {
    let fence = identity.request.metadata.state_fence.clone();
    let record_id = format!("watchdog-spool:{batch_id}:{}", entry.sequence);
    if entry.kind.is_gap_like() {
        let reason_ref = match entry.kind {
            WatchdogEntryKind::Gap => "watchdog-gap",
            WatchdogEntryKind::Recovery => "watchdog-recovery",
            WatchdogEntryKind::Heartbeat => {
                return Err(owner_refused(
                    "watchdog heartbeat entry reached the gap submission path".to_owned(),
                ));
            }
        };
        let record = ObservationRecordEnvelope {
            record_id,
            kind: ObservationRecordKind::CoverageGap,
            event: None,
            coverage_gap: Some(CoverageGap {
                gap_id: format!("watchdog-gap:{batch_id}:{}", entry.sequence),
                obligation_profile_ref: "watchdog-spool-coverage".to_owned(),
                reason_ref: reason_ref.to_owned(),
                affected_interval: None,
                disposition: GapDisposition::DegradeDependentGuarantees,
                protected: false,
                evidence_refs: vec![entry.record_digest.clone(), entry.payload_digest.clone()],
            }),
            journal_control_event: false,
            parent_record_id: None,
        };
        return Ok(ObservationSubmission {
            operation_id: per_entry_operation.as_str().to_owned(),
            idempotency_key: per_entry_idempotency.to_owned(),
            state_fence: fence,
            record,
            record_v2: None,
            capture_route: CaptureRoute::WatchdogSpool,
            durability: Durability::Durable,
            plan: None,
            task_selection: None,
            evidence: None,
        });
    }
    let record = ObservationRecordEnvelope {
        record_id,
        kind: ObservationRecordKind::Telemetry,
        event: Some(ObservationEventCore {
            event_id_and_time: ObservationEventIdentity {
                event_id: format!("watchdog-spool-event:{batch_id}:{}", entry.sequence),
                clock: ClockReading::default(),
            },
            producer_generation_and_trace: ProducerTrace {
                producer: "watchdog-spool".to_owned(),
                generation: fence.resource_generation.value().to_string(),
                trace_ref: Some(entry.payload_digest.clone()),
            },
            kind: ObservationKind::LoopOrNoProgress,
            affected_scope: ObservationScope {
                work_scope: WorkScopeId::new(GOVERNOR_SCOPE_ID)
                    .map_err(|error| owner_refused(error.to_string()))?,
                task_ref: None,
                attempt_ref: Some(entry.payload_digest.clone()),
                module_or_route_ref: Some("watchdog-spool".to_owned()),
            },
            observed_delta: format!(
                "watchdog supervision evidence sequence {} batch {batch_id} digest {batch_digest} (not health truth)",
                entry.sequence
            ),
            expected_baseline: None,
            evidence_and_raw_handles: vec![
                entry.record_digest.clone(),
                entry.payload_digest.clone(),
            ],
            coverage_and_blind_intervals: CoverageEvidence {
                disposition: CoverageDisposition::Complete,
                denominator_source_ref: "watchdog-spool".to_owned(),
                interval: None,
                blind_intervals: Vec::new(),
                observed_count: 1,
            },
            privacy_retention_and_disclosure: PrivacyRetentionDisclosure {
                privacy_domain_ref: "governor-verification".to_owned(),
                retention_policy_ref: "governor-retention".to_owned(),
                disclosure_class: "internal".to_owned(),
            },
            candidate_importance: 1,
            dedup_key: format!(
                "watchdog-spool:{batch_digest}:{}:{}",
                entry.sequence, entry.record_digest
            ),
        }),
        coverage_gap: None,
        journal_control_event: false,
        parent_record_id: None,
    };
    Ok(ObservationSubmission {
        operation_id: per_entry_operation.as_str().to_owned(),
        idempotency_key: per_entry_idempotency.to_owned(),
        state_fence: fence,
        record,
        record_v2: None,
        capture_route: CaptureRoute::WatchdogSpool,
        durability: Durability::Durable,
        plan: None,
        task_selection: None,
        evidence: None,
    })
}

/// Proves a gap-like entry yields a `ProblemCandidate` signal and a legal
/// `Open -> Triaged` problem edge on scratch copies only. Severity is fixed
/// `Info` and the transition target is fixed to `Triaged`: an incident is
/// never self-certified here.
fn check_watchdog_gap_candidate(
    fence: &StateFence,
    batch_id: &str,
    batch_digest: &str,
    entry: &WatchdogEntryAdmission,
) -> Result<(), CompositionError> {
    let signal_id = SignalId::new(format!("watchdog-gap-signal:{batch_id}:{}", entry.sequence))
        .map_err(|error| owner_refused(error.to_string()))?;
    let evidence = ArtifactId::new(format!(
        "watchdog-spool-entry:{batch_id}:{}",
        entry.sequence
    ))
    .map_err(|error| owner_refused(error.to_string()))?;
    let signal = Signal {
        signal_id: signal_id.clone(),
        rule_id: "watchdog-spool-gap".to_owned(),
        severity: SignalSeverity::Info,
        subject: format!("watchdog spool gap sequence {}", entry.sequence),
        scope_id: GOVERNOR_SCOPE_ID.to_owned(),
        observed_at: ClockReading::default(),
        evidence_handles: vec![evidence.clone()],
        observation: None,
        attribution: SignalAttribution::Suspected,
        processing_state: SignalProcessingState::Observed,
        delivery_state: DeliveryState::Pending,
        disposition: SignalDisposition::ProblemCandidate,
        dedup_key: format!(
            "watchdog-gap:{batch_digest}:{}:{}",
            entry.sequence, entry.record_digest
        ),
        reopen_condition: "watchdog-gap-recovery-observed".to_owned(),
        state_fence: fence.clone(),
    };
    signal.validate().map_err(|error| {
        owner_refused(format!("watchdog gap signal is not admissible: {error}"))
    })?;
    if signal.disposition != SignalDisposition::ProblemCandidate
        || signal.severity == SignalSeverity::IncidentCandidate
    {
        return Err(owner_refused(
            "watchdog gap signal must stay a non-incident problem candidate".to_owned(),
        ));
    }
    let mut scratch = Problem {
        problem_id: ProblemId::new(format!(
            "watchdog-gap-problem:{batch_id}:{}",
            entry.sequence
        ))
        .map_err(|error| owner_refused(error.to_string()))?,
        signal_refs: vec![signal_id],
        title: format!(
            "watchdog coverage gap candidate batch {batch_id} sequence {}",
            entry.sequence
        ),
        scope_id: GOVERNOR_SCOPE_ID.to_owned(),
        owner: OwnerRef {
            principal: GOVERNOR_SCOPE_ID.to_owned(),
            generation: fence.resource_generation.value().to_string(),
        },
        state: ProblemState::Open,
        evidence_refs: vec![evidence],
        resolution_condition: format!("watchdog recovery observed for sequence {}", entry.sequence),
        acknowledged_by: None,
        state_fence: fence.clone(),
        revision: 1,
        reopen_count: 0,
    };
    scratch.validate().map_err(|error| {
        owner_refused(format!(
            "watchdog gap problem scratch state is not admissible: {error}"
        ))
    })?;
    scratch
        .transition(fence, ProblemState::Triaged)
        .map_err(|error| {
            owner_refused(format!(
                "watchdog gap problem cannot legally become a candidate: {error}"
            ))
        })?;
    Ok(())
}

/// Builds the per-entry observation-leg envelope under the derived per-entry
/// operation identity. Required proof binds the spool digests so a mutated
/// payload under the same sequence changes the canonical hash and conflicts
/// instead of overwriting.
#[allow(
    clippy::too_many_arguments,
    reason = "the watchdog envelope binds every spool identity explicitly"
)]
fn watchdog_observation_envelope(
    identity: &eliot_protocol::RequestIdentity,
    observation_operation: &OperationId,
    submission: &ObservationSubmission,
    batch_id: &str,
    batch_digest: &str,
    entry: &WatchdogEntryAdmission,
    manifest_digest: &OperationManifestDigest,
) -> Result<CanonicalWriteEnvelope, CompositionError> {
    let fence = &identity.request.metadata.state_fence;
    let request_digest = submission
        .request_digest()
        .map_err(|error| owner_refused(error.to_string()))?;
    let mut parameters = BTreeMap::new();
    for (name, value) in [
        ("record_id", submission.record.record_id.clone()),
        ("request_digest", request_digest),
        ("operation_id", submission.operation_id.clone()),
        ("idempotency_key", submission.idempotency_key.clone()),
        ("batch_id", batch_id.to_owned()),
        ("batch_digest", batch_digest.to_owned()),
        ("sequence", entry.sequence.to_string()),
        ("record_digest", entry.record_digest.clone()),
        ("payload_digest", entry.payload_digest.clone()),
    ] {
        parameters.insert(name.to_owned(), serde_json::Value::String(value));
    }
    let envelope = CanonicalWriteEnvelope {
        operation_id: observation_operation.clone(),
        request: identity.request.metadata.clone(),
        idempotency_key: submission.idempotency_key.clone(),
        scope_id: ScopeId::new(GOVERNOR_SCOPE_ID)
            .map_err(|error| owner_refused(error.to_string()))?,
        task_id: identity
            .request
            .metadata
            .task_id
            .as_ref()
            .map(|task| task.as_str().to_owned()),
        transition_class: TransitionClass::CaptureCandidate,
        requested_effect_ceiling: EffectClass::Candidate,
        admission_contract_set_digest: canonical_digest(submission)?,
        operation_manifest_digest: manifest_digest.clone(),
        semantic_commands: vec![NamedMutationRequest {
            operation: NamedMutationOperation::CaptureObservation,
            parameters,
        }],
        event_projection_relation_intents: EventProjectionRelationIntents {
            event_ids: Vec::new(),
            projection_kinds: Vec::new(),
            relation_kinds: Vec::new(),
        },
        security: SecurityContext::default(),
        required_proof_and_approval_refs: vec![
            entry.record_digest.clone(),
            entry.payload_digest.clone(),
        ],
        expected_revision_heads: Vec::new(),
        expected_ordering_heads: vec![OrderingHeadExpectation {
            scope: OrderingScopeId::new(GOVERNOR_ORDERING_SCOPE)
                .map_err(|error| owner_refused(error.to_string()))?,
            expected_sequence: 1,
            state_fence: fence.clone(),
        }],
    };
    envelope.validate()?;
    Ok(envelope)
}

impl<P: KernelTransitionPort + ?Sized> GovernorObservationReconciliation<'_, P> {
    /// Validates readiness plus exact fence agreement for Watchdog admission.
    ///
    /// Mirrors [`Self::validate_identity_fence`] without the doctor echo: the
    /// request binding fence, the envelope metadata fence, and the canonical
    /// owner fence must coincide. No verifier endorsement applies here.
    fn validate_watchdog_identity_fence(
        &self,
        identity: &eliot_protocol::RequestIdentity,
    ) -> Result<(), CompositionError> {
        if self.readiness != CompositionReadiness::Ready {
            return Err(CompositionError::NotReady);
        }
        identity
            .validate()
            .map_err(|error| identity_refused(error.to_string()))?;
        let fence = &identity.request.metadata.state_fence;
        if identity.request.state_fence != *fence {
            return Err(identity_refused(
                "admitted request fence does not match the request binding fence".to_owned(),
            ));
        }
        if self.canonical.state_fence() != fence {
            return Err(identity_refused(
                "admitted request fence does not match the active canonical fence".to_owned(),
            ));
        }
        Ok(())
    }

    /// Returns the already-committed per-entry observation receipt for an
    /// identical retry, or fails closed when the same operation carries
    /// different bytes. The caller passes the derived per-entry identity
    /// (caller binding plus per-entry idempotency), so the receipt binding
    /// check compares against that identity.
    async fn reconcile_watchdog_observation_receipt(
        &self,
        identity: &eliot_protocol::RequestIdentity,
        observation_operation: &OperationId,
        recovery_hash: &str,
        manifest_digest: &OperationManifestDigest,
    ) -> Result<Option<WriteReceipt>, CompositionError> {
        if let Some(receipt) = self.kernel.receipt(observation_operation.clone()).await? {
            if receipt.idempotency_key == identity.idempotency_key
                && receipt.canonical_request_hash == recovery_hash
            {
                check_receipt(
                    &receipt,
                    observation_operation,
                    identity,
                    recovery_hash,
                    TransitionClass::CaptureCandidate,
                    manifest_digest,
                )?;
                return Ok(Some(receipt));
            }
            return Err(identity_refused(format!(
                "operation {observation_operation} is already committed with different canonical bytes"
            )));
        }
        Ok(None)
    }

    /// Admits one Watchdog spool export batch into canonical observations
    /// through the common gateway.
    ///
    /// See [`WatchdogAdmittedEntry`] and the module-level Watchdog admission
    /// documentation for the heartbeat/gap mapping, the idempotency rule, and
    /// the deferred composition accessor.
    #[allow(
        clippy::too_many_lines,
        reason = "the per-entry scratch/commit/reconcile steps stay in explicit order"
    )]
    pub async fn admit_watchdog_batch(
        &self,
        identity: &eliot_protocol::RequestIdentity,
        base_operation_id: &OperationId,
        batch_id: &str,
        batch_digest: &str,
        entries: &[WatchdogEntryAdmission],
    ) -> Result<Vec<WatchdogAdmittedEntry>, CompositionError> {
        self.validate_watchdog_identity_fence(identity)?;
        validate_watchdog_batch_identity(batch_id, batch_digest)?;
        for entry in entries {
            validate_watchdog_entry(entry)?;
        }
        if entries.is_empty() {
            return Ok(Vec::new());
        }
        let manifest_digest = production_manifest_digest()?;
        let fence = identity.request.metadata.state_fence.clone();
        let mut scratch = self.observation.clone();
        let mut outcomes = Vec::with_capacity(entries.len());
        for entry in entries {
            let observation_operation =
                OperationId::new(format!("{base_operation_id}/watchdog-{}", entry.sequence))
                    .map_err(|error| owner_refused(error.to_string()))?;
            let per_entry_idempotency = format!(
                "{}:watchdog:{batch_id}:{}",
                identity.idempotency_key, entry.sequence
            );
            // Derived per-entry identity: the caller binding plus the
            // deterministic per-entry idempotency. The canonical owner
            // requires the envelope idempotency to equal the admitted
            // identity idempotency, so each entry commits under its own
            // identity. A retry must reuse the caller identity and the base
            // operation (documented above); anything else conflicts instead
            // of writing a second observation for one spool sequence.
            let entry_identity = eliot_protocol::RequestIdentity {
                request: identity.request.clone(),
                idempotency_key: per_entry_idempotency.clone(),
                deadline_unix_ms: identity.deadline_unix_ms,
                cancellation_id: identity.cancellation_id.clone(),
            };
            let submission = watchdog_submission(
                &observation_operation,
                &per_entry_idempotency,
                identity,
                batch_id,
                batch_digest,
                entry,
            )?;
            match scratch
                .admit(submission.clone())
                .map_err(|error| owner_refused(error.to_string()))?
            {
                ObservationAdmissionResult::Accepted { .. }
                | ObservationAdmissionResult::Replayed { .. } => {}
                ObservationAdmissionResult::Rejected { rejection } => {
                    if rejection.disposition == RejectionDisposition::Conflict {
                        return Err(owner_refused(format!(
                            "watchdog observation identity conflict: {}",
                            rejection.all_contract_errors.join("; ")
                        )));
                    }
                    return Err(owner_refused(format!(
                        "watchdog observation is not admissible: {}",
                        rejection.all_contract_errors.join("; ")
                    )));
                }
            }
            if entry.kind.is_gap_like() {
                check_watchdog_gap_candidate(&fence, batch_id, batch_digest, entry)?;
            }
            let envelope = watchdog_observation_envelope(
                &entry_identity,
                &observation_operation,
                &submission,
                batch_id,
                batch_digest,
                entry,
                &manifest_digest,
            )?;
            let expected_hash = envelope
                .canonical_request_hash()
                .map_err(CompositionError::Canonical)?;
            if let Some(receipt) = self
                .reconcile_watchdog_observation_receipt(
                    &entry_identity,
                    &observation_operation,
                    &expected_hash,
                    &manifest_digest,
                )
                .await?
            {
                outcomes.push(WatchdogAdmittedEntry {
                    sequence: entry.sequence,
                    record_digest: entry.record_digest.clone(),
                    receipt: Some(receipt),
                });
                continue;
            }
            match self
                .commit_observation_leg(
                    &entry_identity,
                    &observation_operation,
                    envelope,
                    &expected_hash,
                    &manifest_digest,
                )
                .await
            {
                Ok(receipt) => outcomes.push(WatchdogAdmittedEntry {
                    sequence: entry.sequence,
                    record_digest: entry.record_digest.clone(),
                    receipt: Some(receipt),
                }),
                Err(CompositionError::Kernel(KernelPortError::Unknown(_))) => {
                    outcomes.push(WatchdogAdmittedEntry {
                        sequence: entry.sequence,
                        record_digest: entry.record_digest.clone(),
                        receipt: None,
                    });
                }
                Err(other) => return Err(other),
            }
        }
        Ok(outcomes)
    }

    /// Admits one independently verified Doctor result into canonical Problem
    /// state through the common gateway.
    ///
    /// The caller supplies evidence, never a verdict: only an endorsed
    /// [`IndependentVerification`] reaches the canonical path, and only a
    /// `Committed` observation receipt admits the recovery leg. See the
    /// module documentation for the validation order, the problem binding
    /// contract, and the two-commit idempotency choreography.
    pub async fn admit_doctor_verification(
        &self,
        identity: &eliot_protocol::RequestIdentity,
        operation_id: &eliot_contracts::OperationId,
        report: &eliot_doctor_core::VerificationReport,
    ) -> Result<eliot_store_api::WriteReceipt, CompositionError> {
        let doctor_fence = self.validate_identity_fence(identity)?;
        let verified = validate_report_independence(report, &doctor_fence)?;
        let binding = self.resolve_problem_binding(report)?;
        let scratch =
            self.admit_scratch_observation(operation_id, identity, report, &verified, &binding)?;
        let legs = build_doctor_leg_envelopes(
            identity,
            operation_id,
            &verified,
            &binding,
            &scratch,
            &doctor_fence.digest,
        )?;
        let PreparedDoctorLegs {
            manifest_digest,
            observation_operation,
            observation_envelope,
            recovery_envelope,
            recovery_hash,
        } = legs;
        if let Some(receipt) = self
            .reconcile_existing_receipt(identity, operation_id, &recovery_hash, &manifest_digest)
            .await?
        {
            return Ok(receipt);
        }
        let observation_hash = observation_envelope
            .canonical_request_hash()
            .map_err(CompositionError::Canonical)?;
        let observation_receipt = self
            .commit_observation_leg(
                identity,
                &observation_operation,
                observation_envelope,
                &observation_hash,
                &manifest_digest,
            )
            .await?;
        if observation_receipt.status != WriteReceiptStatus::Committed {
            return Ok(observation_receipt);
        }
        let receipt = self
            .commit_problem_leg(
                identity,
                operation_id,
                recovery_envelope,
                &recovery_hash,
                &manifest_digest,
            )
            .await?;
        Ok(receipt)
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use std::task::{Context, Poll};

    use eliot_contracts::{
        ClockReading, EpochId, EpochLineageId, OperationId, ProductId, RequestId, RequestMetadata,
        ResourceGeneration, SessionId, SourceId,
    };
    use eliot_doctor_core::{
        ArtifactBinding, AttemptIdentityBinding, DiagnosticBrief, EvaluationOutcome,
        EvidenceHandle, IndependenceClass, IndependenceProfile, RegisteredOperation,
        RepairAttemptIdentity, RepairClass, RepairEffectIdentity, RepairOperationRef, RepairRecipe,
        RepairRecipeIdentity, RepairRecipeManifest, ScopeAttestation, VerificationExecution,
        VerificationReport, VerifierEvidence,
    };
    use eliot_protocol::RequestIdentity;
    use eliot_receipts::RequestBinding;
    use eliot_store_api::{
        CommitId, OrderingHeadExpectation, PreparedTransition, Resubmission,
        RevisionHeadExpectation, ScopeRevisionView, StoreHealth, WriteReceipt, WriteReceiptStatus,
        issue_store_receipt_envelope, validate_store_receipt_envelope,
    };

    use crate::{CanonicalAdmissionSnapshot, KernelPortFuture};

    const TEST_LINEAGE_A: &str = "550e8400-e29b-41d4-a716-446655440000";

    fn test_epoch(lineage: &str, sequence: u64) -> EpochId {
        EpochId::new(
            EpochLineageId::new(lineage).expect("valid test lineage"),
            std::num::NonZeroU64::new(sequence).expect("nonzero test sequence"),
        )
        .expect("valid test epoch")
    }

    struct TestKernel {
        committed: Mutex<BTreeMap<String, (String, String, WriteReceipt)>>,
        problem_revisions: Mutex<BTreeMap<String, u64>>,
        apply_calls: Mutex<u64>,
    }

    impl TestKernel {
        fn new(problem_revisions: BTreeMap<String, u64>) -> Self {
            Self {
                committed: Mutex::new(BTreeMap::new()),
                problem_revisions: Mutex::new(problem_revisions),
                apply_calls: Mutex::new(0),
            }
        }

        fn apply_count(&self) -> u64 {
            *self.apply_calls.lock().expect("apply lock")
        }

        fn problem_revision(&self, problem_id: &str) -> Option<u64> {
            self.problem_revisions
                .lock()
                .expect("revision lock")
                .get(problem_id)
                .copied()
        }
    }

    /// Validates identity/transition binding plus revision/ordering fences.
    fn check_test_transition_bindings(
        identity: &RequestIdentity,
        transition: &PreparedTransition,
        expected_revision_heads: &[RevisionHeadExpectation],
        expected_ordering_heads: &[OrderingHeadExpectation],
    ) -> Result<(), KernelPortError> {
        identity
            .validate()
            .map_err(|error| KernelPortError::Contract(error.to_string()))?;
        transition
            .validate()
            .map_err(|error| KernelPortError::Contract(error.to_string()))?;
        if identity.request.metadata.state_fence != transition.state_fence {
            return Err(KernelPortError::Contract(
                "test gateway: identity fence does not match transition".to_owned(),
            ));
        }
        if identity.idempotency_key != transition.identity.idempotency_key {
            return Err(KernelPortError::Contract(
                "test gateway: idempotency does not match transition".to_owned(),
            ));
        }
        for head in expected_revision_heads {
            head.validate()
                .map_err(|error| KernelPortError::Contract(error.to_string()))?;
            if head.state_fence != transition.state_fence {
                return Err(KernelPortError::Contract(
                    "test gateway: revision head fence mismatch".to_owned(),
                ));
            }
        }
        for head in expected_ordering_heads {
            head.validate()
                .map_err(|error| KernelPortError::Contract(error.to_string()))?;
            if head.state_fence != transition.state_fence {
                return Err(KernelPortError::Contract(
                    "test gateway: ordering head fence mismatch".to_owned(),
                ));
            }
        }
        Ok(())
    }

    /// Builds the committed test receipt plus its store envelope.
    fn build_test_receipt(
        identity: &RequestIdentity,
        transition: &PreparedTransition,
        hash: &str,
        sequence: u64,
    ) -> Result<WriteReceipt, KernelPortError> {
        let operation_id = transition.identity.operation_id.clone();
        let candidate = WriteReceipt {
            operation_id: operation_id.clone(),
            idempotency_key: transition.identity.idempotency_key.clone(),
            canonical_request_hash: hash.to_owned(),
            transition_class: transition.transition_class,
            status: WriteReceiptStatus::Committed,
            commit_id: Some(
                CommitId::new(format!("commit-{operation_id}"))
                    .map_err(|error| KernelPortError::Contract(error.to_string()))?,
            ),
            state_fence: transition.state_fence.clone(),
            ordering_sequences: Vec::new(),
            revision_before_after: Vec::new(),
            applied_command_ids: vec!["cmd-1".to_owned()],
            emitted_event_ids: Vec::new(),
            projection_refs: Vec::new(),
            outbox_refs: Vec::new(),
            operation_manifest_digest: transition.operation_manifest_digest.clone(),
            error_code: None,
            resubmission: Resubmission::None,
            committed_at: Some(format!("commit-sequence-{sequence:016}")),
            envelope: None,
        };
        candidate
            .validate()
            .map_err(|error| KernelPortError::Contract(error.to_string()))?;
        let envelope = issue_store_receipt_envelope(
            &identity.request.metadata,
            transition,
            &candidate,
            sequence,
        )
        .map_err(|error| KernelPortError::Contract(error.to_string()))?;
        let mut receipt = candidate;
        receipt.envelope = Some(envelope);
        validate_store_receipt_envelope(&identity.request.metadata, transition, &receipt)
            .map_err(|error| KernelPortError::Contract(error.to_string()))?;
        Ok(receipt)
    }

    /// Applies the test problem-revision compare-and-swap for recovery legs.
    fn apply_test_revision_cas(
        kernel: &TestKernel,
        transition_class: TransitionClass,
        expected_revision_heads: &[RevisionHeadExpectation],
    ) -> Result<(), KernelPortError> {
        if transition_class != TransitionClass::RecoverySchema {
            return Ok(());
        }
        let mut revisions = kernel.problem_revisions.lock().expect("revision lock");
        for head in expected_revision_heads {
            if let Some(problem_id) = head.key.as_str().strip_prefix("problem:") {
                let current = revisions.get(problem_id).copied().unwrap_or(0);
                if current == 0 || current != head.expected_revision {
                    return Err(KernelPortError::Contract(
                        "test gateway: problem revision compare-and-swap failed".to_owned(),
                    ));
                }
                revisions.insert(problem_id.to_owned(), current + 1);
            }
        }
        Ok(())
    }

    impl KernelTransitionPort for TestKernel {
        fn apply_prepared<'a>(
            &'a self,
            identity: &RequestIdentity,
            transition: PreparedTransition,
            expected_revision_heads: Vec<RevisionHeadExpectation>,
            expected_ordering_heads: Vec<OrderingHeadExpectation>,
        ) -> KernelPortFuture<'a, WriteReceipt> {
            let identity = identity.clone();
            Box::pin(async move {
                check_test_transition_bindings(
                    &identity,
                    &transition,
                    &expected_revision_heads,
                    &expected_ordering_heads,
                )?;
                let key = transition.identity.operation_id.as_str().to_owned();
                let hash = transition.identity.canonical_request_hash.clone();
                let mut committed = self.committed.lock().expect("committed lock");
                if let Some((_, stored_hash, receipt)) = committed.get(&key) {
                    if *stored_hash == hash {
                        return Ok(receipt.clone());
                    }
                    return Err(KernelPortError::Contract(
                        "test gateway: committed operation identity conflict".to_owned(),
                    ));
                }
                apply_test_revision_cas(
                    self,
                    transition.transition_class,
                    &expected_revision_heads,
                )?;
                let sequence = u64::try_from(committed.len())
                    .map_err(|error| KernelPortError::Contract(error.to_string()))?
                    + 1;
                let receipt = build_test_receipt(&identity, &transition, &hash, sequence)?;
                *self.apply_calls.lock().expect("apply lock") += 1;
                committed.insert(
                    key,
                    (
                        transition.identity.idempotency_key.clone(),
                        hash,
                        receipt.clone(),
                    ),
                );
                Ok(receipt)
            })
        }

        fn receipt(&self, operation_id: OperationId) -> KernelPortFuture<'_, Option<WriteReceipt>> {
            Box::pin(async move {
                Ok(self
                    .committed
                    .lock()
                    .expect("committed lock")
                    .get(operation_id.as_str())
                    .map(|(_, _, receipt)| receipt.clone()))
            })
        }

        fn health(&self) -> KernelPortFuture<'_, StoreHealth> {
            Box::pin(async move { Err(KernelPortError::NotAdmitted("test port".to_owned())) })
        }
    }

    fn block_on<T>(future: impl Future<Output = T>) -> T {
        let waker = std::task::Waker::noop();
        let mut context = Context::from_waker(waker);
        let mut future = Box::pin(future);
        loop {
            match future.as_mut().poll(&mut context) {
                Poll::Ready(output) => return output,
                Poll::Pending => std::thread::yield_now(),
            }
        }
    }

    fn fence() -> StateFence {
        StateFence::new(
            test_epoch(TEST_LINEAGE_A, 1),
            ResourceGeneration::new(1).expect("generation"),
        )
    }

    fn fixed_time() -> time::OffsetDateTime {
        time::OffsetDateTime::from_unix_timestamp(1_786_000_000).expect("fixed test time")
    }

    fn future_deadline() -> time::OffsetDateTime {
        time::OffsetDateTime::from_unix_timestamp(2_000_000_000).expect("future deadline")
    }

    fn manifest() -> RepairRecipeManifest {
        RepairRecipeManifest {
            manifest_id: "test-manifest".to_owned(),
            manifest_revision: 1,
            operations: vec![RegisteredOperation {
                operation_id: "test-operation".to_owned(),
                adapter_id: "test-adapter".to_owned(),
                description: "test operation".to_owned(),
                definition_digest: sha256_hex(b"test-operation-definition"),
            }],
        }
    }

    fn recipe() -> RepairRecipe {
        RepairRecipe {
            recipe_id: "test-recipe".to_owned(),
            revision: 1,
            problem_classes: BTreeSet::from(["test-class".to_owned()]),
            components: BTreeSet::from(["test-component".to_owned()]),
            repair_class: RepairClass::AutomaticSafe,
            prerequisites: Vec::new(),
            required_authority: "governor".to_owned(),
            allowed_effects: BTreeSet::from(["test-operation".to_owned()]),
            operations: vec!["test-operation".to_owned()],
            expected_observables: vec!["test-observable".to_owned()],
            verification_contract: vec!["test-contract".to_owned()],
            rollback_or_compensation: vec!["test-rollback".to_owned()],
            attempt_budget: 1,
            cooldown: time::Duration::ZERO,
            stop_conditions: vec!["test-stop".to_owned()],
        }
    }

    fn brief(problem_id: &str) -> DiagnosticBrief {
        DiagnosticBrief {
            problem_id: problem_id.to_owned(),
            component: "test-component".to_owned(),
            failure_class: "test-class".to_owned(),
            symptom: "test symptom".to_owned(),
            impact: "test impact".to_owned(),
            evidence: vec![
                EvidenceHandle::new("brief-evidence", sha256_hex(b"brief-evidence-bytes"))
                    .expect("brief evidence"),
            ],
            unknowns: Vec::new(),
        }
    }

    fn operation(manifest_value: &RepairRecipeManifest) -> RepairOperationRef {
        manifest_value
            .resolve("test-operation")
            .expect("registered operation")
    }

    fn attempt(
        attempt_id: &str,
        brief_value: &DiagnosticBrief,
        recipe_value: &RepairRecipe,
        operation_value: &RepairOperationRef,
        doctor_fence: &eliot_doctor_core::StateFence,
    ) -> RepairAttemptIdentity {
        let recipe_identity = RepairRecipeIdentity::bind(recipe_value).expect("recipe identity");
        RepairAttemptIdentity::bind(&AttemptIdentityBinding {
            attempt_id,
            brief: brief_value,
            recipe: &recipe_identity,
            operation: operation_value,
            fence: doctor_fence,
            epoch: None,
            approval: None,
            budget_units: 1,
            deadline: future_deadline(),
        })
        .expect("attempt identity")
    }

    fn effect(
        attempt_value: &RepairAttemptIdentity,
        operation_value: &RepairOperationRef,
    ) -> RepairEffectIdentity {
        RepairEffectIdentity::bind(attempt_value, operation_value, 0).expect("effect identity")
    }

    fn report(
        attempt_value: RepairAttemptIdentity,
        effect_value: RepairEffectIdentity,
        doctor_fence: &eliot_doctor_core::StateFence,
        problem_id: &str,
        evaluation: EvaluationOutcome,
    ) -> VerificationReport {
        let evidence = VerifierEvidence {
            verification_execution: VerificationExecution::Executed,
            evaluation,
            artifact_binding: ArtifactBinding::BoundExact {
                target_digest: effect_value.digest().to_owned(),
            },
            scope: ScopeAttestation {
                fence_digest: doctor_fence.digest.clone(),
                observed_at: fixed_time(),
                fence_current: true,
            },
            independence: IndependenceProfile::new(BTreeSet::from([
                IndependenceClass::DistinctFailureDomain,
            ]))
            .expect("independence"),
            evidence: vec![
                EvidenceHandle::new(problem_id, sha256_hex(b"raw-verifier-evidence"))
                    .expect("problem evidence"),
                EvidenceHandle::new("verifier-log", sha256_hex(b"verifier-log-bytes"))
                    .expect("log evidence"),
            ],
        };
        VerificationReport {
            attempt: attempt_value,
            effect: effect_value,
            evidence,
            reported_at: fixed_time(),
        }
    }

    fn valid_report(problem_id: &str, attempt_id: &str) -> VerificationReport {
        let fence_value = fence();
        let doctor_fence = doctor_fence_echo(&fence_value).expect("doctor echo");
        let manifest_value = manifest();
        manifest_value.validate().expect("manifest valid");
        let operation_value = operation(&manifest_value);
        manifest_value
            .check_admitted(&operation_value)
            .expect("operation admitted");
        let recipe_value = recipe();
        let brief_value = brief(problem_id);
        let attempt_value = attempt(
            attempt_id,
            &brief_value,
            &recipe_value,
            &operation_value,
            &doctor_fence,
        );
        attempt_value.validate().expect("attempt valid");
        let effect_value = effect(&attempt_value, &operation_value);
        effect_value.validate().expect("effect valid");
        let report_value = report(
            attempt_value,
            effect_value,
            &doctor_fence,
            problem_id,
            EvaluationOutcome::Pass,
        );
        report_value.validate().expect("report valid");
        report_value
            .endorse(&doctor_fence)
            .expect("report endorses");
        report_value
    }

    fn identity(fence_value: &StateFence) -> RequestIdentity {
        let metadata = RequestMetadata {
            request_id: RequestId::new("req-doctor-1").expect("request id"),
            session_id: Some(SessionId::new("session-doctor-1").expect("session")),
            task_id: None,
            product_id: ProductId::new("test-product").expect("product"),
            source_id: SourceId::new("agent-bridge").expect("source"),
            state_fence: fence_value.clone(),
            clock: ClockReading::default(),
        };
        RequestIdentity {
            request: RequestBinding {
                metadata,
                state_fence: fence_value.clone(),
            },
            idempotency_key: "idem-doctor-1".to_owned(),
            deadline_unix_ms: 1_800_000_000_000,
            cancellation_id: "cancel-doctor-1".to_owned(),
        }
    }

    fn canonical_owner(fence_value: &StateFence) -> CanonicalAdmissionOwner {
        let scope = ScopeRevisionView {
            scope_id: ScopeId::new("governor").expect("scope"),
            revision_heads: Vec::new(),
            ordering_heads: Vec::new(),
            state_fence: fence_value.clone(),
        };
        let snapshot =
            CanonicalAdmissionSnapshot::new(fence_value.clone(), 1, None).expect("snapshot");
        CanonicalAdmissionOwner::new(fence_value.clone(), scope, snapshot).expect("canonical owner")
    }

    fn evidence_refs(report_value: &VerificationReport) -> Vec<String> {
        report_value
            .evidence
            .evidence
            .iter()
            .map(|handle| handle.reference.clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    }

    fn adapter<'a>(
        journal: &'a ObservationJournal,
        revisions: &'a BTreeMap<String, u64>,
        canonical: &'a CanonicalAdmissionOwner,
        kernel: &'a TestKernel,
    ) -> GovernorObservationReconciliation<'a, TestKernel> {
        GovernorObservationReconciliation::new(
            journal,
            revisions,
            canonical,
            kernel,
            CompositionReadiness::Ready,
        )
    }

    #[test]
    fn verified_repair_commits_and_same_operation_retry_returns_the_same_receipt() {
        let fence_value = fence();
        let journal = ObservationJournal::default();
        let revisions = BTreeMap::from([("problem-1".to_owned(), 3_u64)]);
        let canonical = canonical_owner(&fence_value);
        let kernel = TestKernel::new(revisions.clone());
        let owner = adapter(&journal, &revisions, &canonical, &kernel);
        let identity_value = identity(&fence_value);
        let operation_id = OperationId::new("op-doctor-positive").expect("operation id");
        let report_value = valid_report("problem-1", "attempt-1");
        let receipt = block_on(owner.admit_doctor_verification(
            &identity_value,
            &operation_id,
            &report_value,
        ))
        .expect("verified repair admits");
        assert_eq!(receipt.operation_id, operation_id);
        assert_eq!(receipt.idempotency_key, identity_value.idempotency_key);
        assert_eq!(receipt.status, WriteReceiptStatus::Committed);
        assert_eq!(receipt.transition_class, TransitionClass::RecoverySchema);
        assert_eq!(receipt.state_fence, fence_value);
        assert_eq!(kernel.apply_count(), 2);
        assert_eq!(kernel.problem_revision("problem-1"), Some(4));
        let stored = block_on(kernel.receipt(operation_id.clone()))
            .expect("receipt route")
            .expect("stored receipt");
        assert_eq!(stored, receipt);
        let replayed = block_on(owner.admit_doctor_verification(
            &identity_value,
            &operation_id,
            &report_value,
        ))
        .expect("same-operation retry reconciles");
        assert_eq!(replayed, receipt);
        assert_eq!(
            kernel.apply_count(),
            2,
            "retry with identical bytes must not execute a second transition"
        );
        assert_eq!(kernel.problem_revision("problem-1"), Some(4));
    }

    #[test]
    fn false_verification_is_rejected_with_zero_commits() {
        let fence_value = fence();
        let journal = ObservationJournal::default();
        let revisions = BTreeMap::from([("problem-1".to_owned(), 3_u64)]);
        let canonical = canonical_owner(&fence_value);
        let kernel = TestKernel::new(revisions.clone());
        let owner = adapter(&journal, &revisions, &canonical, &kernel);
        let identity_value = identity(&fence_value);
        let operation_id = OperationId::new("op-doctor-false").expect("operation id");
        let doctor_fence = doctor_fence_echo(&fence_value).expect("doctor echo");
        let manifest_value = manifest();
        let operation_value = operation(&manifest_value);
        let recipe_value = recipe();
        let brief_value = brief("problem-1");
        let attempt_value = attempt(
            "attempt-false",
            &brief_value,
            &recipe_value,
            &operation_value,
            &doctor_fence,
        );
        let effect_value = effect(&attempt_value, &operation_value);
        let report_value = report(
            attempt_value,
            effect_value,
            &doctor_fence,
            "problem-1",
            EvaluationOutcome::Fail,
        );
        let rejected = block_on(owner.admit_doctor_verification(
            &identity_value,
            &operation_id,
            &report_value,
        ));
        assert!(
            matches!(rejected, Err(CompositionError::Owner(_))),
            "false verification was not rejected: {rejected:?}"
        );
        assert_eq!(kernel.apply_count(), 0);
        assert!(kernel.committed.lock().expect("committed lock").is_empty());
        assert_eq!(kernel.problem_revision("problem-1"), Some(3));
    }

    #[test]
    fn exact_observation_replay_reconciles_while_mutated_bytes_conflict() {
        let fence_value = fence();
        let revisions = BTreeMap::from([("problem-1".to_owned(), 3_u64)]);
        let canonical = canonical_owner(&fence_value);
        let kernel = TestKernel::new(revisions.clone());
        let identity_value = identity(&fence_value);
        let operation_id = OperationId::new("op-doctor-replay").expect("operation id");
        let report_value = valid_report("problem-1", "attempt-replay");
        let refs = evidence_refs(&report_value);
        let submission = verification_submission(
            &operation_id,
            &identity_value,
            &report_value,
            "problem-1",
            &refs,
        )
        .expect("submission builds");
        let mut recovered = ObservationJournal::default();
        let admitted = recovered.admit(submission).expect("recovery admission");
        assert!(matches!(
            admitted,
            ObservationAdmissionResult::Accepted { .. }
        ));
        let journal =
            ObservationJournal::from_entries(recovered.snapshot()).expect("journal rebuilds");
        let owner = adapter(&journal, &revisions, &canonical, &kernel);
        let receipt = block_on(owner.admit_doctor_verification(
            &identity_value,
            &operation_id,
            &report_value,
        ))
        .expect("first admission commits");
        assert_eq!(receipt.status, WriteReceiptStatus::Committed);
        assert_eq!(kernel.apply_count(), 2);
        let replayed = block_on(owner.admit_doctor_verification(
            &identity_value,
            &operation_id,
            &report_value,
        ))
        .expect("exact replay reconciles");
        assert_eq!(replayed, receipt);
        assert_eq!(
            kernel.apply_count(),
            2,
            "exact observation replay must not produce a second transition"
        );
        let mutated_report = valid_report("problem-1", "attempt-mutated");
        let mutated = block_on(owner.admit_doctor_verification(
            &identity_value,
            &operation_id,
            &mutated_report,
        ));
        assert!(
            matches!(mutated, Err(CompositionError::Owner(_))),
            "mutated bytes under the same idempotency key must conflict: {mutated:?}"
        );
        assert_eq!(kernel.apply_count(), 2, "conflicting retry must not commit");
    }

    #[test]
    fn watchdog_batch_admits_heartbeat_and_gap_idempotently() {
        let fence_value = fence();
        let journal = ObservationJournal::default();
        let revisions = BTreeMap::new();
        let canonical = canonical_owner(&fence_value);
        let kernel = TestKernel::new(revisions.clone());
        let owner = adapter(&journal, &revisions, &canonical, &kernel);
        let identity_value = identity(&fence_value);
        let base = OperationId::new("op-watchdog-batch-1").expect("base operation");
        let batch_id = "batch-watchdog-1";
        let batch_digest = sha256_hex(b"watchdog-batch-1");
        let entries = vec![
            WatchdogEntryAdmission {
                sequence: 1,
                kind: WatchdogEntryKind::Heartbeat,
                record_digest: sha256_hex(b"watchdog-rec-1"),
                payload_digest: sha256_hex(b"watchdog-pay-1"),
                observed_at_ms: 1_786_000_000_000,
            },
            WatchdogEntryAdmission {
                sequence: 2,
                kind: WatchdogEntryKind::Gap,
                record_digest: sha256_hex(b"watchdog-rec-2"),
                payload_digest: sha256_hex(b"watchdog-pay-2"),
                observed_at_ms: 1_786_000_000_001,
            },
        ];
        let outcomes = block_on(owner.admit_watchdog_batch(
            &identity_value,
            &base,
            batch_id,
            &batch_digest,
            &entries,
        ))
        .expect("watchdog batch admits");
        assert_eq!(outcomes.len(), 2);
        for (outcome, entry) in outcomes.iter().zip(entries.iter()) {
            assert_eq!(outcome.sequence, entry.sequence);
            assert_eq!(outcome.record_digest, entry.record_digest);
            let receipt = outcome.receipt.as_ref().expect("committed receipt");
            assert_eq!(receipt.status, WriteReceiptStatus::Committed);
            assert_eq!(receipt.transition_class, TransitionClass::CaptureCandidate);
            assert_eq!(receipt.state_fence, fence_value);
        }
        assert_eq!(kernel.apply_count(), 2);
        let replayed = block_on(owner.admit_watchdog_batch(
            &identity_value,
            &base,
            batch_id,
            &batch_digest,
            &entries,
        ))
        .expect("exact batch replay reconciles");
        assert_eq!(replayed, outcomes);
        assert_eq!(
            kernel.apply_count(),
            2,
            "exact batch replay must not execute a second transition per spool sequence"
        );
        let mut mutated = entries.clone();
        mutated[0].record_digest = sha256_hex(b"watchdog-rec-1-mutated");
        let conflict = block_on(owner.admit_watchdog_batch(
            &identity_value,
            &base,
            batch_id,
            &batch_digest,
            &mutated,
        ));
        // Fail-closed at either layer: journal identity conflict (Owner) when
        // the composition persists the first admission, or canonical receipt
        // reconciliation (Provider) when scratch is per-call as here. Both
        // refuse a second transition for one spool sequence.
        assert!(
            matches!(
                conflict,
                Err(CompositionError::Owner(_) | CompositionError::Provider(_))
            ),
            "mutated payload under the same spool sequence must conflict: {conflict:?}"
        );
        assert_eq!(kernel.apply_count(), 2, "conflicting retry must not commit");
    }
}
