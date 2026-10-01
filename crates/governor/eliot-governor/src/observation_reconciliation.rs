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
//! - domain legality on a scratch copy only: the verification is admitted to a
//!   cloned journal through [`ObservationJournal::admit`] (same key plus same
//!   bytes replays, changed bytes conflict). The scratch result is never
//!   published.
//!
//! The Problem/Incident record itself is deliberately *not* re-simulated here
//! (see "Named prerequisite" below). A `Problem` can only carry a live owner
//! through an [`AuthenticatedOwnerLease`](eliot_problem::AuthenticatedOwnerLease),
//! and this composition holds none, so any record synthesized here would have
//! to invent one. It also could not assert the edge it used to assert:
//! `Verifying -> Resolved` is refused as a bare
//! [`Problem::transition`](eliot_problem::Problem::transition) and is reachable
//! only through [`Problem::resolve`](eliot_problem::Problem::resolve) against
//! the record's own pre-fixed `expected_resolution` set.
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
//! Maintenance source results take the same canonical route through
//! [`GovernorObservationReconciliation::admit_maintenance_result`]: the
//! Governor prepares the typed observation for the governed self scope from the
//! maintained subsystem's own record (its exact v1 event core, scope,
//! provenance and privacy disclosure, with the field-complete
//! [`MaintenanceRecord`] family in the v2 payload), the Kernel checks
//! authority/fence/identity through [`CanonicalAdmissionOwner::commit`], and the
//! Store returns its own receipt unchanged. The stable publication identity is
//! derived from the source event and its revisions, never from retry time, so
//! an identical replay reconciles the existing receipt while changed content
//! under the same identity conflicts. A lost acknowledgement reads the original
//! receipt back through the neutral port rather than committing again, and
//! required proof carries only the execution evidence the source result really
//! holds, so a no-attempt deferral publishes with no fabricated execution
//! references. `eliot_system` is a projection of that source data, never
//! permission to copy arbitrary project contents into a global record.
//!
//! Failure mapping reuses the existing [`CompositionError`] variants (no new
//! variant is introduced so the closed matches elsewhere in this crate keep
//! compiling): request-identity, fence, and operation-identity mismatches are
//! [`CompositionError::Provider`]; every other deterministic admission
//! refusal — false verification, unknown/ambiguous problem binding, empty or
//! invalid evidence, non-candidate supervision signal, journal conflict,
//! malformed store receipt — is [`CompositionError::Owner`]. Detail strings
//! name the refused property; they are diagnostics, never control flow.
//!
//! Honest gaps: the `problem:{problem_id}` revision-head key namespace is a
//! Governor-to-Store compare-and-swap contract proposal owned by the store
//! boundary (T3); the verifier fence-echo digest derivation above is the
//! interim binding until the lineaged epoch migration (T6/#64) lands. No
//! verifier is implemented here and no repair is executed: endorsement
//! consumes evidence produced outside the effect executor.
//!
//! Named prerequisite (#1759) — **no production
//! [`OwnerLeaseIssuer`](eliot_problem::OwnerLeaseIssuer) exists in this
//! tree.** The trait is declared in `eliot-problem/src/ownership.rs` and its
//! only implementation anywhere is a `#[cfg(test)]` issuer inside that crate's
//! own unit tests, so
//! [`AuthenticatedOwnerLease`](eliot_problem::AuthenticatedOwnerLease) is
//! unreachable from `eliot-governor`. This Governor holds problem identities
//! and revisions only (`ProblemOwner` is a `BTreeMap<String, u64>`), never
//! records and never leases. Consequently the
//! two Problem/Incident scratch probes that used to live here — a
//! `Verifying -> Resolved` probe and a watchdog-gap `Candidate` Incident probe,
//! both built from a literal `owner: OwnerRef { principal: GOVERNOR_SCOPE_ID }`
//! — have been removed rather than re-pointed at a self-named principal.
//! Naming yourself the owner is not ownership, and a scratch that asserted it
//! proved only that the Governor's own literal was well formed.
//!
//! What still gates both paths is unchanged and is checked against real
//! admitted state: exact problem binding (zero and ambiguous matches both
//! refuse), non-empty deduplicated verifier evidence, `endorse` against the
//! projected fence echo, and the `problem:{problem_id}` compare-and-swap
//! revision head carried by `recovery_envelope`. What is genuinely missing
//! and named rather than stubbed: closing the bound Problem needs
//! `Problem::resolve` with a `ClosureEvidence` whose verifier is independent
//! of the current owner and whose `verified_observables` cover the record's
//! pre-fixed `expected_resolution`, and raising any Problem or Incident needs
//! an `AuthenticatedOwnerLease` from a real issuer. Both belong to the lease
//! owner and the Problem owner respectively, not to this Governor.
//!
//! The nine named owner transitions (issue #1759 I2) are prepared and committed
//! from this owner through
//! [`GovernorObservationReconciliation::commit_problem_owner_transition`], which
//! reuses this same gateway and the same `problem:{problem_id}` revision-head
//! namespace. That entry currently has **no caller anywhere in the tree** — not
//! a production entry and not a test — so the whole nine-verb path is reached
//! from nothing. It is type-sound and its preparation is exercised through the
//! same gateway as every other canonical write here; what is missing is a caller,
//! and the caller cannot be written until the lease owner exists, because the
//! entry takes an `AuthenticatedOwnerLease` and nothing outside `eliot-problem`'s
//! own test module can construct one. Both facts are stated here rather than
//! worked around: no principal string is accepted on that path, no Problem or
//! Incident literal is constructed in this module, and no alias or wrapper was
//! added to make the missing caller appear to exist.

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
    ObservationKind, ObservationRecordEnvelope, ObservationRecordEnvelopeV2, ObservationRecordKind,
    ObservationScope, ObservationSubmission, PrivacyRetentionDisclosure, ProducerTrace,
    RecordFamilyPayloadV2, RejectionDisposition,
};
use eliot_observation_contracts::{MaintenanceRecord, MaintenanceResultV1};
use eliot_problem::{
    DeliveryState, Signal, SignalAttribution, SignalDisposition, SignalId, SignalProcessingState,
    SignalSeverity,
};
use eliot_receipts::WorkScopeId;
use eliot_store_api::{
    CONTRACT_VERSION, EffectClass, EventProjectionRelationIntents, NamedMutationOperation,
    NamedMutationRequest, NamedOperationManifest, OperationManifestDigest, OrderingHeadExpectation,
    OrderingScopeId, RevisionHeadExpectation, RevisionKey, ScopeId, SecurityContext,
    TransitionClass, WriteReceipt, WriteReceiptStatus,
};

use crate::problem_owner_transitions::{
    ProblemOwnerTransitionOutcome, ProblemOwnerTransitionRequest, prepare_problem_owner_transition,
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
        admission_contract_set_digest: eliot_canonical::supported_admission_contract_set_digest()?,
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
        admission_contract_set_digest: eliot_canonical::supported_admission_contract_set_digest()?,
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

/// Builds the deterministic observation submission for one maintenance result.
///
/// The exact v1 event core, scope, provenance and privacy disclosure come from
/// the maintained subsystem's own record; this path never substitutes a global
/// identity for them, so publishing into `eliot_system` stays a projection of
/// source data rather than a copy of arbitrary project contents. The v2 payload
/// carries the exact [`MaintenanceRecord`] family, which keeps the versioned
/// result and its utility evidence field-complete.
fn maintenance_result_submission(
    operation_id: &OperationId,
    idempotency_key: &str,
    identity: &eliot_protocol::RequestIdentity,
    record: &MaintenanceRecord,
) -> ObservationSubmission {
    let record_v2 = ObservationRecordEnvelopeV2 {
        payload: RecordFamilyPayloadV2::Maintenance(record.clone()),
        caller_family_hint: Some(ObservationRecordKind::Maintenance),
        parent_record_id: None,
    };
    ObservationSubmission {
        operation_id: operation_id.as_str().to_owned(),
        idempotency_key: idempotency_key.to_owned(),
        state_fence: identity.request.metadata.state_fence.clone(),
        record: ObservationRecordEnvelope {
            record_id: record.record_id.clone(),
            kind: ObservationRecordKind::Maintenance,
            event: Some(record.core.clone()),
            coverage_gap: None,
            journal_control_event: false,
            parent_record_id: None,
        },
        record_v2: Some(record_v2),
        capture_route: CaptureRoute::CanonicalJournal,
        durability: Durability::Durable,
        plan: None,
        task_selection: None,
        evidence: None,
    }
}

/// Builds the observation-leg envelope for one maintenance result.
///
/// The envelope addresses the maintained subsystem's own work scope and binds
/// the stable publication identity: record identity, source outcome revision
/// and evaluation revision. Required proof carries only the execution evidence
/// the source result actually holds, so a no-attempt deferral publishes with
/// empty proof rather than fabricated execution references.
fn maintenance_observation_envelope(
    identity: &eliot_protocol::RequestIdentity,
    observation_operation: &OperationId,
    submission: &ObservationSubmission,
    record: &MaintenanceRecord,
    proof_refs: &[String],
    manifest_digest: &OperationManifestDigest,
) -> Result<CanonicalWriteEnvelope, CompositionError> {
    let fence = &identity.request.metadata.state_fence;
    let request_digest = submission
        .request_digest()
        .map_err(|error| owner_refused(error.to_string()))?;
    let work_scope = record.core.affected_scope.work_scope.as_str();
    let mut parameters = BTreeMap::new();
    for (name, value) in [
        ("record_id", record.record_id.clone()),
        ("request_digest", request_digest),
        ("operation_id", submission.operation_id.clone()),
        ("idempotency_key", submission.idempotency_key.clone()),
        ("maintenance_action", record.maintenance_action.clone()),
        ("trigger_ref", record.trigger_ref.clone()),
        (
            "source_outcome_revision",
            record
                .result
                .as_ref()
                .map_or_else(String::new, |result| result.source_outcome_revision.clone()),
        ),
        (
            "evaluation_revision",
            record
                .result
                .as_ref()
                .map_or_else(String::new, |result| result.evaluation_revision.to_string()),
        ),
        ("work_scope", work_scope.to_owned()),
    ] {
        parameters.insert(name.to_owned(), serde_json::Value::String(value));
    }
    let envelope = CanonicalWriteEnvelope {
        operation_id: observation_operation.clone(),
        request: identity.request.metadata.clone(),
        idempotency_key: submission.idempotency_key.clone(),
        scope_id: ScopeId::new(work_scope).map_err(|error| owner_refused(error.to_string()))?,
        task_id: identity
            .request
            .metadata
            .task_id
            .as_ref()
            .map(|task| task.as_str().to_owned()),
        transition_class: TransitionClass::CaptureCandidate,
        requested_effect_ceiling: EffectClass::Candidate,
        admission_contract_set_digest: eliot_canonical::supported_admission_contract_set_digest()?,
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
        required_proof_and_approval_refs: proof_refs.to_vec(),
        expected_revision_heads: Vec::new(),
        expected_ordering_heads: vec![OrderingHeadExpectation {
            scope: OrderingScopeId::new(format!("scope:{work_scope}"))
                .map_err(|error| owner_refused(error.to_string()))?,
            expected_sequence: 1,
            state_fence: fence.clone(),
        }],
    };
    envelope.validate()?;
    Ok(envelope)
}

/// Collects the execution evidence the source result actually holds.
///
/// A no-attempt deferral carries none, and this returns an empty proof set
/// rather than inventing attempt, effect or receipt references.
fn maintenance_execution_proof(record: &MaintenanceRecord) -> Vec<String> {
    let Some(result) = record.result.as_deref() else {
        return Vec::new();
    };
    let mut refs: Vec<String> = Vec::new();
    for reference in result
        .actual_effect_refs
        .iter()
        .chain(&result.checkpoint_refs)
        .chain(&result.reconciliation_refs)
    {
        if !refs.contains(reference) {
            refs.push(reference.clone());
        }
    }
    refs
}

impl<P: KernelTransitionPort + ?Sized> GovernorObservationReconciliation<'_, P> {
    /// Admits one maintenance source result into the canonical observation path
    /// and returns the exact store receipt.
    ///
    /// The Governor prepares the typed observation for the governed self scope;
    /// the Kernel checks authority, fence and identity through
    /// [`CanonicalAdmissionOwner::commit`], and the Store returns its own
    /// receipt unchanged. Stable publication identity is derived from the
    /// source event and its revisions, never from retry time, so an identical
    /// replay reconciles the existing receipt while changed content under the
    /// same identity conflicts. A lost acknowledgement reads back the original
    /// receipt through the neutral port instead of committing again; logging or
    /// transport acknowledgement is never treated as publication.
    pub async fn admit_maintenance_result(
        &self,
        identity: &eliot_protocol::RequestIdentity,
        base_operation_id: &OperationId,
        record: &MaintenanceRecord,
    ) -> Result<WriteReceipt, CompositionError> {
        self.validate_capture_identity_fence(identity)?;
        record.validate().map_err(|error| {
            owner_refused(format!("maintenance result is not admissible: {error}"))
        })?;
        let publication_id = record.result.as_deref().map_or_else(
            || record.record_id.clone(),
            |result: &MaintenanceResultV1| result.publication_id.clone(),
        );
        let revision_suffix = record.result.as_deref().map_or_else(String::new, |result| {
            format!("-r{}", result.evaluation_revision)
        });
        let observation_operation = OperationId::new(format!(
            "{base_operation_id}/maintenance-{publication_id}{revision_suffix}"
        ))
        .map_err(|error| owner_refused(error.to_string()))?;
        let per_result_idempotency = format!(
            "{}:maintenance:{publication_id}{revision_suffix}",
            identity.idempotency_key
        );
        // Derived per-result identity: the canonical owner requires the
        // envelope idempotency to equal the admitted identity idempotency, and
        // the envelope request binding must stay the caller's. A retry must
        // therefore reuse the caller identity and the base operation, so the
        // derived store identity stays a pure function of the source event.
        let result_identity = eliot_protocol::RequestIdentity {
            request: identity.request.clone(),
            idempotency_key: per_result_idempotency.clone(),
            deadline_unix_ms: identity.deadline_unix_ms,
            cancellation_id: identity.cancellation_id.clone(),
        };
        let submission = maintenance_result_submission(
            &observation_operation,
            &per_result_idempotency,
            identity,
            record,
        );
        let mut scratch = self.observation.clone();
        match scratch
            .admit(submission.clone())
            .map_err(|error| owner_refused(error.to_string()))?
        {
            ObservationAdmissionResult::Accepted { .. }
            | ObservationAdmissionResult::Replayed { .. } => {}
            ObservationAdmissionResult::Rejected { rejection } => {
                if rejection.disposition == RejectionDisposition::Conflict {
                    return Err(owner_refused(format!(
                        "maintenance observation identity conflict: {}",
                        rejection.all_contract_errors.join("; ")
                    )));
                }
                return Err(owner_refused(format!(
                    "maintenance observation is not admissible: {}",
                    rejection.all_contract_errors.join("; ")
                )));
            }
        }
        let manifest_digest = production_manifest_digest()?;
        let proof_refs = maintenance_execution_proof(record);
        let envelope = maintenance_observation_envelope(
            &result_identity,
            &observation_operation,
            &submission,
            record,
            &proof_refs,
            &manifest_digest,
        )?;
        let expected_hash = envelope
            .canonical_request_hash()
            .map_err(CompositionError::Canonical)?;
        if let Some(receipt) = self
            .reconcile_capture_observation_receipt(
                &result_identity,
                &observation_operation,
                &expected_hash,
                &manifest_digest,
            )
            .await?
        {
            return Ok(receipt);
        }
        self.commit_observation_leg(
            &result_identity,
            &observation_operation,
            envelope,
            &expected_hash,
            &manifest_digest,
        )
        .await
    }

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

    /// Admits the verification to a scratch journal clone, without publishing
    /// authority.
    ///
    /// The scratch journal is the only thing proved legal here. The bound
    /// `Problem` is not re-simulated: this composition holds no Problem record
    /// and no `AuthenticatedOwnerLease`, and the `Verifying -> Resolved` edge it
    /// used to assert is refused as a bare `Problem::transition` and is
    /// reachable only through `Problem::resolve` against the record's own
    /// pre-fixed `expected_resolution` set. That closure is the Problem owner's
    /// decision on independent evidence, not the Governor's; the named
    /// prerequisite is in the module documentation.
    fn admit_scratch_observation(
        &self,
        operation_id: &OperationId,
        identity: &eliot_protocol::RequestIdentity,
        report: &VerificationReport,
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

/// What one negative-memory gate decision did to one pending action.
///
/// The variant is the decision's own typed outcome, re-derived from the gate
/// rather than restated by the caller, so the appended observation cannot
/// describe a block as a warning.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NegativeMemoryGateOutcome {
    /// An exact admitted match refused the effect under a `Block` policy.
    Blocked,
    /// An exact admitted match refused the effect until the named admitted
    /// discriminating check has run.
    ProbeRequired,
    /// A near match or advisory disposition proceeded to ordinary
    /// authorization. This is a warning, never a permission.
    ProceededWithWarning,
    /// A complete bounded enumeration found no applicable rule and the effect
    /// proceeded.
    ProceededWithoutWarning,
    /// The gate could not decide, and the effect was refused rather than
    /// judged.
    ///
    /// This variant exists because its absence was a live defect: with no way
    /// to say "undecided", an undecidable gate had to be recorded as
    /// `ProceededWithoutWarning`, which asserts two things that are both
    /// false - that a complete enumeration ran, and that the effect proceeded.
    /// Neither is true of an `Unavailable` decision, which is the gate refusing
    /// to certify either a match or an absence. An absence of evidence is not
    /// evidence of absence, and an undecided gate is not a pass.
    Undecided,
}

impl NegativeMemoryGateOutcome {
    /// The closed wire token for this outcome.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Blocked => "blocked",
            Self::ProbeRequired => "probe_required",
            Self::ProceededWithWarning => "proceeded_with_warning",
            Self::ProceededWithoutWarning => "proceeded_without_warning",
            Self::Undecided => "undecided",
        }
    }
}

/// One matched negative-memory gate decision, as it is appended to the
/// observation path.
///
/// Every identity here is owner-issued or record-derived: the action identity
/// comes from the gated request, the rule identity and rule-set revision from
/// the store-observed read the decision was taken over, and the read handle
/// from that same read. No field is a free-form caller annotation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NegativeMemoryGateObservation {
    /// The gated action's own operation identity.
    pub action_operation_id: String,
    /// The gated action's effect identity.
    pub action_effect_id: String,
    /// The gated action's input digest.
    pub action_input_digest: String,
    /// The scope the effect was admitted at.
    pub scope_id: String,
    /// Immutable record identity of the rule that decided the action.
    pub record_id: String,
    /// The exact rule revision that was in force.
    pub rule_revision: u64,
    /// The exact rule content digest that was in force.
    pub record_digest: String,
    /// The named read the rule set was resolved through.
    pub read_handle: String,
    /// The scope revision head the store reported for that read.
    pub rule_set_revision: u64,
    /// The decision's own typed outcome.
    pub outcome: NegativeMemoryGateOutcome,
    /// Whether the gated effect actually reached the canonical store.
    ///
    /// This is a fact about the receipt the caller already holds. A refused
    /// effect is never reported as committed, and a committed effect is never
    /// reported as refused.
    pub committed_effect: bool,
}

impl NegativeMemoryGateObservation {
    /// The stable replay identity of this matched decision.
    ///
    /// It is derived from the action and the rule, so a replay of the same
    /// decision converges on the same observation while a different decision
    /// about the same pair is a distinct observation.
    #[must_use]
    pub fn observation_identity(&self) -> String {
        format!(
            "{}:{}:{}:{}",
            self.action_operation_id,
            self.record_id,
            self.rule_revision,
            self.outcome.as_str()
        )
    }

    /// The deduplication key the journal stores this observation under.
    #[must_use]
    pub fn dedup_key(&self) -> String {
        sha256_hex(self.observation_identity().as_bytes())
    }
}

/// Builds the deterministic observation submission for one gate outcome.
///
/// The event core, scope, provenance and privacy disclosure come from the
/// gated request's own retained identities, so publishing into `eliot_system`
/// stays a projection of source data rather than a copy of arbitrary project
/// contents. Retry carries identical canonical bytes, so a replay converges
/// and a changed outcome under the same identity conflicts.
fn negative_memory_gate_submission(
    operation_id: &OperationId,
    idempotency_key: &str,
    identity: &eliot_protocol::RequestIdentity,
    outcome: &NegativeMemoryGateObservation,
) -> Result<ObservationSubmission, CompositionError> {
    let fence = identity.request.metadata.state_fence.clone();
    let generation = fence.resource_generation.value().to_string();
    let work_scope =
        WorkScopeId::new(GOVERNOR_SCOPE_ID).map_err(|error| owner_refused(error.to_string()))?;
    let record = ObservationRecordEnvelope {
        record_id: format!("negative-memory-gate:{}", outcome.dedup_key()),
        kind: ObservationRecordKind::Telemetry,
        event: Some(ObservationEventCore {
            event_id_and_time: ObservationEventIdentity {
                event_id: format!("negative-memory-gate-event:{}", outcome.dedup_key()),
                clock: ClockReading::default(),
            },
            producer_generation_and_trace: ProducerTrace {
                producer: "governor-negative-memory-gate".to_owned(),
                generation,
                trace_ref: Some(outcome.read_handle.clone()),
            },
            kind: ObservationKind::FailureOrRepair,
            affected_scope: ObservationScope {
                work_scope,
                task_ref: None,
                attempt_ref: Some(outcome.action_operation_id.clone()),
                module_or_route_ref: Some("negative-memory".to_owned()),
            },
            observed_delta: format!(
                "negative-memory rule {}:{} decided operation {} effect {} as {}",
                outcome.record_id,
                outcome.rule_revision,
                outcome.action_operation_id,
                outcome.action_effect_id,
                outcome.outcome.as_str()
            ),
            expected_baseline: None,
            evidence_and_raw_handles: vec![outcome.read_handle.clone()],
            coverage_and_blind_intervals: CoverageEvidence {
                disposition: CoverageDisposition::Complete,
                denominator_source_ref: format!(
                    "negative-memory-rule-set:{}",
                    outcome.rule_set_revision
                ),
                interval: None,
                blind_intervals: Vec::new(),
                observed_count: 1,
            },
            privacy_retention_and_disclosure: PrivacyRetentionDisclosure {
                privacy_domain_ref: "governor-negative-memory".to_owned(),
                retention_policy_ref: "governor-retention".to_owned(),
                disclosure_class: "internal".to_owned(),
            },
            candidate_importance: 1,
            dedup_key: outcome.dedup_key(),
        }),
        coverage_gap: None,
        journal_control_event: false,
        parent_record_id: None,
    };
    Ok(ObservationSubmission {
        operation_id: operation_id.as_str().to_owned(),
        idempotency_key: idempotency_key.to_owned(),
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

/// Builds the observation-leg envelope for one gate outcome.
///
/// The envelope addresses the governed self scope and binds the stable
/// publication identity: the action operation, the rule identity and revision,
/// the rule-set revision, and the read handle. Required proof carries the rule
/// content digest and the read handle, both of which the decision already
/// holds, so no reference is invented here.
fn negative_memory_gate_envelope(
    identity: &eliot_protocol::RequestIdentity,
    observation_operation: &OperationId,
    submission: &ObservationSubmission,
    outcome: &NegativeMemoryGateObservation,
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
        ("action_operation_id", outcome.action_operation_id.clone()),
        ("action_effect_id", outcome.action_effect_id.clone()),
        ("action_input_digest", outcome.action_input_digest.clone()),
        ("record_id", outcome.record_id.clone()),
        ("rule_revision", outcome.rule_revision.to_string()),
        ("record_digest", outcome.record_digest.clone()),
        ("read_handle", outcome.read_handle.clone()),
        ("rule_set_revision", outcome.rule_set_revision.to_string()),
        ("outcome", outcome.outcome.as_str().to_owned()),
        ("committed_effect", outcome.committed_effect.to_string()),
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
        admission_contract_set_digest: eliot_canonical::supported_admission_contract_set_digest()?,
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
            outcome.record_digest.clone(),
            outcome.read_handle.clone(),
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
///   `DegradeDependentGuarantees`) plus an admitted `Signal
///   { disposition: ProblemCandidate }`. Severity is fixed `Info`, disposition
///   is fixed `ProblemCandidate`, and attribution stays `Suspected` — never
///   `Incident`, never a canonical `Problem`/`Incident` write, never from model
///   prose. The watchdog supplies the observation; promotion stays with the
///   authority that actually holds a `PromotionAuthority`.
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

/// Proves a gap-like entry yields a `ProblemCandidate` signal, and nothing more.
///
/// This is the whole of the watchdog's authority over a gap. A coverage gap is
/// an *observation* the watchdog supplies, not a canonical Problem and not
/// Incident authority, so no `Problem`/`Incident` record is synthesized here.
/// Doing so would have required naming an owner — the literal this function
/// used to build asserted `owner: OwnerRef { principal: GOVERNOR_SCOPE_ID }`,
/// which is the self-certification #1759 removes and which this composition
/// cannot now express anyway (see the named prerequisite in the module
/// documentation). The synthetic `Problem` proved only that the Governor's own
/// literal was well formed, and the synthetic Incident review request named a
/// `source_problem` that was never raised, which is exactly the nonexistent-ID
/// link the issue forbids.
///
/// What remains is checked against the real admitted Signal and is the
/// property the removed scratches stood in for. `PromotionAuthority` has
/// exactly two variants, `DeterministicPolicy { rule_id }` and
/// `AuthorizedHuman { decision_ref }`, and a supervision gap supplies neither:
/// its `rule_id` names the observation rule that fired, not an admitted
/// Incident policy decision, and `Suspected` attribution is by definition a
/// hypothesis rather than a finding. So the three axes are required together —
/// a `ProblemCandidate` disposition, a severity that is not
/// `IncidentCandidate`, and `Suspected` attribution — and any promotion stays
/// with the authority that actually holds one.
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
        signal_id,
        rule_id: "watchdog-spool-gap".to_owned(),
        severity: SignalSeverity::Info,
        subject: format!("watchdog spool gap sequence {}", entry.sequence),
        scope_id: GOVERNOR_SCOPE_ID.to_owned(),
        observed_at: ClockReading::default(),
        evidence_handles: vec![evidence],
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
    if signal.attribution != SignalAttribution::Suspected {
        return Err(owner_refused(
            "watchdog gap signal must stay suspected; a coverage gap is an observation, not a finding that could name an incident promotion authority"
                .to_owned(),
        ));
    }
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
        admission_contract_set_digest: eliot_canonical::supported_admission_contract_set_digest()?,
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
    /// Validates readiness plus exact fence agreement for a direct canonical
    /// capture (Watchdog spool and maintenance results).
    ///
    /// Mirrors [`Self::validate_identity_fence`] without the doctor echo: the
    /// request binding fence, the envelope metadata fence, and the canonical
    /// owner fence must coincide. No verifier endorsement applies here.
    fn validate_capture_identity_fence(
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
    ///
    /// This is also the lost-acknowledgement readback for every direct
    /// canonical capture: an identical source event queries the original
    /// receipt here instead of executing a second publication.
    async fn reconcile_capture_observation_receipt(
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
        self.validate_capture_identity_fence(identity)?;
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
                .reconcile_capture_observation_receipt(
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

    /// Appends one matched negative-memory gate outcome to the canonical
    /// observation path (issue #1731 W6).
    ///
    /// This is the existing observation path, not a second journal: the
    /// Governor builds the typed observation for the governed self scope, the
    /// Kernel checks authority, fence and identity through
    /// [`CanonicalAdmissionOwner::commit`], and the store returns its own
    /// receipt unchanged.
    ///
    /// The publication identity is derived from the **action** being gated and
    /// the **rule** that decided it, never from retry time, so an identical
    /// replay reconciles the existing receipt while a changed outcome under the
    /// same identity conflicts. A lost acknowledgement reads the original
    /// receipt back through the neutral port rather than committing again.
    ///
    /// `committed_effect` records whether the gated effect actually reached the
    /// store. It is a fact about the canonical receipt the caller already
    /// holds, never an inference from the decision.
    ///
    /// # Errors
    ///
    /// Returns [`CompositionError`] when the admitted identity, fence or
    /// operation binding does not hold, when the journal refuses the
    /// submission, or when the canonical commit cannot be completed or
    /// reconciled.
    pub async fn admit_negative_memory_gate_observation(
        &self,
        identity: &eliot_protocol::RequestIdentity,
        base_operation_id: &OperationId,
        outcome: &NegativeMemoryGateObservation,
    ) -> Result<WriteReceipt, CompositionError> {
        self.validate_capture_identity_fence(identity)?;
        let observation_operation = OperationId::new(format!(
            "{base_operation_id}/negative-memory-gate-{}",
            outcome.observation_identity()
        ))
        .map_err(|error| owner_refused(error.to_string()))?;
        let idempotency_key = format!(
            "{}:negative-memory-gate:{}",
            identity.idempotency_key,
            outcome.observation_identity()
        );
        let submission = negative_memory_gate_submission(
            &observation_operation,
            &idempotency_key,
            identity,
            outcome,
        )?;
        let mut scratch = self.observation.clone();
        match scratch
            .admit(submission.clone())
            .map_err(|error| owner_refused(error.to_string()))?
        {
            ObservationAdmissionResult::Accepted { .. }
            | ObservationAdmissionResult::Replayed { .. } => {}
            ObservationAdmissionResult::Rejected { rejection } => {
                return Err(owner_refused(format!(
                    "negative-memory gate observation is not admissible: {}",
                    rejection.all_contract_errors.join("; ")
                )));
            }
        }
        let manifest_digest = production_manifest_digest()?;
        let envelope = negative_memory_gate_envelope(
            &eliot_protocol::RequestIdentity {
                request: identity.request.clone(),
                idempotency_key: idempotency_key.clone(),
                deadline_unix_ms: identity.deadline_unix_ms,
                cancellation_id: identity.cancellation_id.clone(),
            },
            &observation_operation,
            &submission,
            outcome,
            &manifest_digest,
        )?;
        let expected_hash = envelope
            .canonical_request_hash()
            .map_err(CompositionError::Canonical)?;
        if let Some(receipt) = self
            .reconcile_capture_observation_receipt(
                identity,
                &observation_operation,
                &expected_hash,
                &manifest_digest,
            )
            .await?
        {
            return Ok(receipt);
        }
        self.commit_observation_leg(
            identity,
            &observation_operation,
            envelope,
            &expected_hash,
            &manifest_digest,
        )
        .await
    }

    /// Commits one named Problem owner transition (issue #1759 I2).
    ///
    /// This is the production entry for the nine named transitions. It adds no
    /// preparation path and no transaction API: the transition is prepared once
    /// by [`crate::prepare_problem_owner_transition`], converted to the one
    /// `PreparedTransition` by the existing envelope, and committed through
    /// [`CanonicalAdmissionOwner::commit`], the same gateway every other
    /// canonical write on this owner uses.
    ///
    /// The four bindings are compared, not carried: the source Signal is checked
    /// against the admitted fence and against the candidate's retained
    /// `signal_refs`; the verb and the candidate `record_digest` are inside the
    /// canonical request hash; the expected record revision is compared with the
    /// record here and travels as the `problem:{problem_id}` revision-head
    /// expectation the store arbitrates; and the presented
    /// [`AuthenticatedOwnerLease`](eliot_problem::AuthenticatedOwnerLease) is
    /// re-proved against the lease owner's own commitment and required to be
    /// exactly the lease identity the candidate retains.
    ///
    /// A lost commit response reconciles the original receipt through the
    /// neutral port instead of committing a second transition, so a retry of the
    /// same transition never produces a second Problem or a second escalation.
    ///
    /// The returned [`ProblemOwnerTransitionOutcome`] reports the committed
    /// candidate, the retained closure of a `Waive`/`Supersede` transition, and
    /// the store's own receipt.
    ///
    /// This entry has no caller anywhere in the tree today, and no production
    /// [`OwnerLeaseIssuer`](eliot_problem::OwnerLeaseIssuer) exists either, so
    /// no caller could present the
    /// [`AuthenticatedOwnerLease`](eliot_problem::AuthenticatedOwnerLease) this
    /// takes: every verb is type-sound here and production-unreachable until the
    /// lease owner issues one. A caller was deliberately not written, because a
    /// caller that cannot construct its own argument is not a caller.
    ///
    /// # Errors
    ///
    /// Returns [`CompositionError`] when readiness or fence agreement fails, the
    /// expected record revision does not match the committed record, the source
    /// Signal or presented authorization does not hold, the state machine refuses
    /// the verb, or the canonical commit cannot be completed or reconciled.
    ///
    /// [`CompositionError::ProblemOwnerTransitionUncommittable`] is the one
    /// refusal that is a statement about the *record* rather than about the
    /// request: the committed Problem retains no ownership-lease identity, so the
    /// store would refuse the commit under every presented lease. The caller's
    /// response is to repair that record — assign an eligible successor under a
    /// newly issued lease, or record an actually observed owner loss — and not to
    /// retry this transition, which cannot commit either way.
    pub async fn commit_problem_owner_transition(
        &self,
        request: &ProblemOwnerTransitionRequest<'_>,
    ) -> Result<ProblemOwnerTransitionOutcome, CompositionError> {
        self.validate_capture_identity_fence(request.identity)?;
        let manifest_digest = production_manifest_digest()?;
        let operation_id = request.operation_id()?;
        let prepared = prepare_problem_owner_transition(&manifest_digest, request)?;
        let expected_hash = prepared
            .envelope
            .canonical_request_hash()
            .map_err(CompositionError::Canonical)?;
        // The proactive same-operation receipt check is the lost-acknowledgement
        // readback: an identical replay returns the original receipt instead of
        // executing a second transition, and the same operation with different
        // canonical bytes fails closed here.
        let reconciled = match self.kernel.receipt(operation_id.clone()).await? {
            Some(receipt) => {
                check_receipt(
                    &receipt,
                    &operation_id,
                    &prepared.identity,
                    &expected_hash,
                    TransitionClass::RecoverySchema,
                    &manifest_digest,
                )?;
                receipt
            }
            None => {
                self.commit_problem_leg(
                    &prepared.identity,
                    &operation_id,
                    prepared.envelope,
                    &expected_hash,
                    &manifest_digest,
                )
                .await?
            }
        };
        // Only a committed receipt is a readback of committed state; a rejected
        // or unknown outcome is reported as such rather than dressed up as the
        // record having moved.
        if reconciled.status != WriteReceiptStatus::Committed {
            return Err(owner_refused(format!(
                "problem owner transition {} was not committed: {:?}",
                prepared.transition.as_str(),
                reconciled.status
            )));
        }
        Ok(ProblemOwnerTransitionOutcome {
            transition: prepared.transition,
            problem: prepared.candidate,
            closure: prepared.closure,
            receipt: reconciled,
        })
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
        let scratch = self.admit_scratch_observation(operation_id, identity, report, &binding)?;
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
        ArtifactBinding, AttemptIdentityBinding, BindingArg, DiagnosticBrief, EvaluationOutcome,
        EvidenceHandle, ExecutableBinding, IndependenceClass, IndependenceProfile,
        RegisteredOperation, RepairAttemptIdentity, RepairClass, RepairEffectIdentity,
        RepairOperationRef, RepairRecipe, RepairRecipeIdentity, RepairRecipeManifest,
        ScopeAttestation, VerificationExecution, VerificationReport, VerifierEvidence,
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
            // Issue-#18 bindings are copied exactly from the admitted
            // transition, never defaulted; equality is enforced by the
            // receipt-issuing path below.
            admission_digest: transition.admission_digest.clone(),
            mutation_plan_digest: transition.mutation_plan_digest.clone(),
            semantic_source_revisions: transition.semantic_source_revisions.clone(),
            // I5.19: bound from the admitted transition, never defaulted;
            // equality is enforced by the receipt-issuing path below.
            policy_config_schema_versions: eliot_store_api::PolicyConfigSchemaVersions::bound_to(
                transition,
            ),
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

    fn test_binding() -> ExecutableBinding {
        let binding = ExecutableBinding {
            artifact_digest: "a".repeat(64),
            program: "eliot-doctor.exe".to_owned(),
            argv: vec![BindingArg::Literal {
                value: "--version".to_owned(),
            }],
            env: BTreeMap::new(),
            timeout_ms: 5_000,
            max_stdout_bytes: 65_536,
            max_stderr_bytes: 65_536,
        };
        binding.validate().expect("test binding validates");
        binding
    }

    fn manifest() -> RepairRecipeManifest {
        let binding = test_binding();
        RepairRecipeManifest {
            manifest_id: "test-manifest".to_owned(),
            manifest_revision: 1,
            operations: vec![RegisteredOperation {
                operation_id: "test-operation".to_owned(),
                adapter_id: "test-adapter".to_owned(),
                description: "test operation".to_owned(),
                definition_digest: binding.digest(),
                binding,
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
            executable_bindings: [("test-operation".to_owned(), test_binding())]
                .into_iter()
                .collect(),
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
