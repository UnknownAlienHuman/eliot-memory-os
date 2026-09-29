//! W6 owner-verified negative-memory extinction evidence (I12.19, A14.3).
//!
//! Extinction is a governed narrowing of one admitted rule's influence. This
//! module keeps the original fingerprint immutable, requires the exact reopen
//! verifier and evidence named by that fingerprint, and appends a distinct
//! canonical receipt that links the prior and successor action policies. A
//! model score, elapsed horizon, or unbound evidence reference cannot publish
//! the narrower policy.
//!
//! Replaying the same verifier receipt for the same rule and policy revision
//! produces the same event, handle, operation ID, and idempotency key. Reusing
//! that event identity with changed content is an identity conflict at the
//! canonical write boundary.

use std::collections::BTreeSet;

use eliot_contracts::{OperationId, StateFence, sha256_hex};
use eliot_doctor_core::VerificationReport;
use eliot_dreamer_failure::{NegativeMemoryActionPolicy, NegativeMemoryDisposition};
use eliot_protocol::RequestIdentity;
use eliot_store_api::{
    EffectClass, EventProjectionRelationIntents, LearningRecordKind,
    MAX_LEARNING_RECORD_JSON_BYTES, NamedMutationRequest, OrderingHeadExpectation,
    OrderingScopeId, RevisionHeadExpectation, ScopeId, SecurityContext,
    StateFence as StoreStateFence, TransitionClass, WriteReceipt, WriteReceiptStatus,
    canonical_json_bytes,
    decode_learning_mutation, generated_operation_manifests, learning_record_commit_params,
    learning_record_mutation_request, operation_manifest_set_digest, reject_direct_learning_write,
};
use serde::Serialize;

use crate::composition::{CompositionError, GovernorComposition, KernelGenerationPort};
use crate::observation_reconciliation::{
    NegativeMemoryExtinctionObservationReceipt, doctor_fence_echo,
};

/// Wire revision of an appended extinction receipt.
const EXTINCTION_DOCUMENT_SCHEMA_VERSION: u32 = 1;
/// Stable operation namespace for one owner-verified extinction event.
const EXTINCTION_IDENTITY_DOMAIN: &str = "eliot-negative-memory-extinction-v1";
/// Closed learning-record handle prefix.
const EXTINCTION_HANDLE_PREFIX: &str = "negative-memory-extinction";
/// Shared Governor ordering scope for the source policy and observation rows.
const GOVERNOR_ORDERING_SCOPE: &str = "scope:governor";

/// The only successful outcome that may narrow an active negative-memory rule.
///
/// This closed value is produced by the owner-side reopen verifier. The
/// extinction admission rejects a rule that still applies or whose status is
/// unresolved; neither result can be interpreted as permission to narrow.
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum NegativeMemoryExtinctionOutcome {
    /// The required owner verifier established the recorded reopen condition.
    SafeToNarrow,
    /// Re-exposure confirmed that the existing restriction still applies.
    StillApplies,
    /// The verifier could not establish either safe reopening or continued
    /// applicability.
    Inconclusive,
}

/// Owner-issued evidence from evaluating one record's reopen condition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NegativeMemoryExtinctionEvidence {
    /// Exact report from the current typed Doctor verifier contract. Extinction
    /// admission re-endorses it against the reopen request fence; a caller
    /// string or model assertion cannot replace the report.
    pub verification_report: VerificationReport,
    /// Stable digest of the exact verification report, not a caller-selected
    /// receipt alias.
    pub verification_ref: String,
    /// Verifier identity named by the fingerprint's reopen condition. The
    /// evidence report must itself carry this exact identity as an evidence
    /// handle; the label alone is not accepted.
    pub verifier: String,
    /// Digest of the reopen condition the verifier evaluated.
    pub condition_digest: String,
    /// Typed result from that verifier.
    pub outcome: NegativeMemoryExtinctionOutcome,
    /// Complete evidence set required by the fingerprint's reopen condition.
    pub evidence_refs: Vec<String>,
    /// Deterministic identity of the successor policy admission, derived from
    /// its owner id, immediate revision and exact content digest.
    pub admission_ref: String,
}

/// One owner-authorized policy narrowing after exact reopen evidence.
#[derive(Clone, Debug)]
pub struct NegativeMemoryExtinctionRequest {
    /// Immutable fingerprint whose history remains in force as evidence.
    pub record: eliot_dreamer_failure::NegativeMemoryFingerprint,
    /// Currently admitted policy for the exact fingerprint revision.
    pub prior_policy: NegativeMemoryActionPolicy,
    /// Strictly narrower policy admitted by the same semantic owner.
    pub successor_policy: NegativeMemoryActionPolicy,
    /// Owner-verifier evidence for the exact reopen condition.
    pub evidence: NegativeMemoryExtinctionEvidence,
    /// Fence at which the verifier evidence and policy decision were admitted.
    pub state_fence: StateFence,
}

/// Why one extinction request cannot append a narrower policy receipt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NegativeMemoryExtinctionRefusal {
    /// The source fingerprint failed its own validator.
    RecordInvalid { detail: String },
    /// A prior or successor policy failed its own validator.
    PolicyInvalid { detail: String },
    /// A policy is not bound to the exact fingerprint revision and digest.
    PolicyBindingInvalid { policy_id: String, detail: String },
    /// The action-policy owner differs from the fingerprint's semantic owner.
    OwnerMismatch {
        policy_owner: String,
        semantic_owner: String,
    },
    /// The prior policy does not currently block or require a discriminating
    /// check, so this request has no restricting influence to extinguish.
    PriorPolicyNotRestricting,
    /// A successful reopen must narrow the policy to `RequireCheck` or
    /// `Advisory`; it cannot keep or increase the restriction.
    SuccessorPolicyNotNarrower,
    /// A narrowing policy revision must be the immediate next revision.
    PolicyRevisionNotSuccessor { expected: u64, observed: u64 },
    /// The verifier result does not authorize an extinction event.
    OutcomeDoesNotAuthorizeNarrowing {
        observed: NegativeMemoryExtinctionOutcome,
    },
    /// The evidence does not bind the fingerprint's exact reopen contract.
    EvidenceInvalid { detail: String },
    /// The State Fence failed validation.
    StateFenceInvalid { detail: String },
    /// The immutable receipt could not be canonicalized or bounded.
    DocumentInvalid { detail: String },
}

/// Checks one owner-verified extinction request before any write is built.
pub fn validate_negative_memory_extinction(
    request: &NegativeMemoryExtinctionRequest,
) -> Result<(), NegativeMemoryExtinctionRefusal> {
    request
        .record
        .validate()
        .map_err(|error| NegativeMemoryExtinctionRefusal::RecordInvalid {
            detail: error.to_string(),
        })?;
    validate_policy("prior", &request.prior_policy, &request.record)?;
    validate_policy("successor", &request.successor_policy, &request.record)?;

    let prior = &request.prior_policy;
    let successor = &request.successor_policy;
    if prior.policy_owner != request.record.semantic_owner
        || successor.policy_owner != request.record.semantic_owner
    {
        return Err(NegativeMemoryExtinctionRefusal::OwnerMismatch {
            policy_owner: if prior.policy_owner != request.record.semantic_owner {
                prior.policy_owner.clone()
            } else {
                successor.policy_owner.clone()
            },
            semantic_owner: request.record.semantic_owner.clone(),
        });
    }
    if !matches!(
        prior.disposition,
        NegativeMemoryDisposition::Block | NegativeMemoryDisposition::RequireCheck
    ) {
        return Err(NegativeMemoryExtinctionRefusal::PriorPolicyNotRestricting);
    }
    let narrows_influence = matches!(
        (prior.disposition, successor.disposition),
        (
            NegativeMemoryDisposition::Block,
            NegativeMemoryDisposition::RequireCheck | NegativeMemoryDisposition::Advisory
        ) | (
            NegativeMemoryDisposition::RequireCheck,
            NegativeMemoryDisposition::Advisory
        )
    );
    if !narrows_influence {
        return Err(NegativeMemoryExtinctionRefusal::SuccessorPolicyNotNarrower);
    }
    if prior.policy_id != successor.policy_id
        || prior.policy_owner != successor.policy_owner
        || prior.binding != successor.binding
        || prior.named_check_id != successor.named_check_id
    {
        return Err(NegativeMemoryExtinctionRefusal::PolicyInvalid {
            detail: "extinction must revise the same owner policy and exact record binding"
                .to_owned(),
        });
    }
    let expected_revision = prior.policy_revision.checked_add(1).ok_or_else(|| {
        NegativeMemoryExtinctionRefusal::PolicyRevisionNotSuccessor {
            expected: u64::MAX,
            observed: successor.policy_revision,
        }
    })?;
    if successor.policy_revision != expected_revision {
        return Err(
            NegativeMemoryExtinctionRefusal::PolicyRevisionNotSuccessor {
                expected: expected_revision,
                observed: successor.policy_revision,
            },
        );
    }
    if request.evidence.outcome != NegativeMemoryExtinctionOutcome::SafeToNarrow {
        return Err(
            NegativeMemoryExtinctionRefusal::OutcomeDoesNotAuthorizeNarrowing {
                observed: request.evidence.outcome,
            },
        );
    }
    let expected_admission_ref = negative_memory_policy_admission_ref(successor);
    if request.evidence.admission_ref != expected_admission_ref {
        return Err(NegativeMemoryExtinctionRefusal::EvidenceInvalid {
            detail: "admission reference does not bind the exact successor policy revision and digest"
                .to_owned(),
        });
    }
    validate_reopen_evidence(request)?;
    request.state_fence.validate().map_err(|error| {
        NegativeMemoryExtinctionRefusal::StateFenceInvalid {
            detail: error.to_string(),
        }
    })?;
    Ok(())
}

fn validate_policy(
    role: &'static str,
    policy: &NegativeMemoryActionPolicy,
    record: &eliot_dreamer_failure::NegativeMemoryFingerprint,
) -> Result<(), NegativeMemoryExtinctionRefusal> {
    policy
        .validate()
        .map_err(|error| NegativeMemoryExtinctionRefusal::PolicyInvalid {
            detail: format!("{role} policy: {error}"),
        })?;
    policy.validate_binding(record).map_err(|error| {
        NegativeMemoryExtinctionRefusal::PolicyBindingInvalid {
            policy_id: policy.policy_id.clone(),
            detail: error.to_string(),
        }
    })
}

fn validate_reopen_evidence(
    request: &NegativeMemoryExtinctionRequest,
) -> Result<(), NegativeMemoryExtinctionRefusal> {
    let evidence = &request.evidence;
    let reopen = &request.record.reopen;
    for (field, value) in [
        ("verification_ref", evidence.verification_ref.as_str()),
        ("verifier", evidence.verifier.as_str()),
        ("admission_ref", evidence.admission_ref.as_str()),
    ] {
        if value.trim().is_empty() || value.chars().any(char::is_control) {
            return Err(NegativeMemoryExtinctionRefusal::EvidenceInvalid {
                detail: format!("{field} must be non-blank text without control characters"),
            });
        }
    }
    if evidence.verifier != reopen.required_verifier {
        return Err(NegativeMemoryExtinctionRefusal::EvidenceInvalid {
            detail: "verifier does not equal the fingerprint's required reopen verifier".to_owned(),
        });
    }
    if evidence.condition_digest != reopen.condition_digest {
        return Err(NegativeMemoryExtinctionRefusal::EvidenceInvalid {
            detail: "evidence does not bind the fingerprint's reopen condition digest".to_owned(),
        });
    }
    evidence
        .verification_report
        .validate()
        .map_err(|error| NegativeMemoryExtinctionRefusal::EvidenceInvalid {
            detail: format!("verification report is malformed: {error}"),
        })?;
    let verifier_fence = doctor_fence_echo(&request.state_fence).map_err(|error| {
        NegativeMemoryExtinctionRefusal::EvidenceInvalid {
            detail: format!("verification fence binding is unavailable: {error}"),
        }
    })?;
    evidence
        .verification_report
        .endorse(&verifier_fence)
        .map_err(|_| NegativeMemoryExtinctionRefusal::EvidenceInvalid {
            detail: "reopen evidence is not independently verified under the exact request fence"
                .to_owned(),
        })?;
    let report_refs: BTreeSet<&str> = evidence
        .verification_report
        .evidence
        .evidence
        .iter()
        .map(|handle| handle.reference.as_str())
        .collect();
    let claimed_refs: BTreeSet<&str> = evidence.evidence_refs.iter().map(String::as_str).collect();
    if report_refs != claimed_refs {
        return Err(NegativeMemoryExtinctionRefusal::EvidenceInvalid {
            detail: "evidence references must exactly match the endorsed verifier report"
                .to_owned(),
        });
    }
    let required: BTreeSet<&str> = reopen
        .required_evidence_refs
        .iter()
        .map(String::as_str)
        .collect();
    if claimed_refs != required {
        return Err(NegativeMemoryExtinctionRefusal::EvidenceInvalid {
            detail: "endorsed report must exactly cover the reopen condition's required evidence set"
                .to_owned(),
        });
    }
    if !report_refs.contains(reopen.required_verifier.as_str()) {
        return Err(NegativeMemoryExtinctionRefusal::EvidenceInvalid {
            detail: "endorsed verifier evidence does not name the exact required reopen verifier"
                .to_owned(),
        });
    }
    if !evidence
        .verification_report
        .evidence
        .evidence
        .iter()
        .any(|handle| handle.digest == reopen.condition_digest)
    {
        return Err(NegativeMemoryExtinctionRefusal::EvidenceInvalid {
            detail: "endorsed verifier evidence does not bind the exact reopen condition digest"
                .to_owned(),
        });
    }
    let report_bytes = canonical_json_bytes(&evidence.verification_report).map_err(|error| {
        NegativeMemoryExtinctionRefusal::EvidenceInvalid {
            detail: format!("verification report cannot be canonicalized: {error}"),
        }
    })?;
    let verification_report_digest = sha256_hex(&report_bytes);
    if evidence.verification_ref != verification_report_digest {
        return Err(NegativeMemoryExtinctionRefusal::EvidenceInvalid {
            detail: "verification reference is not the digest of the endorsed report".to_owned(),
        });
    }
    let mut observed = BTreeSet::new();
    for reference in &evidence.evidence_refs {
        if reference.trim().is_empty()
            || reference.chars().any(char::is_control)
            || !observed.insert(reference.as_str())
        {
            return Err(NegativeMemoryExtinctionRefusal::EvidenceInvalid {
                detail: "evidence references must be non-blank, control-free and unique".to_owned(),
            });
        }
    }
    let required: BTreeSet<&str> = reopen
        .required_evidence_refs
        .iter()
        .map(String::as_str)
        .collect();
    if observed != required {
        return Err(NegativeMemoryExtinctionRefusal::EvidenceInvalid {
            detail: "evidence references must exactly cover the reopen condition's required set"
                .to_owned(),
        });
    }
    Ok(())
}

#[derive(Serialize)]
struct ExtinctionIdentityPreimage<'a> {
    domain: &'static str,
    record_id: &'a str,
    rule_revision: u64,
    record_digest: &'a str,
    policy_id: &'a str,
    prior_policy_revision: u64,
    prior_policy_digest: &'a str,
    successor_policy_revision: u64,
    verification_ref: &'a str,
    state_fence: &'a StateFence,
}

/// Returns the stable identity used for both event deduplication and writes.
pub fn negative_memory_extinction_event_id(
    request: &NegativeMemoryExtinctionRequest,
) -> Result<String, NegativeMemoryExtinctionRefusal> {
    validate_negative_memory_extinction(request)?;
    let preimage = ExtinctionIdentityPreimage {
        domain: EXTINCTION_IDENTITY_DOMAIN,
        record_id: &request.record.record_id,
        rule_revision: request.record.rule_revision,
        record_digest: &request.record.record_digest,
        policy_id: &request.prior_policy.policy_id,
        prior_policy_revision: request.prior_policy.policy_revision,
        prior_policy_digest: &request.prior_policy.policy_digest,
        successor_policy_revision: request.successor_policy.policy_revision,
        verification_ref: &request.evidence.verification_ref,
        state_fence: &request.state_fence,
    };
    let bytes = canonical_json_bytes(&preimage).map_err(|error| {
        NegativeMemoryExtinctionRefusal::DocumentInvalid {
            detail: format!("event identity: {error}"),
        }
    })?;
    Ok(sha256_hex(&bytes))
}

/// Immutable canonical payload appended for one successful narrowing.
#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct NegativeMemoryExtinctionDocument {
    /// Wire revision of this receipt.
    pub schema_version: u32,
    /// Stable event identity; exact verifier replays retain it.
    pub event_id: String,
    /// Fingerprint identity retained as historical evidence.
    pub record_id: String,
    /// Exact fingerprint revision retained as historical evidence.
    pub rule_revision: u64,
    /// Exact fingerprint digest retained as historical evidence.
    pub record_digest: String,
    /// Previously admitted restricting policy.
    pub prior_policy: NegativeMemoryActionPolicy,
    /// Owner-admitted strictly narrower successor policy.
    pub successor_policy: NegativeMemoryActionPolicy,
    /// Owner-verified reopen result.
    pub outcome: NegativeMemoryExtinctionOutcome,
    /// Exact reopen condition digest that was evaluated.
    pub condition_digest: String,
    /// Owner verifier named by the reopen condition.
    pub verifier: String,
    /// Stable identity of the owner's verification receipt.
    pub verification_ref: String,
    /// Complete evidence references required by the reopen condition.
    pub evidence_refs: Vec<String>,
    /// Owner-issued admission reference for the narrower policy.
    pub admission_ref: String,
    /// Fence at which the verification and narrowing were admitted.
    pub state_fence: StateFence,
}

impl NegativeMemoryExtinctionDocument {
    /// Digest over the exact canonical receipt bytes.
    pub fn document_digest(&self) -> Result<String, NegativeMemoryExtinctionRefusal> {
        let bytes = canonical_json_bytes(self).map_err(|error| {
            NegativeMemoryExtinctionRefusal::DocumentInvalid {
                detail: error.to_string(),
            }
        })?;
        Ok(sha256_hex(&bytes))
    }
}

fn extinction_document(
    request: &NegativeMemoryExtinctionRequest,
) -> Result<NegativeMemoryExtinctionDocument, NegativeMemoryExtinctionRefusal> {
    let event_id = negative_memory_extinction_event_id(request)?;
    Ok(NegativeMemoryExtinctionDocument {
        schema_version: EXTINCTION_DOCUMENT_SCHEMA_VERSION,
        event_id,
        record_id: request.record.record_id.clone(),
        rule_revision: request.record.rule_revision,
        record_digest: request.record.record_digest.clone(),
        prior_policy: request.prior_policy.clone(),
        successor_policy: request.successor_policy.clone(),
        outcome: request.evidence.outcome,
        condition_digest: request.evidence.condition_digest.clone(),
        verifier: request.evidence.verifier.clone(),
        verification_ref: request.evidence.verification_ref.clone(),
        evidence_refs: request.evidence.evidence_refs.clone(),
        admission_ref: request.evidence.admission_ref.clone(),
        state_fence: request.state_fence.clone(),
    })
}

/// Builds the closed named mutation for one extinction receipt.
///
/// The deterministic idempotency key is derived from the record, policy
/// revision, verifier receipt and State Fence. The store accepts only the new
/// closed kind through `RecordLearningRecord`; it does not reinterpret the
/// extinction document.
pub fn negative_memory_extinction_mutation_request(
    request: &NegativeMemoryExtinctionRequest,
    scope_digest: &str,
    fence_digest: &str,
) -> Result<(NamedMutationRequest, NegativeMemoryExtinctionDocument), NegativeMemoryExtinctionRefusal>
{
    validate_learning_scope_and_fence_digests(request, scope_digest, fence_digest)?;
    let document = extinction_document(request)?;
    let bytes = canonical_json_bytes(&document).map_err(|error| {
        NegativeMemoryExtinctionRefusal::DocumentInvalid {
            detail: error.to_string(),
        }
    })?;
    if bytes.len() > MAX_LEARNING_RECORD_JSON_BYTES {
        return Err(NegativeMemoryExtinctionRefusal::DocumentInvalid {
            detail: "extinction receipt exceeds the bounded learning-record length".to_owned(),
        });
    }
    let record_json = String::from_utf8(bytes).map_err(|error| {
        NegativeMemoryExtinctionRefusal::DocumentInvalid {
            detail: format!("extinction receipt is not UTF-8: {error}"),
        }
    })?;
    let record_digest = sha256_hex(record_json.as_bytes());
    let handle = format!("{EXTINCTION_HANDLE_PREFIX}:{}", document.event_id);
    let idempotency_key = handle.clone();
    let mutation = learning_record_mutation_request(learning_record_commit_params(
        LearningRecordKind::NegativeMemoryExtinctionReceipt,
        handle,
        record_json,
        record_digest,
        scope_digest.to_owned(),
        fence_digest.to_owned(),
        idempotency_key,
    ));
    reject_direct_learning_write(&mutation).map_err(|error| {
        NegativeMemoryExtinctionRefusal::DocumentInvalid {
            detail: format!("extinction commit guard: {error}"),
        }
    })?;
    Ok((mutation, document))
}

/// Checks the caller-carried learning owner digests against the exact values
/// admitted by the extinction request. The store keeps these refs opaque; the
/// Governor binds them before constructing the named mutation.
fn validate_learning_scope_and_fence_digests(
    request: &NegativeMemoryExtinctionRequest,
    scope_digest: &str,
    fence_digest: &str,
) -> Result<(), NegativeMemoryExtinctionRefusal> {
    let expected_scope_digest = sha256_hex(
        &canonical_json_bytes(&request.record.affected).map_err(|error| {
            NegativeMemoryExtinctionRefusal::EvidenceInvalid {
                detail: format!("recorded affected scope cannot be canonicalized: {error}"),
            }
        })?,
    );
    if scope_digest != expected_scope_digest {
        return Err(NegativeMemoryExtinctionRefusal::EvidenceInvalid {
            detail: "learning scope digest does not bind the record's exact affected scope"
                .to_owned(),
        });
    }
    let expected_fence_digest = sha256_hex(
        &canonical_json_bytes(&request.state_fence).map_err(|error| {
            NegativeMemoryExtinctionRefusal::StateFenceInvalid {
                detail: format!("request State Fence cannot be canonicalized: {error}"),
            }
        })?,
    );
    if fence_digest != expected_fence_digest {
        return Err(NegativeMemoryExtinctionRefusal::StateFenceInvalid {
            detail: "learning fence digest does not bind the request State Fence".to_owned(),
        });
    }
    Ok(())
}

fn governor_ordering_head_expectation(
    expected_ordering_heads: &[OrderingHeadExpectation],
    state_fence: &StoreStateFence,
) -> Result<OrderingHeadExpectation, CompositionError> {
    let governor_scope = OrderingScopeId::new(GOVERNOR_ORDERING_SCOPE)
        .map_err(|error| extinction_owner_error(error.to_string()))?;
    let mut matching = expected_ordering_heads
        .iter()
        .filter(|head| head.scope == governor_scope);
    let expected = matching.next().ok_or_else(|| {
        extinction_owner_error("extinction CAS omits the scope:governor ordering head")
    })?;
    if matching.next().is_some() {
        return Err(extinction_owner_error(
            "extinction CAS duplicates the scope:governor ordering head",
        ));
    }
    expected
        .validate()
        .map_err(|error| extinction_owner_error(format!("governor ordering head: {error}")))?;
    if expected.state_fence != *state_fence {
        return Err(extinction_owner_error(
            "scope:governor ordering head fence does not match the request fence",
        ));
    }
    Ok(expected.clone())
}

/// Receipt returned after the extinction event reaches the canonical writer.
#[derive(Clone, Debug)]
pub struct NegativeMemoryExtinctionReceipt {
    /// Stable identity of the verifier event.
    pub event_id: String,
    /// Operation identity used at the canonical writer.
    pub operation_id: OperationId,
    /// Exact fingerprint identity whose influence was narrowed.
    pub record_id: String,
    /// Exact historical fingerprint revision retained.
    pub rule_revision: u64,
    /// Prior and successor policy revisions committed in the receipt.
    pub prior_policy_revision: u64,
    /// Successor policy revision committed in the receipt.
    pub successor_policy_revision: u64,
    /// Compare-and-swap revision heads supplied by the owner.
    pub expected_revision_heads: Vec<RevisionHeadExpectation>,
    /// Canonical immutable write receipt.
    pub store_write_receipt: WriteReceipt,
    /// Canonical observation receipt for the confirmed false activation.
    pub false_activation_observation: NegativeMemoryExtinctionObservationReceipt,
}

/// Commits one verified narrowing through the governed canonical write seam.
#[allow(
    clippy::too_many_arguments,
    reason = "the owner supplies every input required to bind one canonical extinction receipt"
)]
pub async fn commit_negative_memory_extinction<P: KernelGenerationPort + ?Sized>(
    composition: &GovernorComposition<P>,
    identity: &RequestIdentity,
    request: &NegativeMemoryExtinctionRequest,
    scope_id: ScopeId,
    scope_digest: &str,
    fence_digest: &str,
    proof_refs: Vec<String>,
    expected_revision_heads: Vec<RevisionHeadExpectation>,
    expected_ordering_heads: Vec<OrderingHeadExpectation>,
) -> Result<NegativeMemoryExtinctionReceipt, CompositionError> {
    validate_negative_memory_extinction(request).map_err(extinction_owner_error)?;
    identity
        .validate()
        .map_err(|error| extinction_owner_error(format!("request identity: {error}")))?;
    let envelope_fence = identity.request.metadata.state_fence.clone();
    if request.state_fence != envelope_fence {
        return Err(extinction_owner_error(
            "extinction evidence State Fence does not match the canonical request fence",
        ));
    }
    if scope_id.as_str() != request.record.affected.scope_id.as_str() {
        return Err(extinction_owner_error(
            "extinction scope id does not match the fingerprint's exact affected scope",
        ));
    }
    if expected_revision_heads.is_empty() {
        return Err(extinction_owner_error(
            "extinction append requires an owner-read revision head",
        ));
    }
    // The current canonical planner emits a revision delta only for the
    // transition scope. Reject other requested keys before commit so a
    // successful write cannot become an unacknowledged error when the
    // post-commit receipt cannot prove those heads.
    let canonical_scope_revision_key = format!("scope:{}", scope_id.as_str());
    if expected_revision_heads.len() != 1
        || expected_revision_heads[0].key.as_str() != canonical_scope_revision_key.as_str()
    {
        return Err(extinction_owner_error(
            "extinction CAS must name exactly the canonical transition-scope revision head",
        ));
    }
    for expected in &expected_revision_heads {
        expected
            .validate()
            .map_err(|error| extinction_owner_error(format!("revision head: {error}")))?;
        if expected.state_fence != envelope_fence {
            return Err(extinction_owner_error(
                "extinction revision head fence does not match the request fence",
            ));
        }
    }
    for expected in &expected_ordering_heads {
        expected
            .validate()
            .map_err(|error| extinction_owner_error(format!("ordering head: {error}")))?;
        if expected.state_fence != envelope_fence {
            return Err(extinction_owner_error(
                "extinction ordering head fence does not match the request fence",
            ));
        }
    }
    governor_ordering_head_expectation(&expected_ordering_heads, &envelope_fence)?;

    let (mutation, document) =
        negative_memory_extinction_mutation_request(request, scope_digest, fence_digest)
            .map_err(extinction_owner_error)?;
    let decoded = decode_learning_mutation(mutation.operation, &mutation.parameters)
        .map_err(|error| extinction_owner_error(format!("extinction parameters: {error}")))?;
    let expected_idempotency_key = format!("{EXTINCTION_HANDLE_PREFIX}:{}", document.event_id);
    if decoded.record_kind != LearningRecordKind::NegativeMemoryExtinctionReceipt
        || decoded.handle != expected_idempotency_key
        || decoded.idempotency_key != expected_idempotency_key
    {
        return Err(extinction_owner_error(
            "extinction mutation does not match its deterministic event identity",
        ));
    }
    let operation_id =
        OperationId::new(format!("{EXTINCTION_HANDLE_PREFIX}:{}", document.event_id)).map_err(
            |error| extinction_owner_error(format!("extinction operation identity: {error}")),
        )?;
    let manifest_digest =
        operation_manifest_set_digest(&generated_operation_manifests().map_err(|error| {
            extinction_owner_error(format!("operation manifest set unavailable: {error}"))
        })?)
        .map_err(|error| extinction_owner_error(format!("operation manifest digest: {error}")))?;
    let envelope = eliot_canonical::CanonicalWriteEnvelope {
        operation_id: operation_id.clone(),
        request: identity.request.metadata.clone(),
        idempotency_key: decoded.idempotency_key.clone(),
        scope_id: scope_id.clone(),
        task_id: None,
        transition_class: TransitionClass::CaptureCandidate,
        requested_effect_ceiling: EffectClass::Candidate,
        admission_contract_set_digest: document
            .document_digest()
            .map_err(extinction_owner_error)?,
        operation_manifest_digest: manifest_digest,
        semantic_commands: vec![mutation],
        event_projection_relation_intents: EventProjectionRelationIntents {
            event_ids: Vec::new(),
            projection_kinds: Vec::new(),
            relation_kinds: Vec::new(),
        },
        security: SecurityContext::default(),
        required_proof_and_approval_refs: proof_refs,
        expected_revision_heads: expected_revision_heads.clone(),
        expected_ordering_heads: expected_ordering_heads.clone(),
    };
    let expected_hash = envelope
        .canonical_request_hash()
        .map_err(CompositionError::Canonical)?;
    let receipt = composition
        .observation_reconciliation()
        .commit_negative_memory_receipt(
            identity,
            &operation_id,
            envelope,
            &expected_hash,
            &manifest_digest,
        )
        .await?;
    check_extinction_commit_freshness(
        &receipt,
        &operation_id,
        &decoded.idempotency_key,
        &envelope_fence,
        &expected_revision_heads,
        &expected_ordering_heads,
    )?;
    let false_activation_observation = composition
        .observation_reconciliation()
        .admit_negative_memory_false_activation(
            identity,
            &operation_id,
            &scope_id,
            request,
            &document,
            &receipt,
        )
        .await?;
    Ok(NegativeMemoryExtinctionReceipt {
        event_id: document.event_id,
        operation_id,
        record_id: document.record_id,
        rule_revision: document.rule_revision,
        prior_policy_revision: document.prior_policy.policy_revision,
        successor_policy_revision: document.successor_policy.policy_revision,
        expected_revision_heads,
        store_write_receipt: receipt,
        false_activation_observation,
    })
}

fn extinction_owner_error(error: impl std::fmt::Display) -> CompositionError {
    CompositionError::Owner(format!("negative-memory extinction: {error}"))
}

/// Stable admission handle derived from the exact owner-issued successor
/// policy. It is an identity reference, not a caller-provided authority token.
pub fn negative_memory_policy_admission_ref(policy: &NegativeMemoryActionPolicy) -> String {
    format!(
        "negative-memory-policy-admission:{}:{}:{}",
        policy.policy_id, policy.policy_revision, policy.policy_digest
    )
}

fn check_extinction_commit_freshness(
    receipt: &WriteReceipt,
    operation_id: &OperationId,
    idempotency_key: &str,
    envelope_fence: &StoreStateFence,
    expected_revision_heads: &[RevisionHeadExpectation],
    expected_ordering_heads: &[OrderingHeadExpectation],
) -> Result<(), CompositionError> {
    receipt
        .validate()
        .map_err(|error| extinction_owner_error(format!("write receipt invalid: {error}")))?;
    if receipt.status != WriteReceiptStatus::Committed {
        return Err(extinction_owner_error(
            "extinction receipt is not committed; stale projection refused",
        ));
    }
    if receipt.operation_id != *operation_id || receipt.idempotency_key != idempotency_key {
        return Err(extinction_owner_error(
            "write receipt identity does not match the extinction operation",
        ));
    }
    if receipt.state_fence != *envelope_fence {
        return Err(extinction_owner_error(
            "write receipt fence does not match the committed envelope fence",
        ));
    }
    for expected in expected_revision_heads {
        let mut matching_deltas = receipt
            .revision_before_after
            .iter()
            .filter(|delta| delta.key == expected.key);
        let delta = matching_deltas.next().ok_or_else(|| {
            extinction_owner_error(format!(
                "write receipt omitted expected revision head {}",
                expected.key.as_str(),
            ))
        })?;
        if matching_deltas.next().is_some() {
            return Err(extinction_owner_error(format!(
                "write receipt duplicated expected revision head {}",
                expected.key.as_str(),
            )));
        }
        if delta.before != expected.expected_revision {
            return Err(extinction_owner_error(format!(
                "write receipt revision is stale for {}: expected base {}, observed {}",
                expected.key.as_str(),
                expected.expected_revision,
                delta.before,
            )));
        }
        let expected_successor = expected.expected_revision.checked_add(1).ok_or_else(|| {
            extinction_owner_error(format!(
                "expected revision head {} cannot advance beyond u64::MAX",
                expected.key.as_str(),
            ))
        })?;
        if delta.after != expected_successor {
            return Err(extinction_owner_error(format!(
                "write receipt revision did not append the immediate successor for {}: expected {}, observed {}",
                expected.key.as_str(),
                expected_successor,
                delta.after,
            )));
        }
    }
    for expected in expected_ordering_heads {
        let mut matching_heads = receipt
            .ordering_sequences
            .iter()
            .filter(|head| head.scope == expected.scope);
        let head = matching_heads.next().ok_or_else(|| {
            extinction_owner_error(format!(
                "write receipt omitted expected ordering scope {}",
                expected.scope.as_str(),
            ))
        })?;
        if matching_heads.next().is_some() {
            return Err(extinction_owner_error(format!(
                "write receipt duplicated expected ordering scope {}",
                expected.scope.as_str(),
            )));
        }
        head.validate().map_err(|error| {
            extinction_owner_error(format!("write receipt ordering head: {error}"))
        })?;
        if head.state_fence != *envelope_fence {
            return Err(extinction_owner_error(format!(
                "write receipt ordering fence does not match the committed envelope for {}",
                expected.scope.as_str(),
            )));
        }
        let expected_successor = expected.expected_sequence.checked_add(1).ok_or_else(|| {
            extinction_owner_error(format!(
                "expected ordering scope {} cannot advance beyond u64::MAX",
                expected.scope.as_str(),
            ))
        })?;
        if head.sequence != expected_successor {
            return Err(extinction_owner_error(format!(
                "write receipt ordering did not advance exactly once for {}: expected {}, observed {}",
                expected.scope.as_str(),
                expected_successor,
                head.sequence,
            )));
        }
    }
    Ok(())
}
