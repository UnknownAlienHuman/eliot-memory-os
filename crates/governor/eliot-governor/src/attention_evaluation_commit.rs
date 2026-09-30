//! Governor-owned Human-attention-evaluation persist leg (issue #1784, I11.10).
//!
//! This module is the canonical transition/readback half of item W5: a closed
//! authorized operator request for creation, correction, and invalidation of a
//! [`HumanAttentionEvaluation`](eliot_evaluation_contracts::HumanAttentionEvaluation),
//! with expected revision, deterministic operation identity, exact evidence
//! commitment, receipt/readback verification, replay-same/conflict-changed
//! reconciliation, and lost-acknowledgement recovery. It mints no authority,
//! keeps no ledger, and deletes nothing.
//!
//! Ownership split (issue #1784): the evaluation-contracts crate owns the
//! record shape and structural validation; the Governor evaluation producer
//! (sibling W3/W4 work) assembles candidate records from bounded owner reads;
//! this module admits an already-assembled record onto the persist path; the
//! Kernel checks current authority/fence and mediates persistence; the Store
//! commits canonical rows. Notification/approval state keeps its existing
//! owner: nothing here resolves a Problem, grants an approval, or changes
//! policy, and invalidation never rewrites notification/approval history.
//!
//! Request/identity binding (I11.8 posture): the caller presents an admitted
//! [`RequestIdentity`](eliot_protocol::RequestIdentity) plus the principal and
//! session the owning surface authenticated. This module checks shape and
//! agreement only — identity validity, session equality with the request
//! metadata, idempotency-key agreement between caller and named request, a
//! non-blank principal claim, and principal agreement with the record-bound
//! evaluator (a stale or foreign operator principal fails here). Role/
//! authority truth stays with the owning surface; a stale or foreign role is
//! refused downstream by the Kernel fence and admission checks, never granted
//! here.
//!
//! Operation identity and evidence commitment: the operation id derives
//! deterministically as `attention-evaluation:{evaluation_id}:{revision}`
//! (stable across retries, unique per revision); the idempotency key binds the
//! same coordinates plus the exact record digest; the evidence commitment is
//! the SHA-256 over the canonical bytes of the record's evidence manifest and
//! must equal the commitment recomputed from the presented record. Same
//! identity with identical bytes replays to the original receipt; the same
//! identity with different bytes is an identity conflict that commits nothing
//! (see [`resolve_attention_lost_acknowledgement`]).
//!
//! Revision discipline: creation opens revision one with no predecessor;
//! correction appends the immediately following revision linked to its
//! predecessor (content may change; the link must not); invalidation appends
//! the immediately following revision carrying the invalidation statement with
//! every other byte identical to the invalidated revision. History is
//! append-only: there is no delete operation, and invalidation removes current
//! applicability while retaining the record.
//!
//! Unknown preservation (item A5): this layer performs no transform, default,
//! or aggregation over metric values — digests cover the exact producer bytes,
//! and [`verify_attention_evaluation_readback`] re-proves the digest after the
//! Store round trip, so a substituted zero or dropped unknown fails the digest
//! instead of surfacing as observed harm data. [`attention_unknown_summary`]
//! reports observed/unknown/not-applicable counts per I11.10 group for honest
//! display; it never ranks profiles.
//!
//! Store seam status: the prepared-envelope assembly and the closed named
//! Store operation for attention evaluations land with the Store leg (new
//! operation plus memory/Surreal handlers); until then there is no second
//! path — no UI database, no Notify-local ledger, no experience-bank
//! aliasing. The derived identities, commitments, receipt checks, and
//! readback verification in this module are the stable contract that Store leg
//! must reuse byte-for-byte.
//!
//! Production caller status: the sibling Governor producer (W3/W4) supplies
//! assembled records; the Store-leg binder supplies the commit invocation.
//! No caller is wired here; every function is complete and independently
//! checkable.
//!
//! Fail-closed order in [`validate_attention_evaluation_request`]: record
//! structural validity, caller identity validity, revision/operation/
//! predecessor agreement, operation-identity agreement, evidence-commitment
//! agreement, idempotency agreement, session agreement, principal shape and
//! evaluator agreement.

#![forbid(unsafe_code)]

use eliot_contracts::{
    ArtifactId, ContractId, OperationId, SessionId, StateFence, canonical_json_bytes, sha256_hex,
};
use eliot_evaluation_contracts::{
    HumanAttentionEvaluation, HumanAttentionEvaluationRevisionRef, HumanAttentionMetricGroup,
    HumanAttentionMetricValue,
};
use eliot_protocol::RequestIdentity;
use eliot_store_api::{
    OrderingHeadExpectation, RevisionHeadExpectation, WriteReceipt, WriteReceiptStatus,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Stable operation-identity prefix for attention-evaluation persist operations.
pub const ATTENTION_EVALUATION_OPERATION_PREFIX: &str = "attention-evaluation";

/// Fail-closed errors for the attention-evaluation persist leg.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum AttentionEvaluationCommitError {
    /// The evaluation record itself is structurally invalid.
    #[error("attention evaluation record refused: {0}")]
    Record(String),
    /// The caller identity, session, principal, or idempotency binding is refused.
    #[error("attention evaluation operator identity refused: {0}")]
    Identity(String),
    /// The requested operation or presented operation identity is refused.
    #[error("attention evaluation operation refused: {0}")]
    Operation(String),
    /// The presented evidence commitment does not match the record manifest.
    #[error("attention evaluation evidence commitment refused: {0}")]
    Evidence(String),
    /// The expected revision or predecessor linkage is refused.
    #[error("attention evaluation revision linkage refused: {0}")]
    Revision(String),
    /// The same operation identity carries different bytes than committed.
    #[error("attention evaluation replay conflicts with the committed revision: {0}")]
    Replay(String),
    /// The Store-issued receipt is invalid, stale, or foreign.
    #[error("attention evaluation commit receipt refused: {0}")]
    Receipt(String),
    /// Record bytes could not be serialized or parsed.
    #[error("attention evaluation serialization refused: {0}")]
    Serialization(String),
}

/// Closed persist operation over one evaluation revision. There is deliberately
/// no delete variant: invalidation removes current applicability while the
/// revision history is retained.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum AttentionEvaluationOperation {
    /// Open revision one of a new evaluation with no predecessor.
    Create,
    /// Append the next linked revision; content may change, the link must not.
    Correct,
    /// Append the next linked revision carrying the invalidation statement
    /// with every other byte identical to the invalidated revision.
    Invalidate,
}

/// Closed authorized operator request to persist one evaluation revision.
///
/// The record bytes themselves travel as the already-assembled
/// [`HumanAttentionEvaluation`](eliot_evaluation_contracts::HumanAttentionEvaluation)
/// alongside this request (mirroring the learning-record commit shape); every
/// field here is re-derived from that record during validation and must agree
/// exactly.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttentionEvaluationOperatorRequest {
    /// Which persist operation this request performs.
    pub operation: AttentionEvaluationOperation,
    /// Evaluation identity this request addresses.
    pub evaluation_id: ContractId,
    /// Revision this request persists; must equal the record revision.
    pub expected_revision: u64,
    /// Presented operation identity; must equal the derived
    /// `attention-evaluation:{evaluation_id}:{revision}`.
    pub operation_id: OperationId,
    /// Presented idempotency key; must equal the derived key and the caller
    /// identity key.
    pub idempotency_key: String,
    /// Presented evidence commitment; must equal the SHA-256 over the
    /// canonical bytes of the record's evidence manifest.
    pub evidence_commitment: String,
    /// Authenticated principal claim: non-blank text agreeing with the
    /// record-bound evaluator principal. Authority truth stays with the
    /// owning surface.
    pub principal_id: String,
    /// Authenticated session claim; must equal the session bound in the
    /// caller request metadata.
    pub session_id: SessionId,
}

/// Derived commit identity returned by request validation.
///
/// The Store-leg binder carries these exact values into the prepared
/// transition; the receipt checks compare against them.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AttentionEvaluationCommitIdentity {
    /// Deterministic operation identity for this revision.
    pub operation_id: OperationId,
    /// SHA-256 over the canonical bytes of the exact record revision.
    pub record_digest: String,
    /// SHA-256 over the canonical bytes of the record's evidence manifest.
    pub evidence_commitment: String,
    /// Deterministic idempotency key for this revision bytes.
    pub idempotency_key: String,
}

/// Current-applicability verdict for a persisted revision.
///
/// Expiry is evaluated against a caller-supplied observation instant so this
/// stays pure: unknown expiry timing never silently passes and never silently
/// fails.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttentionEvaluationValidity {
    /// Usable for current tuning and citation.
    Current,
    /// Past its declared expiry; retained for history, unusable for current use.
    Expired,
    /// Invalidated with reason and affected scope; retained for history,
    /// unusable for current use.
    Invalidated {
        /// Why the revision was invalidated.
        reason: String,
        /// Scope, evidence, or policy coordinates the invalidation covers.
        affected_scope_refs: Vec<String>,
    },
}

/// Observed/unknown/not-applicable counts for one I11.10 metric group.
///
/// Counts are denominators for honest display, never inputs to a ranking: a
/// profile with fewer notifications but more missed critical harm is not
/// superior, and these counts cannot say otherwise.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AttentionMetricGroupStatus {
    /// I11.10 group field name.
    pub group: &'static str,
    /// Metrics with an observed value.
    pub observed: u64,
    /// Metrics with an explicit unknown (missing follow-up or collection).
    pub unknown: u64,
    /// Metrics explicitly not applicable.
    pub not_applicable: u64,
}

/// Observed/unknown/not-applicable counts over all ten I11.10 metric groups.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AttentionUnknownSummary {
    /// Per-group counts in I11.10 field order.
    pub groups: Vec<AttentionMetricGroupStatus>,
    /// Total observed metrics across groups.
    pub observed: u64,
    /// Total explicit unknowns across groups; missing follow-up stays here
    /// and is never zero-filled into harm data.
    pub unknown: u64,
    /// Total not-applicable metrics across groups.
    pub not_applicable: u64,
}

/// Derives the deterministic operation identity for one evaluation revision.
///
/// The identity is stable across retries and unique per revision: the same
/// identity with identical bytes replays, with different bytes conflicts.
pub fn attention_evaluation_operation_id(
    evaluation_id: &ContractId,
    revision: u64,
) -> Result<OperationId, AttentionEvaluationCommitError> {
    OperationId::new(format!(
        "{ATTENTION_EVALUATION_OPERATION_PREFIX}:{}:{revision}",
        evaluation_id.as_str(),
    ))
    .map_err(|error| AttentionEvaluationCommitError::Operation(error.to_string()))
}

/// Computes the SHA-256 over the canonical bytes of one exact record revision.
///
/// The digest IS the immutable revision identity: any substitution — including
/// a zero written where the producer recorded unknown — changes the digest.
pub fn attention_record_digest(
    record: &HumanAttentionEvaluation,
) -> Result<String, AttentionEvaluationCommitError> {
    let bytes = canonical_json_bytes(record)
        .map_err(|error| AttentionEvaluationCommitError::Serialization(error.to_string()))?;
    Ok(sha256_hex(&bytes))
}

/// Computes the exact evidence commitment over the record's evidence manifest.
///
/// The commitment binds precisely the evidence the record may cite; foreign
/// evidence expansion against any other set fails.
pub fn attention_evidence_commitment(
    record: &HumanAttentionEvaluation,
) -> Result<String, AttentionEvaluationCommitError> {
    let bytes = canonical_json_bytes(&record.evidence_manifest)
        .map_err(|error| AttentionEvaluationCommitError::Serialization(error.to_string()))?;
    Ok(sha256_hex(&bytes))
}

/// Derives the deterministic idempotency key for one exact revision bytes.
///
/// Stable across retries of the same bytes; distinct bytes yield a distinct
/// key, so a changed-content retry under the same operation identity is
/// detectable at the receipt rather than silently convergent.
#[must_use]
pub fn attention_evaluation_idempotency_key(
    evaluation_id: &ContractId,
    revision: u64,
    record_digest: &str,
) -> String {
    format!(
        "{ATTENTION_EVALUATION_OPERATION_PREFIX}:{}:{revision}:{record_digest}",
        evaluation_id.as_str(),
    )
}

/// Validates a closed authorized operator request against its record revision.
///
/// Fail-closed order: record validity, caller identity validity,
/// revision/operation/predecessor agreement, operation-identity agreement,
/// evidence-commitment agreement, idempotency agreement, session agreement,
/// principal shape and evaluator agreement. Returns the derived commit
/// identity the Store-leg binder must carry into the prepared transition.
/// Foreign evidence cannot reach this gate: the record validator already
/// refuses references absent from the evidence manifest, and the commitment
/// agreement above re-binds the exact manifest bytes.
pub fn validate_attention_evaluation_request(
    record: &HumanAttentionEvaluation,
    prior: Option<&HumanAttentionEvaluation>,
    request: &AttentionEvaluationOperatorRequest,
    identity: &RequestIdentity,
) -> Result<AttentionEvaluationCommitIdentity, AttentionEvaluationCommitError> {
    record
        .validate()
        .map_err(|error| AttentionEvaluationCommitError::Record(error.to_string()))?;
    identity
        .validate()
        .map_err(|error| AttentionEvaluationCommitError::Identity(error.to_string()))?;
    if request.expected_revision == 0 || request.expected_revision != record.revision {
        return Err(AttentionEvaluationCommitError::Revision(format!(
            "expected revision {} does not match record revision {}",
            request.expected_revision, record.revision,
        )));
    }
    if request.evaluation_id.as_str() != record.evaluation_id.as_str() {
        return Err(AttentionEvaluationCommitError::Revision(
            "request evaluation identity does not match the record evaluation identity".to_owned(),
        ));
    }
    check_revision_linkage(record, prior, request.operation)?;
    let operation_id = attention_evaluation_operation_id(&record.evaluation_id, record.revision)?;
    if request.operation_id != operation_id {
        return Err(AttentionEvaluationCommitError::Operation(format!(
            "presented operation identity {} does not match derived {operation_id}",
            request.operation_id,
        )));
    }
    let record_digest = attention_record_digest(record)?;
    let evidence_commitment = attention_evidence_commitment(record)?;
    if request.evidence_commitment != evidence_commitment {
        return Err(AttentionEvaluationCommitError::Evidence(
            "presented evidence commitment does not match the record evidence manifest".to_owned(),
        ));
    }
    let idempotency_key = attention_evaluation_idempotency_key(
        &record.evaluation_id,
        record.revision,
        &record_digest,
    );
    if request.idempotency_key != idempotency_key {
        return Err(AttentionEvaluationCommitError::Identity(
            "presented idempotency key does not match the derived revision key".to_owned(),
        ));
    }
    if identity.idempotency_key != idempotency_key {
        return Err(AttentionEvaluationCommitError::Identity(
            "caller idempotency key does not match the named request key".to_owned(),
        ));
    }
    if identity.request.metadata.session_id != Some(request.session_id.clone()) {
        return Err(AttentionEvaluationCommitError::Identity(
            "caller session does not match the session bound in the request metadata".to_owned(),
        ));
    }
    if request.principal_id.trim().is_empty() {
        return Err(AttentionEvaluationCommitError::Identity(
            "operator principal claim must be non-blank text".to_owned(),
        ));
    }
    if request.principal_id
        != record
            .evaluator_scope_uncertainty_and_invalidation
            .evaluator
            .principal_id
    {
        return Err(AttentionEvaluationCommitError::Identity(
            "operator principal claim does not match the record evaluator principal".to_owned(),
        ));
    }
    Ok(AttentionEvaluationCommitIdentity {
        operation_id,
        record_digest,
        evidence_commitment,
        idempotency_key,
    })
}

/// Checks revision/operation/predecessor agreement for one persist operation.
///
/// Creation opens revision one with no predecessor and no prior revision.
/// Correction and invalidation append the immediately following revision linked
/// to the presented prior; invalidation additionally requires the invalidation
/// statement with every other byte identical to the prior revision, so history
/// is preserved rather than rewritten.
fn check_revision_linkage(
    record: &HumanAttentionEvaluation,
    prior: Option<&HumanAttentionEvaluation>,
    operation: AttentionEvaluationOperation,
) -> Result<(), AttentionEvaluationCommitError> {
    match (operation, prior) {
        (AttentionEvaluationOperation::Create, None) => {
            if record.revision != 1 || record.predecessor.is_some() {
                return Err(AttentionEvaluationCommitError::Revision(
                    "creation must open revision one with no predecessor".to_owned(),
                ));
            }
            Ok(())
        }
        (AttentionEvaluationOperation::Create, Some(_)) => Err(
            AttentionEvaluationCommitError::Revision("creation takes no prior revision".to_owned()),
        ),
        (
            AttentionEvaluationOperation::Correct | AttentionEvaluationOperation::Invalidate,
            Some(prior),
        ) => {
            check_linked_successor(record, prior)?;
            if operation == AttentionEvaluationOperation::Invalidate {
                check_invalidation_preserves_history(record, prior)?;
            }
            Ok(())
        }
        (
            AttentionEvaluationOperation::Correct | AttentionEvaluationOperation::Invalidate,
            None,
        ) => Err(AttentionEvaluationCommitError::Revision(
            "correction and invalidation require the presented prior revision".to_owned(),
        )),
    }
}

/// Checks that a record is the immediately following revision of its prior.
fn check_linked_successor(
    record: &HumanAttentionEvaluation,
    prior: &HumanAttentionEvaluation,
) -> Result<(), AttentionEvaluationCommitError> {
    if prior.evaluation_id.as_str() != record.evaluation_id.as_str() {
        return Err(AttentionEvaluationCommitError::Revision(
            "successor evaluation identity does not match the prior revision".to_owned(),
        ));
    }
    if prior.revision.checked_add(1) != Some(record.revision) {
        return Err(AttentionEvaluationCommitError::Revision(format!(
            "successor revision {} does not immediately follow prior revision {}",
            record.revision, prior.revision,
        )));
    }
    let expected_predecessor = HumanAttentionEvaluationRevisionRef {
        evaluation_id: record.evaluation_id.clone(),
        revision: prior.revision,
    };
    if record.predecessor != Some(expected_predecessor) {
        return Err(AttentionEvaluationCommitError::Revision(
            "successor predecessor link does not name the presented prior revision".to_owned(),
        ));
    }
    Ok(())
}

/// Checks that an invalidation revision preserves the invalidated bytes.
///
/// The invalidation statement and the revision linkage are the only permitted
/// differences from the prior revision: the original evidence, method, and
/// results stay intact, and notification/approval state is untouched.
fn check_invalidation_preserves_history(
    record: &HumanAttentionEvaluation,
    prior: &HumanAttentionEvaluation,
) -> Result<(), AttentionEvaluationCommitError> {
    if record
        .evaluator_scope_uncertainty_and_invalidation
        .invalidation
        .is_none()
    {
        return Err(AttentionEvaluationCommitError::Revision(
            "invalidation requires the invalidation statement on the appended revision".to_owned(),
        ));
    }
    let mut expected = prior.clone();
    expected.revision = record.revision;
    expected.predecessor.clone_from(&record.predecessor);
    expected
        .evaluator_scope_uncertainty_and_invalidation
        .invalidation
        .clone_from(
            &record
                .evaluator_scope_uncertainty_and_invalidation
                .invalidation,
        );
    if expected != *record {
        return Err(AttentionEvaluationCommitError::Revision(
            "invalidation must preserve the invalidated revision bytes apart from the statement"
                .to_owned(),
        ));
    }
    Ok(())
}

/// Counts observed/unknown/not-applicable values in one metric group.
fn count_group(
    group_name: &'static str,
    group: &HumanAttentionMetricGroup,
) -> AttentionMetricGroupStatus {
    let mut status = AttentionMetricGroupStatus {
        group: group_name,
        observed: 0,
        unknown: 0,
        not_applicable: 0,
    };
    for observation in &group.metrics {
        match observation.value {
            HumanAttentionMetricValue::ObservedNumber { .. }
            | HumanAttentionMetricValue::ObservedText { .. } => status.observed += 1,
            HumanAttentionMetricValue::Unknown { .. } => status.unknown += 1,
            HumanAttentionMetricValue::NotApplicable { .. } => status.not_applicable += 1,
        }
    }
    status
}

/// Summarizes observed/unknown/not-applicable counts over the ten I11.10 groups.
///
/// Missing follow-up and inaccessible outcomes remain `unknown` here: an
/// observed zero is an ordinary observed number and is distinct from both.
/// The summary carries no score and supports no ranking.
#[must_use]
pub fn attention_unknown_summary(record: &HumanAttentionEvaluation) -> AttentionUnknownSummary {
    let groups = vec![
        count_group(
            "policy_and_task_risk_profile",
            &record.policy_and_task_risk_profile,
        ),
        count_group(
            "notification_approval_and_telemetry_profile",
            &record.notification_approval_and_telemetry_profile,
        ),
        count_group(
            "missed_critical_and_false_critical_counts",
            &record.missed_critical_and_false_critical_counts,
        ),
        count_group(
            "pre_exposure_prevention_and_conditional_intervention",
            &record.pre_exposure_prevention_and_conditional_intervention,
        ),
        count_group(
            "final_harm_and_residual_risk",
            &record.final_harm_and_residual_risk,
        ),
        count_group(
            "benign_false_blocks_and_abandoned_work",
            &record.benign_false_blocks_and_abandoned_work,
        ),
        count_group(
            "interruption_and_resumption_time_quality",
            &record.interruption_and_resumption_time_quality,
        ),
        count_group(
            "task_correctness_rework_and_human_attention",
            &record.task_correctness_rework_and_human_attention,
        ),
        count_group(
            "overtrust_undertrust_and_recoverability_observations",
            &record.overtrust_undertrust_and_recoverability_observations,
        ),
        count_group(
            "privacy_purpose_retention_and_disclosure_cost",
            &record.privacy_purpose_retention_and_disclosure_cost,
        ),
    ];
    let mut observed = 0;
    let mut unknown = 0;
    let mut not_applicable = 0;
    for group in &groups {
        observed += group.observed;
        unknown += group.unknown;
        not_applicable += group.not_applicable;
    }
    AttentionUnknownSummary {
        groups,
        observed,
        unknown,
        not_applicable,
    }
}

/// Reports the current-applicability verdict for one persisted revision.
///
/// Invalidation removes current use while retaining history; expiry removes
/// current use at its declared instant; anything else stays current. Expiry is
/// evaluated against the caller-supplied observation instant: when either the
/// declared expiry or the instant is unknown, expiry cannot be established and
/// the record is not expired by default.
#[must_use]
pub fn attention_evaluation_validity(
    record: &HumanAttentionEvaluation,
    observed_now_ms: Option<i64>,
) -> AttentionEvaluationValidity {
    if let Some(invalidation) = &record
        .evaluator_scope_uncertainty_and_invalidation
        .invalidation
    {
        return AttentionEvaluationValidity::Invalidated {
            reason: invalidation.reason.clone(),
            affected_scope_refs: invalidation.affected_scope_refs.clone(),
        };
    }
    if let (Some(expires_ms), Some(now_ms)) = (record.expires_at.known_time_ms, observed_now_ms)
        && now_ms >= expires_ms
    {
        return AttentionEvaluationValidity::Expired;
    }
    AttentionEvaluationValidity::Current
}

/// Verifies a Store read-back document against its committed digest.
///
/// Parses the verbatim document, re-validates the contract, and recomputes
/// the digest over the canonical bytes: any substitution on the round trip —
/// including a zero written where the producer recorded unknown — fails the
/// digest instead of surfacing as observed data.
pub fn verify_attention_evaluation_readback(
    record_json: &str,
    expected_digest: &str,
) -> Result<HumanAttentionEvaluation, AttentionEvaluationCommitError> {
    let record: HumanAttentionEvaluation = serde_json::from_str(record_json)
        .map_err(|error| AttentionEvaluationCommitError::Serialization(error.to_string()))?;
    record
        .validate()
        .map_err(|error| AttentionEvaluationCommitError::Record(error.to_string()))?;
    let observed_digest = attention_record_digest(&record)?;
    if observed_digest != expected_digest {
        return Err(AttentionEvaluationCommitError::Receipt(format!(
            "read-back digest {observed_digest} does not match committed {expected_digest}"
        )));
    }
    Ok(record)
}

/// Reconciles a lost commit acknowledgement against the stored receipt.
///
/// Same operation identity with identical canonical bytes returns the stored
/// receipt (one accepted revision, never a second commit); the same identity
/// with different bytes is an identity conflict that commits nothing. The
/// receipt fetch itself stays with the caller and the neutral receipt route;
/// this is the pure replay-same/conflict-changed decision.
pub fn resolve_attention_lost_acknowledgement(
    stored: &WriteReceipt,
    operation_id: &OperationId,
    expected_request_hash: &str,
    idempotency_key: &str,
) -> Result<WriteReceipt, AttentionEvaluationCommitError> {
    stored
        .validate()
        .map_err(|error| AttentionEvaluationCommitError::Receipt(error.to_string()))?;
    if stored.status != WriteReceiptStatus::Committed {
        return Err(AttentionEvaluationCommitError::Receipt(
            "stored receipt is not committed; no acknowledgement to reconcile".to_owned(),
        ));
    }
    if stored.operation_id != *operation_id || stored.idempotency_key != idempotency_key {
        return Err(AttentionEvaluationCommitError::Receipt(
            "stored receipt identity does not match the reconciled operation".to_owned(),
        ));
    }
    if stored.canonical_request_hash != expected_request_hash {
        return Err(AttentionEvaluationCommitError::Replay(format!(
            "operation {operation_id} is already committed with different canonical bytes"
        )));
    }
    Ok(stored.clone())
}

/// Checks a Store-issued commit receipt for freshness before it is surfaced.
///
/// Receipt validity and terminal-status pairing come from
/// [`WriteReceipt::validate`](eliot_store_api::WriteReceipt::validate);
/// identity, fence, and head agreement mirror the learning-record commit
/// discipline: a stale projection is never reported as a healthy commit.
pub fn check_attention_commit_receipt(
    receipt: &WriteReceipt,
    operation_id: &OperationId,
    idempotency_key: &str,
    envelope_fence: &StateFence,
    expected_revision_heads: &[RevisionHeadExpectation],
    expected_ordering_heads: &[OrderingHeadExpectation],
) -> Result<(), AttentionEvaluationCommitError> {
    receipt
        .validate()
        .map_err(|error| AttentionEvaluationCommitError::Receipt(error.to_string()))?;
    if receipt.status != WriteReceiptStatus::Committed {
        return Err(AttentionEvaluationCommitError::Receipt(
            "attention evaluation commit receipt is not committed; stale projection refused"
                .to_owned(),
        ));
    }
    if receipt.operation_id != *operation_id || receipt.idempotency_key != idempotency_key {
        return Err(AttentionEvaluationCommitError::Receipt(
            "attention evaluation commit receipt identity does not match the committed envelope"
                .to_owned(),
        ));
    }
    if receipt.state_fence != *envelope_fence {
        return Err(AttentionEvaluationCommitError::Receipt(
            "attention evaluation commit receipt fence does not match the committed envelope fence"
                .to_owned(),
        ));
    }
    for expected in expected_revision_heads {
        if let Some(delta) = receipt
            .revision_before_after
            .iter()
            .find(|delta| delta.key == expected.key)
            && delta.before != expected.expected_revision
        {
            return Err(AttentionEvaluationCommitError::Receipt(format!(
                "attention evaluation commit receipt revision is stale for {}: expected base {}, observed {}",
                expected.key.as_str(),
                expected.expected_revision,
                delta.before,
            )));
        }
    }
    for expected in expected_ordering_heads {
        if let Some(head) = receipt
            .ordering_sequences
            .iter()
            .find(|head| head.scope == expected.scope)
            && head.sequence <= expected.expected_sequence
        {
            return Err(AttentionEvaluationCommitError::Receipt(format!(
                "attention evaluation commit receipt ordering is stale for {}: expected advance past {}, observed {}",
                expected.scope.as_str(),
                expected.expected_sequence,
                head.sequence,
            )));
        }
    }
    Ok(())
}

/// Collects the manifest-bound evidence references servable for one record.
///
/// Only references listed in the record's own evidence manifest are servable;
/// anything else is a foreign expansion and fails. The check is re-evaluated
/// per call against the presented record, never cached into a wider grant.
pub fn collect_attention_evidence_refs(record: &HumanAttentionEvaluation) -> Vec<ArtifactId> {
    record.evidence_manifest.evidence_refs.clone()
}
