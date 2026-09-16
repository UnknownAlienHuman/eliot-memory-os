//! Provider-neutral, recovery-safe failures for the store wire.

use std::collections::BTreeSet;
use std::fmt;

use eliot_contracts::{OperationId, RequestId, StateFence};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{canonical_json_bytes, sha256_hex};

/// Independent revision for the typed store failure payload.
pub const STORE_FAILURE_CONTRACT_REVISION: &str = "eliot.store.failure.v2";
/// Maximum length of an additive reason token.
pub const MAX_STORE_REASON_CODE_LEN: usize = 64;
/// Maximum length of a non-authoritative human detail.
pub const MAX_STORE_FAILURE_DETAIL_LEN: usize = 1024;
/// Maximum length of a bounded evidence or identity reference.
pub const MAX_STORE_FAILURE_REFERENCE_LEN: usize = 512;
/// Maximum retry delay represented on the wire.
pub const MAX_STORE_FAILURE_RETRY_AFTER_MS: u64 = 3_600_000;
/// Maximum number of recovery/evidence handles in one validated handle set.
pub const MAX_STORE_FAILURE_EVIDENCE_HANDLES: usize = 8;

/// Small stable control axis for a store failure.
///
/// This closed contour is versioned at v2: [`StoreFailure`] carries the
/// `eliot.store.failure.v2` revision and unknown future reason codes survive
/// decoding, while the disposition itself stays closed so exhaustive matches
/// fail closed on unrepresentable arms.
///
/// Authorization/policy denial (issue #205) has an explicit arm: `Denied`
/// asserts an authorization decision, never validation shape. No `StoreError`
/// producer maps to it, and reusing `DeterministicRejection` or `Unsupported`
/// for a denial is rejected — those arms assert validation-shape semantics.
#[derive(
    Clone, Copy, Debug, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum StoreFailureDisposition {
    DeterministicRejection,
    Conflict,
    Denied,
    Unavailable,
    Backpressured,
    DeadlineExceeded,
    MigrationRequired,
    Unsupported,
    UnknownOutcome,
    InternalDefect,
}

/// Additive, provider-neutral reason token.
#[derive(
    Clone, Debug, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(try_from = "String", into = "String")]
pub struct StoreReasonCode(String);

impl StoreReasonCode {
    /// Constructs a bounded uppercase ASCII token.
    pub fn new(value: impl Into<String>) -> Result<Self, StoreFailureContractError> {
        let value = value.into();
        if value.is_empty() || value.len() > MAX_STORE_REASON_CODE_LEN {
            return Err(StoreFailureContractError::Invalid {
                field: "reason_code",
                reason: "must be non-empty and within the length bound",
            });
        }
        if !value
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
            || value.starts_with('_')
            || value.ends_with('_')
            || value.contains("__")
        {
            return Err(StoreFailureContractError::Invalid {
                field: "reason_code",
                reason: "must be an uppercase ASCII token with underscore separators",
            });
        }
        Ok(Self(value))
    }

    /// Returns the stable token text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for StoreReasonCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl TryFrom<String> for StoreReasonCode {
    type Error = StoreFailureContractError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<StoreReasonCode> for String {
    fn from(value: StoreReasonCode) -> Self {
        value.0
    }
}

/// What is known about the mutation when the failure was reported.
///
/// This closed contour is versioned at v2 alongside
/// [`StoreFailureDisposition`].
///
/// `NotApplicable` covers outcomes where no mutation could ever apply
/// (read-path and validation refusals) — no mutation was attempted and none
/// was possible. `NotAttempted` covers outcomes where no mutation was
/// attempted but one could have applied. `ProvenNotApplied` stays reserved
/// for the checked-and-absent case (`known_not_applied`).
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum StoreMutationDisposition {
    NotAttempted,
    NotApplicable,
    ProvenNotApplied,
    Committed,
    Partial,
    Unknown,
}

/// The next safe retry or reconciliation operation.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum StoreRetryDirective {
    DoNotRetry,
    RetrySameIdentityAfterBackoff,
    QueryReceipt,
    ReconcileExactOperation,
    NewIdentityAfterCondition,
    MigrateThenRetryNewIdentity,
    ManualRecovery,
}

/// A bounded recovery action. It grants no authority and changes no fence.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum StoreRecoveryAction {
    None,
    RefreshStateFence,
    RefreshRevisionHeads,
    WaitForCapacity,
    RestoreStoreConnectivity,
    RunSchemaMigration,
    ResolveWriteReceipt,
    ReconcileUnknownOutcome,
    RepairConfiguration,
    EscalateInternalDefect,
    EnterManualRecovery,
}

/// Bounded, unique recovery/evidence handles (issue #205).
///
/// This is the validated contract piece for the evidence-handle invariant:
/// every handle is non-empty, bounded by
/// [`MAX_STORE_FAILURE_REFERENCE_LEN`], free of control characters, unique
/// within the set, and the set holds at most
/// [`MAX_STORE_FAILURE_EVIDENCE_HANDLES`] entries.
///
/// Attachment to the [`StoreFailure`] wire payload is live: the set travels
/// as `evidence_handles` alongside the legacy singular `evidence_ref`,
/// which is kept for wire compatibility during migration.
#[derive(Clone, Debug, Default, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "Vec<String>", into = "Vec<String>")]
pub struct StoreEvidenceHandles(Vec<String>);

impl StoreEvidenceHandles {
    /// Constructs a validated handle set.
    pub fn new(handles: Vec<String>) -> Result<Self, StoreFailureContractError> {
        let value = Self(handles);
        value.validate()?;
        Ok(value)
    }

    /// Validates boundedness, per-handle shape, and uniqueness.
    pub fn validate(&self) -> Result<(), StoreFailureContractError> {
        if self.0.len() > MAX_STORE_FAILURE_EVIDENCE_HANDLES {
            return Err(invalid(
                "evidence_handles",
                "evidence handle set exceeds the bound",
            ));
        }
        let mut seen = BTreeSet::new();
        for handle in &self.0 {
            validate_optional_reference(Some(handle), "evidence_handles")?;
            if !seen.insert(handle) {
                return Err(invalid(
                    "evidence_handles",
                    "evidence handles must be unique",
                ));
            }
        }
        Ok(())
    }

    /// Returns the validated handles in stable order.
    #[must_use]
    pub fn as_slice(&self) -> &[String] {
        &self.0
    }

    /// Returns the number of handles in the set.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns whether the set carries no handles.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl TryFrom<Vec<String>> for StoreEvidenceHandles {
    type Error = StoreFailureContractError;

    fn try_from(value: Vec<String>) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<StoreEvidenceHandles> for Vec<String> {
    fn from(value: StoreEvidenceHandles) -> Self {
        value.0
    }
}

/// Safe provider-neutral observations for a conflict.
#[derive(Clone, Debug, Default, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoreConflictObservation {
    pub expected_state_fence_ref: Option<String>,
    pub observed_state_fence_ref: Option<String>,
    pub revision_key_and_expected_observed_values: Option<String>,
    pub ordering_scope_and_expected_observed_values: Option<String>,
    pub manifest_or_contract_expected_observed_refs: Option<String>,
}

impl StoreConflictObservation {
    fn validate(&self) -> Result<(), StoreFailureContractError> {
        validate_optional_reference(
            self.expected_state_fence_ref.as_deref(),
            "expected_state_fence_ref",
        )?;
        validate_optional_reference(
            self.observed_state_fence_ref.as_deref(),
            "observed_state_fence_ref",
        )?;
        validate_optional_reference(
            self.revision_key_and_expected_observed_values.as_deref(),
            "revision_key_and_expected_observed_values",
        )?;
        validate_optional_reference(
            self.ordering_scope_and_expected_observed_values.as_deref(),
            "ordering_scope_and_expected_observed_values",
        )?;
        validate_optional_reference(
            self.manifest_or_contract_expected_observed_refs.as_deref(),
            "manifest_or_contract_expected_observed_refs",
        )?;
        if self.expected_state_fence_ref.is_none()
            && self.observed_state_fence_ref.is_none()
            && self.revision_key_and_expected_observed_values.is_none()
            && self.ordering_scope_and_expected_observed_values.is_none()
            && self.manifest_or_contract_expected_observed_refs.is_none()
        {
            return Err(invalid(
                "conflict",
                "conflict disposition requires at least one typed observation",
            ));
        }
        if let (Some(expected), Some(observed)) = (
            self.expected_state_fence_ref.as_deref(),
            self.observed_state_fence_ref.as_deref(),
        ) && expected == observed
        {
            return Err(invalid(
                "expected_state_fence_ref",
                "fence conflict requires distinct expected and observed fences",
            ));
        }
        Ok(())
    }
}

/// Identity and safe context available at an error mapping boundary.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct StoreFailureIdentityContext {
    pub request_id: Option<RequestId>,
    pub operation_id: Option<OperationId>,
    pub idempotency_key_ref_or_digest: Option<String>,
    pub state_fence_ref_or_exact_safe_projection: Option<StateFence>,
    pub evidence_ref: Option<String>,
    /// A transport observation used only when importing the legacy error string.
    pub transport_unavailable: bool,
}

/// Compatibility spelling for callers that use request context terminology.
pub type StoreFailureRequestContext = StoreFailureIdentityContext;

/// Typed provider-neutral store failure payload.
#[derive(Clone, Debug, JsonSchema, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoreFailure {
    pub contract_revision: String,
    pub disposition: StoreFailureDisposition,
    pub reason_code: StoreReasonCode,
    pub request_id: Option<RequestId>,
    pub operation_id: Option<OperationId>,
    pub idempotency_key_ref_or_digest: Option<String>,
    pub state_fence_ref_or_exact_safe_projection: Option<StateFence>,
    pub mutation_disposition: StoreMutationDisposition,
    pub retry_directive: StoreRetryDirective,
    pub recovery_action: StoreRecoveryAction,
    pub conflict: Option<StoreConflictObservation>,
    /// Non-zero future delay before the same identity may be retried. A set
    /// delay requires a retryable disposition with
    /// `RetrySameIdentityAfterBackoff`, exact request/idempotency evidence,
    /// and the named dependency revision in
    /// `retry_after_dependency_revision` (non-zero, within
    /// [`MAX_STORE_FAILURE_RETRY_AFTER_MS`]).
    pub retry_after_ms: Option<u64>,
    /// Named dependency revision gating `retry_after_ms` (issue #205).
    /// Required whenever `retry_after_ms` is set; bounded, non-empty and
    /// free of control characters.
    #[serde(default)]
    pub retry_after_dependency_revision: Option<String>,
    /// Legacy singular evidence handle, kept for wire compatibility.
    pub evidence_ref: Option<String>,
    /// Bounded unique recovery/evidence handles. Additive under v2 with a
    /// default empty set so older frames still decode; machine-semantic and
    /// bound into [`StoreFailure::semantic_digest`].
    #[serde(default)]
    pub evidence_handles: StoreEvidenceHandles,
    /// Diagnostic prose only; it is excluded from equality and control semantics.
    pub human_detail: Option<String>,
}

impl PartialEq for StoreFailure {
    fn eq(&self, other: &Self) -> bool {
        self.contract_revision == other.contract_revision
            && self.disposition == other.disposition
            && self.reason_code == other.reason_code
            && self.request_id == other.request_id
            && self.operation_id == other.operation_id
            && self.idempotency_key_ref_or_digest == other.idempotency_key_ref_or_digest
            && self.state_fence_ref_or_exact_safe_projection
                == other.state_fence_ref_or_exact_safe_projection
            && self.mutation_disposition == other.mutation_disposition
            && self.retry_directive == other.retry_directive
            && self.recovery_action == other.recovery_action
            && self.conflict == other.conflict
            && self.retry_after_ms == other.retry_after_ms
            && self.retry_after_dependency_revision == other.retry_after_dependency_revision
            && self.evidence_ref == other.evidence_ref
            && self.evidence_handles == other.evidence_handles
    }
}

impl Eq for StoreFailure {}

/// Canonical machine-semantic projection of [`StoreFailure`] feeding
/// [`StoreFailure::semantic_digest`]. `human_detail` is deliberately absent:
/// diagnostic prose must never steer machine recovery.
#[derive(Serialize)]
struct StoreFailureSemanticView<'a> {
    contract_revision: &'a str,
    disposition: StoreFailureDisposition,
    reason_code: &'a str,
    request_id: Option<&'a RequestId>,
    operation_id: Option<&'a OperationId>,
    idempotency_key_ref_or_digest: Option<&'a str>,
    state_fence_ref_or_exact_safe_projection: Option<&'a StateFence>,
    mutation_disposition: StoreMutationDisposition,
    retry_directive: StoreRetryDirective,
    recovery_action: StoreRecoveryAction,
    conflict: Option<&'a StoreConflictObservation>,
    retry_after_ms: Option<u64>,
    retry_after_dependency_revision: Option<&'a str>,
    evidence_ref: Option<&'a str>,
    evidence_handles: &'a StoreEvidenceHandles,
}

impl StoreFailure {
    /// Computes the canonical machine-semantics digest (issue #205).
    ///
    /// The digest binds every machine-semantic field
    /// (`contract_revision`, disposition, reason code, request/operation
    /// identities, mutation/retry/recovery control, conflict observations,
    /// retry delay plus its named dependency revision, evidence reference,
    /// and the bounded unique evidence-handle set) through deterministic
    /// canonical JSON. `human_detail` is diagnostic prose only and is
    /// excluded, so rewording provider text never changes the digest while
    /// any machine tampering does. Two failures that compare equal always
    /// share a digest.
    pub fn semantic_digest(&self) -> Result<String, StoreFailureContractError> {
        let view = StoreFailureSemanticView {
            contract_revision: &self.contract_revision,
            disposition: self.disposition,
            reason_code: self.reason_code.as_str(),
            request_id: self.request_id.as_ref(),
            operation_id: self.operation_id.as_ref(),
            idempotency_key_ref_or_digest: self.idempotency_key_ref_or_digest.as_deref(),
            state_fence_ref_or_exact_safe_projection: self
                .state_fence_ref_or_exact_safe_projection
                .as_ref(),
            mutation_disposition: self.mutation_disposition,
            retry_directive: self.retry_directive,
            recovery_action: self.recovery_action,
            conflict: self.conflict.as_ref(),
            retry_after_ms: self.retry_after_ms,
            retry_after_dependency_revision: self.retry_after_dependency_revision.as_deref(),
            evidence_ref: self.evidence_ref.as_deref(),
            evidence_handles: &self.evidence_handles,
        };
        let bytes = canonical_json_bytes(&view)
            .map_err(|_| invalid("semantic_digest", "canonical semantic encoding failed"))?;
        Ok(sha256_hex(&bytes))
    }

    /// Validates wire shape and all cross-field recovery invariants.
    #[allow(clippy::too_many_lines)]
    pub fn validate(&self) -> Result<(), StoreFailureContractError> {
        if self.contract_revision != STORE_FAILURE_CONTRACT_REVISION {
            return Err(invalid(
                "contract_revision",
                "unsupported store failure contract revision",
            ));
        }
        StoreReasonCode::new(self.reason_code.0.clone())?;
        validate_optional_reference(
            self.idempotency_key_ref_or_digest.as_deref(),
            "idempotency_key_ref_or_digest",
        )?;
        validate_optional_reference(self.evidence_ref.as_deref(), "evidence_ref")?;
        validate_optional_reference(
            self.retry_after_dependency_revision.as_deref(),
            "retry_after_dependency_revision",
        )?;
        self.evidence_handles.validate()?;
        if let Some(fence) = &self.state_fence_ref_or_exact_safe_projection {
            fence.validate().map_err(|_| {
                invalid(
                    "state_fence_ref_or_exact_safe_projection",
                    "invalid state fence",
                )
            })?;
        }
        if let Some(conflict) = &self.conflict {
            conflict.validate()?;
            if self.disposition != StoreFailureDisposition::Conflict {
                return Err(invalid(
                    "conflict",
                    "conflict observations require conflict disposition",
                ));
            }
        }
        if self.disposition == StoreFailureDisposition::Conflict && self.conflict.is_none() {
            return Err(invalid(
                "conflict",
                "conflict disposition requires typed conflict details",
            ));
        }
        if let Some(detail) = &self.human_detail
            && (detail.is_empty()
                || detail.len() > MAX_STORE_FAILURE_DETAIL_LEN
                || detail.chars().any(char::is_control))
        {
            return Err(invalid(
                "human_detail",
                "must be bounded, non-empty and free of control characters",
            ));
        }
        if let Some(delay) = self.retry_after_ms
            && (delay == 0
                || delay > MAX_STORE_FAILURE_RETRY_AFTER_MS
                || self.retry_after_dependency_revision.is_none()
                || !matches!(
                    self.disposition,
                    StoreFailureDisposition::Unavailable
                        | StoreFailureDisposition::Backpressured
                        | StoreFailureDisposition::DeadlineExceeded
                )
                || self.retry_directive != StoreRetryDirective::RetrySameIdentityAfterBackoff)
        {
            return Err(invalid(
                "retry_after_ms",
                "retry delay requires a non-zero future delay with a retryable disposition, retry directive and named dependency revision",
            ));
        }

        if self.mutation_disposition == StoreMutationDisposition::Committed {
            return Err(invalid(
                "mutation_disposition",
                "committed outcome requires a WriteReceipt",
            ));
        }
        if self.disposition == StoreFailureDisposition::DeterministicRejection
            && !matches!(
                self.mutation_disposition,
                StoreMutationDisposition::NotAttempted | StoreMutationDisposition::NotApplicable
            )
        {
            return Err(invalid(
                "mutation_disposition",
                "deterministic rejection must not claim an attempted mutation",
            ));
        }
        if self.disposition == StoreFailureDisposition::UnknownOutcome
            && (self.operation_id.is_none()
                || self.mutation_disposition != StoreMutationDisposition::Unknown
                || !is_reconciliation_directive(self.retry_directive))
        {
            return Err(invalid(
                "unknown_outcome",
                "requires exact operation identity, unknown mutation and reconciliation",
            ));
        }
        if self.mutation_disposition == StoreMutationDisposition::Unknown
            && (self.disposition != StoreFailureDisposition::UnknownOutcome
                || self.operation_id.is_none()
                || !is_reconciliation_directive(self.retry_directive))
        {
            return Err(invalid(
                "mutation_disposition",
                "unknown mutation requires exact-operation reconciliation",
            ));
        }
        if is_reconciliation_directive(self.retry_directive)
            && (self.operation_id.is_none()
                || self.disposition != StoreFailureDisposition::UnknownOutcome
                || self.mutation_disposition != StoreMutationDisposition::Unknown)
        {
            return Err(invalid(
                "retry_directive",
                "receipt queries and exact reconciliation require unknown outcome",
            ));
        }
        if self.reason_code.as_str() == "IDENTITY_CONFLICT"
            && self.retry_directive == StoreRetryDirective::RetrySameIdentityAfterBackoff
        {
            return Err(invalid(
                "retry_directive",
                "identity conflict cannot retry the same identity",
            ));
        }
        if self.retry_directive == StoreRetryDirective::RetrySameIdentityAfterBackoff
            && !matches!(
                self.disposition,
                StoreFailureDisposition::Unavailable
                    | StoreFailureDisposition::Backpressured
                    | StoreFailureDisposition::DeadlineExceeded
            )
        {
            return Err(invalid(
                "retry_directive",
                "same-identity retry requires a retryable disposition",
            ));
        }
        if self.retry_directive == StoreRetryDirective::RetrySameIdentityAfterBackoff
            && self.request_id.is_none()
            && self.idempotency_key_ref_or_digest.is_none()
        {
            return Err(invalid(
                "retry_directive",
                "same-identity retry requires exact request or idempotency evidence",
            ));
        }
        if self.disposition == StoreFailureDisposition::UnknownOutcome
            && self.recovery_action != StoreRecoveryAction::ReconcileUnknownOutcome
        {
            return Err(invalid(
                "recovery_action",
                "unknown outcome requires unknown-outcome reconciliation",
            ));
        }
        Ok(())
    }

    /// Constructs the typed failure for a provider outcome that cannot yet be
    /// reconciled. The admitted operation identity is the only identity this
    /// constructor accepts; provider-reported identities stay outside it.
    pub fn from_provider_unknown_outcome(
        context: &StoreFailureIdentityContext,
    ) -> Result<Self, StoreFailureContractError> {
        Self::unknown_outcome(context, "PROVIDER_OUTCOME_UNKNOWN")
    }

    /// Converts the complete current `StoreError` set without wildcard collapse.
    #[allow(clippy::too_many_lines)]
    #[allow(clippy::needless_pass_by_value)]
    pub fn from_store_error(
        error: crate::StoreError,
        context: StoreFailureIdentityContext,
    ) -> Result<Self, StoreFailureContractError> {
        use crate::StoreError;

        let mut failure = Self::base(&context);
        let (disposition, reason_code, mutation, retry, recovery, conflict_observation) =
            match &error {
                StoreError::InvalidField { .. } => deterministic("INVALID_FIELD"),
                StoreError::Empty { .. } => deterministic("EMPTY_FIELD"),
                StoreError::Duplicate { .. } => deterministic("DUPLICATE_IDENTITY"),
                StoreError::Foundation(_) => deterministic("FOUNDATION_CONTRACT_REJECTED"),
                StoreError::Security(_) => deterministic("SECURITY_CONTRACT_REJECTED"),
                StoreError::Receipt(_) => deterministic("RECEIPT_CONTRACT_REJECTED"),
                StoreError::UnknownOperation => unsupported("UNKNOWN_NAMED_OPERATION"),
                StoreError::ManifestMismatch => unsupported("OPERATION_MANIFEST_MISMATCH"),
                StoreError::TransitionClassExceeded => unsupported("TRANSITION_CLASS_EXCEEDED"),
                StoreError::EffectCeilingExceeded => unsupported("EFFECT_CEILING_EXCEEDED"),
                StoreError::FenceMismatch => conflict(
                    "STATE_FENCE_MISMATCH",
                    StoreRecoveryAction::RefreshStateFence,
                    StoreConflictObservation {
                        observed_state_fence_ref: Some("STATE_FENCE_MISMATCH".to_owned()),
                        ..Default::default()
                    },
                ),
                StoreError::RevisionConflict => conflict(
                    "REVISION_CONFLICT",
                    StoreRecoveryAction::RefreshRevisionHeads,
                    StoreConflictObservation {
                        revision_key_and_expected_observed_values: Some(
                            "REVISION_CONFLICT".to_owned(),
                        ),
                        ..Default::default()
                    },
                ),
                StoreError::OrderingConflict => conflict(
                    "ORDERING_CONFLICT",
                    StoreRecoveryAction::RefreshRevisionHeads,
                    StoreConflictObservation {
                        ordering_scope_and_expected_observed_values: Some(
                            "ORDERING_CONFLICT".to_owned(),
                        ),
                        ..Default::default()
                    },
                ),
                StoreError::InvalidProjection => defect("INVALID_PROJECTION"),
                StoreError::InvalidOutbox => defect("INVALID_OUTBOX"),
                StoreError::InvalidReceipt => defect("INVALID_RECEIPT"),
                StoreError::IdentityConflict => (
                    StoreFailureDisposition::Conflict,
                    "IDENTITY_CONFLICT",
                    StoreMutationDisposition::NotAttempted,
                    StoreRetryDirective::NewIdentityAfterCondition,
                    StoreRecoveryAction::None,
                    Some(StoreConflictObservation {
                        manifest_or_contract_expected_observed_refs: Some(
                            "IDENTITY_CONFLICT".to_owned(),
                        ),
                        ..Default::default()
                    }),
                ),
                StoreError::TransitionDigestMismatch { expected, observed } => (
                    StoreFailureDisposition::Conflict,
                    "TRANSITION_DIGEST_MISMATCH",
                    StoreMutationDisposition::NotAttempted,
                    StoreRetryDirective::NewIdentityAfterCondition,
                    StoreRecoveryAction::None,
                    Some(StoreConflictObservation {
                        manifest_or_contract_expected_observed_refs: Some(format!(
                            "expected:{expected} observed:{observed}"
                        )),
                        ..Default::default()
                    }),
                ),
                StoreError::ReceiptNotFound => (
                    StoreFailureDisposition::DeterministicRejection,
                    "RECEIPT_NOT_FOUND",
                    StoreMutationDisposition::NotAttempted,
                    StoreRetryDirective::DoNotRetry,
                    StoreRecoveryAction::ResolveWriteReceipt,
                    None,
                ),
                StoreError::MissingReceiptEnvelope => {
                    return Self::unknown_outcome(&context, "RECEIPT_ENVELOPE_MISSING");
                }
                StoreError::PayloadTooLarge => deterministic("PAYLOAD_TOO_LARGE"),
                StoreError::Unavailable => (
                    StoreFailureDisposition::Unavailable,
                    "STORE_UNAVAILABLE",
                    StoreMutationDisposition::NotAttempted,
                    StoreRetryDirective::RetrySameIdentityAfterBackoff,
                    StoreRecoveryAction::RestoreStoreConnectivity,
                    None,
                ),
                StoreError::Serialization(_) => defect("SERIALIZATION_FAILURE"),
            };
        drop(error);
        drop(context);
        failure.disposition = disposition;
        failure.reason_code = StoreReasonCode::new(reason_code)?;
        failure.mutation_disposition = mutation;
        failure.retry_directive = retry;
        failure.recovery_action = recovery;
        failure.conflict = conflict_observation;
        failure.validate()?;
        Ok(failure)
    }

    fn unknown_outcome(
        context: &StoreFailureIdentityContext,
        reason_code: &'static str,
    ) -> Result<Self, StoreFailureContractError> {
        let mut failure = Self::base(context);
        if failure.operation_id.is_none() {
            return Err(StoreFailureContractError::MissingOperationIdentity);
        }
        failure.disposition = StoreFailureDisposition::UnknownOutcome;
        failure.reason_code = StoreReasonCode::new(reason_code)?;
        failure.mutation_disposition = StoreMutationDisposition::Unknown;
        failure.retry_directive = StoreRetryDirective::ReconcileExactOperation;
        failure.recovery_action = StoreRecoveryAction::ReconcileUnknownOutcome;
        failure.validate()?;
        Ok(failure)
    }

    fn base(context: &StoreFailureIdentityContext) -> Self {
        Self {
            contract_revision: STORE_FAILURE_CONTRACT_REVISION.to_owned(),
            disposition: StoreFailureDisposition::InternalDefect,
            reason_code: StoreReasonCode("INTERNAL_STORE_FAILURE".to_owned()),
            request_id: context.request_id.clone(),
            operation_id: context.operation_id.clone(),
            idempotency_key_ref_or_digest: context.idempotency_key_ref_or_digest.clone(),
            state_fence_ref_or_exact_safe_projection: context
                .state_fence_ref_or_exact_safe_projection
                .clone(),
            mutation_disposition: StoreMutationDisposition::NotAttempted,
            retry_directive: StoreRetryDirective::DoNotRetry,
            recovery_action: StoreRecoveryAction::None,
            conflict: None,
            retry_after_ms: None,
            retry_after_dependency_revision: None,
            evidence_ref: context.evidence_ref.clone(),
            evidence_handles: StoreEvidenceHandles::default(),
            human_detail: None,
        }
    }
}

/// Closed erasure refusal reported by the fail-closed surface aggregation.
///
/// This is the only erasure-specific taxonomy added by the store port: every
/// variant maps into the existing typed [`StoreFailure`] via
/// [`ErasureFailureKind::store_failure`]. No new public error taxonomy exists
/// beyond this mapping. `Unknown` never maps to success: it always becomes
/// `UnknownOutcome` with exact-operation reconciliation.
#[derive(
    Clone, Copy, Debug, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum ErasureFailureKind {
    /// At least one required surface is incomplete (or the outcome set is
    /// empty, duplicated, misordered, missing, or extra).
    Incomplete,
    /// At least one required surface reports unknown outcome; takes
    /// precedence over [`Self::Incomplete`].
    Unknown,
    /// The backend does not implement durable intent; refuses with zero
    /// destructive calls.
    UnsupportedIntent,
    /// The same operation identity carries a different admitted digest.
    IntentConflict,
}

impl ErasureFailureKind {
    /// Returns the stable additive reason token for this refusal.
    #[must_use]
    pub const fn reason_code(self) -> &'static str {
        match self {
            Self::Incomplete => "ERASURE_SURFACE_INCOMPLETE",
            Self::Unknown => "ERASURE_SURFACE_UNKNOWN",
            Self::UnsupportedIntent => "ERASURE_INTENT_UNSUPPORTED",
            Self::IntentConflict => "ERASURE_INTENT_CONFLICT",
        }
    }

    /// Maps this refusal into the existing typed [`StoreFailure`].
    ///
    /// * `Incomplete` becomes `Unavailable` with a `Partial` mutation: some
    ///   destructive work may have happened and manual recovery owns the rest.
    /// * `Unknown` becomes `UnknownOutcome` with an `Unknown` mutation and
    ///   exact-operation reconciliation; it is never success.
    /// * `UnsupportedIntent` becomes `Unsupported` with no attempted mutation.
    /// * `IntentConflict` becomes `Conflict` requiring a new identity after
    ///   the condition changes.
    pub fn store_failure(
        self,
        context: &StoreFailureIdentityContext,
    ) -> Result<StoreFailure, StoreFailureContractError> {
        let mut failure = StoreFailure::base(context);
        let (disposition, mutation, retry, recovery) = match self {
            Self::Incomplete => (
                StoreFailureDisposition::Unavailable,
                StoreMutationDisposition::Partial,
                StoreRetryDirective::ManualRecovery,
                StoreRecoveryAction::EnterManualRecovery,
            ),
            Self::Unknown => {
                if failure.operation_id.is_none() {
                    return Err(StoreFailureContractError::MissingOperationIdentity);
                }
                (
                    StoreFailureDisposition::UnknownOutcome,
                    StoreMutationDisposition::Unknown,
                    StoreRetryDirective::ReconcileExactOperation,
                    StoreRecoveryAction::ReconcileUnknownOutcome,
                )
            }
            Self::UnsupportedIntent => (
                StoreFailureDisposition::Unsupported,
                StoreMutationDisposition::NotAttempted,
                StoreRetryDirective::DoNotRetry,
                StoreRecoveryAction::None,
            ),
            Self::IntentConflict => (
                StoreFailureDisposition::Conflict,
                StoreMutationDisposition::NotAttempted,
                StoreRetryDirective::NewIdentityAfterCondition,
                StoreRecoveryAction::None,
            ),
        };
        failure.disposition = disposition;
        failure.reason_code = StoreReasonCode::new(self.reason_code())?;
        failure.mutation_disposition = mutation;
        failure.retry_directive = retry;
        failure.recovery_action = recovery;
        // Intent conflicts carry no measured expected/observed values at this
        // boundary, so the observation holds the axis category marker (same
        // rationale as `StoreFailure::from_store_error`).
        failure.conflict = match self {
            Self::IntentConflict => Some(StoreConflictObservation {
                manifest_or_contract_expected_observed_refs: Some(
                    "ERASURE_INTENT_CONFLICT".to_owned(),
                ),
                ..Default::default()
            }),
            Self::Incomplete | Self::Unknown | Self::UnsupportedIntent => None,
        };
        failure.validate()?;
        Ok(failure)
    }
}

/// Maps one erasure refusal into the existing typed [`StoreFailure`].
///
/// Thin free-function form of [`ErasureFailureKind::store_failure`] for
/// call sites that hold the kind by value.
pub fn erasure_store_failure(
    kind: ErasureFailureKind,
    context: &StoreFailureIdentityContext,
) -> Result<StoreFailure, StoreFailureContractError> {
    kind.store_failure(context)
}

fn invalid(field: &'static str, reason: &'static str) -> StoreFailureContractError {
    StoreFailureContractError::Invalid { field, reason }
}

fn is_reconciliation_directive(directive: StoreRetryDirective) -> bool {
    matches!(
        directive,
        StoreRetryDirective::QueryReceipt | StoreRetryDirective::ReconcileExactOperation
    )
}

fn deterministic(
    reason: &'static str,
) -> (
    StoreFailureDisposition,
    &'static str,
    StoreMutationDisposition,
    StoreRetryDirective,
    StoreRecoveryAction,
    Option<StoreConflictObservation>,
) {
    (
        StoreFailureDisposition::DeterministicRejection,
        reason,
        StoreMutationDisposition::NotAttempted,
        StoreRetryDirective::DoNotRetry,
        StoreRecoveryAction::None,
        None,
    )
}

fn unsupported(
    reason: &'static str,
) -> (
    StoreFailureDisposition,
    &'static str,
    StoreMutationDisposition,
    StoreRetryDirective,
    StoreRecoveryAction,
    Option<StoreConflictObservation>,
) {
    (
        StoreFailureDisposition::Unsupported,
        reason,
        StoreMutationDisposition::NotAttempted,
        StoreRetryDirective::DoNotRetry,
        StoreRecoveryAction::None,
        None,
    )
}

/// Conflict mapping with the axis-correct typed observation.
///
/// The attached observation carries a category marker naming the conflict
/// axis, not measured expected/observed values: `StoreError` variants carry
/// no such values. Markers keep the `CONFLICT requires typed details`
/// invariant total over this constructor; the bridge/edge follow-up replaces
/// markers with exact expected/observed evidence.
fn conflict(
    reason: &'static str,
    recovery: StoreRecoveryAction,
    observation: StoreConflictObservation,
) -> (
    StoreFailureDisposition,
    &'static str,
    StoreMutationDisposition,
    StoreRetryDirective,
    StoreRecoveryAction,
    Option<StoreConflictObservation>,
) {
    (
        StoreFailureDisposition::Conflict,
        reason,
        StoreMutationDisposition::NotAttempted,
        StoreRetryDirective::NewIdentityAfterCondition,
        recovery,
        Some(observation),
    )
}

fn defect(
    reason: &'static str,
) -> (
    StoreFailureDisposition,
    &'static str,
    StoreMutationDisposition,
    StoreRetryDirective,
    StoreRecoveryAction,
    Option<StoreConflictObservation>,
) {
    (
        StoreFailureDisposition::InternalDefect,
        reason,
        StoreMutationDisposition::NotAttempted,
        StoreRetryDirective::ManualRecovery,
        StoreRecoveryAction::EscalateInternalDefect,
        None,
    )
}

fn validate_optional_reference(
    value: Option<&str>,
    field: &'static str,
) -> Result<(), StoreFailureContractError> {
    if let Some(value) = value
        && (value.is_empty()
            || value.len() > MAX_STORE_FAILURE_REFERENCE_LEN
            || value.chars().any(char::is_control))
    {
        return Err(invalid(
            field,
            "must be bounded, non-empty and free of control characters",
        ));
    }
    Ok(())
}

/// The exact legacy string-shaped failure variants accepted at the boundary.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum LegacyStoreFailureV1 {
    Unknown {
        operation_id: OperationId,
        reason: String,
    },
    Error {
        error: String,
    },
}

/// Imports the current v1 string response shape without parsing human text.
pub fn decode_legacy_store_failure_v1(
    value: &serde_json::Value,
    context: &StoreFailureIdentityContext,
) -> Result<StoreFailure, StoreFailureContractError> {
    let legacy: LegacyStoreFailureV1 = serde_json::from_value(value.clone())
        .map_err(|_| invalid("legacy_failure", "not a supported v1 store failure shape"))?;
    match legacy {
        LegacyStoreFailureV1::Unknown {
            operation_id,
            reason,
        } => {
            let mut failure = StoreFailure::base(context);
            failure.disposition = StoreFailureDisposition::UnknownOutcome;
            failure.reason_code = StoreReasonCode::new("PROVIDER_OUTCOME_UNKNOWN")?;
            failure.operation_id = Some(operation_id);
            failure.mutation_disposition = StoreMutationDisposition::Unknown;
            failure.retry_directive = StoreRetryDirective::ReconcileExactOperation;
            failure.recovery_action = StoreRecoveryAction::ReconcileUnknownOutcome;
            failure.human_detail = bounded_legacy_detail(reason)?;
            failure.validate()?;
            Ok(failure)
        }
        LegacyStoreFailureV1::Error { error } => {
            let mut failure = StoreFailure::base(context);
            if context.transport_unavailable {
                failure.disposition = StoreFailureDisposition::Unavailable;
                failure.reason_code = StoreReasonCode::new("STORE_UNAVAILABLE")?;
                failure.retry_directive = StoreRetryDirective::RetrySameIdentityAfterBackoff;
                failure.recovery_action = StoreRecoveryAction::RestoreStoreConnectivity;
            } else {
                failure.disposition = StoreFailureDisposition::InternalDefect;
                failure.reason_code = StoreReasonCode::new("INTERNAL_STORE_FAILURE")?;
                failure.retry_directive = StoreRetryDirective::ManualRecovery;
                failure.recovery_action = StoreRecoveryAction::EscalateInternalDefect;
            }
            failure.human_detail = bounded_legacy_detail(error)?;
            failure.validate()?;
            Ok(failure)
        }
    }
}

fn bounded_legacy_detail(value: String) -> Result<Option<String>, StoreFailureContractError> {
    if value.is_empty() {
        return Ok(None);
    }
    if value.len() > MAX_STORE_FAILURE_DETAIL_LEN || value.chars().any(char::is_control) {
        return Err(invalid(
            "human_detail",
            "legacy detail exceeds the bounded safe surface",
        ));
    }
    Ok(Some(value))
}

/// Errors raised while constructing or validating the typed failure contract.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum StoreFailureContractError {
    #[error("store failure contract field {field}: {reason}")]
    Invalid {
        field: &'static str,
        reason: &'static str,
    },
    #[error("unknown outcome requires an exact operation identity")]
    MissingOperationIdentity,
}
