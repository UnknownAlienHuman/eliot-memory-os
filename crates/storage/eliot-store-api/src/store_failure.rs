//! Provider-neutral, recovery-safe failures for the store wire.

use std::fmt;

use eliot_contracts::{OperationId, RequestId, StateFence};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

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

/// Small stable control axis for a store failure.
#[derive(
    Clone, Copy, Debug, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum StoreFailureDisposition {
    DeterministicRejection,
    Conflict,
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
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum StoreMutationDisposition {
    NotAttempted,
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
        )
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
    pub retry_after_ms: Option<u64>,
    pub evidence_ref: Option<String>,
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
            && self.evidence_ref == other.evidence_ref
    }
}

impl Eq for StoreFailure {}

impl StoreFailure {
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
            && (delay > MAX_STORE_FAILURE_RETRY_AFTER_MS
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
                "retry delay requires a retryable disposition and retry directive",
            ));
        }

        if self.mutation_disposition == StoreMutationDisposition::Committed {
            return Err(invalid(
                "mutation_disposition",
                "committed outcome requires a WriteReceipt",
            ));
        }
        if self.disposition == StoreFailureDisposition::DeterministicRejection
            && self.mutation_disposition != StoreMutationDisposition::NotAttempted
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

    /// Converts the complete current `StoreError` set without wildcard collapse.
    #[allow(clippy::too_many_lines)]
    #[allow(clippy::needless_pass_by_value)]
    pub fn from_store_error(
        error: crate::StoreError,
        context: StoreFailureIdentityContext,
    ) -> Result<Self, StoreFailureContractError> {
        use crate::StoreError;

        let mut failure = Self::base(&context);
        let (disposition, reason_code, mutation, retry, recovery) = match &error {
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
            ),
            StoreError::RevisionConflict => conflict(
                "REVISION_CONFLICT",
                StoreRecoveryAction::RefreshRevisionHeads,
            ),
            StoreError::OrderingConflict => conflict(
                "ORDERING_CONFLICT",
                StoreRecoveryAction::RefreshRevisionHeads,
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
            ),
            StoreError::ReceiptNotFound => (
                StoreFailureDisposition::DeterministicRejection,
                "RECEIPT_NOT_FOUND",
                StoreMutationDisposition::NotAttempted,
                StoreRetryDirective::DoNotRetry,
                StoreRecoveryAction::ResolveWriteReceipt,
            ),
            StoreError::MissingReceiptEnvelope => {
                if failure.operation_id.is_none() {
                    return Err(StoreFailureContractError::MissingOperationIdentity);
                }
                (
                    StoreFailureDisposition::UnknownOutcome,
                    "RECEIPT_ENVELOPE_MISSING",
                    StoreMutationDisposition::Unknown,
                    StoreRetryDirective::ReconcileExactOperation,
                    StoreRecoveryAction::ReconcileUnknownOutcome,
                )
            }
            StoreError::PayloadTooLarge => deterministic("PAYLOAD_TOO_LARGE"),
            StoreError::Unavailable => (
                StoreFailureDisposition::Unavailable,
                "STORE_UNAVAILABLE",
                StoreMutationDisposition::NotAttempted,
                StoreRetryDirective::RetrySameIdentityAfterBackoff,
                StoreRecoveryAction::RestoreStoreConnectivity,
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
            evidence_ref: context.evidence_ref.clone(),
            human_detail: None,
        }
    }
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
) {
    (
        StoreFailureDisposition::DeterministicRejection,
        reason,
        StoreMutationDisposition::NotAttempted,
        StoreRetryDirective::DoNotRetry,
        StoreRecoveryAction::None,
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
) {
    (
        StoreFailureDisposition::Unsupported,
        reason,
        StoreMutationDisposition::NotAttempted,
        StoreRetryDirective::DoNotRetry,
        StoreRecoveryAction::None,
    )
}

fn conflict(
    reason: &'static str,
    recovery: StoreRecoveryAction,
) -> (
    StoreFailureDisposition,
    &'static str,
    StoreMutationDisposition,
    StoreRetryDirective,
    StoreRecoveryAction,
) {
    (
        StoreFailureDisposition::Conflict,
        reason,
        StoreMutationDisposition::NotAttempted,
        StoreRetryDirective::NewIdentityAfterCondition,
        recovery,
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
) {
    (
        StoreFailureDisposition::InternalDefect,
        reason,
        StoreMutationDisposition::NotAttempted,
        StoreRetryDirective::ManualRecovery,
        StoreRecoveryAction::EscalateInternalDefect,
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
