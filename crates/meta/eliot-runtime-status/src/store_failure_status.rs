//! Read-only typed store-failure status projection.
//!
//! This module projects owner-neutral [`StoreFailure`] values into a
//! fail-closed status shape with a writer-readiness denominator. Every field
//! is copied or derived from the typed contract inputs; diagnostic prose
//! never drives control flow, and a failure never reports a healthy state.

use eliot_store_api::{
    MAX_STORE_FAILURE_REFERENCE_LEN, OperationId, STORE_FAILURE_CONTRACT_REVISION,
    StoreConflictObservation, StoreFailure, StoreFailureDisposition, StoreMutationDisposition,
    StoreReasonCode, StoreRecoveryAction, StoreRetryDirective,
};

use crate::ComponentState;

/// Maximum number of blocking operation references retained by the
/// writer-readiness denominator.
pub const MAX_BLOCKING_OPERATION_REFS: usize = 256;

/// Read-only projection of one typed store failure.
#[derive(Debug, Clone)]
pub struct StoreFailureStatusProjection {
    pub disposition: StoreFailureDisposition,
    pub reason_code: StoreReasonCode,
    pub operation_id: Option<OperationId>,
    pub mutation_disposition: StoreMutationDisposition,
    pub retry_directive: StoreRetryDirective,
    pub recovery_action: StoreRecoveryAction,
    pub conflict: Option<StoreConflictObservation>,
    pub retry_after_ms: Option<u64>,
    pub evidence_ref: Option<String>,
    pub owner: &'static str,
    pub next_safe_action: &'static str,
    pub blocks_writer_readiness: bool,
    pub component_state: ComponentState,
}

/// Errors raised while projecting a typed store failure.
#[derive(Debug, Clone, PartialEq)]
pub enum StoreFailureStatusError {
    InvalidRevision,
    ContractRejected,
}

impl std::fmt::Display for StoreFailureStatusError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidRevision => f.write_str("unsupported store failure contract revision"),
            Self::ContractRejected => f.write_str("store failure contract rejected"),
        }
    }
}

impl std::error::Error for StoreFailureStatusError {}

fn next_safe_action_for(
    retry_directive: StoreRetryDirective,
    recovery_action: StoreRecoveryAction,
) -> &'static str {
    match (retry_directive, recovery_action) {
        (StoreRetryDirective::ReconcileExactOperation, _) => {
            "reconcile exact operation by receipt before any retry"
        }
        (StoreRetryDirective::QueryReceipt, _) => "query write receipt for the exact operation",
        (StoreRetryDirective::RetrySameIdentityAfterBackoff, _) => {
            "retry same identity after backoff"
        }
        (StoreRetryDirective::NewIdentityAfterCondition, _) => {
            "new identity after condition clears"
        }
        (StoreRetryDirective::MigrateThenRetryNewIdentity, _) => {
            "migrate then retry with new identity"
        }
        (StoreRetryDirective::ManualRecovery, _) => "enter manual recovery",
        (
            StoreRetryDirective::DoNotRetry,
            StoreRecoveryAction::EnterManualRecovery | StoreRecoveryAction::EscalateInternalDefect,
        ) => "enter manual recovery",
        (StoreRetryDirective::DoNotRetry, StoreRecoveryAction::ResolveWriteReceipt) => {
            "query write receipt for the exact operation"
        }
        (StoreRetryDirective::DoNotRetry, _) => "do not retry without operator review",
    }
}

fn blocks_writer_readiness_for(
    disposition: StoreFailureDisposition,
    mutation_disposition: StoreMutationDisposition,
    retry_directive: StoreRetryDirective,
) -> bool {
    matches!(disposition, StoreFailureDisposition::UnknownOutcome)
        || matches!(mutation_disposition, StoreMutationDisposition::Unknown)
        || matches!(
            retry_directive,
            StoreRetryDirective::ReconcileExactOperation
        )
}

fn derive_component_state(
    disposition: StoreFailureDisposition,
    reason_code: &StoreReasonCode,
    evidence_ref: Option<String>,
) -> ComponentState {
    let reason = reason_code.as_str().to_owned();
    match disposition {
        StoreFailureDisposition::UnknownOutcome => ComponentState::Unknown {
            reason,
            gap: evidence_ref.unwrap_or_else(|| "reconcile exact operation".to_owned()),
        },
        StoreFailureDisposition::Unavailable
        | StoreFailureDisposition::Backpressured
        | StoreFailureDisposition::DeadlineExceeded => ComponentState::Unavailable { reason },
        StoreFailureDisposition::InternalDefect => ComponentState::Corrupt { reason },
        StoreFailureDisposition::Conflict
        | StoreFailureDisposition::DeterministicRejection
        | StoreFailureDisposition::Unsupported
        | StoreFailureDisposition::MigrationRequired => ComponentState::NotHealthy { reason },
    }
}

/// Projects one typed store failure into its read-only status shape.
pub fn project_store_failure(
    failure: &StoreFailure,
) -> Result<StoreFailureStatusProjection, StoreFailureStatusError> {
    if failure.contract_revision.as_str() != STORE_FAILURE_CONTRACT_REVISION {
        return Err(StoreFailureStatusError::InvalidRevision);
    }
    failure
        .validate()
        .map_err(|_| StoreFailureStatusError::ContractRejected)?;
    // Bounded evidence identity only. The length bound mirrors
    // `MAX_STORE_FAILURE_REFERENCE_LEN` from the store failure contract;
    // values carrying control characters are rejected as unprojectable.
    let evidence_ref = match failure.evidence_ref.clone() {
        Some(value) => {
            if value.len() > MAX_STORE_FAILURE_REFERENCE_LEN {
                return Err(StoreFailureStatusError::ContractRejected);
            }
            if value.chars().any(char::is_control) {
                return Err(StoreFailureStatusError::ContractRejected);
            }
            Some(value)
        }
        None => None,
    };
    let disposition = failure.disposition;
    let mutation_disposition = failure.mutation_disposition;
    let retry_directive = failure.retry_directive;
    let recovery_action = failure.recovery_action;
    let next_safe_action = next_safe_action_for(retry_directive, recovery_action);
    let blocks_writer_readiness =
        blocks_writer_readiness_for(disposition, mutation_disposition, retry_directive);
    let component_state =
        derive_component_state(disposition, &failure.reason_code, evidence_ref.clone());
    Ok(StoreFailureStatusProjection {
        disposition,
        reason_code: failure.reason_code.clone(),
        operation_id: failure.operation_id.clone(),
        mutation_disposition,
        retry_directive,
        recovery_action,
        conflict: failure.conflict.clone(),
        retry_after_ms: failure.retry_after_ms,
        evidence_ref,
        owner: "store",
        next_safe_action,
        blocks_writer_readiness,
        component_state,
    })
}

/// Maps a projected store failure to its fail-closed component state.
pub fn component_state_for(projection: &StoreFailureStatusProjection) -> ComponentState {
    derive_component_state(
        projection.disposition,
        &projection.reason_code,
        projection.evidence_ref.clone(),
    )
}

/// Writer-readiness denominator over one batch of typed store failures.
#[derive(Debug, Clone)]
pub struct WriterReadinessDenominator {
    pub total: usize,
    pub blocking_operation_refs: Vec<String>,
    pub ready: bool,
}

/// Derives the writer-readiness denominator from typed failure inputs.
///
/// Blocking membership is derived from the typed disposition, mutation and
/// retry fields through the same matches used by [`project_store_failure`].
/// Entries that fail contract validation still count toward the total and
/// force the denominator closed. Unidentified blocking entries count toward
/// the total and force the denominator closed without inventing references.
/// Retained references are capped at [`MAX_BLOCKING_OPERATION_REFS`], keeping
/// the first entries; truncation forces the denominator closed.
pub fn writer_readiness_denominator<'a>(
    failures: impl IntoIterator<Item = &'a StoreFailure>,
) -> WriterReadinessDenominator {
    let mut total: usize = 0;
    let mut blocking_operation_refs: Vec<String> = Vec::new();
    let mut unidentified_blocking = false;
    let mut truncated = false;
    let mut contract_rejected = false;
    for failure in failures {
        total = total.saturating_add(1);
        if failure.validate().is_err() {
            contract_rejected = true;
        }
        let blocking = blocks_writer_readiness_for(
            failure.disposition,
            failure.mutation_disposition,
            failure.retry_directive,
        );
        if !blocking {
            continue;
        }
        match failure.operation_id.as_ref() {
            Some(operation_id) => {
                if blocking_operation_refs.len() >= MAX_BLOCKING_OPERATION_REFS {
                    truncated = true;
                } else {
                    blocking_operation_refs.push(operation_id.as_str().to_owned());
                }
            }
            None => {
                unidentified_blocking = true;
            }
        }
    }
    let ready = total == 0
        || (blocking_operation_refs.is_empty()
            && !unidentified_blocking
            && !truncated
            && !contract_rejected);
    WriterReadinessDenominator {
        total,
        blocking_operation_refs,
        ready,
    }
}
