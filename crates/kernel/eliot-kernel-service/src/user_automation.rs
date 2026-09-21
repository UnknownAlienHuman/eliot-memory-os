//! Authenticated UserAutomation operator orchestration.
//!
//! This module is a stateless service over the existing canonical Store and
//! Durable Job/WakeIntent owners. It validates the authenticated request and
//! the Store's typed response, then returns the exact response to the Kernel
//! route. It owns no revisions, scheduler, job journal, authority, outbox or
//! notification state.

use std::collections::BTreeSet;

use eliot_contracts::{ContractVersion, RequestMetadata, StateFence};
use eliot_kernel_core::user_automation::UserAutomationExecutionProjection;
use eliot_kernel_core::{
    UserAutomationConfigurationState, UserAutomationError, UserAutomationFailureProjection,
    UserAutomationInvocation, UserAutomationOperation, UserAutomationOperatorIntent,
    UserAutomationRevision,
};
use eliot_runtime_contracts::{WakeIntent, WakeIntentState};
use eliot_store_api::{
    OperationId, OperationIdentity, StoreError, WriteReceipt, WriteReceiptStatus,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Stable service contract identity.
pub const USER_AUTOMATION_SERVICE_CONTRACT_NAME: &str = "eliot.kernel.user-automation.service";
/// Current service contract revision.
pub const USER_AUTOMATION_SERVICE_CONTRACT_VERSION: ContractVersion = ContractVersion::new(1, 0, 0);

/// Errors raised before a UserAutomation service response can be returned.
#[derive(Debug, Error)]
pub enum UserAutomationServiceError {
    /// A request or response failed the closed UserAutomation contract.
    #[error("UserAutomation service contract: {0}")]
    Contract(#[from] UserAutomationError),
    /// The authenticated request metadata is invalid.
    #[error("UserAutomation request metadata is invalid: {0}")]
    Metadata(String),
    /// The operation identity or canonical Store response is invalid.
    #[error("UserAutomation Store contract: {0}")]
    Store(#[from] StoreError),
    /// The presented principal did not bind to the operator intent.
    #[error("UserAutomation principal does not bind to the operator intent")]
    PrincipalMismatch,
    /// The presented State Fence did not bind to the operator intent/response.
    #[error("UserAutomation State Fence mismatch")]
    FenceMismatch,
    /// The Store response was not for the exact admitted operation.
    #[error("UserAutomation Store response identity mismatch")]
    IdentityMismatch,
    /// The Store response had a closed-shape or operation/result mismatch.
    #[error("UserAutomation Store response mismatch: {0}")]
    ResponseMismatch(&'static str),
}

/// Authenticated service request constructed by the Kernel front door.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserAutomationServiceRequest {
    /// Live authenticated request metadata.
    pub context: RequestMetadata,
    /// Principal authenticated by the Kernel/Host route.
    pub authenticated_principal: String,
    /// Exact retry identity admitted by the caller boundary.
    pub identity: OperationIdentity,
    /// Closed operator operation.
    pub intent: UserAutomationOperatorIntent,
}

impl UserAutomationServiceRequest {
    /// Validates the authenticated request before it reaches the Store.
    pub fn validate(&self) -> Result<(), UserAutomationServiceError> {
        self.context
            .validate()
            .map_err(|error| UserAutomationServiceError::Metadata(error.to_string()))?;
        self.identity.validate()?;
        self.intent.validate()?;
        validate_text(&self.authenticated_principal, "authenticated_principal")?;
        if self.intent.state_fence != self.context.state_fence {
            return Err(UserAutomationServiceError::FenceMismatch);
        }
        if self.intent.principal_ref != self.authenticated_principal {
            return Err(UserAutomationServiceError::PrincipalMismatch);
        }
        Ok(())
    }

    fn store_request(&self) -> UserAutomationStoreRequest {
        UserAutomationStoreRequest {
            context: self.context.clone(),
            identity: self.identity.clone(),
            intent: self.intent.clone(),
        }
    }
}

/// Exact request passed to the existing canonical Store adapter.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserAutomationStoreRequest {
    /// Request metadata bound to the active State Fence.
    pub context: RequestMetadata,
    /// Canonical Store operation/idempotency/request identity.
    pub identity: OperationIdentity,
    /// Closed UserAutomation operation selected by the authenticated caller.
    pub intent: UserAutomationOperatorIntent,
}

impl UserAutomationStoreRequest {
    /// Validates the Store-facing request without granting authority.
    pub fn validate(&self) -> Result<(), UserAutomationServiceError> {
        self.context
            .validate()
            .map_err(|error| UserAutomationServiceError::Metadata(error.to_string()))?;
        self.identity.validate()?;
        self.intent.validate()?;
        if self.intent.state_fence != self.context.state_fence {
            return Err(UserAutomationServiceError::FenceMismatch);
        }
        Ok(())
    }
}

/// Read projections returned by the canonical UserAutomation owner.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum UserAutomationReadResult {
    /// Current revisions visible to the authenticated operator.
    List {
        /// Canonical revision projections.
        revisions: Vec<UserAutomationRevision>,
    },
    /// Current configuration and execution projection.
    Status {
        /// Current immutable revision.
        revision: UserAutomationRevision,
        /// Projection into the existing Durable Job/history owner.
        execution: UserAutomationExecutionProjection,
    },
    /// Immutable execution/history projection.
    History {
        /// Automation selected by the query.
        automation_id: String,
        /// Execution and reconciliation references retained by the owner.
        execution: UserAutomationExecutionProjection,
    },
    /// Last owner-issued failure, with its revision binding.
    InspectLastFailure {
        /// Automation selected by the query.
        automation_id: String,
        /// Revision that owns the failure class.
        revision: UserAutomationRevision,
        /// No failure means no notification is manufactured by this service.
        failure: Option<UserAutomationFailureProjection>,
    },
}

/// Mutation projections returned by the canonical UserAutomation owner.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum UserAutomationMutationResult {
    /// Result for create/edit/pause/resume/remove.
    Revision {
        /// Canonical revision after the requested operation.
        revision: UserAutomationRevision,
        /// Future, unadmitted wakes cancelled by remove.
        cancelled_wake_ids: Vec<String>,
    },
    /// Result for run-now using one explicit manual nonce.
    RunNow {
        /// Canonical invocation selected by the owner.
        invocation: UserAutomationInvocation,
        /// Existing inert wake projection for the occurrence.
        wake_intent: WakeIntent,
    },
}

/// Closed Store response disposition.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum UserAutomationStoreOutcome {
    /// Read-only owner projection; no write receipt is allowed.
    Read {
        /// Typed read projection.
        result: UserAutomationReadResult,
    },
    /// Newly committed canonical mutation.
    Committed {
        /// Store-issued receipt envelope and durable identity.
        receipt: WriteReceipt,
        /// Typed mutation projection.
        result: UserAutomationMutationResult,
    },
    /// Exact replay of the same canonical mutation identity.
    Replayed {
        /// Original Store-issued receipt envelope and durable identity.
        receipt: WriteReceipt,
        /// Typed mutation projection.
        result: UserAutomationMutationResult,
    },
}

/// Exact response returned by the canonical Store adapter.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserAutomationStoreResponse {
    /// Echo of the exact request identity answered by the Store.
    pub identity: OperationIdentity,
    /// Fence under which the projection/receipt was observed.
    pub state_fence: StateFence,
    /// Closed Store outcome.
    pub outcome: UserAutomationStoreOutcome,
}

/// Adapter over the existing CanonicalStoreClient.
///
/// Implementations must use the existing Store named-operation/transaction
/// and receipt paths. This port is a service seam, not a second persistence
/// or lifecycle owner.
#[allow(async_fn_in_trait)]
pub trait UserAutomationStorePort: Send + Sync {
    /// Executes one authenticated UserAutomation read or mutation.
    async fn execute_user_automation(
        &self,
        request: UserAutomationStoreRequest,
    ) -> Result<UserAutomationStoreResponse, StoreError>;

    /// Looks up one exact operation identity for I14.21 reconciliation.
    async fn receipt(&self, operation_id: OperationId) -> Result<Option<WriteReceipt>, StoreError>;
}

/// Stateless UserAutomation service over one canonical Store port.
pub struct UserAutomationService<'a, P: ?Sized> {
    port: &'a P,
}

impl<'a, P: UserAutomationStorePort + ?Sized> UserAutomationService<'a, P> {
    /// Binds the service to the already-composed canonical Store adapter.
    #[must_use]
    pub const fn new(port: &'a P) -> Self {
        Self { port }
    }

    /// Validates and executes one authenticated operator operation.
    pub async fn dispatch(
        &self,
        request: UserAutomationServiceRequest,
    ) -> Result<UserAutomationStoreResponse, UserAutomationServiceError> {
        request.validate()?;
        let store_request = request.store_request();
        store_request.validate()?;
        let response = self.port.execute_user_automation(store_request).await?;
        validate_response(&request, &response)?;
        Ok(response)
    }

    /// Reconciles one exact Store operation after an uncertain response.
    ///
    /// A missing receipt remains unresolved. The service never resubmits the
    /// operation and never converts a transport failure into success.
    pub async fn reconcile(
        &self,
        context: &RequestMetadata,
        identity: &OperationIdentity,
    ) -> Result<Option<WriteReceipt>, UserAutomationServiceError> {
        context
            .validate()
            .map_err(|error| UserAutomationServiceError::Metadata(error.to_string()))?;
        identity.validate()?;
        let Some(receipt) = self.port.receipt(identity.operation_id.clone()).await? else {
            return Ok(None);
        };
        validate_receipt(identity, &context.state_fence, &receipt)?;
        Ok(Some(receipt))
    }
}

fn validate_response(
    request: &UserAutomationServiceRequest,
    response: &UserAutomationStoreResponse,
) -> Result<(), UserAutomationServiceError> {
    if response.identity != request.identity {
        return Err(UserAutomationServiceError::IdentityMismatch);
    }
    if response.state_fence != request.context.state_fence {
        return Err(UserAutomationServiceError::FenceMismatch);
    }

    match &response.outcome {
        UserAutomationStoreOutcome::Read { result } => {
            if !is_read_operation(&request.intent.operation) {
                return Err(UserAutomationServiceError::ResponseMismatch(
                    "read response for mutation",
                ));
            }
            validate_read_result(
                &request.intent.operation,
                result,
                &request.context.state_fence,
            )
        }
        UserAutomationStoreOutcome::Committed { receipt, result }
        | UserAutomationStoreOutcome::Replayed { receipt, result } => {
            if is_read_operation(&request.intent.operation) {
                return Err(UserAutomationServiceError::ResponseMismatch(
                    "mutation response for read",
                ));
            }
            validate_receipt(&request.identity, &request.context.state_fence, receipt)?;
            validate_mutation_result(&request.intent.operation, result)
        }
    }
}

fn is_read_operation(operation: &UserAutomationOperation) -> bool {
    matches!(
        operation,
        UserAutomationOperation::List { .. }
            | UserAutomationOperation::Status { .. }
            | UserAutomationOperation::History { .. }
            | UserAutomationOperation::InspectLastFailure { .. }
    )
}

fn validate_read_result(
    operation: &UserAutomationOperation,
    result: &UserAutomationReadResult,
    state_fence: &StateFence,
) -> Result<(), UserAutomationServiceError> {
    match (operation, result) {
        (UserAutomationOperation::List { .. }, UserAutomationReadResult::List { revisions }) => {
            let mut identities = BTreeSet::new();
            for revision in revisions {
                revision.validate()?;
                if !identities.insert((revision.automation_id.clone(), revision.revision.clone())) {
                    return Err(UserAutomationServiceError::ResponseMismatch(
                        "duplicate revision in list",
                    ));
                }
            }
            Ok(())
        }
        (
            UserAutomationOperation::Status { automation_id },
            UserAutomationReadResult::Status {
                revision,
                execution,
            },
        ) => {
            revision.validate()?;
            execution.validate()?;
            if &revision.automation_id != automation_id {
                return Err(UserAutomationServiceError::ResponseMismatch(
                    "status automation identity",
                ));
            }
            Ok(())
        }
        (
            UserAutomationOperation::History { automation_id },
            UserAutomationReadResult::History {
                automation_id: response_id,
                execution,
            },
        ) => {
            execution.validate()?;
            if response_id != automation_id {
                return Err(UserAutomationServiceError::ResponseMismatch(
                    "history automation identity",
                ));
            }
            Ok(())
        }
        (
            UserAutomationOperation::InspectLastFailure { automation_id },
            UserAutomationReadResult::InspectLastFailure {
                automation_id: response_id,
                revision,
                failure,
            },
        ) => {
            revision.validate()?;
            if response_id != automation_id || &revision.automation_id != automation_id {
                return Err(UserAutomationServiceError::ResponseMismatch(
                    "failure automation identity",
                ));
            }
            if let Some(failure) = failure {
                failure.validate(revision, state_fence)?;
            }
            Ok(())
        }
        _ => Err(UserAutomationServiceError::ResponseMismatch(
            "read result kind",
        )),
    }
}

fn validate_mutation_result(
    operation: &UserAutomationOperation,
    result: &UserAutomationMutationResult,
) -> Result<(), UserAutomationServiceError> {
    match (operation, result) {
        (
            UserAutomationOperation::Create { revision: expected },
            UserAutomationMutationResult::Revision {
                revision,
                cancelled_wake_ids,
            },
        ) => {
            expected.validate()?;
            revision.validate()?;
            if expected != revision
                || revision.supersedes.is_some()
                || !cancelled_wake_ids.is_empty()
            {
                return Err(UserAutomationServiceError::ResponseMismatch(
                    "create revision result",
                ));
            }
            Ok(())
        }
        (
            UserAutomationOperation::Edit {
                previous_revision,
                revision: expected,
            },
            UserAutomationMutationResult::Revision {
                revision,
                cancelled_wake_ids,
            },
        ) => {
            expected.validate_supersedes(previous_revision)?;
            revision.validate_supersedes(previous_revision)?;
            if expected != revision || !cancelled_wake_ids.is_empty() {
                return Err(UserAutomationServiceError::ResponseMismatch(
                    "edit revision result",
                ));
            }
            Ok(())
        }
        (
            UserAutomationOperation::Pause {
                automation_id,
                automation_revision,
            },
            UserAutomationMutationResult::Revision {
                revision,
                cancelled_wake_ids,
            },
        ) => validate_state_transition(
            revision,
            automation_id,
            automation_revision,
            UserAutomationConfigurationState::Paused,
            cancelled_wake_ids,
        ),
        (
            UserAutomationOperation::Resume {
                automation_id,
                automation_revision,
            },
            UserAutomationMutationResult::Revision {
                revision,
                cancelled_wake_ids,
            },
        ) => validate_state_transition(
            revision,
            automation_id,
            automation_revision,
            UserAutomationConfigurationState::Active,
            cancelled_wake_ids,
        ),
        (
            UserAutomationOperation::Remove {
                automation_id,
                automation_revision,
            },
            UserAutomationMutationResult::Revision {
                revision,
                cancelled_wake_ids,
            },
        ) => {
            revision.validate()?;
            if revision.automation_id != *automation_id
                || revision.revision != *automation_revision
                || revision.configuration_state != UserAutomationConfigurationState::Retired
            {
                return Err(UserAutomationServiceError::ResponseMismatch(
                    "remove revision result",
                ));
            }
            validate_text_list(cancelled_wake_ids, "cancelled_wake_ids")
        }
        (
            UserAutomationOperation::RunNow {
                automation_id,
                automation_revision,
                nonce,
            },
            UserAutomationMutationResult::RunNow {
                invocation,
                wake_intent,
            },
        ) => {
            invocation.validate()?;
            if invocation.automation_id != *automation_id
                || invocation.automation_revision != *automation_revision
                || invocation.trigger
                    != (eliot_kernel_core::UserAutomationTrigger::Manual {
                        nonce: nonce.clone(),
                    })
                || invocation.trigger_origin
                    != eliot_kernel_core::UserAutomationTriggerOrigin::Human
                || invocation.occurrence_identity()? != wake_intent.wake_id
            {
                return Err(UserAutomationServiceError::ResponseMismatch(
                    "run-now invocation identity",
                ));
            }
            wake_intent
                .validate()
                .map_err(|_| UserAutomationServiceError::ResponseMismatch("wake intent shape"))?;
            if wake_intent.state != WakeIntentState::Pending {
                return Err(UserAutomationServiceError::ResponseMismatch(
                    "run-now wake state",
                ));
            }
            Ok(())
        }
        _ => Err(UserAutomationServiceError::ResponseMismatch(
            "mutation result kind",
        )),
    }
}

fn validate_state_transition(
    revision: &UserAutomationRevision,
    automation_id: &str,
    automation_revision: &str,
    expected_state: UserAutomationConfigurationState,
    cancelled_wake_ids: &[String],
) -> Result<(), UserAutomationServiceError> {
    revision.validate()?;
    if revision.automation_id != automation_id
        || revision.revision != automation_revision
        || revision.configuration_state != expected_state
        || !cancelled_wake_ids.is_empty()
    {
        return Err(UserAutomationServiceError::ResponseMismatch(
            "configuration state transition",
        ));
    }
    Ok(())
}

fn validate_receipt(
    identity: &OperationIdentity,
    state_fence: &StateFence,
    receipt: &WriteReceipt,
) -> Result<(), UserAutomationServiceError> {
    receipt.validate()?;
    if receipt.operation_id != identity.operation_id
        || receipt.idempotency_key != identity.idempotency_key
        || receipt.canonical_request_hash != identity.canonical_request_hash
        || receipt.state_fence != *state_fence
        || receipt.status != WriteReceiptStatus::Committed
    {
        return Err(UserAutomationServiceError::IdentityMismatch);
    }
    receipt.require_reconciliation_envelope()?;
    Ok(())
}

fn validate_text(value: &str, field: &'static str) -> Result<(), UserAutomationServiceError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(UserAutomationServiceError::Contract(
            UserAutomationError::Invalid(field),
        ));
    }
    Ok(())
}

fn validate_text_list(
    values: &[String],
    field: &'static str,
) -> Result<(), UserAutomationServiceError> {
    let mut unique = BTreeSet::new();
    for value in values {
        validate_text(value, field)?;
        if !unique.insert(value) {
            return Err(UserAutomationServiceError::ResponseMismatch(
                "duplicate list item",
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use eliot_contracts::{
        ClockReading, EpochId, EpochLineageId, ProductId, RequestId, ResourceGeneration, SourceId,
    };
    use std::num::NonZeroU64;
    use std::sync::{Arc, Mutex};

    fn fence() -> StateFence {
        let epoch = EpochId::new(
            EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000").expect("lineage"),
            NonZeroU64::new(1).expect("sequence"),
        )
        .expect("epoch");
        StateFence::new(epoch, ResourceGeneration::genesis())
    }

    fn request() -> UserAutomationServiceRequest {
        let state_fence = fence();
        let context = RequestMetadata {
            request_id: RequestId::new("user-automation-request").expect("request id"),
            session_id: None,
            task_id: None,
            product_id: ProductId::new("eliot-test").expect("product"),
            source_id: SourceId::new("eliot-user-automation").expect("source"),
            state_fence: state_fence.clone(),
            clock: ClockReading {
                valid_time_ms: Some(1),
                known_time_ms: Some(1),
                transaction_sequence: None,
                monotonic_ns: Some(1),
            },
        };
        let identity = OperationIdentity {
            operation_id: OperationId::new("user-automation-operation").expect("operation id"),
            idempotency_key: "user-automation-idempotency".to_owned(),
            canonical_request_hash: "a".repeat(64),
        };
        UserAutomationServiceRequest {
            context,
            authenticated_principal: "human-1".to_owned(),
            identity,
            intent: UserAutomationOperatorIntent {
                intent_id: "intent-1".to_owned(),
                principal_ref: "human-1".to_owned(),
                state_fence,
                operation: UserAutomationOperation::List {
                    include_retired: false,
                },
            },
        }
    }

    #[derive(Clone)]
    struct ScriptedPort {
        response: UserAutomationStoreResponse,
        seen: Arc<Mutex<Option<UserAutomationStoreRequest>>>,
    }

    #[allow(async_fn_in_trait)]
    impl UserAutomationStorePort for ScriptedPort {
        async fn execute_user_automation(
            &self,
            request: UserAutomationStoreRequest,
        ) -> Result<UserAutomationStoreResponse, StoreError> {
            *self.seen.lock().expect("seen lock") = Some(request);
            Ok(self.response.clone())
        }

        async fn receipt(
            &self,
            _operation_id: OperationId,
        ) -> Result<Option<WriteReceipt>, StoreError> {
            Ok(None)
        }
    }

    #[tokio::test]
    async fn dispatch_binds_authenticated_intent_and_rejects_foreign_response() {
        let request = request();
        let seen = Arc::new(Mutex::new(None));
        let port = ScriptedPort {
            response: UserAutomationStoreResponse {
                identity: request.identity.clone(),
                state_fence: request.context.state_fence.clone(),
                outcome: UserAutomationStoreOutcome::Read {
                    result: UserAutomationReadResult::List {
                        revisions: Vec::new(),
                    },
                },
            },
            seen: seen.clone(),
        };
        let service = UserAutomationService::new(&port);
        service
            .dispatch(request.clone())
            .await
            .expect("exact response is accepted");
        let observed = seen.lock().expect("seen lock").clone().expect("request");
        assert_eq!(observed.identity, request.identity);
        assert_eq!(observed.intent, request.intent);

        let mut foreign_response = port.response.clone();
        foreign_response.identity.operation_id =
            OperationId::new("foreign-operation").expect("foreign operation id");
        let foreign_port = ScriptedPort {
            response: foreign_response,
            seen: Arc::new(Mutex::new(None)),
        };
        let error = UserAutomationService::new(&foreign_port)
            .dispatch(request)
            .await
            .expect_err("foreign response must fail closed");
        assert!(matches!(
            error,
            UserAutomationServiceError::IdentityMismatch
        ));
    }
}
