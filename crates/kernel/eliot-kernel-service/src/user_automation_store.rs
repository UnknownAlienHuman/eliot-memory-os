//! Canonical [`UserAutomationStorePort`] backend over the existing
//! canonical Store (issue #1779).
//!
//! This module is the Store-owned adapter the frozen
//! [`UserAutomationService`](super::UserAutomationService) dispatches
//! through. It translates one authenticated
//! [`UserAutomationStoreRequest`] into exactly one admitted
//! [`PreparedTransition`](eliot_store_api::PreparedTransition) (or one
//! closed named read), executes it through the existing
//! [`CanonicalStoreClient`](eliot_store_api::CanonicalStoreClient)
//! named read/transaction/receipt paths, and projects the typed
//! [`UserAutomationStoreResponse`]. It owns no revisions, scheduler, job
//! journal, authority, cache, outbox, or notification state: durability,
//! ordering, and receipts stay with the canonical Store; revision
//! lineage and invocation derivation stay with the Kernel-owned domain;
//! response validation stays with the frozen service.
//!
//! Execution projections compose from the stored revision documents
//! only. Live Durable Job enrichment (resolving
//! `current_execution_refs` strings into typed execution references) is
//! a future join with the Durable Job owner: projections carry empty
//! typed ref lists plus the stored history handle, which the frozen
//! service accepts. Wake cancellation on remove likewise returns empty
//! until the scheduler owner supplies the cancelled identities.

use std::collections::BTreeMap;

use eliot_kernel_core::user_automation::{
    UserAutomationExecutionProjection, UserAutomationInvocation, UserAutomationOperation,
    UserAutomationRevision,
};
use eliot_store_api::{
    CanonicalRequestView, CanonicalStoreClient, NamedReadOperation, NamedReadRequest,
    NamedReadResponse, OrderingScopeId, PreparedTransition, RevisionHead, ScopeId, SecurityContext,
    StateFence, StoreError, TransitionClass, USER_AUTOMATION_SCOPE, WriteReceipt,
    WriteReceiptStatus, automation_create_params, automation_edit_params,
    automation_invocation_read_request, automation_mutation_request, automation_read_request,
    automation_revision_read_request, automation_run_now_params,
    automation_state_transition_params, canonical_json_bytes, canonical_request_hash,
    generated_operation_manifests, operation_manifest_set_digest, sha256_hex,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::{
    UserAutomationMutationResult, UserAutomationReadResult, UserAutomationServiceError,
    UserAutomationStoreOutcome, UserAutomationStorePort, UserAutomationStoreRequest,
    UserAutomationStoreResponse,
};

/// Canonical Store adapter implementing the frozen automation port.
///
/// Generic over any [`CanonicalStoreClient`] so production backends and
/// scripted test doubles share the exact translation path.
#[derive(Clone, Debug)]
pub struct CanonicalUserAutomationStore<C> {
    client: C,
}

/// Kernel-authenticated selector for one production UserAutomation occurrence.
///
/// The daemon contributes only the automation and immutable revision selectors.
/// Kernel supplies the authenticated principal and current State Fence before
/// this value reaches the canonical Store owner. The selector therefore cannot
/// grant authority or replace the owner-issued revision.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserAutomationOwnerLookup {
    /// Stable automation identity selected by the operator trigger.
    pub automation_id: String,
    /// Immutable revision selected by the operator trigger.
    pub requested_revision: String,
    /// Principal copied from the authenticated Kernel session.
    pub authenticated_principal: String,
    /// Current generation fence copied from the authenticated Kernel session.
    pub state_fence: StateFence,
}

impl UserAutomationOwnerLookup {
    /// Validates selector shape and the current owner fence before Store IO.
    pub fn validate(&self) -> Result<(), StoreError> {
        self.state_fence
            .validate()
            .map_err(StoreError::Foundation)?;
        for (value, field) in [
            (&self.automation_id, "automation.automation_id"),
            (&self.requested_revision, "automation.requested_revision"),
            (
                &self.authenticated_principal,
                "automation.authenticated_principal",
            ),
        ] {
            if value.trim().is_empty() || value.chars().any(char::is_control) {
                return Err(StoreError::InvalidField {
                    field,
                    reason: "must be non-blank text",
                });
            }
        }
        Ok(())
    }
}

/// Exact named-read evidence retained beside one owner lookup.
///
/// The payload itself is projected into the typed immutable revision. These
/// fields retain the closed operation, selectors, fence, and response heads so
/// later preflight can prove which canonical read supplied the owner material.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserAutomationNamedReadProvenance {
    /// Closed Store named operation used for the read.
    pub operation: NamedReadOperation,
    /// Exact closed parameters sent to the Store.
    pub parameters: BTreeMap<String, Value>,
    /// Fence placed on the Store request.
    pub request_state_fence: StateFence,
    /// Fence returned by the Store response.
    pub response_state_fence: StateFence,
    /// Store revision heads returned with the named response.
    pub response_revision_heads: Vec<RevisionHead>,
    /// Digest of the complete Store payload returned for this named read.
    ///
    /// Revision heads and the response fence are global observations.  The
    /// payload digest retains the target row/read projection as well, so a
    /// current-pointer revalidation can reject a response race even when the
    /// global head list and StateFence happen to be unchanged.
    pub response_payload_digest: String,
}

/// Provenance for the two canonical reads needed to bind a current revision.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserAutomationOwnerReadProvenance {
    /// First current-pointer read proving the requested revision is current.
    pub current_before: UserAutomationNamedReadProvenance,
    /// History read supplying the immutable revision document.
    pub history: UserAutomationNamedReadProvenance,
    /// Bounded revalidation read proving the pointer stayed unchanged.
    pub current_after: UserAutomationNamedReadProvenance,
}

/// Owner-issued current revision bound to the authenticated principal and fence.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserAutomationOwnerSnapshot {
    /// Stable automation identity.
    pub automation_id: String,
    /// The immutable revision read from canonical history.
    pub revision: UserAutomationRevision,
    /// Live admission state from the current pointer. It may differ from the
    /// immutable revision document after pause/resume and is never written
    /// back into that historical document.
    pub current_configuration_state:
        eliot_kernel_core::user_automation::UserAutomationConfigurationState,
    /// Principal that the revision was checked against.
    pub authenticated_principal: String,
    /// Fence under which both named reads were observed.
    pub state_fence: StateFence,
    /// Exact named-read evidence for the snapshot.
    pub provenance: UserAutomationOwnerReadProvenance,
}

impl<C> CanonicalUserAutomationStore<C> {
    /// Binds the port to the composed canonical Store client.
    pub fn new(client: C) -> Self {
        Self { client }
    }

    /// Builds the exact current-pointer and immutable-history reads for one
    /// authenticated owner lookup. This is the Store owner's only selector
    /// construction path for production occurrence preflight.
    pub fn owner_read_requests(
        lookup: &UserAutomationOwnerLookup,
    ) -> Result<(NamedReadRequest, NamedReadRequest), StoreError> {
        lookup.validate()?;
        let current = automation_revision_read_request(
            QUERY_CURRENT.to_owned(),
            lookup.automation_id.clone(),
            lookup.requested_revision.clone(),
            false,
            1,
            lookup.state_fence.clone(),
        )?;
        let history = automation_revision_read_request(
            QUERY_HISTORY.to_owned(),
            lookup.automation_id.clone(),
            lookup.requested_revision.clone(),
            false,
            1,
            lookup.state_fence.clone(),
        )?;
        Ok((current, history))
    }

    /// Builds the exact invocation read used to recover owner-issued
    /// provenance. The occurrence selector addresses one retained row and
    /// cannot widen into the bounded invocation page.
    pub fn invocation_read_request(
        automation_id: String,
        occurrence_id: String,
        state_fence: StateFence,
    ) -> Result<NamedReadRequest, StoreError> {
        automation_invocation_read_request(automation_id, occurrence_id, state_fence)
    }

    /// Projects one exact owner-issued invocation response.
    pub fn project_invocation(
        automation_id: &str,
        occurrence_id: &str,
        request: &NamedReadRequest,
        response: NamedReadResponse,
    ) -> Result<UserAutomationInvocation, StoreError> {
        let expected = Self::invocation_read_request(
            automation_id.to_owned(),
            occurrence_id.to_owned(),
            request.state_fence.clone(),
        )?;
        if request != &expected {
            return Err(StoreError::IdentityConflict);
        }
        validate_named_response(request, &response)?;
        let entries = response
            .payload
            .get(eliot_store_api::AUTOMATION_PAGE_INVOCATIONS)
            .and_then(Value::as_array)
            .ok_or(StoreError::InvalidField {
                field: "automation.invocations",
                reason: "exact invocation projection malformed",
            })?;
        if entries.len() != 1 {
            return Err(StoreError::InvalidField {
                field: "automation.invocations",
                reason: "exact invocation read is incomplete",
            });
        }
        let entry = &entries[0];
        if entry.get("automation_id").and_then(Value::as_str) != Some(automation_id)
            || entry.get("occurrence_id").and_then(Value::as_str) != Some(occurrence_id)
        {
            return Err(StoreError::IdentityConflict);
        }
        let document = entry.get("invocation_json").and_then(Value::as_str).ok_or(
            StoreError::InvalidField {
                field: "automation.invocation_json",
                reason: "stored invocation document malformed",
            },
        )?;
        let invocation: UserAutomationInvocation = serde_json::from_str(document)
            .map_err(|error| StoreError::Serialization(error.to_string()))?;
        invocation
            .validate()
            .map_err(|_| StoreError::InvalidField {
                field: "automation.invocation",
                reason: "stored invocation failed domain validation",
            })?;
        if invocation.automation_id != automation_id
            || invocation
                .occurrence_identity()
                .map_err(|_| StoreError::InvalidField {
                    field: "automation.occurrence_id",
                    reason: "stored invocation identity failed",
                })?
                != occurrence_id
        {
            return Err(StoreError::IdentityConflict);
        }
        Ok(invocation)
    }

    /// Projects a current/history/current bounded revalidation sequence into
    /// an authenticated owner snapshot. The method performs no Store IO and
    /// never accepts a revision, principal, or fence from response payload as
    /// authority.
    pub fn project_owner_snapshot(
        lookup: &UserAutomationOwnerLookup,
        current_request: &NamedReadRequest,
        current_response: NamedReadResponse,
        history_request: &NamedReadRequest,
        history_response: NamedReadResponse,
        current_after_request: &NamedReadRequest,
        current_after_response: NamedReadResponse,
    ) -> Result<UserAutomationOwnerSnapshot, StoreError> {
        let (expected_current, expected_history) = Self::owner_read_requests(lookup)?;
        if current_request != &expected_current
            || history_request != &expected_history
            || current_after_request != &expected_current
        {
            return Err(StoreError::IdentityConflict);
        }
        validate_owner_named_response(lookup, current_request, &current_response)?;
        validate_owner_named_response(lookup, history_request, &history_response)?;
        validate_owner_named_response(lookup, current_after_request, &current_after_response)?;

        let current_before_payload_digest = canonical_payload_digest(&current_response.payload)?;
        let current_after_payload_digest =
            canonical_payload_digest(&current_after_response.payload)?;
        if current_before_payload_digest != current_after_payload_digest {
            return Err(StoreError::RevisionConflict);
        }
        if current_response.revision_heads != history_response.revision_heads
            || current_response.revision_heads != current_after_response.revision_heads
        {
            return Err(StoreError::RevisionConflict);
        }

        let current = owner_current_row(&current_response)?;
        let current_after = owner_current_row(&current_after_response)?;
        let (current_automation_id, current_revision, current_state) =
            owner_current_fields(current)?;
        let (after_automation_id, after_revision, after_state) =
            owner_current_fields(current_after)?;
        if current_automation_id != after_automation_id
            || current_revision != after_revision
            || current_state != after_state
        {
            return Err(StoreError::RevisionConflict);
        }
        if current_automation_id != lookup.automation_id
            || current_revision != lookup.requested_revision
        {
            return Err(StoreError::InvalidField {
                field: "automation.revision",
                reason: "requested revision is not the current immutable revision",
            });
        }

        let entries = history_response
            .payload
            .get(eliot_store_api::AUTOMATION_PAGE_REVISIONS)
            .and_then(Value::as_array)
            .ok_or(StoreError::InvalidField {
                field: "automation.revisions",
                reason: "owner history projection malformed",
            })?;
        if entries.len() != 1 {
            return Err(StoreError::InvalidField {
                field: "automation.revisions",
                reason: "exact immutable revision read is incomplete",
            });
        }
        let entry = entries
            .iter()
            .find(|entry| {
                entry.get("revision").and_then(Value::as_str)
                    == Some(lookup.requested_revision.as_str())
            })
            .ok_or(StoreError::InvalidField {
                field: "automation.revision",
                reason: "requested immutable revision is not retained",
            })?;
        let document =
            entry
                .get("revision_json")
                .and_then(Value::as_str)
                .ok_or(StoreError::InvalidField {
                    field: "automation.revision_json",
                    reason: "stored owner revision document is malformed",
                })?;
        let revision: UserAutomationRevision = serde_json::from_str(document)
            .map_err(|error| StoreError::Serialization(error.to_string()))?;
        revision.validate().map_err(|_| StoreError::InvalidField {
            field: "automation.revision",
            reason: "stored owner revision failed domain validation",
        })?;
        if revision.automation_id != lookup.automation_id
            || revision.revision != lookup.requested_revision
            || revision.owner_principal != lookup.authenticated_principal
        {
            return Err(StoreError::IdentityConflict);
        }
        Ok(UserAutomationOwnerSnapshot {
            automation_id: lookup.automation_id.clone(),
            revision,
            current_configuration_state: current_state,
            authenticated_principal: lookup.authenticated_principal.clone(),
            state_fence: lookup.state_fence.clone(),
            provenance: UserAutomationOwnerReadProvenance {
                current_before: owner_read_provenance(current_request, &current_response),
                history: owner_read_provenance(history_request, &history_response),
                current_after: owner_read_provenance(
                    current_after_request,
                    &current_after_response,
                ),
            },
        })
    }

    /// Borrows the composed client (test seam only).
    #[cfg(test)]
    pub(crate) fn client(&self) -> &C {
        &self.client
    }
}

fn validate_owner_named_response(
    lookup: &UserAutomationOwnerLookup,
    request: &NamedReadRequest,
    response: &NamedReadResponse,
) -> Result<(), StoreError> {
    validate_named_response(request, response)?;
    let payload_fence = response
        .payload
        .get(eliot_store_api::AUTOMATION_PAGE_STATE_FENCE)
        .cloned()
        .ok_or(StoreError::InvalidField {
            field: "automation.state_fence",
            reason: "owner read omitted its projection fence",
        })?;
    let payload_fence: StateFence =
        serde_json::from_value(payload_fence).map_err(|_| StoreError::InvalidField {
            field: "automation.state_fence",
            reason: "owner read projection fence is malformed",
        })?;
    if payload_fence != lookup.state_fence {
        return Err(StoreError::FenceMismatch);
    }
    Ok(())
}

fn validate_named_response(
    request: &NamedReadRequest,
    response: &NamedReadResponse,
) -> Result<(), StoreError> {
    request.validate()?;
    response.validate()?;
    if response.operation != request.operation || response.state_fence != request.state_fence {
        return Err(StoreError::FenceMismatch);
    }
    let payload_fence = response
        .payload
        .get(eliot_store_api::AUTOMATION_PAGE_STATE_FENCE)
        .cloned()
        .ok_or(StoreError::InvalidField {
            field: "automation.state_fence",
            reason: "owner read omitted its projection fence",
        })?;
    let payload_fence: StateFence =
        serde_json::from_value(payload_fence).map_err(|_| StoreError::InvalidField {
            field: "automation.state_fence",
            reason: "owner read projection fence is malformed",
        })?;
    if payload_fence != request.state_fence {
        return Err(StoreError::FenceMismatch);
    }
    Ok(())
}

fn owner_current_row(response: &NamedReadResponse) -> Result<&Value, StoreError> {
    response
        .payload
        .get(eliot_store_api::AUTOMATION_PAGE_CURRENT)
        .filter(|value| !value.is_null())
        .ok_or(StoreError::InvalidField {
            field: "automation.automation_id",
            reason: "unknown automation",
        })
}

fn owner_current_fields(
    current: &Value,
) -> Result<
    (
        &str,
        &str,
        eliot_kernel_core::user_automation::UserAutomationConfigurationState,
    ),
    StoreError,
> {
    let automation_id =
        current
            .get("automation_id")
            .and_then(Value::as_str)
            .ok_or(StoreError::InvalidField {
                field: "automation.automation_id",
                reason: "current owner row is malformed",
            })?;
    let revision =
        current
            .get("revision")
            .and_then(Value::as_str)
            .ok_or(StoreError::InvalidField {
                field: "automation.revision",
                reason: "current owner row is malformed",
            })?;
    let state = serde_json::from_value(current.get("configuration_state").cloned().ok_or(
        StoreError::InvalidField {
            field: "automation.configuration_state",
            reason: "current owner row is malformed",
        },
    )?)
    .map_err(|_| StoreError::InvalidField {
        field: "automation.configuration_state",
        reason: "current owner state is not closed",
    })?;
    Ok((automation_id, revision, state))
}

fn owner_read_provenance(
    request: &NamedReadRequest,
    response: &NamedReadResponse,
) -> UserAutomationNamedReadProvenance {
    UserAutomationNamedReadProvenance {
        operation: request.operation,
        parameters: request.parameters.clone(),
        request_state_fence: request.state_fence.clone(),
        response_state_fence: response.state_fence.clone(),
        response_revision_heads: response.revision_heads.clone(),
        response_payload_digest: canonical_payload_digest(&response.payload)
            .expect("validated named-read payload must be canonicalizable"),
    }
}

fn canonical_payload_digest(payload: &Value) -> Result<String, StoreError> {
    let bytes = canonical_json_bytes(payload)
        .map_err(|error| StoreError::Serialization(error.to_string()))?;
    Ok(sha256_hex(&bytes))
}

/// Closed automation-state query kinds carried to the store read.
const QUERY_LIST: &str = "list";
/// Closed automation-state query kinds carried to the store read.
const QUERY_CURRENT: &str = "current";
/// Closed automation-state query kinds carried to the store read.
const QUERY_HISTORY: &str = "history";
/// Closed automation-state query kinds carried to the store read.
const QUERY_FAILURE: &str = "failure";

/// Maps a service validation failure onto the closed store error set.
///
/// The frozen service pre-validates every request, so these arms are
/// defense in depth: a malformed request fails here before any Store
/// I/O, never as a committed transition.
fn map_request_error(error: UserAutomationServiceError) -> StoreError {
    match error {
        UserAutomationServiceError::Store(store) => store,
        UserAutomationServiceError::FenceMismatch => StoreError::FenceMismatch,
        UserAutomationServiceError::IdentityMismatch => StoreError::IdentityConflict,
        UserAutomationServiceError::Metadata(_) => StoreError::InvalidField {
            field: "automation.context",
            reason: "request metadata invalid",
        },
        UserAutomationServiceError::PrincipalMismatch => StoreError::InvalidField {
            field: "automation.principal",
            reason: "principal mismatch",
        },
        UserAutomationServiceError::Contract(_) => StoreError::InvalidField {
            field: "automation.operation",
            reason: "operator operation failed validation",
        },
        UserAutomationServiceError::ResponseMismatch(_) => StoreError::InvalidField {
            field: "automation.response",
            reason: "store response mismatch",
        },
    }
}

#[allow(async_fn_in_trait)]
impl<C: CanonicalStoreClient> UserAutomationStorePort for CanonicalUserAutomationStore<C> {
    async fn execute_user_automation(
        &self,
        request: UserAutomationStoreRequest,
    ) -> Result<UserAutomationStoreResponse, StoreError> {
        request.validate().map_err(map_request_error)?;
        match &request.intent.operation {
            UserAutomationOperation::List { .. }
            | UserAutomationOperation::Status { .. }
            | UserAutomationOperation::History { .. }
            | UserAutomationOperation::InspectLastFailure { .. } => {
                self.execute_read(&request).await
            }
            UserAutomationOperation::Create { .. }
            | UserAutomationOperation::Edit { .. }
            | UserAutomationOperation::Pause { .. }
            | UserAutomationOperation::Resume { .. }
            | UserAutomationOperation::Remove { .. }
            | UserAutomationOperation::RunNow { .. } => self.execute_mutation(&request).await,
        }
    }

    async fn receipt(
        &self,
        operation_id: eliot_store_api::OperationId,
    ) -> Result<Option<WriteReceipt>, StoreError> {
        self.client.receipt(operation_id).await
    }
}

impl<C: CanonicalStoreClient> CanonicalUserAutomationStore<C> {
    /// Executes one authenticated read through the closed named read.
    async fn execute_read(
        &self,
        request: &UserAutomationStoreRequest,
    ) -> Result<UserAutomationStoreResponse, StoreError> {
        let outcome = match &request.intent.operation {
            UserAutomationOperation::List { include_retired } => {
                self.read_list_outcome(request, *include_retired).await?
            }
            UserAutomationOperation::Status { automation_id } => {
                self.read_status_outcome(request, automation_id).await?
            }
            UserAutomationOperation::History { automation_id } => {
                self.read_history_outcome(request, automation_id).await?
            }
            UserAutomationOperation::InspectLastFailure { automation_id } => {
                self.read_inspect_outcome(request, automation_id).await?
            }
            _ => {
                return Err(StoreError::UnknownOperation);
            }
        };
        Ok(UserAutomationStoreResponse {
            identity: request.identity.clone(),
            state_fence: request.context.state_fence.clone(),
            outcome,
        })
    }

    /// Projects the list read from current pointers plus their revision
    /// documents.
    async fn read_list_outcome(
        &self,
        request: &UserAutomationStoreRequest,
        include_retired: bool,
    ) -> Result<UserAutomationStoreOutcome, StoreError> {
        let fence = request.context.state_fence.clone();
        let query = automation_read_request(
            QUERY_LIST.to_owned(),
            None,
            include_retired,
            eliot_store_api::MAX_AUTOMATION_PAGE_RECORDS,
            fence.clone(),
        )?;
        let payload = self.client.execute_named(query).await?.payload;
        let currents = payload
            .get(eliot_store_api::AUTOMATION_PAGE_CURRENTS)
            .and_then(Value::as_array)
            .ok_or(StoreError::InvalidField {
                field: "automation.currents",
                reason: "store list projection malformed",
            })?;
        let mut revisions = Vec::with_capacity(currents.len());
        for current in currents {
            let automation_id = current.get("automation_id").and_then(Value::as_str).ok_or(
                StoreError::InvalidField {
                    field: "automation.automation_id",
                    reason: "store list entry malformed",
                },
            )?;
            let revision = current.get("revision").and_then(Value::as_str).ok_or(
                StoreError::InvalidField {
                    field: "automation.revision",
                    reason: "store list entry malformed",
                },
            )?;
            revisions.push(
                self.read_revision_document(&fence, automation_id, revision)
                    .await?,
            );
        }
        Ok(UserAutomationStoreOutcome::Read {
            result: UserAutomationReadResult::List { revisions },
        })
    }

    /// Projects the status read from the current revision row.
    async fn read_status_outcome(
        &self,
        request: &UserAutomationStoreRequest,
        automation_id: &str,
    ) -> Result<UserAutomationStoreOutcome, StoreError> {
        let revision = self.read_current_revision(request, automation_id).await?;
        let execution = Self::execution_projection(&revision)?;
        Ok(UserAutomationStoreOutcome::Read {
            result: UserAutomationReadResult::Status {
                revision,
                execution,
            },
        })
    }

    /// Projects the history read from the revision-row set.
    async fn read_history_outcome(
        &self,
        request: &UserAutomationStoreRequest,
        automation_id: &str,
    ) -> Result<UserAutomationStoreOutcome, StoreError> {
        let fence = request.context.state_fence.clone();
        let query = automation_read_request(
            QUERY_HISTORY.to_owned(),
            Some(automation_id.to_owned()),
            false,
            eliot_store_api::MAX_AUTOMATION_PAGE_RECORDS,
            fence,
        )?;
        let payload = self.client.execute_named(query).await?.payload;
        let entries = payload
            .get(eliot_store_api::AUTOMATION_PAGE_REVISIONS)
            .and_then(Value::as_array)
            .ok_or(StoreError::InvalidField {
                field: "automation.revisions",
                reason: "store history projection malformed",
            })?;
        if entries.is_empty() {
            return Err(StoreError::InvalidField {
                field: "automation.automation_id",
                reason: "unknown automation",
            });
        }
        let execution = UserAutomationExecutionProjection {
            current_execution_refs: Vec::new(),
            unresolved_reconciliation_refs: Vec::new(),
            history_query_ref: format!("automation-history:{automation_id}"),
        };
        execution.validate().map_err(|_| StoreError::InvalidField {
            field: "automation.execution",
            reason: "execution projection invalid",
        })?;
        Ok(UserAutomationStoreOutcome::Read {
            result: UserAutomationReadResult::History {
                automation_id: automation_id.to_owned(),
                execution,
            },
        })
    }

    /// Projects the inspect read from the failure absence plus the bound
    /// current revision.
    async fn read_inspect_outcome(
        &self,
        request: &UserAutomationStoreRequest,
        automation_id: &str,
    ) -> Result<UserAutomationStoreOutcome, StoreError> {
        let fence = request.context.state_fence.clone();
        let query = automation_read_request(
            QUERY_FAILURE.to_owned(),
            Some(automation_id.to_owned()),
            false,
            1,
            fence,
        )?;
        let payload = self.client.execute_named(query).await?.payload;
        if !payload
            .get(eliot_store_api::AUTOMATION_PAGE_FAILURE)
            .is_some_and(Value::is_null)
        {
            return Err(StoreError::InvalidField {
                field: "automation.failure",
                reason: "failure projection malformed",
            });
        }
        let revision = self.read_current_revision(request, automation_id).await?;
        Ok(UserAutomationStoreOutcome::Read {
            result: UserAutomationReadResult::InspectLastFailure {
                automation_id: automation_id.to_owned(),
                revision,
                failure: None,
            },
        })
    }

    /// Reads the current revision for one automation.
    async fn read_current_revision(
        &self,
        request: &UserAutomationStoreRequest,
        automation_id: &str,
    ) -> Result<UserAutomationRevision, StoreError> {
        let query = automation_read_request(
            QUERY_CURRENT.to_owned(),
            Some(automation_id.to_owned()),
            false,
            1,
            request.context.state_fence.clone(),
        )?;
        let payload = self.client.execute_named(query).await?.payload;
        let current = payload.get(eliot_store_api::AUTOMATION_PAGE_CURRENT);
        let revision_id = current
            .and_then(|current| current.get("revision"))
            .and_then(Value::as_str)
            .ok_or(StoreError::InvalidField {
                field: "automation.automation_id",
                reason: "unknown automation",
            })?;
        self.read_revision_document(&request.context.state_fence, automation_id, revision_id)
            .await
    }

    /// Reads one immutable revision document and validates it through
    /// the Kernel-owned domain.
    async fn read_revision_document(
        &self,
        fence: &StateFence,
        automation_id: &str,
        revision: &str,
    ) -> Result<UserAutomationRevision, StoreError> {
        let query = automation_revision_read_request(
            QUERY_HISTORY.to_owned(),
            automation_id.to_owned(),
            revision.to_owned(),
            false,
            1,
            fence.clone(),
        )?;
        let payload = self.client.execute_named(query).await?.payload;
        let entries = payload
            .get(eliot_store_api::AUTOMATION_PAGE_REVISIONS)
            .and_then(Value::as_array)
            .ok_or(StoreError::InvalidField {
                field: "automation.revisions",
                reason: "store history projection malformed",
            })?;
        if entries.len() != 1 {
            return Err(StoreError::InvalidField {
                field: "automation.revisions",
                reason: "exact immutable revision read is incomplete",
            });
        }
        let entry = &entries[0];
        let document =
            entry
                .get("revision_json")
                .and_then(Value::as_str)
                .ok_or(StoreError::InvalidField {
                    field: "automation.revision_json",
                    reason: "stored revision document malformed",
                })?;
        let parsed: UserAutomationRevision = serde_json::from_str(document)
            .map_err(|error| StoreError::Serialization(error.to_string()))?;
        parsed.validate().map_err(|_| StoreError::InvalidField {
            field: "automation.revision",
            reason: "stored revision failed domain validation",
        })?;
        if entry.get("revision").and_then(Value::as_str) != Some(revision)
            || parsed.automation_id != automation_id
            || parsed.revision != revision
        {
            return Err(StoreError::InvalidField {
                field: "automation.revision",
                reason: "stored revision identity mismatch",
            });
        }
        Ok(parsed)
    }

    /// Composes the execution projection from one validated revision.
    ///
    /// Typed Durable Job enrichment stays a future join: the stored
    /// `current_execution_refs` strings are opaque without the job
    /// owner, so the projection carries empty typed ref lists plus the
    /// stored history handle, which the frozen service accepts.
    fn execution_projection(
        revision: &UserAutomationRevision,
    ) -> Result<UserAutomationExecutionProjection, StoreError> {
        let projection = UserAutomationExecutionProjection {
            current_execution_refs: Vec::new(),
            unresolved_reconciliation_refs: Vec::new(),
            history_query_ref: revision.execution_history_query_ref.clone(),
        };
        projection
            .validate()
            .map_err(|_| StoreError::InvalidField {
                field: "automation.execution",
                reason: "execution projection invalid",
            })?;
        Ok(projection)
    }

    /// Executes one authenticated mutation through one admitted
    /// canonical transaction.
    async fn execute_mutation(
        &self,
        request: &UserAutomationStoreRequest,
    ) -> Result<UserAutomationStoreResponse, StoreError> {
        let (transition, manifest_digest) = self.build_transition(request).await?;
        let view = CanonicalRequestView::from_apply(&request.context, &transition, &[], &[]);
        let computed = canonical_request_hash(&view)?;
        if computed != request.identity.canonical_request_hash {
            return Err(StoreError::TransitionDigestMismatch {
                expected: request.identity.canonical_request_hash.clone(),
                observed: computed,
            });
        }
        let replayed = match self
            .client
            .receipt(request.identity.operation_id.clone())
            .await?
        {
            Some(existing)
                if existing.idempotency_key == request.identity.idempotency_key
                    && existing.canonical_request_hash
                        == request.identity.canonical_request_hash =>
            {
                true
            }
            Some(_) => return Err(StoreError::IdentityConflict),
            None => false,
        };
        let receipt = self
            .client
            .apply_prepared(&request.context, transition, Vec::new(), Vec::new())
            .await?;
        if receipt.status != WriteReceiptStatus::Committed {
            return Err(StoreError::InvalidField {
                field: "automation.receipt",
                reason: "transition was not committed",
            });
        }
        receipt.validate()?;
        if receipt.state_fence != request.context.state_fence {
            return Err(StoreError::FenceMismatch);
        }
        if receipt.operation_manifest_digest != manifest_digest {
            return Err(StoreError::ManifestMismatch);
        }
        receipt.require_reconciliation_envelope()?;
        let result = self.project_mutation_result(request).await?;
        Ok(UserAutomationStoreResponse {
            identity: request.identity.clone(),
            state_fence: request.context.state_fence.clone(),
            outcome: if replayed {
                UserAutomationStoreOutcome::Replayed { receipt, result }
            } else {
                UserAutomationStoreOutcome::Committed { receipt, result }
            },
        })
    }

    /// Builds the one admitted transition for an authenticated intent.
    ///
    /// Public so the Kernel route owner can seal the exact canonical
    /// request hash before dispatch: the route builds the request with a
    /// placeholder hash, calls this method, seals
    /// `identity.canonical_request_hash` from
    /// [`CanonicalRequestView`](eliot_store_api::CanonicalRequestView),
    /// and dispatches. The port rebuilds deterministically at dispatch;
    /// a concurrent row change between sealing and dispatch fails closed
    /// on the digest (never as a divergent commit) and the route
    /// re-issues.
    pub async fn build_transition(
        &self,
        request: &UserAutomationStoreRequest,
    ) -> Result<(PreparedTransition, eliot_store_api::OperationManifestDigest), StoreError> {
        let parameters = self.mutation_parameters(request).await?;
        let operation = automation_mutation_request(parameters);
        let manifest_digest = operation_manifest_set_digest(&generated_operation_manifests()?)?;
        // The admission digest binds the admitted request with the
        // identity-hash field cleared: the hash itself is bound separately
        // by the transition view, so clearing keeps admission deterministic
        // across sealing (which fills the hash after building) and dispatch
        // (which rebuilds from the sealed request). A caller-supplied
        // admission digest is never trusted.
        let mut admission_view = request.clone();
        admission_view.identity.canonical_request_hash = String::new();
        let admission_digest = sha256_hex(
            &canonical_json_bytes(&admission_view)
                .map_err(|error| StoreError::Serialization(error.to_string()))?,
        );
        let automation_id = automation_scope(&request.intent.operation);
        let mut transition = PreparedTransition {
            identity: request.identity.clone(),
            state_fence: request.context.state_fence.clone(),
            scope_id: ScopeId::new(USER_AUTOMATION_SCOPE)?,
            task_id: request.context.task_id.clone().map(|task| task.to_string()),
            ordering_scopes: vec![OrderingScopeId::new(format!("automation:{automation_id}"))?],
            transition_class: TransitionClass::UserAutomation,
            requested_effect_ceiling: TransitionClass::UserAutomation.maximum_effect(),
            admission_contract_set_digest: admission_digest,
            operation_manifest_digest: manifest_digest.clone(),
            // Issue-#18 digests are derived below via `bind_issue18_digests`,
            // never defaulted; this Kernel leg binds no semantic source (`[]`).
            admission_digest: String::new(),
            mutation_plan_digest: String::new(),
            semantic_source_revisions: Vec::new(),
            named_operations: vec![operation],
            event_projection_relation_intents: eliot_store_api::EventProjectionRelationIntents {
                event_ids: Vec::new(),
                projection_kinds: Vec::new(),
                relation_kinds: Vec::new(),
            },
            security: SecurityContext::default(),
            required_proof_and_approval_refs: Vec::new(),
        };
        eliot_store_api::bind_issue18_digests(&mut transition)?;
        transition.validate()?;
        Ok((transition, manifest_digest))
    }

    /// Renders the closed mutation parameter map for one intent.
    async fn mutation_parameters(
        &self,
        request: &UserAutomationStoreRequest,
    ) -> Result<BTreeMap<String, Value>, StoreError> {
        match &request.intent.operation {
            UserAutomationOperation::Create { revision } => {
                let document = serde_json::to_string(revision)
                    .map_err(|error| StoreError::Serialization(error.to_string()))?;
                Ok(automation_create_params(
                    revision.automation_id.clone(),
                    revision.revision.clone(),
                    state_wire(revision.configuration_state),
                    document,
                ))
            }
            UserAutomationOperation::Edit {
                previous_revision,
                revision,
            } => {
                let document = serde_json::to_string(revision)
                    .map_err(|error| StoreError::Serialization(error.to_string()))?;
                Ok(automation_edit_params(
                    revision.automation_id.clone(),
                    previous_revision.revision.clone(),
                    revision.revision.clone(),
                    state_wire(revision.configuration_state),
                    document,
                ))
            }
            UserAutomationOperation::Pause {
                automation_id,
                automation_revision,
            } => Ok(automation_state_transition_params(
                "pause".to_owned(),
                automation_id.clone(),
                automation_revision.clone(),
                eliot_store_api::AUTOMATION_STATE_PAUSED.to_owned(),
            )),
            UserAutomationOperation::Resume {
                automation_id,
                automation_revision,
            } => Ok(automation_state_transition_params(
                "resume".to_owned(),
                automation_id.clone(),
                automation_revision.clone(),
                eliot_store_api::AUTOMATION_STATE_ACTIVE.to_owned(),
            )),
            UserAutomationOperation::Remove {
                automation_id,
                automation_revision,
            } => Ok(automation_state_transition_params(
                "remove".to_owned(),
                automation_id.clone(),
                automation_revision.clone(),
                eliot_store_api::AUTOMATION_STATE_RETIRED.to_owned(),
            )),
            UserAutomationOperation::RunNow {
                automation_id,
                automation_revision,
                nonce,
            } => {
                let invocation = self
                    .invocation_for(request, automation_id, automation_revision, nonce)
                    .await?;
                let occurrence_id =
                    invocation
                        .occurrence_identity()
                        .map_err(|_| StoreError::InvalidField {
                            field: "automation.occurrence",
                            reason: "occurrence identity failed",
                        })?;
                let document = serde_json::to_string(&invocation)
                    .map_err(|error| StoreError::Serialization(error.to_string()))?;
                Ok(automation_run_now_params(
                    automation_id.clone(),
                    automation_revision.clone(),
                    occurrence_id,
                    document,
                ))
            }
            _ => Err(StoreError::UnknownOperation),
        }
    }

    /// Builds the typed invocation for a run-now intent from the stored
    /// current revision and the authenticated nonce.
    async fn invocation_for(
        &self,
        request: &UserAutomationStoreRequest,
        automation_id: &str,
        automation_revision: &str,
        nonce: &str,
    ) -> Result<UserAutomationInvocation, StoreError> {
        let revision = self
            .read_revision_document(
                &request.context.state_fence,
                automation_id,
                automation_revision,
            )
            .await?;
        if nonce.trim().is_empty() || nonce.chars().any(char::is_control) {
            return Err(StoreError::InvalidField {
                field: "automation.nonce",
                reason: "nonce must be non-blank text",
            });
        }
        let invocation = UserAutomationInvocation {
            automation_id: revision.automation_id.clone(),
            automation_revision: revision.revision.clone(),
            trigger: eliot_kernel_core::user_automation::UserAutomationTrigger::Manual {
                nonce: nonce.to_owned(),
            },
            mode: revision.mode,
            principal_ref: request.authenticated_principal.clone(),
            work_scope_ref: revision.work_scope.scope_id.clone(),
            workdir_ref: revision.workdir_ref.clone(),
            trigger_origin: eliot_kernel_core::user_automation::UserAutomationTriggerOrigin::Human,
            child_depth: 0,
            provenance: Some(
                eliot_kernel_core::user_automation::UserAutomationInvocationProvenance {
                    request_metadata: request.context.clone(),
                    source_operation: request.intent.operation.clone(),
                    operation_id: request.identity.operation_id.clone(),
                    idempotency_key: request.identity.idempotency_key.clone(),
                    canonical_request_hash: request.identity.canonical_request_hash.clone(),
                },
            ),
        };
        invocation
            .require_run_now_provenance(&request.context.state_fence)
            .map_err(|_| StoreError::InvalidField {
                field: "automation.invocation.provenance",
                reason: "RunNow requires authenticated task/session and exact source operation",
            })?;
        Ok(invocation)
    }

    /// Projects the typed mutation result from current store rows.
    async fn project_mutation_result(
        &self,
        request: &UserAutomationStoreRequest,
    ) -> Result<super::UserAutomationMutationResult, StoreError> {
        match &request.intent.operation {
            UserAutomationOperation::Create { revision }
            | UserAutomationOperation::Edit { revision, .. } => {
                let stored = self
                    .read_revision_document(
                        &request.context.state_fence,
                        &revision.automation_id,
                        &revision.revision,
                    )
                    .await?;
                if stored != *revision {
                    return Err(StoreError::InvalidField {
                        field: "automation.revision",
                        reason: "stored revision diverged from the admitted revision",
                    });
                }
                Ok(UserAutomationMutationResult::Revision {
                    revision: stored,
                    cancelled_wake_ids: Vec::new(),
                })
            }
            UserAutomationOperation::Pause {
                automation_id,
                automation_revision,
            } => {
                self.project_state_result(request, automation_id, automation_revision, "PAUSED")
                    .await
            }
            UserAutomationOperation::Resume {
                automation_id,
                automation_revision,
            } => {
                self.project_state_result(request, automation_id, automation_revision, "ACTIVE")
                    .await
            }
            UserAutomationOperation::Remove {
                automation_id,
                automation_revision,
            } => {
                let mut revision = self
                    .read_revision_document(
                        &request.context.state_fence,
                        automation_id,
                        automation_revision,
                    )
                    .await?;
                revision.configuration_state =
                    eliot_kernel_core::user_automation::UserAutomationConfigurationState::Retired;
                revision.validate().map_err(|_| StoreError::InvalidField {
                    field: "automation.revision",
                    reason: "retired projection failed domain validation",
                })?;
                Ok(UserAutomationMutationResult::Revision {
                    revision,
                    cancelled_wake_ids: Vec::new(),
                })
            }
            UserAutomationOperation::RunNow {
                automation_id,
                automation_revision,
                nonce,
            } => {
                self.project_run_now_result(request, automation_id, automation_revision, nonce)
                    .await
            }
            _ => Err(StoreError::UnknownOperation),
        }
    }

    /// Projects a run-now result from the stored invocation plus a
    /// freshly compiled inert wake intent.
    async fn project_run_now_result(
        &self,
        request: &UserAutomationStoreRequest,
        automation_id: &str,
        automation_revision: &str,
        nonce: &str,
    ) -> Result<super::UserAutomationMutationResult, StoreError> {
        let invocation = self
            .invocation_for(request, automation_id, automation_revision, nonce)
            .await?;
        let occurrence_id =
            invocation
                .occurrence_identity()
                .map_err(|_| StoreError::InvalidField {
                    field: "automation.occurrence",
                    reason: "occurrence identity failed",
                })?;
        let stored = self
            .read_invocation_document(request, &occurrence_id)
            .await?;
        if stored != invocation {
            return Err(StoreError::InvalidField {
                field: "automation.invocation",
                reason: "stored invocation diverged from the admitted invocation",
            });
        }
        let revision = self
            .read_revision_document(
                &request.context.state_fence,
                automation_id,
                automation_revision,
            )
            .await?;
        let wake_intent = revision
            .compile_wake_intent(&occurrence_id, request.context.state_fence.clone())
            .map_err(|_| StoreError::InvalidField {
                field: "automation.wake",
                reason: "wake intent failed domain compilation",
            })?;
        Ok(UserAutomationMutationResult::RunNow {
            invocation: stored,
            wake_intent,
        })
    }

    /// Projects a pause/resume result by flipping the stored document's
    /// admission state mechanically (validated downstream by the frozen
    /// service; the immutable stored row is never rewritten).
    async fn project_state_result(
        &self,
        request: &UserAutomationStoreRequest,
        automation_id: &str,
        automation_revision: &str,
        state: &str,
    ) -> Result<super::UserAutomationMutationResult, StoreError> {
        let mut revision = self
            .read_revision_document(
                &request.context.state_fence,
                automation_id,
                automation_revision,
            )
            .await?;
        revision.configuration_state = match state {
            "PAUSED" => {
                eliot_kernel_core::user_automation::UserAutomationConfigurationState::Paused
            }
            _ => eliot_kernel_core::user_automation::UserAutomationConfigurationState::Active,
        };
        revision.validate().map_err(|_| StoreError::InvalidField {
            field: "automation.revision",
            reason: "state projection failed domain validation",
        })?;
        Ok(UserAutomationMutationResult::Revision {
            revision,
            cancelled_wake_ids: Vec::new(),
        })
    }

    /// Reads one stored invocation document for run-now projection.
    async fn read_invocation_document(
        &self,
        request: &UserAutomationStoreRequest,
        occurrence_id: &str,
    ) -> Result<UserAutomationInvocation, StoreError> {
        let automation_id = match &request.intent.operation {
            UserAutomationOperation::RunNow { automation_id, .. } => automation_id.clone(),
            _ => {
                return Err(StoreError::UnknownOperation);
            }
        };
        let query = automation_invocation_read_request(
            automation_id,
            occurrence_id.to_owned(),
            request.context.state_fence.clone(),
        )?;
        let response = self.client.execute_named(query.clone()).await?;
        CanonicalUserAutomationStore::<C>::project_invocation(
            query
                .parameters
                .get(eliot_store_api::AUTOMATION_PARAM_AUTOMATION_ID)
                .and_then(Value::as_str)
                .ok_or(StoreError::InvalidField {
                    field: "automation.automation_id",
                    reason: "exact invocation request omitted automation selector",
                })?,
            occurrence_id,
            &query,
            response,
        )
    }
}

/// Returns the automation identity scoping one intent's ordering stream.
fn automation_scope(operation: &UserAutomationOperation) -> String {
    match operation {
        UserAutomationOperation::Create { revision }
        | UserAutomationOperation::Edit { revision, .. } => revision.automation_id.clone(),
        UserAutomationOperation::List { .. } => "list".to_owned(),
        UserAutomationOperation::Status { automation_id }
        | UserAutomationOperation::History { automation_id }
        | UserAutomationOperation::Pause { automation_id, .. }
        | UserAutomationOperation::Resume { automation_id, .. }
        | UserAutomationOperation::Remove { automation_id, .. }
        | UserAutomationOperation::RunNow { automation_id, .. }
        | UserAutomationOperation::InspectLastFailure { automation_id } => automation_id.clone(),
    }
}

/// Renders the domain admission state into the closed wire spelling.
fn state_wire(
    state: eliot_kernel_core::user_automation::UserAutomationConfigurationState,
) -> String {
    match state {
        eliot_kernel_core::user_automation::UserAutomationConfigurationState::Active => {
            "ACTIVE".to_owned()
        }
        eliot_kernel_core::user_automation::UserAutomationConfigurationState::Paused => {
            "PAUSED".to_owned()
        }
        eliot_kernel_core::user_automation::UserAutomationConfigurationState::BlockedConfig => {
            "BLOCKED_CONFIG".to_owned()
        }
        eliot_kernel_core::user_automation::UserAutomationConfigurationState::Retired => {
            "RETIRED".to_owned()
        }
    }
}
