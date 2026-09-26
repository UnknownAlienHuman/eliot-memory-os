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
//!
//! Issue #2808 owns the occurrence denominator those projections are
//! derived from. `reconciliation_obligations` is the only producer of the
//! retained obligation set: it reads the owner-declared occurrence
//! denominator, requires the owner-issued `completeness` block (read
//! revision plus `COMPLETE`/`TRUNCATED` coverage), and re-proves that read
//! revision against the exact revision-head set the owner returned. A row
//! with no usable invocation document, no owner-issued provenance, or an
//! unreadable canonical receipt becomes a typed obligation tied to that
//! exact row, and a denominator the owner did not prove complete becomes an
//! obligation carrying the durable owner query handle. Absence of evidence
//! is therefore `unknown`, never "no reconciliation obligation" (I5.16), so
//! Status, History, deterministic preflight and Remove all answer from one
//! denominator read revision and an incomplete denominator blocks.

use std::collections::BTreeMap;

use eliot_kernel_core::user_automation::{
    AutomationReconciliationCause, AutomationReconciliationReference,
    UserAutomationExecutionProjection, UserAutomationInvocation, UserAutomationOperation,
    UserAutomationRevision,
};
use eliot_store_api::{
    CanonicalRequestView, CanonicalStoreClient, NamedReadOperation, NamedReadRequest,
    NamedReadResponse, OrderingScopeId, PreparedTransition, RevisionHead, ScopeId, SecurityContext,
    StateFence, StoreError, TransitionClass, USER_AUTOMATION_SCOPE, WriteReceipt,
    WriteReceiptStatus, audit_heads_digest, automation_create_params, automation_cursor_verify,
    automation_edit_params, automation_invocation_read_request, automation_mutation_request,
    automation_read_request, automation_revision_read_request, automation_run_now_params,
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
const QUERY_INVOCATIONS: &str = "invocations";
/// Closed automation-state query kinds carried to the store read.
const QUERY_FAILURE: &str = "failure";

/// Closed owner-issued coverage vocabulary carried by one paged automation
/// read under the store contract's `completeness` payload field.
const AUTOMATION_PAGE_COMPLETENESS_FIELD: &str = "completeness";
/// Owner-issued read-revision field of the completeness metadata.
const AUTOMATION_PAGE_READ_REVISION_FIELD: &str = "read_revision";
/// Rows-returned field of the completeness metadata.
const AUTOMATION_PAGE_RETURNED_FIELD: &str = "returned";
/// Closed coverage disposition field of the completeness metadata.
const AUTOMATION_PAGE_COVERAGE_FIELD: &str = "coverage";
/// Owner-minted continuation carried by a truncated page.
const AUTOMATION_PAGE_NEXT_CURSOR_FIELD: &str = eliot_store_api::AUTOMATION_PAGE_NEXT_CURSOR;
/// Closed coverage value: the owner proved the page exhausts the denominator.
const AUTOMATION_COVERAGE_COMPLETE: &str = "COMPLETE";
/// Closed coverage value: the owner returned a bounded prefix only.
const AUTOMATION_COVERAGE_TRUNCATED: &str = "TRUNCATED";

/// Versioned prefix of the durable owner query handle naming one automation
/// occurrence denominator. The handle is the closed named read plus the exact
/// owner-issued read revision, so the unrepresented remainder of a
/// non-proven denominator stays addressable after retirement instead of
/// disappearing with the bounded page.
const AUTOMATION_DENOMINATOR_QUERY_PREFIX: &str = "GetUserAutomationState:invocations:v1:";

/// Maximum accumulated invocation-document bytes one denominator read may
/// inspect before it reports partial/recovery-required instead of a bounded
/// but silent set. The bound is a cumulative work limit over the declared
/// denominator, not a per-page one.
const MAX_AUTOMATION_DENOMINATOR_BYTES: usize = 4 * 1024 * 1024;

/// Maximum pages one denominator read may pull before it reports
/// partial/recovery-required.
///
/// Pages stay individually bounded; this is the cumulative work limit over the
/// declared denominator. Exhausting it yields the same durable
/// `IncompleteDenominator` obligation as a truncated owner page, never an empty
/// or silently incomplete successful set.
const MAX_AUTOMATION_DENOMINATOR_PAGES: usize = 256;

/// One stored row's effect disposition inside the occurrence denominator.
enum OccurrenceEvidence {
    /// The row's admitting canonical operation is proven committed with no
    /// outstanding reconciliation envelope, so the row carries no obligation.
    Resolved,
    /// The row still carries exactly one typed obligation.
    Unresolved(AutomationReconciliationReference),
}

/// Owner-issued denominator coverage decoded from one paged read.
struct AutomationDenominatorCoverage {
    /// Owner-issued read revision this page was produced at.
    read_revision: String,
    /// Whether the owner proved the page exhausts the declared denominator.
    complete: bool,
    /// Owner-minted continuation for the next page, present exactly on a
    /// truncated page.
    next_cursor: Option<String>,
}

/// One occurrence-denominator read: the retained obligations plus the
/// owner-issued coverage they were derived from.
struct AutomationObligationSet {
    /// Typed obligations in deterministic occurrence order.
    references: Vec<AutomationReconciliationReference>,
    /// Owner-issued read revision the denominator was read at.
    read_revision: String,
}

/// One complete owner-issued execution projection bound to the denominator
/// revision it was read at.
struct AutomationExecutionProjectionPage {
    /// Typed projection consumed by Status, History and preflight.
    projection: UserAutomationExecutionProjection,
    /// Owner-issued read revision the occurrence denominator was read at.
    read_revision: String,
}

/// One bounded page of the declared occurrence denominator plus the
/// owner-issued coverage that proves what the page represents.
struct AutomationDenominatorPage {
    /// Rows the owner served on this page, in the denominator's total order.
    entries: Vec<Value>,
    /// Owner-issued coverage of exactly this page.
    coverage: AutomationDenominatorCoverage,
}

/// Mutable state of one paged denominator walk.
///
/// The walk keeps exactly one head snapshot: the first page's owner-issued read
/// revision is the denominator revision, and every later page must prove the
/// same one, so occurrences committed after it belong to a successor read
/// instead of being folded into this answer.
#[derive(Default)]
struct AutomationDenominatorWalk {
    /// Obligations observed so far, in page order.
    references: Vec<AutomationReconciliationReference>,
    /// The one owner-issued read revision every page of this walk must prove.
    denominator_revision: Option<String>,
    /// Pages already requested, the cumulative work bound over the denominator.
    pages: usize,
    /// Accumulated invocation-document bytes, the cumulative byte bound.
    inspected_bytes: usize,
    /// Verified continuation for the next page, absent on the first request.
    cursor: Option<String>,
}

impl AutomationDenominatorWalk {
    /// Binds the walk to the read revision of the page just served.
    ///
    /// A second, different read revision inside one projection means the
    /// denominator was assembled from two snapshots (I5.27, I14.21), so the
    /// walk fails closed instead of answering as one complete set.
    fn adopt(&mut self, read_revision: &str) -> Result<(), StoreError> {
        match self.denominator_revision.as_deref() {
            None => {
                self.denominator_revision = Some(read_revision.to_owned());
                Ok(())
            }
            Some(observed) if observed == read_revision => Ok(()),
            Some(_) => Err(StoreError::RevisionConflict),
        }
    }
}

/// Decodes the owner-issued denominator coverage of one paged read.
///
/// The `completeness` block is mandatory: a page that omits it cannot be read
/// as a complete denominator, because absence of a coverage record is
/// `unknown`, not unrestricted/complete (I5.16). The declared read revision is
/// re-proved against the exact revision-head set the owner returned with the
/// response, so a page cannot claim a denominator revision the owner did not
/// serve, and the declared row count is re-proved against the page actually
/// carried.
///
/// A truncated page must carry an owner-minted continuation and a complete page
/// must not: without the successor there is no address for the remainder, and
/// one on a proven-complete page would invite a consumer to keep reading past
/// the end of the denominator. Either mismatch fails closed rather than
/// resolving into a page this adapter would page over.
fn denominator_coverage(
    payload: &Value,
    rows: usize,
    heads: &[RevisionHead],
) -> Result<AutomationDenominatorCoverage, StoreError> {
    let malformed =
        |field: &'static str, reason: &'static str| StoreError::InvalidField { field, reason };
    let block = payload
        .get(AUTOMATION_PAGE_COMPLETENESS_FIELD)
        .ok_or_else(|| {
            malformed(
                "automation.completeness",
                "paged automation read omitted owner-issued completeness",
            )
        })?;
    let read_revision = block
        .get(AUTOMATION_PAGE_READ_REVISION_FIELD)
        .and_then(Value::as_str)
        .ok_or_else(|| {
            malformed(
                "automation.read_revision",
                "owner-issued read revision is malformed",
            )
        })?
        .to_owned();
    let declared_rows = block
        .get(AUTOMATION_PAGE_RETURNED_FIELD)
        .and_then(Value::as_u64)
        .ok_or_else(|| {
            malformed(
                "automation.returned",
                "owner-issued returned row count is malformed",
            )
        })?;
    let observed_rows = u64::try_from(rows).map_err(|_| {
        malformed(
            "automation.returned",
            "projected automation page length is not representable",
        )
    })?;
    if observed_rows != declared_rows {
        return Err(malformed(
            "automation.returned",
            "owner-issued returned row count does not match the projected page",
        ));
    }
    let coverage = block
        .get(AUTOMATION_PAGE_COVERAGE_FIELD)
        .and_then(Value::as_str)
        .ok_or_else(|| {
            malformed(
                "automation.coverage",
                "owner-issued coverage disposition is malformed",
            )
        })?;
    let complete = match coverage {
        AUTOMATION_COVERAGE_COMPLETE => true,
        AUTOMATION_COVERAGE_TRUNCATED => false,
        _ => {
            return Err(malformed(
                "automation.coverage",
                "owner-issued coverage disposition is not a closed value",
            ));
        }
    };
    let next_cursor = block
        .get(AUTOMATION_PAGE_NEXT_CURSOR_FIELD)
        .map(|value| {
            value.as_str().map(str::to_owned).ok_or_else(|| {
                malformed(
                    "automation.next_cursor",
                    "owner-issued continuation is not a string",
                )
            })
        })
        .transpose()?;
    if complete && next_cursor.is_some() {
        return Err(malformed(
            "automation.next_cursor",
            "owner-proven complete page must not carry a continuation",
        ));
    }
    if !complete && next_cursor.is_none() {
        return Err(malformed(
            "automation.next_cursor",
            "truncated page omitted the owner-issued continuation",
        ));
    }
    let observed_heads: Vec<(String, u64)> = heads
        .iter()
        .map(|head| (head.key.as_str().to_owned(), head.revision))
        .collect();
    if read_revision != audit_heads_digest(&observed_heads)? {
        return Err(StoreError::RevisionConflict);
    }
    Ok(AutomationDenominatorCoverage {
        read_revision,
        complete,
        next_cursor,
    })
}

/// Returns the verified continuation for one truncated page of a denominator.
///
/// The cursor is re-proved against this exact automation, query, owner-issued
/// read revision, admission fence and page bound before it is echoed, so an
/// owner that minted a cursor for another denominator, another head snapshot or
/// another page bound cannot redirect the walk. A commit between pages advances
/// the head set, so the re-proof fails closed and the walk restarts under the
/// successor read rather than continuing over a set that moved.
fn denominator_page_cursor(
    cursor: &str,
    query: &str,
    automation_id: &str,
    coverage: &AutomationDenominatorCoverage,
    fence: &StateFence,
    max_records: u16,
) -> Result<String, StoreError> {
    automation_cursor_verify(
        cursor,
        query,
        automation_id,
        &coverage.read_revision,
        fence,
        max_records,
    )?;
    Ok(cursor.to_owned())
}

/// Returns the exact occurrence identity one stored invocation row carries.
///
/// A row that names another automation is an identity conflict, and a row
/// without a usable occurrence identity cannot be tied to any obligation, so
/// both fail closed instead of being skipped.
fn occurrence_row_identity(entry: &Value, automation_id: &str) -> Result<String, StoreError> {
    if entry.get("automation_id").and_then(Value::as_str) != Some(automation_id) {
        return Err(StoreError::IdentityConflict);
    }
    entry
        .get("occurrence_id")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or(StoreError::InvalidField {
            field: "automation.occurrence_id",
            reason: "invocation row omitted its occurrence identity",
        })
}

/// Builds one per-occurrence obligation for evidence the owner could not
/// supply.
///
/// `operation_ref` is an actionable migration/reconciliation reference bound
/// to the exact row. It never states a committed or failed outcome that was
/// not observed.
fn evidence_obligation(
    occurrence_id: &str,
    cause: AutomationReconciliationCause,
    read_revision: &str,
) -> AutomationReconciliationReference {
    AutomationReconciliationReference {
        occurrence_id: occurrence_id.to_owned(),
        operation_ref: format!("automation-occurrence-reconciliation:{occurrence_id}"),
        cause,
        read_revision: read_revision.to_owned(),
        denominator_query_ref: None,
    }
}

/// Builds the fail-closed obligation raised when the declared occurrence
/// denominator is not owner-proven complete.
///
/// The obligation is tied to the exact automation denominator and carries the
/// durable owner query handle that enumerates the rest of the set, so a later
/// read finishes it instead of restating an empty successful set.
fn incomplete_denominator_reference(
    automation_id: &str,
    read_revision: &str,
) -> AutomationReconciliationReference {
    AutomationReconciliationReference {
        occurrence_id: format!("automation-occurrence-denominator:{automation_id}"),
        operation_ref: format!(
            "automation-denominator-reconciliation:{automation_id}:{read_revision}"
        ),
        cause: AutomationReconciliationCause::IncompleteDenominator,
        read_revision: read_revision.to_owned(),
        denominator_query_ref: Some(format!(
            "{AUTOMATION_DENOMINATOR_QUERY_PREFIX}{automation_id}@{read_revision}"
        )),
    }
}

/// Decodes one stored invocation row from the occurrence denominator.
///
/// `Ok(None)` means the row carries no usable owner-issued invocation
/// evidence: the document is absent, legacy, or malformed. I5.16 makes that
/// `unknown`, so the caller raises a typed obligation tied to the exact row
/// instead of skipping it. A row whose document is present, valid, and bound to
/// a different automation or occurrence is an identity conflict and still fails
/// closed.
fn projected_invocation(entry: &Value) -> Result<Option<UserAutomationInvocation>, StoreError> {
    let Some(document) = entry.get("invocation_json").and_then(Value::as_str) else {
        return Ok(None);
    };
    let Ok(invocation) = serde_json::from_str::<UserAutomationInvocation>(document) else {
        return Ok(None);
    };
    if invocation.validate().is_err() {
        return Ok(None);
    }
    let occurrence_id = invocation
        .occurrence_identity()
        .map_err(|_| StoreError::IdentityConflict)?;
    if entry.get("automation_id").and_then(Value::as_str) != Some(invocation.automation_id.as_str())
        || entry.get("occurrence_id").and_then(Value::as_str) != Some(occurrence_id.as_str())
    {
        return Err(StoreError::IdentityConflict);
    }
    Ok(Some(invocation))
}

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
        let execution = self
            .execution_projection(&request.context.state_fence, automation_id, &revision)
            .await?;
        Ok(UserAutomationStoreOutcome::Read {
            result: UserAutomationReadResult::Status {
                revision,
                execution: execution.projection,
            },
        })
    }

    /// Projects the history read from the revision-row set.
    ///
    /// The history denominator must be owner-proven complete, which the owner
    /// proves per page: a bounded first page is not evidence that no later
    /// immutable revision exists, so the walk follows the owner-minted
    /// continuation to the end of the declared set instead of answering from an
    /// arbitrary first row. Every page is re-proved against one owner-issued
    /// read revision, the admission fence and the page bound, so a commit, a
    /// retirement, or a repeated or reordered page request can neither make an
    /// old page look complete nor fold a successor read into this answer. The
    /// page and the occurrence denominator must also agree on one read
    /// revision, so a read that raced a successor commit fails closed instead
    /// of answering from two snapshots.
    async fn read_history_outcome(
        &self,
        request: &UserAutomationStoreRequest,
        automation_id: &str,
    ) -> Result<UserAutomationStoreOutcome, StoreError> {
        let fence = request.context.state_fence.clone();
        let mut cursor: Option<String> = None;
        let mut pages = 0usize;
        let mut first_revision: Option<String> = None;
        let history_coverage = loop {
            pages = pages.saturating_add(1);
            if pages > MAX_AUTOMATION_DENOMINATOR_PAGES {
                return Err(StoreError::InvalidField {
                    field: "automation.revisions",
                    reason: "history walk exhausted its page budget",
                });
            }
            let base = automation_read_request(
                QUERY_HISTORY.to_owned(),
                Some(automation_id.to_owned()),
                false,
                eliot_store_api::MAX_AUTOMATION_PAGE_RECORDS,
                fence.clone(),
            )?;
            let query = match cursor.as_deref() {
                None => base,
                Some(cursor) => {
                    let mut request = base;
                    request.parameters.insert(
                        eliot_store_api::AUTOMATION_PARAM_CURSOR.to_owned(),
                        Value::String(cursor.to_owned()),
                    );
                    request.validate()?;
                    request
                }
            };
            // The request is validated against its own response, and
            // `NamedReadRequest` is not `Copy`, so the send takes a clone. This
            // is the same shape the other validating reads in this file already
            // use.
            let response = self.client.execute_named(query.clone()).await?;
            validate_named_response(&query, &response)?;
            let entries = response
                .payload
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
            let coverage =
                denominator_coverage(&response.payload, entries.len(), &response.revision_heads)?;
            if first_revision.is_none() {
                first_revision = entries
                    .first()
                    .and_then(|entry| entry.get("revision"))
                    .and_then(Value::as_str)
                    .map(str::to_owned);
            }
            if coverage.complete {
                break coverage;
            }
            let Some(next) = coverage.next_cursor.as_deref() else {
                return Err(StoreError::InvalidField {
                    field: "automation.revisions",
                    reason: "history page is not owner-proven complete",
                });
            };
            cursor = Some(denominator_page_cursor(
                next,
                QUERY_HISTORY,
                automation_id,
                &coverage,
                &fence,
                eliot_store_api::MAX_AUTOMATION_PAGE_RECORDS,
            )?);
        };
        let revision_id = first_revision.ok_or(StoreError::InvalidField {
            field: "automation.revision",
            reason: "store history projection malformed",
        })?;
        let revision = self
            .read_revision_document(&request.context.state_fence, automation_id, &revision_id)
            .await?;
        let execution = self
            .execution_projection(&request.context.state_fence, automation_id, &revision)
            .await?;
        if execution.read_revision != history_coverage.read_revision {
            return Err(StoreError::RevisionConflict);
        }
        Ok(UserAutomationStoreOutcome::Read {
            result: UserAutomationReadResult::History {
                automation_id: automation_id.to_owned(),
                execution: execution.projection,
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

    /// Composes the execution projection from the stored revision plus the
    /// real outstanding reconciliation obligations.
    ///
    /// `current_execution_refs` stays the stored Durable Job reference
    /// projection: the canonical Durable Job owner, not this Store adapter,
    /// resolves those references to a job state. The unresolved
    /// reconciliation set is derived from the complete declared occurrence
    /// denominator: an occurrence whose admitting canonical operation has no
    /// committed receipt, or a receipt that still requires a reconciliation
    /// envelope, is an outstanding I14.21 obligation and is preserved verbatim
    /// through status, history, and retirement. This is the single production
    /// constructor of the projection, so Status, History, preflight and Remove
    /// answer from one denominator read revision.
    async fn execution_projection(
        &self,
        fence: &StateFence,
        automation_id: &str,
        revision: &UserAutomationRevision,
    ) -> Result<AutomationExecutionProjectionPage, StoreError> {
        let obligations = self
            .reconciliation_obligations(fence, automation_id)
            .await?;
        let projection = UserAutomationExecutionProjection {
            current_execution_refs: Vec::new(),
            unresolved_reconciliation_refs: obligations.references,
            history_query_ref: revision.execution_history_query_ref.clone(),
        };
        projection
            .validate()
            .map_err(|_| StoreError::InvalidField {
                field: "automation.execution",
                reason: "execution projection invalid",
            })?;
        Ok(AutomationExecutionProjectionPage {
            projection,
            read_revision: obligations.read_revision,
        })
    }

    /// Reads the declared occurrence denominator and returns every obligation
    /// it still carries, with the owner-issued coverage they came from.
    ///
    /// The declared denominator is walked page by page under ONE owner-issued
    /// read revision. Each page is individually bounded by
    /// [`MAX_AUTOMATION_PAGE_RECORDS`](eliot_store_api::MAX_AUTOMATION_PAGE_RECORDS);
    /// the walk resumes through the owner-minted continuation, whose exclusive
    /// last row identity is a key comparison on the denominator's total
    /// ordering and never an offset over a moving set. Every page is re-proved
    /// against the same automation, read revision, fence and page bound, so a
    /// concurrent commit, a retirement, a repeated page request or a reordered
    /// request can neither drop a row nor repeat one, and a page from a
    /// successor read is refused instead of folded in.
    ///
    /// Every same-fence invocation row the owner declared is inspected. A row
    /// whose admitting canonical operation is proven committed with no
    /// outstanding reconciliation envelope contributes nothing; every other row
    /// contributes exactly one typed obligation:
    ///
    /// - a missing, legacy, or malformed invocation document, a row without
    ///   owner-issued provenance, and an unreadable canonical receipt are
    ///   `unknown` evidence, not "no effect" (I5.16), and each becomes an
    ///   obligation tied to that exact row with an actionable migration
    ///   reference;
    /// - a denominator the owner did not prove complete, or one whose
    ///   cumulative page or document budget this read exhausted, is itself an
    ///   obligation carrying the durable owner query handle, so the
    ///   unrepresented remainder stays visible and addressable after
    ///   retirement instead of reading as an empty successful set.
    ///
    /// The set is deduplicated only on exact occurrence/operation identity
    /// after its binding is validated; two rows claiming one occurrence with a
    /// different operation, cause, or read revision are an identity conflict
    /// rather than one arbitrarily retained representative.
    async fn reconciliation_obligations(
        &self,
        fence: &StateFence,
        automation_id: &str,
    ) -> Result<AutomationObligationSet, StoreError> {
        let mut walk = AutomationDenominatorWalk::default();
        loop {
            walk.pages = walk.pages.saturating_add(1);
            if walk.pages > MAX_AUTOMATION_DENOMINATOR_PAGES {
                return Self::incomplete_denominator(
                    automation_id,
                    &walk.references,
                    walk.denominator_revision.clone(),
                );
            }
            let page = self
                .invocation_denominator_page(fence, automation_id, walk.cursor.as_deref())
                .await?;
            walk.adopt(&page.coverage.read_revision)?;
            let exhausted = self.classify_page(&page, automation_id, &mut walk).await?;
            if exhausted {
                return Self::incomplete_denominator(
                    automation_id,
                    &walk.references,
                    walk.denominator_revision.clone(),
                );
            }
            if page.coverage.complete {
                return Self::obligation_set(walk.references, &page.coverage.read_revision);
            }
            let Some(next) = page.coverage.next_cursor.as_deref() else {
                return Self::incomplete_denominator(
                    automation_id,
                    &walk.references,
                    walk.denominator_revision.clone(),
                );
            };
            walk.cursor = Some(denominator_page_cursor(
                next,
                QUERY_INVOCATIONS,
                automation_id,
                &page.coverage,
                fence,
                eliot_store_api::MAX_AUTOMATION_PAGE_RECORDS,
            )?);
        }
    }

    /// Reads one page of the declared occurrence denominator, optionally
    /// resuming after a verified continuation.
    ///
    /// The request is re-validated against its own response, so a page always
    /// carries the projection fence it was asked under, and the owner-issued
    /// coverage of that page is decoded here rather than trusted from a
    /// consumer.
    async fn invocation_denominator_page(
        &self,
        fence: &StateFence,
        automation_id: &str,
        cursor: Option<&str>,
    ) -> Result<AutomationDenominatorPage, StoreError> {
        let query = automation_read_request(
            QUERY_INVOCATIONS.to_owned(),
            Some(automation_id.to_owned()),
            false,
            eliot_store_api::MAX_AUTOMATION_PAGE_RECORDS,
            fence.clone(),
        )?;
        let request = match cursor {
            None => query,
            // The owner minted the continuation for this exact denominator, read
            // revision, fence and page bound; the request is re-validated before
            // dispatch.
            Some(cursor) => {
                let mut request = query;
                request.parameters.insert(
                    eliot_store_api::AUTOMATION_PARAM_CURSOR.to_owned(),
                    Value::String(cursor.to_owned()),
                );
                request.validate()?;
                request
            }
        };
        // Validated against its own response; `NamedReadRequest` is not `Copy`,
        // so the send takes a clone.
        let response = self.client.execute_named(request.clone()).await?;
        validate_named_response(&request, &response)?;
        let entries = response
            .payload
            .get(eliot_store_api::AUTOMATION_PAGE_INVOCATIONS)
            .and_then(Value::as_array)
            .ok_or(StoreError::InvalidField {
                field: "automation.invocations",
                reason: "store invocation projection malformed",
            })?;
        let coverage =
            denominator_coverage(&response.payload, entries.len(), &response.revision_heads)?;
        Ok(AutomationDenominatorPage {
            entries: entries.clone(),
            coverage,
        })
    }

    /// Classifies one denominator page into obligations, accumulating the
    /// cumulative document budget across pages.
    ///
    /// Returns whether the cumulative budget was exhausted: a page that ran out
    /// of budget leaves the rest of the denominator unclassified, which the
    /// caller reports as partial/recovery-required rather than as a successful
    /// set.
    async fn classify_page(
        &self,
        page: &AutomationDenominatorPage,
        automation_id: &str,
        walk: &mut AutomationDenominatorWalk,
    ) -> Result<bool, StoreError> {
        for entry in &page.entries {
            let occurrence_id = occurrence_row_identity(entry, automation_id)?;
            walk.inspected_bytes = walk.inspected_bytes.saturating_add(
                entry
                    .get("invocation_json")
                    .and_then(Value::as_str)
                    .map_or(0, str::len),
            );
            if walk.inspected_bytes > MAX_AUTOMATION_DENOMINATOR_BYTES {
                return Ok(true);
            }
            if let OccurrenceEvidence::Unresolved(reference) = self
                .occurrence_evidence(entry, &occurrence_id, &page.coverage.read_revision)
                .await?
            {
                walk.references.push(reference);
            }
        }
        Ok(false)
    }

    /// Closes one walk with the durable partial/recovery-required disposition.
    ///
    /// The obligations already observed are preserved verbatim and the
    /// denominator-level obligation carrying the durable owner query handle is
    /// appended, so a bound that was exhausted reports partial coverage instead
    /// of a successful but incomplete set. The read revision comes from the
    /// pages already served: a walk refused before its first page has no
    /// owner-issued revision to name, and says so through the closed store
    /// error rather than inventing one.
    fn incomplete_denominator(
        automation_id: &str,
        references: &[AutomationReconciliationReference],
        read_revision: Option<String>,
    ) -> Result<AutomationObligationSet, StoreError> {
        let read_revision = read_revision.ok_or(StoreError::InvalidField {
            field: "automation.reconciliation",
            reason: "denominator walk exhausted its page budget before any owner-issued page",
        })?;
        let reference = incomplete_denominator_reference(automation_id, &read_revision);
        reference.validate().map_err(|_| StoreError::InvalidField {
            field: "automation.reconciliation",
            reason: "incomplete denominator reference invalid",
        })?;
        let mut observed = references.to_vec();
        observed.push(reference);
        Self::obligation_set(observed, &read_revision)
    }

    /// Folds the observed obligations into one deterministic, conflict-checked
    /// set at a single owner-issued read revision.
    ///
    /// Exact repeats of one logical identity collapse, so a repeated or
    /// reordered page request is idempotent; a divergent repeat is an identity
    /// conflict rather than one arbitrarily retained representative.
    fn obligation_set(
        references: Vec<AutomationReconciliationReference>,
        read_revision: &str,
    ) -> Result<AutomationObligationSet, StoreError> {
        let mut by_occurrence: BTreeMap<String, AutomationReconciliationReference> =
            BTreeMap::new();
        for reference in references {
            match by_occurrence.get(&reference.occurrence_id) {
                Some(existing) if *existing == reference => {}
                Some(_) => return Err(StoreError::IdentityConflict),
                None => {
                    by_occurrence.insert(reference.occurrence_id.clone(), reference);
                }
            }
        }
        Ok(AutomationObligationSet {
            references: by_occurrence.into_values().collect(),
            read_revision: read_revision.to_owned(),
        })
    }

    /// Classifies one stored invocation row into a resolved effect or one
    /// typed reconciliation obligation.
    async fn occurrence_evidence(
        &self,
        entry: &Value,
        occurrence_id: &str,
        read_revision: &str,
    ) -> Result<OccurrenceEvidence, StoreError> {
        let Some(invocation) = projected_invocation(entry)? else {
            return Ok(OccurrenceEvidence::Unresolved(evidence_obligation(
                occurrence_id,
                AutomationReconciliationCause::MissingInvocationEvidence,
                read_revision,
            )));
        };
        let Some(provenance) = invocation.provenance.as_ref() else {
            return Ok(OccurrenceEvidence::Unresolved(evidence_obligation(
                occurrence_id,
                AutomationReconciliationCause::MissingInvocationProvenance,
                read_revision,
            )));
        };
        // An unavailable receipt lookup is unknown evidence, not an absent
        // effect: the row keeps its obligation instead of being dropped from
        // the denominator.
        let Ok(receipt) = self.client.receipt(provenance.operation_id.clone()).await else {
            return Ok(OccurrenceEvidence::Unresolved(evidence_obligation(
                occurrence_id,
                AutomationReconciliationCause::ReceiptEvidenceUnavailable,
                read_revision,
            )));
        };
        let Some(receipt) = receipt else {
            return Ok(OccurrenceEvidence::Unresolved(evidence_obligation(
                occurrence_id,
                AutomationReconciliationCause::UnresolvedOperation,
                read_revision,
            )));
        };
        receipt.validate()?;
        if receipt.idempotency_key != provenance.idempotency_key
            || receipt.canonical_request_hash != provenance.canonical_request_hash
            || receipt.state_fence != provenance.request_metadata.state_fence
        {
            return Err(StoreError::IdentityConflict);
        }
        // An exact committed receipt removes only its own obligation.
        if receipt.status == eliot_store_api::WriteReceiptStatus::Committed
            && receipt.require_reconciliation_envelope().is_ok()
        {
            Ok(OccurrenceEvidence::Resolved)
        } else {
            Ok(OccurrenceEvidence::Unresolved(evidence_obligation(
                occurrence_id,
                AutomationReconciliationCause::UnresolvedOperation,
                read_revision,
            )))
        }
    }

    /// Fails closed when the declared occurrence denominator is not
    /// owner-proven complete for one automation.
    ///
    /// The retirement leg only moves the current pointer, so the immutable
    /// invocation rows and their outstanding obligations survive it. What it
    /// must never do is retire on a bounded first page and let a later Status
    /// or History read of the retired automation report "no reconciliation
    /// obligation" from the same bounded page. Retirement itself is never
    /// refused because an effect is unresolved: the obligations are preserved
    /// verbatim, only an unrepresentable denominator is rejected.
    async fn require_complete_occurrence_denominator(
        &self,
        fence: &StateFence,
        automation_id: &str,
    ) -> Result<(), StoreError> {
        let obligations = self
            .reconciliation_obligations(fence, automation_id)
            .await?;
        if obligations.references.iter().any(|obligation| {
            obligation.cause == AutomationReconciliationCause::IncompleteDenominator
        }) {
            return Err(StoreError::InvalidField {
                field: "automation.reconciliation",
                reason: "retirement requires an owner-proven complete occurrence denominator",
            });
        }
        Ok(())
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
            } => {
                // Retirement may not narrow the occurrence denominator: the
                // retired automation still answers Status and History from the
                // same immutable invocation rows, so the leg first proves that
                // the complete obligation set is enumerable at one owner-issued
                // read revision. The proof runs before the transition is
                // admitted, so an unrepresentable denominator never retires.
                self.require_complete_occurrence_denominator(
                    &request.context.state_fence,
                    automation_id,
                )
                .await?;
                Ok(automation_state_transition_params(
                    "remove".to_owned(),
                    automation_id.clone(),
                    automation_revision.clone(),
                    eliot_store_api::AUTOMATION_STATE_RETIRED.to_owned(),
                ))
            }
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
