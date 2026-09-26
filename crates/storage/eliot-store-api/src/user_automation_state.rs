//! Canonical user-automation wire contract (issue #1779, I5/I11).
//!
//! This module owns the serialization-only wire boundary for durable
//! `UserAutomation` revisions, admission state, and invocations: versioned
//! identity, closed parameter declarations support, per-leg completeness
//! validation on raw parameter maps, and request builders. It contains no
//! automation semantics, no lineage decisions, and no receipt validation:
//! the Kernel-owned domain (`eliot-kernel-core::user_automation`,
//! frozen at Beauvoir `7ac430c2`) owns revision validity, supersession,
//! invocation derivation, and wake compilation; the frozen service
//! (`UserAutomationService`) owns response validation; the canonical
//! backend drives persistence within its fenced transaction and outbox
//! owner. Wire shapes stay serialization-only and never become a second
//! semantic model.
//!
//! Wire identity: [`USER_AUTOMATION_STATE_SCHEMA_V1`]
//! (`eliot.automation.state.v1`). Mutation operation:
//! `ApplyUserAutomationState`. Read operation: `GetUserAutomationState`.
//! Transition class: `UserAutomation` with a `ReversibleMutation`
//! ceiling.
//!
//! Revision and invocation documents travel as opaque JSON objects: the
//! store preserves them verbatim and validates shape/bounds/closed
//! discriminators structurally. Lineage (create-first, edit-supersedes,
//! state transitions, invocation derivation) is Kernel-owned; the store
//! enforces only key existence, current-pointer compare-and-set, and
//! row immutability. Read queries mirror the domain `UserAutomationQueryKind`
//! minus `Preflight` (B-owned config projection per the frozen domain
//! `USER_AUTOMATION_PREFLIGHT_SELECTOR`).
//!
//! Paged denominator completeness (issue #2808). The bounded `history` and
//! `invocations` page payloads additionally carry one owner-issued
//! `completeness` object, so a consumer can never read a bounded first page
//! as a complete invocation denominator:
//!
//! ```text
//! completeness = {
//!   read_revision: <lowercase SHA-256 hex digest of the sorted
//!                   (revision-head key, revision) set this read observed>;
//!   returned:      <rows carried by this page>;
//!   coverage:      "COMPLETE" | "TRUNCATED";
//! }
//! ```
//!
//! `COMPLETE` is an owner proof, not a page-length observation: the owner
//! read one probe row past `max_records` and matched no further same-fence
//! row of the declared denominator. A page shorter than `max_records` is
//! never completeness by itself. `read_revision` changes whenever a commit
//! advances any revision head, so a new occurrence, an edit, or a retirement
//! all belong to a successor read and a page can never be presented as
//! current under a stale denominator. Absence of the object is `unknown`,
//! never unrestricted/complete (I5.16).
//!
//! Paged continuation (issue #2808). A `TRUNCATED` completeness block also
//! carries one owner-minted `next_cursor`, and the read accepts it back as the
//! optional `cursor` selector of the two page-bearing denominator reads
//! (`history`, `invocations`). The cursor is a versioned, canonically encoded
//! object bound to every property a stable continuation needs:
//!
//! ```text
//! automation-page:v1:{"after_row_id":…,"automation_id":…,"max_records":…,
//!                     "order":"ASC","query":…,"read_revision":…,
//!                     "state_fence":…}
//! ```
//!
//! - `query` and `automation_id` bind the cursor to one declared denominator,
//!   so a cursor minted for `invocations` cannot page `history` or another
//!   automation;
//! - `read_revision` and `state_fence` bind it to one head snapshot, so a page
//!   requested after a commit that advanced any revision head fails closed
//!   instead of skipping or repeating a row under a moving set;
//! - `order` names the ordering direction, so a consumer and an owner cannot
//!   silently disagree about which key the `after_row_id` compares against;
//! - `after_row_id` is the **exclusive last row identity** of the page just
//!   served — never an offset, so reordering, deletion and retirement cannot
//!   lose or repeat a logical identity;
//! - `max_records` binds the page bound in force, so a repage under different
//!   bounds invalidates outstanding cursors instead of re-reading a window.
//!
//! Both backends order the `history` denominator by `revision` and the
//! `invocations` denominator by `occurrence_id`, ascending, so the exclusive
//! comparison is a total, stable key on either contour. Callers echo cursors;
//! only the store owner mints them and [`automation_page_cursor_parse`]
//! re-verifies every binding before a page is served.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

use crate::{
    NamedMutationOperation, NamedMutationRequest, NamedReadOperation, NamedReadRequest,
    ReadConsistency, StateFence, StoreError, canonical_json_bytes,
};

/// Versioned wire/schema identity for canonical user-automation state.
pub const USER_AUTOMATION_STATE_SCHEMA_V1: &str = "eliot.automation.state.v1";
/// Closed mutation operation name for user-automation writes.
pub const USER_AUTOMATION_MUTATION_NAME: &str = "ApplyUserAutomationState";
/// Closed read operation name for user-automation reads.
pub const USER_AUTOMATION_READ_NAME: &str = "GetUserAutomationState";
/// Fixed transition scope for all automation rows (mirrors the frozen
/// domain `USER_AUTOMATION_SCOPE`).
pub const USER_AUTOMATION_SCOPE: &str = "user-automation";
/// Maximum accepted `automation_id` / `occurrence_id` length in bytes.
pub const MAX_AUTOMATION_ID_BYTES: usize = 256;
/// Maximum accepted `revision` identity length in bytes.
pub const MAX_AUTOMATION_REVISION_ID_BYTES: usize = 128;
/// Maximum accepted revision/invocation document length in bytes.
///
/// Revisions are bounded operator documents (full config, schedule,
/// policy, ceilings). 256 KiB covers deeply-nested policies while staying
/// fail-closed; larger payloads belong in Blob Store behind handles
/// (I7.2), never inline in a named operation.
pub const MAX_AUTOMATION_DOC_BYTES: usize = 262_144;
/// Maximum records one automation read may return.
pub const MAX_AUTOMATION_PAGE_RECORDS: u16 = 64;
/// Maximum accepted owner-minted page-continuation cursor length in bytes.
///
/// The cursor is a canonically encoded object over two bounded identities, two
/// digests, the ordering direction and the page bound, so 1 KiB leaves
/// headroom for the longest admissible identities while keeping the read input
/// far below the activated read input bound.
pub const MAX_AUTOMATION_CURSOR_BYTES: usize = 1_024;

/// Mutation discriminator parameter (closed mutation leg).
pub const AUTOMATION_PARAM_OPERATION: &str = "operation";
/// Stable automation identity (all legs; exact read selector).
pub const AUTOMATION_PARAM_AUTOMATION_ID: &str = "automation_id";
/// Immutable revision identity (revision legs; row key half).
pub const AUTOMATION_PARAM_REVISION: &str = "revision";
/// Opaque canonical revision document (revision legs).
pub const AUTOMATION_PARAM_REVISION_JSON: &str = "revision_json";
/// Superseded revision identity (edit leg only).
pub const AUTOMATION_PARAM_PREVIOUS_REVISION: &str = "previous_revision";
/// Closed admission state (revision legs; stored on the current pointer).
pub const AUTOMATION_PARAM_CONFIGURATION_STATE: &str = "configuration_state";
/// Stable occurrence identity (run-now leg; row key).
pub const AUTOMATION_PARAM_OCCURRENCE_ID: &str = "occurrence_id";
/// Opaque canonical invocation document (run-now leg).
pub const AUTOMATION_PARAM_INVOCATION_JSON: &str = "invocation_json";
/// Opaque canonical failure document (failure leg): JSON object with the
/// class `fingerprint`, the typed `reason` wire value, and the
/// `notification_dedup_key` echoed from the failure projection.
pub const AUTOMATION_PARAM_FAILURE_JSON: &str = "failure_json";
/// Read query discriminator parameter.
pub const AUTOMATION_PARAM_QUERY: &str = "query";
/// `"true"`/`"false"` retired-row inclusion (list query, required).
pub const AUTOMATION_PARAM_INCLUDE_RETIRED: &str = "include_retired";
/// Decimal page-size bound (list/history/invocations, required).
pub const AUTOMATION_PARAM_MAX_RECORDS: &str = "max_records";
/// Owner-minted page-continuation selector (history/invocations, optional).
///
/// An absent selector reads the first page of the declared denominator. A
/// present selector resumes strictly after the exclusive last row identity the
/// owner served, under the read revision, fence, ordering direction and page
/// bound the owner minted it with. It is never an offset, so a moving set can
/// neither lose nor repeat a row.
pub const AUTOMATION_PARAM_CURSOR: &str = "cursor";

/// Mutation leg discriminator values (mirror the domain operation
/// `snake_case` kinds).
pub const AUTOMATION_OPERATION_CREATE: &str = "create";
/// Mutation leg discriminator values.
pub const AUTOMATION_OPERATION_EDIT: &str = "edit";
/// Mutation leg discriminator values.
pub const AUTOMATION_OPERATION_PAUSE: &str = "pause";
/// Mutation leg discriminator values.
pub const AUTOMATION_OPERATION_RESUME: &str = "resume";
/// Mutation leg discriminator values.
pub const AUTOMATION_OPERATION_REMOVE: &str = "remove";
/// Mutation leg discriminator values.
pub const AUTOMATION_OPERATION_RUN_NOW: &str = "run-now";
/// Mutation leg discriminator values (failure-history writer leg).
pub const AUTOMATION_OPERATION_FAILURE: &str = "failure";

/// Read query discriminator values (mirror the domain query kinds minus
/// `Preflight`, which is B-owned).
pub const AUTOMATION_QUERY_LIST: &str = "list";
/// Read query discriminator values.
pub const AUTOMATION_QUERY_CURRENT: &str = "current";
/// Read query discriminator values.
pub const AUTOMATION_QUERY_HISTORY: &str = "history";
/// Read query discriminator values.
pub const AUTOMATION_QUERY_INVOCATIONS: &str = "invocations";
/// Read query discriminator values (the failure writer leg records the
/// last failure row; absence stays explicit, never fabricated).
pub const AUTOMATION_QUERY_FAILURE: &str = "failure";

/// Closed admission-state wire values (mirror the domain
/// `SCREAMING_SNAKE_CASE` states).
pub const AUTOMATION_STATE_ACTIVE: &str = "ACTIVE";
/// Closed admission-state wire values.
pub const AUTOMATION_STATE_PAUSED: &str = "PAUSED";
/// Closed admission-state wire values.
pub const AUTOMATION_STATE_BLOCKED_CONFIG: &str = "BLOCKED_CONFIG";
/// Closed admission-state wire values.
pub const AUTOMATION_STATE_RETIRED: &str = "RETIRED";

/// Read payload field: current-row array (list).
pub const AUTOMATION_PAGE_CURRENTS: &str = "currents";
/// Read payload field: single current row or null (current).
pub const AUTOMATION_PAGE_CURRENT: &str = "current";
/// Read payload field: revision-row array (history).
pub const AUTOMATION_PAGE_REVISIONS: &str = "revisions";
/// Read payload field: invocation-row array (invocations).
pub const AUTOMATION_PAGE_INVOCATIONS: &str = "invocations";
/// Read payload field: failure row or null (failure).
pub const AUTOMATION_PAGE_FAILURE: &str = "failure";
/// Read payload field: owner revision read at (max current revision).
pub const AUTOMATION_PAGE_REVISION: &str = "revision";
/// Read payload field: projection fence.
pub const AUTOMATION_PAGE_STATE_FENCE: &str = "state_fence";
/// Completeness field: owner-minted continuation for the next page.
///
/// Present exactly on a `TRUNCATED` page, and absent on a `COMPLETE` one: a
/// complete denominator has no successor page, so absence here is a proven end
/// of the set, not missing evidence (I5.16).
pub const AUTOMATION_PAGE_NEXT_CURSOR: &str = "next_cursor";
/// Version tag of the canonical automation page-continuation cursor encoding.
pub const AUTOMATION_CURSOR_VERSION: &str = "automation-page:v1";
/// The one ordering direction the automation page denominators serve.
///
/// Both backends order the `history` denominator by `revision` and the
/// `invocations` denominator by `occurrence_id`, ascending. The direction is
/// part of the cursor so a consumer can never compare `after_row_id` against a
/// different key than the owner paged on.
pub const AUTOMATION_CURSOR_ORDER_ASCENDING: &str = "ASC";

/// Fail-closed automation wire errors before [`StoreError`] projection.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum AutomationContractError {
    /// A field failed bounded validation.
    #[error("invalid field {field}: {reason}")]
    InvalidField {
        /// Invalid field name.
        field: &'static str,
        /// Stable reason code.
        reason: &'static str,
    },
    /// A required leg parameter is absent.
    #[error("missing automation parameter: {0}")]
    MissingParameter(&'static str),
}

impl AutomationContractError {
    /// Projects the contract error onto the closed store error set.
    #[must_use]
    pub const fn into_store_error(self) -> StoreError {
        match self {
            Self::InvalidField { field, reason } => StoreError::InvalidField { field, reason },
            Self::MissingParameter(name) => StoreError::InvalidField {
                field: name,
                reason: "missing required automation parameter",
            },
        }
    }
}

/// Raw validated mutation decoded from a mutation parameter map.
///
/// Documents stay opaque strings: the backend persists them verbatim and
/// arbitrates keys/pointers. This enum carries no lineage semantics
/// beyond leg completeness.
#[derive(Clone, Debug, PartialEq)]
pub enum DecodedAutomationMutation {
    /// Create the first immutable revision + current pointer.
    Create {
        /// Stable automation identity.
        automation_id: String,
        /// Immutable revision identity.
        revision: String,
        /// Verbatim canonical revision document.
        revision_json: String,
        /// Closed admission state for the current pointer.
        configuration_state: String,
    },
    /// Add a superseding immutable revision + move the current pointer.
    Edit {
        /// Stable automation identity.
        automation_id: String,
        /// Current revision that must be superseded.
        previous_revision: String,
        /// New immutable revision identity.
        revision: String,
        /// Verbatim canonical revision document.
        revision_json: String,
        /// Closed admission state for the current pointer.
        configuration_state: String,
    },
    /// Move admission state without touching the immutable revision.
    StateTransition {
        /// Closed leg: pause, resume, or remove.
        operation: String,
        /// Stable automation identity.
        automation_id: String,
        /// Revision the pointer must currently name.
        revision: String,
        /// Closed admission state for the current pointer.
        configuration_state: String,
    },
    /// Record one manual occurrence without mutating the schedule.
    RunNow {
        /// Stable automation identity.
        automation_id: String,
        /// Immutable revision being run (must exist).
        revision: String,
        /// Stable occurrence identity (derived by the Kernel owner).
        occurrence_id: String,
        /// Verbatim canonical invocation document.
        invocation_json: String,
    },
    /// Record one revision-bound configuration failure as immutable
    /// history. The named revision must exist; repeats of one failure
    /// class converge on the existing row.
    Failure {
        /// Stable automation identity.
        automation_id: String,
        /// Immutable revision that owns the failure class (must exist).
        revision: String,
        /// Stable occurrence identity retained as history context.
        occurrence_id: String,
        /// Verbatim canonical failure document.
        failure_json: String,
        /// Parsed canonical failure document.
        failure: AutomationFailureDocument,
    },
}

/// Decoded read query with its closed selectors.
#[derive(Clone, Debug, PartialEq)]
pub struct DecodedAutomationRead {
    /// Closed query discriminator.
    pub query: String,
    /// Exact automation selector (required except list).
    pub automation_id: Option<String>,
    /// Optional exact immutable revision selector for current/history owner reads.
    pub requested_revision: Option<String>,
    /// Optional exact occurrence selector for invocation-owner reads.
    pub requested_occurrence_id: Option<String>,
    /// Retired-row inclusion (list only).
    pub include_retired: bool,
    /// Page-size bound (list/history/invocations only).
    pub max_records: u16,
    /// Verified owner-minted continuation for a paged denominator read.
    pub cursor: Option<AutomationPageCursor>,
}

/// One owner-minted continuation over one paged automation denominator.
///
/// Every field is a binding the owner re-verifies before serving the next page,
/// and every field is required: a continuation that could omit its denominator,
/// its head snapshot, its direction or its exclusive last row identity would be
/// an offset over a changing set. The exclusive last row identity is the
/// `revision` of the last history row served, or the `occurrence_id` of the
/// last invocation row served, matching the query's total ordering key.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AutomationPageCursor {
    /// Closed query discriminator whose denominator this cursor pages.
    pub query: String,
    /// Stable automation identity owning the declared denominator.
    pub automation_id: String,
    /// Owner-issued read revision this cursor was minted at.
    pub read_revision: String,
    /// Admission fence the page was served under.
    pub state_fence: StateFence,
    /// Ordering direction of the denominator (`ASC`).
    pub order: String,
    /// Exclusive last row identity served; the next page starts strictly after.
    pub after_row_id: String,
    /// Page bound in force when the cursor was minted.
    pub max_records: u16,
}

impl AutomationPageCursor {
    /// Validates every binding before a page is served from the cursor.
    ///
    /// Rejects a non-closed query, a direction this contract does not serve, a
    /// blank or unbounded row identity, a page bound outside the closed range,
    /// and a read revision that is not the SHA-256 hex the owner issues. I5.27:
    /// the encoding is versioned and every field affecting scope and ordering is
    /// explicit, never defaulted or omitted.
    fn validate(&self) -> Result<(), AutomationContractError> {
        if !matches!(
            self.query.as_str(),
            AUTOMATION_QUERY_HISTORY | AUTOMATION_QUERY_INVOCATIONS
        ) {
            return Err(AutomationContractError::InvalidField {
                field: AUTOMATION_PARAM_CURSOR,
                reason: "continuation is only valid for paged denominator reads",
            });
        }
        if self.order != AUTOMATION_CURSOR_ORDER_ASCENDING {
            return Err(AutomationContractError::InvalidField {
                field: AUTOMATION_PARAM_CURSOR,
                reason: "continuation direction is not a closed value",
            });
        }
        validate_automation_id(&self.automation_id).map_err(|_| {
            AutomationContractError::InvalidField {
                field: AUTOMATION_PARAM_CURSOR,
                reason: "continuation automation identity is invalid",
            }
        })?;
        if self.after_row_id.trim().is_empty() || self.after_row_id.chars().any(char::is_control) {
            return Err(AutomationContractError::InvalidField {
                field: AUTOMATION_PARAM_CURSOR,
                reason: "continuation last row identity must be non-blank text",
            });
        }
        if self.after_row_id.len() > MAX_AUTOMATION_ID_BYTES {
            return Err(AutomationContractError::InvalidField {
                field: AUTOMATION_PARAM_CURSOR,
                reason: "continuation last row identity exceeds the length bound",
            });
        }
        if self.read_revision.len() != 64
            || !self
                .read_revision
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return Err(AutomationContractError::InvalidField {
                field: AUTOMATION_PARAM_CURSOR,
                reason: "continuation read revision must be lowercase SHA-256 hex",
            });
        }
        self.state_fence
            .validate()
            .map_err(|_| AutomationContractError::InvalidField {
                field: AUTOMATION_PARAM_CURSOR,
                reason: "continuation fence is invalid",
            })?;
        if self.max_records == 0 || self.max_records > MAX_AUTOMATION_PAGE_RECORDS {
            return Err(AutomationContractError::InvalidField {
                field: AUTOMATION_PARAM_CURSOR,
                reason: "continuation page bound is out of range",
            });
        }
        Ok(())
    }

    /// Renders the canonical wire encoding of one continuation.
    ///
    /// The canonical encoding is deterministic and versioned: the same bindings
    /// always produce the same bytes on every contour, so a cursor survives a
    /// round trip through a request, a response and the next request unchanged.
    ///
    /// An encoding failure is a typed mint failure, never an empty body: a
    /// versioned prefix carrying no bindings would be a well-formed-looking
    /// wire that no echoed continuation can ever verify, so the owner would
    /// publish a `TRUNCATED` page whose successor has no address. The mint
    /// fails closed instead, and the read that needed the continuation fails
    /// rather than reporting a page whose remainder cannot be resumed.
    fn to_wire(&self) -> Result<String, StoreError> {
        let body = canonical_json_bytes(self).map_err(|error| {
            StoreError::Serialization(format!(
                "automation page cursor canonical encoding failed: {error}"
            ))
        })?;
        let body = String::from_utf8(body).map_err(|error| {
            StoreError::Serialization(format!(
                "automation page cursor canonical encoding is not UTF-8: {error}"
            ))
        })?;
        Ok(format!("{AUTOMATION_CURSOR_VERSION}:{body}"))
    }
}

/// Mints one continuation for the page just served.
///
/// The owner calls this only for a `TRUNCATED` page, binding the exclusive last
/// row identity it actually served, the read revision and fence it served it
/// under, and the page bound in force. Callers echo the returned text; they
/// never construct or edit it.
pub fn automation_cursor_mint(
    query: &str,
    automation_id: &str,
    read_revision: &str,
    state_fence: &StateFence,
    after_row_id: &str,
    max_records: u16,
) -> Result<String, StoreError> {
    let cursor = AutomationPageCursor {
        query: query.to_owned(),
        automation_id: automation_id.to_owned(),
        read_revision: read_revision.to_owned(),
        state_fence: state_fence.clone(),
        order: AUTOMATION_CURSOR_ORDER_ASCENDING.to_owned(),
        after_row_id: after_row_id.to_owned(),
        max_records,
    };
    cursor
        .validate()
        .map_err(AutomationContractError::into_store_error)?;
    let wire = cursor.to_wire()?;
    if wire.len() > MAX_AUTOMATION_CURSOR_BYTES {
        return Err(StoreError::PayloadTooLarge);
    }
    Ok(wire)
}

/// Verifies one echoed continuation against the page about to be served.
///
/// Only the canonical [`AUTOMATION_CURSOR_VERSION`] encoding verifies; no
/// scaffold, foreign or hand-written shape is accepted, because a cursor whose
/// denominator, head snapshot, direction, fence, page bound or exclusive last
/// row identity is not exactly the one the owner minted is an offset over a
/// moving set. `read_revision` is re-proved against the digest the owner is
/// serving right now, so a commit that advanced any revision head invalidates
/// outstanding cursors and restarts enumeration instead of drifting.
pub fn automation_cursor_verify(
    wire: &str,
    query: &str,
    automation_id: &str,
    read_revision: &str,
    state_fence: &StateFence,
    max_records: u16,
) -> Result<AutomationPageCursor, StoreError> {
    let malformed = || StoreError::InvalidField {
        field: AUTOMATION_PARAM_CURSOR,
        reason: "continuation is malformed, foreign, or stale",
    };
    let cursor = automation_cursor_shape(wire, query, automation_id, max_records)?;
    if cursor.read_revision != read_revision || cursor.state_fence != *state_fence {
        return Err(malformed());
    }
    Ok(cursor)
}

/// Builds the closed `ApplyUserAutomationState` mutation request.
#[must_use]
pub fn automation_mutation_request(params: BTreeMap<String, Value>) -> NamedMutationRequest {
    NamedMutationRequest {
        operation: NamedMutationOperation::ApplyUserAutomationState,
        parameters: params,
    }
}

/// Builds a create-leg parameter map.
pub fn automation_create_params(
    automation_id: String,
    revision: String,
    configuration_state: String,
    revision_json: String,
) -> BTreeMap<String, Value> {
    BTreeMap::from([
        (
            AUTOMATION_PARAM_OPERATION.to_owned(),
            Value::String(AUTOMATION_OPERATION_CREATE.to_owned()),
        ),
        (
            AUTOMATION_PARAM_AUTOMATION_ID.to_owned(),
            Value::String(automation_id),
        ),
        (
            AUTOMATION_PARAM_REVISION.to_owned(),
            Value::String(revision),
        ),
        (
            AUTOMATION_PARAM_CONFIGURATION_STATE.to_owned(),
            Value::String(configuration_state),
        ),
        (
            AUTOMATION_PARAM_REVISION_JSON.to_owned(),
            Value::String(revision_json),
        ),
    ])
}

/// Builds an edit-leg parameter map.
pub fn automation_edit_params(
    automation_id: String,
    previous_revision: String,
    revision: String,
    configuration_state: String,
    revision_json: String,
) -> BTreeMap<String, Value> {
    let mut params =
        automation_create_params(automation_id, revision, configuration_state, revision_json);
    params.insert(
        AUTOMATION_PARAM_OPERATION.to_owned(),
        Value::String(AUTOMATION_OPERATION_EDIT.to_owned()),
    );
    params.insert(
        AUTOMATION_PARAM_PREVIOUS_REVISION.to_owned(),
        Value::String(previous_revision),
    );
    params
}

/// Builds a pause/resume/remove-leg parameter map (no revision document:
/// the immutable revision is untouched, only the pointer moves).
pub fn automation_state_transition_params(
    operation: String,
    automation_id: String,
    revision: String,
    configuration_state: String,
) -> BTreeMap<String, Value> {
    BTreeMap::from([
        (
            AUTOMATION_PARAM_OPERATION.to_owned(),
            Value::String(operation),
        ),
        (
            AUTOMATION_PARAM_AUTOMATION_ID.to_owned(),
            Value::String(automation_id),
        ),
        (
            AUTOMATION_PARAM_REVISION.to_owned(),
            Value::String(revision),
        ),
        (
            AUTOMATION_PARAM_CONFIGURATION_STATE.to_owned(),
            Value::String(configuration_state),
        ),
    ])
}

/// Builds a run-now-leg parameter map.
pub fn automation_run_now_params(
    automation_id: String,
    revision: String,
    occurrence_id: String,
    invocation_json: String,
) -> BTreeMap<String, Value> {
    BTreeMap::from([
        (
            AUTOMATION_PARAM_OPERATION.to_owned(),
            Value::String(AUTOMATION_OPERATION_RUN_NOW.to_owned()),
        ),
        (
            AUTOMATION_PARAM_AUTOMATION_ID.to_owned(),
            Value::String(automation_id),
        ),
        (
            AUTOMATION_PARAM_REVISION.to_owned(),
            Value::String(revision),
        ),
        (
            AUTOMATION_PARAM_OCCURRENCE_ID.to_owned(),
            Value::String(occurrence_id),
        ),
        (
            AUTOMATION_PARAM_INVOCATION_JSON.to_owned(),
            Value::String(invocation_json),
        ),
    ])
}

/// Builds a failure-leg parameter map.
pub fn automation_failure_params(
    automation_id: String,
    revision: String,
    occurrence_id: String,
    failure_json: String,
) -> BTreeMap<String, Value> {
    BTreeMap::from([
        (
            AUTOMATION_PARAM_OPERATION.to_owned(),
            Value::String(AUTOMATION_OPERATION_FAILURE.to_owned()),
        ),
        (
            AUTOMATION_PARAM_AUTOMATION_ID.to_owned(),
            Value::String(automation_id),
        ),
        (
            AUTOMATION_PARAM_REVISION.to_owned(),
            Value::String(revision),
        ),
        (
            AUTOMATION_PARAM_OCCURRENCE_ID.to_owned(),
            Value::String(occurrence_id),
        ),
        (
            AUTOMATION_PARAM_FAILURE_JSON.to_owned(),
            Value::String(failure_json),
        ),
    ])
}

/// Builds the closed `GetUserAutomationState` read request.
pub fn automation_read_request(
    query: String,
    automation_id: Option<String>,
    include_retired: bool,
    max_records: u16,
    state_fence: StateFence,
) -> Result<NamedReadRequest, StoreError> {
    let mut parameters = BTreeMap::new();
    parameters.insert(AUTOMATION_PARAM_QUERY.to_owned(), Value::String(query));
    if let Some(automation_id) = automation_id {
        parameters.insert(
            AUTOMATION_PARAM_AUTOMATION_ID.to_owned(),
            Value::String(automation_id),
        );
    }
    parameters.insert(
        AUTOMATION_PARAM_INCLUDE_RETIRED.to_owned(),
        Value::String(include_retired.to_string()),
    );
    parameters.insert(
        AUTOMATION_PARAM_MAX_RECORDS.to_owned(),
        Value::String(max_records.to_string()),
    );
    let request = NamedReadRequest {
        operation: NamedReadOperation::GetUserAutomationState,
        scope_id: None,
        consistency: ReadConsistency::ExactFence,
        state_fence,
        parameters,
    };
    request.validate()?;
    Ok(request)
}

/// Builds an exact immutable-revision read for the canonical owner boundary.
///
/// The selector is accepted only by the closed `current`/`history` read
/// contract. Provider adapters must use it to address the immutable row by
/// identity; it is not a page cursor or a caller-authored revision document.
pub fn automation_revision_read_request(
    query: String,
    automation_id: String,
    revision: String,
    include_retired: bool,
    max_records: u16,
    state_fence: StateFence,
) -> Result<NamedReadRequest, StoreError> {
    let mut request = automation_read_request(
        query,
        Some(automation_id),
        include_retired,
        max_records,
        state_fence,
    )?;
    request.parameters.insert(
        AUTOMATION_PARAM_REVISION.to_owned(),
        Value::String(revision),
    );
    request.validate()?;
    Ok(request)
}

/// Builds an exact invocation read for one owner-issued occurrence.
///
/// The selector addresses the immutable invocation row by its occurrence
/// identity. It is accepted only by the closed `invocations` query and never
/// falls back to the bounded invocation page.
pub fn automation_invocation_read_request(
    automation_id: String,
    occurrence_id: String,
    state_fence: StateFence,
) -> Result<NamedReadRequest, StoreError> {
    let mut request = automation_read_request(
        AUTOMATION_QUERY_INVOCATIONS.to_owned(),
        Some(automation_id),
        false,
        1,
        state_fence,
    )?;
    request.parameters.insert(
        AUTOMATION_PARAM_OCCURRENCE_ID.to_owned(),
        Value::String(occurrence_id),
    );
    request.validate()?;
    Ok(request)
}

/// Validates closed mutation parameters for one automation operation.
///
/// The operation identity is the discriminator: each leg declares exactly
/// its required params, and value rules (id bounds, document shape/bounds,
/// closed state/query membership, page bounds) run here so every backend
/// shares one acceptance boundary. Lineage validity (supersession,
/// transitions, invocation derivation) stays Kernel-owned.
pub fn validate_automation_mutation_params(
    operation: NamedMutationOperation,
    parameters: &BTreeMap<String, Value>,
) -> Result<(), StoreError> {
    if operation != NamedMutationOperation::ApplyUserAutomationState {
        return Err(StoreError::UnknownOperation);
    }
    let leg = text_param(parameters, AUTOMATION_PARAM_OPERATION)?;
    validate_automation_id(text_param(parameters, AUTOMATION_PARAM_AUTOMATION_ID)?)?;
    match leg {
        AUTOMATION_OPERATION_CREATE => {
            validate_revision_id(text_param(parameters, AUTOMATION_PARAM_REVISION)?)?;
            validate_configuration_state(text_param(
                parameters,
                AUTOMATION_PARAM_CONFIGURATION_STATE,
            )?)?;
            validate_automation_doc(
                text_param(parameters, AUTOMATION_PARAM_REVISION_JSON)?,
                AUTOMATION_PARAM_REVISION_JSON,
            )?;
            Ok(())
        }
        AUTOMATION_OPERATION_EDIT => {
            validate_revision_id(text_param(parameters, AUTOMATION_PARAM_PREVIOUS_REVISION)?)?;
            validate_revision_id(text_param(parameters, AUTOMATION_PARAM_REVISION)?)?;
            validate_configuration_state(text_param(
                parameters,
                AUTOMATION_PARAM_CONFIGURATION_STATE,
            )?)?;
            validate_automation_doc(
                text_param(parameters, AUTOMATION_PARAM_REVISION_JSON)?,
                AUTOMATION_PARAM_REVISION_JSON,
            )?;
            Ok(())
        }
        AUTOMATION_OPERATION_PAUSE | AUTOMATION_OPERATION_RESUME | AUTOMATION_OPERATION_REMOVE => {
            validate_revision_id(text_param(parameters, AUTOMATION_PARAM_REVISION)?)?;
            validate_configuration_state(text_param(
                parameters,
                AUTOMATION_PARAM_CONFIGURATION_STATE,
            )?)?;
            Ok(())
        }
        AUTOMATION_OPERATION_RUN_NOW => {
            validate_revision_id(text_param(parameters, AUTOMATION_PARAM_REVISION)?)?;
            validate_occurrence_id(text_param(parameters, AUTOMATION_PARAM_OCCURRENCE_ID)?)?;
            validate_automation_doc(
                text_param(parameters, AUTOMATION_PARAM_INVOCATION_JSON)?,
                AUTOMATION_PARAM_INVOCATION_JSON,
            )?;
            Ok(())
        }
        AUTOMATION_OPERATION_FAILURE => {
            validate_revision_id(text_param(parameters, AUTOMATION_PARAM_REVISION)?)?;
            validate_occurrence_id(text_param(parameters, AUTOMATION_PARAM_OCCURRENCE_ID)?)?;
            parse_automation_failure_document(text_param(
                parameters,
                AUTOMATION_PARAM_FAILURE_JSON,
            )?)?;
            Ok(())
        }
        _ => Err(StoreError::UnknownOperation),
    }
}

/// Decodes one validated mutation parameter map into its raw leg.
pub fn decode_automation_mutation(
    operation: NamedMutationOperation,
    parameters: &BTreeMap<String, Value>,
) -> Result<DecodedAutomationMutation, StoreError> {
    validate_automation_mutation_params(operation, parameters)?;
    let text_of = |name: &'static str| -> Result<String, StoreError> {
        parameters
            .get(name)
            .and_then(Value::as_str)
            .map(str::to_owned)
            .ok_or(StoreError::InvalidField {
                field: name,
                reason: "automation parameter must be present",
            })
    };
    let leg = text_of(AUTOMATION_PARAM_OPERATION)?;
    match leg.as_str() {
        AUTOMATION_OPERATION_CREATE => Ok(DecodedAutomationMutation::Create {
            automation_id: text_of(AUTOMATION_PARAM_AUTOMATION_ID)?,
            revision: text_of(AUTOMATION_PARAM_REVISION)?,
            revision_json: text_of(AUTOMATION_PARAM_REVISION_JSON)?,
            configuration_state: text_of(AUTOMATION_PARAM_CONFIGURATION_STATE)?,
        }),
        AUTOMATION_OPERATION_EDIT => Ok(DecodedAutomationMutation::Edit {
            automation_id: text_of(AUTOMATION_PARAM_AUTOMATION_ID)?,
            previous_revision: text_of(AUTOMATION_PARAM_PREVIOUS_REVISION)?,
            revision: text_of(AUTOMATION_PARAM_REVISION)?,
            revision_json: text_of(AUTOMATION_PARAM_REVISION_JSON)?,
            configuration_state: text_of(AUTOMATION_PARAM_CONFIGURATION_STATE)?,
        }),
        AUTOMATION_OPERATION_PAUSE | AUTOMATION_OPERATION_RESUME | AUTOMATION_OPERATION_REMOVE => {
            Ok(DecodedAutomationMutation::StateTransition {
                operation: leg,
                automation_id: text_of(AUTOMATION_PARAM_AUTOMATION_ID)?,
                revision: text_of(AUTOMATION_PARAM_REVISION)?,
                configuration_state: text_of(AUTOMATION_PARAM_CONFIGURATION_STATE)?,
            })
        }
        AUTOMATION_OPERATION_RUN_NOW => Ok(DecodedAutomationMutation::RunNow {
            automation_id: text_of(AUTOMATION_PARAM_AUTOMATION_ID)?,
            revision: text_of(AUTOMATION_PARAM_REVISION)?,
            occurrence_id: text_of(AUTOMATION_PARAM_OCCURRENCE_ID)?,
            invocation_json: text_of(AUTOMATION_PARAM_INVOCATION_JSON)?,
        }),
        AUTOMATION_OPERATION_FAILURE => {
            let failure_json = text_of(AUTOMATION_PARAM_FAILURE_JSON)?;
            Ok(DecodedAutomationMutation::Failure {
                automation_id: text_of(AUTOMATION_PARAM_AUTOMATION_ID)?,
                revision: text_of(AUTOMATION_PARAM_REVISION)?,
                occurrence_id: text_of(AUTOMATION_PARAM_OCCURRENCE_ID)?,
                failure: parse_automation_failure_document(&failure_json)?,
                failure_json,
            })
        }
        _ => Err(StoreError::UnknownOperation),
    }
}

/// Validates the closed read selectors and decodes the query.
#[allow(
    clippy::too_many_lines,
    reason = "closed query-discriminator table; one arm per read kind"
)]
pub fn validate_automation_read_params(
    parameters: &BTreeMap<String, Value>,
) -> Result<DecodedAutomationRead, StoreError> {
    let query = text_param(parameters, AUTOMATION_PARAM_QUERY)?;
    let automation_id = parameters
        .get(AUTOMATION_PARAM_AUTOMATION_ID)
        .and_then(Value::as_str)
        .map(str::to_owned);
    if let Some(id) = automation_id.as_deref() {
        validate_automation_id(id)?;
    }
    let requested_revision = parameters
        .get(AUTOMATION_PARAM_REVISION)
        .and_then(Value::as_str)
        .map(str::to_owned);
    if let Some(revision) = requested_revision.as_deref() {
        validate_revision_id(revision)?;
    }
    let requested_occurrence_id = parameters
        .get(AUTOMATION_PARAM_OCCURRENCE_ID)
        .and_then(Value::as_str)
        .map(str::to_owned);
    if let Some(occurrence_id) = requested_occurrence_id.as_deref() {
        validate_occurrence_id(occurrence_id)?;
    }
    let include_retired = parameters
        .get(AUTOMATION_PARAM_INCLUDE_RETIRED)
        .and_then(Value::as_str)
        .ok_or(StoreError::InvalidField {
            field: "automation.include_retired",
            reason: "retired-row inclusion flag is required",
        })?;
    let include_retired = match include_retired {
        "true" => true,
        "false" => false,
        _ => {
            return Err(StoreError::InvalidField {
                field: "automation.include_retired",
                reason: "retired-row inclusion must be true or false",
            });
        }
    };
    let max_records = parameters
        .get(AUTOMATION_PARAM_MAX_RECORDS)
        .and_then(Value::as_str)
        .ok_or(StoreError::InvalidField {
            field: "automation.max_records",
            reason: "page bound is required",
        })?;
    let max_records: u16 = max_records.parse().map_err(|_| StoreError::InvalidField {
        field: "automation.max_records",
        reason: "page bound must be a decimal count",
    })?;
    if max_records == 0 || max_records > MAX_AUTOMATION_PAGE_RECORDS {
        return Err(StoreError::InvalidField {
            field: "automation.max_records",
            reason: "page bound is out of range",
        });
    }
    // A present-but-non-string continuation fails closed instead of reading as
    // an absent cursor, which would silently restart the denominator at page
    // one and re-serve rows the consumer already folded in.
    let cursor_text = match parameters.get(AUTOMATION_PARAM_CURSOR) {
        None => None,
        Some(value) => Some(value.as_str().ok_or(StoreError::InvalidField {
            field: AUTOMATION_PARAM_CURSOR,
            reason: "continuation must be a string",
        })?),
    };
    match query {
        AUTOMATION_QUERY_LIST => {
            if requested_revision.is_some() || requested_occurrence_id.is_some() {
                return Err(StoreError::InvalidField {
                    field: if requested_revision.is_some() {
                        AUTOMATION_PARAM_REVISION
                    } else {
                        AUTOMATION_PARAM_OCCURRENCE_ID
                    },
                    reason: "selector is not valid for list reads",
                });
            }
            if cursor_text.is_some() {
                return Err(StoreError::InvalidField {
                    field: AUTOMATION_PARAM_CURSOR,
                    reason: "continuation is not valid for list reads",
                });
            }
            Ok(DecodedAutomationRead {
                query: query.to_owned(),
                automation_id: None,
                requested_revision: None,
                requested_occurrence_id: None,
                include_retired,
                max_records,
                cursor: None,
            })
        }
        AUTOMATION_QUERY_CURRENT | AUTOMATION_QUERY_HISTORY => {
            if requested_occurrence_id.is_some() {
                return Err(StoreError::InvalidField {
                    field: AUTOMATION_PARAM_OCCURRENCE_ID,
                    reason: "occurrence selector is only valid for invocations reads",
                });
            }
            let automation_id = automation_id.ok_or(StoreError::InvalidField {
                field: "automation.automation_id",
                reason: "exact automation selector is required",
            })?;
            // An exact immutable-revision read addresses one immutable row and
            // must never widen into a bounded page, so it cannot also page.
            let cursor = match (query, cursor_text) {
                (AUTOMATION_QUERY_HISTORY, Some(text)) if requested_revision.is_none() => Some(
                    automation_cursor_shape(text, query, &automation_id, max_records)?,
                ),
                (_, Some(_)) => {
                    return Err(StoreError::InvalidField {
                        field: AUTOMATION_PARAM_CURSOR,
                        reason: "continuation is only valid for paged denominator reads",
                    });
                }
                _ => None,
            };
            Ok(DecodedAutomationRead {
                query: query.to_owned(),
                automation_id: Some(automation_id),
                requested_revision,
                requested_occurrence_id: None,
                include_retired,
                max_records,
                cursor,
            })
        }
        AUTOMATION_QUERY_INVOCATIONS => {
            if requested_revision.is_some() {
                return Err(StoreError::InvalidField {
                    field: AUTOMATION_PARAM_REVISION,
                    reason: "revision selector is only valid for current/history reads",
                });
            }
            let automation_id = automation_id.ok_or(StoreError::InvalidField {
                field: "automation.automation_id",
                reason: "exact automation selector is required",
            })?;
            // An exact occurrence read addresses one retained row and must never
            // widen into a bounded page, so it cannot also page.
            let cursor =
                match cursor_text {
                    Some(text) if requested_occurrence_id.is_none() => Some(
                        automation_cursor_shape(text, query, &automation_id, max_records)?,
                    ),
                    Some(_) => {
                        return Err(StoreError::InvalidField {
                            field: AUTOMATION_PARAM_CURSOR,
                            reason: "continuation is not valid with an exact occurrence selector",
                        });
                    }
                    None => None,
                };
            Ok(DecodedAutomationRead {
                query: query.to_owned(),
                automation_id: Some(automation_id),
                requested_revision: None,
                requested_occurrence_id,
                include_retired,
                max_records,
                cursor,
            })
        }
        AUTOMATION_QUERY_FAILURE => {
            if requested_revision.is_some() || requested_occurrence_id.is_some() {
                return Err(StoreError::InvalidField {
                    field: if requested_revision.is_some() {
                        AUTOMATION_PARAM_REVISION
                    } else {
                        AUTOMATION_PARAM_OCCURRENCE_ID
                    },
                    reason: "selector is not valid for failure reads",
                });
            }
            if cursor_text.is_some() {
                return Err(StoreError::InvalidField {
                    field: AUTOMATION_PARAM_CURSOR,
                    reason: "continuation is not valid for failure reads",
                });
            }
            let automation_id = automation_id.ok_or(StoreError::InvalidField {
                field: "automation.automation_id",
                reason: "exact automation selector is required",
            })?;
            Ok(DecodedAutomationRead {
                query: query.to_owned(),
                automation_id: Some(automation_id),
                requested_revision: None,
                requested_occurrence_id: None,
                include_retired,
                max_records,
                cursor: None,
            })
        }
        _ => Err(StoreError::UnknownOperation),
    }
}

/// Decodes one echoed continuation into its verified shape bindings.
///
/// This is the pre-dispatch half of [`automation_cursor_verify`]: it proves the
/// encoding, the closed query, the closed direction, the bounded row identity
/// and that the cursor names this automation under this page bound. The
/// read-revision binding against the live head set is re-proved by the owner
/// that serves the page, because only the owner observes those heads.
fn automation_cursor_shape(
    wire: &str,
    query: &str,
    automation_id: &str,
    max_records: u16,
) -> Result<AutomationPageCursor, StoreError> {
    let malformed = || StoreError::InvalidField {
        field: AUTOMATION_PARAM_CURSOR,
        reason: "continuation is malformed or foreign",
    };
    if wire.len() > MAX_AUTOMATION_CURSOR_BYTES {
        return Err(malformed());
    }
    let Some(body) = wire.strip_prefix(&format!("{AUTOMATION_CURSOR_VERSION}:")) else {
        return Err(malformed());
    };
    let cursor: AutomationPageCursor = serde_json::from_str(body).map_err(|_| malformed())?;
    cursor.validate().map_err(|_| malformed())?;
    if cursor.query != query
        || cursor.automation_id != automation_id
        || cursor.max_records != max_records
    {
        return Err(malformed());
    }
    Ok(cursor)
}

fn text_param<'a>(
    parameters: &'a BTreeMap<String, Value>,
    name: &'static str,
) -> Result<&'a str, StoreError> {
    parameters
        .get(name)
        .and_then(Value::as_str)
        .ok_or(StoreError::InvalidField {
            field: name,
            reason: "automation parameter must be a string",
        })
}

fn validate_automation_id(automation_id: &str) -> Result<(), StoreError> {
    if automation_id.trim().is_empty() || automation_id.chars().any(char::is_control) {
        return Err(StoreError::InvalidField {
            field: "automation.automation_id",
            reason: "automation identity must be non-blank text",
        });
    }
    if automation_id.len() > MAX_AUTOMATION_ID_BYTES {
        return Err(StoreError::InvalidField {
            field: "automation.automation_id",
            reason: "automation identity exceeds the length bound",
        });
    }
    Ok(())
}

fn validate_revision_id(revision: &str) -> Result<(), StoreError> {
    if revision.trim().is_empty() || revision.chars().any(char::is_control) {
        return Err(StoreError::InvalidField {
            field: "automation.revision",
            reason: "revision identity must be non-blank text",
        });
    }
    if revision.len() > MAX_AUTOMATION_REVISION_ID_BYTES {
        return Err(StoreError::InvalidField {
            field: "automation.revision",
            reason: "revision identity exceeds the length bound",
        });
    }
    Ok(())
}

fn validate_occurrence_id(occurrence_id: &str) -> Result<(), StoreError> {
    if occurrence_id.trim().is_empty() || occurrence_id.chars().any(char::is_control) {
        return Err(StoreError::InvalidField {
            field: "automation.occurrence_id",
            reason: "occurrence identity must be non-blank text",
        });
    }
    if occurrence_id.len() > MAX_AUTOMATION_ID_BYTES {
        return Err(StoreError::InvalidField {
            field: "automation.occurrence_id",
            reason: "occurrence identity exceeds the length bound",
        });
    }
    Ok(())
}

/// Validates opaque automation documents structurally: bounded length and
/// a JSON object. Document semantics (revision validity, supersession,
/// invocation derivation) stay Kernel-owned.
pub fn validate_automation_doc(document: &str, field: &'static str) -> Result<(), StoreError> {
    if document.is_empty() || document.len() > MAX_AUTOMATION_DOC_BYTES {
        return Err(StoreError::InvalidField {
            field,
            reason: "automation document is outside the bounded length",
        });
    }
    let value: Value = serde_json::from_str(document)
        .map_err(|error| StoreError::Serialization(error.to_string()))?;
    if !value.is_object() {
        return Err(StoreError::InvalidField {
            field,
            reason: "automation document must be a JSON object",
        });
    }
    Ok(())
}

/// Canonical failure document persisted verbatim by the failure leg
/// (issue #1779). The fingerprint is the deterministic class digest
/// minted by the Kernel-owned revision; the reason wire value and the
/// notification dedup key travel opaque so the Store never interprets
/// failure semantics. Failure content validity (fingerprint derivation,
/// notification shape) stays Kernel-owned.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AutomationFailureDocument {
    /// Deterministic failure-class fingerprint (lowercase SHA-256 hex).
    pub fingerprint: String,
    /// Typed failure-reason wire value (canonical JSON).
    pub reason: String,
    /// Notification dedup key echoed from the failure projection.
    pub notification_dedup_key: String,
}

/// Validates one failure document structurally plus its closed fields.
pub fn validate_automation_failure_document(
    document: &AutomationFailureDocument,
) -> Result<(), StoreError> {
    if document.fingerprint.len() != 64
        || !document
            .fingerprint
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(StoreError::InvalidField {
            field: "automation.fingerprint",
            reason: "failure fingerprint must be SHA-256 hex",
        });
    }
    validate_failure_text(&document.reason, "automation.reason")?;
    validate_failure_text(
        &document.notification_dedup_key,
        "automation.notification_dedup_key",
    )?;
    Ok(())
}

fn validate_failure_text(value: &str, field: &'static str) -> Result<(), StoreError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(StoreError::InvalidField {
            field,
            reason: "failure text must be non-blank wire text",
        });
    }
    if value.len() > MAX_AUTOMATION_DOC_BYTES {
        return Err(StoreError::InvalidField {
            field,
            reason: "failure text exceeds the document bound",
        });
    }
    Ok(())
}

/// Parses and validates the `failure_json` leg parameter into its
/// canonical document.
pub fn parse_automation_failure_document(
    failure_json: &str,
) -> Result<AutomationFailureDocument, StoreError> {
    validate_automation_doc(failure_json, AUTOMATION_PARAM_FAILURE_JSON)?;
    let document: AutomationFailureDocument = serde_json::from_str(failure_json)
        .map_err(|error| StoreError::Serialization(error.to_string()))?;
    validate_automation_failure_document(&document)?;
    Ok(document)
}

/// Storage key for one failure row: automation, revision, fingerprint.
/// Repeats of one failure class converge on this key; the first writer
/// wins and later repeats keep the existing row.
#[must_use]
pub fn automation_failure_key(automation_id: &str, revision: &str, fingerprint: &str) -> String {
    format!("{automation_id}\x1f{revision}\x1f{fingerprint}")
}

/// Canonical failure-history record reference for one failure row.
/// Deterministic over the row key, so replays and converged repeats
/// resolve the identical reference.
#[must_use]
pub fn automation_failure_history_ref(
    automation_id: &str,
    revision: &str,
    fingerprint: &str,
) -> String {
    format!("automation-failure:{automation_id}:{revision}:{fingerprint}")
}

/// Returns whether the value names a closed admission state (mirror of
/// the domain `SCREAMING_SNAKE_CASE` states; membership only, transitions
/// stay Kernel-owned).
#[must_use]
pub const fn is_configuration_state_wire(value: &str) -> bool {
    matches!(
        value.as_bytes(),
        b"ACTIVE" | b"PAUSED" | b"BLOCKED_CONFIG" | b"RETIRED"
    )
}

fn validate_configuration_state(state: &str) -> Result<(), StoreError> {
    if !is_configuration_state_wire(state) {
        return Err(StoreError::InvalidField {
            field: "automation.configuration_state",
            reason: "unknown admission state",
        });
    }
    Ok(())
}
