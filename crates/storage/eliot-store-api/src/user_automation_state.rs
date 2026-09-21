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

use std::collections::BTreeMap;

use serde_json::Value;
use thiserror::Error;

use crate::{
    NamedMutationOperation, NamedMutationRequest, NamedReadOperation, NamedReadRequest,
    ReadConsistency, StateFence, StoreError,
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
/// Read query discriminator parameter.
pub const AUTOMATION_PARAM_QUERY: &str = "query";
/// `"true"`/`"false"` retired-row inclusion (list query, required).
pub const AUTOMATION_PARAM_INCLUDE_RETIRED: &str = "include_retired";
/// Decimal page-size bound (list/history/invocations, required).
pub const AUTOMATION_PARAM_MAX_RECORDS: &str = "max_records";

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

/// Read query discriminator values (mirror the domain query kinds minus
/// `Preflight`, which is B-owned).
pub const AUTOMATION_QUERY_LIST: &str = "list";
/// Read query discriminator values.
pub const AUTOMATION_QUERY_CURRENT: &str = "current";
/// Read query discriminator values.
pub const AUTOMATION_QUERY_HISTORY: &str = "history";
/// Read query discriminator values.
pub const AUTOMATION_QUERY_INVOCATIONS: &str = "invocations";
/// Read query discriminator values (explicit absence until a failure
/// writer path exists; never a fabricated failure).
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
}

/// Decoded read query with its closed selectors.
#[derive(Clone, Debug, PartialEq)]
pub struct DecodedAutomationRead {
    /// Closed query discriminator.
    pub query: String,
    /// Exact automation selector (required except list).
    pub automation_id: Option<String>,
    /// Retired-row inclusion (list only).
    pub include_retired: bool,
    /// Page-size bound (list/history/invocations only).
    pub max_records: u16,
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
        _ => Err(StoreError::UnknownOperation),
    }
}

/// Validates the closed read selectors and decodes the query.
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
    match query {
        AUTOMATION_QUERY_LIST => Ok(DecodedAutomationRead {
            query: query.to_owned(),
            automation_id: None,
            include_retired,
            max_records,
        }),
        AUTOMATION_QUERY_CURRENT
        | AUTOMATION_QUERY_HISTORY
        | AUTOMATION_QUERY_INVOCATIONS
        | AUTOMATION_QUERY_FAILURE => {
            let automation_id = automation_id.ok_or(StoreError::InvalidField {
                field: "automation.automation_id",
                reason: "exact automation selector is required",
            })?;
            Ok(DecodedAutomationRead {
                query: query.to_owned(),
                automation_id: Some(automation_id),
                include_retired,
                max_records,
            })
        }
        _ => Err(StoreError::UnknownOperation),
    }
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
