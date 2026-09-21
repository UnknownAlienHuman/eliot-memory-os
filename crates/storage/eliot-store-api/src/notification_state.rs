//! Canonical notification-state wire contract (issue #1780, I11.5/I11.7).
//!
//! This module owns the serialization-only wire boundary for notification
//! state: versioned identity, closed parameter declarations support,
//! leg-completeness validation on raw parameter maps, and request builders.
//! It contains no notification domain model, no transition logic, and no
//! receipt validation: the shared kernel-core model
//! (`eliot_kernel_core::notification_state`) owns the typed record and its
//! fail-closed transitions, and the canonical backend drives that model
//! within its fenced transaction and outbox owner. Wire shapes stay
//! serialization-only and never become a second semantic model.
//!
//! Wire identity: [`NOTIFICATION_STATE_SCHEMA_V1`] (`eliot.notify.state.v1`).
//! Mutation operation: `ApplyNotificationState`. Read operation:
//! `GetNotificationState`. Transition class: `NotificationState` with a
//! `ReversibleMutation` ceiling.

use std::collections::BTreeMap;

use serde_json::Value;
use thiserror::Error;

use crate::{
    NamedMutationOperation, NamedMutationRequest, NamedReadOperation, NamedReadRequest,
    ReadConsistency, StateFence, StoreError,
};

/// Versioned wire/schema identity for canonical notification state.
pub const NOTIFICATION_STATE_SCHEMA_V1: &str = "eliot.notify.state.v1";
/// Closed mutation operation name for notification-state transitions.
pub const NOTIFICATION_STATE_MUTATION_NAME: &str = "ApplyNotificationState";
/// Closed read operation name for the notification-state projection.
pub const NOTIFICATION_STATE_READ_NAME: &str = "GetNotificationState";
/// Fixed transition scope for all notification records.
pub const NOTIFICATION_STATE_SCOPE: &str = "notification-state";
/// Maximum accepted `dedup_key` length in bytes.
pub const MAX_DEDUP_KEY_BYTES: usize = 256;
/// Maximum accepted read page size.
pub const MAX_NOTIFICATION_PAGE_LIMIT: u16 = 128;

/// Mutation discriminator parameter.
pub const NOTIFY_PARAM_MUTATION: &str = "mutation";
/// Deduplication-key parameter (upsert index; exact read selector).
pub const NOTIFY_PARAM_DEDUP_KEY: &str = "dedup_key";
/// Notification identity parameter (lifecycle legs; exact read selector).
pub const NOTIFY_PARAM_NOTIFICATION_ID: &str = "notification_id";
/// Canonical record-input JSON (upsert leg).
pub const NOTIFY_PARAM_RECORD_JSON: &str = "record_json";
/// Canonical source-receipt JSON (upsert leg).
pub const NOTIFY_PARAM_SOURCE_RECEIPT_JSON: &str = "source_receipt_json";
/// Canonical delivery-state JSON (delivery leg).
pub const NOTIFY_PARAM_DELIVERY_JSON: &str = "delivery_json";
/// Delivery channel selector (delivery leg).
pub const NOTIFY_PARAM_CHANNEL: &str = "channel";
/// Acknowledging principal (acknowledge leg).
pub const NOTIFY_PARAM_PRINCIPAL: &str = "principal";
/// Human disposition (resolve leg).
pub const NOTIFY_PARAM_DISPOSITION: &str = "disposition";
/// Canonical resolution-authorization JSON (resolve leg).
pub const NOTIFY_PARAM_AUTHORIZATION_JSON: &str = "authorization_json";
/// Optional record-scope filter (read).
pub const NOTIFY_PARAM_SCOPE: &str = "scope";
/// `"true"` or `"false"` resolved-row inclusion (read, required).
pub const NOTIFY_PARAM_INCLUDE_RESOLVED: &str = "include_resolved";
/// Decimal page-size bound (read, required).
pub const NOTIFY_PARAM_PAGE_LIMIT: &str = "page_limit";
/// Opaque dedup-key cursor (read, optional).
pub const NOTIFY_PARAM_CURSOR: &str = "cursor";

/// Mutation leg discriminator values.
pub const NOTIFY_MUTATION_UPSERT: &str = "UPSERT";
/// Mutation leg discriminator values.
pub const NOTIFY_MUTATION_DELIVERY: &str = "DELIVERY";
/// Mutation leg discriminator values.
pub const NOTIFY_MUTATION_ACKNOWLEDGE: &str = "ACKNOWLEDGE";
/// Mutation leg discriminator values.
pub const NOTIFY_MUTATION_RESOLVE: &str = "RESOLVE";

/// Closed delivery-channel wire selectors (mirror the shared model spelling).
pub const NOTIFY_CHANNEL_CONTROL_BOARD: &str = "CONTROL_BOARD";
/// Closed delivery-channel wire selectors (mirror the shared model spelling).
pub const NOTIFY_CHANNEL_NATIVE_TOAST: &str = "NATIVE_TOAST";
/// Closed delivery-channel wire selectors (mirror the shared model spelling).
pub const NOTIFY_CHANNEL_WINDOWS_EVENT_LOG: &str = "WINDOWS_EVENT_LOG";
/// Closed delivery-channel wire selectors (mirror the shared model spelling).
pub const NOTIFY_CHANNEL_RECOVERY_FALLBACK: &str = "RECOVERY_FALLBACK";

/// Read payload field: projected record array.
pub const NOTIFY_PAGE_RECORDS: &str = "records";
/// Read payload field: inbox metrics object.
pub const NOTIFY_PAGE_METRICS: &str = "metrics";
/// Read payload field: projection fence.
pub const NOTIFY_PAGE_STATE_FENCE: &str = "state_fence";
/// Read payload field: owner revision read at.
pub const NOTIFY_PAGE_REVISION: &str = "revision";

/// Fail-closed notification wire errors before [`StoreError`] projection.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum NotificationContractError {
    /// A field failed bounded validation.
    #[error("invalid field {field}: {reason}")]
    InvalidField {
        /// Invalid field name.
        field: &'static str,
        /// Stable reason code.
        reason: &'static str,
    },
    /// The mutation discriminator is unknown.
    #[error("unknown notification mutation leg")]
    UnknownMutation,
    /// A required leg parameter is absent.
    #[error("missing notification parameter: {0}")]
    MissingParameter(&'static str),
}

impl NotificationContractError {
    /// Projects the contract error onto the closed store error set.
    #[must_use]
    pub const fn into_store_error(self) -> StoreError {
        match self {
            Self::InvalidField { field, reason } => StoreError::InvalidField { field, reason },
            Self::UnknownMutation => StoreError::UnknownOperation,
            Self::MissingParameter(name) => StoreError::InvalidField {
                field: name,
                reason: "missing required notification parameter",
            },
        }
    }
}

/// Raw validated legs decoded from a mutation parameter map.
///
/// Payloads stay canonical JSON values: the backend deserializes them into
/// the shared kernel-core model types and drives the transitions. This enum
/// carries no domain semantics beyond leg completeness.
#[derive(Clone, Debug, PartialEq)]
pub enum DecodedNotificationMutation {
    /// Create or coalesce one record.
    Upsert {
        /// Deduplication index key.
        dedup_key: String,
        /// Canonical record-input JSON.
        record_json: Value,
        /// Canonical source-receipt JSON.
        source_receipt_json: Value,
    },
    /// Record verified delivery state.
    Delivery {
        /// Canonical notification identity.
        notification_id: String,
        /// Channel wire selector.
        channel: String,
        /// Canonical delivery-state JSON.
        delivery_json: Value,
    },
    /// Acknowledge without resolving.
    Acknowledge {
        /// Canonical notification identity.
        notification_id: String,
        /// Acknowledging principal.
        principal: String,
    },
    /// Resolve with receipt-bound authorization.
    Resolve {
        /// Canonical notification identity.
        notification_id: String,
        /// Human disposition.
        disposition: String,
        /// Canonical resolution-authorization JSON.
        authorization_json: Value,
    },
}

/// Builds the closed `ApplyNotificationState` mutation request.
#[must_use]
pub fn notification_mutation_request(params: BTreeMap<String, Value>) -> NamedMutationRequest {
    NamedMutationRequest {
        operation: NamedMutationOperation::ApplyNotificationState,
        parameters: params,
    }
}

/// Builds the closed `GetNotificationState` read request.
pub fn notification_read_request(
    scope: Option<String>,
    dedup_key: Option<String>,
    notification_id: Option<String>,
    include_resolved: bool,
    page_limit: u16,
    cursor: Option<String>,
    state_fence: StateFence,
) -> Result<NamedReadRequest, StoreError> {
    let mut parameters = BTreeMap::new();
    if let Some(scope) = scope {
        parameters.insert(NOTIFY_PARAM_SCOPE.to_owned(), Value::String(scope));
    }
    if let Some(dedup_key) = dedup_key {
        parameters.insert(NOTIFY_PARAM_DEDUP_KEY.to_owned(), Value::String(dedup_key));
    }
    if let Some(notification_id) = notification_id {
        parameters.insert(
            NOTIFY_PARAM_NOTIFICATION_ID.to_owned(),
            Value::String(notification_id),
        );
    }
    parameters.insert(
        NOTIFY_PARAM_INCLUDE_RESOLVED.to_owned(),
        Value::String(include_resolved.to_string()),
    );
    parameters.insert(
        NOTIFY_PARAM_PAGE_LIMIT.to_owned(),
        Value::String(page_limit.to_string()),
    );
    if let Some(cursor) = cursor {
        parameters.insert(NOTIFY_PARAM_CURSOR.to_owned(), Value::String(cursor));
    }
    if page_limit == 0 || page_limit > MAX_NOTIFICATION_PAGE_LIMIT {
        return Err(StoreError::InvalidField {
            field: "notification.page_limit",
            reason: "page limit is out of range",
        });
    }
    let request = NamedReadRequest {
        operation: NamedReadOperation::GetNotificationState,
        scope_id: None,
        consistency: ReadConsistency::ExactFence,
        state_fence,
        parameters,
    };
    request.validate()?;
    Ok(request)
}

/// Validates closed mutation parameters: exact leg discriminator plus
/// conditional leg presence (the declaration table enforces membership and
/// per-value shape; this enforces leg completeness).
pub fn validate_notification_mutation_params(
    parameters: &BTreeMap<String, Value>,
) -> Result<(), StoreError> {
    let leg = parameters
        .get(NOTIFY_PARAM_MUTATION)
        .and_then(Value::as_str)
        .ok_or(StoreError::InvalidField {
            field: "notification.mutation",
            reason: "mutation leg discriminator is required",
        })?;
    let require_text = |name: &'static str| -> Result<(), StoreError> {
        match parameters.get(name).and_then(Value::as_str) {
            Some(value) if !value.trim().is_empty() && !value.chars().any(char::is_control) => {
                Ok(())
            }
            _ => Err(StoreError::InvalidField {
                field: name,
                reason: "leg parameter must be non-blank text",
            }),
        }
    };
    let require_object = |name: &'static str| -> Result<(), StoreError> {
        match parameters.get(name) {
            Some(Value::Object(_)) => Ok(()),
            _ => Err(StoreError::InvalidField {
                field: name,
                reason: "leg parameter must be a JSON object",
            }),
        }
    };
    require_text(NOTIFY_PARAM_MUTATION)?;
    match leg {
        NOTIFY_MUTATION_UPSERT => {
            require_text(NOTIFY_PARAM_DEDUP_KEY)?;
            require_object(NOTIFY_PARAM_RECORD_JSON)?;
            require_object(NOTIFY_PARAM_SOURCE_RECEIPT_JSON)?;
        }
        NOTIFY_MUTATION_DELIVERY => {
            require_text(NOTIFY_PARAM_NOTIFICATION_ID)?;
            let channel = parameters
                .get(NOTIFY_PARAM_CHANNEL)
                .and_then(Value::as_str)
                .unwrap_or_default();
            if !is_channel_wire(channel) {
                return Err(StoreError::InvalidField {
                    field: "notification.channel",
                    reason: "unknown delivery channel",
                });
            }
            require_object(NOTIFY_PARAM_DELIVERY_JSON)?;
        }
        NOTIFY_MUTATION_ACKNOWLEDGE => {
            require_text(NOTIFY_PARAM_NOTIFICATION_ID)?;
            require_text(NOTIFY_PARAM_PRINCIPAL)?;
        }
        NOTIFY_MUTATION_RESOLVE => {
            require_text(NOTIFY_PARAM_NOTIFICATION_ID)?;
            require_text(NOTIFY_PARAM_DISPOSITION)?;
            require_object(NOTIFY_PARAM_AUTHORIZATION_JSON)?;
        }
        _ => return Err(StoreError::UnknownOperation),
    }
    Ok(())
}

/// Decodes one validated mutation parameter map into its raw legs.
pub fn decode_notification_mutation(
    parameters: &BTreeMap<String, Value>,
) -> Result<DecodedNotificationMutation, StoreError> {
    validate_notification_mutation_params(parameters)?;
    let text_of = |name: &'static str| -> Result<String, StoreError> {
        parameters
            .get(name)
            .and_then(Value::as_str)
            .map(str::to_owned)
            .ok_or(StoreError::InvalidField {
                field: name,
                reason: "leg parameter must be present",
            })
    };
    let object_of = |name: &'static str| -> Result<Value, StoreError> {
        parameters
            .get(name)
            .cloned()
            .ok_or(StoreError::InvalidField {
                field: name,
                reason: "leg parameter must be present",
            })
    };
    let leg = text_of(NOTIFY_PARAM_MUTATION)?;
    match leg.as_str() {
        NOTIFY_MUTATION_UPSERT => Ok(DecodedNotificationMutation::Upsert {
            dedup_key: text_of(NOTIFY_PARAM_DEDUP_KEY)?,
            record_json: object_of(NOTIFY_PARAM_RECORD_JSON)?,
            source_receipt_json: object_of(NOTIFY_PARAM_SOURCE_RECEIPT_JSON)?,
        }),
        NOTIFY_MUTATION_DELIVERY => Ok(DecodedNotificationMutation::Delivery {
            notification_id: text_of(NOTIFY_PARAM_NOTIFICATION_ID)?,
            channel: text_of(NOTIFY_PARAM_CHANNEL)?,
            delivery_json: object_of(NOTIFY_PARAM_DELIVERY_JSON)?,
        }),
        NOTIFY_MUTATION_ACKNOWLEDGE => Ok(DecodedNotificationMutation::Acknowledge {
            notification_id: text_of(NOTIFY_PARAM_NOTIFICATION_ID)?,
            principal: text_of(NOTIFY_PARAM_PRINCIPAL)?,
        }),
        NOTIFY_MUTATION_RESOLVE => Ok(DecodedNotificationMutation::Resolve {
            notification_id: text_of(NOTIFY_PARAM_NOTIFICATION_ID)?,
            disposition: text_of(NOTIFY_PARAM_DISPOSITION)?,
            authorization_json: object_of(NOTIFY_PARAM_AUTHORIZATION_JSON)?,
        }),
        _ => Err(StoreError::UnknownOperation),
    }
}

/// Returns whether the selector names a closed delivery channel.
#[must_use]
pub const fn is_channel_wire(value: &str) -> bool {
    matches!(
        value.as_bytes(),
        b"CONTROL_BOARD" | b"NATIVE_TOAST" | b"WINDOWS_EVENT_LOG" | b"RECOVERY_FALLBACK"
    )
}
