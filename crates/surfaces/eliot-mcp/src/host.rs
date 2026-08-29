//! Host-facing request and cancellation contracts for the MCP bridge.
//!
//! These values are inert input. They deliberately contain no ELIOT
//! `RequestIdentity`, application `SessionBinding`, principal, task,
//! `WorkScope`, `StateFence`, lease, authority epoch, or effect ceiling.
//! Kernel/Governor binding happens after the bridge validates this contract.

use std::collections::{BTreeMap, BTreeSet};

use schemars::JsonSchema;
use serde::{Deserialize, Deserializer, Serialize, de};
use thiserror::Error;

use crate::contract::ContractViolation;
use crate::{ClientCapabilities, McpProtocolVersion, ToolRequest};

/// Stable revision of the host-facing request contract.
pub const HOST_REQUEST_CONTRACT_REVISION: &str = "1.0.0";
/// Maximum UTF-8 length of one host correlation identity.
pub const MAX_HOST_CORRELATION_BYTES: usize = 512;
/// Maximum UTF-8 length of one Kernel-issued operation handle.
pub const MAX_HOST_OPERATION_HANDLE_BYTES: usize = 2_048;
/// Maximum UTF-8 length of one observed resource reference.
pub const MAX_HOST_RESOURCE_REF_BYTES: usize = 2_048;
/// Maximum number of opaque resource observations in one host request.
pub const MAX_HOST_RESOURCE_REFS: usize = 32;
/// Maximum number of stream-qualified event cursors in one host request.
pub const MAX_HOST_EVENT_CURSORS: usize = 16;
/// Maximum number of non-authoritative trace fields in one host request.
pub const MAX_HOST_TRACE_ENTRIES: usize = 16;
/// Maximum relative deadline preference accepted from a host, in milliseconds.
///
/// This is a request preference only. Kernel owns the actual absolute deadline.
pub const MAX_HOST_DEADLINE_PREFERENCE_MS: u64 = 24 * 60 * 60 * 1_000;

const MAX_HOST_SESSION_HINT_BYTES: usize = 512;
const MAX_HOST_EVENT_STREAM_ID_BYTES: usize = 512;
const MAX_HOST_TRACE_KEY_BYTES: usize = 256;
const MAX_HOST_TRACE_VALUE_BYTES: usize = 1_024;
const MAX_HOST_CANCELLATION_REASON_BYTES: usize = 1_024;

macro_rules! opaque_host_id {
    ($name:ident, $field:literal, $maximum:expr, $description:literal) => {
        #[doc = $description]
        #[derive(
            Clone, Debug, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize,
        )]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            /// Creates a validated opaque identity.
            pub fn new(value: impl Into<String>) -> Result<Self, HostContractError> {
                let value = value.into();
                bounded_text(&value, $field, $maximum)?;
                Ok(Self(value))
            }

            /// Returns the opaque identity text without assigning semantics to it.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                let value = String::deserialize(deserializer)?;
                Self::new(value).map_err(de::Error::custom)
            }
        }
    };
}

opaque_host_id!(
    HostCorrelationId,
    "host.correlation_id",
    MAX_HOST_CORRELATION_BYTES,
    "Opaque correlation allocated by the host. It is not an ELIOT request, Session, task, or authority identity."
);
opaque_host_id!(
    HostOperationHandle,
    "host.operation_handle",
    MAX_HOST_OPERATION_HANDLE_BYTES,
    "Opaque operation handle returned by the Kernel-facing port after admission. Its text grants no authority by itself."
);
opaque_host_id!(
    HostObservedResourceRef,
    "host.observed_context.observed_resource_refs",
    MAX_HOST_RESOURCE_REF_BYTES,
    "Opaque resource observation supplied by the host. It is not a NativeResourceLease or filesystem grant."
);
opaque_host_id!(
    HostEventStreamId,
    "host.observed_context.event_cursors.stream_id",
    MAX_HOST_EVENT_STREAM_ID_BYTES,
    "Opaque host event-stream identity used only to qualify an observed sequence cursor."
);

/// One non-authoritative host event cursor qualified by its exact stream.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostObservedEventCursor {
    /// Host-native stream identity. It is not an ELIOT Session or authority identity.
    pub stream_id: HostEventStreamId,
    /// Last positive sequence observed by the host for this stream.
    pub sequence: u64,
}

impl HostObservedEventCursor {
    /// Creates one validated stream-qualified cursor observation.
    pub fn new(
        stream_id: HostEventStreamId,
        sequence: u64,
    ) -> Result<Self, HostContractError> {
        let value = Self {
            stream_id,
            sequence,
        };
        value.validate()?;
        Ok(value)
    }

    fn validate(&self) -> Result<(), HostContractError> {
        if self.sequence == 0 {
            return Err(HostContractError::InvalidField {
                field: "host.observed_context.event_cursors.sequence",
                reason: "must be greater than zero",
            });
        }
        Ok(())
    }
}

/// Bounded observations supplied by the host for discrimination and tracing.
///
/// Every field is non-authoritative. Resource references are opaque observations,
/// not filesystem grants; `host_session_hint` is correlation, not an ELIOT Session.
#[derive(Clone, Debug, Default, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostObservedContext {
    /// Optional host-native session or turn correlation.
    pub host_session_hint: Option<String>,
    /// Opaque resource handles currently observed by the host.
    #[serde(default)]
    pub observed_resource_refs: Vec<HostObservedResourceRef>,
    /// Stream-qualified host event cursors observed before this request.
    #[serde(default)]
    pub event_cursors: Vec<HostObservedEventCursor>,
    /// Non-authoritative bounded trace correlation.
    #[serde(default)]
    pub trace_context: BTreeMap<String, String>,
}

impl HostObservedContext {
    /// Validates boundedness and opaque-correlation semantics.
    pub fn validate(&self) -> Result<(), HostContractError> {
        if let Some(hint) = &self.host_session_hint {
            bounded_text(
                hint,
                "host.observed_context.host_session_hint",
                MAX_HOST_SESSION_HINT_BYTES,
            )?;
        }
        if self.observed_resource_refs.len() > MAX_HOST_RESOURCE_REFS {
            return Err(HostContractError::InvalidField {
                field: "host.observed_context.observed_resource_refs",
                reason: "exceeds the bounded resource-reference count",
            });
        }
        ensure_unique(
            &self.observed_resource_refs,
            "host.observed_context.observed_resource_refs",
        )?;
        if self.event_cursors.len() > MAX_HOST_EVENT_CURSORS {
            return Err(HostContractError::InvalidField {
                field: "host.observed_context.event_cursors",
                reason: "exceeds the bounded event-cursor count",
            });
        }
        let mut streams = BTreeSet::new();
        for cursor in &self.event_cursors {
            cursor.validate()?;
            if !streams.insert(&cursor.stream_id) {
                return Err(HostContractError::InvalidField {
                    field: "host.observed_context.event_cursors.stream_id",
                    reason: "must not contain duplicate stream identities",
                });
            }
        }
        if self.trace_context.len() > MAX_HOST_TRACE_ENTRIES {
            return Err(HostContractError::InvalidField {
                field: "host.observed_context.trace_context",
                reason: "exceeds the bounded trace-entry count",
            });
        }
        for (key, value) in &self.trace_context {
            bounded_text(
                key,
                "host.observed_context.trace_context.key",
                MAX_HOST_TRACE_KEY_BYTES,
            )?;
            bounded_text(
                value,
                "host.observed_context.trace_context.value",
                MAX_HOST_TRACE_VALUE_BYTES,
            )?;
        }
        Ok(())
    }
}

/// Inert host request for one canonical logical MCP operation.
///
/// The bridge validates this value and forwards it with its trusted attach and
/// transport facts. Kernel/Governor then resolves principal, Session, task,
/// scope, fence, policy, authority, idempotency, cancellation, and deadline.
#[derive(Clone, Debug, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostInvocationRequest {
    /// MCP compatibility profile observed at the host boundary.
    pub protocol_version: McpProtocolVersion,
    /// Host-owned correlation echoed in the eventual response.
    pub correlation_id: HostCorrelationId,
    /// Presentation-only client capabilities.
    #[serde(default)]
    pub client_capabilities: ClientCapabilities,
    /// Canonical logical ELIOT operation and inert arguments. Domain handles
    /// inside the tool payload remain selectors, not task/scope authority.
    pub tool: ToolRequest,
    /// Optional relative deadline preference; Kernel sets the absolute deadline.
    pub deadline_preference_ms: Option<u64>,
    /// Bounded non-authoritative host observations.
    #[serde(default)]
    pub observed_context: HostObservedContext,
}

impl HostInvocationRequest {
    /// Validates the host boundary without issuing or accepting ELIOT authority.
    pub fn validate(&self) -> Result<(), HostContractError> {
        validate_deadline_preference(self.deadline_preference_ms)?;
        self.observed_context.validate()?;
        self.tool.validate().map_err(contract_violation)
    }
}

/// Inert host request to cancel one previously admitted operation.
///
/// The target is a Kernel-issued opaque handle. The host does not supply a
/// canonical cancellation identity, authority epoch, State Fence, or Session.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostCancellationRequest {
    /// MCP compatibility profile observed at the host boundary.
    pub protocol_version: McpProtocolVersion,
    /// Correlation identity of this cancellation request.
    pub correlation_id: HostCorrelationId,
    /// Opaque exact-operation handle returned after Kernel admission.
    pub operation_handle: HostOperationHandle,
    /// Optional public cancellation reason. Cancellation does not require prose.
    #[serde(default)]
    pub reason: Option<String>,
    /// Optional relative deadline preference; Kernel sets the absolute deadline.
    pub deadline_preference_ms: Option<u64>,
    /// Bounded non-authoritative host observations.
    #[serde(default)]
    pub observed_context: HostObservedContext,
}

impl HostCancellationRequest {
    /// Validates the cancellation shape without proving that the target is owned.
    pub fn validate(&self) -> Result<(), HostContractError> {
        if let Some(reason) = &self.reason {
            bounded_text(
                reason,
                "host.cancel.reason",
                MAX_HOST_CANCELLATION_REASON_BYTES,
            )?;
        }
        validate_deadline_preference(self.deadline_preference_ms)?;
        self.observed_context.validate()
    }
}

/// Host-facing contract validation failure before Kernel/Governor binding.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum HostContractError {
    /// A bounded field is absent, malformed, duplicated, or oversized.
    #[error("invalid host contract field {field}: {reason}")]
    InvalidField {
        /// Stable field path.
        field: &'static str,
        /// Stable public reason.
        reason: &'static str,
    },
}

fn validate_deadline_preference(value: Option<u64>) -> Result<(), HostContractError> {
    if value.is_some_and(|value| value == 0 || value > MAX_HOST_DEADLINE_PREFERENCE_MS) {
        return Err(HostContractError::InvalidField {
            field: "host.deadline_preference_ms",
            reason: "must be within the admitted relative deadline range",
        });
    }
    Ok(())
}

fn contract_violation(value: ContractViolation) -> HostContractError {
    match value {
        ContractViolation::InvalidField { field, reason } => {
            HostContractError::InvalidField { field, reason }
        }
    }
}

fn bounded_text(
    value: &str,
    field: &'static str,
    maximum_bytes: usize,
) -> Result<(), HostContractError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(HostContractError::InvalidField {
            field,
            reason: "must be non-blank and contain no control characters",
        });
    }
    if value.len() > maximum_bytes {
        return Err(HostContractError::InvalidField {
            field,
            reason: "exceeds the bounded UTF-8 length",
        });
    }
    Ok(())
}

fn ensure_unique<T: Ord>(
    values: &[T],
    field: &'static str,
) -> Result<(), HostContractError> {
    let mut seen = BTreeSet::new();
    for value in values {
        if !seen.insert(value) {
            return Err(HostContractError::InvalidField {
                field,
                reason: "must not contain duplicate values",
            });
        }
    }
    Ok(())
}
