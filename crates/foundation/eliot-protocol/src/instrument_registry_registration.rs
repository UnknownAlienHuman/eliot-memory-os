use crate::protocol_v1::{bounded_text, lowercase_sha256};
use crate::{
    HostRequestAuthenticatedSource, HostRequestEnvelope, HostRequestKind,
    MAX_HOST_REQUEST_TEXT_BYTES, ProtocolError, RequestIdentity,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const INSTRUMENT_REGISTRY_REGISTRATION_OPERATOR_OPERATION: &str =
    "instrument_registry_registration.operator";
pub const INSTRUMENT_REGISTRY_REGISTRATION_STATUS_OPERATION: &str =
    "instrument_registry_registration.status";

/// Closed HostRequest body for an explicitly admitted Instrument Registry
/// registration. The bytes identify the candidate; current Governor authority
/// still owns the canonical mutation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct InstrumentRegistryRegistrationInvocation {
    pub wire_id: String,
    pub wire_version: u16,
    pub request_identity: RequestIdentity,
    /// Kernel-derived identity for the authenticated user and OS session.
    pub authenticated_principal_sha256: String,
    pub snapshot_json: String,
}

/// Closed operator request. Its scope and registry bytes are inert selectors
/// until the current Governor owner resolves and admits the mutation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct InstrumentRegistryRegistrationOperatorRequest {
    pub wire_id: String,
    pub wire_version: u16,
    pub work_scope_id: String,
    pub snapshot_json: String,
}

/// Closed same-owner lookup for one admitted registration result.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct InstrumentRegistryRegistrationStatusRequest {
    pub wire_id: String,
    pub wire_version: u16,
    pub operation_id: String,
    pub request_digest: String,
    pub work_scope_id: String,
}

impl InstrumentRegistryRegistrationInvocation {
    pub const WIRE_ID: &'static str = "eliot.instrument-registry-registration";
    pub const WIRE_VERSION: u16 = 1;
    pub const PAYLOAD_SCHEMA_ID: &'static str = "eliot.instrument-registry-registration.v1";
    pub const MAX_SNAPSHOT_BYTES: usize = 1_048_576;

    pub fn validate_for_envelope(
        &self,
        envelope: &HostRequestEnvelope,
    ) -> Result<(), ProtocolError> {
        self.request_identity.validate()?;
        if self.wire_id != Self::WIRE_ID || self.wire_version != Self::WIRE_VERSION {
            return Err(ProtocolError::InvalidField {
                field: "instrument_registry_registration.wire",
                reason: "unsupported registration payload",
            });
        }
        if self.snapshot_json.is_empty() || self.snapshot_json.len() > Self::MAX_SNAPSHOT_BYTES {
            return Err(ProtocolError::InvalidField {
                field: "instrument_registry_registration.snapshot_json",
                reason: "snapshot bytes are empty or exceed the registration bound",
            });
        }
        lowercase_sha256(
            &self.authenticated_principal_sha256,
            "instrument_registry_registration.authenticated_principal_sha256",
        )?;
        let _: Value =
            serde_json::from_str(&self.snapshot_json).map_err(|_| ProtocolError::InvalidField {
                field: "instrument_registry_registration.snapshot_json",
                reason: "snapshot is not valid JSON",
            })?;
        let expected_session = self
            .request_identity
            .request
            .metadata
            .session_id
            .as_ref()
            .map(ToString::to_string);
        let expected_task = self
            .request_identity
            .request
            .metadata
            .task_id
            .as_ref()
            .map(ToString::to_string);
        if envelope.kind != HostRequestKind::InstrumentRegistryRegistration
            || envelope.identity.capability != "instrument_registry.register"
            || envelope.identity.payload_schema_id != Self::PAYLOAD_SCHEMA_ID
            || envelope.identity.request_id.as_str()
                != self.request_identity.request.metadata.request_id.as_str()
            || envelope.identity.idempotency_key != self.request_identity.idempotency_key
            || envelope.identity.cancellation_id != self.request_identity.cancellation_id
            || envelope.identity.deadline_unix_ms != self.request_identity.deadline_unix_ms
            || envelope.identity.session_id.as_ref() != expected_session.as_ref()
            || envelope.identity.task_id.as_ref() != expected_task.as_ref()
            || envelope.identity.work_scope_id.is_none()
            || envelope.state_fence != self.request_identity.request.state_fence
            || envelope.identity.payload_sha256 != self.action_payload_sha256()?
            || matches!(
                &envelope.authenticated_source,
                Some(HostRequestAuthenticatedSource::Operator { request_identity })
                    if request_identity != &self.request_identity
            )
        {
            return Err(ProtocolError::InvalidField {
                field: "instrument_registry_registration.envelope",
                reason: "registration body differs from its typed HostRequest identity",
            });
        }
        Ok(())
    }

    pub fn action_payload_sha256(&self) -> Result<String, ProtocolError> {
        let bytes = eliot_contracts::canonical_json_bytes(&serde_json::json!({
            "wire_id": Self::WIRE_ID,
            "wire_version": Self::WIRE_VERSION,
            "request_identity": self.request_identity,
            "authenticated_principal_sha256": self.authenticated_principal_sha256,
            "snapshot_json": self.snapshot_json,
        }))
        .map_err(|error| ProtocolError::Json(error.to_string()))?;
        Ok(eliot_contracts::sha256_hex(&bytes))
    }
}

impl InstrumentRegistryRegistrationOperatorRequest {
    pub const WIRE_ID: &'static str = "eliot.instrument-registry-registration.operator";
    pub const WIRE_VERSION: u16 = 1;

    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.wire_id != Self::WIRE_ID || self.wire_version != Self::WIRE_VERSION {
            return Err(ProtocolError::InvalidField {
                field: "instrument_registry_registration_operator.wire",
                reason: "unsupported operator registration request",
            });
        }
        bounded_text(
            &self.work_scope_id,
            "instrument_registry_registration_operator.work_scope_id",
            MAX_HOST_REQUEST_TEXT_BYTES,
        )?;
        if self.snapshot_json.is_empty()
            || self.snapshot_json.len()
                > InstrumentRegistryRegistrationInvocation::MAX_SNAPSHOT_BYTES
        {
            return Err(ProtocolError::InvalidField {
                field: "instrument_registry_registration_operator.snapshot_json",
                reason: "candidate snapshot is empty or exceeds the registration bound",
            });
        }
        let _: Value =
            serde_json::from_str(&self.snapshot_json).map_err(|_| ProtocolError::InvalidField {
                field: "instrument_registry_registration_operator.snapshot_json",
                reason: "candidate snapshot is not valid JSON",
            })?;
        Ok(())
    }
}

impl InstrumentRegistryRegistrationStatusRequest {
    pub const WIRE_ID: &'static str = "eliot.instrument-registry-registration.status";
    pub const WIRE_VERSION: u16 = 1;

    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.wire_id != Self::WIRE_ID || self.wire_version != Self::WIRE_VERSION {
            return Err(ProtocolError::InvalidField {
                field: "instrument_registry_registration_status.wire",
                reason: "unsupported operator registration status request",
            });
        }
        bounded_text(
            &self.operation_id,
            "instrument_registry_registration_status.operation_id",
            MAX_HOST_REQUEST_TEXT_BYTES,
        )?;
        lowercase_sha256(
            &self.request_digest,
            "instrument_registry_registration_status.request_digest",
        )?;
        if self.operation_id != format!("hostreq:{}", self.request_digest) {
            return Err(ProtocolError::InvalidField {
                field: "instrument_registry_registration_status.operation_id",
                reason: "must be the opaque handle for the exact request digest",
            });
        }
        bounded_text(
            &self.work_scope_id,
            "instrument_registry_registration_status.work_scope_id",
            MAX_HOST_REQUEST_TEXT_BYTES,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::{
        InstrumentRegistryRegistrationOperatorRequest, InstrumentRegistryRegistrationStatusRequest,
    };

    #[test]
    fn operator_registration_accepts_bounded_json_and_refuses_invalid_snapshot() {
        let valid = InstrumentRegistryRegistrationOperatorRequest {
            wire_id: InstrumentRegistryRegistrationOperatorRequest::WIRE_ID.to_owned(),
            wire_version: InstrumentRegistryRegistrationOperatorRequest::WIRE_VERSION,
            work_scope_id: "scope-current".to_owned(),
            snapshot_json: "{}".to_owned(),
        };
        assert!(valid.validate().is_ok());

        let invalid = InstrumentRegistryRegistrationOperatorRequest {
            snapshot_json: "{".to_owned(),
            ..valid
        };
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn status_lookup_requires_the_exact_opaque_request_handle() {
        let digest = "a".repeat(64);
        let valid = InstrumentRegistryRegistrationStatusRequest {
            wire_id: InstrumentRegistryRegistrationStatusRequest::WIRE_ID.to_owned(),
            wire_version: InstrumentRegistryRegistrationStatusRequest::WIRE_VERSION,
            operation_id: format!("hostreq:{digest}"),
            request_digest: digest,
            work_scope_id: "scope-current".to_owned(),
        };
        assert!(valid.validate().is_ok());

        let mut foreign = valid;
        foreign.operation_id = "hostreq:foreign".to_owned();
        assert!(foreign.validate().is_err());
    }
}
