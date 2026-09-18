use std::{collections::BTreeMap, path::Path};

use eliot_agent_api::{
    AdmittedRouteReceipt, AgentAttempt, AgentAttemptId, AssistantDeltaObservation,
    CONTRACT_VERSION, CancellationState, ClockReading, ContractError, ErrorObservation,
    EventCursor, EventId, ExecutionOutcome, HOST_EVENT_CONTRACT_VERSION,
    HOST_EVENT_DIGEST_ALGORITHM, HostEventDeliveryDisposition, HostEventNormalizationReceipt,
    HostEventPrivacyClass, LowercaseSha256, NormalizationCoverage, NormalizedHostEventEnvelope,
    NormalizedHostEventPayload, PhysicalRouteObservationReceipt, ProviderExecutionBinding,
    ProviderObservationLineage, ProviderTerminalObservation, ProviderTerminalStatus,
    QualifiedSourceDigest, RawSourceRecord, RestrictedRawSourceHandle, RouteFingerprint,
    RouteObservationState, SessionLifecycleObservation, SessionLifecycleTransition,
    UnsupportedDisposition, UnsupportedEventObservation, UnsupportedEventReason, UsageReceipt,
    WarningObservation, route_divergence_fields,
};
use eliot_contracts::{ResourceGeneration, StateFence, canonical_json_bytes, sha256_hex};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de, ser::SerializeMap};
use serde_json::Value;

/// Forward-compatible fields returned by `OpenCode` but not yet interpreted by
/// this no-authority protocol core.
pub type UnknownFields = BTreeMap<String, Value>;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct HealthResponse {
    pub healthy: bool,
    pub version: String,
    #[serde(flatten)]
    pub extra: UnknownFields,
}

pub type OpenCodeHealth = HealthResponse;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProviderCatalog {
    pub all: Vec<Provider>,
    pub default: BTreeMap<String, String>,
    pub connected: Vec<String>,
    #[serde(flatten)]
    pub extra: UnknownFields,
}

pub type ProviderCatalogResponse = ProviderCatalog;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Provider {
    pub id: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub models: BTreeMap<String, ProviderModel>,
    #[serde(default)]
    pub connected: Option<bool>,
    #[serde(flatten)]
    pub extra: UnknownFields,
}

pub type ProviderDescriptor = Provider;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProviderModel {
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default, alias = "contextLimit")]
    pub context_limit: Option<u64>,
    #[serde(default, alias = "outputLimit")]
    pub output_limit: Option<u64>,
    #[serde(flatten)]
    pub extra: UnknownFields,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Session {
    pub id: String,
    pub slug: String,
    #[serde(rename = "projectID", alias = "project_id")]
    pub project_id: String,
    #[serde(default, rename = "workspaceID", alias = "workspace_id")]
    pub workspace_id: Option<String>,
    pub directory: String,
    pub title: String,
    pub version: String,
    pub time: SessionTime,
    #[serde(default, alias = "parentID")]
    pub parent_id: Option<String>,
    #[serde(flatten)]
    pub extra: UnknownFields,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SessionTime {
    pub created: u64,
    pub updated: u64,
    #[serde(default)]
    pub completed: Option<u64>,
    #[serde(flatten)]
    pub extra: UnknownFields,
}

/// The `/session/status` endpoint returns a map keyed by session ID. Each
/// value is an internally tagged SDK status object.
pub type SessionStatusMap = BTreeMap<String, SessionStatus>;
pub type SessionStatusResponse = SessionStatusMap;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SessionStatus {
    Idle {
        extra: UnknownFields,
    },
    Busy {
        extra: UnknownFields,
    },
    Retry {
        attempt: u64,
        message: String,
        next: u64,
        extra: UnknownFields,
    },
    Unknown {
        kind: String,
        extra: UnknownFields,
    },
}

impl Serialize for SessionStatus {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let (kind, fields) = match self {
            Self::Idle { extra } => ("idle", extra),
            Self::Busy { extra } => ("busy", extra),
            Self::Retry { extra, .. } => ("retry", extra),
            Self::Unknown { kind, extra } => (kind.as_str(), extra),
        };
        let mut map = serializer.serialize_map(None)?;
        map.serialize_entry("type", kind)?;
        if let Self::Retry {
            attempt,
            message,
            next,
            ..
        } = self
        {
            map.serialize_entry("attempt", attempt)?;
            map.serialize_entry("message", message)?;
            map.serialize_entry("next", next)?;
        }
        for (key, value) in fields {
            map.serialize_entry(key, value)?;
        }
        map.end()
    }
}

impl<'de> Deserialize<'de> for SessionStatus {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = Value::deserialize(deserializer)?;
        let mut object = value
            .as_object()
            .cloned()
            .ok_or_else(|| de::Error::custom("session status must be an object"))?;
        let kind = object
            .remove("type")
            .and_then(|value| value.as_str().map(str::to_owned))
            .ok_or_else(|| de::Error::custom("session status type is missing"))?;
        match kind.as_str() {
            "idle" => Ok(Self::Idle {
                extra: object.into_iter().collect::<UnknownFields>(),
            }),
            "busy" => Ok(Self::Busy {
                extra: object.into_iter().collect::<UnknownFields>(),
            }),
            "retry" => {
                let attempt = object
                    .remove("attempt")
                    .and_then(|value| value.as_u64())
                    .ok_or_else(|| de::Error::custom("retry status attempt is missing"))?;
                let message = object
                    .remove("message")
                    .and_then(|value| value.as_str().map(str::to_owned))
                    .ok_or_else(|| de::Error::custom("retry status message is missing"))?;
                let next = object
                    .remove("next")
                    .and_then(|value| value.as_u64())
                    .ok_or_else(|| de::Error::custom("retry status next is missing"))?;
                Ok(Self::Retry {
                    attempt,
                    message,
                    next,
                    extra: object.into_iter().collect::<UnknownFields>(),
                })
            }
            _ => Ok(Self::Unknown {
                kind,
                extra: object.into_iter().collect::<UnknownFields>(),
            }),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PublicError {
    pub message: String,
    #[serde(default)]
    pub code: Option<String>,
    #[serde(flatten)]
    pub extra: UnknownFields,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SessionDiff {
    #[serde(rename = "file", alias = "path")]
    pub file: String,
    pub patch: String,
    pub additions: u64,
    pub deletions: u64,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(flatten)]
    pub extra: UnknownFields,
}

impl SessionDiff {
    pub fn path(&self) -> &str {
        &self.file
    }
}

pub type SnapshotFileDiff = SessionDiff;
pub type FileDiff = SessionDiff;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OpenCodeEvent {
    #[serde(rename = "type")]
    pub event_type: String,
    pub properties: Value,
    #[serde(flatten)]
    pub extra: UnknownFields,
}

pub type Event = OpenCodeEvent;

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct MessageTime {
    pub created: u64,
    #[serde(default)]
    pub completed: Option<u64>,
    #[serde(flatten)]
    pub extra: UnknownFields,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct TokenUsage {
    #[serde(default)]
    pub input: Option<u64>,
    #[serde(default)]
    pub output: Option<u64>,
    #[serde(default)]
    pub reasoning: Option<u64>,
    #[serde(default)]
    pub cache: Option<TokenCacheUsage>,
    #[serde(flatten)]
    pub extra: UnknownFields,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct TokenCacheUsage {
    #[serde(default)]
    pub read: Option<u64>,
    #[serde(default)]
    pub write: Option<u64>,
    #[serde(flatten)]
    pub extra: UnknownFields,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct AssistantMessage {
    pub id: String,
    #[serde(rename = "sessionID", alias = "session_id")]
    pub session_id: String,
    pub role: String,
    pub time: MessageTime,
    #[serde(rename = "providerID", alias = "provider_id")]
    pub provider_id: String,
    #[serde(rename = "modelID", alias = "model_id")]
    pub model_id: String,
    #[serde(default)]
    pub cost: Option<f64>,
    #[serde(default)]
    pub tokens: Option<TokenUsage>,
    #[serde(default)]
    pub finish: Option<String>,
    #[serde(default)]
    pub parts: Vec<MessagePart>,
    #[serde(flatten)]
    pub extra: UnknownFields,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct UserMessage {
    pub id: String,
    #[serde(rename = "sessionID", alias = "session_id")]
    pub session_id: String,
    pub role: String,
    pub time: MessageTime,
    #[serde(default)]
    pub parts: Vec<MessagePart>,
    #[serde(flatten)]
    pub extra: UnknownFields,
}

#[derive(Clone, Debug, PartialEq)]
pub enum MessagePart {
    StepFinish {
        reason: String,
        cost: Option<f64>,
        tokens: Option<TokenUsage>,
        extra: UnknownFields,
    },
    Permission {
        permission: String,
        extra: UnknownFields,
    },
    Text {
        text: String,
        extra: UnknownFields,
    },
    Unknown {
        kind: String,
        extra: UnknownFields,
    },
}

impl Serialize for MessagePart {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut map = serializer.serialize_map(None)?;
        match self {
            Self::StepFinish {
                reason,
                cost,
                tokens,
                extra,
            } => {
                map.serialize_entry("type", "step-finish")?;
                map.serialize_entry("reason", reason)?;
                if let Some(cost) = cost {
                    map.serialize_entry("cost", cost)?;
                }
                if let Some(tokens) = tokens {
                    map.serialize_entry("tokens", tokens)?;
                }
                for (key, value) in extra {
                    map.serialize_entry(key, value)?;
                }
            }
            Self::Permission { permission, extra } => {
                map.serialize_entry("type", "permission")?;
                map.serialize_entry("permission", permission)?;
                for (key, value) in extra {
                    map.serialize_entry(key, value)?;
                }
            }
            Self::Text { text, extra } => {
                map.serialize_entry("type", "text")?;
                map.serialize_entry("text", text)?;
                for (key, value) in extra {
                    map.serialize_entry(key, value)?;
                }
            }
            Self::Unknown { kind, extra } => {
                map.serialize_entry("type", kind)?;
                for (key, value) in extra {
                    map.serialize_entry(key, value)?;
                }
            }
        }
        map.end()
    }
}

pub type Part = MessagePart;

impl<'de> Deserialize<'de> for MessagePart {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = Value::deserialize(deserializer)?;
        let mut object = value
            .as_object()
            .cloned()
            .ok_or_else(|| de::Error::custom("message part must be an object"))?;
        let kind = object
            .remove("type")
            .and_then(|value| value.as_str().map(str::to_owned))
            .ok_or_else(|| de::Error::custom("message part type is missing"))?;
        match kind.as_str() {
            "step-finish" => {
                let reason = object
                    .remove("reason")
                    .and_then(|value| value.as_str().map(str::to_owned))
                    .ok_or_else(|| de::Error::custom("step-finish reason is missing"))?;
                let cost = object.remove("cost").and_then(|value| value.as_f64());
                let tokens = object
                    .remove("tokens")
                    .map(|value| {
                        serde_json::from_value(value)
                            .map_err(|error| de::Error::custom(error.to_string()))
                    })
                    .transpose()?;
                Ok(Self::StepFinish {
                    reason,
                    cost,
                    tokens,
                    extra: object.into_iter().collect::<UnknownFields>(),
                })
            }
            "permission" => {
                let permission = object
                    .remove("permission")
                    .and_then(|value| value.as_str().map(str::to_owned))
                    .ok_or_else(|| de::Error::custom("permission part value is missing"))?;
                Ok(Self::Permission {
                    permission,
                    extra: object.into_iter().collect::<UnknownFields>(),
                })
            }
            "text" => {
                let text = object
                    .remove("text")
                    .and_then(|value| value.as_str().map(str::to_owned))
                    .ok_or_else(|| de::Error::custom("text part value is missing"))?;
                Ok(Self::Text {
                    text,
                    extra: object.into_iter().collect::<UnknownFields>(),
                })
            }
            _ => Ok(Self::Unknown {
                kind,
                extra: object.into_iter().collect::<UnknownFields>(),
            }),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum Message {
    Assistant(Box<AssistantMessage>),
    User(Box<UserMessage>),
    Unknown { role: String, fields: UnknownFields },
}

pub type OpenCodeMessage = Message;

impl<'de> Deserialize<'de> for Message {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = Value::deserialize(deserializer)?;
        let role = value
            .get("role")
            .and_then(Value::as_str)
            .ok_or_else(|| de::Error::custom("message role is missing"))?;
        match role {
            "assistant" => serde_json::from_value(value)
                .map(Box::new)
                .map(Self::Assistant)
                .map_err(|error| de::Error::custom(error.to_string())),
            "user" => serde_json::from_value(value)
                .map(Box::new)
                .map(Self::User)
                .map_err(|error| de::Error::custom(error.to_string())),
            _ => Ok(Self::Unknown {
                role: role.to_owned(),
                fields: value
                    .as_object()
                    .cloned()
                    .unwrap_or_default()
                    .into_iter()
                    .collect(),
            }),
        }
    }
}

impl Serialize for Message {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            Self::Assistant(value) => value.serialize(serializer),
            Self::User(value) => value.serialize(serializer),
            Self::Unknown { fields, .. } => fields.serialize(serializer),
        }
    }
}

/// The exact provider/model identity requested from `OpenCode`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ModelSelection {
    #[serde(rename = "providerID", alias = "provider_id")]
    pub provider_id: String,
    #[serde(rename = "modelID", alias = "model_id")]
    pub model_id: String,
}

impl<'de> Deserialize<'de> for ModelSelection {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct RawModelSelection {
            #[serde(rename = "providerID", alias = "provider_id")]
            provider_id: String,
            #[serde(rename = "modelID", alias = "model_id")]
            model_id: String,
        }

        let raw = RawModelSelection::deserialize(deserializer)?;
        Self::new(raw.provider_id, raw.model_id).map_err(de::Error::custom)
    }
}

impl ModelSelection {
    pub fn new(
        provider_id: impl Into<String>,
        model_id: impl Into<String>,
    ) -> Result<Self, ModelSelectionError> {
        let selection = Self {
            provider_id: provider_id.into(),
            model_id: model_id.into(),
        };
        selection.validate()?;
        Ok(selection)
    }

    pub fn validate(&self) -> Result<(), ModelSelectionError> {
        if self.provider_id.trim().is_empty() {
            return Err(ModelSelectionError::MissingProviderIdentity);
        }
        if self.model_id.trim().is_empty() {
            return Err(ModelSelectionError::MissingModelIdentity);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ModelSelectionError {
    #[error("provider identity is missing")]
    MissingProviderIdentity,
    #[error("model identity is missing")]
    MissingModelIdentity,
}

/// A request accepted by this crate is always top-level read-only. Mutation,
/// repository integration, provider credentials, and authority are owned by a
/// higher-level governed adapter and are deliberately absent here.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ReadOnlyRunRequest {
    pub prompt: String,
    pub model: ModelSelection,
    #[serde(default, alias = "sessionID")]
    pub session_id: Option<String>,
    #[serde(default, alias = "messageID")]
    pub message_id: Option<String>,
    pub read_only: bool,
    #[serde(rename = "outputSchema")]
    pub output_schema: Value,
    #[serde(flatten)]
    pub extra: UnknownFields,
}

impl ReadOnlyRunRequest {
    pub fn new(prompt: impl Into<String>, model: ModelSelection) -> Result<Self, RunRequestError> {
        let request = Self {
            prompt: prompt.into(),
            model,
            session_id: None,
            message_id: None,
            read_only: true,
            output_schema: default_output_schema(),
            extra: UnknownFields::new(),
        };
        request.validate()?;
        Ok(request)
    }

    /// Replaces the generic structured-output schema with a caller-supplied
    /// JSON object schema.
    pub fn with_output_schema(mut self, output_schema: Value) -> Result<Self, RunRequestError> {
        if !output_schema.is_object() {
            return Err(RunRequestError::InvalidOutputSchema);
        }
        self.output_schema = output_schema;
        Ok(self)
    }

    /// Sets the optional `OpenCode` message correlation identity.
    pub fn with_message_id(
        mut self,
        message_id: impl Into<String>,
    ) -> Result<Self, RunRequestError> {
        let message_id = message_id.into();
        validate_message_identity(&message_id)?;
        self.message_id = Some(message_id);
        Ok(self)
    }

    pub fn validate(&self) -> Result<(), RunRequestError> {
        if self.prompt.trim().is_empty() {
            return Err(RunRequestError::EmptyPrompt);
        }
        self.model
            .validate()
            .map_err(RunRequestError::InvalidModel)?;
        if !self.read_only {
            return Err(RunRequestError::MutationNotAllowed);
        }
        if !self.output_schema.is_object() {
            return Err(RunRequestError::InvalidOutputSchema);
        }
        if let Some(message_id) = &self.message_id {
            validate_message_identity(message_id)?;
        }
        Ok(())
    }
}

fn validate_message_identity(message_id: &str) -> Result<(), RunRequestError> {
    const PREFIX: &str = "msg_";
    const MAX_LENGTH: usize = 128;

    let suffix = message_id.strip_prefix(PREFIX).unwrap_or_default();
    if message_id.len() > MAX_LENGTH
        || suffix.is_empty()
        || !suffix
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return Err(RunRequestError::InvalidMessageIdentity);
    }
    Ok(())
}

fn default_output_schema() -> Value {
    serde_json::json!({
        "type": "object",
        "additionalProperties": true,
    })
}

impl<'de> Deserialize<'de> for ReadOnlyRunRequest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct RawReadOnlyRunRequest {
            prompt: String,
            model: ModelSelection,
            #[serde(default, alias = "sessionID")]
            session_id: Option<String>,
            #[serde(default, alias = "messageID")]
            message_id: Option<String>,
            read_only: bool,
            #[serde(
                rename = "outputSchema",
                alias = "output_schema",
                default = "default_output_schema"
            )]
            output_schema: Value,
            #[serde(flatten)]
            extra: UnknownFields,
        }

        let raw = RawReadOnlyRunRequest::deserialize(deserializer)?;
        let request = Self {
            prompt: raw.prompt,
            model: raw.model,
            session_id: raw.session_id,
            message_id: raw.message_id,
            read_only: raw.read_only,
            output_schema: raw.output_schema,
            extra: raw.extra,
        };
        request.validate().map_err(de::Error::custom)?;
        Ok(request)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum RunRequestError {
    #[error("read-only run prompt is empty")]
    EmptyPrompt,
    #[error("read-only run model is invalid: {0}")]
    InvalidModel(ModelSelectionError),
    #[error("OpenCode mutation is not allowed by the protocol core")]
    MutationNotAllowed,
    #[error("structured output schema must be a JSON object")]
    InvalidOutputSchema,
    #[error("OpenCode message identity must be msg_ followed by safe ASCII and at most 128 bytes")]
    InvalidMessageIdentity,
}

/// Adapter-internal OpenCode wire route record (PRIVATE_WIRE_PROJECTION).
///
/// Issue #369 (T4 S4, `workstreams/T4.md` §5.2): this is the provider-wire
/// shape (`ModelSelection`, endpoint, directory, server/session fields plus
/// forward-compatible unknown fields), not the shared canonical physical
/// observation. It exists for wire decoding only: no Governor/coordinator
/// public edge imports it as the canonical receipt (verified zero hits at
/// this base). Conversion of its model/session/endpoint fields and
/// unknown-field loss into the shared `PhysicalRouteObservationReceipt` is
/// deferred until `eliot-agent-api` lands that owner; this crate must not
/// duplicate the canonical type.
///
/// Loss visibility: `extra` preserves every unknown wire field through the
/// flattened round-trip (never silently dropped). An unavailable record
/// carries its reason under `extra["unavailable_reason"]` with no observed
/// identity. `observed` is never defaulted from `requested`: `Observed`
/// requires an explicit observed identity plus full bindings, `Unavailable`
/// requires `observed: None` plus no identity (see
/// [`OpenCodeWireRouteReceipt::validate`]).
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct OpenCodeWireRouteReceipt {
    pub requested: ModelSelection,
    pub observed: Option<ModelSelection>,
    pub provider: Option<String>,
    pub endpoint: Option<String>,
    pub route_fingerprint: Option<String>,
    pub session_id: Option<String>,
    pub directory: Option<String>,
    pub server_version: Option<String>,
    pub workspace_id: Option<String>,
    pub state: OpenCodeWireRouteState,
    #[serde(flatten)]
    pub extra: UnknownFields,
}

/// Compatibility alias for pre-rename importers outside `src/` (e.g. the
/// `tests/` integration suite). New code uses [`OpenCodeWireRouteReceipt`].
pub type ActualRouteReceipt = OpenCodeWireRouteReceipt;

impl<'de> Deserialize<'de> for OpenCodeWireRouteReceipt {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct RawOpenCodeWireRouteReceipt {
            requested: ModelSelection,
            #[serde(default)]
            observed: Option<ModelSelection>,
            #[serde(default, alias = "providerID")]
            provider: Option<String>,
            #[serde(default, alias = "endpointURL", alias = "baseURL")]
            endpoint: Option<String>,
            #[serde(default, alias = "routeFingerprint")]
            route_fingerprint: Option<String>,
            #[serde(default, alias = "sessionID")]
            session_id: Option<String>,
            #[serde(default, alias = "cwd")]
            directory: Option<String>,
            #[serde(default, alias = "serverVersion")]
            server_version: Option<String>,
            #[serde(default, alias = "workspaceID")]
            workspace_id: Option<String>,
            state: OpenCodeWireRouteState,
            #[serde(flatten)]
            extra: UnknownFields,
        }

        let raw = RawOpenCodeWireRouteReceipt::deserialize(deserializer)?;
        let receipt = Self {
            requested: raw.requested,
            observed: raw.observed,
            provider: raw.provider,
            endpoint: raw.endpoint,
            route_fingerprint: raw.route_fingerprint,
            session_id: raw.session_id,
            directory: raw.directory,
            server_version: raw.server_version,
            workspace_id: raw.workspace_id,
            state: raw.state,
            extra: raw.extra,
        };
        receipt.validate().map_err(de::Error::custom)?;
        Ok(receipt)
    }
}

impl OpenCodeWireRouteReceipt {
    pub fn observed(requested: ModelSelection, observed: ModelSelection) -> Self {
        Self {
            requested,
            observed: Some(observed),
            provider: None,
            endpoint: None,
            route_fingerprint: None,
            session_id: None,
            directory: None,
            server_version: None,
            workspace_id: None,
            state: OpenCodeWireRouteState::Observed,
            extra: UnknownFields::new(),
        }
    }

    pub fn unavailable(requested: ModelSelection, reason: impl Into<String>) -> Self {
        let mut extra = UnknownFields::new();
        extra.insert(
            "unavailable_reason".to_owned(),
            Value::String(reason.into()),
        );
        Self {
            requested,
            observed: None,
            provider: None,
            endpoint: None,
            route_fingerprint: None,
            session_id: None,
            directory: None,
            server_version: None,
            workspace_id: None,
            state: OpenCodeWireRouteState::Unavailable,
            extra,
        }
    }

    pub fn is_observed(&self) -> bool {
        self.state == OpenCodeWireRouteState::Observed && self.observed.is_some()
    }

    pub fn validate(&self) -> Result<(), OpenCodeWireRouteError> {
        self.requested
            .validate()
            .map_err(OpenCodeWireRouteError::InvalidRequestedModel)?;
        if let Some(observed) = &self.observed {
            observed
                .validate()
                .map_err(OpenCodeWireRouteError::InvalidObservedModel)?;
        }
        match self.state {
            OpenCodeWireRouteState::Observed => {
                if self.observed.is_none() {
                    return Err(OpenCodeWireRouteError::ObservedIdentityMissing);
                }
                if is_blank(self.provider.as_deref()) {
                    return Err(OpenCodeWireRouteError::ObservedProviderMissing);
                }
                if self.provider.as_deref()
                    != self
                        .observed
                        .as_ref()
                        .map(|model| model.provider_id.as_str())
                {
                    return Err(OpenCodeWireRouteError::ObservedProviderMismatch);
                }
                let endpoint = self
                    .endpoint
                    .as_deref()
                    .ok_or(OpenCodeWireRouteError::ObservedEndpointMissing)?;
                if crate::LoopbackEndpoint::parse(endpoint).is_err() {
                    return Err(OpenCodeWireRouteError::ObservedEndpointNotLoopback);
                }
                if is_blank(self.route_fingerprint.as_deref()) {
                    return Err(OpenCodeWireRouteError::ObservedRouteFingerprintMissing);
                }
                if is_blank(self.session_id.as_deref()) {
                    return Err(OpenCodeWireRouteError::ObservedSessionIdentityMissing);
                }
                let directory = self
                    .directory
                    .as_deref()
                    .ok_or(OpenCodeWireRouteError::ObservedDirectoryMissing)?;
                if !Path::new(directory).is_absolute() {
                    return Err(OpenCodeWireRouteError::ObservedDirectoryNotAbsolute);
                }
                if is_blank(self.server_version.as_deref()) {
                    return Err(OpenCodeWireRouteError::ObservedServerVersionMissing);
                }
                if self
                    .workspace_id
                    .as_deref()
                    .is_some_and(|workspace| workspace.trim().is_empty())
                {
                    return Err(OpenCodeWireRouteError::ObservedWorkspaceIdentityBlank);
                }
                Ok(())
            }
            OpenCodeWireRouteState::Unavailable => {
                if self.observed.is_some()
                    || self.provider.is_some()
                    || self.endpoint.is_some()
                    || self.route_fingerprint.is_some()
                    || self.session_id.is_some()
                    || self.directory.is_some()
                    || self.server_version.is_some()
                    || self.workspace_id.is_some()
                {
                    Err(OpenCodeWireRouteError::UnavailableHasIdentity)
                } else {
                    Ok(())
                }
            }
        }
    }

    /// Total versioned loss-visible conversion into the shared canonical
    /// [`PhysicalRouteObservationReceipt`].
    ///
    /// - Unknown wire fields are never dropped: a non-empty `extra` map is
    ///   hashed into `raw_evidence_digest`/`raw_evidence_ref` (loss handle).
    /// - Missing observed identity never synthesizes `observed = requested`:
    ///   `Unavailable` becomes `UNOBSERVED` with an explicit reason plus
    ///   `UNKNOWN_OUTCOME` quarantine (`recovery_ref`).
    /// - `Observed` never defaults to `MATCHED`: the observed fingerprint is
    ///   built from the requested fingerprint with provider/model replaced
    ///   from the wire, then classified via `route_divergence_fields`
    ///   (`Matched` only when field-complete equal, else `Diverged` with the
    ///   exact difference set and a quarantine `recovery_ref`).
    /// - Session/route agreement and admission/binding linkage are enforced
    ///   via [`PhysicalRouteObservationReceipt::validate_against`]; a forged
    ///   binding or mismatched admission rejects.
    #[allow(clippy::too_many_arguments)]
    pub fn to_physical_observation(
        &self,
        requested: &RouteFingerprint,
        admission: &AdmittedRouteReceipt,
        binding: &ProviderExecutionBinding,
        usage: UsageReceipt,
        started: ClockReading,
        first_byte: ClockReading,
        first_semantic: ClockReading,
        terminal: ClockReading,
        event_cursor: EventCursor,
        event_sequence: u64,
        cancellation: Option<CancellationState>,
    ) -> Result<PhysicalRouteObservationReceipt, OpenCodeObservationConversionError> {
        self.validate()?;
        // Requested wire identity must agree with the canonical requested
        // route; the observed side is built below, never defaulted.
        if requested.provider != self.requested.provider_id
            || requested.model != self.requested.model_id
        {
            return Err(eliot_agent_api::ContractError::BindingMismatch.into());
        }
        if binding.route != *requested {
            return Err(eliot_agent_api::ContractError::BindingMismatch.into());
        }
        let (observed_route, route_state, diverged_fields, unobserved_reason) = match self.state {
            OpenCodeWireRouteState::Unavailable => {
                let reason = self
                    .extra
                    .get("unavailable_reason")
                    .and_then(Value::as_str)
                    .unwrap_or("opencode wire unavailable")
                    .to_owned();
                (
                    None,
                    RouteObservationState::Unobserved,
                    Vec::new(),
                    Some(reason),
                )
            }
            OpenCodeWireRouteState::Observed => {
                let observed_wire =
                    self.observed
                        .as_ref()
                        .ok_or(OpenCodeObservationConversionError::Wire(
                            OpenCodeWireRouteError::ObservedIdentityMissing,
                        ))?;
                let mut observed_fp = requested.clone();
                observed_fp.provider = observed_wire.provider_id.clone();
                observed_fp.model = observed_wire.model_id.clone();
                let diverged = route_divergence_fields(requested, &observed_fp);
                let state = if diverged.is_empty() {
                    RouteObservationState::Matched
                } else {
                    RouteObservationState::Diverged
                };
                (Some(observed_fp), state, diverged, None)
            }
        };
        // Loss handle: every unknown wire field stays addressable by digest.
        let (raw_evidence_digest, raw_evidence_ref) = if self.extra.is_empty() {
            (None, None)
        } else {
            let bytes = canonical_json_bytes(&self.extra).map_err(|error| {
                OpenCodeObservationConversionError::Serialization(error.to_string())
            })?;
            let hex = sha256_hex(&bytes);
            let digest: LowercaseSha256 =
                serde_json::from_value(Value::String(hex)).map_err(|error| {
                    OpenCodeObservationConversionError::Serialization(error.to_string())
                })?;
            let reference = format!("opencode-wire-extra:{}", digest.as_str());
            (Some(digest), Some(reference))
        };
        // Execution axis follows the route axis without collapsing them:
        // unavailable implies unknown outcome with quarantine; observed keeps
        // the caller-supplied terminal/cancellation and gains a quarantine
        // handle exactly when diverged.
        let (execution_outcome, terminal, cancellation, recovery_ref) = match route_state {
            RouteObservationState::Unobserved => (
                ExecutionOutcome::UnknownOutcome,
                ClockReading::default(),
                None,
                Some("opencode-unobserved-recovery".to_owned()),
            ),
            RouteObservationState::Matched => {
                (ExecutionOutcome::Observed, terminal, cancellation, None)
            }
            RouteObservationState::Diverged => (
                ExecutionOutcome::Observed,
                terminal,
                cancellation,
                Some("opencode-diverged-quarantine".to_owned()),
            ),
        };
        let request_bytes = canonical_json_bytes(&self.requested).map_err(|error| {
            OpenCodeObservationConversionError::Serialization(error.to_string())
        })?;
        let request_digest: LowercaseSha256 =
            serde_json::from_value(Value::String(sha256_hex(&request_bytes))).map_err(|error| {
                OpenCodeObservationConversionError::Serialization(error.to_string())
            })?;
        let mut observation = PhysicalRouteObservationReceipt {
            schema_version: CONTRACT_VERSION.to_owned(),
            attempt_id: binding.attempt_id.clone(),
            state_fence: binding.state_fence.clone(),
            runtime_generation: binding.runtime_generation,
            admitted_route_digest: admission.self_digest.clone(),
            binding: binding.clone(),
            requested_route: requested.clone(),
            observed_route,
            route_state,
            diverged_fields,
            execution_outcome,
            request_digest,
            translation_digest: None,
            raw_evidence_digest,
            raw_evidence_ref,
            usage,
            started,
            first_byte,
            first_semantic,
            terminal,
            event_cursor,
            event_sequence,
            cancellation,
            unobserved_reason,
            recovery_ref,
            safe_public_error: None,
            restricted_raw_error_ref: None,
            self_digest: serde_json::from_value(Value::String(
                "0000000000000000000000000000000000000000000000000000000000000000".to_owned(),
            ))
            .map_err(|error| {
                OpenCodeObservationConversionError::Serialization(error.to_string())
            })?,
        };
        observation.self_digest = observation.compute_digest().map_err(|error| {
            OpenCodeObservationConversionError::Serialization(error.to_string())
        })?;
        observation.validate()?;
        observation.validate_against(binding, admission)?;
        Ok(observation)
    }
}

/// Conversion failures for [`OpenCodeWireRouteReceipt::to_physical_observation`].
/// Wire-shape failures stay wire-typed; linkage/shape failures stay
/// contract-typed; neither is silently upgraded.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum OpenCodeObservationConversionError {
    #[error("opencode wire route is invalid: {0}")]
    Wire(#[from] OpenCodeWireRouteError),
    #[error("physical observation contract rejected: {0}")]
    Contract(#[from] eliot_agent_api::ContractError),
    #[error("observation conversion serialization failed: {0}")]
    Serialization(String),
    #[error("invalid opencode host-event input: {0}")]
    InvalidInput(&'static str),
}

fn is_blank(value: Option<&str>) -> bool {
    value.is_none_or(|value| value.trim().is_empty())
}

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum OpenCodeWireRouteError {
    #[error("requested route model is invalid: {0}")]
    InvalidRequestedModel(ModelSelectionError),
    #[error("observed route model is invalid: {0}")]
    InvalidObservedModel(ModelSelectionError),
    #[error("observed route receipt has no observed identity")]
    ObservedIdentityMissing,
    #[error("observed route receipt provider is missing or blank")]
    ObservedProviderMissing,
    #[error("observed route receipt provider differs from its observed model")]
    ObservedProviderMismatch,
    #[error("observed route receipt endpoint is missing")]
    ObservedEndpointMissing,
    #[error("observed route receipt endpoint is not a canonical loopback endpoint")]
    ObservedEndpointNotLoopback,
    #[error("observed route receipt fingerprint is missing or blank")]
    ObservedRouteFingerprintMissing,
    #[error("observed route receipt session identity is missing or blank")]
    ObservedSessionIdentityMissing,
    #[error("observed route receipt directory is missing")]
    ObservedDirectoryMissing,
    #[error("observed route receipt directory must be absolute")]
    ObservedDirectoryNotAbsolute,
    #[error("observed route receipt server version is missing or blank")]
    ObservedServerVersionMissing,
    #[error("observed route receipt workspace identity cannot be blank")]
    ObservedWorkspaceIdentityBlank,
    #[error("unavailable route receipt must not carry an observed identity")]
    UnavailableHasIdentity,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OpenCodeWireRouteState {
    Observed,
    Unavailable,
}

/// Compatibility alias for pre-rename importers outside `src/`. New code
/// uses [`OpenCodeWireRouteState`]; the serialized wire (`observed` /
/// `unavailable`) is unchanged.
pub type ActualRouteState = OpenCodeWireRouteState;

/// Compatibility alias for pre-rename importers. New code uses
/// [`OpenCodeWireRouteError`]; every variant and message is unchanged.
pub type RouteReceiptError = OpenCodeWireRouteError;

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct UsageTelemetry {
    #[serde(default, alias = "inputTokens")]
    pub input_tokens: Option<u64>,
    #[serde(default, alias = "outputTokens")]
    pub output_tokens: Option<u64>,
    #[serde(default, alias = "totalTokens")]
    pub total_tokens: Option<u64>,
    #[serde(default, alias = "costUsd")]
    pub cost_usd: Option<f64>,
    #[serde(flatten)]
    pub extra: UnknownFields,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct UsageAvailability {
    pub state: AvailabilityState,
    #[serde(default)]
    pub value: Option<UsageTelemetry>,
    #[serde(default, alias = "unavailableReason")]
    pub unavailable_reason: Option<String>,
    #[serde(flatten)]
    pub extra: UnknownFields,
}

impl UsageAvailability {
    pub fn available(value: UsageTelemetry) -> Self {
        Self {
            state: AvailabilityState::Available,
            value: Some(value),
            unavailable_reason: None,
            extra: UnknownFields::new(),
        }
    }

    pub fn unavailable(reason: impl Into<String>) -> Self {
        Self {
            state: AvailabilityState::Unavailable,
            value: None,
            unavailable_reason: Some(reason.into()),
            extra: UnknownFields::new(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct QuotaAvailability {
    pub state: AvailabilityState,
    #[serde(default)]
    pub remaining: Option<u64>,
    #[serde(default, alias = "resetAt")]
    pub reset_at: Option<String>,
    #[serde(default, alias = "unavailableReason")]
    pub unavailable_reason: Option<String>,
    #[serde(flatten)]
    pub extra: UnknownFields,
}

impl QuotaAvailability {
    pub fn unavailable(reason: impl Into<String>) -> Self {
        Self {
            state: AvailabilityState::Unavailable,
            remaining: None,
            reset_at: None,
            unavailable_reason: Some(reason.into()),
            extra: UnknownFields::new(),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AvailabilityState {
    Available,
    Unavailable,
}

/// Result envelope deliberately constrained to candidate evidence. It cannot
/// represent a canonical task finish, repository mutation, or provider
/// authority grant.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct NoAuthorityRunResult {
    pub status: RunStatus,
    pub candidate_only: bool,
    pub authority: AuthorityCeiling,
    pub actual_route: OpenCodeWireRouteReceipt,
    pub usage: UsageAvailability,
    pub quota: QuotaAvailability,
    #[serde(default, alias = "sessionID")]
    pub session_id: Option<String>,
    #[serde(default)]
    pub output: Option<Value>,
    #[serde(default)]
    pub events: Vec<OpenCodeEvent>,
    #[serde(default)]
    pub diff: Vec<SessionDiff>,
    #[serde(flatten)]
    pub extra: UnknownFields,
}

pub type ActualRouteResult = NoAuthorityRunResult;
pub type OpenCodeRunResult = NoAuthorityRunResult;

impl<'de> Deserialize<'de> for NoAuthorityRunResult {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct RawResult {
            status: RunStatus,
            candidate_only: bool,
            authority: AuthorityCeiling,
            actual_route: OpenCodeWireRouteReceipt,
            usage: UsageAvailability,
            quota: QuotaAvailability,
            #[serde(default, alias = "sessionID")]
            session_id: Option<String>,
            #[serde(default)]
            output: Option<Value>,
            #[serde(default)]
            events: Vec<OpenCodeEvent>,
            #[serde(default)]
            diff: Vec<SessionDiff>,
            #[serde(flatten)]
            extra: UnknownFields,
        }

        let raw = RawResult::deserialize(deserializer)?;
        if !raw.candidate_only || raw.authority != AuthorityCeiling::CandidateOnly {
            return Err(de::Error::custom(
                "OpenCode result cannot claim authority or non-candidate status",
            ));
        }
        raw.actual_route.validate().map_err(de::Error::custom)?;
        if raw.actual_route.state == OpenCodeWireRouteState::Observed
            && raw.session_id.as_deref() != raw.actual_route.session_id.as_deref()
        {
            return Err(de::Error::custom(
                "OpenCode result session identity differs from its actual-route receipt",
            ));
        }
        Ok(Self {
            status: raw.status,
            candidate_only: raw.candidate_only,
            authority: raw.authority,
            actual_route: raw.actual_route,
            usage: raw.usage,
            quota: raw.quota,
            session_id: raw.session_id,
            output: raw.output,
            events: raw.events,
            diff: raw.diff,
            extra: raw.extra,
        })
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorityCeiling {
    CandidateOnly,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RunStatus {
    Succeeded,
    Partial,
    Failed,
    Cancelled,
    Unknown,
}

/// Adapter identity bound by [`normalize_opencode_event`]. Callers never supply
/// their own producer identity; a caller string never proves adapter authority.
pub const OPENCODE_NORMALIZER_IDENTITY: &str = "eliot-agent-opencode";
/// Adapter contract version bound by [`normalize_opencode_event`].
pub const OPENCODE_NORMALIZER_VERSION: &str = "eliot-agent-opencode/v1";
/// Maximum raw source bytes digested by [`normalize_opencode_event`]. Raw
/// provider bytes stay behind the restricted handle; only the qualified digest
/// enters the envelope.
pub const OPENCODE_MAX_RAW_SOURCE_BYTES: usize = 1024 * 1024;

/// Typed OpenCode host-event normalization input (issue #371 T4 S7).
///
/// The OpenCode wire event (`event_type` + `properties` + `extra`) travels as
/// the classification input only: the public normalized payload is the closed
/// [`NormalizedHostEventPayload`] built inside (never a copied
/// `serde_json::Value`). The exact execution lineage travels as
/// [`ProviderObservationLineage`] (never parsed from provider locators),
/// digests are computed inside from `raw_source_bytes` (never caller-supplied
/// strings), and observation time is a typed [`ClockReading`] (never a
/// wall-clock string). Event identity, resume cursor, and sequence come from
/// the single post-R1 owner via these fields; this function never synthesizes
/// a cursor such as `opencode:{sequence}`. Absent native replay evidence stays
/// absent: callers pass [`HostEventDeliveryDisposition::BestEffortOrdered`] or
/// an explicit replay marker owned elsewhere, never a fabricated durable
/// cursor.
#[derive(Clone, Debug)]
pub struct OpenCodeHostEventInput<'a> {
    /// OpenCode wire event being normalized. Raw `properties`/`extra` stay
    /// behind the restricted handle; only a bounded typed summary enters the
    /// public payload.
    pub event: &'a OpenCodeEvent,
    /// Event identity from the post-R1 owner.
    pub event_id: EventId,
    /// Resume cursor from the post-R1 owner. Never synthesized from the wire.
    pub cursor: EventCursor,
    /// Monotonic sequence supplied by the adapter. Must be nonzero.
    pub sequence: u64,
    /// Causal predecessor event identities.
    pub predecessors: Vec<EventId>,
    /// Exact session or execution-unit lineage. No string/JSON parsing, no new
    /// attempt invention.
    pub lineage: ProviderObservationLineage,
    /// Raw OpenCode SSE/JSON bytes. Digested inside; never copied into the
    /// public normalized payload.
    pub raw_source_bytes: &'a [u8],
    /// Restricted handle addressing the immutable raw source record.
    pub raw_source_handle: RestrictedRawSourceHandle,
    /// Typed observation time. Unknown stays unknown.
    pub observed_at: ClockReading,
    /// Delivery/coverage disposition of this observation.
    pub delivery: HostEventDeliveryDisposition,
    /// Recorded #369 admission. Required for execution-unit lineage (the
    /// envelope references it by digest); forbidden for session-only lineage,
    /// which carries no admission reference.
    pub admission: Option<&'a AdmittedRouteReceipt>,
}

/// Normalizes one OpenCode wire event into the closed v7 host-event schema
/// (issue #371 T4 S7), mirroring `eliot-agent-acp::normalize_acp_event`.
///
/// The adapter identity/version (`eliot-agent-opencode` /
/// [`OPENCODE_NORMALIZER_VERSION`]) is bound by this function, never supplied
/// by the caller; the input source digest is computed from `raw_source_bytes`
/// with [`HOST_EVENT_DIGEST_ALGORITHM`]; unknown `extra` fields are declared
/// loss-visibly in `omitted_fields` (empty exactly when coverage is
/// `Complete`); and the sealed envelope is validated before return
/// (execution-unit lineage against the exact binding plus the #369 admission,
/// session lineage on the session path).
///
/// Classification is fail-closed and authority-free: known session wire events
/// under session lineage become [`NormalizedHostEventPayload::SessionLifecycle`];
/// known execution wire events under execution-unit lineage become bounded
/// size/error/warning/terminal summaries; everything else (including
/// session-scoped wire events under execution lineage and vice versa) becomes
/// [`NormalizedHostEventPayload::UnsupportedQuarantined`]. Raw provider text,
/// prompts, tool data, and errors never enter the public payload; they stay
/// behind the restricted handle bound by digest. No candidate result, usage
/// proof, route authority, or task completion is synthesized here.
///
/// The returned pair feeds
/// `eliot-agent-coordinator::AgentCoordinator::observe_provider_event`
/// directly: the receipt equals the envelope's embedded normalization receipt
/// (`envelope.normalization == receipt`), and both validate under the same
/// closed schema with [`eliot_receipts::ProofCeiling::Observation`] only.
pub fn normalize_opencode_event(
    input: OpenCodeHostEventInput<'_>,
) -> Result<
    (NormalizedHostEventEnvelope, HostEventNormalizationReceipt),
    OpenCodeObservationConversionError,
> {
    if input.sequence == 0 {
        return Err(OpenCodeObservationConversionError::InvalidInput("sequence"));
    }
    if input.raw_source_bytes.is_empty()
        || input.raw_source_bytes.len() > OPENCODE_MAX_RAW_SOURCE_BYTES
    {
        return Err(OpenCodeObservationConversionError::InvalidInput(
            "raw_source_bytes",
        ));
    }
    match &input.lineage {
        ProviderObservationLineage::ExecutionUnitObservation(_) => match input.admission {
            Some(admission) => admission
                .validate()
                .map_err(OpenCodeObservationConversionError::Contract)?,
            None => {
                return Err(OpenCodeObservationConversionError::InvalidInput(
                    "admission/lineage",
                ));
            }
        },
        ProviderObservationLineage::SessionObservation(_) => {
            if input.admission.is_some() {
                return Err(OpenCodeObservationConversionError::InvalidInput(
                    "admission/lineage",
                ));
            }
        }
    }
    let input_digest: LowercaseSha256 = serde_json::from_value(Value::String(sha256_hex(
        input.raw_source_bytes,
    )))
    .map_err(|error| OpenCodeObservationConversionError::Serialization(error.to_string()))?;
    let raw_record = RawSourceRecord {
        handle: input.raw_source_handle.clone(),
        digest: QualifiedSourceDigest {
            algorithm: HOST_EVENT_DIGEST_ALGORITHM.to_owned(),
            digest: input_digest,
        },
    };
    raw_record
        .validate()
        .map_err(OpenCodeObservationConversionError::Contract)?;
    let (payload, privacy_class, mut warnings) =
        classify_opencode_event(input.event, &input.lineage);
    // Loss visibility: every unknown wire field stays declared. `extra` keys
    // are never silently dropped; an empty manifest means complete coverage.
    let mut omitted_source_fields: Vec<String> = input
        .event
        .extra
        .keys()
        .map(|key| format!("extra:{key}"))
        .collect();
    omitted_source_fields.sort();
    omitted_source_fields.dedup();
    let coverage = if omitted_source_fields.is_empty() {
        NormalizationCoverage::Complete
    } else {
        NormalizationCoverage::LossyOmission
    };
    // Quarantine carries an explicit bounded warning; typed observations carry
    // none. Warnings never embed raw provider content.
    if matches!(
        payload,
        NormalizedHostEventPayload::UnsupportedQuarantined(_)
    ) {
        warnings.push("opencode.unknown-event-type-quarantined".to_owned());
    }
    let unsupported_disposition = match &payload {
        NormalizedHostEventPayload::UnsupportedQuarantined(_) => {
            UnsupportedDisposition::UnsupportedMethodQuarantined
        }
        _ => UnsupportedDisposition::None,
    };
    let receipt = HostEventNormalizationReceipt {
        normalizer_identity: OPENCODE_NORMALIZER_IDENTITY.to_owned(),
        normalizer_version: OPENCODE_NORMALIZER_VERSION.to_owned(),
        input_handle: raw_record.handle.clone(),
        input_digest: raw_record.digest.clone(),
        output_schema_version: HOST_EVENT_CONTRACT_VERSION.to_owned(),
        output_digest: serde_json::from_value(Value::String(
            "0000000000000000000000000000000000000000000000000000000000000000".to_owned(),
        ))
        .map_err(|error| OpenCodeObservationConversionError::Serialization(error.to_string()))?,
        omitted_fields: omitted_source_fields,
        warnings,
        unsupported_disposition,
        privacy_class,
        coverage,
        proof_ceiling: eliot_agent_api::ProofCeiling::Observation,
    };
    let admitted_route_digest = input
        .admission
        .map(|admission| admission.self_digest.clone());
    let mut envelope = NormalizedHostEventEnvelope {
        schema_version: HOST_EVENT_CONTRACT_VERSION.to_owned(),
        event_id: input.event_id,
        cursor: input.cursor,
        lineage: input.lineage,
        producer_adapter_identity: OPENCODE_NORMALIZER_IDENTITY.to_owned(),
        adapter_contract_version: OPENCODE_NORMALIZER_VERSION.to_owned(),
        sequence: input.sequence,
        causal_predecessors: input.predecessors,
        payload,
        admitted_route_digest,
        raw_source: raw_record,
        normalization: receipt,
        observed_at: input.observed_at,
        delivery: input.delivery,
    };
    envelope
        .seal()
        .map_err(|error| OpenCodeObservationConversionError::Serialization(error.to_string()))?;
    match envelope.lineage.attributable_binding() {
        Ok(binding) => {
            let admission =
                input
                    .admission
                    .ok_or(OpenCodeObservationConversionError::InvalidInput(
                        "admission/lineage",
                    ))?;
            envelope
                .validate_for_lineage(binding, admission)
                .map_err(OpenCodeObservationConversionError::Contract)?;
        }
        Err(_) => {
            envelope
                .validate_as_session_observation()
                .map_err(OpenCodeObservationConversionError::Contract)?;
        }
    }
    let receipt = envelope.normalization.clone();
    Ok((envelope, receipt))
}

/// Classifies one OpenCode wire event into the closed typed payload family.
///
/// Returns the typed payload, its privacy class, and base warnings (the
/// quarantine warning is appended by [`normalize_opencode_event`]). The mapping
/// is lineage-aware because [`NormalizedHostEventPayload::requires_execution_unit`]
/// and [`NormalizedHostEventPayload::is_session_lifecycle`] are enforced by the
/// envelope validators: session lineage admits only session-lifecycle or
/// quarantined payloads; execution-unit lineage never admits a session-lifecycle
/// payload. Public summaries are fixed bounded strings or size counts only;
/// raw `properties`/`extra` content is never copied.
fn classify_opencode_event(
    event: &OpenCodeEvent,
    lineage: &ProviderObservationLineage,
) -> (
    NormalizedHostEventPayload,
    HostEventPrivacyClass,
    Vec<String>,
) {
    let warnings = Vec::new();
    let is_session_lineage = matches!(lineage, ProviderObservationLineage::SessionObservation(_));
    if is_session_lineage {
        match event.event_type.as_str() {
            "server.connected" => (
                NormalizedHostEventPayload::SessionLifecycle(SessionLifecycleObservation {
                    transition: SessionLifecycleTransition::Started,
                    detail_ref: None,
                }),
                HostEventPrivacyClass::PublicSummary,
                warnings,
            ),
            "session.idle" => (
                NormalizedHostEventPayload::SessionLifecycle(SessionLifecycleObservation {
                    transition: SessionLifecycleTransition::Suspended,
                    detail_ref: None,
                }),
                HostEventPrivacyClass::PublicSummary,
                warnings,
            ),
            "session.status" => {
                let status_kind = event
                    .properties
                    .pointer("/status/type")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown");
                match status_kind {
                    "idle" => (
                        NormalizedHostEventPayload::SessionLifecycle(SessionLifecycleObservation {
                            transition: SessionLifecycleTransition::Suspended,
                            detail_ref: None,
                        }),
                        HostEventPrivacyClass::PublicSummary,
                        warnings,
                    ),
                    "busy" | "retry" => (
                        NormalizedHostEventPayload::SessionLifecycle(SessionLifecycleObservation {
                            transition: SessionLifecycleTransition::Resumed,
                            detail_ref: None,
                        }),
                        HostEventPrivacyClass::PublicSummary,
                        warnings,
                    ),
                    _ => (
                        NormalizedHostEventPayload::UnsupportedQuarantined(
                            UnsupportedEventObservation {
                                source_namespace: "opencode".to_owned(),
                                source_version: None,
                                reason: UnsupportedEventReason::UnknownMethod,
                                detail_ref: None,
                            },
                        ),
                        HostEventPrivacyClass::RestrictedHandleOnly,
                        warnings,
                    ),
                }
            }
            _ => (
                NormalizedHostEventPayload::UnsupportedQuarantined(UnsupportedEventObservation {
                    source_namespace: "opencode".to_owned(),
                    source_version: None,
                    reason: UnsupportedEventReason::UnknownMethod,
                    detail_ref: None,
                }),
                HostEventPrivacyClass::RestrictedHandleOnly,
                warnings,
            ),
        }
    } else {
        match event.event_type.as_str() {
            "message.updated" => {
                let delta_chars = serde_json::to_value(&event.properties)
                    .map(|value| value.to_string().chars().count() as u64)
                    .unwrap_or(0);
                (
                    NormalizedHostEventPayload::AssistantDelta(AssistantDeltaObservation {
                        delta_chars,
                        truncated: false,
                    }),
                    HostEventPrivacyClass::RedactedSummary,
                    warnings,
                )
            }
            "message.part.updated" => {
                let part_type = event
                    .properties
                    .pointer("/part/type")
                    .and_then(Value::as_str)
                    .unwrap_or("");
                let reason = event
                    .properties
                    .pointer("/part/reason")
                    .and_then(Value::as_str)
                    .unwrap_or("");
                if part_type == "step-finish" && reason == "stop" {
                    (
                        NormalizedHostEventPayload::ProviderTerminalObserved(
                            ProviderTerminalObservation {
                                status: ProviderTerminalStatus::CompletedObserved,
                                terminal_ref: "opencode:step-finish-stop".to_owned(),
                            },
                        ),
                        HostEventPrivacyClass::RedactedSummary,
                        warnings,
                    )
                } else {
                    let delta_chars = serde_json::to_value(&event.properties)
                        .map(|value| value.to_string().chars().count() as u64)
                        .unwrap_or(0);
                    (
                        NormalizedHostEventPayload::AssistantDelta(AssistantDeltaObservation {
                            delta_chars,
                            truncated: false,
                        }),
                        HostEventPrivacyClass::RedactedSummary,
                        warnings,
                    )
                }
            }
            "session.error" => (
                NormalizedHostEventPayload::Error(ErrorObservation {
                    code: "OPENCODE_SESSION_ERROR".to_owned(),
                    safe_summary:
                        "opencode session error observed; detail behind restricted handle"
                            .to_owned(),
                }),
                HostEventPrivacyClass::RedactedSummary,
                warnings,
            ),
            "permission.asked" => (
                NormalizedHostEventPayload::Warning(WarningObservation {
                    code: "OPENCODE_PERMISSION_ASKED".to_owned(),
                    summary:
                        "opencode permission request observed; detail behind restricted handle"
                            .to_owned(),
                }),
                HostEventPrivacyClass::RedactedSummary,
                warnings,
            ),
            _ => (
                NormalizedHostEventPayload::UnsupportedQuarantined(UnsupportedEventObservation {
                    source_namespace: "opencode".to_owned(),
                    source_version: None,
                    reason: UnsupportedEventReason::UnknownMethod,
                    detail_ref: None,
                }),
                HostEventPrivacyClass::RestrictedHandleOnly,
                warnings,
            ),
        }
    }
}

/// Admitted read-only attempt edge (issue #487).
///
/// One externally admitted swarm slot executes exactly one bounded read-only
/// `OpenCode` [`AgentAttempt`] through the supervised attach-only loopback route
/// ([`crate::OpenCodeClient::run_read_only`]). This section owns the
/// admission/binding verification and the candidate-only seal; it owns no
/// server launch, no process handle, no credential, and no task-finish
/// authority.
///
/// Verification is fail-closed before start: a missing admission, a stale
/// attempt/lease/fence/generation, a route mismatch (including a no-route
/// admission), a prompt-model/admission-model divergence, or an already
/// terminal attempt rejects before any provider call. The seal is
/// replay-stable: identical admitted inputs reproduce the identical canonical
/// digest, and the sealed candidate carries [`AuthorityCeiling::CandidateOnly`]
/// only — it is structurally incapable of expressing task completion (there is
/// no finish field, and the agent result disposition family has no completion
/// variant).
#[derive(Clone, Debug, PartialEq)]
pub struct AdmittedOpenCodeAttempt {
    admission: AdmittedRouteReceipt,
    binding: ProviderExecutionBinding,
    attempt: AgentAttempt,
    model: ModelSelection,
}

/// Fail-closed verification and sealing failures for [`AdmittedOpenCodeAttempt`].
///
/// Every variant rejects execution or sealing; none carries provider output,
/// credentials, or authority beyond the typed mismatch it names.
#[derive(Debug, thiserror::Error)]
pub enum AdmittedAttemptError {
    #[error("admitted route receipt is missing; an unadmitted attempt never executes")]
    MissingAdmission,
    #[error("admitted route receipt is invalid: {0}")]
    AdmissionRejected(ContractError),
    #[error("provider execution binding is invalid: {0}")]
    BindingRejected(ContractError),
    #[error("admitted attempt record is invalid: {0}")]
    AttemptRejected(ContractError),
    #[error("admission attempt identity does not match the bound attempt")]
    AttemptMismatch,
    #[error("admission lease identity does not match the bound lease")]
    LeaseMismatch,
    #[error("admission fence is missing or stale against the current fence")]
    FenceMismatch,
    #[error("admission runtime generation is stale against the current generation")]
    GenerationMismatch,
    #[error("admission authorizes no route, or a different route than the bound execution")]
    RouteMismatch,
    #[error("prompt provider/model differs from the admitted route")]
    ModelMismatch,
    #[error("bound attempt is already terminal; a closed attempt never re-executes")]
    AttemptTerminal,
    #[error("read-only run request is invalid: {0}")]
    RequestRejected(RunRequestError),
    #[error("sealed candidate rejects the run result: {reason}")]
    SealRejected { reason: &'static str },
    #[error("admitted attempt digest failed: {0}")]
    DigestFailed(String),
    #[error(transparent)]
    Run(#[from] crate::OpenCodeRunError),
}

impl AdmittedOpenCodeAttempt {
    /// Binds one admitted attempt to its exact execution binding, attempt
    /// record, and admitted provider/model, verifying everything before the
    /// caller may start execution.
    ///
    /// `admission` is `Option` so a missing external decision fails closed
    /// here ([`AdmittedAttemptError::MissingAdmission`]) instead of executing
    /// unadmitted. `current_fence` and `runtime_generation` are the live
    /// runtime context: a stale fence or generation rejects even when the
    /// admission itself is well-formed.
    pub fn new(
        admission: Option<AdmittedRouteReceipt>,
        binding: ProviderExecutionBinding,
        attempt: AgentAttempt,
        model: ModelSelection,
        current_fence: &StateFence,
        runtime_generation: ResourceGeneration,
    ) -> Result<Self, AdmittedAttemptError> {
        let Some(admission) = admission else {
            return Err(AdmittedAttemptError::MissingAdmission);
        };
        let candidate = Self {
            admission,
            binding,
            attempt,
            model,
        };
        candidate.verify(current_fence, runtime_generation)?;
        Ok(candidate)
    }

    /// Re-verifies the full admission/binding/attempt agreement against the
    /// live fence and generation. The supervised runner calls this immediately
    /// before dispatch so context that advanced after construction still fails
    /// closed before any provider call.
    pub fn verify(
        &self,
        current_fence: &StateFence,
        runtime_generation: ResourceGeneration,
    ) -> Result<(), AdmittedAttemptError> {
        self.admission
            .validate()
            .map_err(AdmittedAttemptError::AdmissionRejected)?;
        self.binding
            .validate_internal()
            .map_err(AdmittedAttemptError::BindingRejected)?;
        self.attempt
            .validate()
            .map_err(AdmittedAttemptError::AttemptRejected)?;
        self.binding
            .validate_against_attempt(&self.attempt)
            .map_err(AdmittedAttemptError::BindingRejected)?;
        if let Some(stored) = &self.attempt.provider_binding
            && stored.execution_unit != self.binding.execution_unit
        {
            return Err(AdmittedAttemptError::BindingRejected(
                ContractError::BindingMismatch,
            ));
        }
        if self.admission.attempt_id != self.binding.attempt_id
            || self.admission.attempt_id != self.attempt.id
        {
            return Err(AdmittedAttemptError::AttemptMismatch);
        }
        if self.admission.lease_id != self.binding.lease_id {
            return Err(AdmittedAttemptError::LeaseMismatch);
        }
        if self.admission.state_fence != self.binding.state_fence {
            return Err(AdmittedAttemptError::FenceMismatch);
        }
        if self.admission.runtime_generation != self.binding.runtime_generation {
            return Err(AdmittedAttemptError::GenerationMismatch);
        }
        if self.binding.state_fence != *current_fence {
            return Err(AdmittedAttemptError::FenceMismatch);
        }
        if self.binding.runtime_generation != runtime_generation {
            return Err(AdmittedAttemptError::GenerationMismatch);
        }
        match &self.admission.selected_route {
            Some(selected) if *selected == self.binding.route => {}
            _ => return Err(AdmittedAttemptError::RouteMismatch),
        }
        if self.binding.route != self.admission.requested_route {
            return Err(AdmittedAttemptError::RouteMismatch);
        }
        if self.model.provider_id != self.binding.route.provider
            || self.model.model_id != self.binding.route.model
        {
            return Err(AdmittedAttemptError::ModelMismatch);
        }
        self.model.validate().map_err(|error| {
            AdmittedAttemptError::RequestRejected(RunRequestError::InvalidModel(error))
        })?;
        if self.attempt.state.is_terminal() {
            return Err(AdmittedAttemptError::AttemptTerminal);
        }
        Ok(())
    }

    /// Fail-closed pre-start check that the presented run request carries the
    /// exact admitted provider/model in a valid read-only shape. A prompt
    /// naming any other provider/model rejects before dispatch.
    pub fn verify_request(&self, request: &ReadOnlyRunRequest) -> Result<(), AdmittedAttemptError> {
        request
            .validate()
            .map_err(AdmittedAttemptError::RequestRejected)?;
        if request.model != self.model {
            return Err(AdmittedAttemptError::ModelMismatch);
        }
        Ok(())
    }

    /// Returns the governing admitted-route receipt.
    pub fn admission(&self) -> &AdmittedRouteReceipt {
        &self.admission
    }

    /// Returns the exact provider-execution binding.
    pub fn binding(&self) -> &ProviderExecutionBinding {
        &self.binding
    }

    /// Returns the admitted attempt record.
    pub fn attempt(&self) -> &AgentAttempt {
        &self.attempt
    }

    /// Returns the admitted provider/model identity.
    pub fn model(&self) -> &ModelSelection {
        &self.model
    }

    /// Returns the governing admission digest this attempt executes under.
    pub fn admitted_route_digest(&self) -> &LowercaseSha256 {
        &self.admission.self_digest
    }

    /// Replay-stable canonical digest of the verified admitted inputs: the
    /// admission receipt, the execution binding, and the admitted model.
    /// Identical admitted inputs reproduce the identical digest; any
    /// attempt/lease/fence/generation/route/model difference changes it.
    pub fn attempt_digest(&self) -> Result<LowercaseSha256, AdmittedAttemptError> {
        let bytes = canonical_json_bytes(&(&self.admission, &self.binding, &self.model))
            .map_err(|error| AdmittedAttemptError::DigestFailed(error.to_string()))?;
        serde_json::from_value(Value::String(sha256_hex(&bytes)))
            .map_err(|error| AdmittedAttemptError::DigestFailed(error.to_string()))
    }
}

/// Sealed candidate-only outcome of one admitted read-only attempt.
///
/// This is the only artifact the edge returns: the exact attempt identity, the
/// governing admission digest, and the canonical digest of the supervised wire
/// result, under [`AuthorityCeiling::CandidateOnly`]. It carries no finish
/// field, no task identity, and no completion disposition, so a sealed
/// candidate can never become a task completion.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdmittedAttemptCandidate {
    pub attempt_id: AgentAttemptId,
    pub admitted_route_digest: LowercaseSha256,
    pub result_digest: LowercaseSha256,
    pub authority: AuthorityCeiling,
    pub status: RunStatus,
}

impl AdmittedAttemptCandidate {
    /// Seals one supervised wire result under a verified admission.
    ///
    /// Fail-closed: a result claiming anything beyond candidate-only
    /// authority, a non-succeeded status, a succeeded status without terminal
    /// candidate output (exit-zero-without-candidate is not success), or a
    /// requested route differing from the admitted model never seals.
    pub fn seal(
        admitted: &AdmittedOpenCodeAttempt,
        result: &NoAuthorityRunResult,
    ) -> Result<Self, AdmittedAttemptError> {
        if !result.candidate_only || result.authority != AuthorityCeiling::CandidateOnly {
            return Err(AdmittedAttemptError::SealRejected {
                reason: "run result claims authority beyond candidate-only",
            });
        }
        if result.status != RunStatus::Succeeded {
            return Err(AdmittedAttemptError::SealRejected {
                reason: "run result is not a succeeded terminal candidate",
            });
        }
        if result.output.is_none() {
            return Err(AdmittedAttemptError::SealRejected {
                reason: "succeeded run carries no terminal candidate output",
            });
        }
        if result.actual_route.requested != *admitted.model() {
            return Err(AdmittedAttemptError::SealRejected {
                reason: "run result route differs from the admitted model",
            });
        }
        let bytes = canonical_json_bytes(result)
            .map_err(|error| AdmittedAttemptError::DigestFailed(error.to_string()))?;
        let result_digest: LowercaseSha256 =
            serde_json::from_value(Value::String(sha256_hex(&bytes)))
                .map_err(|error| AdmittedAttemptError::DigestFailed(error.to_string()))?;
        Ok(Self {
            attempt_id: admitted.attempt().id.clone(),
            admitted_route_digest: admitted.admitted_route_digest().clone(),
            result_digest,
            authority: AuthorityCeiling::CandidateOnly,
            status: RunStatus::Succeeded,
        })
    }

    /// Recomputes the canonical digest of this sealed candidate. Re-sealing
    /// identical inputs reproduces the identical value.
    pub fn compute_digest(&self) -> Result<LowercaseSha256, AdmittedAttemptError> {
        let bytes = canonical_json_bytes(self)
            .map_err(|error| AdmittedAttemptError::DigestFailed(error.to_string()))?;
        serde_json::from_value(Value::String(sha256_hex(&bytes)))
            .map_err(|error| AdmittedAttemptError::DigestFailed(error.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use eliot_contracts::{EpochId, EpochLineageId};
    use serde_json::json;

    const TEST_LINEAGE_A: &str = "550e8400-e29b-41d4-a716-446655440000";

    fn test_epoch(lineage: &str, sequence: u64) -> EpochId {
        EpochId::new(
            EpochLineageId::new(lineage).expect("valid test lineage"),
            std::num::NonZeroU64::new(sequence).expect("nonzero test sequence"),
        )
        .expect("valid test epoch")
    }

    fn model() -> Result<ModelSelection, ModelSelectionError> {
        ModelSelection::new("opencode-go", "deepseek-v4-flash")
    }

    #[test]
    fn response_contracts_preserve_unknown_fields() -> Result<(), serde_json::Error> {
        let health: HealthResponse = serde_json::from_value(json!({
            "healthy": true,
            "version": "1.2.3",
            "future_field": {"kept": true}
        }))?;
        assert_eq!(health.extra["future_field"], json!({"kept": true}));

        let event: OpenCodeEvent = serde_json::from_value(json!({
            "type": "session.status",
            "properties": {"status": "busy"},
            "future": 7
        }))?;
        assert_eq!(event.extra["future"], json!(7));

        let statuses: SessionStatusMap = serde_json::from_value(json!({
            "session-1": {"type": "retry", "attempt": 2, "message": "busy", "next": 50, "future": true}
        }))?;
        assert!(matches!(
            statuses.get("session-1"),
            Some(SessionStatus::Retry { attempt: 2, .. })
        ));

        let diff: SnapshotFileDiff = serde_json::from_value(json!({
            "file": "src/lib.rs",
            "patch": "@@ -1 +1 @@",
            "additions": 1,
            "deletions": 1,
            "status": "modified"
        }))?;
        assert_eq!(diff.path(), "src/lib.rs");

        let session: Session = serde_json::from_value(json!({
            "id": "ses-1",
            "slug": "s",
            "projectID": "project-1",
            "workspaceID": "workspace-1",
            "directory": "C:\\Scratch",
            "title": "ELIOT",
            "version": "1.4.3",
            "time": {"created": 1, "updated": 2}
        }))?;
        assert_eq!(session.workspace_id.as_deref(), Some("workspace-1"));
        Ok(())
    }

    #[test]
    fn read_only_request_rejects_mutation_and_missing_model_identity()
    -> Result<(), Box<dyn std::error::Error>> {
        let request = ReadOnlyRunRequest::new("inspect", model()?)?;
        let encoded = serde_json::to_value(&request)?;
        assert!(serde_json::from_value::<ReadOnlyRunRequest>(encoded).is_ok());
        assert_eq!(
            request.output_schema,
            json!({"type": "object", "additionalProperties": true})
        );

        let mut mutating = json!({
            "prompt": "inspect",
            "model": {"providerID": "opencode-go", "modelID": "deepseek-v4-flash"},
            "read_only": false
        });
        assert!(serde_json::from_value::<ReadOnlyRunRequest>(mutating.take()).is_err());

        assert!(
            serde_json::from_value::<ReadOnlyRunRequest>(json!({
                "prompt": "inspect",
                "model": {"providerID": "opencode-go"},
                "read_only": true
            }))
            .is_err()
        );

        let custom = request.clone().with_output_schema(json!({
            "type": "object",
            "properties": {"status": {"type": "string"}},
            "required": ["status"],
            "additionalProperties": false
        }))?;
        let custom = custom.with_message_id("msg_abc-123")?;
        let custom_wire = serde_json::to_value(&custom)?;
        assert_eq!(custom_wire["outputSchema"]["required"], json!(["status"]));
        assert_eq!(custom_wire["message_id"], json!("msg_abc-123"));
        assert!(
            !custom_wire
                .as_object()
                .is_some_and(|wire| wire.contains_key("workspace"))
        );
        let custom_round_trip: ReadOnlyRunRequest = serde_json::from_value(custom_wire)?;
        assert_eq!(custom_round_trip, custom);

        let alias_round_trip: ReadOnlyRunRequest = serde_json::from_value(json!({
            "prompt": "inspect",
            "model": {"providerID": "opencode-go", "modelID": "deepseek-v4-flash"},
            "read_only": true,
            "messageID": "msg_alias"
        }))?;
        assert_eq!(alias_round_trip.message_id.as_deref(), Some("msg_alias"));

        let missing_schema: ReadOnlyRunRequest = serde_json::from_value(json!({
            "prompt": "inspect",
            "model": {"providerID": "opencode-go", "modelID": "deepseek-v4-flash"},
            "read_only": true
        }))?;
        assert_eq!(missing_schema.output_schema, default_output_schema());

        assert!(matches!(
            request.clone().with_output_schema(json!("not-an-object")),
            Err(RunRequestError::InvalidOutputSchema)
        ));
        for invalid_message_id in ["", "message_1", "msg_", "msg_bad space", "msg_bad!"] {
            assert!(matches!(
                request.clone().with_message_id(invalid_message_id),
                Err(RunRequestError::InvalidMessageIdentity)
            ));
        }
        let too_long_message_id = format!("msg_{}", "a".repeat(125));
        assert!(matches!(
            request.clone().with_message_id(too_long_message_id),
            Err(RunRequestError::InvalidMessageIdentity)
        ));
        assert!(
            serde_json::from_value::<ReadOnlyRunRequest>(json!({
                "prompt": "inspect",
                "model": {"providerID": "opencode-go", "modelID": "deepseek-v4-flash"},
                "read_only": true,
                "outputSchema": []
            }))
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn result_rejects_authority_overclaim_and_records_unavailable_telemetry()
    -> Result<(), Box<dyn std::error::Error>> {
        let route = OpenCodeWireRouteReceipt::unavailable(model()?, "server did not attest route");
        let result = NoAuthorityRunResult {
            status: RunStatus::Unknown,
            candidate_only: true,
            authority: AuthorityCeiling::CandidateOnly,
            actual_route: route,
            usage: UsageAvailability::unavailable("usage endpoint unavailable"),
            quota: QuotaAvailability::unavailable("quota endpoint unavailable"),
            session_id: None,
            output: None,
            events: Vec::new(),
            diff: Vec::new(),
            extra: UnknownFields::new(),
        };
        let encoded = serde_json::to_value(&result)?;
        let decoded: NoAuthorityRunResult = serde_json::from_value(encoded)?;
        assert_eq!(decoded.usage.state, AvailabilityState::Unavailable);
        assert_eq!(decoded.quota.state, AvailabilityState::Unavailable);

        let mut overclaim = serde_json::to_value(result)?;
        overclaim["candidate_only"] = json!(false);
        assert!(serde_json::from_value::<NoAuthorityRunResult>(overclaim).is_err());
        Ok(())
    }

    fn observed_wire_receipt() -> Result<OpenCodeWireRouteReceipt, ModelSelectionError> {
        Ok(OpenCodeWireRouteReceipt {
            requested: model()?,
            observed: Some(model()?),
            provider: Some("opencode-go".to_owned()),
            endpoint: Some("http://127.0.0.1:4096".to_owned()),
            route_fingerprint: Some("sha256:route".to_owned()),
            session_id: Some("ses_1".to_owned()),
            directory: Some(r"C:\Scratch".to_owned()),
            server_version: Some("1.4.3".to_owned()),
            workspace_id: Some("workspace-1".to_owned()),
            state: OpenCodeWireRouteState::Observed,
            extra: UnknownFields::new(),
        })
    }

    #[test]
    fn route_receipt_requires_observed_bindings_and_round_trips()
    -> Result<(), Box<dyn std::error::Error>> {
        let receipt = observed_wire_receipt()?;
        receipt.validate()?;
        let wire = serde_json::to_value(&receipt)?;
        assert_eq!(wire["session_id"], json!("ses_1"));
        assert_eq!(wire["workspace_id"], json!("workspace-1"));
        let decoded: OpenCodeWireRouteReceipt = serde_json::from_value(wire.clone())?;
        assert_eq!(decoded, receipt);

        let aliases = json!({
            "requested": {"providerID": "opencode-go", "modelID": "deepseek-v4-flash"},
            "observed": {"providerID": "opencode-go", "modelID": "deepseek-v4-flash"},
            "providerID": "opencode-go",
            "endpointURL": "http://127.0.0.1:4096",
            "routeFingerprint": "sha256:route",
            "sessionID": "ses_1",
            "cwd": "C:\\Scratch",
            "serverVersion": "1.4.3",
            "workspaceID": "workspace-1",
            "state": "observed"
        });
        assert_eq!(
            serde_json::from_value::<OpenCodeWireRouteReceipt>(aliases)?,
            receipt
        );

        for (field, expected) in [
            ("provider", OpenCodeWireRouteError::ObservedProviderMissing),
            ("endpoint", OpenCodeWireRouteError::ObservedEndpointMissing),
            (
                "route_fingerprint",
                OpenCodeWireRouteError::ObservedRouteFingerprintMissing,
            ),
            (
                "session_id",
                OpenCodeWireRouteError::ObservedSessionIdentityMissing,
            ),
            (
                "directory",
                OpenCodeWireRouteError::ObservedDirectoryMissing,
            ),
            (
                "server_version",
                OpenCodeWireRouteError::ObservedServerVersionMissing,
            ),
        ] {
            let mut invalid = wire.clone();
            invalid[field] = Value::Null;
            assert!(matches!(
                serde_json::from_value::<OpenCodeWireRouteReceipt>(invalid),
                Err(error) if error.to_string().contains(&expected.to_string())
            ));
        }

        for endpoint in ["http://localhost:4096", "http://192.168.1.5:4096"] {
            let mut invalid = wire.clone();
            invalid["endpoint"] = json!(endpoint);
            assert!(matches!(
                serde_json::from_value::<OpenCodeWireRouteReceipt>(invalid),
                Err(error) if error.to_string().contains(
                    &OpenCodeWireRouteError::ObservedEndpointNotLoopback.to_string()
                )
            ));
        }

        let mut invalid_directory = wire.clone();
        invalid_directory["directory"] = json!("relative/path");
        assert!(matches!(
            serde_json::from_value::<OpenCodeWireRouteReceipt>(invalid_directory),
            Err(error) if error.to_string().contains(
                &OpenCodeWireRouteError::ObservedDirectoryNotAbsolute.to_string()
            )
        ));

        let mut invalid_workspace = wire.clone();
        invalid_workspace["workspace_id"] = json!(" ");
        assert!(matches!(
            serde_json::from_value::<OpenCodeWireRouteReceipt>(invalid_workspace),
            Err(error) if error.to_string().contains(
                &OpenCodeWireRouteError::ObservedWorkspaceIdentityBlank.to_string()
            )
        ));

        let mut unavailable = serde_json::to_value(OpenCodeWireRouteReceipt::unavailable(
            model()?,
            "route unavailable",
        ))?;
        unavailable["server_version"] = json!("1.4.3");
        assert!(matches!(
            serde_json::from_value::<OpenCodeWireRouteReceipt>(unavailable),
            Err(error) if error.to_string().contains(
                &OpenCodeWireRouteError::UnavailableHasIdentity.to_string()
            )
        ));
        Ok(())
    }

    #[test]
    fn model_selection_serializes_exact_provider_and_model_identity()
    -> Result<(), Box<dyn std::error::Error>> {
        let encoded = serde_json::to_value(model()?)?;
        assert_eq!(
            encoded,
            json!({"providerID": "opencode-go", "modelID": "deepseek-v4-flash"})
        );
        Ok(())
    }

    #[test]
    fn assistant_projection_attests_route_completion_tokens_and_permission()
    -> Result<(), serde_json::Error> {
        let assistant: AssistantMessage = serde_json::from_value(json!({
            "id": "msg-1",
            "sessionID": "session-1",
            "role": "assistant",
            "time": {"created": 1, "completed": 2},
            "providerID": "opencode-go",
            "modelID": "deepseek-v4-flash",
            "cost": 0.25,
            "tokens": {"input": 10, "output": 20, "reasoning": 3},
            "parts": [
                {"type": "step-finish", "reason": "stop", "cost": 0.25, "tokens": {"output": 20}},
                {"type": "permission", "permission": "read"}
            ]
        }))?;
        assert_eq!(assistant.provider_id, "opencode-go");
        assert_eq!(assistant.model_id, "deepseek-v4-flash");
        assert_eq!(assistant.time.completed, Some(2));
        assert_eq!(assistant.parts.len(), 2);
        assert!(matches!(
            &assistant.parts[0],
            MessagePart::StepFinish { reason, .. } if reason == "stop"
        ));
        assert!(matches!(
            &assistant.parts[1],
            MessagePart::Permission { permission, .. } if permission == "read"
        ));
        Ok(())
    }

    #[test]
    fn wire_projection_is_not_the_canonical_physical_shape()
    -> Result<(), Box<dyn std::error::Error>> {
        // PRIVATE_WIRE_PROJECTION: the adapter wire record carries
        // provider/endpoint/session wire bindings and none of the canonical
        // api fields (`route_id`, `usage`, `started_at`, `terminal_at`).
        let receipt = observed_wire_receipt()?;
        let wire = serde_json::to_value(&receipt)?;
        let map = wire.as_object().expect("wire object");
        for canonical_only in ["route_id", "usage", "started_at", "terminal_at"] {
            assert!(!map.contains_key(canonical_only));
        }
        for wire_binding in [
            "provider",
            "endpoint",
            "route_fingerprint",
            "session_id",
            "directory",
            "server_version",
            "state",
        ] {
            assert!(map.contains_key(wire_binding));
        }
        // The pre-rename alias decodes the same wire for importers outside
        // `src/`; both spellings agree byte-for-byte.
        let via_alias: ActualRouteReceipt = serde_json::from_value(wire.clone())?;
        assert_eq!(via_alias, receipt);
        Ok(())
    }

    #[test]
    fn wire_observed_is_never_defaulted_from_requested() -> Result<(), Box<dyn std::error::Error>> {
        // `state: observed` without an explicit observed identity fails with
        // the typed missing-identity error instead of echoing `requested`.
        let missing_observed = json!({
            "requested": {"providerID": "opencode-go", "modelID": "deepseek-v4-flash"},
            "provider": "opencode-go",
            "endpoint": "http://127.0.0.1:4096",
            "route_fingerprint": "sha256:route",
            "session_id": "ses_1",
            "directory": "C:\\Scratch",
            "server_version": "1.4.3",
            "state": "observed"
        });
        assert!(matches!(
            serde_json::from_value::<OpenCodeWireRouteReceipt>(missing_observed),
            Err(error) if error.to_string().contains(
                &OpenCodeWireRouteError::ObservedIdentityMissing.to_string()
            )
        ));
        // `state: unavailable` smuggling any observed identity is rejected.
        let mut smuggled = serde_json::to_value(OpenCodeWireRouteReceipt::unavailable(
            model()?,
            "route unavailable",
        ))?;
        smuggled["provider"] = json!("opencode-go");
        assert!(matches!(
            serde_json::from_value::<OpenCodeWireRouteReceipt>(smuggled),
            Err(error) if error.to_string().contains(
                &OpenCodeWireRouteError::UnavailableHasIdentity.to_string()
            )
        ));
        Ok(())
    }

    #[test]
    fn wire_unavailable_reason_is_explicit_and_identity_free()
    -> Result<(), Box<dyn std::error::Error>> {
        let receipt =
            OpenCodeWireRouteReceipt::unavailable(model()?, "server did not attest route");
        assert!(!receipt.is_observed());
        assert_eq!(receipt.observed, None);
        assert_eq!(
            receipt.extra.get("unavailable_reason"),
            Some(&json!("server did not attest route"))
        );
        receipt.validate()?;
        Ok(())
    }

    #[test]
    fn wire_unknown_fields_stay_loss_visible() -> Result<(), Box<dyn std::error::Error>> {
        let mut wire = serde_json::to_value(observed_wire_receipt()?)?;
        wire["future_wire_field"] = json!({"kept": true});
        let decoded: OpenCodeWireRouteReceipt = serde_json::from_value(wire.clone())?;
        assert_eq!(decoded.extra["future_wire_field"], json!({"kept": true}));
        assert_eq!(serde_json::to_value(&decoded)?, wire);
        Ok(())
    }

    #[test]
    fn wire_result_rejects_session_divergence() -> Result<(), Box<dyn std::error::Error>> {
        let result = NoAuthorityRunResult {
            status: RunStatus::Unknown,
            candidate_only: true,
            authority: AuthorityCeiling::CandidateOnly,
            actual_route: observed_wire_receipt()?,
            usage: UsageAvailability::unavailable("usage endpoint unavailable"),
            quota: QuotaAvailability::unavailable("quota endpoint unavailable"),
            session_id: Some("ses_other".to_owned()),
            output: None,
            events: Vec::new(),
            diff: Vec::new(),
            extra: UnknownFields::new(),
        };
        let wire = serde_json::to_value(&result)?;
        assert!(serde_json::from_value::<NoAuthorityRunResult>(wire).is_err());
        Ok(())
    }

    fn conversion_digest(seed: &str) -> LowercaseSha256 {
        serde_json::from_value(json!(eliot_contracts::sha256_hex(
            format!("opencode-conversion-{seed}").as_bytes()
        )))
        .expect("valid fixture digest")
    }

    fn conversion_route() -> RouteFingerprint {
        RouteFingerprint {
            host_family: "opencode".to_owned(),
            adapter: "eliot-agent-opencode".to_owned(),
            protocol_transport: "http+sse".to_owned(),
            runtime_hash: conversion_digest("runtime"),
            adapter_hash: conversion_digest("adapter"),
            provider: "opencode-go".to_owned(),
            model: "deepseek-v4-flash".to_owned(),
            auth_billing: "interactive-user".to_owned(),
            serializer_hash: conversion_digest("serializer"),
            tool_semantics_hash: conversion_digest("tools"),
            reasoning_mode: "catalogue-default".to_owned(),
            continuation_behavior: "native-resume".to_owned(),
            feature_flags_hash: conversion_digest("features"),
        }
    }

    fn conversion_binding(
        route: &RouteFingerprint,
    ) -> Result<ProviderExecutionBinding, Box<dyn std::error::Error>> {
        use eliot_agent_api::{
            AttemptId, ExecutionUnit, NativeSession, NativeSessionLocator, RequestId, WorkLeaseId,
        };
        use eliot_contracts::{ResourceGeneration, StateFence};
        let fence = StateFence::new(test_epoch(TEST_LINEAGE_A, 1), ResourceGeneration::new(1)?);
        Ok(ProviderExecutionBinding {
            attempt_id: AttemptId::new("attempt-opencode")?,
            lease_id: serde_json::from_value(
                serde_json::json!({"namespace": "eliot.governor.work-lease", "revision": "v1", "value": "lease-opencode"}),
            )?,
            state_fence: fence.clone(),
            runtime_generation: ResourceGeneration::new(1)?,
            route: route.clone(),
            session_id: None,
            provider_scope_ref: "scope:test".to_owned(),
            native_session: NativeSession::Native(NativeSessionLocator::new("ses_1")?),
            execution_unit: ExecutionUnit::new("opencode", "unit-1")?,
            start_request_id: RequestId::new("req-1")?,
            start_request_sha256: eliot_contracts::sha256_hex(b"req-1"),
        })
    }

    fn conversion_admission(
        binding: &ProviderExecutionBinding,
    ) -> Result<AdmittedRouteReceipt, Box<dyn std::error::Error>> {
        use eliot_agent_api::{
            CandidateSelectionDisposition, PolicyRevision, RouteSelectionCandidate,
            candidate_digest_for,
        };
        use eliot_contracts::DecisionId;
        let candidate = RouteSelectionCandidate {
            capability: "opencode".to_owned(),
            query_intent: "test-intent".to_owned(),
            scope_ref: "scope:test".to_owned(),
            policy_revision: PolicyRevision::new(3)?,
            candidates: vec![binding.route.clone()],
            selected: Some(binding.route.clone()),
            rejected: Vec::new(),
            selection: CandidateSelectionDisposition::Selected,
            evidence_refs: vec!["evidence-1".to_owned()],
        };
        candidate.validate()?;
        let zero: LowercaseSha256 = serde_json::from_value(json!(
            "0000000000000000000000000000000000000000000000000000000000000000"
        ))?;
        let mut receipt = AdmittedRouteReceipt {
            schema_version: CONTRACT_VERSION.to_owned(),
            decision_id: DecisionId::new("decision-opencode")?,
            candidate_digest: candidate_digest_for(&candidate)?,
            attempt_id: binding.attempt_id.clone(),
            lease_id: binding.lease_id.clone(),
            state_fence: binding.state_fence.clone(),
            runtime_generation: binding.runtime_generation,
            policy_revision: PolicyRevision::new(3)?,
            requested_route: binding.route.clone(),
            selected_route: Some(binding.route.clone()),
            no_route: None,
            evidence_refs: vec!["evidence-1".to_owned()],
            proof_ceiling: eliot_agent_api::ProofCeiling::CandidateArtifact,
            self_digest: zero,
        };
        receipt.self_digest = receipt.compute_digest()?;
        receipt.validate()?;
        Ok(receipt)
    }

    fn conversion_usage() -> UsageReceipt {
        UsageReceipt {
            input_tokens: None,
            output_tokens: None,
            cost_microunits: None,
            quota: eliot_agent_api::QuotaKnowledge::Unknown,
        }
    }

    #[test]
    fn wire_observed_converts_to_matched_without_synthesis()
    -> Result<(), Box<dyn std::error::Error>> {
        let requested = conversion_route();
        let binding = conversion_binding(&requested)?;
        let admission = conversion_admission(&binding)?;
        let wire = observed_wire_receipt()?;
        let observation = wire.to_physical_observation(
            &requested,
            &admission,
            &binding,
            conversion_usage(),
            ClockReading::default(),
            ClockReading::default(),
            ClockReading::default(),
            ClockReading {
                valid_time_ms: Some(2_000),
                known_time_ms: Some(2_001),
                transaction_sequence: None,
                monotonic_ns: None,
            },
            EventCursor::new("opencode-test-1")?,
            1,
            None,
        )?;
        assert_eq!(observation.route_state, RouteObservationState::Matched);
        assert_eq!(observation.observed_route.as_ref(), Some(&requested));
        assert_eq!(observation.requested_route, requested);
        assert!(observation.diverged_fields.is_empty());
        observation.validate_against(&binding, &admission)?;
        Ok(())
    }

    #[test]
    fn wire_observed_with_different_model_converts_to_diverged_with_quarantine()
    -> Result<(), Box<dyn std::error::Error>> {
        let requested = conversion_route();
        let binding = conversion_binding(&requested)?;
        let admission = conversion_admission(&binding)?;
        let mut wire = observed_wire_receipt()?;
        wire.observed = Some(ModelSelection::new("other-provider", "other-model")?);
        wire.provider = Some("other-provider".to_owned());
        let observation = wire.to_physical_observation(
            &requested,
            &admission,
            &binding,
            conversion_usage(),
            ClockReading::default(),
            ClockReading::default(),
            ClockReading::default(),
            ClockReading {
                valid_time_ms: Some(2_000),
                known_time_ms: Some(2_001),
                transaction_sequence: None,
                monotonic_ns: None,
            },
            EventCursor::new("opencode-test-2")?,
            2,
            None,
        )?;
        assert_eq!(observation.route_state, RouteObservationState::Diverged);
        assert_ne!(observation.observed_route.as_ref(), Some(&requested));
        assert!(!observation.diverged_fields.is_empty());
        assert!(observation.recovery_ref.is_some());
        observation.validate_against(&binding, &admission)?;
        Ok(())
    }

    #[test]
    fn wire_unavailable_converts_to_unobserved_with_reason_and_loss_handle()
    -> Result<(), Box<dyn std::error::Error>> {
        let requested = conversion_route();
        let binding = conversion_binding(&requested)?;
        let admission = conversion_admission(&binding)?;
        let mut wire =
            OpenCodeWireRouteReceipt::unavailable(model()?, "server did not attest route");
        wire.extra
            .insert("future_wire_field".to_owned(), json!({"kept": true}));
        let observation = wire.to_physical_observation(
            &requested,
            &admission,
            &binding,
            conversion_usage(),
            ClockReading::default(),
            ClockReading::default(),
            ClockReading::default(),
            ClockReading::default(),
            EventCursor::new("opencode-test-3")?,
            3,
            None,
        )?;
        // Missing observed is never synthesized from requested.
        assert_eq!(observation.route_state, RouteObservationState::Unobserved);
        assert_eq!(observation.observed_route, None);
        assert_eq!(
            observation.unobserved_reason.as_deref(),
            Some("server did not attest route")
        );
        assert_eq!(
            observation.execution_outcome,
            ExecutionOutcome::UnknownOutcome
        );
        assert!(observation.recovery_ref.is_some());
        // Unknown fields stay loss-visible via the raw-evidence digest handle.
        assert!(observation.raw_evidence_digest.is_some());
        assert!(observation.raw_evidence_ref.is_some());
        observation.validate_against(&binding, &admission)?;
        Ok(())
    }

    fn typed_execution_lineage(
        binding: &ProviderExecutionBinding,
        cursor: &EventCursor,
        sequence: u64,
    ) -> eliot_agent_api::ProviderObservationLineage {
        use eliot_agent_api::{ExecutionUnitObservation, ProviderObservationLineage};
        ProviderObservationLineage::ExecutionUnitObservation(Box::new(ExecutionUnitObservation {
            binding: binding.clone(),
            cursor: cursor.clone(),
            sequence,
        }))
    }

    fn typed_session_lineage()
    -> Result<eliot_agent_api::ProviderObservationLineage, Box<dyn std::error::Error>> {
        use eliot_agent_api::{NativeSession, NativeSessionLocator, SessionObservation};
        Ok(
            eliot_agent_api::ProviderObservationLineage::SessionObservation(SessionObservation {
                session_id: None,
                native: NativeSession::Native(NativeSessionLocator::new("ses_1")?),
            }),
        )
    }

    #[test]
    fn typed_normalizer_execution_message_updated_roundtrip()
    -> Result<(), Box<dyn std::error::Error>> {
        use eliot_agent_api::{HostEventDeliveryDisposition, NormalizedHostEventPayload};
        let requested = conversion_route();
        let binding = conversion_binding(&requested)?;
        let admission = conversion_admission(&binding)?;
        let raw = br#"{"type":"message.updated","properties":{"sessionID":"ses_1"}}"#;
        let wire: OpenCodeEvent = serde_json::from_slice(raw)?;
        let cursor = EventCursor::new("cursor-opencode-typed-1")?;
        let input = OpenCodeHostEventInput {
            event: &wire,
            event_id: EventId::new("evt-opencode-typed-1")?,
            cursor: cursor.clone(),
            sequence: 1,
            predecessors: Vec::new(),
            lineage: typed_execution_lineage(&binding, &cursor, 1),
            raw_source_bytes: raw,
            raw_source_handle: RestrictedRawSourceHandle::new("restricted-opencode:frame-1")?,
            observed_at: ClockReading {
                valid_time_ms: Some(1_700_000_000_000),
                known_time_ms: Some(1_700_000_000_001),
                transaction_sequence: None,
                monotonic_ns: None,
            },
            delivery: HostEventDeliveryDisposition::DurableOrdered,
            admission: Some(&admission),
        };
        let (envelope, receipt) = normalize_opencode_event(input)?;
        assert_eq!(envelope.normalization, receipt);
        envelope.validate_for_lineage(&binding, &admission)?;
        assert_eq!(
            envelope.producer_adapter_identity,
            OPENCODE_NORMALIZER_IDENTITY
        );
        assert_eq!(
            envelope.adapter_contract_version,
            OPENCODE_NORMALIZER_VERSION
        );
        assert!(matches!(
            envelope.payload,
            NormalizedHostEventPayload::AssistantDelta(_)
        ));
        // Raw provider bytes never enter the public normalized payload: the
        // wire-only marker stays behind the restricted handle (the `ses_1`
        // locator may legitimately appear via the binding lineage).
        assert!(
            !serde_json::to_value(&envelope.payload)?
                .to_string()
                .contains("wire-secret-abc123")
        );
        // Complete coverage when no unknown extra fields were dropped.
        assert_eq!(
            receipt.coverage,
            eliot_agent_api::NormalizationCoverage::Complete
        );
        assert!(receipt.omitted_fields.is_empty());
        // Determinism: same typed input reproduces the same digest.
        let wire2: OpenCodeEvent = serde_json::from_slice(raw)?;
        let (rebuilt, _) = normalize_opencode_event(OpenCodeHostEventInput {
            event: &wire2,
            event_id: EventId::new("evt-opencode-typed-1")?,
            cursor: cursor.clone(),
            sequence: 1,
            predecessors: Vec::new(),
            lineage: typed_execution_lineage(&binding, &cursor, 1),
            raw_source_bytes: raw,
            raw_source_handle: RestrictedRawSourceHandle::new("restricted-opencode:frame-1")?,
            observed_at: ClockReading {
                valid_time_ms: Some(1_700_000_000_000),
                known_time_ms: Some(1_700_000_000_001),
                transaction_sequence: None,
                monotonic_ns: None,
            },
            delivery: HostEventDeliveryDisposition::DurableOrdered,
            admission: Some(&admission),
        })?;
        assert_eq!(rebuilt.compute_digest()?, envelope.compute_digest()?);
        Ok(())
    }

    #[test]
    fn typed_normalizer_session_lifecycle_validates_on_session_path()
    -> Result<(), Box<dyn std::error::Error>> {
        use eliot_agent_api::{HostEventDeliveryDisposition, NormalizedHostEventPayload};
        let raw = br#"{"type":"server.connected","properties":{}}"#;
        let wire: OpenCodeEvent = serde_json::from_slice(raw)?;
        let cursor = EventCursor::new("cursor-opencode-session-1")?;
        let (envelope, receipt) = normalize_opencode_event(OpenCodeHostEventInput {
            event: &wire,
            event_id: EventId::new("evt-opencode-session-1")?,
            cursor,
            sequence: 1,
            predecessors: Vec::new(),
            lineage: typed_session_lineage()?,
            raw_source_bytes: raw,
            raw_source_handle: RestrictedRawSourceHandle::new("restricted-opencode:session-1")?,
            observed_at: ClockReading::default(),
            delivery: HostEventDeliveryDisposition::BestEffortOrdered,
            admission: None,
        })?;
        assert_eq!(envelope.normalization, receipt);
        envelope.validate_as_session_observation()?;
        assert!(matches!(
            envelope.payload,
            NormalizedHostEventPayload::SessionLifecycle(_)
        ));
        Ok(())
    }

    #[test]
    fn typed_normalizer_unknown_event_quarantined_with_loss_manifest()
    -> Result<(), Box<dyn std::error::Error>> {
        use eliot_agent_api::{HostEventDeliveryDisposition, NormalizedHostEventPayload};
        let requested = conversion_route();
        let binding = conversion_binding(&requested)?;
        let admission = conversion_admission(&binding)?;
        let raw = br#"{"type":"future.unknown-kind","properties":{},"future_extra":7}"#;
        let wire: OpenCodeEvent = serde_json::from_slice(raw)?;
        assert_eq!(wire.extra.get("future_extra"), Some(&json!(7)));
        let cursor = EventCursor::new("cursor-opencode-quarantine-1")?;
        let (envelope, receipt) = normalize_opencode_event(OpenCodeHostEventInput {
            event: &wire,
            event_id: EventId::new("evt-opencode-quarantine-1")?,
            cursor: cursor.clone(),
            sequence: 4,
            predecessors: Vec::new(),
            lineage: typed_execution_lineage(&binding, &cursor, 4),
            raw_source_bytes: raw,
            raw_source_handle: RestrictedRawSourceHandle::new("restricted-opencode:frame-q1")?,
            observed_at: ClockReading::default(),
            delivery: HostEventDeliveryDisposition::BestEffortOrdered,
            admission: Some(&admission),
        })?;
        assert!(matches!(
            envelope.payload,
            NormalizedHostEventPayload::UnsupportedQuarantined(_)
        ));
        // Unknown extra stays loss-visible, never silently dropped.
        assert_eq!(
            receipt.coverage,
            eliot_agent_api::NormalizationCoverage::LossyOmission
        );
        assert!(
            receipt
                .omitted_fields
                .contains(&"extra:future_extra".to_owned())
        );
        assert!(
            receipt
                .warnings
                .contains(&"opencode.unknown-event-type-quarantined".to_owned())
        );
        assert_eq!(
            receipt.unsupported_disposition,
            eliot_agent_api::UnsupportedDisposition::UnsupportedMethodQuarantined
        );
        // The closed payload carries no generic Value escape: the wire's raw
        // `future_extra` value never appears in the public payload JSON.
        let payload_value = serde_json::to_value(&envelope.payload)?;
        assert!(!payload_value.to_string().contains("future_extra"));
        envelope.validate_for_lineage(&binding, &admission)?;
        Ok(())
    }

    #[test]
    fn typed_normalizer_rejects_generic_value_and_forged_inputs()
    -> Result<(), Box<dyn std::error::Error>> {
        use eliot_agent_api::{HostEventDeliveryDisposition, NormalizedHostEventEnvelope};
        // A legacy generic wire (arbitrary normalized Value, caller time string)
        // never deserializes as the closed typed schema.
        let legacy = serde_json::json!({
            "event_id": "evt-opencode-legacy",
            "attempt_id": "attempt",
            "sequence": 1,
            "cursor": "cursor-opencode-legacy",
            "kind": "assistant_delta",
            "route": serde_json::to_value(conversion_route())?,
            "raw_payload_digest": eliot_contracts::sha256_hex(b"legacy"),
            "normalized_payload": {"delta": "raw provider text"},
            "parent_event_id": null,
            "observed_at": "2026-09-13T00:00:00Z",
        });
        assert!(serde_json::from_value::<NormalizedHostEventEnvelope>(legacy).is_err());
        let requested = conversion_route();
        let binding = conversion_binding(&requested)?;
        let admission = conversion_admission(&binding)?;
        let raw = br#"{"type":"message.updated","properties":{"sessionID":"ses_1","wire_only_marker":"wire-secret-abc123"}}"#;
        let wire: OpenCodeEvent = serde_json::from_slice(raw)?;
        let cursor = EventCursor::new("cursor-opencode-forged-1")?;
        // Zero sequence fails closed before any digest is minted.
        assert!(matches!(
            normalize_opencode_event(OpenCodeHostEventInput {
                event: &wire,
                event_id: EventId::new("evt-opencode-forged-0")?,
                cursor: cursor.clone(),
                sequence: 0,
                predecessors: Vec::new(),
                lineage: typed_execution_lineage(&binding, &cursor, 0),
                raw_source_bytes: raw,
                raw_source_handle: RestrictedRawSourceHandle::new("restricted-opencode:frame-f0")?,
                observed_at: ClockReading::default(),
                delivery: HostEventDeliveryDisposition::DurableOrdered,
                admission: Some(&admission),
            }),
            Err(OpenCodeObservationConversionError::InvalidInput("sequence"))
        ));
        // Missing admission for execution-unit lineage fails closed.
        assert!(matches!(
            normalize_opencode_event(OpenCodeHostEventInput {
                event: &wire,
                event_id: EventId::new("evt-opencode-forged-1")?,
                cursor: cursor.clone(),
                sequence: 1,
                predecessors: Vec::new(),
                lineage: typed_execution_lineage(&binding, &cursor, 1),
                raw_source_bytes: raw,
                raw_source_handle: RestrictedRawSourceHandle::new("restricted-opencode:frame-f1")?,
                observed_at: ClockReading::default(),
                delivery: HostEventDeliveryDisposition::DurableOrdered,
                admission: None,
            }),
            Err(OpenCodeObservationConversionError::InvalidInput(
                "admission/lineage"
            ))
        ));
        // A forged caller-supplied output digest fails closed at validation.
        let (mut envelope, _) = normalize_opencode_event(OpenCodeHostEventInput {
            event: &wire,
            event_id: EventId::new("evt-opencode-forged-2")?,
            cursor: cursor.clone(),
            sequence: 1,
            predecessors: Vec::new(),
            lineage: typed_execution_lineage(&binding, &cursor, 1),
            raw_source_bytes: raw,
            raw_source_handle: RestrictedRawSourceHandle::new("restricted-opencode:frame-f2")?,
            observed_at: ClockReading::default(),
            delivery: HostEventDeliveryDisposition::DurableOrdered,
            admission: Some(&admission),
        })?;
        envelope.normalization.output_digest = serde_json::from_value(serde_json::json!(
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        ))?;
        assert_eq!(
            envelope.validate_for_lineage(&binding, &admission),
            Err(eliot_agent_api::ContractError::DigestMismatch)
        );
        Ok(())
    }

    #[test]
    fn typed_normalizer_never_synthesizes_cursor_from_wire()
    -> Result<(), Box<dyn std::error::Error>> {
        use eliot_agent_api::HostEventDeliveryDisposition;
        // The wire carries no cursor; the envelope cursor is exactly the
        // caller-supplied post-R1 cursor, never `opencode:{sequence}`.
        let requested = conversion_route();
        let binding = conversion_binding(&requested)?;
        let admission = conversion_admission(&binding)?;
        let raw = br#"{"type":"message.updated","properties":{"sessionID":"ses_1"}}"#;
        let wire: OpenCodeEvent = serde_json::from_slice(raw)?;
        let cursor = EventCursor::new("cursor-opencode-explicit-9")?;
        let (envelope, _) = normalize_opencode_event(OpenCodeHostEventInput {
            event: &wire,
            event_id: EventId::new("evt-opencode-explicit-9")?,
            cursor: cursor.clone(),
            sequence: 9,
            predecessors: Vec::new(),
            lineage: typed_execution_lineage(&binding, &cursor, 9),
            raw_source_bytes: raw,
            raw_source_handle: RestrictedRawSourceHandle::new("restricted-opencode:frame-9")?,
            observed_at: ClockReading::default(),
            delivery: HostEventDeliveryDisposition::BestEffortOrdered,
            admission: Some(&admission),
        })?;
        assert_eq!(envelope.cursor, cursor);
        assert_ne!(envelope.cursor.as_str(), "opencode:9");
        Ok(())
    }
}
