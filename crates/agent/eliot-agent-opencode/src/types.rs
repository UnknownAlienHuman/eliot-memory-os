use std::{collections::BTreeMap, path::Path};

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

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ActualRouteReceipt {
    pub requested: ModelSelection,
    pub observed: Option<ModelSelection>,
    pub provider: Option<String>,
    pub endpoint: Option<String>,
    pub route_fingerprint: Option<String>,
    pub session_id: Option<String>,
    pub directory: Option<String>,
    pub server_version: Option<String>,
    pub workspace_id: Option<String>,
    pub state: ActualRouteState,
    #[serde(flatten)]
    pub extra: UnknownFields,
}

impl<'de> Deserialize<'de> for ActualRouteReceipt {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct RawActualRouteReceipt {
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
            state: ActualRouteState,
            #[serde(flatten)]
            extra: UnknownFields,
        }

        let raw = RawActualRouteReceipt::deserialize(deserializer)?;
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

impl ActualRouteReceipt {
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
            state: ActualRouteState::Observed,
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
            state: ActualRouteState::Unavailable,
            extra,
        }
    }

    pub fn is_observed(&self) -> bool {
        self.state == ActualRouteState::Observed && self.observed.is_some()
    }

    pub fn validate(&self) -> Result<(), RouteReceiptError> {
        self.requested
            .validate()
            .map_err(RouteReceiptError::InvalidRequestedModel)?;
        if let Some(observed) = &self.observed {
            observed
                .validate()
                .map_err(RouteReceiptError::InvalidObservedModel)?;
        }
        match self.state {
            ActualRouteState::Observed => {
                if self.observed.is_none() {
                    return Err(RouteReceiptError::ObservedIdentityMissing);
                }
                if is_blank(self.provider.as_deref()) {
                    return Err(RouteReceiptError::ObservedProviderMissing);
                }
                if self.provider.as_deref()
                    != self
                        .observed
                        .as_ref()
                        .map(|model| model.provider_id.as_str())
                {
                    return Err(RouteReceiptError::ObservedProviderMismatch);
                }
                let endpoint = self
                    .endpoint
                    .as_deref()
                    .ok_or(RouteReceiptError::ObservedEndpointMissing)?;
                if crate::LoopbackEndpoint::parse(endpoint).is_err() {
                    return Err(RouteReceiptError::ObservedEndpointNotLoopback);
                }
                if is_blank(self.route_fingerprint.as_deref()) {
                    return Err(RouteReceiptError::ObservedRouteFingerprintMissing);
                }
                if is_blank(self.session_id.as_deref()) {
                    return Err(RouteReceiptError::ObservedSessionIdentityMissing);
                }
                let directory = self
                    .directory
                    .as_deref()
                    .ok_or(RouteReceiptError::ObservedDirectoryMissing)?;
                if !Path::new(directory).is_absolute() {
                    return Err(RouteReceiptError::ObservedDirectoryNotAbsolute);
                }
                if is_blank(self.server_version.as_deref()) {
                    return Err(RouteReceiptError::ObservedServerVersionMissing);
                }
                if self
                    .workspace_id
                    .as_deref()
                    .is_some_and(|workspace| workspace.trim().is_empty())
                {
                    return Err(RouteReceiptError::ObservedWorkspaceIdentityBlank);
                }
                Ok(())
            }
            ActualRouteState::Unavailable => {
                if self.observed.is_some()
                    || self.provider.is_some()
                    || self.endpoint.is_some()
                    || self.route_fingerprint.is_some()
                    || self.session_id.is_some()
                    || self.directory.is_some()
                    || self.server_version.is_some()
                    || self.workspace_id.is_some()
                {
                    Err(RouteReceiptError::UnavailableHasIdentity)
                } else {
                    Ok(())
                }
            }
        }
    }
}

fn is_blank(value: Option<&str>) -> bool {
    value.is_none_or(|value| value.trim().is_empty())
}

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum RouteReceiptError {
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
pub enum ActualRouteState {
    Observed,
    Unavailable,
}

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
    pub actual_route: ActualRouteReceipt,
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
            actual_route: ActualRouteReceipt,
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
        if raw.actual_route.state == ActualRouteState::Observed
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

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
        let route = ActualRouteReceipt::unavailable(model()?, "server did not attest route");
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

    fn observed_route_receipt() -> Result<ActualRouteReceipt, ModelSelectionError> {
        Ok(ActualRouteReceipt {
            requested: model()?,
            observed: Some(model()?),
            provider: Some("opencode-go".to_owned()),
            endpoint: Some("http://127.0.0.1:4096".to_owned()),
            route_fingerprint: Some("sha256:route".to_owned()),
            session_id: Some("ses_1".to_owned()),
            directory: Some(r"C:\Scratch".to_owned()),
            server_version: Some("1.4.3".to_owned()),
            workspace_id: Some("workspace-1".to_owned()),
            state: ActualRouteState::Observed,
            extra: UnknownFields::new(),
        })
    }

    #[test]
    fn route_receipt_requires_observed_bindings_and_round_trips()
    -> Result<(), Box<dyn std::error::Error>> {
        let receipt = observed_route_receipt()?;
        receipt.validate()?;
        let wire = serde_json::to_value(&receipt)?;
        assert_eq!(wire["session_id"], json!("ses_1"));
        assert_eq!(wire["workspace_id"], json!("workspace-1"));
        let decoded: ActualRouteReceipt = serde_json::from_value(wire.clone())?;
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
            serde_json::from_value::<ActualRouteReceipt>(aliases)?,
            receipt
        );

        for (field, expected) in [
            ("provider", RouteReceiptError::ObservedProviderMissing),
            ("endpoint", RouteReceiptError::ObservedEndpointMissing),
            (
                "route_fingerprint",
                RouteReceiptError::ObservedRouteFingerprintMissing,
            ),
            (
                "session_id",
                RouteReceiptError::ObservedSessionIdentityMissing,
            ),
            ("directory", RouteReceiptError::ObservedDirectoryMissing),
            (
                "server_version",
                RouteReceiptError::ObservedServerVersionMissing,
            ),
        ] {
            let mut invalid = wire.clone();
            invalid[field] = Value::Null;
            assert!(matches!(
                serde_json::from_value::<ActualRouteReceipt>(invalid),
                Err(error) if error.to_string().contains(&expected.to_string())
            ));
        }

        for endpoint in ["http://localhost:4096", "http://192.168.1.5:4096"] {
            let mut invalid = wire.clone();
            invalid["endpoint"] = json!(endpoint);
            assert!(matches!(
                serde_json::from_value::<ActualRouteReceipt>(invalid),
                Err(error) if error.to_string().contains(
                    &RouteReceiptError::ObservedEndpointNotLoopback.to_string()
                )
            ));
        }

        let mut invalid_directory = wire.clone();
        invalid_directory["directory"] = json!("relative/path");
        assert!(matches!(
            serde_json::from_value::<ActualRouteReceipt>(invalid_directory),
            Err(error) if error.to_string().contains(
                &RouteReceiptError::ObservedDirectoryNotAbsolute.to_string()
            )
        ));

        let mut invalid_workspace = wire.clone();
        invalid_workspace["workspace_id"] = json!(" ");
        assert!(matches!(
            serde_json::from_value::<ActualRouteReceipt>(invalid_workspace),
            Err(error) if error.to_string().contains(
                &RouteReceiptError::ObservedWorkspaceIdentityBlank.to_string()
            )
        ));

        let mut unavailable = serde_json::to_value(ActualRouteReceipt::unavailable(
            model()?,
            "route unavailable",
        ))?;
        unavailable["server_version"] = json!("1.4.3");
        assert!(matches!(
            serde_json::from_value::<ActualRouteReceipt>(unavailable),
            Err(error) if error.to_string().contains(
                &RouteReceiptError::UnavailableHasIdentity.to_string()
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
}
