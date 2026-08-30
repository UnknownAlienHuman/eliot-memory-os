use schemars::JsonSchema;
use serde::{Deserialize, Deserializer, Serialize, de};

use super::{
    ProcessStreamSinkError, ProcessStreamSinkTerminalId, canonical_digest, validate_digest,
};

#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ProcessStreamSinkTerminalCommandKind {
    Finalize,
    Abort,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessStreamSinkTerminalCommandIdentity {
    terminal_id: ProcessStreamSinkTerminalId,
    kind: ProcessStreamSinkTerminalCommandKind,
    request_sha256: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TerminalCommandIdentityWire {
    terminal_id: ProcessStreamSinkTerminalId,
    kind: ProcessStreamSinkTerminalCommandKind,
    request_sha256: String,
}

impl ProcessStreamSinkTerminalCommandIdentity {
    #[allow(
        clippy::needless_pass_by_value,
        reason = "a checked identity takes ownership of its terminal namespace"
    )]
    pub fn new(
        terminal_id: ProcessStreamSinkTerminalId,
        kind: ProcessStreamSinkTerminalCommandKind,
        request_sha256: impl Into<String>,
    ) -> Result<Self, ProcessStreamSinkError> {
        let terminal_id = ProcessStreamSinkTerminalId::new(terminal_id.as_str().to_owned())?;
        let request_sha256 = request_sha256.into();
        validate_digest("request_sha256", &request_sha256)?;
        Ok(Self {
            terminal_id,
            kind,
            request_sha256,
        })
    }

    pub fn from_request<T: Serialize>(
        terminal_id: ProcessStreamSinkTerminalId,
        kind: ProcessStreamSinkTerminalCommandKind,
        request: &T,
    ) -> Result<Self, ProcessStreamSinkError> {
        let request_sha256 = canonical_digest("terminal_request", request)?;
        Self::new(terminal_id, kind, request_sha256)
    }

    pub const fn terminal_id(&self) -> &ProcessStreamSinkTerminalId {
        &self.terminal_id
    }

    pub const fn kind(&self) -> ProcessStreamSinkTerminalCommandKind {
        self.kind
    }

    pub fn request_sha256(&self) -> &str {
        &self.request_sha256
    }

    pub(crate) fn validate(&self) -> Result<(), ProcessStreamSinkError> {
        let _ = ProcessStreamSinkTerminalId::new(self.terminal_id.as_str().to_owned())?;
        validate_digest("request_sha256", &self.request_sha256)
    }
}

impl<'de> Deserialize<'de> for ProcessStreamSinkTerminalCommandIdentity {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let wire = TerminalCommandIdentityWire::deserialize(deserializer)?;
        let value = Self {
            terminal_id: wire.terminal_id,
            kind: wire.kind,
            request_sha256: wire.request_sha256,
        };
        value.validate().map_err(de::Error::custom)?;
        Ok(value)
    }
}
