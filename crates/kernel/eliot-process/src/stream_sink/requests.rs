use schemars::JsonSchema;
use serde::{Deserialize, Deserializer, Serialize, de};

use super::types::{
    ProcessStreamDigestAlgorithm, ProcessStreamSinkLimits, ProcessStreamSinkSessionId,
    ProcessStreamSinkSourceId, ProcessStreamSinkState, ProcessStreamSinkTerminalId,
};
use super::{PROCESS_STREAM_SINK_SCHEMA_VERSION, ProcessStreamSinkError};
use super::{
    ProcessExecutionBinding, ProcessStreamKind, ProcessStreamPolicyBinding,
    ProcessStreamPrefixPreview, ProcessStreamTransformationBinding, StreamEvidenceGap,
    StreamTransportStatus, canonical_digest, validate_binding, validate_digest, validate_gaps,
    validate_preview_limit,
};
use super::{ProcessStreamSinkTerminalCommandIdentity, ProcessStreamSinkTerminalCommandKind};

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessStreamSinkOpenRequest {
    schema_version: String,
    session_id: ProcessStreamSinkSessionId,
    source_id: ProcessStreamSinkSourceId,
    terminal_id: ProcessStreamSinkTerminalId,
    binding: ProcessExecutionBinding,
    stream: ProcessStreamKind,
    policy: ProcessStreamPolicyBinding,
    limits: ProcessStreamSinkLimits,
    transport_digest_algorithm: ProcessStreamDigestAlgorithm,
    source_digest_algorithm: ProcessStreamDigestAlgorithm,
    open_request_sha256: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OpenRequestWire {
    schema_version: String,
    session_id: ProcessStreamSinkSessionId,
    source_id: ProcessStreamSinkSourceId,
    terminal_id: ProcessStreamSinkTerminalId,
    binding: ProcessExecutionBinding,
    stream: ProcessStreamKind,
    policy: ProcessStreamPolicyBinding,
    limits: ProcessStreamSinkLimits,
    transport_digest_algorithm: ProcessStreamDigestAlgorithm,
    source_digest_algorithm: ProcessStreamDigestAlgorithm,
    open_request_sha256: String,
}

#[derive(Serialize)]
struct OpenRequestMaterial<'a> {
    schema_version: &'a str,
    session_id: &'a ProcessStreamSinkSessionId,
    source_id: &'a ProcessStreamSinkSourceId,
    terminal_id: &'a ProcessStreamSinkTerminalId,
    binding: &'a ProcessExecutionBinding,
    stream: ProcessStreamKind,
    policy: &'a ProcessStreamPolicyBinding,
    limits: ProcessStreamSinkLimits,
    transport_digest_algorithm: ProcessStreamDigestAlgorithm,
    source_digest_algorithm: ProcessStreamDigestAlgorithm,
}

impl ProcessStreamSinkOpenRequest {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        session_id: ProcessStreamSinkSessionId,
        source_id: ProcessStreamSinkSourceId,
        terminal_id: ProcessStreamSinkTerminalId,
        binding: ProcessExecutionBinding,
        stream: ProcessStreamKind,
        policy: ProcessStreamPolicyBinding,
        limits: ProcessStreamSinkLimits,
        transport_digest_algorithm: ProcessStreamDigestAlgorithm,
        source_digest_algorithm: ProcessStreamDigestAlgorithm,
    ) -> Result<Self, ProcessStreamSinkError> {
        let mut value = Self {
            schema_version: PROCESS_STREAM_SINK_SCHEMA_VERSION.to_owned(),
            session_id,
            source_id,
            terminal_id,
            binding,
            stream,
            policy,
            limits,
            transport_digest_algorithm,
            source_digest_algorithm,
            open_request_sha256: String::new(),
        };
        value.validate_without_digest()?;
        value.open_request_sha256 = value.compute_digest()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), ProcessStreamSinkError> {
        self.validate_without_digest()?;
        validate_digest("open_request_sha256", &self.open_request_sha256)?;
        if self.open_request_sha256 != self.compute_digest()? {
            return Err(ProcessStreamSinkError::OpenDigestMismatch);
        }
        Ok(())
    }

    fn validate_without_digest(&self) -> Result<(), ProcessStreamSinkError> {
        if self.schema_version != PROCESS_STREAM_SINK_SCHEMA_VERSION {
            return Err(ProcessStreamSinkError::InvalidRequest {
                reason: "unsupported sink schema version",
            });
        }
        validate_binding(&self.binding)?;
        let policy = serde_json::to_value(&self.policy).map_err(|_| {
            ProcessStreamSinkError::InvalidRequest {
                reason: "invalid policy",
            }
        })?;
        serde_json::from_value::<ProcessStreamPolicyBinding>(policy).map_err(|_| {
            ProcessStreamSinkError::InvalidRequest {
                reason: "invalid policy",
            }
        })?;
        Ok(())
    }

    fn compute_digest(&self) -> Result<String, ProcessStreamSinkError> {
        canonical_digest(
            "open_request",
            &OpenRequestMaterial {
                schema_version: &self.schema_version,
                session_id: &self.session_id,
                source_id: &self.source_id,
                terminal_id: &self.terminal_id,
                binding: &self.binding,
                stream: self.stream,
                policy: &self.policy,
                limits: self.limits,
                transport_digest_algorithm: self.transport_digest_algorithm,
                source_digest_algorithm: self.source_digest_algorithm,
            },
        )
    }

    pub fn schema_version(&self) -> &str {
        &self.schema_version
    }
    pub const fn session_id(&self) -> &ProcessStreamSinkSessionId {
        &self.session_id
    }
    pub const fn source_id(&self) -> &ProcessStreamSinkSourceId {
        &self.source_id
    }
    pub const fn terminal_id(&self) -> &ProcessStreamSinkTerminalId {
        &self.terminal_id
    }
    pub const fn binding(&self) -> &ProcessExecutionBinding {
        &self.binding
    }
    pub const fn stream(&self) -> ProcessStreamKind {
        self.stream
    }
    pub const fn policy(&self) -> &ProcessStreamPolicyBinding {
        &self.policy
    }
    pub const fn limits(&self) -> &ProcessStreamSinkLimits {
        &self.limits
    }
    pub const fn transport_digest_algorithm(&self) -> ProcessStreamDigestAlgorithm {
        self.transport_digest_algorithm
    }
    pub const fn source_digest_algorithm(&self) -> ProcessStreamDigestAlgorithm {
        self.source_digest_algorithm
    }
    pub fn open_request_sha256(&self) -> &str {
        &self.open_request_sha256
    }

    pub fn open_digest(&self) -> &str {
        &self.open_request_sha256
    }
}

impl<'de> Deserialize<'de> for ProcessStreamSinkOpenRequest {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let wire = OpenRequestWire::deserialize(deserializer)?;
        let value = Self {
            schema_version: wire.schema_version,
            session_id: wire.session_id,
            source_id: wire.source_id,
            terminal_id: wire.terminal_id,
            binding: wire.binding,
            stream: wire.stream,
            policy: wire.policy,
            limits: wire.limits,
            transport_digest_algorithm: wire.transport_digest_algorithm,
            source_digest_algorithm: wire.source_digest_algorithm,
            open_request_sha256: wire.open_request_sha256,
        };
        value.validate().map_err(de::Error::custom)?;
        Ok(value)
    }
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessStreamSinkAppend {
    sequence: u64,
    offset: u64,
    bytes: Vec<u8>,
    sha256: String,
    wait_budget_ms: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AppendWire {
    sequence: u64,
    offset: u64,
    bytes: Vec<u8>,
    sha256: String,
    wait_budget_ms: u64,
}

impl ProcessStreamSinkAppend {
    pub fn new(
        sequence: u64,
        offset: u64,
        bytes: Vec<u8>,
        sha256: impl Into<String>,
        wait_budget_ms: u64,
    ) -> Result<Self, ProcessStreamSinkError> {
        let value = Self {
            sequence,
            offset,
            bytes,
            sha256: sha256.into(),
            wait_budget_ms,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn from_bytes(sequence: u64, offset: u64, bytes: Vec<u8>, wait_budget_ms: u64) -> Self {
        Self {
            sequence,
            offset,
            sha256: eliot_contracts::sha256_hex(&bytes),
            bytes,
            wait_budget_ms,
        }
    }

    pub fn validate(&self) -> Result<(), ProcessStreamSinkError> {
        validate_digest("append.sha256", &self.sha256)?;
        if self.sha256 != eliot_contracts::sha256_hex(&self.bytes) {
            return Err(ProcessStreamSinkError::InvalidDigest {
                field: "append.sha256",
            });
        }
        Ok(())
    }

    pub const fn sequence(&self) -> u64 {
        self.sequence
    }
    pub const fn offset(&self) -> u64 {
        self.offset
    }
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
    pub fn sha256(&self) -> &str {
        &self.sha256
    }
    pub const fn byte_length(&self) -> u64 {
        self.bytes.len() as u64
    }
    pub const fn wait_budget_ms(&self) -> u64 {
        self.wait_budget_ms
    }
}

impl<'de> Deserialize<'de> for ProcessStreamSinkAppend {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let wire = AppendWire::deserialize(deserializer)?;
        Self::new(
            wire.sequence,
            wire.offset,
            wire.bytes,
            wire.sha256,
            wire.wait_budget_ms,
        )
        .map_err(de::Error::custom)
    }
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", tag = "kind")]
pub enum ProcessStreamSinkAppendDisposition {
    Accepted {
        next_sequence: u64,
        next_offset: u64,
    },
    Replayed {
        next_sequence: u64,
        next_offset: u64,
    },
    Backpressured {
        retry_after_ms: u64,
    },
    DeadlineExceeded,
    Cancelled,
    Terminal {
        state: ProcessStreamSinkState,
        terminal_sha256: String,
    },
}

#[derive(Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum AppendDispositionKind {
    Accepted,
    Replayed,
    Backpressured,
    DeadlineExceeded,
    Cancelled,
    Terminal,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AppendDispositionWire {
    kind: AppendDispositionKind,
    next_sequence: Option<u64>,
    next_offset: Option<u64>,
    retry_after_ms: Option<u64>,
    state: Option<ProcessStreamSinkState>,
    terminal_sha256: Option<String>,
}

impl<'de> Deserialize<'de> for ProcessStreamSinkAppendDisposition {
    #[allow(
        clippy::too_many_lines,
        reason = "each wire variant is checked explicitly before construction"
    )]
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let wire = AppendDispositionWire::deserialize(deserializer)?;
        let AppendDispositionWire {
            kind,
            next_sequence,
            next_offset,
            retry_after_ms,
            state,
            terminal_sha256,
        } = wire;

        match kind {
            AppendDispositionKind::Accepted => {
                if retry_after_ms.is_some() || state.is_some() || terminal_sha256.is_some() {
                    return Err(de::Error::custom(
                        "accepted disposition has unexpected fields",
                    ));
                }
                Ok(Self::Accepted {
                    next_sequence: next_sequence
                        .ok_or_else(|| de::Error::missing_field("next_sequence"))?,
                    next_offset: next_offset
                        .ok_or_else(|| de::Error::missing_field("next_offset"))?,
                })
            }
            AppendDispositionKind::Replayed => {
                if retry_after_ms.is_some() || state.is_some() || terminal_sha256.is_some() {
                    return Err(de::Error::custom(
                        "replayed disposition has unexpected fields",
                    ));
                }
                Ok(Self::Replayed {
                    next_sequence: next_sequence
                        .ok_or_else(|| de::Error::missing_field("next_sequence"))?,
                    next_offset: next_offset
                        .ok_or_else(|| de::Error::missing_field("next_offset"))?,
                })
            }
            AppendDispositionKind::Backpressured => {
                if next_sequence.is_some()
                    || next_offset.is_some()
                    || state.is_some()
                    || terminal_sha256.is_some()
                {
                    return Err(de::Error::custom(
                        "backpressured disposition has unexpected fields",
                    ));
                }
                let retry_after_ms =
                    retry_after_ms.ok_or_else(|| de::Error::missing_field("retry_after_ms"))?;
                if retry_after_ms == 0 {
                    return Err(de::Error::custom(
                        "backpressured disposition requires a non-zero retry hint",
                    ));
                }
                Ok(Self::Backpressured { retry_after_ms })
            }
            AppendDispositionKind::DeadlineExceeded => {
                if next_sequence.is_some()
                    || next_offset.is_some()
                    || retry_after_ms.is_some()
                    || state.is_some()
                    || terminal_sha256.is_some()
                {
                    return Err(de::Error::custom(
                        "deadline-exceeded disposition has unexpected fields",
                    ));
                }
                Ok(Self::DeadlineExceeded)
            }
            AppendDispositionKind::Cancelled => {
                if next_sequence.is_some()
                    || next_offset.is_some()
                    || retry_after_ms.is_some()
                    || state.is_some()
                    || terminal_sha256.is_some()
                {
                    return Err(de::Error::custom(
                        "cancelled disposition has unexpected fields",
                    ));
                }
                Ok(Self::Cancelled)
            }
            AppendDispositionKind::Terminal => {
                if next_sequence.is_some() || next_offset.is_some() || retry_after_ms.is_some() {
                    return Err(de::Error::custom(
                        "terminal disposition has unexpected fields",
                    ));
                }
                let state = state.ok_or_else(|| de::Error::missing_field("state"))?;
                if !state.is_terminal() {
                    return Err(de::Error::custom(
                        "terminal disposition requires a terminal state",
                    ));
                }
                let terminal_sha256 =
                    terminal_sha256.ok_or_else(|| de::Error::missing_field("terminal_sha256"))?;
                validate_digest("terminal_sha256", &terminal_sha256).map_err(de::Error::custom)?;
                Ok(Self::Terminal {
                    state,
                    terminal_sha256,
                })
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ProcessStreamSinkAbortReason {
    Cancellation,
    PolicyProhibition,
    RedactionFailure,
    TransportFailure,
    CallerShutdown,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessStreamSinkFinalizeRequest {
    terminal_id: ProcessStreamSinkTerminalId,
    expected_final_sequence: u64,
    expected_final_offset: u64,
    wait_budget_ms: u64,
    transport: StreamTransportStatus,
    observed_sha256: String,
    observed_bytes: u64,
    preview: ProcessStreamPrefixPreview,
    transformation: Option<ProcessStreamTransformationBinding>,
    gaps: Vec<StreamEvidenceGap>,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessStreamSinkAbortRequest {
    terminal_id: ProcessStreamSinkTerminalId,
    reason: ProcessStreamSinkAbortReason,
    expected_final_sequence: u64,
    expected_final_offset: u64,
    wait_budget_ms: u64,
    transport: StreamTransportStatus,
    observed_sha256: String,
    observed_bytes: u64,
    preview: ProcessStreamPrefixPreview,
    transformation: Option<ProcessStreamTransformationBinding>,
    gaps: Vec<StreamEvidenceGap>,
}

const MAX_STREAM_EVIDENCE_GAPS: usize = 10;

fn deserialize_bounded_gaps<'de, D>(deserializer: D) -> Result<Vec<StreamEvidenceGap>, D::Error>
where
    D: Deserializer<'de>,
{
    struct BoundedGapsVisitor;

    impl<'de> de::Visitor<'de> for BoundedGapsVisitor {
        type Value = Vec<StreamEvidenceGap>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("an array of at most ten stream evidence gaps")
        }

        fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
        where
            A: de::SeqAccess<'de>,
        {
            let mut gaps = Vec::with_capacity(MAX_STREAM_EVIDENCE_GAPS);
            while let Some(gap) = sequence.next_element()? {
                if gaps.len() == MAX_STREAM_EVIDENCE_GAPS {
                    return Err(de::Error::custom(
                        "stream evidence gap count exceeds the protocol ceiling",
                    ));
                }
                gaps.push(gap);
            }
            Ok(gaps)
        }
    }

    deserializer.deserialize_seq(BoundedGapsVisitor)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FinalizeWire {
    terminal_id: ProcessStreamSinkTerminalId,
    expected_final_sequence: u64,
    expected_final_offset: u64,
    wait_budget_ms: u64,
    transport: StreamTransportStatus,
    observed_sha256: String,
    observed_bytes: u64,
    preview: ProcessStreamPrefixPreview,
    transformation: Option<ProcessStreamTransformationBinding>,
    #[serde(deserialize_with = "deserialize_bounded_gaps")]
    gaps: Vec<StreamEvidenceGap>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AbortWire {
    terminal_id: ProcessStreamSinkTerminalId,
    reason: ProcessStreamSinkAbortReason,
    expected_final_sequence: u64,
    expected_final_offset: u64,
    wait_budget_ms: u64,
    transport: StreamTransportStatus,
    observed_sha256: String,
    observed_bytes: u64,
    preview: ProcessStreamPrefixPreview,
    transformation: Option<ProcessStreamTransformationBinding>,
    #[serde(deserialize_with = "deserialize_bounded_gaps")]
    gaps: Vec<StreamEvidenceGap>,
}

macro_rules! request_accessors {
    ($type:ident) => {
        impl $type {
            pub const fn terminal_id(&self) -> &ProcessStreamSinkTerminalId {
                &self.terminal_id
            }
            pub const fn expected_final_sequence(&self) -> u64 {
                self.expected_final_sequence
            }
            pub const fn expected_final_offset(&self) -> u64 {
                self.expected_final_offset
            }
            pub const fn wait_budget_ms(&self) -> u64 {
                self.wait_budget_ms
            }
            pub const fn transport(&self) -> StreamTransportStatus {
                self.transport
            }
            pub fn observed_sha256(&self) -> &str {
                &self.observed_sha256
            }
            pub const fn observed_bytes(&self) -> u64 {
                self.observed_bytes
            }
            pub const fn preview(&self) -> &ProcessStreamPrefixPreview {
                &self.preview
            }
            pub const fn transformation(&self) -> Option<&ProcessStreamTransformationBinding> {
                self.transformation.as_ref()
            }
            pub fn gaps(&self) -> &[StreamEvidenceGap] {
                &self.gaps
            }
            fn validate_shape(&self) -> Result<(), ProcessStreamSinkError> {
                if self.gaps.len() > MAX_STREAM_EVIDENCE_GAPS {
                    return Err(ProcessStreamSinkError::InvalidRequest {
                        reason: "stream evidence gap count exceeds the protocol ceiling",
                    });
                }
                validate_digest("observed_sha256", &self.observed_sha256)?;
                validate_gaps(&self.gaps)?;
                if self.preview.representation()
                    == super::super::StreamPreviewRepresentation::TransportBytes
                    && self.preview.represented_bytes() != self.observed_bytes
                {
                    return Err(ProcessStreamSinkError::InvalidRequest {
                        reason: "transport preview must represent observed bytes",
                    });
                }
                if let Some(transformation) = &self.transformation {
                    let value = serde_json::to_value(transformation).map_err(|_| {
                        ProcessStreamSinkError::InvalidRequest {
                            reason: "invalid transformation binding",
                        }
                    })?;
                    serde_json::from_value::<ProcessStreamTransformationBinding>(value).map_err(
                        |_| ProcessStreamSinkError::InvalidRequest {
                            reason: "invalid transformation binding",
                        },
                    )?;
                }
                Ok(())
            }
        }
    };
}

impl ProcessStreamSinkFinalizeRequest {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        terminal_id: ProcessStreamSinkTerminalId,
        expected_final_sequence: u64,
        expected_final_offset: u64,
        wait_budget_ms: u64,
        transport: StreamTransportStatus,
        observed_sha256: impl Into<String>,
        observed_bytes: u64,
        preview: ProcessStreamPrefixPreview,
        transformation: Option<ProcessStreamTransformationBinding>,
        gaps: Vec<StreamEvidenceGap>,
    ) -> Result<Self, ProcessStreamSinkError> {
        let value = Self {
            terminal_id,
            expected_final_sequence,
            expected_final_offset,
            wait_budget_ms,
            transport,
            observed_sha256: observed_sha256.into(),
            observed_bytes,
            preview,
            transformation,
            gaps,
        };
        value.validate_shape()?;
        Ok(value)
    }

    pub fn command_identity(
        &self,
    ) -> Result<ProcessStreamSinkTerminalCommandIdentity, ProcessStreamSinkError> {
        self.validate_shape()?;
        ProcessStreamSinkTerminalCommandIdentity::from_request(
            self.terminal_id.clone(),
            ProcessStreamSinkTerminalCommandKind::Finalize,
            self,
        )
    }
}
request_accessors!(ProcessStreamSinkFinalizeRequest);

impl<'de> Deserialize<'de> for ProcessStreamSinkFinalizeRequest {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let wire = FinalizeWire::deserialize(deserializer)?;
        Self::new(
            wire.terminal_id,
            wire.expected_final_sequence,
            wire.expected_final_offset,
            wire.wait_budget_ms,
            wire.transport,
            wire.observed_sha256,
            wire.observed_bytes,
            wire.preview,
            wire.transformation,
            wire.gaps,
        )
        .map_err(de::Error::custom)
    }
}

impl ProcessStreamSinkAbortRequest {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        terminal_id: ProcessStreamSinkTerminalId,
        reason: ProcessStreamSinkAbortReason,
        expected_final_sequence: u64,
        expected_final_offset: u64,
        wait_budget_ms: u64,
        transport: StreamTransportStatus,
        observed_sha256: impl Into<String>,
        observed_bytes: u64,
        preview: ProcessStreamPrefixPreview,
        transformation: Option<ProcessStreamTransformationBinding>,
        gaps: Vec<StreamEvidenceGap>,
    ) -> Result<Self, ProcessStreamSinkError> {
        let value = Self {
            terminal_id,
            reason,
            expected_final_sequence,
            expected_final_offset,
            wait_budget_ms,
            transport,
            observed_sha256: observed_sha256.into(),
            observed_bytes,
            preview,
            transformation,
            gaps,
        };
        value.validate_shape()?;
        Ok(value)
    }

    pub const fn reason(&self) -> ProcessStreamSinkAbortReason {
        self.reason
    }

    pub fn command_identity(
        &self,
    ) -> Result<ProcessStreamSinkTerminalCommandIdentity, ProcessStreamSinkError> {
        self.validate_shape()?;
        ProcessStreamSinkTerminalCommandIdentity::from_request(
            self.terminal_id.clone(),
            ProcessStreamSinkTerminalCommandKind::Abort,
            self,
        )
    }
}
request_accessors!(ProcessStreamSinkAbortRequest);

impl<'de> Deserialize<'de> for ProcessStreamSinkAbortRequest {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let wire = AbortWire::deserialize(deserializer)?;
        Self::new(
            wire.terminal_id,
            wire.reason,
            wire.expected_final_sequence,
            wire.expected_final_offset,
            wire.wait_budget_ms,
            wire.transport,
            wire.observed_sha256,
            wire.observed_bytes,
            wire.preview,
            wire.transformation,
            wire.gaps,
        )
        .map_err(de::Error::custom)
    }
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessStreamSinkSessionView {
    session_id: ProcessStreamSinkSessionId,
    source_id: ProcessStreamSinkSourceId,
    terminal_id: ProcessStreamSinkTerminalId,
    state: ProcessStreamSinkState,
    next_sequence: u64,
    next_offset: u64,
    admitted_chunks: u64,
    admitted_bytes: u64,
    admitted_sha256: String,
    open_request_sha256: String,
    terminal_sha256: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SessionViewWire {
    session_id: ProcessStreamSinkSessionId,
    source_id: ProcessStreamSinkSourceId,
    terminal_id: ProcessStreamSinkTerminalId,
    state: ProcessStreamSinkState,
    next_sequence: u64,
    next_offset: u64,
    admitted_chunks: u64,
    admitted_bytes: u64,
    admitted_sha256: String,
    open_request_sha256: String,
    terminal_sha256: Option<String>,
}

impl ProcessStreamSinkSessionView {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        session_id: ProcessStreamSinkSessionId,
        source_id: ProcessStreamSinkSourceId,
        terminal_id: ProcessStreamSinkTerminalId,
        state: ProcessStreamSinkState,
        next_sequence: u64,
        next_offset: u64,
        admitted_chunks: u64,
        admitted_bytes: u64,
        admitted_sha256: impl Into<String>,
        open_request_sha256: impl Into<String>,
        terminal_sha256: Option<String>,
    ) -> Result<Self, ProcessStreamSinkError> {
        let value = Self {
            session_id,
            source_id,
            terminal_id,
            state,
            next_sequence,
            next_offset,
            admitted_chunks,
            admitted_bytes,
            admitted_sha256: admitted_sha256.into(),
            open_request_sha256: open_request_sha256.into(),
            terminal_sha256,
        };
        value.validate()?;
        Ok(value)
    }

    fn validate(&self) -> Result<(), ProcessStreamSinkError> {
        if self.state.is_terminal()
            || self.state == ProcessStreamSinkState::Opening
                && (self.next_sequence != 0
                    || self.next_offset != 0
                    || self.admitted_chunks != 0
                    || self.admitted_bytes != 0)
        {
            return Err(ProcessStreamSinkError::InvalidRequest {
                reason: "session view state or counters are invalid",
            });
        }
        validate_digest("admitted_sha256", &self.admitted_sha256)?;
        validate_digest("open_request_sha256", &self.open_request_sha256)?;
        if self.next_sequence != self.admitted_chunks || self.next_offset != self.admitted_bytes {
            return Err(ProcessStreamSinkError::InvalidRequest {
                reason: "session view counters must agree with the next sequence and offset",
            });
        }
        if self.terminal_sha256.is_some() {
            return Err(ProcessStreamSinkError::InvalidRequest {
                reason: "nonterminal session view cannot expose a terminal digest",
            });
        }
        Ok(())
    }

    pub const fn session_id(&self) -> &ProcessStreamSinkSessionId {
        &self.session_id
    }
    pub const fn source_id(&self) -> &ProcessStreamSinkSourceId {
        &self.source_id
    }
    pub const fn terminal_id(&self) -> &ProcessStreamSinkTerminalId {
        &self.terminal_id
    }
    pub const fn state(&self) -> ProcessStreamSinkState {
        self.state
    }
    pub const fn next_sequence(&self) -> u64 {
        self.next_sequence
    }
    pub const fn next_offset(&self) -> u64 {
        self.next_offset
    }
    pub const fn admitted_chunks(&self) -> u64 {
        self.admitted_chunks
    }
    pub const fn admitted_bytes(&self) -> u64 {
        self.admitted_bytes
    }
    pub fn admitted_sha256(&self) -> &str {
        &self.admitted_sha256
    }
    pub fn open_request_sha256(&self) -> &str {
        &self.open_request_sha256
    }
    pub fn terminal_sha256(&self) -> Option<&str> {
        self.terminal_sha256.as_deref()
    }
}

impl<'de> Deserialize<'de> for ProcessStreamSinkSessionView {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let wire = SessionViewWire::deserialize(deserializer)?;
        Self::new(
            wire.session_id,
            wire.source_id,
            wire.terminal_id,
            wire.state,
            wire.next_sequence,
            wire.next_offset,
            wire.admitted_chunks,
            wire.admitted_bytes,
            wire.admitted_sha256,
            wire.open_request_sha256,
            wire.terminal_sha256,
        )
        .map_err(de::Error::custom)
    }
}

/// A readback result never contains raw stream bytes.
#[allow(
    clippy::large_enum_variant,
    reason = "terminal readback is intentionally the complete typed result"
)]
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", tag = "kind")]
pub enum ProcessStreamSinkReadback {
    Session {
        view: ProcessStreamSinkSessionView,
    },
    Terminal {
        terminal: super::terminal::ProcessStreamSinkTerminal,
    },
    UnknownOutcome {
        outcome: ProcessStreamSinkUnknownOutcome,
    },
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessStreamSinkUnknownOutcome {
    session_id: ProcessStreamSinkSessionId,
    terminal_id: ProcessStreamSinkTerminalId,
    open_request_sha256: String,
    uncertainty_sha256: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UnknownOutcomeWire {
    session_id: ProcessStreamSinkSessionId,
    terminal_id: ProcessStreamSinkTerminalId,
    open_request_sha256: String,
    uncertainty_sha256: String,
}

impl ProcessStreamSinkUnknownOutcome {
    pub fn new(
        session_id: ProcessStreamSinkSessionId,
        terminal_id: ProcessStreamSinkTerminalId,
        open_request_sha256: impl Into<String>,
        uncertainty_sha256: impl Into<String>,
    ) -> Result<Self, ProcessStreamSinkError> {
        let value = Self {
            session_id,
            terminal_id,
            open_request_sha256: open_request_sha256.into(),
            uncertainty_sha256: uncertainty_sha256.into(),
        };
        validate_digest("open_request_sha256", &value.open_request_sha256)?;
        validate_digest("uncertainty_sha256", &value.uncertainty_sha256)?;
        Ok(value)
    }
    pub const fn session_id(&self) -> &ProcessStreamSinkSessionId {
        &self.session_id
    }
    pub const fn terminal_id(&self) -> &ProcessStreamSinkTerminalId {
        &self.terminal_id
    }
    pub fn open_request_sha256(&self) -> &str {
        &self.open_request_sha256
    }
    pub fn uncertainty_sha256(&self) -> &str {
        &self.uncertainty_sha256
    }
}

impl<'de> Deserialize<'de> for ProcessStreamSinkUnknownOutcome {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let wire = UnknownOutcomeWire::deserialize(deserializer)?;
        Self::new(
            wire.session_id,
            wire.terminal_id,
            wire.open_request_sha256,
            wire.uncertainty_sha256,
        )
        .map_err(de::Error::custom)
    }
}

pub(crate) fn validate_request_budget(
    budget: u64,
    maximum: u64,
) -> Result<(), ProcessStreamSinkError> {
    if budget > maximum {
        return Err(ProcessStreamSinkError::InvalidRequest {
            reason: "request wait budget exceeds session limit",
        });
    }
    Ok(())
}

pub(crate) fn validate_request_preview(
    preview: &ProcessStreamPrefixPreview,
    limits: &ProcessStreamSinkLimits,
) -> Result<(), ProcessStreamSinkError> {
    validate_preview_limit(preview, limits)
}
