use schemars::JsonSchema;
use serde::Serialize;

use super::requests::{
    ProcessStreamSinkAbortRequest, ProcessStreamSinkFinalizeRequest, ProcessStreamSinkOpenRequest,
    validate_request_budget, validate_request_preview,
};
use super::types::{
    ProcessStreamSinkLimits, ProcessStreamSinkSessionId, ProcessStreamSinkSourceId,
    ProcessStreamSinkState, ProcessStreamSinkTerminalId,
};
use super::{
    ProcessExecutionBinding, ProcessStreamEvidence, ProcessStreamKind, ProcessStreamPolicyBinding,
    ProcessStreamSinkError, canonical_digest, validate_binding, validate_digest,
    validate_terminal_evidence,
};
use super::{ProcessStreamSinkTerminalCommandIdentity, ProcessStreamSinkTerminalCommandKind};

/// Live in-process capability returned only from a checked open request.
///
/// This type intentionally implements `Serialize` but not `Deserialize`.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessStreamSinkSession {
    schema_version: String,
    session_id: ProcessStreamSinkSessionId,
    source_id: ProcessStreamSinkSourceId,
    terminal_id: ProcessStreamSinkTerminalId,
    binding: ProcessExecutionBinding,
    stream: ProcessStreamKind,
    policy: ProcessStreamPolicyBinding,
    limits: ProcessStreamSinkLimits,
    transport_digest_algorithm: super::types::ProcessStreamDigestAlgorithm,
    source_digest_algorithm: super::types::ProcessStreamDigestAlgorithm,
    open_request_sha256: String,
}

impl ProcessStreamSinkSession {
    /// Mints a live capability after validating and recomputing the open digest.
    #[allow(
        clippy::needless_pass_by_value,
        reason = "consuming the request prevents capability duplication"
    )]
    pub fn from_open_request(
        request: ProcessStreamSinkOpenRequest,
    ) -> Result<Self, ProcessStreamSinkError> {
        request.validate()?;
        Ok(Self {
            schema_version: request.schema_version().to_owned(),
            session_id: request.session_id().clone(),
            source_id: request.source_id().clone(),
            terminal_id: request.terminal_id().clone(),
            binding: request.binding().clone(),
            stream: request.stream(),
            policy: request.policy().clone(),
            limits: *request.limits(),
            transport_digest_algorithm: request.transport_digest_algorithm(),
            source_digest_algorithm: request.source_digest_algorithm(),
            open_request_sha256: request.open_request_sha256().to_owned(),
        })
    }

    pub fn new(request: ProcessStreamSinkOpenRequest) -> Result<Self, ProcessStreamSinkError> {
        Self::from_open_request(request)
    }

    pub fn validate(&self) -> Result<(), ProcessStreamSinkError> {
        if self.schema_version != super::PROCESS_STREAM_SINK_SCHEMA_VERSION {
            return Err(ProcessStreamSinkError::InvalidRequest {
                reason: "unsupported sink schema version",
            });
        }
        validate_binding(&self.binding)?;
        validate_digest("open_request_sha256", &self.open_request_sha256)
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
    pub const fn transport_digest_algorithm(&self) -> super::types::ProcessStreamDigestAlgorithm {
        self.transport_digest_algorithm
    }
    pub const fn source_digest_algorithm(&self) -> super::types::ProcessStreamDigestAlgorithm {
        self.source_digest_algorithm
    }
    pub fn open_request_sha256(&self) -> &str {
        &self.open_request_sha256
    }

    pub fn validate_append(
        &self,
        request: &super::requests::ProcessStreamSinkAppend,
    ) -> Result<(), ProcessStreamSinkError> {
        self.validate()?;
        request.validate()?;
        if request.wait_budget_ms() > self.limits.max_append_wait_ms() {
            return Err(ProcessStreamSinkError::InvalidRequest {
                reason: "append wait budget exceeds session limit",
            });
        }
        if request.byte_length() > self.limits.max_chunk_bytes() {
            return Err(ProcessStreamSinkError::ChunkLimitExceeded);
        }
        Ok(())
    }

    pub fn validate_finalize(
        &self,
        request: &ProcessStreamSinkFinalizeRequest,
    ) -> Result<(), ProcessStreamSinkError> {
        self.validate()?;
        if request.terminal_id() != self.terminal_id() {
            return Err(ProcessStreamSinkError::TerminalIdentityConflict);
        }
        validate_request_budget(request.wait_budget_ms(), self.limits.max_finalize_wait_ms())?;
        validate_request_preview(request.preview(), &self.limits)?;
        Ok(())
    }

    pub fn validate_abort(
        &self,
        request: &ProcessStreamSinkAbortRequest,
    ) -> Result<(), ProcessStreamSinkError> {
        self.validate()?;
        if request.terminal_id() != self.terminal_id() {
            return Err(ProcessStreamSinkError::TerminalIdentityConflict);
        }
        validate_request_budget(request.wait_budget_ms(), self.limits.max_abort_wait_ms())?;
        validate_request_preview(request.preview(), &self.limits)?;
        Ok(())
    }
}

#[derive(Serialize)]
struct TerminalMaterial<'a> {
    schema_version: &'a str,
    session_id: &'a ProcessStreamSinkSessionId,
    source_id: &'a ProcessStreamSinkSourceId,
    terminal_id: &'a ProcessStreamSinkTerminalId,
    open_request_sha256: &'a str,
    state: ProcessStreamSinkState,
    final_sequence: u64,
    final_offset: u64,
    admitted_chunks: u64,
    admitted_bytes: u64,
    admitted_sha256: &'a str,
    command_identity: &'a ProcessStreamSinkTerminalCommandIdentity,
    evidence: &'a ProcessStreamEvidence,
}

/// Checked terminal capability and raw/unassessed stream evidence.
///
/// Like a session, this value is not deserializable into a live capability.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessStreamSinkTerminal {
    schema_version: String,
    session_id: ProcessStreamSinkSessionId,
    source_id: ProcessStreamSinkSourceId,
    terminal_id: ProcessStreamSinkTerminalId,
    open_request_sha256: String,
    state: ProcessStreamSinkState,
    final_sequence: u64,
    final_offset: u64,
    admitted_chunks: u64,
    admitted_bytes: u64,
    admitted_sha256: String,
    command_identity: ProcessStreamSinkTerminalCommandIdentity,
    evidence: ProcessStreamEvidence,
    terminal_sha256: String,
}

impl ProcessStreamSinkTerminal {
    #[allow(clippy::too_many_arguments)]
    #[allow(
        clippy::needless_pass_by_value,
        reason = "terminal construction consumes the live capability"
    )]
    pub fn from_finalize(
        session: ProcessStreamSinkSession,
        request: ProcessStreamSinkFinalizeRequest,
        state: ProcessStreamSinkState,
        final_sequence: u64,
        final_offset: u64,
        admitted_sha256: impl Into<String>,
        evidence: ProcessStreamEvidence,
    ) -> Result<Self, ProcessStreamSinkError> {
        session.validate_finalize(&request)?;
        let command_identity = request.command_identity()?;
        let admitted_sha256 = admitted_sha256.into();
        if command_identity.terminal_id() != session.terminal_id()
            || final_sequence != request.expected_final_sequence()
            || final_offset != request.expected_final_offset()
            || request.observed_sha256() != admitted_sha256
            || request.observed_bytes() != final_offset
            || request.transport() != evidence.transport()
            || request.preview() != evidence.preview()
            || request.transformation()
                != evidence.source().and_then(|source| source.transformation())
            || request.gaps() != evidence.gaps()
        {
            return Err(ProcessStreamSinkError::TerminalIdentityConflict);
        }
        Self::from_checked(
            &session,
            &request,
            command_identity,
            state,
            final_sequence,
            final_offset,
            admitted_sha256,
            evidence,
            ProcessStreamSinkTerminalCommandKind::Finalize,
        )
    }

    #[allow(clippy::too_many_arguments)]
    #[allow(
        clippy::needless_pass_by_value,
        reason = "terminal construction consumes the live capability"
    )]
    pub fn from_abort(
        session: ProcessStreamSinkSession,
        request: ProcessStreamSinkAbortRequest,
        state: ProcessStreamSinkState,
        final_sequence: u64,
        final_offset: u64,
        admitted_sha256: impl Into<String>,
        evidence: ProcessStreamEvidence,
    ) -> Result<Self, ProcessStreamSinkError> {
        session.validate_abort(&request)?;
        let command_identity = request.command_identity()?;
        let admitted_sha256 = admitted_sha256.into();
        if command_identity.terminal_id() != session.terminal_id()
            || final_sequence != request.expected_final_sequence()
            || final_offset != request.expected_final_offset()
            || request.observed_sha256() != admitted_sha256
            || request.observed_bytes() != final_offset
            || request.transport() != evidence.transport()
            || request.preview() != evidence.preview()
            || request.transformation()
                != evidence.source().and_then(|source| source.transformation())
            || request.gaps() != evidence.gaps()
        {
            return Err(ProcessStreamSinkError::TerminalIdentityConflict);
        }
        Self::from_checked(
            &session,
            &request,
            command_identity,
            state,
            final_sequence,
            final_offset,
            admitted_sha256,
            evidence,
            ProcessStreamSinkTerminalCommandKind::Abort,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn from_checked<R: CommandRequest>(
        session: &ProcessStreamSinkSession,
        request: &R,
        command_identity: ProcessStreamSinkTerminalCommandIdentity,
        state: ProcessStreamSinkState,
        final_sequence: u64,
        final_offset: u64,
        admitted_sha256: String,
        evidence: ProcessStreamEvidence,
        expected_kind: ProcessStreamSinkTerminalCommandKind,
    ) -> Result<Self, ProcessStreamSinkError> {
        session.validate()?;
        if command_identity.kind() != expected_kind
            || command_identity.terminal_id() != session.terminal_id()
            || command_identity != request.command_identity()?
        {
            return Err(ProcessStreamSinkError::TerminalIdentityConflict);
        }
        if !state.is_terminal() {
            return Err(ProcessStreamSinkError::EvidenceInvariant {
                reason: "terminal state must be write-closed".to_owned(),
            });
        }
        validate_digest("admitted_sha256", &admitted_sha256)?;
        if final_sequence > session.limits().max_chunks() {
            return Err(ProcessStreamSinkError::ChunkCountLimitExceeded);
        }
        if final_offset > session.limits().max_total_admitted_bytes() {
            return Err(ProcessStreamSinkError::TotalLimitExceeded);
        }
        if final_offset != request.expected_final_offset() {
            return Err(ProcessStreamSinkError::OffsetMismatch {
                expected: request.expected_final_offset(),
                observed: final_offset,
            });
        }
        if evidence.binding() != session.binding() {
            return Err(ProcessStreamSinkError::BindingMismatch);
        }
        if evidence.stream() != session.stream() {
            return Err(ProcessStreamSinkError::StreamMismatch);
        }
        if evidence.policy() != session.policy() {
            return Err(ProcessStreamSinkError::PolicyMismatch);
        }
        if evidence.observed_sha256() != admitted_sha256
            || evidence.observed_bytes() != final_offset
        {
            return Err(ProcessStreamSinkError::EvidenceInvariant {
                reason: "evidence must identify every admitted transport byte".to_owned(),
            });
        }
        validate_terminal_evidence(state, &evidence)?;
        let mut value = Self {
            schema_version: super::PROCESS_STREAM_SINK_SCHEMA_VERSION.to_owned(),
            session_id: session.session_id().clone(),
            source_id: session.source_id().clone(),
            terminal_id: session.terminal_id().clone(),
            open_request_sha256: session.open_request_sha256().to_owned(),
            state,
            final_sequence,
            final_offset,
            admitted_chunks: final_sequence,
            admitted_bytes: final_offset,
            admitted_sha256,
            command_identity,
            evidence,
            terminal_sha256: String::new(),
        };
        value.terminal_sha256 = value.compute_digest()?;
        Ok(value)
    }

    fn compute_digest(&self) -> Result<String, ProcessStreamSinkError> {
        canonical_digest(
            "terminal",
            &TerminalMaterial {
                schema_version: &self.schema_version,
                session_id: &self.session_id,
                source_id: &self.source_id,
                terminal_id: &self.terminal_id,
                open_request_sha256: &self.open_request_sha256,
                state: self.state,
                final_sequence: self.final_sequence,
                final_offset: self.final_offset,
                admitted_chunks: self.admitted_chunks,
                admitted_bytes: self.admitted_bytes,
                admitted_sha256: &self.admitted_sha256,
                command_identity: &self.command_identity,
                evidence: &self.evidence,
            },
        )
    }

    pub fn validate(&self) -> Result<(), ProcessStreamSinkError> {
        if self.schema_version != super::PROCESS_STREAM_SINK_SCHEMA_VERSION {
            return Err(ProcessStreamSinkError::InvalidRequest {
                reason: "unsupported sink schema version",
            });
        }
        validate_digest("open_request_sha256", &self.open_request_sha256)?;
        validate_digest("admitted_sha256", &self.admitted_sha256)?;
        validate_digest("terminal_sha256", &self.terminal_sha256)?;
        self.command_identity.validate()?;
        if self.command_identity.terminal_id() != &self.terminal_id {
            return Err(ProcessStreamSinkError::TerminalIdentityConflict);
        }
        if !self.state.is_terminal() {
            return Err(ProcessStreamSinkError::EvidenceInvariant {
                reason: "terminal state must be write-closed".to_owned(),
            });
        }
        if self.final_sequence != self.admitted_chunks {
            return Err(ProcessStreamSinkError::SequenceGap {
                expected: self.admitted_chunks,
                observed: self.final_sequence,
            });
        }
        if self.terminal_sha256 != self.compute_digest()? {
            return Err(ProcessStreamSinkError::EvidenceInvariant {
                reason: "terminal digest does not match its description".to_owned(),
            });
        }
        if self.final_offset != self.admitted_bytes
            || self.evidence.observed_bytes() != self.admitted_bytes
            || self.evidence.observed_sha256() != self.admitted_sha256
        {
            return Err(ProcessStreamSinkError::EvidenceInvariant {
                reason: "terminal counters do not match evidence".to_owned(),
            });
        }
        validate_terminal_evidence(self.state, &self.evidence)
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
    pub const fn final_sequence(&self) -> u64 {
        self.final_sequence
    }
    pub const fn final_offset(&self) -> u64 {
        self.final_offset
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
    pub const fn evidence(&self) -> &ProcessStreamEvidence {
        &self.evidence
    }
    pub fn open_request_sha256(&self) -> &str {
        &self.open_request_sha256
    }
    pub fn terminal_sha256(&self) -> &str {
        &self.terminal_sha256
    }

    pub const fn command_identity(&self) -> &ProcessStreamSinkTerminalCommandIdentity {
        &self.command_identity
    }

    pub fn validate_against_finalize(
        &self,
        request: &ProcessStreamSinkFinalizeRequest,
    ) -> Result<(), ProcessStreamSinkError> {
        self.validate()?;
        let identity = request.command_identity()?;
        if identity.kind() != ProcessStreamSinkTerminalCommandKind::Finalize
            || &identity != self.command_identity()
        {
            return Err(ProcessStreamSinkError::TerminalIdentityConflict);
        }
        Ok(())
    }

    pub fn validate_against_abort(
        &self,
        request: &ProcessStreamSinkAbortRequest,
    ) -> Result<(), ProcessStreamSinkError> {
        self.validate()?;
        let identity = request.command_identity()?;
        if identity.kind() != ProcessStreamSinkTerminalCommandKind::Abort
            || &identity != self.command_identity()
        {
            return Err(ProcessStreamSinkError::TerminalIdentityConflict);
        }
        Ok(())
    }

    pub fn identity_sha256(&self) -> &str {
        &self.terminal_sha256
    }
}

trait CommandRequest {
    fn command_identity(
        &self,
    ) -> Result<ProcessStreamSinkTerminalCommandIdentity, ProcessStreamSinkError>;
    fn expected_final_offset(&self) -> u64;
}

impl CommandRequest for ProcessStreamSinkFinalizeRequest {
    fn command_identity(
        &self,
    ) -> Result<ProcessStreamSinkTerminalCommandIdentity, ProcessStreamSinkError> {
        ProcessStreamSinkFinalizeRequest::command_identity(self)
    }

    fn expected_final_offset(&self) -> u64 {
        self.expected_final_offset()
    }
}

impl CommandRequest for ProcessStreamSinkAbortRequest {
    fn command_identity(
        &self,
    ) -> Result<ProcessStreamSinkTerminalCommandIdentity, ProcessStreamSinkError> {
        ProcessStreamSinkAbortRequest::command_identity(self)
    }

    fn expected_final_offset(&self) -> u64 {
        self.expected_final_offset()
    }
}
