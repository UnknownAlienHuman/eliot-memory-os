//! Provider adapter for bounded .NET/MSBuild process invocations.
//!
//! The adapter validates a declared command and delegates every external
//! process to the shared `eliot-process` executor.  It deliberately has no
//! private spawn path, process-tree owner, finish authority, or filesystem
//! policy.

#![forbid(unsafe_code)]

use std::sync::Arc;

use eliot_instrument_api::{InstrumentInvocation, InstrumentKind};
use eliot_process::{
    CancellationReceipt, ProcessEvidence, ProcessEvidenceSink, ProcessExecutionError,
    ProcessExecutionView, ProcessExecutor, ProcessRequest, ProcessStartReceipt,
};
use thiserror::Error;

/// Stable contract identifier for this adapter.
pub const CONTRACT_ID: &str = "eliot.instrument.dotnet.msbuild";
/// Default executable used for SDK-style projects.
pub const DOTNET_EXECUTABLE: &str = "dotnet";
/// Default `MSBuild` profile passed to `dotnet`.
pub const DEFAULT_PROFILE: &str = "msbuild";

/// Configuration for bounded .NET/MSBuild command validation.
#[derive(Clone, Debug)]
pub struct DotnetMsbuildConfig {
    /// Executable name accepted for dotnet requests.
    pub dotnet_executable: String,
    /// Executable name accepted for direct `MSBuild` requests.
    pub msbuild_executable: String,
}

impl Default for DotnetMsbuildConfig {
    fn default() -> Self {
        Self {
            dotnet_executable: DOTNET_EXECUTABLE.to_owned(),
            msbuild_executable: "msbuild".to_owned(),
        }
    }
}

impl DotnetMsbuildConfig {
    /// Creates configuration and rejects blank executable identities.
    pub fn new(
        dotnet_executable: impl Into<String>,
        msbuild_executable: impl Into<String>,
    ) -> Result<Self, AdapterError> {
        let dotnet_executable = dotnet_executable.into();
        let msbuild_executable = msbuild_executable.into();
        if dotnet_executable.trim().is_empty() || msbuild_executable.trim().is_empty() {
            return Err(AdapterError::InvalidConfiguration(
                "tool executable must not be blank",
            ));
        }
        Ok(Self {
            dotnet_executable,
            msbuild_executable,
        })
    }
}

/// Exact declared .NET/MSBuild command shape.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DotnetMsbuildCommand {
    /// Executable selected by the admitted profile.
    pub executable: String,
    /// Exact argument vector, kept separate from shell syntax.
    pub arguments: Vec<String>,
    /// Isolated external build root.
    pub target: String,
}

impl DotnetMsbuildCommand {
    /// Builds a command for `dotnet msbuild` or direct `msbuild` execution.
    pub fn new(
        target: impl Into<String>,
        executable: impl Into<String>,
        arguments: &[String],
    ) -> Result<Self, AdapterError> {
        let target = checked_text(target.into(), "target")?;
        let executable = checked_text(executable.into(), "executable")?;
        let mut args = Vec::with_capacity(arguments.len());
        for argument in arguments {
            args.push(checked_text(argument.clone(), "argument")?);
        }
        Ok(Self {
            executable,
            arguments: args,
            target,
        })
    }

    /// Checks exact request identity without interpreting process output.
    pub fn matches_request(&self, request: &ProcessRequest) -> bool {
        request.executable().eq_ignore_ascii_case(&self.executable)
            && request.working_directory() == self.target
            && request.argv() == self.arguments
    }
}

/// Errors produced before or during adapter execution.
#[derive(Debug, Error)]
pub enum AdapterError {
    #[error("invalid dotnet adapter configuration: {0}")]
    InvalidConfiguration(&'static str),
    #[error("unsupported .NET/MSBuild invocation: {0}")]
    UnsupportedInvocation(String),
    #[error("dotnet process command does not match the declared profile")]
    CommandMismatch,
    #[error("process receipt does not bind to the admitted request")]
    ReceiptMismatch,
    #[error(transparent)]
    Process(#[from] ProcessExecutionError),
}

/// Shared-executor adapter for .NET/MSBuild.
pub struct DotnetMsbuildAdapter<E> {
    executor: Arc<E>,
    config: DotnetMsbuildConfig,
}

impl<E> DotnetMsbuildAdapter<E> {
    /// Creates an adapter around the active process executor.
    #[must_use]
    pub fn new(executor: Arc<E>) -> Self {
        Self::with_config(executor, DotnetMsbuildConfig::default())
    }

    /// Creates an adapter with explicit executable identities.
    #[must_use]
    pub fn with_config(executor: Arc<E>, config: DotnetMsbuildConfig) -> Self {
        Self { executor, config }
    }

    /// Validates the invocation class and executable policy.
    pub fn validate_invocation(
        &self,
        invocation: &InstrumentInvocation,
    ) -> Result<(), AdapterError> {
        invocation
            .validate()
            .map_err(|error| AdapterError::UnsupportedInvocation(error.to_string()))?;
        if !matches!(
            invocation.kind,
            InstrumentKind::Build
                | InstrumentKind::Test
                | InstrumentKind::Verify
                | InstrumentKind::Inspect
        ) {
            return Err(AdapterError::UnsupportedInvocation(
                "only build, test, verify, and inspect are supported".to_owned(),
            ));
        }
        if invocation.arguments.iter().any(|arg| arg.contains('\0')) {
            return Err(AdapterError::UnsupportedInvocation(
                "arguments may not contain NUL".to_owned(),
            ));
        }
        Ok(())
    }

    /// Launches one exact declared command through the shared executor.
    pub async fn launch(
        &self,
        invocation: &InstrumentInvocation,
        command: &DotnetMsbuildCommand,
        request: ProcessRequest,
        sink: Arc<dyn ProcessEvidenceSink>,
    ) -> Result<ProcessStartReceipt, AdapterError>
    where
        E: ProcessExecutor + 'static,
    {
        self.validate_invocation(invocation)?;
        let expected = if command.executable.eq_ignore_ascii_case("dotnet") {
            &self.config.dotnet_executable
        } else {
            &self.config.msbuild_executable
        };
        if !command.executable.eq_ignore_ascii_case(expected) || !command.matches_request(&request)
        {
            return Err(AdapterError::CommandMismatch);
        }
        let operation = request.operation_id().clone();
        let digest = request.invocation_digest().to_owned();
        let generation = request.generation();
        let receipt = self.executor.start(request, sink).await?;
        if receipt.operation_id() != &operation
            || receipt.request_digest() != digest
            || receipt.accepted_generation() != generation
        {
            return Err(AdapterError::ReceiptMismatch);
        }
        Ok(receipt)
    }

    /// Inspects an operation through the shared executor.
    pub async fn inspect(
        &self,
        operation: &eliot_process::OperationId,
    ) -> Result<ProcessExecutionView, AdapterError>
    where
        E: ProcessExecutor + 'static,
    {
        Ok(self.executor.inspect(operation.clone()).await?)
    }

    /// Cancels an operation through the shared executor.
    pub async fn cancel(
        &self,
        operation: &eliot_process::OperationId,
    ) -> Result<CancellationReceipt, AdapterError>
    where
        E: ProcessExecutor + 'static,
    {
        Ok(self.executor.cancel(operation.clone()).await?)
    }

    /// Reconciles an operation and returns observation-only evidence.
    pub async fn reconcile(
        &self,
        operation: &eliot_process::OperationId,
    ) -> Result<ProcessEvidence, AdapterError>
    where
        E: ProcessExecutor + 'static,
    {
        Ok(self.executor.reconcile(operation.clone()).await?)
    }
}

/// Compatibility spelling for callers that refer to the adapter as an executor.
pub type DotnetMsbuildExecutor<E> = DotnetMsbuildAdapter<E>;

fn checked_text(value: String, field: &'static str) -> Result<String, AdapterError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(AdapterError::UnsupportedInvocation(format!(
            "{field} must be non-blank and free of control characters"
        )));
    }
    Ok(value)
}
