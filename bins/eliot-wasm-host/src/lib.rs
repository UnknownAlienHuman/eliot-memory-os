//! B-12's thin, provider-injected WASM component-host composition.
//!
//! A-12 owns component admission, generation/fence validation, limits, trap
//! classification, and the engine/process ports. P-11 owns bounded runtime
//! mechanics. This package only selects a compiled profile and composes those
//! two public surfaces; it does not mint authority, state, routes, or engine
//! implementations.

#![forbid(unsafe_code)]

use std::fmt;
use std::time::Duration;

use eliot_runtime::{Runtime, RuntimeConfig, ShutdownHandle, ShutdownOutcome};
use eliot_wasm_runtime::{
    InvocationId, InvocationRequest, InvocationResult, RuntimeError, WasmRuntime,
};

/// The canonical B-12 composition profiles.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Profile {
    /// D2's operational component-host composition.
    D2Operational,
    /// The complete admitted component composition.
    FullComposition,
}

impl Profile {
    /// Returns the canonical profile spelling used by the binary surface.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::D2Operational => "D2_OPERATIONAL",
            Self::FullComposition => "FULL_COMPOSITION",
        }
    }

    /// Returns whether this profile is compiled into the current binary.
    #[must_use]
    pub const fn is_compiled(self) -> bool {
        match self {
            Self::D2Operational => cfg!(feature = "eliot-profile-d2-operational"),
            Self::FullComposition => cfg!(feature = "eliot-profile-full-composition"),
        }
    }
}

impl fmt::Display for Profile {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// The local-only transports understood by the binary contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Transport {
    /// Length-delimited local standard input/output.
    Stdio,
    /// Local loopback, reserved for an injected transport owner.
    Loopback,
}

impl Transport {
    fn parse(value: &str) -> Result<Self, CliError> {
        match value {
            "stdio" => Ok(Self::Stdio),
            "loopback" => Ok(Self::Loopback),
            other => Err(CliError::RemoteTransportForbidden(other.to_owned())),
        }
    }
}

/// Fail-closed command-line parsing errors.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CliError {
    /// No profile was supplied.
    MissingProfile,
    /// The profile spelling is not canonical.
    UnsupportedProfile(String),
    /// An argument is malformed or unknown.
    MalformedArgument(String),
    /// A non-local transport was requested.
    RemoteTransportForbidden(String),
}

impl fmt::Display for CliError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingProfile => formatter.write_str("MISSING_PROFILE"),
            Self::UnsupportedProfile(profile) => write!(formatter, "UNSUPPORTED_PROFILE:{profile}"),
            Self::MalformedArgument(argument) => write!(formatter, "MALFORMED_ARGUMENT:{argument}"),
            Self::RemoteTransportForbidden(transport) => {
                write!(formatter, "REMOTE_TRANSPORT_FORBIDDEN:{transport}")
            }
        }
    }
}

impl std::error::Error for CliError {}

impl std::str::FromStr for Profile {
    type Err = CliError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "D2_OPERATIONAL" => Ok(Self::D2Operational),
            "FULL_COMPOSITION" => Ok(Self::FullComposition),
            other => Err(CliError::UnsupportedProfile(other.to_owned())),
        }
    }
}

/// Parsed profile and local transport selection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CliConfig {
    /// Selected profile.
    pub profile: Profile,
    /// Selected local transport.
    pub transport: Transport,
}

/// Parses B-12's profile and transport arguments without adding a CLI crate.
pub fn parse_args<I, S>(arguments: I) -> Result<CliConfig, CliError>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    let arguments: Vec<String> = arguments.into_iter().map(Into::into).collect();
    let mut profile = None;
    let mut transport = Transport::Stdio;
    let mut index = 0;
    while index < arguments.len() {
        match arguments[index].as_str() {
            "--profile" => {
                let value = arguments.get(index + 1).ok_or_else(|| {
                    CliError::MalformedArgument("--profile requires a value".to_owned())
                })?;
                profile = Some(value.parse()?);
                index += 2;
            }
            value if value.starts_with("--profile=") => {
                let value = value.trim_start_matches("--profile=");
                if value.is_empty() {
                    return Err(CliError::MalformedArgument(
                        "--profile= requires a value".to_owned(),
                    ));
                }
                profile = Some(value.parse()?);
                index += 1;
            }
            "--transport" => {
                let value = arguments.get(index + 1).ok_or_else(|| {
                    CliError::MalformedArgument("--transport requires a value".to_owned())
                })?;
                transport = Transport::parse(value)?;
                index += 2;
            }
            value if value.starts_with("--transport=") => {
                let value = value.trim_start_matches("--transport=");
                if value.is_empty() {
                    return Err(CliError::MalformedArgument(
                        "--transport= requires a value".to_owned(),
                    ));
                }
                transport = Transport::parse(value)?;
                index += 1;
            }
            value => return Err(CliError::MalformedArgument(value.to_owned())),
        }
    }
    Ok(CliConfig {
        profile: profile.ok_or(CliError::MissingProfile)?,
        transport,
    })
}

/// B-12's injected component-host runner.
pub struct WasmHostRunner {
    profile: Profile,
    runtime: Runtime,
    wasm_runtime: WasmRuntime,
}

impl WasmHostRunner {
    /// Composes an already-created P-11 runtime with an injected A-12 facade.
    ///
    /// The A-12 facade remains responsible for preserving the exact resolved
    /// manifest, WIT world, capability envelope, limits, generation, lease,
    /// and fence. B-12 does not inspect or recreate any of those bindings.
    ///
    /// # Errors
    ///
    /// Returns a typed plan gap when the requested profile is not compiled.
    pub fn new(
        profile: Profile,
        runtime: Runtime,
        wasm_runtime: WasmRuntime,
    ) -> Result<Self, RuntimeBuildError> {
        if !profile.is_compiled() {
            return Err(RuntimeBuildError::ProfileUnavailable(profile));
        }
        Ok(Self {
            profile,
            runtime,
            wasm_runtime,
        })
    }

    /// Alias emphasizing that both runtime surfaces are dependency-injected.
    pub fn from_surfaces(
        profile: Profile,
        runtime: Runtime,
        wasm_runtime: WasmRuntime,
    ) -> Result<Self, RuntimeBuildError> {
        Self::new(profile, runtime, wasm_runtime)
    }

    /// Builds the binary's typed-unavailable local composition.
    ///
    /// No concrete Wasmtime engine, route, kernel endpoint, process provider,
    /// manifest provider, or verifier is admitted by this default path.
    pub fn unavailable(profile: Profile) -> Result<Self, RuntimeBuildError> {
        let runtime = Runtime::new(
            RuntimeConfig {
                mailbox_capacity: 32,
                control_reserve: 4,
                concurrency: 1,
                control_concurrency_reserve: 1,
                fairness_quantum: 8,
                restart_budget: 0,
                restart_window: Duration::from_secs(60),
                restart_backoff: Duration::from_millis(50),
                shutdown_grace: Duration::from_secs(1),
            },
            None,
        )
        .map_err(RuntimeBuildError::Runtime)?;
        Self::new(profile, runtime, WasmRuntime::new(None))
    }

    /// Returns the selected profile.
    #[must_use]
    pub const fn profile(&self) -> Profile {
        self.profile
    }

    /// Returns P-11's available protected-control capacity.
    #[must_use]
    pub fn control_capacity(&self) -> usize {
        self.runtime
            .available_capacity(eliot_runtime::ExecutionClass::ProtectedControl)
    }

    /// Executes one inert caller request through the injected A-12 surface.
    ///
    /// A-12 returns the typed result, including generation, limit, fence,
    /// trap, unavailable, and unknown-outcome classifications.
    pub fn execute(&mut self, request: InvocationRequest) -> InvocationResult {
        self.wasm_runtime.execute(request)
    }

    /// Cancels an unknown A-12 invocation without changing its typed outcome.
    pub fn cancel(
        &mut self,
        invocation_id: &InvocationId,
        request_digest: &eliot_wasm_runtime::Sha256Digest,
    ) -> Result<InvocationResult, RuntimeError> {
        self.wasm_runtime.cancel(invocation_id, request_digest)
    }

    /// Reconciles an unknown A-12 invocation through its injected providers.
    pub fn reconcile(
        &mut self,
        invocation_id: &InvocationId,
        request_digest: &eliot_wasm_runtime::Sha256Digest,
    ) -> Result<InvocationResult, RuntimeError> {
        self.wasm_runtime.reconcile(invocation_id, request_digest)
    }

    /// Requests P-11 admission shutdown and returns whether this call won it.
    #[must_use]
    pub fn request_shutdown(&self) -> bool {
        self.runtime.shutdown_handle().request()
    }

    /// Returns a P-11 shutdown handle without creating another lifecycle.
    #[must_use]
    pub fn shutdown_handle(&self) -> ShutdownHandle {
        self.runtime.shutdown_handle()
    }

    /// Completes P-11 shutdown after the configured grace period.
    pub async fn shutdown(&self) -> ShutdownOutcome {
        self.runtime.shutdown().await
    }
}

/// Construction failures for the thin runner.
#[derive(Debug)]
pub enum RuntimeBuildError {
    /// The requested profile was not compiled into this binary.
    ProfileUnavailable(Profile),
    /// P-11 rejected the fixed binary runtime configuration.
    Runtime(eliot_runtime::ConfigError),
}

impl fmt::Display for RuntimeBuildError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ProfileUnavailable(profile) => {
                write!(formatter, "PLAN_GAP:PROFILE_UNAVAILABLE:{profile}")
            }
            Self::Runtime(error) => write!(formatter, "RUNTIME_CONFIG_INVALID:{error:?}"),
        }
    }
}

impl std::error::Error for RuntimeBuildError {}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use eliot_wasm_runtime::{
        ExecutionContour, InvocationDisposition, InvocationId, WorkScopeRef, WorkUnitId,
    };

    fn test_profile() -> Profile {
        if Profile::D2Operational.is_compiled() {
            Profile::D2Operational
        } else {
            Profile::FullComposition
        }
    }

    fn request(cancellation_requested: bool) -> InvocationRequest {
        InvocationRequest::new(
            InvocationId::new("fixture-invocation").expect("invocation"),
            eliot_wasm_runtime::CapabilityId::new("fixture-component").expect("component"),
            WorkUnitId::new("fixture-work-unit").expect("work unit"),
            WorkScopeRef::new("fixture-scope").expect("scope"),
            ExecutionContour::Shadow,
            Vec::new(),
            7,
            cancellation_requested,
        )
        .expect("request")
    }

    #[test]
    fn canonical_profiles_bind_to_each_feature() {
        assert_eq!(
            Profile::D2Operational.is_compiled(),
            cfg!(feature = "eliot-profile-d2-operational")
        );
        assert_eq!(
            Profile::FullComposition.is_compiled(),
            cfg!(feature = "eliot-profile-full-composition")
        );
        assert!(test_profile().is_compiled());
        assert_eq!("FULL_COMPOSITION".parse(), Ok(Profile::FullComposition));
    }

    #[test]
    fn malformed_and_remote_inputs_fail_closed() {
        assert_eq!(parse_args::<_, &str>([]), Err(CliError::MissingProfile));
        assert!(matches!(
            parse_args([
                "--profile",
                "D2_OPERATIONAL",
                "--transport",
                "tcp://127.0.0.1"
            ]),
            Err(CliError::RemoteTransportForbidden(_))
        ));
        assert!(matches!(
            parse_args(["--profile", "D2_OPERATIONAL", "--profile"]),
            Err(CliError::MalformedArgument(_))
        ));
    }

    #[test]
    fn unavailable_default_is_a_typed_plan_gap() {
        let mut runner = WasmHostRunner::unavailable(test_profile()).expect("runner");
        let result = runner.execute(request(false));
        assert_eq!(
            result.receipt.disposition,
            InvocationDisposition::Unavailable
        );
        assert_eq!(result.receipt.error, Some(RuntimeError::PlanGap));
    }

    #[test]
    fn injected_a12_surface_preserves_typed_cancellation() {
        let mut runner = WasmHostRunner::new(
            test_profile(),
            Runtime::new(
                RuntimeConfig {
                    mailbox_capacity: 4,
                    control_reserve: 1,
                    concurrency: 1,
                    control_concurrency_reserve: 1,
                    fairness_quantum: 1,
                    restart_budget: 0,
                    restart_window: Duration::from_secs(1),
                    restart_backoff: Duration::from_millis(1),
                    shutdown_grace: Duration::from_millis(1),
                },
                None,
            )
            .expect("runtime"),
            WasmRuntime::new(None),
        )
        .expect("runner");
        let result = runner.execute(request(true));
        assert_eq!(result.receipt.disposition, InvocationDisposition::Rejected);
        assert_eq!(result.receipt.error, Some(RuntimeError::Cancelled));
    }

    #[test]
    fn absent_profile_is_rejected_before_surface_use() {
        let opposite = if test_profile() == Profile::D2Operational {
            Profile::FullComposition
        } else {
            Profile::D2Operational
        };
        let runtime = Runtime::new(
            RuntimeConfig {
                mailbox_capacity: 4,
                control_reserve: 1,
                concurrency: 1,
                control_concurrency_reserve: 1,
                fairness_quantum: 1,
                restart_budget: 0,
                restart_window: Duration::from_secs(1),
                restart_backoff: Duration::from_millis(1),
                shutdown_grace: Duration::from_millis(1),
            },
            None,
        )
        .expect("runtime");
        match WasmHostRunner::new(opposite, runtime, WasmRuntime::new(None)) {
            Err(RuntimeBuildError::ProfileUnavailable(profile)) => assert_eq!(profile, opposite),
            Err(RuntimeBuildError::Runtime(error)) => {
                panic!("wrong construction error: {error:?}")
            }
            Ok(_) => panic!("uncompiled profile was accepted"),
        }
    }

    #[test]
    fn shutdown_is_only_forwarded_to_p11() {
        let runner = WasmHostRunner::unavailable(test_profile()).expect("runner");
        assert_eq!(runner.control_capacity(), 1);
        assert!(runner.request_shutdown());
        assert!(!runner.request_shutdown());
        assert!(runner.shutdown_handle().is_requested());
    }
}
