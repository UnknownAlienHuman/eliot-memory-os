//! B-12's thin, provider-injected WASM component-host composition.
//!
//! A-12 owns component admission, generation/fence validation, limits, trap
//! classification, and the engine/process ports. P-11 owns bounded runtime
//! mechanics. This package only selects a compiled profile and composes those
//! two public surfaces; it does not mint authority, state, routes, or engine
//! implementations.

#![forbid(unsafe_code)]

use std::fmt;
#[cfg(test)]
use std::time::Duration;

#[cfg(test)]
use eliot_runtime::RuntimeConfig;
use eliot_runtime::{Runtime, ShutdownHandle, ShutdownOutcome};
use eliot_wasm_runtime::{
    InvocationId, InvocationRequest, InvocationResult, RuntimeError, RuntimePorts, WasmRuntime,
};

mod cli_contract;
mod wasmtime_provider;

pub use cli_contract::{CliConfig, CliError, Profile, Transport, parse_args};
pub use wasmtime_provider::{WasmtimeBuildError, WasmtimeComponentEngine};

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

    /// Binds the concrete Wasmtime provider to the existing authority ports.
    ///
    /// The supplied ports remain the owners of admission, generation, fencing,
    /// process authority, and promotion. This method only replaces the engine
    /// slot with the provider-specific adapter.
    pub fn with_wasmtime_engine(
        profile: Profile,
        runtime: Runtime,
        mut ports: RuntimePorts,
        engine: WasmtimeComponentEngine,
    ) -> Result<Self, RuntimeBuildError> {
        ports.engine = Box::new(engine);
        Self::new(profile, runtime, WasmRuntime::new(Some(ports)))
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
    #[cfg(not(all(
        feature = "eliot-profile-d2-operational",
        feature = "eliot-profile-full-composition"
    )))]
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
        let runner = WasmHostRunner::new(
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
        assert_eq!(runner.control_capacity(), 1);
        assert!(runner.request_shutdown());
        assert!(!runner.request_shutdown());
        assert!(runner.shutdown_handle().is_requested());
    }
}
