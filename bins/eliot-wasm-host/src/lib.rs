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
    ComponentEnginePort, InvocationId, InvocationRequest, InvocationResult, RuntimeError,
    RuntimePorts, WasmRuntime,
};

mod admission;
mod artifact_preflight;
mod child_engine;
mod cli_contract;
mod contour;
mod governed_admission;
mod guest_exec;
mod installed_binary;
mod shadow;
mod typed_bindings;
mod typed_execution;
mod wasmtime_provider;

pub use admission::{PortGrantError, resolve_kernel_port_grant};
pub use artifact_preflight::{
    MAX_ARTIFACT_BYTES, Preflight, PreflightError, preflight_bytes, read_bounded_artifact,
};
pub use child_engine::{ISOLATED_CHILD_IMPLEMENTATION_ID, IsolatedChildEngine};
pub use cli_contract::{CliConfig, CliError, GuestExecArgs, Profile, Transport, parse_args};
pub use contour::{
    AdmittedGeneration, AdmittedPrototype, AuthorizedHostCall, Contour, ContourGateError,
    FS_CAPABILITY, GenerationManifest, GovernorGrant, HostCallProposal, NET_CAPABILITY,
    PINNED_WASMTIME_VERSION, PrototypeContourDecision, SELF_CONTAINED_GUEST_TARGET,
    STANDARD_GUEST_TARGET, admit_generation, admit_generation_with_bytes, admit_prototype,
    authorize_host_call, check_activation_imports, check_admitted_request,
};
pub use guest_exec::{
    ChildMetering, EXIT_COMPLETED, EXIT_DENIED, EXIT_ENGINE_FAILED, EXIT_NOT_COMPLETED,
    GuestExecRejection, GuestExecRequest, metering_line, parse_metering_line, run_guest_exec,
    validate_request,
};
pub use governed_admission::{
    HostAdmitError, admit_governed_host, check_governed_host_output,
};
pub use installed_binary::{
    InstalledBinary, InstalledBinaryError, WasmHostBinaryBinding, resolve_installed_binary,
};
pub use shadow::{ShadowError, enforce_shadow_no_effect, shadow_port_error};
pub use typed_bindings::{
    LEGACY_EXPORT, LEGACY_WORLD, TYPED_PACKAGE_ID, TYPED_WIT_VERSION, TypedWorld,
    export_matches_interface, typed_wit_digest,
};
pub use typed_execution::{
    ExecutionMode, TypedDescriptor, TypedExecutionError, TypedReceipt, default_experimental_limits,
    domain_handoff, execute_describe_experimental, execute_governed_refusal,
};
pub use wasmtime_provider::{
    WasmtimeBuildError, WasmtimeComponentEngine, provider_configuration_digest,
};

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

    /// Binds the concrete engine provider to the existing authority ports.
    ///
    /// The supplied ports remain the owners of admission, generation, fencing,
    /// process authority, and promotion. This method only replaces the engine
    /// slot with the provider-specific adapter: either the in-process
    /// Wasmtime provider or the isolated-child engine (never both — pairing
    /// them would execute the guest twice).
    pub fn with_wasmtime_engine(
        profile: Profile,
        runtime: Runtime,
        mut ports: RuntimePorts,
        engine: Box<dyn ComponentEnginePort>,
    ) -> Result<Self, RuntimeBuildError> {
        ports.engine = engine;
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

    /// Executes one caller request through the injected A-12 surface.
    ///
    /// A-12 returns the typed result, including generation, limit, fence,
    /// trap, unavailable, and unknown-outcome classifications.
    pub fn execute(&mut self, request: InvocationRequest) -> InvocationResult {
        self.wasm_runtime.execute(request)
    }

    /// Executes one request under a bound contour admission.
    ///
    /// The host gate matches the caller request against the bound admission
    /// — contour, component identity, and input envelope — before touching
    /// A-12, so work admitted for another component, another contour, or a
    /// larger input envelope can never reach Wasmtime here. Artifact and
    /// interface digests were byte-verified at admission and are enforced
    /// again at invoke by the engine and Governor coherence; fence/epoch
    /// freshness stays with Governor/Kernel authority inside the execution
    /// path. An admitted WASM generation delegates to the injected A-12
    /// surface verbatim and returns exactly its verdict — this method adds
    /// routing, never semantics.
    pub fn execute_admitted(
        &mut self,
        admitted: &AdmittedGeneration,
        request: InvocationRequest,
    ) -> Result<InvocationResult, ContourGateError> {
        check_admitted_request(admitted, &request)?;
        Ok(self.wasm_runtime.execute(request))
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

    fn admitted_manifest() -> GenerationManifest {
        use eliot_wasm_runtime::{ArtifactAccessLimits, CancellationPolicy, EpochPolicy};
        use std::collections::BTreeSet;

        GenerationManifest {
            component_id: "fixture-component".to_owned(),
            target: STANDARD_GUEST_TARGET.to_owned(),
            artifact_digest: eliot_wasm_runtime::Sha256Digest::of_bytes(b"caller-fixture"),
            wit_digest: eliot_wasm_runtime::Sha256Digest::of_bytes(b"caller-wit"),
            world: "context-admission".to_owned(),
            allowed_imports: Vec::new(),
            allowed_exports: vec!["admission".to_owned()],
            capability_grants: Vec::new(),
            limits: eliot_wasm_runtime::InvocationLimits {
                max_input_bytes: 64,
                max_output_bytes: 1024,
                max_host_calls: 2,
                max_fuel: 10_000,
                max_memory_bytes: 65_536,
                max_table_elements: 8,
                max_instances: 1,
                max_stack_bytes: 8 * 1024,
                wall_deadline_ms: 500,
                epoch: EpochPolicy {
                    deadline_ticks: 100,
                    cancellation: CancellationPolicy::EpochAndFuel,
                },
                artifact_access: ArtifactAccessLimits {
                    allowed_digests: BTreeSet::new(),
                    max_reads: 1,
                    max_bytes: 8 * 1024 * 1024,
                },
            },
            state_class: "stateless".to_owned(),
            migration_contract: "none".to_owned(),
            privacy_policy: "project_code".to_owned(),
            comparator: "shadow-exact".to_owned(),
            rollback_generation: Some("gen-41".to_owned()),
        }
    }

    fn test_runner() -> WasmHostRunner {
        WasmHostRunner::new(
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
        .expect("runner")
    }

    #[test]
    fn admitted_wasm_generation_delegates_verbatim_to_a12() {
        let decision = PrototypeContourDecision::default();
        let admitted = admit_generation(Some(&decision), &admitted_manifest(), &[])
            .expect("admitted generation");
        let mut admitted_runner = test_runner();
        let mut direct_runner = test_runner();
        // The admitted call returns exactly the injected A-12 verdict: the
        // wrapper adds routing, never semantics.
        assert_eq!(
            admitted_runner.execute_admitted(&admitted, request(false)),
            Ok(direct_runner.execute(request(false)))
        );
    }

    #[test]
    fn non_wasm_admission_is_refused_before_a12() {
        let native = PrototypeContourDecision::select_native_process("needs raw USB scan")
            .expect("native decision");
        let admitted =
            admit_generation(Some(&native), &admitted_manifest(), &[]).expect("native admission");
        let mut runner = test_runner();
        assert_eq!(
            runner.execute_admitted(&admitted, request(false)),
            Err(ContourGateError::ContourNotServedHere(
                "ISOLATED_NATIVE_PROCESS".to_owned()
            ))
        );
        assert_eq!(
            ContourGateError::ContourNotServedHere("ISOLATED_NATIVE_PROCESS".to_owned())
                .to_string(),
            "CONTOUR_NOT_SERVED_HERE:ISOLATED_NATIVE_PROCESS"
        );
    }

    #[test]
    fn foreign_component_is_denied_without_touching_a12() {
        // No ports are bound (`WasmRuntime::new(None)`): denial must come
        // from the host gate alone, before any A-12 contact is possible.
        let decision = PrototypeContourDecision::default();
        let mut foreign_manifest = admitted_manifest();
        foreign_manifest.component_id = "other-component".to_owned();
        let admitted =
            admit_generation(Some(&decision), &foreign_manifest, &[]).expect("foreign admission");
        let mut runner = test_runner();
        assert_eq!(
            runner.execute_admitted(&admitted, request(false)),
            Err(ContourGateError::ComponentNotAdmitted(
                "fixture-component".to_owned()
            ))
        );
        assert_eq!(
            ContourGateError::ComponentNotAdmitted("fixture-component".to_owned()).to_string(),
            "COMPONENT_NOT_ADMITTED:fixture-component"
        );
    }

    #[test]
    fn oversized_input_is_denied_without_touching_a12() {
        let decision = PrototypeContourDecision::default();
        let admitted =
            admit_generation(Some(&decision), &admitted_manifest(), &[]).expect("admission");
        let mut runner = test_runner();
        let oversized = InvocationRequest::new(
            InvocationId::new("fixture-oversized").expect("invocation"),
            eliot_wasm_runtime::CapabilityId::new("fixture-component").expect("component"),
            WorkUnitId::new("fixture-work-unit").expect("work unit"),
            WorkScopeRef::new("fixture-scope").expect("scope"),
            ExecutionContour::Shadow,
            vec![0u8; 65],
            7,
            false,
        )
        .expect("request");
        assert_eq!(
            runner.execute_admitted(&admitted, oversized),
            Err(ContourGateError::InputLimitExceeded(
                "input-bytes".to_owned()
            ))
        );
    }
}
