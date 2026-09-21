//! B-12's admitted-port grant gate.
//!
//! The component host performs a governed call only through a complete
//! Kernel/Governor-admitted [`RuntimePorts`] grant. No authenticated Kernel
//! admission channel is bound into this binary yet: production
//! Governor/Authority/source/promotion/P-03 providers do not exist (only the
//! Wasmtime engine provider and neutral-crate test mocks do), and no
//! transport delivers an admitted grant to this process. This module is the
//! single seam where that transport plugs in. Until then every resolution
//! fails closed with [`PortGrantError`]: the host constructs no engine,
//! admits no invocation, and performs no component call. A grant is never
//! fabricated from ambient caller input.
//!
//! Required grant hook (Ramu lane — Kernel `daemon_request_dispatch` owner):
//! the legitimate grant arrives as an authenticated Kernel-issued
//! [`RuntimePorts`] bundle (Governor + Authority + source + promotion +
//! P-03 + verifier ports, engine slot filled by this host's
//! `with_wasmtime_engine`). Nearest in-tree anchors for the handshake
//! shape (different domain — Kernel service lifecycle, NOT a ports grant):
//! `KernelComposition::execute_daemon_request`
//! (`bins/eliot-kernel/src/daemon_request_dispatch.rs`), and the host
//! admission receipt family
//! (`crates/kernel/eliot-kernel-service/src/lifecycle.rs`,
//! `reconcile_host_request_admission` /
//! `reconcile_native_worker_claim_admission`). No callable hook yielding a
//! `RuntimePorts` grant exists in-tree as of this write: `execute_daemon_request`
//! serves async session-bound lifecycle frames, and the lifecycle
//! reconciliation functions prove receipt/envelope binding without issuing
//! ports. Calling either as a grant source would misappropriate another
//! domain's authority, so this gate keeps returning `NoAdmissionChannel`
//! (→ `Unavailable`/`PlanGap` downstream; `UnknownOutcome` preserved where
//! the runtime already reports it) until Ramu's lane delivers the real
//! call. The required call, when it lands, is exactly:
//! `resolve_kernel_port_grant()` → Ramu's
//! `fn (authenticated_kernel_channel) -> Result<RuntimePorts, GrantError>`
//! with the error mapped to [`PortGrantError`]; nothing else in this
//! binary changes shape.

use std::fmt;

use eliot_wasm_runtime::RuntimePorts;

/// Fail-closed denial when no admitted port grant is bound.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PortGrantError {
    /// No authenticated Kernel admission channel is bound into this process,
    /// so no `RuntimePorts` grant exists and no component call may occur.
    NoAdmissionChannel,
}

impl fmt::Display for PortGrantError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoAdmissionChannel => formatter.write_str(
                "PLAN_GAP:KERNEL_ADMISSION_REQUIRED:no Kernel-admitted RuntimePorts grant is bound",
            ),
        }
    }
}

impl std::error::Error for PortGrantError {}

/// Resolves the Kernel-admitted port grant for this process.
///
/// Always fails closed until an authenticated Kernel admission transport is
/// bound here. The transport plugs in by returning the exact admitted
/// `RuntimePorts`; this function never assembles ports from CLI text,
/// environment, files, or any other ambient caller input.
pub fn resolve_kernel_port_grant() -> Result<RuntimePorts, PortGrantError> {
    Err(PortGrantError::NoAdmissionChannel)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use std::time::Duration;

    use eliot_runtime::{Runtime, RuntimeConfig};
    use eliot_wasm_runtime::{
        CapabilityId, ExecutionContour, InvocationDisposition, InvocationId, InvocationRequest,
        RuntimeError, WasmRuntime, WorkScopeRef, WorkUnitId,
    };

    use super::*;
    use crate::{Profile, WasmHostRunner};

    fn test_profile() -> Profile {
        if Profile::D2Operational.is_compiled() {
            Profile::D2Operational
        } else {
            Profile::FullComposition
        }
    }

    fn test_runtime() -> Runtime {
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
        .expect("runtime")
    }

    fn live_request() -> InvocationRequest {
        InvocationRequest::new(
            InvocationId::new("fixture-live-invocation").expect("invocation"),
            CapabilityId::new("fixture-component").expect("component"),
            WorkUnitId::new("fixture-work-unit").expect("work unit"),
            WorkScopeRef::new("fixture-scope").expect("scope"),
            ExecutionContour::Shadow,
            Vec::new(),
            7,
            false,
        )
        .expect("request")
    }

    #[test]
    fn unbound_admission_channel_fails_closed() {
        assert!(matches!(
            resolve_kernel_port_grant(),
            Err(PortGrantError::NoAdmissionChannel)
        ));
        assert!(
            PortGrantError::NoAdmissionChannel
                .to_string()
                .starts_with("PLAN_GAP:KERNEL_ADMISSION_REQUIRED")
        );
    }

    #[test]
    fn runner_without_port_grant_performs_no_component_call() {
        let mut runner =
            WasmHostRunner::new(test_profile(), test_runtime(), WasmRuntime::new(None))
                .expect("runner");
        let result = runner.execute(live_request());
        assert_eq!(
            result.receipt.disposition,
            InvocationDisposition::Unavailable
        );
        assert_eq!(result.receipt.error, Some(RuntimeError::PlanGap));
    }
}
