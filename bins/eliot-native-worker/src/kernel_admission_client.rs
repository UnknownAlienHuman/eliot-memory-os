//! Kernel admission client transport for native-worker startup claim.
//!
//! Architecture: Kernel is the governing admission authority per
//! `ELIOT_ARCHITECTURE.md` 4.5-draft (A0.3, A2.2, A12.2, A12.3, A13.2;
//! ARCH-AUTH-01, ARCH-SEC-01, ARCH-SEC-02). Native-worker is a thin composition
//! boundary that must not assume or synthesize admission/authority.
//!
//! Implementation: Uses `eliot-cli::kernel_client::KernelClient` health probe and
//! `native_worker.claim` transact probe per `ELIOT_IMPLEMENTATION.md` 0.29-draft
//! (I1.2, I7.3, I7.5, I15.2, P.3, I2.2, I2.23) and `bins/eliot-native-worker` crate
//! boundary. Fails closed until Kernel supplies a session-bound claim and preserves
//! exact transport error mapping and handshake strings.
//!
//! Responsibility: Kernel admission client transport only — health handshake,
//! claim probe, and typed `KernelAdmissionRequired` error mapping for startup.
//!
//! Forbidden: No Kernel semantic or admission authority, no native process
//! lifecycle/supervision, no Store/canonical writer, no Dreamer/research/curation,
//! no route/provider selection, no default/retry/adoption/mint and no fabrication
//! of process requests or permits.

use eliot_cli::kernel_client::{KernelClient, KernelClientError};

use super::NativeWorkerError;

/// Authenticated Kernel front-door adapter for the worker's startup claim.
///
/// The current Kernel client exposes health and generic execute transport, but
/// not the session-bound native-worker claim carrying identity, fence, clock,
/// and one-shot process request.  This adapter therefore never fabricates a
/// request or permit: it probes the operation and fails closed until that
/// contract is supplied by Kernel.
pub struct KernelNativeWorkerClient;

impl KernelNativeWorkerClient {
    pub fn connect() -> Result<Self, NativeWorkerError> {
        let mut client = KernelClient::load().map_err(|error| kernel_admission_error(&error))?;
        let health = client
            .probe()
            .map_err(|error| kernel_admission_error(&error))?;
        if health.get("status").and_then(serde_json::Value::as_str) != Some("OPEN") {
            return Err(NativeWorkerError::KernelAdmissionRequired(
                "Kernel health handshake was not OPEN".to_owned(),
            ));
        }
        let _claim = client
            .transact_json(
                "native_worker.claim",
                serde_json::json!({
                    "protocol": eliot_native_worker_core::PROTOCOL_VERSION,
                    "operation": "claim"
                }),
            )
            .map_err(|error| kernel_admission_error(&error))?;
        Err(NativeWorkerError::KernelAdmissionRequired(
            "Kernel returned no session-bound native-worker claim contract".to_owned(),
        ))
    }
}

pub(super) fn kernel_admission_error(error: &KernelClientError) -> NativeWorkerError {
    NativeWorkerError::KernelAdmissionRequired(error.to_string())
}
