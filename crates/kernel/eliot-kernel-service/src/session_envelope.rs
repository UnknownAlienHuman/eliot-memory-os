//! Kernel-owner runtime session-envelope facts (issue #1942, lane O1).
//!
//! Owner: the in-process Kernel service owner ([`KernelService`] in
//! `lifecycle.rs`) holds the accepted Host candidate binding
//! ([`KernelService::candidate_binding`]) and the consumed activation receipt
//! ([`KernelService::activation_receipt`]). Every field below traces to a
//! read of that live owner state; no caller-supplied value is accepted.
//!
//! Live reads:
//!
//! - `snapshot.runtime_generation`: the approved runtime generation consumed
//!   by the Kernel, read from the live activation receipt
//!   (`KernelActivationReceipt::generation` in `protocol.rs`). Fails closed
//!   with [`RuntimeEnvelopeError::NotActivated`] while no activation has been
//!   consumed.
//!
//! Absence: the kernel candidate vocabulary (`HostKernelCandidateBinding` in
//! `protocol.rs`: installation, host/kernel epochs, activation identity,
//! artifact/config hashes, job/pipe/process/job bindings, supervision
//! incarnation, restart budget) carries no runtime identity string, so
//! `snapshot.runtime_id` has no live source and [`produce_runtime_id`]
//! fails closed naming it.
//!
//! Non-conflation note: the activation receipt's `operation_id` is a
//! `PlatformHandle` scoped to the Host-owned activation operation. It is a
//! different identity domain from the reactive delivery record's
//! `record.operation_id` (`eliot_contracts::OperationId`, per delivered
//! content operation) and must never be presented as that fact.
//!
//! Consumer: `resolve_runtime_envelope` in
//! `bins/eliot-agent-bridge/src/reactive_owner_publication.rs` (D2 lane,
//! read-only reference) names the missing `snapshot.runtime_id` and
//! `snapshot.runtime_generation` facts.

use eliot_contracts::ResourceGeneration;
use thiserror::Error;

use crate::lifecycle::KernelService;

/// Live Kernel runtime-generation fact for the session envelope.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RuntimeEnvelopeFacts {
    /// Approved runtime generation consumed by the Kernel.
    pub runtime_generation: ResourceGeneration,
}

/// Fail-closed Kernel runtime-envelope errors. Each names the exact D2 fact
/// that cannot be resolved from live owner state.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum RuntimeEnvelopeError {
    /// The kernel candidate vocabulary carries no runtime identity string,
    /// so `snapshot.runtime_id` has no live source. The candidate binding
    /// holds installation, epochs, activation identity, artifact/config
    /// hashes, and process/job bindings — never a runtime identity.
    #[error("kernel owner holds no runtime identity for snapshot.runtime_id")]
    RuntimeIdNotOwned,
    /// No activation has been consumed yet, so the activation receipt (and
    /// with it the approved runtime generation) is absent.
    #[error("kernel activation receipt absent for snapshot.runtime_generation")]
    NotActivated,
}

/// Attempt to produce the runtime identity for the session envelope.
///
/// Always fails closed: the Kernel owner holds no runtime identity in live
/// state (see [`RuntimeEnvelopeError::RuntimeIdNotOwned`]). The owner borrow
/// is threaded to prove the read was attempted against live state rather
/// than skipped.
pub fn produce_runtime_id(service: &KernelService) -> Result<String, RuntimeEnvelopeError> {
    let _ = service.candidate_binding();
    Err(RuntimeEnvelopeError::RuntimeIdNotOwned)
}

/// Produce the approved runtime generation consumed by the Kernel.
///
/// Reads the live activation receipt ([`KernelService::activation_receipt`],
/// `KernelActivationReceipt::generation` in `protocol.rs`).
pub fn produce_runtime_generation(
    service: &KernelService,
) -> Result<RuntimeEnvelopeFacts, RuntimeEnvelopeError> {
    let receipt = service
        .activation_receipt()
        .ok_or(RuntimeEnvelopeError::NotActivated)?;
    Ok(RuntimeEnvelopeFacts {
        runtime_generation: receipt.generation,
    })
}
