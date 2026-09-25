//! The `run` guest export over the accepted `guest.wit` byte shape.
//!
//! `guest.wit` declares `export run: func(input: list<u8>) -> result<list<u8>,
//! string>`. This module implements exactly that signature in Rust types:
//! canonical [`GuestRequest`](crate::conversion::GuestRequest) bytes in,
//! canonical [`GuestResponse`](crate::conversion::GuestResponse) bytes out.
//! Undecodable or oversize input keeps the transport-level `Err`; every
//! decodable envelope returns `Ok` bytes carrying either the native result
//! (complete or first-class incomplete) or the exhaustive typed error, so
//! rejected calls still report zero native calls instead of a trap.
//!
//! Component binding generation (`wit-bindgen` + `wit-component`) for the
//! accepted #756 typed world is not available on this base; no raw
//! canonical-ABI memory protocol is fabricated here. The typed
//! `context-admission` `admit`/`describe` operations are bound through the
//! descriptor digest and the exhaustive typed conversion, not a second ABI.

#[cfg(not(target_arch = "wasm32"))]
use eliot_governor::{Governor, LearningAdmissionPermit};

use crate::conversion::{
    CallLedger, GuestResponse, decode_request, encode_response, handle_with_ledger,
};

/// Guest export `run`: bytes in, bytes out, native called at most once.
pub fn run(input: &[u8]) -> Result<Vec<u8>, String> {
    let ledger = CallLedger::new();
    run_with_ledger(input, &ledger)
}

/// Guest export `run` with an observable native-call ledger.
pub fn run_with_ledger(input: &[u8], ledger: &CallLedger) -> Result<Vec<u8>, String> {
    let request = decode_request(input).map_err(|error| error.to_string())?;
    let response: GuestResponse = handle_with_ledger(&request, ledger);
    encode_response(&response).map_err(|error| error.to_string())
}

/// Host-governed guest export `run`: bytes in, bytes out, governed delivery.
///
/// Host-only (`not(wasm32)`): the guest contour cannot owner-verify issuance,
/// liveness, or expiry, so learning-marked invocations — requests carrying
/// learning tickets, overlay subjects, or candidate-derived behavior — must
/// enter through this entrypoint instead of the plain [`run_with_ledger`]
/// path (which refuses them with `LearningRequiresGovernedPath` before the
/// native gate runs).
///
/// The decoded request is routed through
/// [`compile_learning_context`](crate::host::compile_learning_context) with
/// the caller-supplied live [`Governor`] owner, owner-issued admission
/// permit, and owner-sourced clock (`now_unix_secs` must be host time, never
/// a requester-envelope value): campaign identity, the exact State Fence,
/// the live owner epoch/generation rebind, and the per-mark screen (cited
/// issuance, overlay/candidate subject binding, mark expiry, draft state,
/// reusable closure/owner status) are all verified before the native
/// invocation runs. Any violation is refused with `native_calls == 0`, so
/// expired marks, unclosed or ownerless reusables, and foreign-task/fence
/// compilations are refused at delivery.
///
/// Unmarked compilations bound by the same permit decide exactly as through
/// the plain path once the permit binding checks pass; compilations without
/// an owner permit must use [`run`] / [`run_with_ledger`].
///
/// Registry-backed carriage (overlay-record liveness, ACTIVE backlog
/// backing, distinct cross-task admission receipts) is enforced by the
/// composed [`compose_governed_compilation`](crate::governed_compose::compose_governed_compilation)
/// path, whose production backlog, overlay, and cross-task handles are owned
/// by the host composition root — not by this byte transport — so that path
/// is entered there with live handles, not here.
#[cfg(not(target_arch = "wasm32"))]
pub fn run_governed(
    input: &[u8],
    governor: &Governor,
    permit: &LearningAdmissionPermit,
    now_unix_secs: u64,
) -> Result<Vec<u8>, String> {
    let request = decode_request(input).map_err(|error| error.to_string())?;
    let response: GuestResponse =
        crate::host::compile_learning_context(governor, permit, &request, now_unix_secs);
    encode_response(&response).map_err(|error| error.to_string())
}

/// World-qualified name of the byte-transport export; case 1 proves the typed
/// world/interface constants separately against the accepted WIT.
#[must_use]
pub const fn qualified_export_name() -> &'static str {
    "guest#run"
}
