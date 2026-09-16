//! The `handle` guest export over the accepted `dreamer-handler` shape.
//!
//! `dreamer-handler.wit` declares a `handle` function returning a
//! `result<handler-outcome, handler-error>` inside the exported `handler`
//! interface. Component binding generation (`wit-bindgen` plus
//! `wit-component`) for the #756 typed world is not available on this base,
//! so no raw canonical-ABI memory protocol is fabricated here.
//!
//! This module implements the canonical-byte transport of the typed
//! [`GuestRequest`](crate::conversion::GuestRequest) envelope under the same
//! export name, carrying either the native candidate set or the exhaustive
//! typed error. Undecodable or oversize input keeps the transport-level `Err`;
//! every decodable envelope returns `Ok` bytes with zero native calls on any
//! rejection instead of a trap.

use crate::conversion::{
    CallLedger, GuestResponse, decode_request, encode_response, handle_static_with_ledger,
};

/// Guest export `handle`: bytes in, bytes out, native never called.
///
/// Static composition only: preflight runs for real and the static registry
/// is proven closed, but without owner-published live ports every
/// dispatchable envelope returns the frozen missing-owner error with zero
/// native calls. The typed dispatch path with injected ports lives in
/// [`handle_with_ports`](crate::conversion::handle_with_ports).
pub fn handle(input: &[u8]) -> Result<Vec<u8>, String> {
    let ledger = CallLedger::new();
    handle_with_ledger(input, &ledger)
}

/// Guest export `handle` with an observable native-call ledger.
pub fn handle_with_ledger(input: &[u8], ledger: &CallLedger) -> Result<Vec<u8>, String> {
    let request = decode_request(input).map_err(|error| error.to_string())?;
    let response: GuestResponse = handle_static_with_ledger(&request, ledger);
    encode_response(&response).map_err(|error| error.to_string())
}

/// World-qualified name of this export; case 1 proves it equals
/// `{WORLD_NAME}#{EXPORT_NAME}` from the single-source constants.
#[must_use]
pub const fn qualified_export_name() -> &'static str {
    "dreamer-handler#handle"
}
