//! The `screen` guest export over the readable `memory-curation-screen` shape.
//!
//! `memory-curation-screen.wit` declares `screen: func(request:
//! screen-request) -> result<screen-outcome, screen-error>` inside the
//! exported `screen` interface. Component binding generation (`wit-bindgen`
//! plus `wit-component`) for the #756 typed world is not available on this
//! base, so no raw canonical-ABI memory protocol is fabricated here.
//!
//! This module implements the canonical-byte transport of the typed
//! [`GuestRequest`](crate::conversion::GuestRequest) envelope under the same
//! export name, carrying either the native `CurationScreenResult` or the
//! exhaustive typed error. Undecodable or oversize input keeps the
//! transport-level `Err`; every decodable envelope returns `Ok` bytes with
//! zero native calls on any rejection instead of a trap.

use crate::conversion::{
    CallLedger, GuestResponse, decode_request, encode_response, handle_with_ledger,
};

/// Guest export `screen`: bytes in, bytes out, native called at most once.
pub fn screen(input: &[u8]) -> Result<Vec<u8>, String> {
    let ledger = CallLedger::new();
    screen_with_ledger(input, &ledger)
}

/// Guest export `screen` with an observable native-call ledger.
pub fn screen_with_ledger(input: &[u8], ledger: &CallLedger) -> Result<Vec<u8>, String> {
    let request = decode_request(input).map_err(|error| error.to_string())?;
    let response: GuestResponse = handle_with_ledger(&request, ledger);
    encode_response(&response).map_err(|error| error.to_string())
}

/// World-qualified name of this export; case 1 proves it equals
/// `{WORLD_NAME}#{EXPORT_NAME}` from the single-source constants.
#[must_use]
pub const fn qualified_export_name() -> &'static str {
    "memory-curation-screen#screen"
}
