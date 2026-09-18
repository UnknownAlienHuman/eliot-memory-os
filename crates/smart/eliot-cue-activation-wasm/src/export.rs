//! The `activate` guest export over the accepted `cue-activation` shape.
//!
//! `cue-activation.wit` declares `activate: func(request: activation-request)
//! -> result<activation-outcome, activation-error>` inside the exported
//! `activation` interface. This module implements exactly that signature in
//! Rust types: canonical [`GuestRequest`](crate::conversion::GuestRequest)
//! bytes in, canonical [`GuestResponse`](crate::conversion::GuestResponse)
//! bytes out. Undecodable or oversize input keeps the transport-level `Err`;
//! every decodable envelope returns `Ok` bytes carrying either the native
//! evaluation or the exhaustive typed error, so rejected calls still report
//! zero native calls instead of a trap.
//!
//! Component binding generation (`wit-bindgen` + `wit-component`) for the
//! #756 typed world is not available on this base; no raw canonical-ABI
//! memory protocol is fabricated here. The WIT `describe` export needs no
//! transport: it is pure metadata already compiled into
//! [`descriptor`](crate::descriptor::descriptor) with zero native calls.

use crate::conversion::{
    CallLedger, GuestResponse, decode_request, encode_response, handle_with_ledger,
};

/// Guest export `activate`: bytes in, bytes out, native called at most once.
pub fn activate(input: &[u8]) -> Result<Vec<u8>, String> {
    let ledger = CallLedger::new();
    activate_with_ledger(input, &ledger)
}

/// Guest export `activate` with an observable native-call ledger.
pub fn activate_with_ledger(input: &[u8], ledger: &CallLedger) -> Result<Vec<u8>, String> {
    let request = decode_request(input).map_err(|error| error.to_string())?;
    let response: GuestResponse = handle_with_ledger(&request, ledger);
    encode_response(&response).map_err(|error| error.to_string())
}

/// World-qualified name of this export; case 1 proves it equals
/// `{WORLD_NAME}#{EXPORT_NAME}` from the single-source constants.
#[must_use]
pub const fn qualified_export_name() -> &'static str {
    "cue-activation#activate"
}
