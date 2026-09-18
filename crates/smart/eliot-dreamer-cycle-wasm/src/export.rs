//! The `run` guest export over the accepted `guest.wit` shape.
//!
//! `guest.wit` declares `export run: func(input: list<u8>) -> result<list<u8>,
//! string>`. This module implements exactly that signature in Rust types:
//! canonical [`GuestRequest`](crate::conversion::GuestRequest) bytes in,
//! canonical [`GuestResponse`](crate::conversion::GuestResponse) bytes out.
//! Undecodable or oversize input keeps the transport-level `Err`; every
//! decodable envelope returns `Ok` bytes carrying either the native step or
//! the exhaustive typed error, so rejected calls still report zero native
//! calls instead of a trap.
//!
//! Component binding generation (`wit-bindgen` + `wit-component`) for the
//! accepted #756 typed world is not available on this base; no raw
//! canonical-ABI memory protocol is fabricated here.

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

/// World-qualified name of this export; case 1 proves it equals
/// `{WORLD_NAME}#{EXPORT_NAME}` from the single-source constants.
#[must_use]
pub const fn qualified_export_name() -> &'static str {
    "guest#run"
}
