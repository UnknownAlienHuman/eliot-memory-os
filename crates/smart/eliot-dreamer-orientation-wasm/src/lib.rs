//! Thin typed `wasm32-wasip2` adapter over the native Orientation projector.
//!
//! One valid guest invocation calls
//! [`project_orientation`](eliot_dreamer_orientation::project_orientation)
//! exactly once and returns exactly its semantic result. Rejected
//! ABI/input envelopes return before native execution with zero calls.
//! The adapter owns no Orientation logic: no parsing, acquisition,
//! normalization, grounding, rival/probe/clarification algorithm, Human
//! interaction, probe execution, mutable state, authority, effect or Finish.
//!
//! Required reading attestation: `docs_read` route
//! `sha256:2d606625312576d2f3bcc9c396221e9ef4b86254e25e13abc1011385769da6e2`,
//! read receipt `sha256:492655c260670b1c9d1a7faa26b99ab78a8dc0c3f35cfaf4bcc72cce0ae28b46`,
//! bundle `sha256:fecf238c371637de002d651de842c10fe54d3eb45ffe72971592e8a82165d288`
//! (matched routes: `generic-source`, `module-runtime`; 37 required items
//! read, including the owning native/bundle/CEP/evidence sources and the
//! `bins/eliot-wasm-host` read-only composition), plus direct reads of the
//! exact native public API (`crates/smart/eliot-dreamer-orientation/src/`),
//! the accepted `bins/eliot-wasm-host/wit/guest.wit`, the real
//! `eliot-wasm-runtime` facade surface, `rust-toolchain.toml`, and the
//! owning issue #632 body with prior PR #635.

#![forbid(unsafe_code)]

pub mod conversion;
pub mod descriptor;
pub mod export;

pub use conversion::{
    CallLedger, ConversionError, GuestError, GuestRequest, GuestResponse, MAX_GUEST_INPUT_BYTES,
    MAX_GUEST_OUTPUT_BYTES, decode_request, decode_response, disposition_as_str, encode_request,
    encode_response, handle_request_typed, handle_with_ledger, parse_disposition, request_digest,
    wit_export_name,
};
pub use descriptor::{
    ComponentDescriptor, DescriptorError, EXPECTED_TYPED_WORLD, EXPORT_NAME,
    FORBIDDEN_IMPORT_SUBSTRINGS, GUEST_ABI_VERSION, GUEST_TARGET, GUEST_WIT_BYTES, HANDLER_SUBTYPE,
    TOOLCHAIN_BYTES, TOOLCHAIN_CHANNEL, TYPED_WORLD_OWNER, TYPED_WORLD_STATUS, WORLD_NAME,
    WORLD_PACKAGE, WasmImport, check_wasm_imports, descriptor, descriptor_digest,
    is_forbidden_import, list_wasm_imports,
};
pub use export::{qualified_export_name, run, run_with_ledger};
