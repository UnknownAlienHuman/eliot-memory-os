//! Thin typed `wasm32-wasip2` adapter over the native pure Dreamer-cycle transition.
//!
//! One ABI-valid guest invocation calls
//! [`step_dreamer_cycle_at`](eliot_dreamer_cycle::step_dreamer_cycle_at)
//! exactly once and returns exactly its semantic result. Rejected
//! ABI/envelope/schema/bound preflights return before native execution with
//! zero calls. The adapter owns no controller logic: no phase advance,
//! dispatch, model invocation, storage access, epoch mutation,
//! durable publication, effect or task completion.
//!
//! Required reading attestation: `docs_read` route
//! `sha256:fcb24f48a036fb520b77fa4e0d37b2f77fe29a1af616b68306edd175f6e72aa2`,
//! read receipt `sha256:5637c335e05309ad3ef7b7adbc791cbb2e2e7bc1237f285bfcecf7d11ea569de`,
//! bundle `sha256:e2b65fbf9e64b3553082d5adea8c765aa0d91502e541d8824228ab0a931bff9e`
//! (matched routes: `generic-source`, `module-runtime`, `dreamer`; 39 required items
//! read, including the owning native/bundle/contract sources and the
//! `bins/eliot-wasm-host` read-only composition), plus direct reads of the
//! exact native public API (`crates/smart/eliot-dreamer-cycle/src/`),
//! the accepted `bins/eliot-wasm-host/wit/guest.wit`, the real
//! `eliot-wasm-runtime` facade surface, `rust-toolchain.toml`, the owning
//! issue #644 body, and `docs/architecture/` `I09-02`, `I09-03`, `I09-05`,
//! `I09-08`, `I14-19`, `I14-14`, `I05-16`, `I07-20`.

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
