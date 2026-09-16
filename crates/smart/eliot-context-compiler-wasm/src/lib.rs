//! Thin typed `wasm32-wasip2` adapter over the native Context admission gate.
//!
//! One valid guest invocation calls
//! [`admit_context`](eliot_context_admission::admit_context)
//! exactly once and returns exactly its semantic result. Rejected
//! ABI/input envelopes return before native execution with zero calls.
//! The adapter owns no admission logic: no candidate construction (A-16a),
//! assembly/rendering/delivery/use (A-18, #762), measurement/tokenizer
//! algorithm, mutable state, authority, effect or Finish.
//!
//! Required reading attestation: `docs_read` route
//! `sha256:bbecc4665c3c18f52f856405af2fb559cf426a84f410bd34f1f0ffa8b202d043`,
//! read receipt `sha256:96a1256b8c5093458f36c3617b35a07ed7035aeb602e7095279418b85eb4401d`,
//! bundle `sha256:80d31df177d741af44e04828005734e1fcff19e59dfe0fef04e9e4431a3216c5`
//! (matched routes: `generic-source`; 23 required items read, including the
//! owning native/bundle/contract sources), plus direct reads of the exact
//! native public API (`crates/smart/eliot-context-admission/src/`,
//! `crates/smart/eliot-context-contracts/src/`), the accepted
//! `bins/eliot-wasm-host/wit/typed/context-admission.wit` (#756) and
//! `bins/eliot-wasm-host/wit/guest.wit`, the real `eliot-wasm-runtime`
//! facade surface, `rust-toolchain.toml`, the owning issue #638 body, and
//! `docs/architecture/` fragments I14-19, I02-11, I02-20, I15-10, I07-11,
//! I12-32, I02-16, I07-20.

#![forbid(unsafe_code)]

pub mod conversion;
pub mod descriptor;
pub mod export;

pub use conversion::{
    CallLedger, ConversionError, GuestError, GuestRequest, GuestResponse, INCOMPLETE_CODE,
    MAX_GUEST_INPUT_BYTES, MAX_GUEST_OUTPUT_BYTES, admission_disposition_as_str,
    availability_as_str, decode_request, decode_response, encode_request, encode_response,
    handle_request_typed, handle_with_ledger, loss_policy_as_str, parse_admission_disposition,
    parse_availability, parse_loss_policy, parse_representation_kind, representation_kind_as_str,
    request_digest, wit_export_name,
};
pub use descriptor::{
    ADMISSION_WIT_BYTES, ComponentDescriptor, DescriptorError, EXPORT_NAME,
    FORBIDDEN_IMPORT_SUBSTRINGS, GUEST_ABI_VERSION, GUEST_TARGET, GUEST_WIT_BYTES, HANDLER_SUBTYPE,
    TOOLCHAIN_BYTES, TOOLCHAIN_CHANNEL, TYPED_OPS, TYPED_WORLD_INTERFACE, TYPED_WORLD_STATUS,
    WORLD_NAME, WORLD_PACKAGE, WasmImport, check_wasm_imports, descriptor, descriptor_digest,
    is_forbidden_import, list_wasm_imports,
};
pub use export::{qualified_export_name, run, run_with_ledger};
