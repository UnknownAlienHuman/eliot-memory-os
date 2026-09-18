//! Thin typed `wasm32-wasip2` adapter over the native deterministic screen.
//!
//! One valid typed guest invocation calls
//! [`screen_memory_curation`](eliot_memory_curation_screen::screen_memory_curation)
//! exactly once and returns exactly its A-19c
//! [`CurationScreenResult`](eliot_memory_curation_contracts::CurationScreenResult).
//! Rejected ABI/input envelopes return before native execution with zero
//! calls. The adapter owns no screen logic: no protection derivation,
//! eligibility decision, structural finding, paging, Store access, model
//! call, A-31/handler dispatch, canonical mutation, authority, effect or
//! Finish. Degraded, blocked, partial, stale and unsupported-continuation
//! domain states go to A-20 and keep their native outcome; guest glue never
//! converts them to empty success or a second eligibility decision.
//!
//! Required reading attestation: `docs_read` route
//! `sha256:9183dc2d3185b63c8553f767b1d9b64b83e6474ccaccf90a770c9b7b1e282224`,
//! read receipt `sha256:c40fce72a357701ded6051475fad23db2c507a4456e5569640f8f7bfca4677f3`,
//! bundle `sha256:4571828c314332c7dba5c8c96ac5f884cb0909f699e74d2a42bf3a3069a69d4d`
//! (matched routes: `generic-source`; 23 required items read; pair key
//! `sha256:105558fc8957e150fab407b4fc5818ec49dc784f23f246f42dc9d3ca5843196b`),
//! plus direct reads of `docs/architecture/I14-19-wasm-components.md`,
//! `I02-11-independent-build-proof-and-release-units.md`,
//! `I02-20-module-contract-kit-crate-context-capsule-and-module-test-capsule.md`,
//! `I15-10-sandboxing.md`, `I09-06-curation-candidate.md`,
//! `I09-07-memory-transformation-validation.md`,
//! `A04-07-accessibility-support-influence-and-erasure.md`,
//! `I12-19-negative-memory.md`, `I12-20-influence-revocation.md`,
//! `I12-26-memory-admission-and-retrieval-trace.md`,
//! `I21-06-source-portfolio-coverage-denominator-and-coveragereceipt.md`,
//! `I07-20-agent-facing-error-contract.md`, the exact native A-19c/A-20
//! public API (`crates/smart/eliot-memory-curation-contracts/src/`,
//! `crates/smart/eliot-memory-curation-screen/src/`), the readable
//! `bins/eliot-wasm-host/wit/typed/memory-curation-screen.wit` world, the
//! real `eliot-wasm-runtime` facade surface, `rust-toolchain.toml`, the #632
//! orientation-wasm precedent, and the owning issue #642 body.

#![forbid(unsafe_code)]

pub mod conversion;
pub mod descriptor;
pub mod export;

pub use conversion::{
    CallLedger, ConversionError, GuestError, GuestRequest, GuestResponse, MAX_GUEST_INPUT_BYTES,
    MAX_GUEST_OUTPUT_BYTES, availability_as_str, decode_request, decode_response,
    disposition_as_str, eligibility_as_str, encode_request, encode_response, finding_class_as_str,
    finding_proof_as_str, handle_request_typed, handle_with_ledger, parse_availability,
    parse_disposition, parse_eligibility, parse_finding_class, parse_finding_proof,
    parse_protection, parse_result_state, protection_as_str, request_digest, result_state_as_str,
    wit_export_name,
};
pub use descriptor::{
    COMPONENT_VERSION, ComponentDescriptor, DescriptorError, EXPORT_NAME,
    FORBIDDEN_IMPORT_SUBSTRINGS, GUEST_ABI_VERSION, GUEST_TARGET, GUEST_WIT_BYTES, HANDLER_SUBTYPE,
    NATIVE_CONTRACT, NATIVE_CONTRACT_VERSION, NATIVE_OWNER, TOOLCHAIN_BYTES, TOOLCHAIN_CHANNEL,
    TYPED_WORLD_NAME, TYPED_WORLD_OWNER, TYPED_WORLD_STATUS, WORLD_NAME, WORLD_PACKAGE, WasmImport,
    check_wasm_imports, descriptor, descriptor_digest, is_forbidden_import, list_wasm_imports,
};
pub use export::{qualified_export_name, screen, screen_with_ledger};
