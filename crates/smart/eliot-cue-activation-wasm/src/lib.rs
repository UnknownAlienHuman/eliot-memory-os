//! Thin typed `wasm32-wasip2` adapter over the native bounded cue activation
//! evaluator (A-14a).
//!
//! One valid typed guest invocation calls
//! [`evaluate_activation`](eliot_cue_activation::evaluate_activation) exactly
//! once over the caller-supplied immutable snapshot build candidate and
//! returns exactly its semantic evaluation. Rejected ABI/world envelopes
//! return before native execution with zero calls. The adapter owns no cue
//! logic: no normalization, binding admission, snapshot build, index/graph
//! query, inferred edge, model/provider, Context delivery, memory mutation,
//! authority, effect or Finish.
//!
//! Required reading attestation: `docs_read` route
//! `sha256:e42cc1dae671ef39c34a597b13439a3c2da4e5b242db83266fd7be9be04b2732`,
//! read receipt `sha256:b786fe93d6052ceb6bccc526ff6254c009f972df4a6a3fb174cc5745d3deded6`,
//! bundle `sha256:84e30aeedcd14bc09242ac695cdbd5afa3623970a585e0b6a04955981aacc012`
//! (matched routes: `generic-source`, `module-runtime`, `memory-context`; 49
//! required items read; pair key
//! `sha256:105558fc8957e150fab407b4fc5818ec49dc784f23f246f42dc9d3ca5843196b`),
//! plus direct reads of `docs/architecture/I14-19-wasm-components.md`,
//! `I02-11-independent-build-proof-and-release-units.md`,
//! `I02-20-module-contract-kit-crate-context-capsule-and-module-test-capsule.md`,
//! `I15-10-sandboxing.md`, `I12-06-cue-binding.md`, `I12-07-cue-index.md`,
//! `I12-15-bounded-spreading-activation.md`,
//! `I12-26-memory-admission-and-retrieval-trace.md`,
//! `I07-20-agent-facing-error-contract.md`, `I02-17-parallel-agent-development-contract.md`,
//! the exact native A-14a public API
//! (`crates/smart/eliot-cue-activation/src/`), the accepted A-10 vocabulary
//! (`crates/smart/eliot-cue-contracts/src/`), the readable
//! `bins/eliot-wasm-host/wit/typed/cue-activation.wit` activation world, the
//! real `eliot-wasm-runtime` facade surface, `rust-toolchain.toml`, the #632
//! orientation-wasm structural precedent, and the owning issue #640 body.

#![forbid(unsafe_code)]

pub mod conversion;
pub mod descriptor;
pub mod export;

pub use conversion::{
    CallLedger, ConversionError, GuestError, GuestRequest, GuestResponse, MAX_GUEST_INPUT_BYTES,
    MAX_GUEST_OUTPUT_BYTES, bound_kind_as_str, completeness_as_str, decode_request,
    decode_response, encode_request, encode_response, handle_request_typed, handle_with_ledger,
    parse_bound_kind, parse_completeness, request_digest, wit_export_name,
};
pub use descriptor::{
    COMPONENT_VERSION, ComponentDescriptor, DescriptorError, EXPORT_NAME,
    FORBIDDEN_IMPORT_SUBSTRINGS, GUEST_ABI_VERSION, GUEST_TARGET, GUEST_WIT_BYTES, TOOLCHAIN_BYTES,
    TOOLCHAIN_CHANNEL, TYPED_WORLD_NAME, TYPED_WORLD_OWNER, TYPED_WORLD_STATUS, WORLD_NAME,
    WORLD_PACKAGE, WasmImport, check_wasm_imports, descriptor, descriptor_digest,
    is_forbidden_import, list_wasm_imports,
};
pub use export::{activate, activate_with_ledger, qualified_export_name};
