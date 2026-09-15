//! Thin typed `wasm32-wasip2` adapter over the native Curation fan-in (A-31).
//!
//! One valid typed guest invocation calls
//! [`route_validated_curation`](eliot_dreamer_curation::route_validated_curation)
//! exactly once through the statically registered ten-owner registry and
//! returns exactly its semantic candidate set. Rejected ABI/input envelopes
//! return before native execution with zero calls. The adapter owns no
//! Curation logic: no screening, grounding, A-05 validation, handler
//! semantics, preservation recomputation, canonical mutation, authority,
//! effect or Finish.
//!
//! Static registration covers the ten owner *descriptors* (pure data from the
//! accepted A-03 contracts). Live handler bindings are a frozen missing-owner
//! edge: no production [`NativeCurationHandler`](eliot_dreamer_contracts::NativeCurationHandler)
//! implementor exists on this base (see [`StaticPortChallenge`]), so the
//! bytes transport returns the exact typed missing-owner error with zero
//! native calls instead of fabricating handler semantics.
//!
//! Required reading attestation: `docs_read` route
//! `sha256:53612b9f70918b4bef88160cd6757a409f64a48f0d769b213b47a62a989b5541`,
//! read receipt `sha256:cf1bf3fab3535fd38804cdbad56358d150e7908d2e161e64ae2cbcc741961ca1`,
//! bundle `sha256:4d29bc344a678b7e9054426f6039cb985883a38c0558ac098c040bd5492a58d0`
//! (matched routes: `generic-source`, `module-runtime`; 37 required items
//! read), plus direct reads of `docs/architecture/I14-19-wasm-components.md`,
//! `I02-11-independent-build-proof-and-release-units.md`,
//! `I15-10-sandboxing.md`, `I09-06-curation-candidate.md`,
//! `I09-07-memory-transformation-validation.md`,
//! `I12-26-memory-admission-and-retrieval-trace.md`,
//! `I07-20-agent-facing-error-contract.md`, the exact native A-31 public API
//! (`crates/smart/eliot-dreamer-curation/src/`), the accepted A-03 hub
//! (`crates/smart/eliot-dreamer-contracts/src/`), the readable
//! `bins/eliot-wasm-host/wit/typed/dreamer-handler.wit` Curation arm, the real
//! `eliot-wasm-runtime` facade surface, `rust-toolchain.toml`, the #632
//! orientation-wasm precedent, and the owning issue #636 body.

#![forbid(unsafe_code)]

pub mod conversion;
pub mod descriptor;
pub mod export;
pub mod static_registry;

pub use conversion::{
    CallLedger, ConversionError, GuestError, GuestRequest, GuestResponse, MAX_GUEST_INPUT_BYTES,
    MAX_GUEST_OUTPUT_BYTES, decode_request, decode_response, disposition_as_str, encode_request,
    encode_response, family_as_str, handle_request_typed, handle_static_with_ledger,
    handle_with_ports, kind_as_str, parse_disposition, parse_family_spelling, parse_kind_spelling,
    rejection_hint_as_str, request_digest, wit_export_name,
};
pub use descriptor::{
    ComponentDescriptor, DescriptorError, EXPORT_NAME, FORBIDDEN_IMPORT_SUBSTRINGS,
    GUEST_ABI_VERSION, GUEST_TARGET, GUEST_WIT_BYTES, HANDLER_SUBTYPE, TOOLCHAIN_BYTES,
    TOOLCHAIN_CHANNEL, TYPED_WORLD_NAME, TYPED_WORLD_OWNER, TYPED_WORLD_STATUS, WORLD_NAME,
    WORLD_PACKAGE, WasmImport, check_wasm_imports, descriptor, descriptor_digest,
    is_forbidden_import, list_wasm_imports,
};
pub use export::{handle, handle_with_ledger, qualified_export_name};
pub use static_registry::{
    MISSING_OWNER_ISSUES, StaticPortChallenge, assemble_ports, missing_owner_families,
    owner_issue, static_port_challenge, static_registry, static_registry_digest,
};
