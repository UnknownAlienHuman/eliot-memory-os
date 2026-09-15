//! Thin typed `wasm32-wasip2` adapter over the native `ResearchSynthesis` projector.
//!
//! One valid guest invocation reaches the native #995 boundary exactly once
//! and returns the honest boundary error while the native owner is missing.
//! Rejected ABI/input envelopes return before the boundary with zero attempts.
//! The adapter owns no synthesis logic: no sourcing, parsing, grounding,
//! claim synthesis, grade promotion, rival resolution, probe execution,
//! mutable state, authority, effect or Finish. It never emits a brief of its
//! own.
//!
//! Required reading attestation: `docs_read` route
//! `sha256:b2171c4a21a18d1d4ad3105090c5b9f69d8cdb9f24742d660fa0664c6908d06c`,
//! read receipt `sha256:29cfaadc47f61bcdba962f63f33b54c018dfb2537c82aae6bac66396a0eb9bcf`,
//! bundle `sha256:c59dba0f6457917e55dcfe316b2256add62d42f829dd7a7b9ed5d0540f0023b2`
//! (matched routes: `generic-source`, `module-runtime`; 37 required items
//! read), plus direct reads of `docs/architecture/I02-11-*.md`,
//! `I02-20-*.md`, `I07-20-*.md`, `I14-19-wasm-components.md`,
//! `I15-10-sandboxing.md`, `I21-02-*.md`, `I21-06-*.md`, `I21-07-*.md`,
//! `I21-08-*.md`, the readable `bins/eliot-wasm-host/wit/guest.wit` and
//! `bins/eliot-wasm-host/wit/typed/dreamer-handler.wit` `ResearchSynthesis` arm,
//! the real `eliot-wasm-runtime` facade surface, `rust-toolchain.toml`, the
//! owning issue #634 body, the missing-native issue #995 body, and the #632
//! precedent branch (reader, verifier, seven-file adapter).

#![forbid(unsafe_code)]

pub mod conversion;
pub mod descriptor;
pub mod export;

pub use conversion::{
    CANDIDATE_SCHEMA_REVISION, CallLedger, ConversionError, GuestDimensionVerdict, GuestError,
    GuestPreservationDimension, GuestRequest, GuestRequesterOrigin, GuestResponse,
    MAX_GUEST_INPUT_BYTES, MAX_GUEST_OUTPUT_BYTES, ResearchBrief, ResearchCandidate, ResearchClaim,
    ResearchDisposition, ResearchPackRef, ResearchPayload, brief_digest, decode_request,
    decode_response, dimension_as_str, disposition_as_str, encode_request, encode_response,
    handle_request_typed, handle_with_ledger, origin_as_str, parse_disposition, request_digest,
    wit_export_name,
};
pub use descriptor::{
    ComponentDescriptor, DescriptorError, EXPORT_NAME, FORBIDDEN_IMPORT_SUBSTRINGS,
    GUEST_ABI_VERSION, GUEST_TARGET, GUEST_WIT_BYTES, HANDLER_SUBTYPE, NATIVE_CONTRACT_ID,
    NATIVE_OWNER, NATIVE_STATUS, TOOLCHAIN_BYTES, TOOLCHAIN_CHANNEL, TYPED_INTERFACE_NAME,
    TYPED_WIT_BYTES, TYPED_WORLD_NAME, TYPED_WORLD_OWNER, TYPED_WORLD_PACKAGE, TYPED_WORLD_STATUS,
    WORLD_NAME, WORLD_PACKAGE, WasmImport, check_wasm_imports, descriptor, descriptor_digest,
    is_forbidden_import, list_wasm_imports,
};
pub use export::{qualified_export_name, run, run_with_ledger};
