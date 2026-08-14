//! A-12 provider-neutral WASM Component Model admission and execution facade.
//!
//! Public invocation requests are inert. Only facts resolved through injected
//! Governor, authority, source-verifier, promotion-verifier, and P-03 ports can
//! reach an engine. This crate owns none of those authorities and supplies no
//! engine or process implementation.

#![forbid(unsafe_code)]

mod ports;
mod runtime;
mod types;

pub use ports::*;
pub use runtime::WasmRuntime;
pub use types::*;

/// Stable A-12 public contract identity.
pub const CONTRACT_NAME: &str = "eliot.modules.wasm-runtime";
/// Current A-12 wire revision.
pub const CONTRACT_VERSION: &str = "1.0.0";
/// First production component target from I14.19.
pub const DEFAULT_GUEST_TARGET: &str = "wasm32-wasip2";

#[cfg(test)]
mod tests;
