//! Guest descriptor and pure-world import gate bound to the accepted WIT.
//!
//! The typed `context-admission` WIT (#756, accepted on this base), the byte
//! transport `guest.wit`, and the pinned toolchain file are read at compile
//! time from their owning paths, so the descriptor cannot drift from the
//! accepted sources by hand-copying. No ABI is invented here.

use eliot_contracts::{canonical_json_bytes, sha256_hex};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Accepted guest ABI revision carried inside every typed envelope.
pub const GUEST_ABI_VERSION: u32 = 1;
/// WIT package identity from the accepted typed `context-admission` world.
pub const WORLD_PACKAGE: &str = "eliot:current@0.1.0";
/// WIT world name from the accepted typed `context-admission` world.
pub const WORLD_NAME: &str = "context-admission";
/// WIT interface name exported by the accepted typed world.
pub const TYPED_WORLD_INTERFACE: &str = "admission";
/// Typed operations exported by the accepted world (`admit`, `describe`).
pub const TYPED_OPS: &[&str] = &["admit", "describe"];
/// Byte-transport export name from the accepted `guest.wit`.
pub const EXPORT_NAME: &str = "run";
/// Context-compiler subtype handled by this guest.
pub const HANDLER_SUBTYPE: &str = "context-compiler";
/// First production component target from I14.19 (also `DEFAULT_GUEST_TARGET`).
pub const GUEST_TARGET: &str = "wasm32-wasip2";
/// Pinned toolchain channel read from the owning `rust-toolchain.toml`.
pub const TOOLCHAIN_CHANNEL: &str = "1.97.1";
/// Acceptance status of the typed world on this base (#756 accepted).
pub const TYPED_WORLD_STATUS: &str = "ACCEPTED";

/// Exact bytes of the accepted typed world contract at compile time.
pub const ADMISSION_WIT_BYTES: &[u8] =
    include_bytes!("../../../../bins/eliot-wasm-host/wit/typed/context-admission.wit");
/// Exact bytes of the owning byte-transport WIT contract at compile time.
pub const GUEST_WIT_BYTES: &[u8] = include_bytes!("../../../../bins/eliot-wasm-host/wit/guest.wit");
/// Exact bytes of the pinned toolchain file at compile time (read-only dep).
pub const TOOLCHAIN_BYTES: &[u8] = include_str!("../../../../rust-toolchain.toml").as_bytes();

/// Capability namespaces the pure #756 world must never inherit.
pub const FORBIDDEN_IMPORT_SUBSTRINGS: &[&str] = &[
    "filesystem",
    "sockets",
    "network",
    "http",
    "stdio",
    "stdin",
    "stdout",
    "stderr",
    "terminal",
    "environment",
    "environ",
    "env",
    "argv",
    "args",
    "clocks",
    "clock",
    "random",
    "process",
    "thread",
    "credential",
    "store",
    "kernel",
    "provider",
    "model",
    "tool",
    "wasi_snapshot_preview1",
];

/// One imported `(module, name)` pair observed in a built artifact.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WasmImport {
    /// Import module namespace (e.g. `wasi:filesystem/types@0.2.10`).
    pub module: String,
    /// Imported name within the module.
    pub name: String,
}

/// Descriptor failures carry the offending import, never a weakened pass.
#[derive(Clone, Debug, Eq, PartialEq, Error, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum DescriptorError {
    /// Input is not a WebAssembly binary.
    #[error("not a WebAssembly module")]
    NotWasm,
    /// Import parsing failed for a stated reason.
    #[error("import section unreadable: {0}")]
    Unreadable(String),
    /// A forbidden capability namespace was imported.
    #[error("forbidden import {module}::{name}")]
    ForbiddenImport {
        /// Offending import module namespace.
        module: String,
        /// Offended imported name.
        name: String,
    },
}

/// The component identity this guest claims.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ComponentDescriptor {
    /// WIT package identity (must equal [`WORLD_PACKAGE`]).
    pub world_package: String,
    /// WIT world name (must equal [`WORLD_NAME`]).
    pub world: String,
    /// WIT interface name (must equal [`TYPED_WORLD_INTERFACE`]).
    pub interface: String,
    /// Typed operations (must equal [`TYPED_OPS`]).
    pub typed_ops: Vec<String>,
    /// Byte-transport export name (must equal [`EXPORT_NAME`]).
    pub export_name: String,
    /// Handler subtype (must equal [`HANDLER_SUBTYPE`]).
    pub handler_subtype: String,
    /// Guest ABI revision (must equal [`GUEST_ABI_VERSION`]).
    pub abi_version: u32,
    /// Build target (must equal [`GUEST_TARGET`]).
    pub target: String,
    /// Pinned toolchain channel (must equal [`TOOLCHAIN_CHANNEL`]).
    pub toolchain_channel: String,
    /// SHA-256 of [`ADMISSION_WIT_BYTES`].
    pub wit_digest: String,
    /// SHA-256 of [`GUEST_WIT_BYTES`].
    pub guest_wit_digest: String,
    /// Granted capability namespaces; empty for the pure world.
    pub capability_envelope: Vec<String>,
    /// Acceptance status of the typed world.
    pub typed_world_status: String,
}

/// Builds the single canonical descriptor for this guest.
#[must_use]
pub fn descriptor() -> ComponentDescriptor {
    ComponentDescriptor {
        world_package: WORLD_PACKAGE.to_owned(),
        world: WORLD_NAME.to_owned(),
        interface: TYPED_WORLD_INTERFACE.to_owned(),
        typed_ops: TYPED_OPS.iter().map(ToString::to_string).collect(),
        export_name: EXPORT_NAME.to_owned(),
        handler_subtype: HANDLER_SUBTYPE.to_owned(),
        abi_version: GUEST_ABI_VERSION,
        target: GUEST_TARGET.to_owned(),
        toolchain_channel: TOOLCHAIN_CHANNEL.to_owned(),
        wit_digest: sha256_hex(ADMISSION_WIT_BYTES),
        guest_wit_digest: sha256_hex(GUEST_WIT_BYTES),
        capability_envelope: Vec::new(),
        typed_world_status: TYPED_WORLD_STATUS.to_owned(),
    }
}

/// Canonical digest of the descriptor; stable across repeated computation.
#[must_use]
pub fn descriptor_digest() -> String {
    let bytes = canonical_json_bytes(&descriptor()).unwrap_or_default();
    sha256_hex(&bytes)
}

/// Returns `true` when the import pair falls in a forbidden namespace.
#[must_use]
pub fn is_forbidden_import(module: &str, name: &str) -> bool {
    let module = module.to_lowercase();
    let name = name.to_lowercase();
    FORBIDDEN_IMPORT_SUBSTRINGS
        .iter()
        .any(|forbidden| module.contains(forbidden) || name.contains(forbidden))
}

/// Lists every import of a WebAssembly binary without executing it.
pub fn list_wasm_imports(wasm_bytes: &[u8]) -> Result<Vec<WasmImport>, DescriptorError> {
    if wasm_bytes.len() < 8
        || wasm_bytes[0..4] != [0x00, 0x61, 0x73, 0x6D]
        || wasm_bytes[4..8] != [0x01, 0x00, 0x00, 0x00]
    {
        return Err(DescriptorError::NotWasm);
    }
    let parser = wasmparser::Parser::new(0);
    let mut imports = Vec::new();
    for payload in parser.parse_all(wasm_bytes) {
        let payload = payload.map_err(|error| DescriptorError::Unreadable(error.to_string()))?;
        if let wasmparser::Payload::ImportSection(reader) = payload {
            for import in reader.into_imports() {
                let import =
                    import.map_err(|error| DescriptorError::Unreadable(error.to_string()))?;
                imports.push(WasmImport {
                    module: import.module.to_owned(),
                    name: import.name.to_owned(),
                });
            }
        }
    }
    Ok(imports)
}

/// Rejects artifacts importing a forbidden capability before execution.
pub fn check_wasm_imports(wasm_bytes: &[u8]) -> Result<Vec<WasmImport>, DescriptorError> {
    let imports = list_wasm_imports(wasm_bytes)?;
    for import in &imports {
        if is_forbidden_import(&import.module, &import.name) {
            return Err(DescriptorError::ForbiddenImport {
                module: import.module.clone(),
                name: import.name.clone(),
            });
        }
    }
    Ok(imports)
}
