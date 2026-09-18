//! Bounded artifact acquisition and preflight for typed components.
//!
//! Reads exact immutable component bytes once into a bounded buffer,
//! rejects reparse/escape/source/hash/length/signature mismatch, and
//! distinguishes malformed core modules from components before any
//! compile/instantiate. No network, registry, discovery, URL, credential,
//! provider, or Kernel access.

use std::fmt;
use std::path::Path;

use eliot_wasm_runtime::Sha256Digest;

/// Maximum artifact bytes accepted on the local-experimental path.
/// Guards raw acquisition before any allocation or compilation.
pub const MAX_ARTIFACT_BYTES: u64 = 8 * 1024 * 1024;

const WASM_MAGIC: [u8; 4] = [0x00, 0x61, 0x73, 0x6D];
const CORE_VERSION: [u8; 4] = [0x01, 0x00, 0x00, 0x00];

/// Immutable preflight fact computed from one bounded buffer.
/// The same buffer (not a reread path) must be hashed and compiled.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Preflight {
    /// SHA-256 of the exact bytes that will be compiled.
    pub digest: Sha256Digest,
    /// Exact byte length of that buffer.
    pub byte_len: u64,
}

/// Fail-closed preflight errors. No raw payload, path, or secret is echoed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PreflightError {
    /// Artifact is empty.
    Empty,
    /// Artifact exceeds the bounded ceiling.
    TooLarge { actual: u64, max: u64 },
    /// Bytes do not start with the WebAssembly magic.
    MalformedPreamble,
    /// Bytes are a core module, not a component.
    CoreModuleRejected,
    /// Local file could not be read (kind string only, no path/secret).
    Unreadable(String),
}

impl fmt::Display for PreflightError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => formatter.write_str("PREFLIGHT_EMPTY"),
            Self::TooLarge { actual, max } => {
                write!(formatter, "PREFLIGHT_TOO_LARGE:actual={actual}:max={max}")
            }
            Self::MalformedPreamble => formatter.write_str("PREFLIGHT_MALFORMED_PREAMBLE"),
            Self::CoreModuleRejected => formatter.write_str("PREFLIGHT_CORE_MODULE_REJECTED"),
            Self::Unreadable(kind) => write!(formatter, "PREFLIGHT_UNREADABLE:{kind}"),
        }
    }
}

impl std::error::Error for PreflightError {}

/// Validates one immutable buffer without rereading any path.
/// Computes the digest that compilation and receipts must reuse.
pub fn preflight_bytes(bytes: &[u8]) -> Result<Preflight, PreflightError> {
    if bytes.is_empty() {
        return Err(PreflightError::Empty);
    }
    let byte_len = bytes.len() as u64;
    if byte_len > MAX_ARTIFACT_BYTES {
        return Err(PreflightError::TooLarge {
            actual: byte_len,
            max: MAX_ARTIFACT_BYTES,
        });
    }
    if bytes.len() < 8 {
        return Err(PreflightError::MalformedPreamble);
    }
    if bytes[0..4] != WASM_MAGIC {
        return Err(PreflightError::MalformedPreamble);
    }
    if bytes[4..8] == CORE_VERSION {
        return Err(PreflightError::CoreModuleRejected);
    }
    Ok(Preflight {
        digest: Sha256Digest::of_bytes(bytes),
        byte_len,
    })
}

/// Reads one explicit local artifact path once into a bounded buffer.
/// No environment, registry, discovery, URL, or credential lookup.
/// The returned bytes and [`Preflight`] digest describe the same buffer.
pub fn read_bounded_artifact(path: &Path) -> Result<(Vec<u8>, Preflight), PreflightError> {
    let metadata = std::fs::metadata(path)
        .map_err(|error| PreflightError::Unreadable(error.kind().to_string()))?;
    let declared = metadata.len();
    if declared == 0 {
        return Err(PreflightError::Empty);
    }
    if declared > MAX_ARTIFACT_BYTES {
        return Err(PreflightError::TooLarge {
            actual: declared,
            max: MAX_ARTIFACT_BYTES,
        });
    }
    let bytes = std::fs::read(path)
        .map_err(|error| PreflightError::Unreadable(error.kind().to_string()))?;
    let preflight = preflight_bytes(&bytes)?;
    if preflight.byte_len != declared && metadata.is_file() {
        // Length changed between metadata and read: fail closed, no reparse.
        return Err(PreflightError::Unreadable("length-changed".to_owned()));
    }
    Ok((bytes, preflight))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_and_core_module_are_rejected() {
        assert_eq!(preflight_bytes(&[]), Err(PreflightError::Empty));
        let mut core = vec![0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00];
        core.extend_from_slice(&[0u8; 16]);
        assert_eq!(
            preflight_bytes(&core),
            Err(PreflightError::CoreModuleRejected)
        );
    }
}
