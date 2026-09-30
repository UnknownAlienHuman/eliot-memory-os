//! Bounded artifact acquisition and preflight for typed components.
//!
//! Performs pre-open reparse-component checks, then reads one opened regular-file
//! handle into a bounded buffer and checks its length and WebAssembly preamble/core
//! marker. The digest describes that same buffer. Path checks are subject to races
//! and do not establish retained-root, source, or signature authorization. No
//! network, registry, discovery, URL, credential, provider, or Kernel access.

use std::fmt;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

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
    /// Path names a symbolic link or reparse point.
    ReparsePoint,
    /// Path does not name a regular file.
    NotAFile,
    /// Path is not an explicit absolute local path. The experimental lane
    /// denies relative spellings instead of resolving them against the
    /// process working directory.
    NotAbsolute,
    /// File length changed after its opened-handle metadata was observed.
    LengthChanged,
    /// Bytes do not start with the WebAssembly magic.
    MalformedPreamble,
    /// Bytes are a core module, not a component.
    CoreModuleRejected,
    /// Local file could not be read (kind string only, no path/secret).
    Unreadable(String),
    /// Caller-supplied source names a remote, registry, or discovery
    /// location (`://` authority marker), never an explicit bounded local
    /// artifact or fixture.
    ArbitraryPathDenied,
}

impl fmt::Display for PreflightError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => formatter.write_str("PREFLIGHT_EMPTY"),
            Self::TooLarge { actual, max } => {
                write!(formatter, "PREFLIGHT_TOO_LARGE:actual={actual}:max={max}")
            }
            Self::ReparsePoint => formatter.write_str("PREFLIGHT_REPARSE_POINT"),
            Self::NotAFile => formatter.write_str("PREFLIGHT_NOT_A_FILE"),
            Self::NotAbsolute => formatter.write_str("PREFLIGHT_NOT_ABSOLUTE"),
            Self::LengthChanged => formatter.write_str("PREFLIGHT_LENGTH_CHANGED"),
            Self::MalformedPreamble => formatter.write_str("PREFLIGHT_MALFORMED_PREAMBLE"),
            Self::CoreModuleRejected => formatter.write_str("PREFLIGHT_CORE_MODULE_REJECTED"),
            Self::ArbitraryPathDenied => formatter.write_str("PREFLIGHT_ARBITRARY_PATH_DENIED"),
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

/// Rejects a non-absolute artifact path without consulting the environment.
/// The local-experimental lane accepts only an explicit absolute local path,
/// so a relative spelling is denied instead of being resolved against the
/// process working directory (no environment, registry, discovery, URL,
/// credential, provider, or Kernel lookup on that lane).
pub fn require_absolute_artifact_path(path: &Path) -> Result<(), PreflightError> {
    if path.is_absolute() {
        Ok(())
    } else {
        Err(PreflightError::NotAbsolute)
    }
}

/// Reads one explicit local artifact path once into a bounded buffer.
/// No environment, registry, discovery, URL, or credential lookup.
/// The returned bytes and [`Preflight`] digest describe the same buffer.
/// URL/authority-shaped sources are denied before any filesystem access.
pub fn read_bounded_artifact(path: &Path) -> Result<(Vec<u8>, Preflight), PreflightError> {
    reject_remote_artifact_source(path)?;
    let path = absolute_artifact_path(path)?;
    reject_reparse_components(&path)?;
    let file = open_artifact_file(&path)
        .map_err(|error| PreflightError::Unreadable(error.kind().to_string()))?;
    // Post-open final-component check: the pre-open walk above is raceable,
    // so the final component is re-inspected once the handle exists. A link
    // swapped in after the walk is rejected here instead of being followed.
    // Ancestor swaps stay raceable (see module docs); closing them needs
    // retained-root handles.
    reject_final_reparse_point(&path)?;
    let metadata = file
        .metadata()
        .map_err(|error| PreflightError::Unreadable(error.kind().to_string()))?;
    if metadata_is_reparse_point(&metadata) {
        return Err(PreflightError::ReparsePoint);
    }
    if !metadata.is_file() {
        return Err(PreflightError::NotAFile);
    }
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
    // The handle is the only source of artifact bytes. `take` bounds allocation
    // even if the file grows after its length was observed.
    let mut bytes = Vec::new();
    file.take(MAX_ARTIFACT_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| PreflightError::Unreadable(error.kind().to_string()))?;
    let actual = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    if actual > MAX_ARTIFACT_BYTES {
        return Err(PreflightError::TooLarge {
            actual,
            max: MAX_ARTIFACT_BYTES,
        });
    }
    if actual != declared {
        return Err(PreflightError::LengthChanged);
    }
    let preflight = preflight_bytes(&bytes)?;
    Ok((bytes, preflight))
}

/// Rejects URL/authority-shaped sources before any filesystem access. Only
/// an explicit bounded local artifact is admitted on either mode; a remote,
/// registry, or discovery locator is never a local file. Single-colon
/// Windows drive and UNC spellings carry no `://` authority marker and are
/// unaffected.
fn reject_remote_artifact_source(path: &Path) -> Result<(), PreflightError> {
    if path.as_os_str().to_string_lossy().contains("://") {
        return Err(PreflightError::ArbitraryPathDenied);
    }
    Ok(())
}

fn absolute_artifact_path(path: &Path) -> Result<PathBuf, PreflightError> {
    if path.is_absolute() {
        Ok(path.to_path_buf())
    } else {
        std::env::current_dir()
            .map(|current| current.join(path))
            .map_err(|error| PreflightError::Unreadable(error.kind().to_string()))
    }
}

fn reject_reparse_components(path: &Path) -> Result<(), PreflightError> {
    for component in path
        .ancestors()
        .filter(|component| !component.as_os_str().is_empty())
    {
        let metadata = std::fs::symlink_metadata(component)
            .map_err(|error| PreflightError::Unreadable(error.kind().to_string()))?;
        if metadata_is_reparse_point(&metadata) {
            return Err(PreflightError::ReparsePoint);
        }
    }
    Ok(())
}

/// Rejects a final path component that is a symbolic link or reparse point
/// without following it. Shared with the bounded guest-input path, which
/// applies the same no-follow discipline before opening its handle.
pub(crate) fn reject_final_reparse_point(path: &Path) -> Result<(), PreflightError> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|error| PreflightError::Unreadable(error.kind().to_string()))?;
    if metadata_is_reparse_point(&metadata) {
        return Err(PreflightError::ReparsePoint);
    }
    Ok(())
}

fn open_artifact_file(path: &Path) -> std::io::Result<File> {
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;

        // Open the final path component itself so a final reparse point is
        // inspected and rejected instead of being followed to another file.
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)
    }
    #[cfg(not(windows))]
    {
        File::open(path)
    }
}

fn metadata_is_reparse_point(metadata: &std::fs::Metadata) -> bool {
    if metadata.file_type().is_symlink() {
        return true;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;

        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
        metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
    }
    #[cfg(not(windows))]
    {
        false
    }
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
