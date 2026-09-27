//! Structured crash report with build and symbol-artifact metadata (I16.2).
//!
//! I16.2 requires a structured crash report plus a symbol artifact reference.
//! I16.9 bounds crash evidence retention, so the report is a small JSON
//! document naming the build that crashed and the symbol artifact needed to
//! symbolicate it, written next to the operational logs. Stacks and memory
//! dumps never enter the report: a dump belongs in the `BlobStore` under an
//! explicit incident grant, and the report carries only the reference (`I15.4`).

use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::config::MAX_CRASH_REPORT_BYTES;

/// Typed crash-report failure.
#[derive(Debug)]
pub enum CrashReportError {
    /// A required metadata field was blank.
    InvalidMetadata(&'static str),
    /// The report exceeded its byte bound and was not written.
    OverBound {
        /// Rendered size in bytes.
        bytes: u64,
    },
    /// The report could not be serialized or written.
    Io(io::Error),
}

impl fmt::Display for CrashReportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidMetadata(field) => {
                write!(formatter, "crash report metadata rejected: {field}")
            }
            Self::OverBound { bytes } => {
                write!(formatter, "crash report of {bytes} bytes exceeds its bound")
            }
            Self::Io(error) => write!(formatter, "crash report write failed: {error}"),
        }
    }
}

impl std::error::Error for CrashReportError {}

/// Reference to the symbol artifact that resolves a crash's addresses.
///
/// The report names the artifact; it never embeds symbols or stack text.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SymbolArtifact {
    /// Stable artifact identity (path or store handle), never a URL with
    /// credentials.
    pub artifact_ref: String,
    /// Artifact digest used to bind the symbol set to the crashing build.
    pub artifact_sha256: String,
}

/// Build identity carried by every crash report.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CrashReportMetadata {
    /// Crashing process name, e.g. `eliot-kernel`.
    pub process: String,
    /// Package version of the crashing build.
    pub package_version: String,
    /// Build channel or profile revision that produced the executable.
    pub build_profile: String,
    /// Module generation in force at crash time; ties the report to the exact
    /// admitted generation rather than to a process name.
    pub module_generation_ref: String,
    /// Installation profile the process was serving.
    pub runtime_profile: String,
    /// Process identifier that crashed.
    pub process_id: u32,
    /// Panic or fault class, e.g. `panic`, `access_violation`, `abort`.
    pub fault_class: String,
    /// Bounded thread or task name at fault.
    pub fault_site: String,
    /// Symbol artifact that resolves this report's addresses.
    pub symbol_artifact: SymbolArtifact,
}

impl CrashReportMetadata {
    /// Validates that every required identity field is non-blank.
    ///
    /// # Errors
    ///
    /// Returns [`CrashReportError::InvalidMetadata`] naming the first blank
    /// field.
    pub fn validate(&self) -> Result<(), CrashReportError> {
        for (value, field) in [
            (&self.process, "process"),
            (&self.package_version, "package_version"),
            (&self.build_profile, "build_profile"),
            (&self.module_generation_ref, "module_generation_ref"),
            (&self.runtime_profile, "runtime_profile"),
            (&self.fault_class, "fault_class"),
            (&self.fault_site, "fault_site"),
            (
                &self.symbol_artifact.artifact_ref,
                "symbol_artifact.artifact_ref",
            ),
            (
                &self.symbol_artifact.artifact_sha256,
                "symbol_artifact.artifact_sha256",
            ),
        ] {
            if value.trim().is_empty() {
                return Err(CrashReportError::InvalidMetadata(field));
            }
        }
        Ok(())
    }
}

/// One structured crash report: build identity plus a content digest.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CrashReport {
    /// Stable report identity.
    pub report_id: String,
    /// Build and module-generation metadata.
    pub metadata: CrashReportMetadata,
    /// Content digest over the canonical report bytes, used to bind a report
    /// to the symbol artifact and to a downstream incident record.
    pub digest: String,
}

impl CrashReport {
    /// Builds a report and derives its content digest.
    ///
    /// # Errors
    ///
    /// Returns [`CrashReportError::InvalidMetadata`] for a blank required
    /// field.
    pub fn new(report_id: &str, metadata: CrashReportMetadata) -> Result<Self, CrashReportError> {
        if report_id.trim().is_empty() {
            return Err(CrashReportError::InvalidMetadata("report_id"));
        }
        metadata.validate()?;
        let bytes = serde_json::to_vec(&metadata)
            .map_err(|error| CrashReportError::Io(io::Error::other(error)))?;
        Ok(Self {
            report_id: report_id.to_owned(),
            digest: eliot_contracts::sha256_hex(&bytes),
            metadata,
        })
    }

    /// Renders the report as one bounded JSON document.
    ///
    /// # Errors
    ///
    /// Returns [`CrashReportError::OverBound`] when the rendered document
    /// exceeds [`MAX_CRASH_REPORT_BYTES`] and
    /// [`CrashReportError::Io`] when serialization fails.
    pub fn to_bounded_json(&self) -> Result<Vec<u8>, CrashReportError> {
        let bytes = serde_json::to_vec_pretty(self)
            .map_err(|error| CrashReportError::Io(io::Error::other(error)))?;
        let size = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
        if size > MAX_CRASH_REPORT_BYTES {
            return Err(CrashReportError::OverBound { bytes: size });
        }
        Ok(bytes)
    }

    /// Writes the bounded report into `directory` as `<report_id>.json`.
    ///
    /// # Errors
    ///
    /// Returns [`CrashReportError::Io`] when the directory or file cannot be
    /// written, and [`CrashReportError::OverBound`] for an over-bound report.
    pub fn write(&self, directory: &Path) -> Result<PathBuf, CrashReportError> {
        let bytes = self.to_bounded_json()?;
        fs::create_dir_all(directory).map_err(CrashReportError::Io)?;
        let path = directory.join(format!("{}.json", self.report_id));
        fs::write(&path, bytes).map_err(CrashReportError::Io)?;
        Ok(path)
    }
}
