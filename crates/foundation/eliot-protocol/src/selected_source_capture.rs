use crate::{ProtocolError, SelectedSourceCaptureOperation};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Wire identity for the bounded selected-source capture command.
pub const SELECTED_SOURCE_CAPTURE_INVOCATION_WIRE_ID: &str =
    "eliot.protocol.selected-source-capture-invocation";
/// Current selected-source capture command version.
pub const SELECTED_SOURCE_CAPTURE_INVOCATION_WIRE_VERSION: u16 = 1;
/// Host capability name for a selected-source capture invocation.
pub const SELECTED_SOURCE_CAPTURE_CAPABILITY: &str = "eliot.source-capture";
/// Closed host payload schema bound by the admitted envelope.
pub const SELECTED_SOURCE_CAPTURE_PAYLOAD_SCHEMA_ID: &str = "eliot.source-capture.invoke.v1";
/// Maximum UTF-8 byte length for a selected repository-relative source path.
pub const MAX_SELECTED_SOURCE_CAPTURE_PATH_BYTES: usize = 4096;
/// Maximum UTF-8 byte length for a source selector.
pub const MAX_SELECTED_SOURCE_CAPTURE_SELECTOR_BYTES: usize = 512;

/// Closed operation set supported by the one-shot RustAnalyzer capture path.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SelectedSourceCaptureOperation {
    /// One-shot diagnostics for the currently selected source candidate.
    Diagnostics,
    /// One-shot analyzer version probe under the selected candidate scope.
    ProbeVersion,
}

/// Authenticated, typed command to capture one selected source observation.
///
/// The path and selector are untrusted selectors only. Kernel and Governor
/// must resolve them against the retained WorkItem, current WorkScope, Task,
/// Session, and WorkLease before deriving source/configuration commitments.
/// Executable identity and configuration are supplied by the admitted
/// instrument registry, never by this request.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SelectedSourceCaptureInvocation {
    /// Versioned wire discriminator.
    pub wire_id: String,
    /// Versioned wire contract.
    pub wire_version: u16,
    /// One supported one-shot RustAnalyzer operation.
    pub operation: SelectedSourceCaptureOperation,
    /// Repository-relative path selected under the authenticated WorkScope.
    pub selected_relative_path: String,
    /// Optional bounded owner selector for the selected source candidate.
    pub selector: Option<String>,
}

impl SelectedSourceCaptureInvocation {
    /// Validates only the closed wire shape and selector bounds. Authority and
    /// source existence are revalidated by the original owners after claim.
    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.wire_id != SELECTED_SOURCE_CAPTURE_INVOCATION_WIRE_ID
            || self.wire_version != SELECTED_SOURCE_CAPTURE_INVOCATION_WIRE_VERSION
        {
            return Err(ProtocolError::InvalidField {
                field: "selected_source_capture.wire",
                reason: "unsupported selected-source capture invocation",
            });
        }
        bounded_text(
            &self.selected_relative_path,
            "selected_source_capture.selected_relative_path",
            MAX_SELECTED_SOURCE_CAPTURE_PATH_BYTES,
        )?;
        let path = self.selected_relative_path.as_str();
        if path.starts_with('/')
            || path.starts_with('\\')
            || path.contains(':')
            || path.split(['/', '\\']).any(|component| {
                component.is_empty() || component == "." || component == ".."
            })
        {
            return Err(ProtocolError::InvalidField {
                field: "selected_source_capture.selected_relative_path",
                reason: "must be a normalized repository-relative path without traversal components",
            });
        }
        if let Some(selector) = &self.selector {
            bounded_text(
                selector,
                "selected_source_capture.selector",
                MAX_SELECTED_SOURCE_CAPTURE_SELECTOR_BYTES,
            )?;
        }
        Ok(())
    }
}

fn bounded_text(
    value: &str,
    field: &'static str,
    maximum_bytes: usize,
) -> Result<(), ProtocolError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(ProtocolError::InvalidField {
            field,
            reason: "must be non-blank and contain no control characters",
        });
    }
    if value.len() > maximum_bytes {
        return Err(ProtocolError::InvalidField {
            field,
            reason: "exceeds the bounded wire length",
        });
    }
    Ok(())
}
