use crate::ProtocolError;
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
/// Maximum UTF-8 byte length for a SCIP symbol query.
pub const MAX_SELECTED_SOURCE_CAPTURE_SYMBOL_BYTES: usize = 4096;
/// Maximum UTF-8 byte length for a proposed Rust symbol name.
pub const MAX_SELECTED_SOURCE_CAPTURE_NAME_BYTES: usize = 1024;

/// Closed operation set supported by the one-shot RustAnalyzer and SCIP capture path.
///
/// The selected path is the only path-scope input. Executables, analyzer
/// configuration, and index locations remain selected by the current admitted
/// instrument profile and never arrive in this request.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum SelectedSourceCaptureOperation {
    /// One-shot diagnostics for the currently selected source candidate.
    Diagnostics,
    /// One-shot analyzer version probe under the selected candidate scope.
    ProbeVersion,
    /// SCIP definitions for an exact symbol in the selected candidate.
    Definitions { symbol: String },
    /// SCIP references for an exact symbol in the selected candidate.
    References { symbol: String },
    /// SCIP symbols scoped to the selected candidate path.
    Symbols,
    /// SCIP rename analysis. This always yields an unapplied edit candidate.
    RenameCandidate { symbol: String, new_name: String },
}

impl SelectedSourceCaptureOperation {
    /// Stable operation label used by the existing source-capture owner records.
    pub fn operation_name(&self) -> &'static str {
        match self {
            Self::Diagnostics => "Diagnostics",
            Self::ProbeVersion => "ProbeVersion",
            Self::Definitions { .. } => "Definitions",
            Self::References { .. } => "References",
            Self::Symbols => "Symbols",
            Self::RenameCandidate { .. } => "RenameCandidate",
        }
    }

    pub fn validate(&self) -> Result<(), ProtocolError> {
        match self {
            Self::Diagnostics | Self::ProbeVersion | Self::Symbols => Ok(()),
            Self::Definitions { symbol } | Self::References { symbol } => bounded_text(
                symbol,
                "selected_source_capture.operation.symbol",
                MAX_SELECTED_SOURCE_CAPTURE_SYMBOL_BYTES,
            ),
            Self::RenameCandidate { symbol, new_name } => {
                bounded_text(
                    symbol,
                    "selected_source_capture.operation.symbol",
                    MAX_SELECTED_SOURCE_CAPTURE_SYMBOL_BYTES,
                )?;
                bounded_text(
                    new_name,
                    "selected_source_capture.operation.new_name",
                    MAX_SELECTED_SOURCE_CAPTURE_NAME_BYTES,
                )
            }
        }
    }

    /// Serializes every semantic argument into the existing operation field.
    /// The returned JSON is the complete typed operation value, not a digest or
    /// a display label, so the canonical ProposedAttempt readback retains the
    /// exact symbol and rename target that the admitted request carried.
    pub fn canonical_serialization(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }
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
    /// One supported one-shot RustAnalyzer or SCIP operation.
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
        self.operation.validate()?;
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
            || path
                .split(['/', '\\'])
                .any(|component| component.is_empty() || component == "." || component == "..")
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

#[cfg(test)]
mod tests {
    use super::{
        SELECTED_SOURCE_CAPTURE_INVOCATION_WIRE_ID,
        SELECTED_SOURCE_CAPTURE_INVOCATION_WIRE_VERSION, SelectedSourceCaptureInvocation,
        SelectedSourceCaptureOperation,
    };

    #[test]
    fn original_unit_wire_values_remain_compatible_and_semantic_args_round_trip() {
        for (operation, wire) in [
            (
                SelectedSourceCaptureOperation::Diagnostics,
                "\"DIAGNOSTICS\"",
            ),
            (
                SelectedSourceCaptureOperation::ProbeVersion,
                "\"PROBE_VERSION\"",
            ),
        ] {
            assert_eq!(
                serde_json::to_string(&operation).expect("unit operation serializes"),
                wire
            );
            let decoded: SelectedSourceCaptureOperation =
                serde_json::from_str(wire).expect("original unit operation decodes");
            assert_eq!(decoded, operation);
        }

        let definitions = SelectedSourceCaptureOperation::Definitions {
            symbol: "crate::module::function".to_owned(),
        };
        let canonical = definitions
            .canonical_serialization()
            .expect("typed operation serializes");
        let decoded: SelectedSourceCaptureOperation =
            serde_json::from_str(&canonical).expect("semantic operation decodes");
        assert_eq!(decoded, definitions);
        assert!(canonical.contains("crate::module::function"));
    }

    #[test]
    fn semantic_operations_refuse_missing_or_foreign_fields() {
        assert!(
            SelectedSourceCaptureOperation::Definitions {
                symbol: String::new(),
            }
            .validate()
            .is_err()
        );
        assert!(
            serde_json::from_str::<SelectedSourceCaptureOperation>(
                r#"{"DEFINITIONS":{"symbol":"crate::f","foreign":"value"}}"#
            )
            .is_err()
        );
        assert!(
            SelectedSourceCaptureOperation::RenameCandidate {
                symbol: "crate::f".to_owned(),
                new_name: "name\nwith-control".to_owned(),
            }
            .validate()
            .is_err()
        );
    }

    #[test]
    fn selected_path_refuses_traversal_and_accepts_a_repository_relative_file() {
        let invocation = |selected_relative_path: &str| SelectedSourceCaptureInvocation {
            wire_id: SELECTED_SOURCE_CAPTURE_INVOCATION_WIRE_ID.to_owned(),
            wire_version: SELECTED_SOURCE_CAPTURE_INVOCATION_WIRE_VERSION,
            operation: SelectedSourceCaptureOperation::Symbols,
            selected_relative_path: selected_relative_path.to_owned(),
            selector: None,
        };
        assert!(invocation("src/lib.rs").validate().is_ok());
        assert!(invocation("../other/lib.rs").validate().is_err());
        assert!(invocation(r"C:\other\lib.rs").validate().is_err());
    }
}
