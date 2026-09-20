//! Legacy capability importer (Issue #1957, I3.4).
//!
//! Compatibility adapter used during the legacy Governor-config retirement:
//! every legacy capability bool/declaration normalizes to
//! `declared` / `imported_legacy_declaration` with a full route-scope
//! fingerprint where unavailable fields stay `None` (unknown, never inferred).
//! Imported records never satisfy production admission; that decision lives in
//! the Governor-owned capability registry (`eliot-governor`).

#![forbid(unsafe_code)]

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Errors raised while normalizing a legacy capability declaration.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum LegacyImportError {
    /// The legacy capability name is blank or carries control characters.
    #[error("legacy capability name must be non-blank")]
    BlankCapability,
}

/// The only status a legacy import may carry. Legacy input is a declaration,
/// never verified evidence.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImportedCapabilityStatus {
    Declared,
}

/// The only source a legacy import may carry.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImportedCapabilitySource {
    ImportedLegacyDeclaration,
}

/// Route-scope fingerprint carried by a legacy declaration.
///
/// Every field is optional: fields the legacy source cannot provide stay
/// `None` (unknown) rather than inferred.
#[derive(Clone, Debug, Default, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LegacyScopeFingerprint {
    pub runtime_hash: Option<String>,
    pub adapter_hash: Option<String>,
    pub os_architecture: Option<String>,
    pub auth_profile_class: Option<String>,
    pub provider_model_route: Option<String>,
    pub feature_flags_and_serializer: Option<String>,
}

/// One legacy capability bool/declaration awaiting normalization.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LegacyCapabilityDeclaration {
    pub capability: String,
    pub scope: LegacyScopeFingerprint,
}

/// Normalized legacy evidence: always `declared` / `imported_legacy`.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImportedLegacyEvidence {
    pub capability: String,
    pub status: ImportedCapabilityStatus,
    pub source: ImportedCapabilitySource,
    pub scope: LegacyScopeFingerprint,
}

impl ImportedLegacyEvidence {
    /// Legacy evidence never admits a production route.
    #[must_use]
    pub const fn admits_production_route(&self) -> bool {
        false
    }
}

fn non_blank_capability(value: &str) -> Result<(), LegacyImportError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(LegacyImportError::BlankCapability);
    }
    Ok(())
}

/// Maps one legacy capability declaration to `declared/imported_legacy`.
///
/// # Errors
///
/// Returns [`LegacyImportError::BlankCapability`] when the capability name is
/// blank.
pub fn import_legacy_declaration(
    declaration: &LegacyCapabilityDeclaration,
) -> Result<ImportedLegacyEvidence, LegacyImportError> {
    non_blank_capability(&declaration.capability)?;
    Ok(ImportedLegacyEvidence {
        capability: declaration.capability.clone(),
        status: ImportedCapabilityStatus::Declared,
        source: ImportedCapabilitySource::ImportedLegacyDeclaration,
        scope: declaration.scope.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_import_is_declared_and_never_production_admissible() {
        let declaration = LegacyCapabilityDeclaration {
            capability: "route.execute".into(),
            scope: LegacyScopeFingerprint {
                adapter_hash: Some("adapter-hash-1".into()),
                ..LegacyScopeFingerprint::default()
            },
        };
        let imported =
            import_legacy_declaration(&declaration).expect("valid legacy declaration imports");
        assert_eq!(imported.status, ImportedCapabilityStatus::Declared);
        assert_eq!(
            imported.source,
            ImportedCapabilitySource::ImportedLegacyDeclaration
        );
        assert!(!imported.admits_production_route());
        assert_eq!(imported.scope.runtime_hash, None);
    }

    #[test]
    fn blank_legacy_capability_is_rejected() {
        let declaration = LegacyCapabilityDeclaration {
            capability: "  ".into(),
            scope: LegacyScopeFingerprint::default(),
        };
        assert_eq!(
            import_legacy_declaration(&declaration),
            Err(LegacyImportError::BlankCapability)
        );
    }
}
