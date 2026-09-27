//! Module Catalog: the recorded `I2.10` classification of every functional
//! capability cell.
//!
//! This module is the owner-neutral foundation primitive for the Module Catalog
//! described by `I2.10`. One [`ModuleCatalogRecord`] states the five
//! orthogonal classifications of one `FunctionalCapabilityCell` —
//! [`ModuleExecutionContour`], [`ModuleRuntimeClass`], [`ModuleStateClass`],
//! [`ModuleReplacementClass`], [`IterationLane`] — together with the recorded
//! execution-selection decision: the chosen contour, why it is the least
//! privileged one that can express the capability, the rejected alternatives,
//! and the applicable migration/promotion path.
//!
//! Rules this module owns (`I2.10`):
//!
//! * No classification is derived from a crate, bundle, source-layer, or
//!   runtime-layer name. Every value is an explicit declaration; a cell with no
//!   record, no rationale, or no rejected alternative is refused instead of
//!   being filled in.
//! * A cell that declares itself not production-required — generators,
//!   admission utilities, fuzzers, simulations, benchmarks, migration tooling
//!   — is classified with the explicit `development_only` contour and/or
//!   `development_tool` runtime class, which are never required by the
//!   production runtime. A production-required cell may carry neither.
//! * The state/replacement pairing constraints of `I2.10` are the same ones
//!   manifest generation enforces, so both surfaces refuse the same incoherent
//!   pair.
//!
//! It owns no runtime, process, storage, provider, or UI behavior, and it never
//! manufactures authority.

use std::fmt;

use schemars::JsonSchema;
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};

use crate::cell_effective_manifest::{
    development_classification_detail, is_development_classified, state_replacement_compatible,
};
use crate::{
    CapabilityCellId, ContractError, ContractVersion, IterationLane, ModuleExecutionContour,
    ModuleReplacementClass, ModuleRuntimeClass, ModuleStateClass, SourceCrateRef,
};

/// Exact namespace tag of the Module Catalog value family.
///
/// The namespace tag — not the spelling of any single field — determines this
/// identity family. A record with identical spelling from another namespace is
/// never equal to a value of this family.
pub const MODULE_CATALOG_NAMESPACE: &str = "eliot.foundation.module-catalog";

macro_rules! catalog_string {
    ($(#[$meta:meta])* $name:ident, $label:literal) => {
        $(#[$meta])*
        #[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, JsonSchema)]
        #[schemars(transparent)]
        pub struct $name(String);

        impl $name {
            /// Constructs a validated value, rejecting blank or control-bearing text.
            pub fn new(value: impl Into<String>) -> Result<Self, ContractError> {
                let value = value.into();
                if value.trim().is_empty() {
                    return Err(ContractError::Blank { field: $label });
                }
                if value.chars().any(char::is_control) {
                    return Err(ContractError::ControlCharacter { field: $label });
                }
                Ok(Self(value))
            }

            /// Returns the canonical text.
            pub fn as_str(&self) -> &str { &self.0 }

            /// Consumes this value and returns its text.
            pub fn into_string(self) -> String { self.0 }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.0)
            }
        }

        impl std::str::FromStr for $name {
            type Err = ContractError;
            fn from_str(value: &str) -> Result<Self, Self::Err> { Self::new(value) }
        }

        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where S: Serializer { serializer.serialize_str(&self.0) }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where D: Deserializer<'de> {
                let value = String::deserialize(deserializer)?;
                Self::new(value).map_err(de::Error::custom)
            }
        }
    };
}

catalog_string!(
    /// Recorded reason for an execution-selection decision: why the chosen
    /// contour was selected, or why a considered contour was rejected.
    ContourRationale, "contour_rationale");
catalog_string!(
    /// The migration or promotion path applicable to one capability. A later
    /// change of contour is a promotion/migration, not an invisible build
    /// optimization.
    PromotionPath, "promotion_path");

/// One execution contour that was considered for a capability and rejected,
/// with the reason it was not chosen.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RejectedContour {
    /// The contour that was considered and not chosen.
    pub contour: ModuleExecutionContour,
    /// Why this contour does not express the capability.
    pub reason: ContourRationale,
}

/// One Module Catalog record: the classification of one functional capability
/// cell and its recorded execution-selection decision.
///
/// Every field is an explicit declaration. A crate, bundle, source-layer, or
/// runtime-layer name never fills a field, and a value that cannot be pointed
/// at a declaration is a validation defect rather than a default.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ModuleCatalogRecord {
    /// Cell identity this record classifies.
    pub cell: CapabilityCellId,
    /// Revision of the classified cell contract surface.
    pub cell_revision: ContractVersion,
    /// Cargo package hosting the cell source; never a source of authority.
    pub source_crate: SourceCrateRef,
    /// Where the cell executes; the chosen contour of the selection decision.
    pub execution_contour: ModuleExecutionContour,
    /// Runtime role of the cell.
    pub runtime_class: ModuleRuntimeClass,
    /// State ownership class of the cell.
    pub state_class: ModuleStateClass,
    /// Runtime replacement class of the cell; an independent decision from
    /// source decomposition.
    pub replacement_class: ModuleReplacementClass,
    /// Development loop lane of the cell.
    pub iteration_lane: IterationLane,
    /// Explicit declaration of whether the production runtime requires this
    /// capability. Never inferred from any layer or package name.
    pub production_required: bool,
    /// Why `execution_contour` is the least privileged contour that can
    /// express the capability.
    pub least_privilege_reason: ContourRationale,
    /// Contours considered and rejected; at least one, never the chosen
    /// contour.
    pub rejected_alternatives: Vec<RejectedContour>,
    /// The migration/promotion path applicable to this capability.
    pub promotion_path: PromotionPath,
}

/// The Module Catalog: one [`ModuleCatalogRecord`] per functional capability
/// cell.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ModuleCatalog {
    /// One record per classified functional capability cell.
    pub records: Vec<ModuleCatalogRecord>,
}

/// One fail-closed Module Catalog defect. Any variant refuses the record or the
/// query instead of returning a defaulted or name-derived classification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ModuleCatalogError {
    /// No record classifies the requested cell. A classification is never
    /// synthesized from a crate, bundle, source-layer, or runtime-layer name.
    UnknownCapability {
        /// Cell that no record classifies.
        cell: String,
    },
    /// A cell id is claimed by more than one record.
    DuplicateCapability {
        /// Cell claimed by more than one record.
        cell: String,
    },
    /// A record states no rejected alternative, so the execution-selection
    /// decision is not recorded.
    NoRejectedAlternative {
        /// Cell with an unrecorded selection decision.
        cell: String,
    },
    /// A record lists its chosen contour among the rejected alternatives.
    ChosenContourRejected {
        /// Cell with the contradictory decision.
        cell: String,
        /// Contour that is both chosen and rejected.
        contour: String,
    },
    /// The state/replacement pair is inadmissible under `I2.10`.
    IncompatibleStateReplacement {
        /// Cell with the incompatible state/replacement pair.
        cell: String,
        /// Declared state ownership class.
        state: String,
        /// Declared runtime replacement class.
        replacement: String,
    },
    /// A cell that declares itself not production-required carries neither the
    /// explicit `development_only` contour nor the explicit `development_tool`
    /// runtime class.
    DevelopmentClassificationMissing {
        /// Cell with the missing development classification.
        cell: String,
    },
    /// A cell that declares itself production-required carries a
    /// `development_only` contour or a `development_tool` runtime class, which
    /// are never required by the production runtime.
    DevelopmentClassifiedProductionRequired {
        /// Cell making the claim.
        cell: String,
        /// Which development classification the cell carries.
        detail: String,
    },
}

impl fmt::Display for ModuleCatalogError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownCapability { cell } => {
                write!(
                    formatter,
                    "no Module Catalog record classifies cell '{cell}'"
                )
            }
            Self::DuplicateCapability { cell } => {
                write!(
                    formatter,
                    "cell '{cell}' is claimed by more than one catalog record"
                )
            }
            Self::NoRejectedAlternative { cell } => write!(
                formatter,
                "cell '{cell}' records no rejected alternative for its execution contour"
            ),
            Self::ChosenContourRejected { cell, contour } => write!(
                formatter,
                "cell '{cell}' both chooses and rejects contour '{contour}'"
            ),
            Self::IncompatibleStateReplacement {
                cell,
                state,
                replacement,
            } => write!(
                formatter,
                "cell '{cell}' state class '{state}' is incompatible with replacement class '{replacement}'"
            ),
            Self::DevelopmentClassificationMissing { cell } => write!(
                formatter,
                "cell '{cell}' is not production-required and declares neither development_only nor development_tool"
            ),
            Self::DevelopmentClassifiedProductionRequired { cell, detail } => write!(
                formatter,
                "cell '{cell}' is production-required and declares {detail}"
            ),
        }
    }
}

impl std::error::Error for ModuleCatalogError {}

/// Validates the recorded execution-selection decision and the coherence of
/// the five classifications of one record.
fn validate_record(record: &ModuleCatalogRecord) -> Result<(), ModuleCatalogError> {
    let cell = record.cell.as_str().to_owned();
    if record.rejected_alternatives.is_empty() {
        return Err(ModuleCatalogError::NoRejectedAlternative { cell });
    }
    for alternative in &record.rejected_alternatives {
        if alternative.contour == record.execution_contour {
            return Err(ModuleCatalogError::ChosenContourRejected {
                cell,
                contour: format!("{:?}", alternative.contour),
            });
        }
    }
    if !state_replacement_compatible(record.state_class, record.replacement_class) {
        return Err(ModuleCatalogError::IncompatibleStateReplacement {
            cell,
            state: format!("{:?}", record.state_class),
            replacement: format!("{:?}", record.replacement_class),
        });
    }
    let development = is_development_classified(record.execution_contour, record.runtime_class);
    if record.production_required && development {
        return Err(
            ModuleCatalogError::DevelopmentClassifiedProductionRequired {
                cell,
                detail: development_classification_detail(
                    record.execution_contour,
                    record.runtime_class,
                ),
            },
        );
    }
    if !record.production_required && !development {
        return Err(ModuleCatalogError::DevelopmentClassificationMissing { cell });
    }
    Ok(())
}

impl ModuleCatalog {
    /// Returns the classification record of one cell.
    ///
    /// The returned record carries all five classifications together with the
    /// recorded selection rationale. A cell with no record is refused with
    /// [`ModuleCatalogError::UnknownCapability`]; no classification is ever
    /// derived from the cell, crate, bundle, source-layer, or runtime-layer
    /// name.
    pub fn record(
        &self,
        cell: &CapabilityCellId,
    ) -> Result<&ModuleCatalogRecord, ModuleCatalogError> {
        self.records
            .iter()
            .find(|record| &record.cell == cell)
            .ok_or_else(|| ModuleCatalogError::UnknownCapability {
                cell: cell.as_str().to_owned(),
            })
    }

    /// Validates every record, failing closed on the first defect.
    ///
    /// Returns `Ok(())` only when each cell is claimed once, records a
    /// least-privilege reason, at least one rejected alternative that is not
    /// the chosen contour, a promotion path, an admissible `I2.10`
    /// state/replacement pair, and a development classification coherent with
    /// its `production_required` declaration.
    pub fn validate(&self) -> Result<(), ModuleCatalogError> {
        let mut seen: Vec<String> = Vec::with_capacity(self.records.len());
        for record in &self.records {
            let cell = record.cell.as_str().to_owned();
            if seen.contains(&cell) {
                return Err(ModuleCatalogError::DuplicateCapability { cell });
            }
            seen.push(cell);
            validate_record(record)?;
        }
        Ok(())
    }
}
