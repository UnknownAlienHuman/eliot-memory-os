//! Generation-to-pulse readback over the generated capability-cell registry.
//!
//! Read-only, fail-closed evidence projection owned by issue #13: resolves one
//! caller-supplied installed process generation through the generated
//! [`CapabilityCellRegistry`] to its capability cell, public contract digest,
//! proof entrypoint/ceiling, and Product Pulse reference.
//!
//! Hard boundaries (see `crates/meta/AGENTS.md`):
//!
//! * This projection never infers installed/current/healthy state from files,
//!   ports, PIDs, or stale manifests. The `generation` argument is opaque
//!   caller-supplied evidence (owned by issue #11); resolution only reports
//!   which registry record that generation string is bound to, or fails with
//!   [`CellReadbackError::UnknownGeneration`].
//! * Lifecycle ownership is read from the bound registry record only; nothing
//!   here mints, derives, or transfers ownership.
//! * Cell/proof metadata shape is owned by issue #13; live runtime evidence is
//!   owned by issue #11. Notify-surface paths are not touched here.
//! * Proof-ceiling spellings are matched exhaustively on the registry enum,
//!   never derived from `Debug` formatting.

use eliot_contracts::{
    CapabilityCellRegistry, EXPECTED_NORMATIVE_PAIR_KEY, ProductPulse, ProofCeiling,
    RegistryDiagnostic, RegistryValidationError,
};
use serde::{Deserialize, Serialize};

/// Resolved readback of one installed generation through the registry.
///
/// Every field below is cloned from the bound [`CapabilityCellRegistry`]
/// record (or the caller-supplied `generation` echo); no field is inferred
/// from files, ports, PIDs, or manifests. Exactly one of `product_pulse` /
/// `not_applicable_reason` is `Some`, mirroring the registry's
/// [`ProductPulse`] binding. A successful resolution is evidence routing, not
/// an installed/current/healthy claim: liveness remains owned by issue #11.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GenerationCellResolution {
    /// Installed generation string supplied by the caller (echo, not proof).
    pub generation: String,
    /// Bound capability cell identity from the registry record.
    pub cell: String,
    /// Lifecycle owner read from the bound registry record.
    pub lifecycle_owner: String,
    /// Public contract digest of the bound cell.
    pub contract_digest: String,
    /// Where the contract digest was observed (catalogue/generator reference).
    pub digest_source: String,
    /// Independently invokable proof entrypoint of the bound cell.
    pub proof_entrypoint: String,
    /// Highest proof level the bound cell may claim (stable wire spelling).
    pub proof_ceiling: String,
    /// Product Pulse reference, when the bound cell carries one.
    pub product_pulse: Option<String>,
    /// Explicit reason no Product Pulse applies, when the cell declares none.
    pub not_applicable_reason: Option<String>,
    /// Freshness binding: digest of the exact registry value read.
    pub registry_digest: String,
}

/// Fail-closed readback failure. Any variant refuses the resolution instead
/// of projecting partial or inferred evidence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CellReadbackError {
    /// No registry record binds its runtime bundle to this generation.
    UnknownGeneration {
        /// Generation string that matched no bound record.
        generation: String,
    },
    /// The registry is bound to a superseded normative pair.
    StaleRegistry {
        /// Adopted pair key from `docs/normative-pair.toml`.
        expected_pair: String,
        /// Pair key carried by the registry value.
        found_pair: String,
    },
    /// The registry failed validation; every diagnostic is preserved.
    InvalidRegistry(RegistryValidationError),
    /// The bound record carries no independently invokable proof entrypoint.
    MissingProof {
        /// Cell without proof.
        cell: String,
    },
    /// The bound record carries neither a pulse reference nor a usable
    /// exemption reason.
    MissingPulseBinding {
        /// Cell without a usable pulse binding.
        cell: String,
    },
    /// The freshness digest of the validated registry could not be computed,
    /// so no freshness-bound resolution can be returned.
    DigestFailed {
        /// Underlying digest failure detail.
        detail: String,
    },
}

impl std::fmt::Display for CellReadbackError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownGeneration { generation } => write!(
                formatter,
                "unknown installed generation: no capability cell is bound to '{generation}'"
            ),
            Self::StaleRegistry {
                expected_pair,
                found_pair,
            } => write!(
                formatter,
                "stale capability-cell registry: expected pair '{expected_pair}', found '{found_pair}'"
            ),
            Self::InvalidRegistry(error) => write!(formatter, "invalid registry: {error}"),
            Self::MissingProof { cell } => write!(
                formatter,
                "capability cell '{cell}' has no independently invokable proof entrypoint"
            ),
            Self::MissingPulseBinding { cell } => write!(
                formatter,
                "capability cell '{cell}' has neither a Product Pulse reference nor a usable exemption reason"
            ),
            Self::DigestFailed { detail } => {
                write!(formatter, "registry digest unavailable: {detail}")
            }
        }
    }
}

impl std::error::Error for CellReadbackError {}

fn proof_ceiling_name(ceiling: ProofCeiling) -> &'static str {
    match ceiling {
        ProofCeiling::StaticFieldAndMigrationContractOnly => {
            "STATIC_FIELD_AND_MIGRATION_CONTRACT_ONLY"
        }
        ProofCeiling::ModuleEdgeProof => "MODULE_EDGE_PROOF",
        ProofCeiling::ProductProof => "PRODUCT_PROOF",
    }
}

/// Resolves one installed process generation to its capability cell,
/// contract digest, proof entrypoint, and Product Pulse via the registry.
///
/// `generation` is opaque caller-supplied evidence (issue #11 owns liveness);
/// it is matched exactly against each record's bound `runtime_bundle`
/// identifier by iterating `registry.cells` in registry order and taking the
/// first exact match. There is no hardcoded generation table: an unbound
/// generation fails with [`CellReadbackError::UnknownGeneration`].
///
/// Fail-closed order: registry validation diagnostics (a stale pair binding
/// surfaces as [`CellReadbackError::StaleRegistry`], all other diagnostics as
/// [`CellReadbackError::InvalidRegistry`]), then the current-pair check, then
/// the generation lookup, then the bound record's proof/pulse bindings, then
/// the freshness digest. No step manufactures authority or infers health.
pub fn resolve_generation_via_registry(
    generation: &str,
    registry: &CapabilityCellRegistry,
) -> Result<GenerationCellResolution, CellReadbackError> {
    if let Err(validation) = registry.validate() {
        for diagnostic in validation.diagnostics() {
            if let RegistryDiagnostic::StalePairIdentity { expected, found } = diagnostic {
                return Err(CellReadbackError::StaleRegistry {
                    expected_pair: expected.clone(),
                    found_pair: found.clone(),
                });
            }
        }
        return Err(CellReadbackError::InvalidRegistry(validation));
    }
    if !registry.pair_key.is_current() {
        return Err(CellReadbackError::StaleRegistry {
            expected_pair: EXPECTED_NORMATIVE_PAIR_KEY.to_owned(),
            found_pair: registry.pair_key.as_str().to_owned(),
        });
    }
    let record = registry
        .cells
        .iter()
        .find(|candidate| {
            candidate
                .runtime_bundle
                .as_ref()
                .is_some_and(|bundle| bundle.as_str() == generation)
        })
        .ok_or_else(|| CellReadbackError::UnknownGeneration {
            generation: generation.to_owned(),
        })?;
    let proof_entrypoint =
        record
            .proof_entrypoint
            .as_ref()
            .ok_or_else(|| CellReadbackError::MissingProof {
                cell: record.cell.as_str().to_owned(),
            })?;
    let (product_pulse, not_applicable_reason) = match &record.product_pulse {
        ProductPulse::Referenced(pulse) => (Some(pulse.as_str().to_owned()), None),
        ProductPulse::NotApplicable { reason } => {
            if reason.as_str().trim().is_empty() {
                return Err(CellReadbackError::MissingPulseBinding {
                    cell: record.cell.as_str().to_owned(),
                });
            }
            (None, Some(reason.as_str().to_owned()))
        }
    };
    let registry_digest =
        registry
            .registry_digest()
            .map_err(|error| CellReadbackError::DigestFailed {
                detail: error.to_string(),
            })?;
    Ok(GenerationCellResolution {
        generation: generation.to_owned(),
        cell: record.cell.as_str().to_owned(),
        lifecycle_owner: record.lifecycle_owner.as_str().to_owned(),
        contract_digest: record.contract_digest.as_str().to_owned(),
        digest_source: record.contract_digest_source.as_str().to_owned(),
        proof_entrypoint: proof_entrypoint.as_str().to_owned(),
        proof_ceiling: proof_ceiling_name(record.proof_ceiling).to_owned(),
        product_pulse,
        not_applicable_reason,
        registry_digest,
    })
}
