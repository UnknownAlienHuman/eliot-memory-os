//! Error type for bounded self-quality diagnosis.
//!
//! Diagnosis itself performs no repair, so every failure is a contract
//! rejection surfaced from the normative #971 validators.

use eliot_conformance_contracts::SelfQualityContractError;
use thiserror::Error;

/// Failures of bounded self-quality diagnosis.
#[derive(Debug, Error)]
pub enum SelfQualityError {
    /// The input, candidate, disposition, or handoff was rejected by the #971 contract.
    #[error("self-quality contract rejected: {0}")]
    Contract(#[from] SelfQualityContractError),
}
