//! Owner-neutral I0.5 conformance and support contracts.
//!
//! This crate is stateless and effect-free. It defines independent contract
//! maturity, implementation support, evidence execution, and observation-state
//! dimensions without discovering evidence or promoting support.

#![forbid(unsafe_code)]

mod validation;

use serde::{Deserialize, Serialize};
use thiserror::Error;

pub use validation::{
    canonicalize_capability_support_row, canonicalize_contract_set, canonicalize_domain_coverage,
    canonicalize_support_claim_set, validate_capability_support_row,
    validate_capability_support_row_against_coverage, validate_conformance_contract_set,
    validate_domain_coverage, validate_support_claim_set,
};

/// Current serialized contract revision.
pub const CONTRACT_VERSION: u16 = 1;
/// Stable schema identity for this package revision.
pub const CONTRACT_SCHEMA: &str = "eliot.conformance.support-contracts.v1";
/// Maximum entries in one set-like handle collection.
pub const MAX_SET_ITEMS: usize = 256;
/// Maximum support rows in one validation unit.
pub const MAX_SUPPORT_ROWS: usize = 4_096;
/// Maximum UTF-8 bytes in one identifier or handle.
pub const MAX_TEXT_BYTES: usize = 1_024;

/// Maturity of one public contract. This is independent of implementation
/// support, current observation, and evidence execution.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ContractMaturity {
    Skeleton,
    Compatible,
    Stable,
    Replaceable,
    Retired,
}

/// Current implementation support for one exact scoped claim.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ImplementationSupport {
    CurrentVerified,
    CurrentUnverified,
    Partial,
    Blocked,
    Target,
    Experimental,
    Deferred,
    Degraded,
    Stale,
    NotApplicable,
}

impl ImplementationSupport {
    /// Whether this value exposes a current operational surface and therefore
    /// needs an explicit compatibility rule when the contract is retired.
    #[must_use]
    pub const fn is_current_exposure(self) -> bool {
        matches!(
            self,
            Self::CurrentVerified
                | Self::CurrentUnverified
                | Self::Partial
                | Self::Experimental
                | Self::Degraded
        )
    }
}

/// Whether cited evidence was actually executed. This is not an instrument
/// lifecycle and not an evaluator verdict.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EvidenceExecutionStatus {
    NotExecuted,
    Simulated,
    Executed,
    UnknownOutcome,
}

/// Availability/currentness of one observation surface. This axis does not
/// imply maturity, support, or execution.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SupportObservationState {
    Observed,
    NotRunning,
    Unavailable,
    Unknown,
    Stale,
    Conflicted,
}

impl SupportObservationState {
    /// Only current observed coverage can satisfy a verified dependency.
    #[must_use]
    pub const fn satisfies_current_dependency(self) -> bool {
        matches!(self, Self::Observed)
    }
}

/// Closed evidence domains required by Implementation I0.5.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EvidenceDomain {
    Source,
    Build,
    Runtime,
    Store,
    Integrations,
}

impl EvidenceDomain {
    /// Canonical order for deterministic serialization and hashing.
    pub const ALL: [Self; 5] = [
        Self::Source,
        Self::Build,
        Self::Runtime,
        Self::Store,
        Self::Integrations,
    ];
}

/// Observation coverage for one exact I0.5 domain.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DomainCoverage {
    pub contract_version: u16,
    pub domain: EvidenceDomain,
    pub state: SupportObservationState,
    pub source_handles: Vec<String>,
    pub evidence_refs: Vec<String>,
    pub blind_boundaries: Vec<String>,
    pub observed_at_ms: Option<u64>,
    pub expires_at_ms: Option<u64>,
    pub invalidation_set: Vec<String>,
}

/// One exact capability-support claim under an explicit scope and domain
/// dependency set.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilitySupportRow {
    pub contract_version: u16,
    pub contract_ref: String,
    pub support_claim_ref: String,
    pub scope_ref: String,
    pub claim_domain: Option<EvidenceDomain>,
    pub required_dependency_domains: Vec<EvidenceDomain>,
    pub support_observation_state: SupportObservationState,
    pub contract_maturity: ContractMaturity,
    pub implementation_support: ImplementationSupport,
    pub evidence_execution_status: EvidenceExecutionStatus,
    pub proof_profile_ref: Option<String>,
    pub source_handles: Vec<String>,
    pub evidence_refs: Vec<String>,
    pub blind_boundaries: Vec<String>,
    pub invalidation_set: Vec<String>,
    pub compatibility_rule_ref: Option<String>,
    pub not_applicable_reason_ref: Option<String>,
    pub evaluated_at_ms: u64,
}

/// One complete owner-neutral validation unit. It remains immutable input; this
/// crate owns no registry or current-state lifecycle.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConformanceContractSet {
    pub contract_version: u16,
    pub evaluated_at_ms: u64,
    pub domain_coverage: Vec<DomainCoverage>,
    pub support_rows: Vec<CapabilitySupportRow>,
}

/// Closed structural and semantic failures returned by the pure validators.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ConformanceContractError {
    #[error("unsupported contract version {actual}; expected {expected}")]
    UnsupportedContractVersion { expected: u16, actual: u16 },
    #[error("invalid {field}: {reason}")]
    InvalidText {
        field: &'static str,
        reason: &'static str,
    },
    #[error("{field} contains {actual} entries; maximum is {maximum}")]
    CollectionTooLarge {
        field: &'static str,
        maximum: usize,
        actual: usize,
    },
    #[error("duplicate value in {field}: {value}")]
    DuplicateValue { field: &'static str, value: String },
    #[error("{field} is not in canonical order")]
    NonCanonicalCollection { field: &'static str },
    #[error("missing required evidence domain {domain:?}")]
    MissingDomain { domain: EvidenceDomain },
    #[error("duplicate evidence domain {domain:?}")]
    DuplicateDomain { domain: EvidenceDomain },
    #[error("duplicate support claim {support_claim_ref}")]
    DuplicateClaim { support_claim_ref: String },
    #[error(
        "duplicate contract/scope/domain claim for {contract_ref} in {scope_ref}: {claim_domain:?}"
    )]
    DuplicateContractScopeClaim {
        contract_ref: String,
        scope_ref: String,
        claim_domain: Option<EvidenceDomain>,
    },
    #[error("invalid time field {field}")]
    InvalidTime { field: &'static str },
    #[error("invalid support combination: {reason}")]
    InvalidSupportCombination { reason: &'static str },
    #[error("required evidence is missing: {field}")]
    MissingEvidence { field: &'static str },
    #[error("required invalidation set is missing")]
    MissingInvalidationSet,
    #[error("current verified support is missing a proof profile")]
    MissingProofProfile,
    #[error("support claim is missing required domain {domain:?}")]
    MissingRequiredDomain { domain: EvidenceDomain },
    #[error("required domain {domain:?} is not current: {state:?}")]
    DomainNotCurrent {
        domain: EvidenceDomain,
        state: SupportObservationState,
    },
    #[error("required domain {domain:?} has an unresolved blind boundary")]
    DomainBlind { domain: EvidenceDomain },
    #[error(
        "required domain {domain:?} expired at {expired_at_ms} before evaluation {evaluated_at_ms}"
    )]
    DomainExpired {
        domain: EvidenceDomain,
        expired_at_ms: u64,
        evaluated_at_ms: u64,
    },
    #[error("claim observation for {domain:?} is {claimed:?}, but domain coverage is {observed:?}")]
    ClaimObservationMismatch {
        domain: EvidenceDomain,
        claimed: SupportObservationState,
        observed: SupportObservationState,
    },
    #[error("support row evaluation time does not match the contract-set boundary")]
    EvaluationBoundaryMismatch,
}
