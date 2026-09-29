//! Deterministic, candidate-only `FailureFingerprint` synthesis.
//!
//! The handler consumes the complete A03 Failure closure and emits one sealed
//! candidate artifact. It never performs I/O, calls a provider, reads a clock,
//! mutates memory, blocks an action, or promotes causal authority.
//!
//! # Negative memory
//!
//! [`negative_memory`] holds the one current durable negative-memory
//! fingerprint record, the explicit legacy/candidate migration, and the
//! owner-admitted action policy value. [`negative_memory_match`] holds the
//! pure, bounded matcher that compares a pending action against a named rule
//! read. Both are inert: this owner proposes and compares, and neither admits,
//! publishes, blocks, expires nor proves a mechanism.

#![forbid(unsafe_code)]

mod assessment;
mod negative_memory;
mod negative_memory_match;
mod policy;
mod result;

pub use assessment::{
    ApplicabilityAssessment, CausalLimits, FailureAssessment, FailureCountSummary,
    OutcomeAssessment, TriggerAssessment,
};
pub use eliot_dreamer_contracts::{
    FailureAction, FailureApplicability, FailureCoverage, FailureDimension,
    FailureDimensionSource, FailureDimensionValue, FailureDisposition, FailureEnvironment,
};
pub use negative_memory::{
    LegacyFailureFingerprintRecord, NEGATIVE_MEMORY_MAX_BYTES, NEGATIVE_MEMORY_MAX_TEXT,
    NEGATIVE_MEMORY_POLICY_SCHEMA_VERSION, NEGATIVE_MEMORY_SCHEMA_VERSION,
    NegativeMemoryActionPolicy, NegativeMemoryAffectedScope, NegativeMemoryCheckExecution,
    NegativeMemoryCheckOutcome, NegativeMemoryDiscriminatingCheck, NegativeMemoryDisposition,
    NegativeMemoryFalseActivationHistory, NegativeMemoryFingerprint, NegativeMemoryHorizon,
    NegativeMemoryHorizonDomain, NegativeMemoryHorizonDomainKind, NegativeMemoryHorizonRelation,
    NegativeMemoryInvariant, NegativeMemoryInvariantVerification, NegativeMemoryLegacyAdvisory,
    NegativeMemoryLegacyMigration, NegativeMemoryPolicyBinding, NegativeMemoryRecordDefect,
    NegativeMemoryReopenCondition, NegativeMemoryResource, NegativeMemoryResourceKind,
    NegativeMemoryTrigger, NegativeMemoryTriggerResolution, NegativeMemoryUnresolvedReason,
    NegativeMemoryViolation, WildcardApplicability, effect_class_text, migrate_legacy_fingerprint,
    negative_memory_record_defect,
};
pub use negative_memory_match::{
    ComparedScopeSource, DeclaredPageTotal, EnumerationCoverage, ExactMatch, IdentityRelation,
    IncompleteMatch, IncompleteReason, MatchEvidence, NEGATIVE_MEMORY_MATCH_SCHEMA_VERSION,
    NearMatch, NegativeMemoryCandidatePage, NegativeMemoryCandidateRead, NegativeMemoryMatchBound,
    NegativeMemoryMatchKind, NegativeMemoryMatchResult, NegativeMemoryOutcome,
    NegativeMemorySubject, PredicateComparison, ScopeComparison, match_negative_memory,
};
pub use policy::FailurePolicy;
pub use result::{
    FailureHandlerDecision, FailureResult, handler_port, propose_failure_fingerprint,
};

/// Stable registry identity for this handler.
pub const HANDLER_ID: &str = "eliot-dreamer-failure";
