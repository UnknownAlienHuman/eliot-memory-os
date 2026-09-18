//! Bounded candidate-only self-quality diagnosis (A-38, agent order 38).
//!
//! This crate diagnoses one frozen [`SelfQualityInput`] snapshot into either a
//! validated [`SelfQualityDiagnosisCandidate`] or an explicit non-candidate
//! disposition, with inert [`SelfQualityHandoff`] refs to external owners. It
//! performs no Concilium planning, vote tally, source acquisition, probe
//! execution, mutation, authority issuance, effect, store access, provider or
//! model calls, clock reads, or finish handling: see [`PROOF_CEILING`].
//!
//! The normative vocabulary lives in `eliot-conformance-contracts`
//! (`self_quality.rs`, issue #971, contract version 1) and is re-exported here
//! for consumers; this crate never re-defines it.

#![forbid(unsafe_code)]

pub mod diagnose;
pub mod error;
pub mod identity;
pub mod routing;

pub use diagnose::{SelfQualityOutcome, diagnose_self_quality};
pub use error::SelfQualityError;
pub use identity::{
    CAUSAL_PROPERTY, CRATE_NAME, META_AGENT_ORDER, MODULE_ID, PROOF_CEILING, RUNTIME_LAYER,
    SOURCE_LAYER, module_digest,
};
pub use routing::{make_handoff, route_owner};

pub use eliot_conformance_contracts::{
    BlockedDiagnosis, CauseHypothesisStatus, ConflictedDiagnosis, DenominatorCompleteness,
    DimensionOutcome, DimensionStatus, EvidenceCeilings, IncompleteDiagnosis, InterventionState,
    MetricMeasurement, MetricPresence, NoActionDisposition, NoProblemDisposition, ObservationCore,
    ObservationWindow, OwnerBinding, PriorDiagnosisRecord, Priority, ProductContractRef,
    QualityDenominator, QualityLimits, Recurrence, SELF_QUALITY_CANDIDATE_SCHEMA,
    SELF_QUALITY_CONTRACT_VERSION, SELF_QUALITY_HANDOFF_SCHEMA, SELF_QUALITY_SCHEMA,
    SelfQualityContractError, SelfQualityDiagnosisCandidate, SelfQualityDimension,
    SelfQualityHandoff, SelfQualityHandoffOwner, SelfQualityInput, SelfQualityObservation,
    SelfQualityPolicy, Severity, SourceIdentity, UnknownDiagnosis, digest_candidate,
    digest_self_quality_input, digest_self_quality_policy, validate_blocked_against_input,
    validate_candidate_against_input, validate_conflicted_against_input,
    validate_dimension_outcome, validate_handoff, validate_handoff_set,
    validate_incomplete_against_input, validate_no_action_against_input,
    validate_no_problem_against_input, validate_self_quality_input, validate_unknown_against_input,
};
