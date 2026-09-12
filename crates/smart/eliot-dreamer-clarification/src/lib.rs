//! Pure deterministic owner of zero or one atomic clarification candidate.
//!
//! The crate consumes an admitted clarification job, an A-03 validated draft,
//! and an owner-neutral active-agent/Human-boundary projection. It emits an
//! inert candidate or an explicit no-question/blocked/decomposition result.
//! It owns no transport, answer handling, authentication, attention delivery,
//! provider call, Store access, mutation, authority, effect, or Finish path.

#![forbid(unsafe_code)]

mod error;
mod model;
mod select;

pub use error::ClarificationError;
pub use model::{
    ActiveAgentBoundary, ActiveAgentOrHumanBoundary, AdmittedClarificationJob,
    AmbiguityAccounting, AmbiguityAccountingStatus, AmbiguityState, AnswerBranch,
    AnswerMatcher, AnswerOption, AnswerSchema, CandidateInvalidation, ClarificationAmbiguity,
    ClarificationCandidate, ClarificationContentClass, ClarificationDecision,
    ClarificationDisposition, ClarificationPolicy, DecisionOwner, DecisionVariable, HumanBoundary,
    HumanDecisionKind, MaterialityBasis, MaterialityEvidence, NoQuestionReason, NonAnswerBranches,
    ReferenceKind, RoutingRecommendation, SourceDenominator, UnansweredFallback,
    CLARIFICATION_PROOF_CEILING, CLARIFICATION_SCHEMA_VERSION, HARD_MAX_AMBIGUITIES,
    HARD_MAX_OPTIONS, HARD_MAX_OUTPUT_BYTES, HARD_MAX_TEXT_BYTES,
};
pub use select::propose_clarification;

#[cfg(test)]
mod tests;
