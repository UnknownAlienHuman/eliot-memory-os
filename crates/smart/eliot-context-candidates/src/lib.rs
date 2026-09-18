//! Whole Context candidates from seven exact provider projections.
//!
//! Issue #604 (A-16a): the single deterministic pure mapper from the current
//! recipe's seven immutable provider projections to bounded A-15
//! [`ContextCandidateSet`](eliot_context_contracts::ContextCandidateSet)
//! whole lineage-complete atoms:
//!
//! 1. Task Frame (opaque Governor-owned projection);
//! 2. Critical Attention / Conflict (`CriticalAttentionProjection` plus
//!    `ConflictSet`);
//! 3. A-06e `CurrentEpistemicPosition` (contracts only, never the legacy
//!    resolver);
//! 4. explicit A-10 `ActivationResult` (read, never produced: the
//!    `eliot-cue-activation` algorithm crate is never imported or called);
//! 5. negative memory (opaque Governor-owned projection);
//! 6. evidence envelopes plus `SourceAssurance`;
//! 7. affordance / capability (opaque Governor-owned projection).
//!
//! One disposition is emitted for every expected provider role, supplied
//! member and candidate. Atoms are whole units only: no split, summary,
//! truncation, rewrite or generation. The closed versioned
//! member-kind-to-semantic-role-to-loss-policy map lives in
//! [`vocabulary`]. Required and protected Safety-Floor representation is
//! reserved before optional volume (representation fairness, not admission);
//! explicit omissions and frontier are emitted on bounds. No query, ranking,
//! admission, assembly, delivery, authority, effect or Finish step runs here:
//! the output proposes material to A-17a admission.
//!
//! Absent Governor-owned schemas (Task Frame, negative memory, affordance)
//! cross as opaque versioned role handles. A missing required projection
//! stays an explicit missing/partial disposition, never filler.
//!
//! Issue #43 designs the eighth applicable-memory slot at the input boundary
//! ([`MemoryInput`], [`eight_slots`]): the slot shape, availability mapping,
//! and denominator check land here, while mapper adoption of the eight-slot
//! denominator waits for #41 to merge. The mapped denominator stays seven.

#![forbid(unsafe_code)]

pub mod derive;
pub mod inputs;
pub mod mapper;
pub mod vocabulary;

pub use derive::{
    assurance_member_id, attention_member_id, conflict_member_id, derived_member_id,
    direct_member_id, envelope_member_id, epistemic_member_id,
};
pub use eliot_context_contracts::ContextError;
pub use inputs::{
    AttentionInput, CandidateBounds, CandidatePolicy, CandidateRequest, CueActivationResult,
    CueInput, EpistemicInput, EvidenceInput, MAX_MEMORY_CUE_HITS, MEMORY_PROVIDER,
    MemberMeasurement, MemoryExclusion, MemoryInput, OpaqueMember, OpaqueProjection,
    ProjectionSchema, ProjectionState, check_denominator_is_seven_or_eight, eight_slots,
    memory_availability,
};
pub use mapper::{
    ContextCandidateSetResult, FrontierRecord, MAX_FRONTIER_TEXT_BYTES, MemberDisposition,
    MemberOutcome, RoleDisposition, construct_context_candidates,
};
pub use vocabulary::{
    CANDIDATE_SCHEMA_VERSION, KIND_MAP_VERSION, PROVIDER_AFFORDANCE, PROVIDER_ATTENTION,
    PROVIDER_CUE, PROVIDER_EPISTEMIC, PROVIDER_EVIDENCE, PROVIDER_NEGATIVE_MEMORY,
    PROVIDER_TASK_FRAME, kind_rule, role_rank, seven_slots,
};
