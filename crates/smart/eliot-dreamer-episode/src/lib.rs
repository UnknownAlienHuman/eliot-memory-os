//! Pure Episode-specific curation candidate reconstruction.
//!
//! The handler consumes an already admitted A-03 item and immutable owner
//! snapshots. It joins Episode membership, boundaries, chronology, coverage,
//! participants, outcomes and rollback evidence without I/O or mutation.

#![forbid(unsafe_code)]

mod input;
mod reconstruct;
mod result;

pub use input::{
    BoundaryRule, EpisodeOutcome, EpisodeParticipant, EpisodePolicy, EventAndSourceSnapshot,
    EvidenceBinding, ExistingEpisodeMember, ExistingEpisodeSnapshot, GroundedEvent,
    GroundedEventSet, MaterialPreimage, OverlapRule, ValidatedCurationInput,
    event_material_preimage, outcome_material_preimage, participant_material_preimage,
    temporal_material_preimage,
};
pub use reconstruct::reconstruct_episode_candidate;
pub use result::{
    ChronologyLink, ChronologyRelation, EpisodeBoundary, EpisodeCandidate, EpisodeCoverage,
    EpisodeGap, EpisodeRollback, EpisodeStatus, OverlapAssessment, OverlapDisposition,
};
