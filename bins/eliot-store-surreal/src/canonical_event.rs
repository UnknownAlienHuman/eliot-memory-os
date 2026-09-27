//! Store-neutral canonical-event contract, re-exported unchanged.
//!
//! Issue #1931 (`I5-audit`) defines the canonical event, its per-scope hash
//! links, the committed-transition atomicity bundle, and the fenced projection
//! publication in the store-neutral contract crate
//! [`eliot_store_api::canonical_event`], because the admitted Surreal adapter
//! that must commit them is upstream of this composition binary in the
//! dependency graph. This file exists only to keep the bridge's public path
//! `eliot_store_surreal::*` stable; it owns no contract, no durable state, and
//! no canonical-write semantics, exactly as `bins/AGENTS.md` requires of a
//! composition root.

pub use eliot_store_api::canonical_event::{
    CanonicalEvent, CommittedCanonicalTransition, DoctorRebuildAuthority,
    FencedProjectionPublication, ORDERING_LINK_GENESIS_HASH, OrderingLink, ProjectionRebuildPlan,
    SemanticWritePath, ordering_link_hash, request_projection_rebuild,
    request_rebuild_from_semantic_write,
};
