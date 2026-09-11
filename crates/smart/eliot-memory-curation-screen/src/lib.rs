//! Protection-first, deterministic screening over one immutable A19c source.
//!
//! This package evaluates only supplied canonical records. It does not access a
//! Store, invoke a model, select a curation kind, or apply an action. The
//! current bounded rule surface is `provenance_gap_v1` and
//! `conflict_ambiguity_v1`; richer owner evidence remains an explicit gap.
//! One invocation consumes a complete observed source page and measures its
//! input as canonical JSON over request, source, and protection evidence.
//! Logical work is `members + evidence_records + members * profile_rules`.
//! Results carry the exact canonical output byte count. Cursor continuation,
//! page frontiers, live deadlines, cancellation grace, and owner authenticity
//! are intentionally outside this pure structural proof surface.

#![forbid(unsafe_code)]

mod bounds;
mod protection;
mod rules;
mod screen;

pub use bounds::{MAX_INPUT_BYTES, MAX_ITEMS, MAX_OUTPUT_BYTES, MAX_REFERENCES, MAX_WORK_UNITS};
pub use rules::{SUPPORTED_RULES, SupportedRule};
pub use screen::{CurationScreenError, screen_memory_curation};
