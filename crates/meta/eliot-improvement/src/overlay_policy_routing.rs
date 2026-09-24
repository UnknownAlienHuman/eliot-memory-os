//! Routing for overlay-rejected task-level policy changes.
//!
//! A local overlay may change only bounded search or probe stopping rules and
//! verification ordering within the current task plan (S220). Any other
//! surface — task-level stop, finish, acceptance, cancellation, budget, or
//! authority policy — must not be applied by the Context Compiler alone.
//!
//! This module is the fail-closed complement to the overlay composer in
//! `eliot-learning-overlay/src/changes.rs`, which accepts only
//! `VerificationOrder` and `SearchProbeStopping` surfaces. Everything that
//! composer rejects as a non-local surface is routed here into an
//! [`ImprovementCandidateDraft`]: a pure data carrier that the caller must
//! promote as an Improvement or plan candidate through a Task Controller plan
//! revision plus Governor admission via the normal authority path (S220b).
//!
//! The function takes plain `&str` surface/target names so this crate gains
//! no new dependency on `eliot-learning-contracts`.

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};

/// Advisory draft for a task-level policy change rejected from the local overlay path.
///
/// The draft records lineage (`source_overlay_id`, `source_delta_id`,
/// `task_id`) plus the rejected surface/target and a human-readable
/// `policy_summary`. It carries no authority: promotion requires a Task
/// Controller plan revision plus Governor admission through the normal
/// authority path, and it is never applied by the Context Compiler alone.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ImprovementCandidateDraft {
    /// Overlay the rejected change was proposed against.
    pub source_overlay_id: String,
    /// Source delta that carried the rejected change.
    pub source_delta_id: String,
    /// Non-local surface that was rejected (verbatim caller spelling).
    pub rejected_surface: String,
    /// Change target that was rejected (verbatim caller spelling).
    pub rejected_target: String,
    /// Short summary directing the change at the Improvement/plan-candidate path.
    pub policy_summary: String,
    /// Owning task the candidate must be filed against.
    pub task_id: String,
}

/// Route a composer-rejected surface to the Improvement/plan-candidate path.
///
/// Returns `Ok` draft for any non-local surface (everything except
/// `VerificationOrder` / `SearchProbeStopping`, matched case-insensitively
/// in either `PascalCase` or `SCREAMING_SNAKE_CASE` spelling) and
/// `Err("local_surface")` for local surfaces, which stay in the overlay
/// path and must not be filed as Improvement candidates from here.
///
/// The returned draft is advisory only: the caller must still obtain a Task
/// Controller plan revision plus Governor admission through the normal
/// authority path before the change takes effect.
///
/// # Errors
///
/// Returns `Err("local_surface")` when `surface` names a local overlay
/// surface, or `Err("empty_field")` when any input is blank.
pub fn route_rejected_surface(
    surface: &str,
    target: &str,
    source_overlay_id: &str,
    source_delta_id: &str,
    task_id: &str,
) -> Result<ImprovementCandidateDraft, &'static str> {
    if is_local_surface(surface) {
        return Err("local_surface");
    }
    if surface.trim().is_empty()
        || target.trim().is_empty()
        || source_overlay_id.trim().is_empty()
        || source_delta_id.trim().is_empty()
        || task_id.trim().is_empty()
    {
        return Err("empty_field");
    }
    let policy_summary = format!(
        "task-level policy change rejected from local overlay path: surface={surface} target={target}; \
         file as Improvement or plan candidate via Task Controller plan revision plus Governor admission"
    );
    Ok(ImprovementCandidateDraft {
        source_overlay_id: source_overlay_id.to_owned(),
        source_delta_id: source_delta_id.to_owned(),
        rejected_surface: surface.to_owned(),
        rejected_target: target.to_owned(),
        policy_summary,
        task_id: task_id.to_owned(),
    })
}

/// Whether `surface` names a local overlay surface.
///
/// Accepts `VerificationOrder` / `SearchProbeStopping` in `PascalCase` or
/// `VERIFICATION_ORDER` / `SEARCH_PROBE_STOPPING` (`SCREAMING_SNAKE_CASE`,
/// the contract wire spelling), matched case-insensitively with underscores
/// ignored so both spellings fail closed to the same set the overlay
/// composer admits.
fn is_local_surface(surface: &str) -> bool {
    let normalized: String = surface
        .chars()
        .filter(|c| *c != '_')
        .flat_map(|c| c.to_uppercase())
        .collect();
    normalized == "VERIFICATIONORDER" || normalized == "SEARCHPROBESTOPPING"
}
