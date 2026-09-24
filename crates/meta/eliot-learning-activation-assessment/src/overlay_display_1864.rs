//! Read-only display bundle for one admitted nontrivial overlay revision.
//!
//! An attempt with an admitted nontrivial overlay can display the immutable
//! overlay revision, parent, source delta, pre-evaluation prediction, expected
//! observable, regressions/confounders, preserved-success constraint, next
//! discriminator, and rollback condition. This item was missing on `main`.
//!
//! The display mirrors the S209 frozen pre-evaluation fields carried by the
//! sibling writer's
//! [`FrozenPreEvaluation`](eliot_learning_overlay::freeze::FrozenPreEvaluation)
//! bundle (`intended_mechanism` is represented here through the immutable
//! `revision`/`parent`/`source_delta` lineage triple; the remaining frozen
//! fields map one-to-one onto the prediction, observable, regression,
//! preserved-success, discriminator, and rollback slots below). Field order
//! and names here are display-only; durable identity always comes from the
//! overlay canonical digest, never from this display text.
//!
//! Callers must pass only sealed-digest-covered immutable sources (the
//! admitted [`CampaignHarnessOverlayCandidate`](eliot_learning_contracts::CampaignHarnessOverlayCandidate)
//! identity, revision, parent revision, and admitted delta identities, plus
//! the frozen pre-evaluation texts bound by
//! [`frozen_digest`](eliot_learning_overlay::freeze::frozen_digest)) and must
//! fail closed on any digest mismatch before rendering. This constructor
//! rejects blank inputs instead of fabricating display text, but it cannot
//! re-verify the seal itself: the plain-string signature deliberately avoids
//! cross-crate type dependencies, so seal verification stays with the caller.
//!
//! Pure constructor: no I/O, no new dependencies, no `unsafe`.

/// Immutable display bundle for one admitted nontrivial overlay revision.
///
/// Every field is a caller-supplied immutable string. All nine fields are
/// guaranteed non-empty after [`display_admitted_overlay`] succeeds.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OverlayDisplay {
    /// Immutable overlay identity pinned to its monotonic revision
    /// (`"<overlay_id>#<revision>"`).
    pub revision: String,
    /// Parent task revision the overlay was evaluated against.
    pub parent: String,
    /// Comma-joined admitted source delta identities.
    pub source_delta: String,
    /// Outcome predicted when the intended mechanism holds.
    pub prediction: String,
    /// Observable that would confirm the prediction.
    pub expected_observable: String,
    /// Combined regressions/confounders text (`"regressions: …; confounders: …"`).
    pub regressions_confounds: String,
    /// Success that must be preserved for the revision to be acceptable.
    pub preserved_success: String,
    /// Discriminator selecting the next probe when the revision is inconclusive.
    pub next_discriminator: String,
    /// Condition under which the revision must be rolled back.
    pub rollback_condition: String,
}

/// Immutable inputs for building one admitted-overlay display bundle.
///
/// The plain-string shape deliberately avoids cross-crate type dependencies:
/// callers pass sealed-digest-covered immutable sources and must fail closed
/// on any digest mismatch before calling. Seal verification stays with the
/// caller.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OverlayDisplayInput<'a> {
    /// Admitted overlay candidate identity.
    pub overlay_id: &'a str,
    /// Monotonic overlay revision (starts at 1; zero is rejected).
    pub revision: u32,
    /// Parent task revision the overlay was evaluated against.
    pub parent_revision: &'a str,
    /// Admitted source delta identities (nonempty, no blanks).
    pub admitted_delta_ids: &'a [String],
    /// Outcome predicted when the intended mechanism holds.
    pub prediction: &'a str,
    /// Observable that would confirm the prediction.
    pub expected_observable: &'a str,
    /// Plausible regressions the revision could cause.
    pub regressions: &'a str,
    /// Known confounders that could mimic or mask the observable.
    pub confounders: &'a str,
    /// Success that must be preserved for the revision to be acceptable.
    pub preserved_success: &'a str,
    /// Discriminator selecting the next probe when inconclusive.
    pub next_discriminator: &'a str,
    /// Condition under which the revision must be rolled back.
    pub rollback_condition: &'a str,
}

/// Build the display bundle for one admitted nontrivial overlay revision.
///
/// A `revision` of zero (the overlay candidate clock starts at 1) is rejected
/// as a nontriviality violation.
///
/// # Errors
///
/// Returns a `&'static str` naming the first rejected field class when
/// `overlay_id` or `parent_revision` is blank, `revision` is zero,
/// `admitted_delta_ids` is empty or holds a blank identity, or any frozen
/// pre-evaluation text (`prediction`, `expected_observable`, `regressions`,
/// `confounders`, `preserved_success`, `next_discriminator`,
/// `rollback_condition`) is blank.
pub fn display_admitted_overlay(
    input: &OverlayDisplayInput<'_>,
) -> Result<OverlayDisplay, &'static str> {
    let overlay_id = input.overlay_id;
    let revision = input.revision;
    let parent_revision = input.parent_revision;
    let admitted_delta_ids = input.admitted_delta_ids;
    let prediction = input.prediction;
    let expected_observable = input.expected_observable;
    let regressions = input.regressions;
    let confounders = input.confounders;
    let preserved_success = input.preserved_success;
    let next_discriminator = input.next_discriminator;
    let rollback_condition = input.rollback_condition;
    if overlay_id.trim().is_empty() {
        return Err("overlay_id");
    }
    if revision == 0 {
        return Err("revision");
    }
    if parent_revision.trim().is_empty() {
        return Err("parent_revision");
    }
    if admitted_delta_ids.is_empty() {
        return Err("admitted_delta_ids");
    }
    for id in admitted_delta_ids {
        if id.trim().is_empty() {
            return Err("admitted_delta_ids");
        }
    }
    if prediction.trim().is_empty() {
        return Err("prediction");
    }
    if expected_observable.trim().is_empty() {
        return Err("expected_observable");
    }
    if regressions.trim().is_empty() {
        return Err("regressions");
    }
    if confounders.trim().is_empty() {
        return Err("confounders");
    }
    if preserved_success.trim().is_empty() {
        return Err("preserved_success");
    }
    if next_discriminator.trim().is_empty() {
        return Err("next_discriminator");
    }
    if rollback_condition.trim().is_empty() {
        return Err("rollback_condition");
    }
    let display = OverlayDisplay {
        revision: format!("{}#{revision}", overlay_id.trim()),
        parent: parent_revision.trim().to_string(),
        source_delta: admitted_delta_ids.join(","),
        prediction: prediction.trim().to_string(),
        expected_observable: expected_observable.trim().to_string(),
        regressions_confounds: format!(
            "regressions: {}; confounders: {}",
            regressions.trim(),
            confounders.trim()
        ),
        preserved_success: preserved_success.trim().to_string(),
        next_discriminator: next_discriminator.trim().to_string(),
        rollback_condition: rollback_condition.trim().to_string(),
    };
    Ok(display)
}
