//! Frozen pre-evaluation manifest-equivalent fields for one nontrivial overlay revision.
//!
//! For every nontrivial revision, the changed-artifact, intended-mechanism,
//! prediction, expected-observable, regression/confounder, preserved-success
//! and next-discriminator fields are frozen **before** evaluation. Together
//! with the source [`AttemptLearningDeltaCandidate`](eliot_learning_contracts::AttemptLearningDeltaCandidate),
//! the activation receipt and the closure lineage, they carry the donor
//! `HarnessChangeManifest` semantics; no separate mutable manifest record and
//! no second change owner are created.
//!
//! This module defines only the frozen field bundle plus its canonical text
//! and digest helpers. It introduces no new persisted record type and no
//! `HarnessChangeManifest` struct. The caller persists the frozen fields (and
//! the [`frozen_digest`] value binding them to the overlay identity and
//! canonical digest) on the overlay itself, the source delta, the activation
//! receipt and the eventual closure lineage before any evaluation runs. The
//! overlay [`seal`](eliot_learning_contracts::CampaignHarnessOverlayCandidate::seal)
//! covers the canonical digest, so equality of the frozen digest proves the
//! fields were fixed pre-evaluation.

use eliot_learning_contracts::LearningContractError;

use crate::OverlayError;

/// Maximum characters accepted in one frozen pre-evaluation field.
pub const MAX_FROZEN_FIELD_CHARS: usize = 8192;
/// Maximum total characters accepted across all frozen pre-evaluation fields.
pub const MAX_FROZEN_TOTAL_CHARS: usize = 65_536;

/// Manifest-equivalent fields frozen before any evaluation of a nontrivial overlay revision.
///
/// This is a field bundle only, not a persisted record: the integrator stores
/// these values on the overlay itself, the source delta, the activation
/// receipt and the closure lineage. It must never grow a second change owner
/// or a separate mutable manifest type.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FrozenPreEvaluation {
    /// Causal mechanism the revision intends to exercise.
    pub intended_mechanism: String,
    /// Outcome predicted when the mechanism holds.
    pub prediction: String,
    /// Observable that would confirm the prediction.
    pub expected_observable: String,
    /// Regressions the revision could plausibly cause.
    pub possible_regressions: String,
    /// Known confounders that could mimic or mask the observable.
    pub confounders: String,
    /// Success that must be preserved for the revision to be acceptable.
    pub preserved_success_constraint: String,
    /// Discriminator text selecting the next probe when this revision is inconclusive.
    pub next_discriminator_text: String,
    /// Condition under which the revision must be rolled back.
    pub rollback_condition: String,
}

impl FrozenPreEvaluation {
    /// Validate that every frozen field is present, bounded, and tied to a nontrivial revision.
    ///
    /// Nontrivial means the candidate carries at least one change; an empty
    /// revision is rejected by the composer and the overlay contracts, and is
    /// reported here with the same `overlay.changes` field class. Empty frozen
    /// text fails as a missing-field contract error; oversize text fails as a
    /// bound error.
    ///
    /// # Errors
    ///
    /// Returns [`OverlayError::Contract`] when `change_count` is zero or a
    /// frozen field is blank, and [`OverlayError::Bound`] when a field or the
    /// field total exceeds its character ceiling.
    pub fn validate_nontrivial(&self, change_count: usize) -> Result<(), OverlayError> {
        if change_count == 0 {
            return Err(OverlayError::Contract(LearningContractError::Missing {
                field: "overlay.changes",
            }));
        }
        check_field(&self.intended_mechanism, "frozen.intended_mechanism")?;
        check_field(&self.prediction, "frozen.prediction")?;
        check_field(&self.expected_observable, "frozen.expected_observable")?;
        check_field(&self.possible_regressions, "frozen.possible_regressions")?;
        check_field(&self.confounders, "frozen.confounders")?;
        check_field(
            &self.preserved_success_constraint,
            "frozen.preserved_success_constraint",
        )?;
        check_field(
            &self.next_discriminator_text,
            "frozen.next_discriminator_text",
        )?;
        check_field(&self.rollback_condition, "frozen.rollback_condition")?;
        let mut total: usize = 0;
        for value in [
            &self.intended_mechanism,
            &self.prediction,
            &self.expected_observable,
            &self.possible_regressions,
            &self.confounders,
            &self.preserved_success_constraint,
            &self.next_discriminator_text,
            &self.rollback_condition,
        ] {
            total = total
                .checked_add(value.chars().count())
                .ok_or(OverlayError::Bound {
                    field: "frozen.total",
                })?;
        }
        if total > MAX_FROZEN_TOTAL_CHARS {
            return Err(OverlayError::Bound {
                field: "frozen.total",
            });
        }
        Ok(())
    }
}

/// Render the canonical frozen representation of the pre-evaluation fields.
///
/// Each field is emitted in struct order as `name:byte_len:value` on its own
/// line under a version header. The byte-length prefix keeps embedded
/// newlines from desynchronising the record, so the text is a deterministic
/// function of the frozen fields. The integrator hashes this text into the
/// overlay seal path before any evaluation runs.
#[must_use]
pub fn freeze_before_evaluation_text(frozen: &FrozenPreEvaluation) -> String {
    let mut text = String::from("frozen-pre-evaluation/v1\n");
    push_field(&mut text, "intended_mechanism", &frozen.intended_mechanism);
    push_field(&mut text, "prediction", &frozen.prediction);
    push_field(
        &mut text,
        "expected_observable",
        &frozen.expected_observable,
    );
    push_field(
        &mut text,
        "possible_regressions",
        &frozen.possible_regressions,
    );
    push_field(&mut text, "confounders", &frozen.confounders);
    push_field(
        &mut text,
        "preserved_success_constraint",
        &frozen.preserved_success_constraint,
    );
    push_field(
        &mut text,
        "next_discriminator_text",
        &frozen.next_discriminator_text,
    );
    push_field(&mut text, "rollback_condition", &frozen.rollback_condition);
    text
}

/// Bind the frozen fields to one overlay identity and overlay canonical digest.
///
/// The digest reuses the existing [`eliot_contracts::sha256_hex`] helper (the
/// same primitive behind `digest_without_field`); no new hash dependency is
/// introduced. Because the overlay `seal()` covers `canonical_digest`, a
/// stored `frozen_digest` that still matches at evaluation time proves the
/// manifest-equivalent fields were frozen before evaluation.
#[must_use]
pub fn frozen_digest(
    frozen: &FrozenPreEvaluation,
    overlay_id: &str,
    canonical_digest: &str,
) -> String {
    let text = freeze_before_evaluation_text(frozen);
    let mut bytes = Vec::with_capacity(
        overlay_id
            .len()
            .saturating_add(canonical_digest.len())
            .saturating_add(text.len())
            .saturating_add(2),
    );
    bytes.extend_from_slice(overlay_id.as_bytes());
    bytes.push(0);
    bytes.extend_from_slice(canonical_digest.as_bytes());
    bytes.push(0);
    bytes.extend_from_slice(text.as_bytes());
    eliot_contracts::sha256_hex(&bytes)
}

fn check_field(value: &str, field: &'static str) -> Result<(), OverlayError> {
    if value.trim().is_empty() {
        return Err(OverlayError::Contract(LearningContractError::Missing {
            field,
        }));
    }
    if value.chars().count() > MAX_FROZEN_FIELD_CHARS {
        return Err(OverlayError::Bound { field });
    }
    Ok(())
}

fn push_field(text: &mut String, name: &str, value: &str) {
    text.push_str(name);
    text.push(':');
    text.push_str(&value.len().to_string());
    text.push(':');
    text.push_str(value);
    text.push('\n');
}
