//! Append-only ledger of observable influence, per Implementation I16.13
//! (`docs/architecture/I16-13-influence-tracking.md`).
//!
//! The ledger records only what was explicitly observed about one
//! memory/context item: a delivery, an acknowledgement, an expansion, a
//! citation inside an `ActionFrame`/decision, a changed selected action or
//! verifier, the prevention of an exact failed path, and a later outcome that
//! contradicted, showed irrelevant, or showed the item harmful.
//!
//! Two properties are structural rather than advisory:
//!
//! - Influence is never inferred from co-presence in context.  There is no
//!   variant, constructor, or field that turns "the item was available" into a
//!   record: every [`InfluenceObservation`] carries the handle of the specific
//!   explicit observation it reports, so a delivered-only item cannot be
//!   presented as a cited one.  Success after inclusion is not causal credit.
//! - The ledger is append-only.  An admitted entry is never removed or
//!   rewritten; a later [`InfluenceLaterOutcome`] is a new entry that refers to
//!   the earlier one, so the original record and the later outcome both stay
//!   readable.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::field_policy::{RedactedHandle, is_handle_value_for_family};
use super::{
    BufferDisposition, ObservabilityError, TraceContext, text, unique, validate_clock, validate_id,
};
use eliot_contracts::ClockReading;

/// Classification of a later outcome observed for an earlier entry.
#[derive(
    Clone, Copy, Debug, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum InfluenceLaterOutcome {
    /// A user, tool, or observed outcome contradicted the earlier record.
    Contradicted,
    /// A later observation showed the item was irrelevant to the outcome.
    Irrelevant,
    /// A later observation showed the item was harmful.
    Harmful,
}

/// The only observations the ledger can record.
///
/// Each variant names the specific explicit observation it reports, so no
/// variant can be built from co-presence in context.  A claimed verifier
/// change carries both the prior and the selected verifier handle as
/// non-optional fields, so that stronger claim cannot be recorded without both
/// handles.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", tag = "observation")]
pub enum InfluenceObservation {
    /// The item was delivered into the operation's context.
    Delivered {
        /// Handle of the recorded delivery.
        delivery_ref: String,
    },
    /// The delivered item was explicitly acknowledged.
    Acknowledged {
        /// Handle of the recorded acknowledgement.
        acknowledgement_ref: String,
    },
    /// The delivered item was explicitly expanded by a reader.
    Expanded {
        /// Handle of the recorded expansion.
        expansion_ref: String,
    },
    /// The item was explicitly cited inside an `ActionFrame`/decision.
    CitedInDecision {
        /// Handle of the `ActionFrame`/decision that cited the item.
        decision_ref: String,
        /// Handle of the exact citation inside that decision.
        citation_ref: String,
    },
    /// The item changed the selected action.
    ChangedAction {
        /// Handle of the selected action.
        selected_action_ref: String,
    },
    /// The item changed the selected verifier.
    ChangedVerifier {
        /// Handle of the verifier selected before the change.
        prior_verifier_ref: String,
        /// Handle of the verifier selected after the change.
        selected_verifier_ref: String,
    },
    /// The item prevented one exact failed action/outcome path.
    PreventedExactFailure {
        /// Handle of the exact failed path that was prevented.
        prevented_path_ref: String,
    },
    /// A later observation contradicted, ignored, or harmed an earlier entry.
    ///
    /// The earlier entry stays exactly as recorded; this entry is the only
    /// record of the later outcome and refers to the entry it is about.
    LaterOutcome {
        /// Handle of the earlier entry this outcome is about.
        about_entry_ref: String,
        /// Which later outcome was observed.
        outcome: InfluenceLaterOutcome,
        /// Handle of the user/tool/outcome observation behind it.
        outcome_ref: String,
    },
}

impl InfluenceObservation {
    fn validate(&self) -> Result<(), ObservabilityError> {
        match self {
            Self::Delivered { delivery_ref } => {
                non_blank(&[("influence.delivery_ref", delivery_ref.as_str())])
            }
            Self::Acknowledged {
                acknowledgement_ref,
            } => non_blank(&[(
                "influence.acknowledgement_ref",
                acknowledgement_ref.as_str(),
            )]),
            Self::Expanded { expansion_ref } => {
                non_blank(&[("influence.expansion_ref", expansion_ref.as_str())])
            }
            Self::CitedInDecision {
                decision_ref,
                citation_ref,
            } => non_blank(&[
                ("influence.decision_ref", decision_ref.as_str()),
                ("influence.citation_ref", citation_ref.as_str()),
            ]),
            Self::ChangedAction {
                selected_action_ref,
            } => non_blank(&[(
                "influence.selected_action_ref",
                selected_action_ref.as_str(),
            )]),
            Self::ChangedVerifier {
                prior_verifier_ref,
                selected_verifier_ref,
            } => non_blank(&[
                ("influence.prior_verifier_ref", prior_verifier_ref.as_str()),
                (
                    "influence.selected_verifier_ref",
                    selected_verifier_ref.as_str(),
                ),
            ]),
            Self::PreventedExactFailure { prevented_path_ref } => {
                non_blank(&[("influence.prevented_path_ref", prevented_path_ref.as_str())])
            }
            Self::LaterOutcome {
                about_entry_ref,
                outcome_ref,
                ..
            } => non_blank(&[
                ("influence.about_entry_ref", about_entry_ref.as_str()),
                ("influence.outcome_ref", outcome_ref.as_str()),
            ]),
        }
    }
}

fn non_blank(refs: &[(&'static str, &str)]) -> Result<(), ObservabilityError> {
    for (field, value) in refs {
        text(value, field)?;
    }
    Ok(())
}

/// One immutable observable-influence observation.
///
/// The entry is a projection of what was observed; it is not a durable audit
/// receipt, a verifier result, or a claim of benefit.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InfluenceEntry {
    /// Stable identity of this ledger entry.
    pub entry_id: String,
    /// The memory/context item this observation is about.
    pub item_ref: String,
    /// Correlated run lineage of the observing operation.
    pub trace: TraceContext,
    /// When the observation was made.
    pub observed_at: ClockReading,
    /// Immutable redacted evidence handles backing the observation.
    pub evidence_handles: Vec<RedactedHandle>,
    /// The explicit observation itself.
    pub observation: InfluenceObservation,
}

impl InfluenceEntry {
    /// Validates identity, lineage, evidence handles and the observation.
    pub fn validate(&self) -> Result<(), ObservabilityError> {
        validate_id(&self.entry_id, "influence.entry_id")?;
        text(&self.item_ref, "influence.item_ref")?;
        self.trace.validate()?;
        validate_clock(&self.observed_at, "influence.observed_at")?;
        if self.evidence_handles.is_empty() {
            return Err(ObservabilityError::Empty {
                field: "influence.evidence_handles",
            });
        }
        unique(
            self.evidence_handles
                .iter()
                .map(|handle| handle.handle.as_str()),
            "influence.evidence_handles",
        )?;
        for handle in &self.evidence_handles {
            if !is_handle_value_for_family(&handle.handle, handle.family) {
                return Err(ObservabilityError::InvalidField {
                    field: "influence.evidence_handles.handle",
                    reason: "must be a structurally valid redacted handle for its family",
                });
            }
        }
        self.observation.validate()
    }
}

/// Append-only ledger of observable influence.
///
/// An admitted entry is never removed or rewritten.  Re-admitting the
/// identical entry is an idempotent replay; re-using one
/// [`InfluenceEntry::entry_id`] for different bytes is refused as
/// [`ObservabilityError::IdentityConflict`], so an earlier observation can
/// only ever be superseded by a later entry.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct InfluenceLedger {
    entries: Vec<InfluenceEntry>,
}

impl InfluenceLedger {
    /// Creates an empty append-only ledger.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Appends one validated observation and preserves every earlier entry.
    ///
    /// The result is the crate's append disposition: a new entry is
    /// [`BufferDisposition::Accepted`], an identical re-admission is
    /// [`BufferDisposition::Replayed`], and a re-used identity with different
    /// bytes is refused rather than rewritten.
    ///
    /// A [`InfluenceObservation::LaterOutcome`] is admitted only when the entry
    /// it is about is already present, so the original observation and its
    /// later outcome always stay readable together.
    pub fn append(
        &mut self,
        entry: InfluenceEntry,
    ) -> Result<BufferDisposition, ObservabilityError> {
        entry.validate()?;
        if let InfluenceObservation::LaterOutcome {
            about_entry_ref, ..
        } = &entry.observation
            && !self
                .entries
                .iter()
                .any(|existing| &existing.entry_id == about_entry_ref)
        {
            return Err(ObservabilityError::InvalidField {
                field: "influence.about_entry_ref",
                reason: "a later outcome must refer to an entry already in the ledger",
            });
        }
        match self
            .entries
            .iter()
            .find(|existing| existing.entry_id == entry.entry_id)
        {
            Some(existing) if *existing == entry => Ok(BufferDisposition::Replayed),
            Some(_) => Err(ObservabilityError::IdentityConflict),
            None => {
                self.entries.push(entry);
                Ok(BufferDisposition::Accepted)
            }
        }
    }

    /// Returns every entry in append order.
    #[must_use]
    pub fn entries(&self) -> &[InfluenceEntry] {
        &self.entries
    }

    /// Returns the recorded chain for one item, including an entry later
    /// contradicted, shown irrelevant, or shown harmful.
    #[must_use]
    pub fn entries_for_item(&self, item_ref: &str) -> Vec<&InfluenceEntry> {
        self.entries
            .iter()
            .filter(|entry| entry.item_ref == item_ref)
            .collect()
    }

    /// Returns the items explicitly cited inside one `ActionFrame`/decision.
    ///
    /// An item that was only delivered to that decision has no entry here,
    /// which is what separates a merely delivered item from one explicitly
    /// cited in the action decision.
    #[must_use]
    pub fn cited_in_decision(&self, decision_ref: &str) -> Vec<&InfluenceEntry> {
        self.entries
            .iter()
            .filter(|entry| {
                matches!(
                    &entry.observation,
                    InfluenceObservation::CitedInDecision {
                        decision_ref: cited,
                        ..
                    } if cited == decision_ref
                )
            })
            .collect()
    }
}
