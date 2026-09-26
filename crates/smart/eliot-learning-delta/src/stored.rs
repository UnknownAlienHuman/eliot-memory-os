//! Durable stored-delta record shape for consequential attempts.
//!
//! The durable edge from one consequential attempt to the next materially
//! related attempt. Every field is derived from owner records: the campaign,
//! attempt, State Fence, actor/route/overlay/artifact identity, the
//! consequential boundary that was observed, the applied strategy
//! fingerprint, the raw trace/evaluator references, the explicit retry
//! relation, and the disposition.

use std::collections::BTreeSet;

use eliot_contracts::{ArtifactId, StateFence};
use eliot_learning_contracts::{AgentAttemptId, CampaignId, OverlayId};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::boundary::ConsequentialBoundary;
use crate::{LearningDeltaError, RetryReason};

/// Durable disposition vocabulary for a stored learning delta.
///
/// Disposition vocabulary `LOCAL_UPDATE_ADMITTED` | `NEXT_PROBE_CHANGED` |
/// `REUSABLE_CANDIDATE_OPENED` | `NO_JUSTIFIED_CHANGE` | `INCONCLUSIVE` |
/// `INVALID_EVIDENCE`.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum StoredDeltaDisposition {
    /// A local update was admitted against this delta.
    LocalUpdateAdmitted,
    /// The next probe changed as a result of this delta.
    NextProbeChanged,
    /// A reusable candidate was opened from this delta.
    ReusableCandidateOpened,
    /// No justified change followed this delta.
    NoJustifiedChange,
    /// The attempt closed without a justified outcome.
    Inconclusive,
    /// The attempt closed on invalid evidence.
    InvalidEvidence,
}

/// Honest close dispositions for an attempt that yields no delta.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AttemptCloseDisposition {
    /// No justified change.
    NoJustifiedChange,
    /// The evidence does not support a justified outcome.
    Inconclusive,
    /// The evidence binding failed and cannot support a delta.
    InvalidEvidence,
}

impl AttemptCloseDisposition {
    /// Map a close disposition to its same-named stored disposition.
    pub const fn as_stored(self) -> StoredDeltaDisposition {
        match self {
            Self::NoJustifiedChange => StoredDeltaDisposition::NoJustifiedChange,
            Self::Inconclusive => StoredDeltaDisposition::Inconclusive,
            Self::InvalidEvidence => StoredDeltaDisposition::InvalidEvidence,
        }
    }
}

/// Whether a stored record's attempt is materially equivalent to the prior
/// attempt of the same campaign.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RetryEquivalence {
    /// The prior attempt is materially equivalent and an allowed
    /// unchanged-retry reason is recorded.
    Equivalent,
    /// The prior attempt is materially different from this one.
    Distinct,
    /// Neither equivalence nor difference can be asserted, so no behavioural
    /// change may follow from the relation.
    Unknown,
}

/// The exact comparison that produced a retry equivalence verdict.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RetryEquivalenceBasis {
    /// Current and prior canonical strategy fingerprints are equal.
    PriorFingerprintMatches,
    /// Current and prior canonical strategy fingerprints differ.
    PriorFingerprintDiffers,
    /// The prior canonical strategy fingerprint is unavailable.
    PriorFingerprintUnavailable,
}

/// Explicit retry relation retained by a stored delta whose attempt follows a
/// prior attempt in the same campaign.
///
/// I12.24 requires the relation to survive into the durable record: the prior
/// attempt identity, the prior durable delta, the prior canonical strategy
/// fingerprint, the prior observable and evidence references, and — when the
/// two attempts are materially equivalent — one of the allowed
/// unchanged-retry reasons. A verdict of [`RetryEquivalence::Equivalent`] is
/// refused without a declared reason, so a repeated strategy can never be
/// recorded as a controlled repeat by omission.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct StoredRetryRelation {
    /// Prior attempt identity in the same campaign.
    pub prior_attempt_id: AgentAttemptId,
    /// Durable delta artifact the prior attempt committed.
    pub prior_delta_artifact: ArtifactId,
    /// Canonical digest of the prior durable delta.
    pub prior_delta_digest: String,
    /// Canonical strategy fingerprint the prior attempt recorded.
    pub prior_fingerprint: String,
    /// Prior observable references retained for exact trace readback.
    pub prior_observable_refs: Vec<ArtifactId>,
    /// Prior evaluator/evidence references proving the relation.
    pub prior_evidence: Vec<ArtifactId>,
    /// The exact comparison that produced the verdict.
    pub basis: RetryEquivalenceBasis,
    /// Whether this attempt is materially equivalent to the prior one.
    pub equivalence: RetryEquivalence,
    /// Allowed unchanged-retry reason, present exactly when equivalent.
    pub unchanged_retry_reason: Option<RetryReason>,
}

impl StoredRetryRelation {
    /// Validate the prior lineage, the comparison basis, and the reason.
    pub fn validate(&self) -> Result<(), LearningDeltaError> {
        if self.prior_attempt_id.as_str().trim().is_empty()
            || self.prior_delta_artifact.as_str().trim().is_empty()
        {
            return Err(LearningDeltaError::InvalidInput {
                field: "retry.prior",
            });
        }
        for (value, field) in [
            (&self.prior_delta_digest, "retry.prior_digest"),
            (&self.prior_fingerprint, "retry.prior_fingerprint"),
        ] {
            if !is_lower_hex64(value) {
                return Err(LearningDeltaError::InvalidInput { field });
            }
        }
        require_non_empty_unique(&self.prior_observable_refs, "retry.prior_observable_refs")?;
        require_non_empty_unique(&self.prior_evidence, "retry.prior_evidence")?;
        // A declared equivalence must be backed by the matching fingerprint
        // observation and a declared distinctness by its opposite; `Unknown`
        // admits every basis because no fingerprint was established at all.
        // Any other pairing is incoherent and is refused rather than silently
        // downgraded to `Unknown`.
        match (self.equivalence, self.basis) {
            (RetryEquivalence::Equivalent, RetryEquivalenceBasis::PriorFingerprintMatches)
            | (RetryEquivalence::Distinct, RetryEquivalenceBasis::PriorFingerprintDiffers)
            | (
                RetryEquivalence::Unknown,
                RetryEquivalenceBasis::PriorFingerprintMatches
                | RetryEquivalenceBasis::PriorFingerprintDiffers
                | RetryEquivalenceBasis::PriorFingerprintUnavailable,
            ) => {}
            _ => {
                return Err(LearningDeltaError::InvalidInput {
                    field: "retry.equivalence",
                });
            }
        }
        match (self.equivalence, self.unchanged_retry_reason) {
            (RetryEquivalence::Equivalent, Some(_))
            | (RetryEquivalence::Unknown | RetryEquivalence::Distinct, None) => {}
            _ => {
                return Err(LearningDeltaError::InvalidInput {
                    field: "retry.unchanged_retry_reason",
                });
            }
        }
        Ok(())
    }
}

/// Durable stored-delta record naming its campaign, attempt, fence, and lineage.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct StoredLearningDelta {
    /// Named campaign this attempt belongs to.
    pub campaign_id: CampaignId,
    /// Attempt identity this record was derived from.
    pub attempt_id: AgentAttemptId,
    /// State fence the attempt executed under.
    pub state_fence: StateFence,
    /// Actor identity that produced the attempt.
    pub actor_id: String,
    /// Route identity that produced the attempt.
    pub route_id: String,
    /// Overlay identity the delta was evaluated against.
    pub overlay_id: OverlayId,
    /// Consequential boundary the owner observed to justify this record.
    pub consequential_boundary: ConsequentialBoundary,
    /// Canonical fingerprint of the strategy this attempt actually applied.
    pub strategy_fingerprint: String,
    /// Raw trace, artifact, and evaluator references observed for the attempt.
    pub evidence_refs: Vec<ArtifactId>,
    /// Artifact identity of the durable delta.
    pub delta_artifact: ArtifactId,
    /// Lowercase hex SHA-256 of the canonical closure binding this record
    /// commits, excluding this field itself.
    pub delta_digest: String,
    /// Explicit retry relation to the prior attempt of this campaign.
    pub retry_relation: Option<StoredRetryRelation>,
    /// Durable disposition of this stored record.
    pub disposition: StoredDeltaDisposition,
    /// Admission receipt identity; present only when the update was admitted.
    pub admission_receipt_id: Option<String>,
}

impl StoredLearningDelta {
    /// Validate identity, boundary, evidence, digest, lineage, and admission
    /// consistency.
    pub fn validate(&self) -> Result<(), LearningDeltaError> {
        for (value, field) in [
            (self.campaign_id.as_str(), "stored.campaign_id"),
            (self.attempt_id.as_str(), "stored.attempt_id"),
            (self.overlay_id.as_str(), "stored.overlay_id"),
            (self.delta_artifact.as_str(), "stored.delta_artifact"),
        ] {
            if value.trim().is_empty() {
                return Err(LearningDeltaError::InvalidInput { field });
            }
        }
        for (value, field) in [
            (self.actor_id.as_str(), "stored.actor_id"),
            (self.route_id.as_str(), "stored.route_id"),
        ] {
            if value.trim().is_empty() || value.chars().count() > 256 {
                return Err(LearningDeltaError::InvalidInput { field });
            }
        }
        self.state_fence
            .validate()
            .map_err(|_| LearningDeltaError::EvidenceBinding {
                field: "stored.state_fence",
            })?;
        for (value, field) in [
            (&self.delta_digest, "stored.delta_digest"),
            (&self.strategy_fingerprint, "stored.strategy_fingerprint"),
        ] {
            if !is_lower_hex64(value) {
                return Err(LearningDeltaError::InvalidInput { field });
            }
        }
        require_non_empty_unique(&self.evidence_refs, "stored.evidence_refs")?;
        if let Some(retry) = &self.retry_relation {
            retry.validate()?;
            if retry.prior_attempt_id == self.attempt_id {
                return Err(LearningDeltaError::InvalidInput {
                    field: "retry.prior_attempt",
                });
            }
        }
        match self.disposition {
            StoredDeltaDisposition::LocalUpdateAdmitted => {
                let Some(receipt) = self.admission_receipt_id.as_deref() else {
                    return Err(LearningDeltaError::InvalidInput {
                        field: "stored.admission",
                    });
                };
                if receipt.trim().is_empty() {
                    return Err(LearningDeltaError::InvalidInput {
                        field: "stored.admission",
                    });
                }
            }
            _ => {
                // A proposed/unclosed record must not claim admission.
                if self.admission_receipt_id.is_some() {
                    return Err(LearningDeltaError::InvalidInput {
                        field: "stored.admission",
                    });
                }
            }
        }
        Ok(())
    }

    /// The exact durable edge a retry's canonical evidence must reference.
    ///
    /// This is the prior attempt's lineage anchor: the artifact identity and
    /// the canonical digest of this committed record, never an unverified or
    /// reconstructed value.
    pub const fn lineage_ref(&self) -> (&ArtifactId, &str) {
        (&self.delta_artifact, self.delta_digest.as_str())
    }

    /// The explicit retry relation the next attempt inherits, if any.
    #[must_use]
    pub fn lineage_for_retry(&self) -> Option<&StoredRetryRelation> {
        self.retry_relation.as_ref()
    }

    /// Exact canonical evidence handles a materially related attempt must carry
    /// when it references this record: this attempt's own raw trace, artifact,
    /// and evaluator references plus the prior attempt's retained observable
    /// and evidence references.
    pub fn retry_canonical_evidence(&self) -> Vec<ArtifactId> {
        let mut refs = self.evidence_refs.clone();
        if let Some(retry) = &self.retry_relation {
            refs.extend(retry.prior_observable_refs.iter().cloned());
            refs.extend(retry.prior_evidence.iter().cloned());
        }
        refs.sort_by(|left, right| left.as_str().cmp(right.as_str()));
        refs.dedup();
        refs
    }

    /// Report whether this record carries an admitted local update.
    pub fn is_admitted(&self) -> bool {
        self.disposition == StoredDeltaDisposition::LocalUpdateAdmitted
    }
}

/// Require a non-empty, duplicate-free list of artifact identities.
fn require_non_empty_unique(
    refs: &[ArtifactId],
    field: &'static str,
) -> Result<(), LearningDeltaError> {
    if refs.is_empty() {
        return Err(LearningDeltaError::InvalidInput { field });
    }
    let mut seen = BTreeSet::new();
    for id in refs {
        if id.as_str().trim().is_empty() || !seen.insert(id.as_str()) {
            return Err(LearningDeltaError::InvalidInput { field });
        }
    }
    Ok(())
}

/// Check for a 64-character lowercase hex digest without echoing the value.
fn is_lower_hex64(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}
