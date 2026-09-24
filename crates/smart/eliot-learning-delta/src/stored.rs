//! Durable stored-delta record shape for consequential attempts.
//!
//! The durable edge from one consequential attempt to the next materially
//! related attempt.

use eliot_contracts::{ArtifactId, StateFence};
use eliot_learning_contracts::{AgentAttemptId, CampaignId, OverlayId};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::LearningDeltaError;

/// Durable disposition vocabulary for a stored learning delta.
///
/// Disposition vocabulary "LOCAL_UPDATE_ADMITTED | NEXT_PROBE_CHANGED |
/// REUSABLE_CANDIDATE_OPENED | NO_JUSTIFIED_CHANGE | INCONCLUSIVE |
/// INVALID_EVIDENCE".
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
    ///
    /// NoJustifiedChange -> affirmative NoChange outcome (derive
    /// phase_build_no_change), Inconclusive -> Failure::Unknown / no
    /// fabricated Delta, InvalidEvidence -> typed evidence-binding failure
    /// recorded as close reason (never a Delta).
    pub const fn as_stored(self) -> StoredDeltaDisposition {
        match self {
            Self::NoJustifiedChange => StoredDeltaDisposition::NoJustifiedChange,
            Self::Inconclusive => StoredDeltaDisposition::Inconclusive,
            Self::InvalidEvidence => StoredDeltaDisposition::InvalidEvidence,
        }
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
    /// Artifact identity of the durable delta.
    pub delta_artifact: ArtifactId,
    /// Lowercase hex sha256 digest of the durable delta bytes.
    pub delta_digest: String,
    /// Prior durable delta artifact in the retry lineage, if any.
    pub prior_delta_id: Option<ArtifactId>,
    /// Digest of the prior durable delta, paired with `prior_delta_id`.
    pub prior_delta_digest: Option<String>,
    /// Durable disposition of this stored record.
    pub disposition: StoredDeltaDisposition,
    /// Admission receipt identity; present only when the update was admitted.
    pub admission_receipt_id: Option<String>,
}

impl StoredLearningDelta {
    /// Validate identity, digest, lineage, and admission consistency.
    pub fn validate(&self) -> Result<(), LearningDeltaError> {
        if self.campaign_id.as_str().trim().is_empty() {
            return Err(LearningDeltaError::InvalidInput {
                field: "stored.campaign_id",
            });
        }
        if self.attempt_id.as_str().trim().is_empty() {
            return Err(LearningDeltaError::InvalidInput {
                field: "stored.attempt_id",
            });
        }
        if self.overlay_id.as_str().trim().is_empty() {
            return Err(LearningDeltaError::InvalidInput {
                field: "stored.overlay_id",
            });
        }
        if self.delta_artifact.as_str().trim().is_empty() {
            return Err(LearningDeltaError::InvalidInput {
                field: "stored.delta_artifact",
            });
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
        if !is_lower_hex64(&self.delta_digest) {
            return Err(LearningDeltaError::InvalidInput {
                field: "stored.delta_digest",
            });
        }
        match (&self.prior_delta_id, &self.prior_delta_digest) {
            (None, None) => {}
            (Some(id), Some(digest)) => {
                if id.as_str().trim().is_empty() {
                    return Err(LearningDeltaError::InvalidInput {
                        field: "stored.prior_lineage",
                    });
                }
                if !is_lower_hex64(digest) {
                    return Err(LearningDeltaError::InvalidInput {
                        field: "stored.prior_lineage",
                    });
                }
            }
            _ => {
                return Err(LearningDeltaError::InvalidInput {
                    field: "stored.prior_lineage",
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

    /// Return the canonical lineage a retry must reference.
    ///
    /// The retry's canonical lineage references this durable delta (append
    /// delta_artifact id to the retry attempt evidence_refs).
    pub fn lineage_for_retry(&self) -> (&ArtifactId, &str) {
        (&self.delta_artifact, self.delta_digest.as_str())
    }

    /// Report whether this record carries an admitted local update.
    pub fn is_admitted(&self) -> bool {
        self.disposition == StoredDeltaDisposition::LocalUpdateAdmitted
    }
}

/// Check for a 64-character lowercase hex digest without echoing the value.
fn is_lower_hex64(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}
