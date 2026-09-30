//! Owner-issued binding from one Context compilation to the validated
//! immutable campaign learning-state view it was compiled from (I12.24, #1862).
//!
//! I12.24 requires Context Compiler to refuse a campaign learning-state view
//! unless every load-bearing owner revision and the State Fence the view was
//! validated under still hold. The view itself is owned by
//! `eliot-learning-state-view`; the current candidate, admission and assembly
//! cells consume it through this provider-neutral binding, which carries only
//! what a cell needs to perform the join itself: the immutable view identity
//! and its own canonical digest, the exact compilation binding the view was
//! validated under (State Fence included), and the exact load-bearing owner
//! revisions that binding depends on.
//!
//! The binding is evidence, never authority, and existence alone proves
//! nothing. [`CampaignViewBinding::check_compilation`] re-derives nothing: it
//! compares this operation's own binding against the recorded one, so a view
//! validated for another task, attempt, scope, decision or State Fence cannot
//! support this compilation, and a load-bearing set that is empty, malformed
//! or ambiguously keyed is refused before any candidate, decision or packet
//! exists.

use std::collections::BTreeSet;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use eliot_contracts::{ArtifactId, ContractVersion, fences_match_exact};

use crate::{
    CONTEXT_CONTRACT_VERSION, ContextBinding, ContextError, validate_digest, validate_text,
};

/// One exact load-bearing campaign owner revision a compilation depends on.
///
/// Every field is the owner-issued value carried verbatim. `record_id` and
/// `revision` hold the lossless closed owner-native forms as their canonical
/// serialization, so the exact recorded identity is compared byte for byte
/// and never re-derived, re-labelled or approximated.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CampaignOwnerRevisionBinding {
    /// Closed campaign source role label this record satisfies.
    pub role: String,
    /// Owner that issued the immutable record.
    pub owner: String,
    /// Exact owner-native record identity, verbatim.
    pub record_id: String,
    /// Exact owner-native revision, verbatim.
    pub revision: String,
    /// Digest of the complete immutable owner-record content.
    pub content_digest: String,
}

impl CampaignOwnerRevisionBinding {
    /// Validate the closed shape of one owner-issued revision reference.
    pub fn validate(&self) -> Result<(), ContextError> {
        validate_text(&self.role, "campaign_owner_revision.role")?;
        validate_text(&self.owner, "campaign_owner_revision.owner")?;
        validate_text(&self.record_id, "campaign_owner_revision.record_id")?;
        validate_text(&self.revision, "campaign_owner_revision.revision")?;
        validate_digest(
            &self.content_digest,
            "campaign_owner_revision.content_digest",
        )
    }
}

/// The validated immutable campaign learning-state view this compilation is
/// bound to, with its exact load-bearing owner revisions and State Fence.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CampaignViewBinding {
    /// Version of this public binding shape.
    pub schema_version: ContractVersion,
    /// Immutable campaign learning-state view identity.
    pub view_id: ArtifactId,
    /// Campaign the view was derived for.
    pub campaign_id: String,
    /// Canonical digest of the exact immutable view content.
    pub view_digest: String,
    /// Exact compilation binding the view was validated under.
    pub binding: ContextBinding,
    /// Every load-bearing owner revision the view was bound to.
    pub load_bearing_revisions: Vec<CampaignOwnerRevisionBinding>,
}

impl CampaignViewBinding {
    /// Validate the closed shape and the load-bearing revision denominator.
    ///
    /// The load-bearing set must be non-empty and uniquely keyed by role: an
    /// absent or ambiguously keyed load-bearing revision is exactly the
    /// condition I12.24 forbids, so it fails closed here instead of reaching a
    /// decision that would silently omit a load-bearing owner record.
    pub fn validate(&self) -> Result<(), ContextError> {
        if self.schema_version != CONTEXT_CONTRACT_VERSION {
            return Err(ContextError::InvalidField(
                "campaign_view.schema_version",
            ));
        }
        validate_text(&self.campaign_id, "campaign_view.campaign_id")?;
        validate_digest(&self.view_digest, "campaign_view.view_digest")?;
        self.binding.validate()?;
        if self.load_bearing_revisions.is_empty() {
            return Err(ContextError::MissingField(
                "campaign_view.load_bearing_revisions",
            ));
        }
        let mut roles = BTreeSet::new();
        for revision in &self.load_bearing_revisions {
            revision.validate()?;
            if !roles.insert(revision.role.as_str()) {
                return Err(ContextError::Duplicate(
                    "campaign_view.load_bearing_revisions.role",
                ));
            }
        }
        Ok(())
    }

    /// Bind this view to the exact compilation one cell compiles, admits or
    /// renders under.
    ///
    /// The State Fence is compared first and exactly, because a fence is the
    /// authority-carrying part of the binding: a view validated under another
    /// authority epoch, resource generation or task revision is
    /// `ContextError::InvalidFence` whatever else agrees. The remaining
    /// identity — task, attempt, scope and decision — is then compared in
    /// full, so a view belonging to another compilation of the same task is
    /// still refused. Shape and the load-bearing denominator are re-checked on
    /// every call rather than trusted from the producer.
    pub fn check_compilation(&self, binding: &ContextBinding) -> Result<(), ContextError> {
        self.validate()?;
        if !fences_match_exact(&self.binding.state_fence, &binding.state_fence) {
            return Err(ContextError::InvalidFence);
        }
        if self.binding != *binding {
            return Err(ContextError::IdentityConflict);
        }
        Ok(())
    }
}
