//! Authenticated source readback for Orientation's independent classification profile.
//!
//! The profile is an owner-published campaign source, separate from the
//! fixed 26-role learning view. This module only decodes the exact original
//! named-read result; it does not turn task, context, or model fields into a
//! substitute profile.

use eliot_contracts::StateFence;
use eliot_dreamer_contracts::OrientationClassificationProfile;
use eliot_learning_contracts::CampaignSourceRole;
use eliot_store_api::{
    CampaignOwnerProjectionBody, CampaignOwnerReadReceipt, CampaignOwnerRecordId,
    CampaignOwnerRevision, CampaignSourceHead, CampaignSourceReadStatus, CampaignSourceRecord,
    CampaignSourceRevisionRead, campaign_source_owner_id,
};
use thiserror::Error;

/// Typed failure while admitting the original Orientation profile readback.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum OrientationClassificationSourceError {
    /// The named read was missing, stale, or blocked.
    #[error("Orientation classification source read is not current: {0}")]
    NotCurrent(&'static str),
    /// The read did not contain the complete authenticated current tuple.
    #[error("Orientation classification source read is incomplete")]
    IncompleteRead,
    /// The immutable source row was not the exact Orientation role/owner/schema.
    #[error("Orientation classification source identity does not match")]
    IdentityMismatch,
    /// The exact stored row or read receipt failed its native validation.
    #[error("Orientation classification source read is invalid: {0}")]
    InvalidRead(String),
    /// The stored native profile failed its own contract validation.
    #[error("Orientation classification profile is invalid: {0}")]
    InvalidProfile(String),
    /// The original profile does not bind the admitted live task, scope, or fence.
    #[error("Orientation classification profile is not bound to the live task context: {0}")]
    RuntimeBinding(&'static str),
}

/// Decoded semantic profile paired with the unchanged authenticated owner read.
///
/// `read` retains the original CampaignSourceRecord, current head,
/// CampaignOwnerReadReceipt, and read fence. The profile is only a typed view
/// of the source document's native `projection` field; the original row and
/// receipt remain the provenance authority.
#[derive(Clone, Debug)]
pub struct OrientationClassificationSourceReadback<'a> {
    profile: OrientationClassificationProfile,
    read: &'a CampaignSourceRevisionRead,
}

impl<'a> OrientationClassificationSourceReadback<'a> {
    /// Admit one current named-read result for the separate Orientation role.
    pub fn from_read(
        read: &'a CampaignSourceRevisionRead,
    ) -> Result<Self, OrientationClassificationSourceError> {
        read.validate().map_err(|error| {
            OrientationClassificationSourceError::InvalidRead(error.to_string())
        })?;
        match read.status {
            CampaignSourceReadStatus::Current => {}
            CampaignSourceReadStatus::Stale => {
                return Err(OrientationClassificationSourceError::NotCurrent("stale"));
            }
            CampaignSourceReadStatus::Blocked => {
                return Err(OrientationClassificationSourceError::NotCurrent("blocked"));
            }
            CampaignSourceReadStatus::Missing => {
                return Err(OrientationClassificationSourceError::NotCurrent("missing"));
            }
        }
        let (Some(record), Some(head), Some(receipt)) =
            (&read.source, &read.current_head, &read.read_receipt)
        else {
            return Err(OrientationClassificationSourceError::IncompleteRead);
        };
        if !is_orientation_source(record, head, receipt) {
            return Err(OrientationClassificationSourceError::IdentityMismatch);
        }
        let body: CampaignOwnerProjectionBody =
            serde_json::from_value(record.document.body.clone()).map_err(|error| {
                OrientationClassificationSourceError::InvalidRead(error.to_string())
            })?;
        body.validate().map_err(|error| {
            OrientationClassificationSourceError::InvalidRead(error.to_string())
        })?;
        let profile: OrientationClassificationProfile = serde_json::from_value(body.projection)
            .map_err(|error| {
                OrientationClassificationSourceError::InvalidProfile(error.to_string())
            })?;
        profile.validate().map_err(|error| {
            OrientationClassificationSourceError::InvalidProfile(error.to_string())
        })?;
        if !orientation_record_matches_profile(record, &profile) {
            return Err(OrientationClassificationSourceError::IdentityMismatch);
        }
        Ok(Self { profile, read })
    }

    /// Bind the independently-published profile to the exact admitted runtime context.
    pub fn validate_for_runtime(
        &self,
        task_id: &str,
        scope_id: &str,
        state_fence: &StateFence,
    ) -> Result<(), OrientationClassificationSourceError> {
        self.read.validate().map_err(|error| {
            OrientationClassificationSourceError::InvalidRead(error.to_string())
        })?;
        if self.read.status != CampaignSourceReadStatus::Current {
            return Err(OrientationClassificationSourceError::NotCurrent(
                "not current",
            ));
        }
        self.profile.validate().map_err(|error| {
            OrientationClassificationSourceError::InvalidProfile(error.to_string())
        })?;
        let record = self
            .read
            .source
            .as_ref()
            .ok_or(OrientationClassificationSourceError::IncompleteRead)?;
        if !is_orientation_record(record)
            || !orientation_record_matches_profile(record, &self.profile)
        {
            return Err(OrientationClassificationSourceError::IdentityMismatch);
        }
        if self.profile.target.task_id.as_str() != task_id {
            return Err(OrientationClassificationSourceError::RuntimeBinding(
                "task_id",
            ));
        }
        if self.profile.target.scope_id.as_str() != scope_id {
            return Err(OrientationClassificationSourceError::RuntimeBinding(
                "scope_id",
            ));
        }
        if &self.profile.target.state_fence != state_fence
            || &record.recorded_state_fence != state_fence
            || &self.read.read_state_fence != state_fence
        {
            return Err(OrientationClassificationSourceError::RuntimeBinding(
                "state_fence",
            ));
        }
        Ok(())
    }

    /// Borrow the typed profile decoded from the original owner row.
    #[must_use]
    pub const fn profile(&self) -> &OrientationClassificationProfile {
        &self.profile
    }

    /// Borrow the unchanged authenticated owner readback.
    #[must_use]
    pub const fn read(&self) -> &'a CampaignSourceRevisionRead {
        self.read
    }

    /// Return the unchanged original record and authenticated read proof.
    pub fn owner_evidence(
        &self,
    ) -> Result<
        (
            &CampaignSourceRecord,
            &CampaignSourceHead,
            &CampaignOwnerReadReceipt,
            &StateFence,
        ),
        OrientationClassificationSourceError,
    > {
        let record = self
            .read
            .source
            .as_ref()
            .ok_or(OrientationClassificationSourceError::IncompleteRead)?;
        let head = self
            .read
            .current_head
            .as_ref()
            .ok_or(OrientationClassificationSourceError::IncompleteRead)?;
        let receipt = self
            .read
            .read_receipt
            .as_ref()
            .ok_or(OrientationClassificationSourceError::IncompleteRead)?;
        Ok((record, head, receipt, &self.read.read_state_fence))
    }
}

fn is_orientation_source(
    record: &CampaignSourceRecord,
    head: &CampaignSourceHead,
    receipt: &CampaignOwnerReadReceipt,
) -> bool {
    is_orientation_record(record)
        && head.role == CampaignSourceRole::OrientationClassification
        && head.owner_id.as_str()
            == campaign_source_owner_id(CampaignSourceRole::OrientationClassification)
        && head.record_id == record.record_id
        && head.revision == record.revision
        && receipt.role == CampaignSourceRole::OrientationClassification
        && receipt.owner_id.as_str()
            == campaign_source_owner_id(CampaignSourceRole::OrientationClassification)
        && receipt.record_id == record.record_id
        && receipt.revision == record.revision
}

fn is_orientation_record(record: &CampaignSourceRecord) -> bool {
    record.role == CampaignSourceRole::OrientationClassification
        && record.owner_id.as_str()
            == campaign_source_owner_id(CampaignSourceRole::OrientationClassification)
        && record.document.schema
            == eliot_store_api::CampaignSourceDocumentSchema::OrientationClassificationProfile
}

fn orientation_record_matches_profile(
    record: &CampaignSourceRecord,
    profile: &OrientationClassificationProfile,
) -> bool {
    record.record_id == CampaignOwnerRecordId::Artifact(profile.target.target_id.clone())
        && record.revision
            == CampaignOwnerRevision::ResourceSnapshot(profile.target.target_revision.clone())
}
