//! Human-admitted process Blob policy and residency carried by Config.
//!
//! The value deliberately reuses S-04's closed policy and residency types.
//! Config supplies only the Human-owned admission envelope: the enclosing
//! signed snapshot supplies its owner, scope, revision, and StateFence.

use eliot_blob_api::{BlobPolicyBinding, ObjectResidencyKey};
use eliot_contracts::canonical_json_bytes;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::Setting;

/// Exact Config key for an admitted process-stream Blob policy.
pub const BLOB_PROCESS_POLICY_SETTING_KEY: &str = "blob.process.policy";
/// Versioned literal prefix for the closed S-04 policy/residency payload.
pub const BLOB_PROCESS_POLICY_LITERAL_PREFIX: &str = "literal:eliot.blob.process-policy.v1:";
/// Schema retained inside the signed Config Setting value.
pub const BLOB_PROCESS_POLICY_SCHEMA: &str = "eliot.blob.process-policy.v1";

/// The exact policy and full residency template selected by the Config owner.
///
/// The residency template's content digest is preserved as owner input; the
/// process-stream sink replaces only that digest with the exact staged bytes'
/// digest at finalize. The six owner-issued residency domains always survive.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlobProcessPolicyValue {
    pub schema: String,
    pub policy: BlobPolicyBinding,
    pub residency: ObjectResidencyKey,
}

/// Refusal while decoding or binding one Human-admitted policy Setting.
#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum BlobProcessPolicyError {
    #[error("Blob process policy Setting is absent")]
    Missing,
    #[error("Blob process policy Setting is ambiguous")]
    Ambiguous,
    #[error("Blob process policy owner differs from the Config policy owner")]
    ForeignOwner,
    #[error("Blob process policy residency scope differs from the Config scope")]
    ScopeMismatch,
    #[error("Blob process policy value is not a supported canonical v1 value: {0}")]
    InvalidValue(String),
}

impl BlobProcessPolicyValue {
    /// Validates the closed S-04 policy and complete residency template.
    pub fn validate(&self) -> Result<(), BlobProcessPolicyError> {
        if self.schema != BLOB_PROCESS_POLICY_SCHEMA {
            return Err(BlobProcessPolicyError::InvalidValue(
                "unsupported schema".to_owned(),
            ));
        }
        self.policy
            .validate_for_residency(&self.residency)
            .map_err(|error| BlobProcessPolicyError::InvalidValue(error.to_string()))
    }

    /// Validates the exact owner-supplied scope domain and produces the
    /// versioned literal carrier stored inside the signed Config snapshot.
    pub fn to_setting(
        &self,
        owner_ref: &str,
        scope_id: &str,
    ) -> Result<Setting, BlobProcessPolicyError> {
        self.validate()?;
        if self.residency.scope_domain_id.as_str() != scope_id {
            return Err(BlobProcessPolicyError::ScopeMismatch);
        }
        let bytes = canonical_json_bytes(self)
            .map_err(|error| BlobProcessPolicyError::InvalidValue(error.to_string()))?;
        let json = String::from_utf8(bytes)
            .map_err(|error| BlobProcessPolicyError::InvalidValue(error.to_string()))?;
        Ok(Setting {
            key: BLOB_PROCESS_POLICY_SETTING_KEY.to_owned(),
            value_ref: format!("{BLOB_PROCESS_POLICY_LITERAL_PREFIX}{json}"),
            owner_ref: owner_ref.to_owned(),
        })
    }

    /// Parses explicit CLI/config input. Whitespace is accepted at this
    /// boundary, then the resulting typed value is re-encoded canonically in
    /// the owner-signed Config snapshot.
    pub fn from_json(input: &str) -> Result<Self, BlobProcessPolicyError> {
        let value: Self = serde_json::from_str(input)
            .map_err(|error| BlobProcessPolicyError::InvalidValue(error.to_string()))?;
        value.validate()?;
        Ok(value)
    }
}

/// Resolves the one Config-owned process Blob policy from its signed Setting
/// collection. Missing values remain explicit; no default or caller policy is
/// substituted.
pub fn selection_from_settings(
    settings: &[Setting],
    expected_owner_ref: &str,
    expected_scope_id: &str,
) -> Result<Option<BlobProcessPolicyValue>, BlobProcessPolicyError> {
    let mut selected = settings
        .iter()
        .filter(|setting| setting.key == BLOB_PROCESS_POLICY_SETTING_KEY);
    let Some(setting) = selected.next() else {
        return Ok(None);
    };
    if selected.next().is_some() {
        return Err(BlobProcessPolicyError::Ambiguous);
    }
    if setting.owner_ref != expected_owner_ref {
        return Err(BlobProcessPolicyError::ForeignOwner);
    }
    let json = setting
        .value_ref
        .strip_prefix(BLOB_PROCESS_POLICY_LITERAL_PREFIX)
        .ok_or_else(|| {
            BlobProcessPolicyError::InvalidValue(
                "Setting must carry the closed versioned literal".to_owned(),
            )
        })?;
    let value: BlobProcessPolicyValue = serde_json::from_str(json)
        .map_err(|error| BlobProcessPolicyError::InvalidValue(error.to_string()))?;
    value.validate()?;
    if value.residency.scope_domain_id.as_str() != expected_scope_id {
        return Err(BlobProcessPolicyError::ScopeMismatch);
    }
    let canonical = canonical_json_bytes(&value)
        .map_err(|error| BlobProcessPolicyError::InvalidValue(error.to_string()))?;
    if canonical != json.as_bytes() {
        return Err(BlobProcessPolicyError::InvalidValue(
            "literal JSON is not canonical".to_owned(),
        ));
    }
    Ok(Some(value))
}
