//! Explicit, independently bounded Orientation policy.

use eliot_contracts::{canonical_json_bytes, sha256_hex};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::input::OrientationError;

/// Per-dimension limits for one pure projection invocation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OrientationPolicy {
    pub schema_version: u32,
    pub policy_id: String,
    pub policy_revision: u64,
    pub max_output_bytes: u64,
    pub max_input_bytes: u64,
    pub max_source_bytes: u64,
    pub max_source_count: u32,
    pub max_sections: u32,
    pub max_items: u32,
    pub max_work_units: u64,
    pub max_stu: Option<u64>,
    pub observation_time_ms: Option<u64>,
    pub cancellation_requested: bool,
    pub canonical_digest: String,
}

impl OrientationPolicy {
    /// Creates an unsealed policy; `seal` freezes its identity.
    pub fn new(policy_id: impl Into<String>, policy_revision: u64, max_output_bytes: u64) -> Self {
        Self {
            schema_version: 1,
            policy_id: policy_id.into(),
            policy_revision,
            max_output_bytes,
            max_input_bytes: 1_048_576,
            max_source_bytes: 1_048_576,
            max_source_count: 1_024,
            max_sections: 11,
            max_items: 1024,
            max_work_units: 1_000_000,
            max_stu: None,
            observation_time_ms: None,
            cancellation_requested: false,
            canonical_digest: String::new(),
        }
    }

    /// Seals the receipt-excluded policy preimage.
    pub fn seal(&mut self) -> Result<(), OrientationError> {
        self.validate_shape()?;
        self.canonical_digest = self.compute_digest()?;
        Ok(())
    }

    /// Checks bounds and the frozen policy digest.
    pub fn validate(&self) -> Result<(), OrientationError> {
        self.validate_shape()?;
        if self.canonical_digest != self.compute_digest()? {
            return Err(OrientationError::Binding("policy digest"));
        }
        Ok(())
    }

    fn validate_shape(&self) -> Result<(), OrientationError> {
        if self.schema_version != 1
            || self.policy_revision == 0
            || self.policy_id.trim().is_empty()
            || self.policy_id.len() > 256
            || self.max_output_bytes == 0
            || self.max_input_bytes == 0
            || self.max_source_bytes == 0
            || self.max_source_count == 0
            || self.max_output_bytes > 4 * 1024 * 1024
            || self.max_sections == 0
            || self.max_sections > 64
            || self.max_items == 0
            || self.max_items > 4096
            || self.max_work_units == 0
            || self.max_stu == Some(0)
        {
            return Err(OrientationError::Invalid("orientation policy"));
        }
        Ok(())
    }

    fn compute_digest(&self) -> Result<String, OrientationError> {
        #[derive(Serialize)]
        struct Preimage<'a> {
            schema_version: u32,
            policy_id: &'a str,
            policy_revision: u64,
            max_output_bytes: u64,
            max_input_bytes: u64,
            max_source_bytes: u64,
            max_source_count: u32,
            max_sections: u32,
            max_items: u32,
            max_work_units: u64,
            max_stu: Option<u64>,
            observation_time_ms: Option<u64>,
            cancellation_requested: bool,
        }
        let bytes = canonical_json_bytes(&Preimage {
            schema_version: self.schema_version,
            policy_id: &self.policy_id,
            policy_revision: self.policy_revision,
            max_output_bytes: self.max_output_bytes,
            max_input_bytes: self.max_input_bytes,
            max_source_bytes: self.max_source_bytes,
            max_source_count: self.max_source_count,
            max_sections: self.max_sections,
            max_items: self.max_items,
            max_work_units: self.max_work_units,
            max_stu: self.max_stu,
            observation_time_ms: self.observation_time_ms,
            cancellation_requested: self.cancellation_requested,
        })
        .map_err(|_| OrientationError::Encoding("orientation policy"))?;
        Ok(sha256_hex(&bytes))
    }
}
