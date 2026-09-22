//! Bounded Dreamer self-query pose over the existing owner contract
//! (#223, review repair).
//!
//! [`pose_self_query`] accepts the existing
//! `eliot_dreamer_contracts::self_query::SelfQueryInput` (A-03 owner,
//! merged PR #1060), runs the owner's `validate()`, and freezes the owner's
//! `input_digest()` into a [`SelfQueryPoseReceipt`]. That validate-then-
//! digest prefix is exactly the shared entry of both A-08 brief projectors
//! (`project_architecture_brief`, `project_implementation_brief`); this
//! adapter performs no selection, authoring, or model work of its own.
//!
//! There are no parallel subject/request/candidate types here: the request
//! surface, job/admission/attempt bindings, denominator, policy,
//! preservation, and accepted-source snapshot stay with the A-03 owner, and
//! brief projection stays with the A-08 owners. The accepted-source
//! projection as a standalone owner contract stays `NOT_FROZEN` in
//! `crates/smart/cognitive-rev12-contract-schema-freeze.toml` (CC-006):
//! source material travels inside the owner's `ArchitectureSourceSnapshot`,
//! never as invented local fields. This package is not a W9 unblock.

#![forbid(unsafe_code)]

use eliot_dreamer_contracts::self_query::{SelfQueryContractError, SelfQueryInput};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Freeze identity this package builds against.
///
/// See `crates/smart/cognitive-rev12-contract-schema-freeze.toml`.
pub const FREEZE_ID: &str = "cognitive-rev12-contract-schema-freeze-2026-09-22";
/// Owner contract this adapter poses over.
pub const OWNER_CONTRACT: &str = "eliot.smart.dreamer.contracts";

/// A posed self-query: the owner's input digest plus its schema pin.
///
/// The digest identifies the exact validated input closure the brief
/// projectors consume; it proves no admission or source authority beyond
/// what the owner's own `validate()` established.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SelfQueryPoseReceipt {
    /// Owner's canonical digest over the complete input closure.
    pub input_digest: String,
    /// Input schema version the digest was frozen against.
    pub schema_version: u32,
}

impl SelfQueryPoseReceipt {
    /// Validate the receipt: digest shape only. The digest's authority is
    /// the owner's validation at pose time, rechecked by each consumer.
    pub fn validate(&self) -> Result<(), SelfQueryContractError> {
        if self.input_digest.len() != 64
            || !self
                .input_digest
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        {
            return Err(SelfQueryContractError::InvalidDigest {
                field: "receipt.input_digest",
            });
        }
        Ok(())
    }
}

/// Pose a self-query over the existing owner input.
///
/// Runs the owner's `validate()` (job class, bundle/job/receipt/grounded
/// bindings, policy, denominator, preservation, question) and freezes the
/// owner's `input_digest()`. Any owner rejection fails the pose with the
/// owner's own error.
pub fn pose_self_query(
    input: &SelfQueryInput,
) -> Result<SelfQueryPoseReceipt, SelfQueryContractError> {
    input.validate()?;
    Ok(SelfQueryPoseReceipt {
        input_digest: input.input_digest()?,
        schema_version: input.schema_version,
    })
}
