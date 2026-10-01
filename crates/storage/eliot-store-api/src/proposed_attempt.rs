//! Canonical owner record for one admitted source-capture attempt.
//!
//! The attempt is a distinct immutable child of an existing retained WorkItem.
//! Its record is written through the existing `recovery_owner` namespace in
//! the same Store transaction that issues the admission receipt and launch
//! outbox intent.

use std::collections::BTreeMap;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    NamedMutationOperation, NamedMutationRequest, RecoveryRecord, RecoveryRecordKey, StateFence,
    StoreError, canonical_json_bytes, sha256_hex, validate_text,
};

/// Namespace of canonical selected-source ProposedAttempt records.
pub const PROPOSED_ATTEMPT_RECORD_NAMESPACE: &str = "source-capture-proposed-attempt-v1";
/// Schema carried by one canonical ProposedAttempt record.
pub const PROPOSED_ATTEMPT_RECORD_SCHEMA_V1: &str = "eliot.source-capture.proposed-attempt.v1";

/// One admitted and durably retained source-capture attempt.
///
/// Identity and authority fields are copied from the original selected
/// request and current owner projections. This record is data; Store and
/// callers must still revalidate the retained fence and ORS receipts before
/// admitting or launching an effect.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProposedAttemptRecord {
    /// Original retained WorkItem identity. It is never an attempt identity.
    pub work_item_id: String,
    /// New, distinct attempt identity derived by the ORS owner.
    pub proposed_attempt_id: String,
    /// ORS reservation identity staged before this Store transaction.
    pub reservation_id: String,
    /// Exact ORS receipt identity returned by the inactive staging owner.
    pub reservation_stage_receipt_id: String,
    /// Original request identity retained from the authenticated daemon frame.
    pub request_identity: Value,
    /// Original parent operation identity from the selected-source caller.
    pub parent_operation_id: String,
    /// Original governing Task identity.
    pub task_id: String,
    /// Original governing Session identity.
    pub session_id: String,
    /// Original governing WorkScope identity.
    pub work_scope_id: String,
    /// Original active WorkLease identity.
    pub work_lease_id: String,
    /// Authenticated principal retained by the source-selection owner.
    pub principal_id: String,
    /// Selected role retained by the source-selection owner.
    pub selected_role: String,
    /// Closed source-capture operation name.
    pub operation: String,
    /// Selected relative source path.
    pub selected_relative_path: String,
    /// Optional selected symbol or probe selector.
    pub selector: Option<String>,
    /// Source candidate commitment.
    pub source_digest: String,
    /// Resolved configuration commitment.
    pub configuration_digest: String,
    /// Resolved action contract commitment.
    pub action_contract_digest: String,
    /// Exact active authority epoch projection used to stage ORS.
    pub authority_epoch: Value,
    /// Exact closed ORS claims used for the reservation.
    pub reservation_claims: Value,
    /// Original current Store fence.
    pub state_fence: StateFence,
    /// Admission disposition committed by this record.
    pub disposition: String,
    /// Creation time supplied by the current authenticated owner context.
    pub created_at_ms: i64,
}

impl ProposedAttemptRecord {
    /// Validates the persisted attempt and its original work/authority links.
    pub fn validate(&self) -> Result<(), StoreError> {
        for (value, field) in [
            (&self.work_item_id, "proposed_attempt.work_item_id"),
            (&self.proposed_attempt_id, "proposed_attempt.proposed_attempt_id"),
            (&self.reservation_id, "proposed_attempt.reservation_id"),
            (
                &self.reservation_stage_receipt_id,
                "proposed_attempt.reservation_stage_receipt_id",
            ),
            (&self.parent_operation_id, "proposed_attempt.parent_operation_id"),
            (&self.task_id, "proposed_attempt.task_id"),
            (&self.session_id, "proposed_attempt.session_id"),
            (&self.work_scope_id, "proposed_attempt.work_scope_id"),
            (&self.work_lease_id, "proposed_attempt.work_lease_id"),
            (&self.principal_id, "proposed_attempt.principal_id"),
            (&self.selected_role, "proposed_attempt.selected_role"),
            (&self.operation, "proposed_attempt.operation"),
            (
                &self.selected_relative_path,
                "proposed_attempt.selected_relative_path",
            ),
            (&self.disposition, "proposed_attempt.disposition"),
        ] {
            validate_text(value, field)?;
        }
        if self.work_item_id == self.proposed_attempt_id
            || self.reservation_id == self.work_item_id
            || self.reservation_id == self.proposed_attempt_id
        {
            return Err(StoreError::InvalidField {
                field: "proposed_attempt.identity",
                reason: "work item, attempt, and reservation identities must remain distinct",
            });
        }
        if !matches!(self.operation.as_str(), "Diagnostics" | "ProbeVersion")
            || self.disposition != "ADMITTED"
            || self.created_at_ms <= 0
        {
            return Err(StoreError::InvalidField {
                field: "proposed_attempt.lifecycle",
                reason: "operation, ADMITTED disposition, or creation time is invalid",
            });
        }
        self.state_fence
            .validate()
            .map_err(StoreError::Foundation)?;
        if !self.request_identity.is_object()
            || !self.authority_epoch.is_object()
            || !self.reservation_claims.is_object()
        {
            return Err(StoreError::InvalidField {
                field: "proposed_attempt.owner_projection",
                reason: "request, authority epoch, and reservation claims must be objects",
            });
        }
        for (digest, field) in [
            (&self.source_digest, "proposed_attempt.source_digest"),
            (
                &self.configuration_digest,
                "proposed_attempt.configuration_digest",
            ),
            (
                &self.action_contract_digest,
                "proposed_attempt.action_contract_digest",
            ),
        ] {
            validate_text(digest, field)?;
            if digest.len() != 64
                || digest
                    .bytes()
                    .any(|byte| !byte.is_ascii_hexdigit() || byte.is_ascii_uppercase())
            {
                return Err(StoreError::InvalidField {
                    field,
                    reason: "must be a lowercase SHA-256 digest",
                });
            }
        }
        if let Some(selector) = &self.selector {
            validate_text(selector, "proposed_attempt.selector")?;
        }
        Ok(())
    }

    /// Deterministic key for this exact WorkItem/attempt pair.
    #[must_use]
    pub fn record_key(&self) -> RecoveryRecordKey {
        proposed_attempt_record_key(&self.work_item_id, &self.proposed_attempt_id)
    }

    /// Canonical retained payload bytes.
    pub fn canonical_record_json(&self) -> Result<String, StoreError> {
        let bytes = canonical_json_bytes(self)
            .map_err(|error| StoreError::Serialization(error.to_string()))?;
        String::from_utf8(bytes).map_err(|error| StoreError::Serialization(error.to_string()))
    }

    /// Projects this owner record into its canonical recovery-owner row.
    pub fn recovery_record(&self) -> Result<RecoveryRecord, StoreError> {
        self.validate()?;
        let payload = self.canonical_record_json()?.into_bytes();
        let record = RecoveryRecord {
            namespace: PROPOSED_ATTEMPT_RECORD_NAMESPACE.to_owned(),
            key: self.record_key().key,
            state_fence: self.state_fence.clone(),
            revision: 1,
            schema: PROPOSED_ATTEMPT_RECORD_SCHEMA_V1.to_owned(),
            value_digest: sha256_hex(&payload),
            payload,
        };
        record.validate()?;
        Ok(record)
    }
}

/// Derives the deterministic record address for one original work item and
/// its distinct proposed attempt.
#[must_use]
pub fn proposed_attempt_record_key(
    work_item_id: &str,
    proposed_attempt_id: &str,
) -> RecoveryRecordKey {
    let identity = canonical_json_bytes(&(work_item_id, proposed_attempt_id))
        .unwrap_or_else(|_| panic!("(&str, &str) is always canonically encodable"));
    RecoveryRecordKey::new(
        PROPOSED_ATTEMPT_RECORD_NAMESPACE,
        format!("attempt_{}", sha256_hex(&identity)),
    )
    .unwrap_or_else(|_| panic!("derived proposed-attempt key is always well formed"))
}

/// Builds the named Store mutation that admits and persists this attempt.
pub fn proposed_attempt_record_request(
    record: &ProposedAttemptRecord,
) -> Result<NamedMutationRequest, StoreError> {
    record.validate()?;
    Ok(NamedMutationRequest {
        operation: NamedMutationOperation::AdmitProposedAttempt,
        parameters: BTreeMap::from([(
            "record".to_owned(),
            serde_json::to_value(record)
                .map_err(|error| StoreError::Serialization(error.to_string()))?,
        )]),
    })
}

/// Decodes and validates one exact ProposedAttempt mutation payload.
pub fn decode_proposed_attempt_record(
    operation: NamedMutationOperation,
    parameters: &BTreeMap<String, Value>,
) -> Result<ProposedAttemptRecord, StoreError> {
    if operation != NamedMutationOperation::AdmitProposedAttempt {
        return Err(StoreError::UnknownOperation);
    }
    crate::operation_parameters::validate_typed_mutation_parameters(operation, parameters)?;
    let value = parameters.get("record").cloned().ok_or(StoreError::InvalidField {
        field: "proposed_attempt.record",
        reason: "is required",
    })?;
    let record: ProposedAttemptRecord =
        serde_json::from_value(value).map_err(|error| StoreError::Serialization(error.to_string()))?;
    record.validate()?;
    Ok(record)
}
