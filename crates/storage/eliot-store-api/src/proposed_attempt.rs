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
/// Closed operation name for the distinct source-tree archive publication E
/// action. The parent HostRequest remains recorded separately.
pub const SOURCE_SNAPSHOT_STAGE_OPERATION: &str = "SourceSnapshotStage";

/// Exact target and byte commitment for a source-snapshot ProposedAttempt.
/// These values are inert data: authority still comes from the original
/// ActionContract, active ORS reservation, canonical receipt and use-time
/// owner validation.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceSnapshotAdmissionBinding {
    /// SHA-256 of the exact captured source-tree archive bytes.
    pub archive_sha256: String,
    /// Identity of the original BlobRootOwner selecting this target.
    pub blob_root_owner_id: String,
    /// Canonical locator/resource reference returned by the Blob owner.
    pub canonical_locator: String,
    /// Exact five owner payloads whose digests are retained in this record's
    /// ORS reservation claims. Persisting these values with the canonical
    /// SourceSnapshotStage record makes the owner data available for exact
    /// readback after the daemon process is gone; claim references alone are
    /// not treated as payload evidence.
    pub owner_claim_payloads: Vec<Value>,
}

impl SourceSnapshotAdmissionBinding {
    fn validate(&self) -> Result<(), StoreError> {
        crate::validate_digest(
            &self.archive_sha256,
            "proposed_attempt.source_snapshot.archive_sha256",
        )?;
        for (value, field) in [
            (
                &self.blob_root_owner_id,
                "proposed_attempt.source_snapshot.blob_root_owner_id",
            ),
            (
                &self.canonical_locator,
                "proposed_attempt.source_snapshot.canonical_locator",
            ),
        ] {
            validate_text(value, field)?;
        }
        let locator: Value = serde_json::from_str(&self.canonical_locator).map_err(|error| {
            StoreError::Serialization(format!(
                "source snapshot canonical locator is invalid JSON: {error}"
            ))
        })?;
        if !locator.is_object()
            || canonical_json_bytes(&locator)
                .map_err(|error| StoreError::Serialization(error.to_string()))?
                .as_slice()
                != self.canonical_locator.as_bytes()
        {
            return Err(StoreError::InvalidField {
                field: "proposed_attempt.source_snapshot.canonical_locator",
                reason: "must be the canonical JSON object returned by the Blob owner",
            });
        }
        if self.owner_claim_payloads.len() != 5
            || self.owner_claim_payloads.iter().any(|payload| !payload.is_object())
        {
            return Err(StoreError::InvalidField {
                field: "proposed_attempt.source_snapshot.owner_claim_payloads",
                reason: "must retain exactly five original owner payload objects",
            });
        }
        Ok(())
    }
}

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
    /// Present only for the distinct source-tree snapshot publication action.
    /// `skip_serializing_if` preserves the exact v1 encoding for original
    /// Diagnostics/ProbeVersion records that predate this extension.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_snapshot_admission: Option<SourceSnapshotAdmissionBinding>,
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
        let source_snapshot_stage = self.operation == SOURCE_SNAPSHOT_STAGE_OPERATION;
        let known_operation = matches!(self.operation.as_str(), "Diagnostics" | "ProbeVersion")
            || source_snapshot_stage;
        if !known_operation || self.disposition != "ADMITTED" || self.created_at_ms <= 0 {
            return Err(StoreError::InvalidField {
                field: "proposed_attempt.lifecycle",
                reason: "operation, ADMITTED disposition, or creation time is invalid",
            });
        }
        match (&self.source_snapshot_admission, source_snapshot_stage) {
            (Some(binding), true) => {
                binding.validate()?;
                let role_names = ["resources", "lane", "environment", "effects", "quota_view"];
                for (name, payload) in role_names.iter().zip(&binding.owner_claim_payloads) {
                    let claim = self
                        .reservation_claims
                        .get(*name)
                        .ok_or(StoreError::InvalidField {
                            field: "proposed_attempt.reservation_claims",
                            reason: "SourceSnapshotStage is missing an original owner claim",
                        })?;
                    let expected = claim
                        .get("sha256")
                        .and_then(Value::as_str)
                        .ok_or(StoreError::InvalidField {
                            field: "proposed_attempt.reservation_claims",
                            reason: "SourceSnapshotStage is missing an exact owner claim digest",
                        })?;
                    let owner_reference = claim
                        .get("reference")
                        .and_then(Value::as_str)
                        .ok_or(StoreError::InvalidField {
                            field: "proposed_attempt.reservation_claims",
                            reason: "SourceSnapshotStage is missing an original owner reference",
                        })?;
                    if payload
                        .get("owner_reference")
                        .and_then(Value::as_str)
                        != Some(owner_reference)
                    {
                        return Err(StoreError::InvalidField {
                            field: "proposed_attempt.source_snapshot.owner_claim_payloads",
                            reason: "retained owner payload is not bound to its exact original owner reference",
                        });
                    }
                    let payload_digest = sha256_hex(
                        &canonical_json_bytes(payload)
                            .map_err(|error| StoreError::Serialization(error.to_string()))?,
                    );
                    if expected != payload_digest {
                        return Err(StoreError::InvalidField {
                            field: "proposed_attempt.source_snapshot.owner_claim_payloads",
                            reason: "owner payload bytes do not match their original reservation claim digest",
                        });
                    }
                }
            }
            (None, false) => {}
            (None, true) => {
                return Err(StoreError::InvalidField {
                    field: "proposed_attempt.source_snapshot_admission",
                    reason: "is required for SourceSnapshotStage",
                });
            }
            (Some(_), false) => {
                return Err(StoreError::InvalidField {
                    field: "proposed_attempt.source_snapshot_admission",
                    reason: "is permitted only for SourceSnapshotStage",
                });
            }
        }
        if source_snapshot_stage && self.selector.is_some() {
            return Err(StoreError::InvalidField {
                field: "proposed_attempt.selector",
                reason: "SourceSnapshotStage does not carry a selector or use it as a payload slot",
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
        if source_snapshot_stage {
            let identity: eliot_protocol::RequestIdentity =
                serde_json::from_value(self.request_identity.clone()).map_err(|error| {
                    StoreError::Serialization(format!(
                        "source snapshot child RequestIdentity is invalid: {error}"
                    ))
                })?;
            identity.validate().map_err(|error| {
                StoreError::Serialization(format!(
                    "source snapshot child RequestIdentity is invalid: {error}"
                ))
            })?;
            if identity.request.state_fence != self.state_fence
                || identity.request.metadata.state_fence != self.state_fence
                || identity
                    .request
                    .metadata
                    .task_id
                    .as_ref()
                    .map(ToString::to_string)
                    .as_deref()
                    != Some(self.task_id.as_str())
                || identity
                    .request
                    .metadata
                    .session_id
                    .as_ref()
                    .map(ToString::to_string)
                    .as_deref()
                    != Some(self.session_id.as_str())
            {
                return Err(StoreError::InvalidField {
                    field: "proposed_attempt.request_identity",
                    reason: "SourceSnapshotStage child identity must match the exact task, session, and fence",
                });
            }
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

#[cfg(test)]
mod tests {
    use super::*;
    use eliot_contracts::{
        ClockReading, EpochId, EpochLineageId, ProductId, RequestId, ResourceGeneration,
        SessionId, SourceId, StateFence, TaskId,
    };
    use eliot_receipts::RequestBinding;
    use std::num::NonZeroU64;

    fn fence() -> StateFence {
        let lineage = EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000")
            .expect("test lineage");
        let epoch = EpochId::new(lineage, NonZeroU64::new(1).expect("non-zero"))
            .expect("test epoch");
        StateFence::new(epoch, ResourceGeneration::genesis())
    }

    fn record(
        operation: &str,
        selector: Option<&str>,
        source_snapshot_admission: Option<SourceSnapshotAdmissionBinding>,
    ) -> ProposedAttemptRecord {
        let state_fence = fence();
        let metadata = eliot_contracts::RequestMetadata {
            request_id: RequestId::new("source-snapshot-e-child").expect("request ID"),
            session_id: Some(SessionId::new("session-source-snapshot").expect("session ID")),
            task_id: Some(TaskId::new("task-source-snapshot").expect("task ID")),
            product_id: ProductId::new("product-source-snapshot").expect("product ID"),
            source_id: SourceId::new("source-source-snapshot").expect("source ID"),
            state_fence: state_fence.clone(),
            clock: ClockReading::default(),
        };
        let identity = eliot_protocol::RequestIdentity {
            request: RequestBinding {
                metadata,
                state_fence: state_fence.clone(),
            },
            idempotency_key: "source-snapshot-e-idempotency".to_owned(),
            deadline_unix_ms: 1,
            cancellation_id: "source-snapshot-e-cancel".to_owned(),
        };
        let claim_names = ["resources", "lane", "environment", "effects", "quota_view"];
        let claim_refs = [
            "owner:resources",
            "owner:lane",
            "owner:environment",
            "owner:effects",
            "owner:quota",
        ];
        let reservation_claims = if let Some(binding) = &source_snapshot_admission {
            let values = claim_names
                .iter()
                .zip(claim_refs)
                .zip(&binding.owner_claim_payloads)
                .map(|((name, reference), payload)| {
                    let digest = sha256_hex(
                        &canonical_json_bytes(payload).expect("test owner payload is canonical"),
                    );
                    (*name, serde_json::json!({"reference": reference, "sha256": digest}))
                })
                .collect::<BTreeMap<_, _>>();
            serde_json::to_value(values).expect("claim map JSON")
        } else {
            serde_json::json!({
                "resources": {"reference": "owner:resources", "sha256": "e".repeat(64)},
                "lane": {"reference": "owner:lane", "sha256": "f".repeat(64)},
                "environment": {"reference": "owner:environment", "sha256": "a".repeat(64)},
                "effects": {"reference": "owner:effects", "sha256": "b".repeat(64)},
                "quota_view": {"reference": "owner:quota", "sha256": "c".repeat(64)}
            })
        };
        ProposedAttemptRecord {
            work_item_id: "work-item-source-snapshot".to_owned(),
            proposed_attempt_id: "attempt-source-snapshot".to_owned(),
            reservation_id: "reservation-source-snapshot".to_owned(),
            reservation_stage_receipt_id: "receipt-source-snapshot-stage".to_owned(),
            request_identity: serde_json::to_value(identity).expect("RequestIdentity JSON"),
            parent_operation_id: "hostreq:source-snapshot-parent-digest".to_owned(),
            task_id: "task-source-snapshot".to_owned(),
            session_id: "session-source-snapshot".to_owned(),
            work_scope_id: "scope-source-snapshot".to_owned(),
            work_lease_id: "lease-source-snapshot".to_owned(),
            principal_id: "principal-source-snapshot".to_owned(),
            operation: operation.to_owned(),
            selected_relative_path: "src/lib.rs".to_owned(),
            selector: selector.map(str::to_owned),
            source_digest: "b".repeat(64),
            configuration_digest: "c".repeat(64),
            action_contract_digest: "d".repeat(64),
            authority_epoch: serde_json::json!({"lineage": "epoch-1", "sequence": 1}),
            reservation_claims,
            source_snapshot_admission,
            state_fence,
            disposition: "ADMITTED".to_owned(),
            created_at_ms: 1,
        }
    }

    fn binding() -> SourceSnapshotAdmissionBinding {
        SourceSnapshotAdmissionBinding {
            archive_sha256: "a".repeat(64),
            blob_root_owner_id: "blob-root-owner-current".to_owned(),
            canonical_locator: "{\"domain\":\"source-tree\",\"key\":\"archive-1\"}".to_owned(),
            owner_claim_payloads: vec![
                serde_json::json!({"owner":"resources", "owner_reference":"owner:resources"}),
                serde_json::json!({"owner":"lane", "owner_reference":"owner:lane"}),
                serde_json::json!({"owner":"environment", "owner_reference":"owner:environment"}),
                serde_json::json!({"owner":"effects", "owner_reference":"owner:effects"}),
                serde_json::json!({"owner":"quota_view", "owner_reference":"owner:quota"}),
            ],
        }
    }

    #[test]
    fn source_snapshot_stage_requires_exact_archive_and_owner_target_binding() {
        let valid = record(SOURCE_SNAPSHOT_STAGE_OPERATION, None, Some(binding()));
        assert!(valid.validate().is_ok());
        let mut changed_owner_payload = valid.clone();
        changed_owner_payload.source_snapshot_admission.as_mut().expect("E binding")
            .owner_claim_payloads[0]["owner"] = serde_json::json!("substituted");
        assert!(changed_owner_payload.validate().is_err());

        let mut substituted_owner_reference = valid.clone();
        substituted_owner_reference.reservation_claims["resources"]["reference"] =
            serde_json::json!("different-original-owner-row");
        assert!(substituted_owner_reference.validate().is_err());

        let mut missing_owner_payload = binding();
        missing_owner_payload.owner_claim_payloads.pop();
        assert!(record(
            SOURCE_SNAPSHOT_STAGE_OPERATION,
            None,
            Some(missing_owner_payload)
        )
        .validate()
        .is_err());

        assert!(record(SOURCE_SNAPSHOT_STAGE_OPERATION, None, None)
            .validate()
            .is_err());

        let mut changed_archive = binding();
        changed_archive.archive_sha256 = "A".repeat(64);
        assert!(record(
            SOURCE_SNAPSHOT_STAGE_OPERATION,
            None,
            Some(changed_archive)
        )
        .validate()
        .is_err());

        let mut missing_owner = binding();
        missing_owner.blob_root_owner_id.clear();
        assert!(record(
            SOURCE_SNAPSHOT_STAGE_OPERATION,
            None,
            Some(missing_owner)
        )
        .validate()
        .is_err());

        let mut missing_locator = binding();
        missing_locator.canonical_locator.clear();
        assert!(record(
            SOURCE_SNAPSHOT_STAGE_OPERATION,
            None,
            Some(missing_locator)
        )
        .validate()
        .is_err());

        let mut noncanonical_locator = binding();
        noncanonical_locator.canonical_locator =
            "{ \"domain\": \"source-tree\", \"key\": \"archive-1\" }".to_owned();
        assert!(record(
            SOURCE_SNAPSHOT_STAGE_OPERATION,
            None,
            Some(noncanonical_locator)
        )
        .validate()
        .is_err());

        let mut wrong_task = record(SOURCE_SNAPSHOT_STAGE_OPERATION, None, Some(binding()));
        wrong_task.request_identity["request"]["metadata"]["task_id"] =
            serde_json::json!("different-task");
        assert!(wrong_task.validate().is_err());

        let mut wrong_session = record(SOURCE_SNAPSHOT_STAGE_OPERATION, None, Some(binding()));
        wrong_session.request_identity["request"]["metadata"]["session_id"] =
            serde_json::json!("different-session");
        assert!(wrong_session.validate().is_err());

        let mut wrong_fence = record(SOURCE_SNAPSHOT_STAGE_OPERATION, None, Some(binding()));
        wrong_fence.request_identity["request"]["metadata"]["state_fence"]["resource_generation"] =
            serde_json::json!(2);
        assert!(wrong_fence.validate().is_err());
    }

    #[test]
    fn source_snapshot_stage_does_not_reuse_selector_slot_and_old_ops_keep_v1_shape() {
        assert!(record(
            SOURCE_SNAPSHOT_STAGE_OPERATION,
            Some("archive payload"),
            Some(binding())
        )
        .validate()
        .is_err());

        for operation in ["Diagnostics", "ProbeVersion"] {
            let original = record(operation, None, None);
            assert!(original.validate().is_ok());
            let encoded = serde_json::to_value(&original).expect("old record JSON");
            assert!(encoded.get("source_snapshot_admission").is_none());
            let decoded: ProposedAttemptRecord =
                serde_json::from_value(encoded).expect("old record remains readable");
            assert_eq!(decoded, original);
        }

        assert!(record("Diagnostics", None, Some(binding()))
            .validate()
            .is_err());
    }
}
