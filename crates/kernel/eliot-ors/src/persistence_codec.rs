//! Architecture: A13.6 / ARCH-MOD-02 — persistence codec isolated from storage.
//! ORS durable codec boundary; no `Store`, `SurrealDB`, or recovery semantics.
//! Implementation: I18.7 — pure encode/decode with validation.
//! Ownership: I5/I18 — existing ORS handles; codec-only, no writer, semantic `Store`, `SurrealDB`, or recovery authority.

use std::collections::BTreeSet;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use thiserror::Error;

use super::DurableGrantClosureRecord;
use super::DurableGrantGraphRevision;
use super::DurableInboxRecord;
use super::DurableOperationalRecord;
use super::DurableSupervisionLeaseResult;
use super::OperationalKind;
use super::ScopeReservationHead;
use crate::AuthorityHandoffRecord;
use crate::CanonicalDisposition;
use crate::OpaqueLabel;
use crate::OperationalPhase;
use crate::OrsError;
use crate::ProcessEvidenceRecord;
use crate::ProcessStartReplayRecord;
use crate::ProcessStreamRecoveryProjection;
use crate::RecoveryInboxDisposition;
use crate::RecoveryPayload;
use crate::RecoveryPayloadEnvelope;
use crate::RecoveryProblem;
use crate::ReservationRecord;
use crate::ReservationState;
use crate::ScopeTerminalReceipt;
use crate::SupervisionLeaseSnapshot;
use crate::SupervisionLeaseStageReceipt;
use crate::SupervisionLeaseStageResolution;
use crate::UnknownCommitRecord;
use crate::cutover_ownership::StoredCutoverOwnership;
use eliot_runtime_contracts::GenerationCutoverState;
use eliot_store_api::{
    CampaignLearningStateViewPublication, CampaignSourceHead, CampaignSourceRecord,
};

use super::CampaignSourceReservation;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub(super) enum LegacyGrantClosureState {
    Active,
    Fenced,
}

impl LegacyGrantClosureState {
    pub(super) const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "ACTIVE",
            Self::Fenced => "FENCED",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct LegacyGrantClosurePreserved {
    pub(super) grant_id: OpaqueLabel,
    pub(super) covering_grant_id: OpaqueLabel,
    pub(super) covering_root: OpaqueLabel,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct LegacyGrantClosureCommit {
    pub(super) operation_id: OpaqueLabel,
    pub(super) target_id: OpaqueLabel,
    pub(super) authority_root: OpaqueLabel,
    pub(super) revision: u64,
    pub(super) digest: String,
    pub(super) affected: Vec<OpaqueLabel>,
    pub(super) preserved: Vec<LegacyGrantClosurePreserved>,
    pub(super) fenced_introductions: Vec<OpaqueLabel>,
    pub(super) state: LegacyGrantClosureState,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct LegacyGrantClosureRecord {
    pub(super) commit: LegacyGrantClosureCommit,
    pub(super) phase: OperationalPhase,
    pub(super) operation_order: u64,
}

#[derive(Debug, Error)]
pub(super) enum LegacyGrantClosureDecodeError {
    #[error("missing field {field}")]
    MissingField { field: String },
    #[error("invalid field {field}: {reason}")]
    InvalidField { field: String, reason: String },
    #[error("invalid legacy grant-closure shape: {reason}")]
    InvalidShape { reason: String },
}

fn required_field<'a>(
    object: &'a Map<String, Value>,
    field: &str,
    path: &str,
) -> Result<&'a Value, LegacyGrantClosureDecodeError> {
    let value = object
        .get(field)
        .ok_or_else(|| LegacyGrantClosureDecodeError::MissingField {
            field: format!("{path}.{field}"),
        })?;
    if value.is_null() {
        return Err(LegacyGrantClosureDecodeError::MissingField {
            field: format!("{path}.{field}"),
        });
    }
    Ok(value)
}

fn object_field<'a>(
    value: &'a Value,
    field: &str,
    path: &str,
) -> Result<&'a Map<String, Value>, LegacyGrantClosureDecodeError> {
    let object = value
        .as_object()
        .ok_or_else(|| LegacyGrantClosureDecodeError::InvalidField {
            field: format!("{path}.{field}"),
            reason: "expected an object".to_owned(),
        })?;
    required_field(object, field, path).and_then(|nested| {
        nested
            .as_object()
            .ok_or_else(|| LegacyGrantClosureDecodeError::InvalidField {
                field: format!("{path}.{field}"),
                reason: "expected an object".to_owned(),
            })
    })
}

fn reject_unknown_fields(
    object: &Map<String, Value>,
    allowed: &[&str],
    path: &str,
) -> Result<(), LegacyGrantClosureDecodeError> {
    for field in object.keys() {
        if !allowed.iter().any(|candidate| candidate == field) {
            return Err(LegacyGrantClosureDecodeError::InvalidField {
                field: format!("{path}.{field}"),
                reason: "unknown legacy field".to_owned(),
            });
        }
    }
    Ok(())
}

fn decode_field<T: DeserializeOwned>(
    object: &Map<String, Value>,
    field: &str,
    path: &str,
) -> Result<T, LegacyGrantClosureDecodeError> {
    let value = required_field(object, field, path)?;
    serde_json::from_value(value.clone()).map_err(|error| {
        LegacyGrantClosureDecodeError::InvalidField {
            field: format!("{path}.{field}"),
            reason: error.to_string(),
        }
    })
}

fn decode_array<T: DeserializeOwned>(
    object: &Map<String, Value>,
    field: &str,
    path: &str,
) -> Result<Vec<T>, LegacyGrantClosureDecodeError> {
    let value = required_field(object, field, path)?;
    let array = value
        .as_array()
        .ok_or_else(|| LegacyGrantClosureDecodeError::InvalidField {
            field: format!("{path}.{field}"),
            reason: "expected an array".to_owned(),
        })?;
    array
        .iter()
        .enumerate()
        .map(|(index, item)| {
            serde_json::from_value(item.clone()).map_err(|error| {
                LegacyGrantClosureDecodeError::InvalidField {
                    field: format!("{path}.{field}[{index}]"),
                    reason: error.to_string(),
                }
            })
        })
        .collect()
}

fn decode_preserved(
    object: &Map<String, Value>,
    field: &str,
    path: &str,
) -> Result<Vec<LegacyGrantClosurePreserved>, LegacyGrantClosureDecodeError> {
    let value = required_field(object, field, path)?;
    let array = value
        .as_array()
        .ok_or_else(|| LegacyGrantClosureDecodeError::InvalidField {
            field: format!("{path}.{field}"),
            reason: "expected an array".to_owned(),
        })?;
    array
        .iter()
        .enumerate()
        .map(|(index, item)| {
            let item_path = format!("{path}.{field}[{index}]");
            let item_object =
                item.as_object()
                    .ok_or_else(|| LegacyGrantClosureDecodeError::InvalidField {
                        field: item_path.clone(),
                        reason: "expected an object".to_owned(),
                    })?;
            reject_unknown_fields(
                item_object,
                &["grant_id", "covering_grant_id", "covering_root"],
                &item_path,
            )?;
            Ok(LegacyGrantClosurePreserved {
                grant_id: decode_field(item_object, "grant_id", &item_path)?,
                covering_grant_id: decode_field(item_object, "covering_grant_id", &item_path)?,
                covering_root: decode_field(item_object, "covering_root", &item_path)?,
            })
        })
        .collect()
}

fn validate_legacy_record(
    record: &LegacyGrantClosureRecord,
) -> Result<(), LegacyGrantClosureDecodeError> {
    if record.operation_order == 0 {
        return Err(LegacyGrantClosureDecodeError::InvalidField {
            field: "record.operation_order".to_owned(),
            reason: "must be greater than zero".to_owned(),
        });
    }
    if record.commit.revision == 0 {
        return Err(LegacyGrantClosureDecodeError::InvalidField {
            field: "commit.revision".to_owned(),
            reason: "must be greater than zero".to_owned(),
        });
    }
    crate::model::validate_digest(&record.commit.digest, "legacy_grant_closure_digest").map_err(
        |error| LegacyGrantClosureDecodeError::InvalidField {
            field: "commit.digest".to_owned(),
            reason: error.to_string(),
        },
    )?;
    if record.commit.affected.is_empty() {
        return Err(LegacyGrantClosureDecodeError::InvalidField {
            field: "commit.affected".to_owned(),
            reason: "must contain at least the target".to_owned(),
        });
    }
    let mut previous = None;
    for grant_id in &record.commit.affected {
        if previous.is_some_and(|prior| prior >= grant_id) {
            return Err(LegacyGrantClosureDecodeError::InvalidField {
                field: "commit.affected".to_owned(),
                reason: "must be sorted and unique".to_owned(),
            });
        }
        previous = Some(grant_id);
    }
    if !record.commit.affected.contains(&record.commit.target_id) {
        return Err(LegacyGrantClosureDecodeError::InvalidField {
            field: "commit.target_id".to_owned(),
            reason: "must be present in commit.affected".to_owned(),
        });
    }
    let mut previous_preserved = None;
    for preserved in &record.commit.preserved {
        if record.commit.affected.contains(&preserved.grant_id) {
            return Err(LegacyGrantClosureDecodeError::InvalidField {
                field: "commit.preserved".to_owned(),
                reason: "must be disjoint from commit.affected".to_owned(),
            });
        }
        let key = (
            preserved.grant_id.as_str(),
            preserved.covering_grant_id.as_str(),
            preserved.covering_root.as_str(),
        );
        if previous_preserved.is_some_and(|prior| prior >= key) {
            return Err(LegacyGrantClosureDecodeError::InvalidField {
                field: "commit.preserved".to_owned(),
                reason: "must be sorted and unique".to_owned(),
            });
        }
        previous_preserved = Some(key);
    }
    let mut previous_introduction = None;
    for introduction_id in &record.commit.fenced_introductions {
        if previous_introduction.is_some_and(|prior| prior >= introduction_id) {
            return Err(LegacyGrantClosureDecodeError::InvalidField {
                field: "commit.fenced_introductions".to_owned(),
                reason: "must be sorted and unique".to_owned(),
            });
        }
        previous_introduction = Some(introduction_id);
    }
    let expected_phase = match record.commit.state {
        LegacyGrantClosureState::Active => OperationalPhase::Active,
        LegacyGrantClosureState::Fenced => OperationalPhase::Fenced,
    };
    if record.phase != expected_phase {
        return Err(LegacyGrantClosureDecodeError::InvalidField {
            field: "record.phase".to_owned(),
            reason: "does not match the legacy closure state".to_owned(),
        });
    }
    Ok(())
}

/// Decodes only the closed v1 grant-closure shape. It never accepts the v2
/// contract by field-copying: callers must handle the two shapes separately.
pub(super) fn decode_legacy_grant_closure_record(
    value: &str,
) -> Result<LegacyGrantClosureRecord, LegacyGrantClosureDecodeError> {
    let root: Value = serde_json::from_str(value).map_err(|error| {
        LegacyGrantClosureDecodeError::InvalidShape {
            reason: error.to_string(),
        }
    })?;
    let root_object =
        root.as_object()
            .ok_or_else(|| LegacyGrantClosureDecodeError::InvalidShape {
                reason: "record must be a JSON object".to_owned(),
            })?;
    reject_unknown_fields(
        root_object,
        &["commit", "phase", "operation_order"],
        "record",
    )?;
    let commit_object = object_field(&root, "commit", "record")?;
    reject_unknown_fields(
        commit_object,
        &[
            "operation_id",
            "target_id",
            "authority_root",
            "revision",
            "digest",
            "affected",
            "preserved",
            "fenced_introductions",
            "state",
        ],
        "commit",
    )?;
    let commit = LegacyGrantClosureCommit {
        operation_id: decode_field(commit_object, "operation_id", "commit")?,
        target_id: decode_field(commit_object, "target_id", "commit")?,
        authority_root: decode_field(commit_object, "authority_root", "commit")?,
        revision: decode_field(commit_object, "revision", "commit")?,
        digest: decode_field(commit_object, "digest", "commit")?,
        affected: decode_array(commit_object, "affected", "commit")?,
        preserved: decode_preserved(commit_object, "preserved", "commit")?,
        fenced_introductions: decode_array(commit_object, "fenced_introductions", "commit")?,
        state: decode_field(commit_object, "state", "commit")?,
    };
    let record = LegacyGrantClosureRecord {
        commit,
        phase: decode_field(root_object, "phase", "record")?,
        operation_order: decode_field(root_object, "operation_order", "record")?,
    };
    validate_legacy_record(&record)?;
    Ok(record)
}

/// Identifies a row that already carries one of the v2-only fields. This is
/// deliberately conservative: a v1 row is sent to the explicit legacy decoder,
/// while a v2-shaped row must be validated by the current codec.
pub(super) fn is_current_grant_closure_shape(value: &str) -> bool {
    let Ok(root) = serde_json::from_str::<Value>(value) else {
        return false;
    };
    let Some(commit) = root.get("commit").and_then(Value::as_object) else {
        return false;
    };
    [
        "schema",
        "version",
        "declaration",
        "authority",
        "proof_ceiling",
        "authority_receipt",
        "ors_member_receipts",
        "ors_introduction_receipts",
        "canonical_receipt",
    ]
    .iter()
    .any(|field| commit.contains_key(*field))
}

pub(super) fn encode<T: Serialize>(value: &T) -> Result<String, OrsError> {
    serde_json::to_string(value).map_err(|error| OrsError::Encoding(error.to_string()))
}

pub(super) trait PersistedValue: DeserializeOwned {
    const RECORD_TYPE: &'static str;

    fn validate_persisted(&self) -> Result<(), OrsError>;
}

impl PersistedValue for CampaignLearningStateViewPublication {
    const RECORD_TYPE: &'static str = "campaign_learning_state_view";

    fn validate_persisted(&self) -> Result<(), OrsError> {
        self.validate()
            .map_err(|error| OrsError::Contract(error.to_string()))
    }
}

impl PersistedValue for CampaignSourceHead {
    const RECORD_TYPE: &'static str = "campaign_source_head";

    fn validate_persisted(&self) -> Result<(), OrsError> {
        self.validate()
            .map_err(|error| OrsError::Contract(error.to_string()))
    }
}

impl PersistedValue for CampaignSourceRecord {
    const RECORD_TYPE: &'static str = "campaign_source_record";

    fn validate_persisted(&self) -> Result<(), OrsError> {
        self.validate()
            .map_err(|error| OrsError::Contract(error.to_string()))
    }
}

impl PersistedValue for CampaignSourceReservation {
    const RECORD_TYPE: &'static str = "campaign_source_reservation";

    fn validate_persisted(&self) -> Result<(), OrsError> {
        eliot_store_api::validate_sha256_hex(
            &self.request_digest,
            "campaign_source.request_digest",
        )
        .map_err(|error| OrsError::Contract(error.to_string()))?;
        self.publication
            .validate()
            .map_err(|error| OrsError::Contract(error.to_string()))
    }
}

impl PersistedValue for RecoveryPayloadEnvelope {
    const RECORD_TYPE: &'static str = "recovery_envelope";

    fn validate_persisted(&self) -> Result<(), OrsError> {
        self.validate()
    }
}

impl PersistedValue for RecoveryProblem {
    const RECORD_TYPE: &'static str = "recovery_problem";

    fn validate_persisted(&self) -> Result<(), OrsError> {
        self.validate()
    }
}

impl PersistedValue for ProcessStartReplayRecord {
    const RECORD_TYPE: &'static str = "process_start_replay";

    fn validate_persisted(&self) -> Result<(), OrsError> {
        self.validate()
    }
}

impl PersistedValue for AuthorityHandoffRecord {
    const RECORD_TYPE: &'static str = "authority_handoff";

    fn validate_persisted(&self) -> Result<(), OrsError> {
        self.validate()
    }
}

impl PersistedValue for ProcessEvidenceRecord {
    const RECORD_TYPE: &'static str = "process_evidence";

    fn validate_persisted(&self) -> Result<(), OrsError> {
        self.validate()
    }
}

/// Issue #269: the process-stream recovery projection rides the same ORS codec
/// as every other record family. There is no second codec, no second table
/// owner and no separate journal for stdout/stderr: `contract_version` is the
/// existing ORS contract version, and `validate()` is the single fail-closed
/// gate that also makes a synthetic `raw:` locator unrepresentable.
impl PersistedValue for ProcessStreamRecoveryProjection {
    const RECORD_TYPE: &'static str = "process_stream_recovery";

    fn validate_persisted(&self) -> Result<(), OrsError> {
        self.validate()
    }
}

impl PersistedValue for ScopeReservationHead {
    const RECORD_TYPE: &'static str = "scope_head";

    fn validate_persisted(&self) -> Result<(), OrsError> {
        self.writer_epoch.validate()?;
        self.canonical_head.validate()?;
        if self.last_reserved_sequence < self.canonical_head.sequence
            || self.last_terminal_sequence > self.last_reserved_sequence
        {
            return Err(OrsError::OrderingHeadMismatch);
        }
        Ok(())
    }
}

impl PersistedValue for crate::GrantClosureCommit {
    const RECORD_TYPE: &'static str = "grant_closure_commit";

    fn validate_persisted(&self) -> Result<(), OrsError> {
        crate::model::validate_grant_closure_contract(self)
    }
}

impl PersistedValue for DurableGrantClosureRecord {
    const RECORD_TYPE: &'static str = "grant_closure";

    fn validate_persisted(&self) -> Result<(), OrsError> {
        PersistedValue::validate_persisted(&self.commit)?;
        if self.operation_order == 0 {
            return Err(OrsError::IntegrityProblem {
                record_type: "grant_closure",
                reason: "operation order is zero".to_owned(),
            });
        }
        let expected = match self.commit.state {
            crate::GrantClosureState::Active => OperationalPhase::Active,
            crate::GrantClosureState::Revoked => OperationalPhase::Fenced,
        };
        if self.phase != expected {
            return Err(OrsError::IntegrityProblem {
                record_type: "grant_closure",
                reason: "closure phase disagrees with its committed state".to_owned(),
            });
        }
        Ok(())
    }
}

impl PersistedValue for DurableGrantGraphRevision {
    const RECORD_TYPE: &'static str = "grant_graph_revision";

    fn validate_persisted(&self) -> Result<(), OrsError> {
        if self.revision == 0 {
            return Err(OrsError::IntegrityProblem {
                record_type: "grant_graph_revision",
                reason: "revision watermark is zero".to_owned(),
            });
        }
        if self.operation_order == 0 {
            return Err(OrsError::IntegrityProblem {
                record_type: "grant_graph_revision",
                reason: "operation order is zero".to_owned(),
            });
        }
        Ok(())
    }
}

impl PersistedValue for ReservationRecord {
    const RECORD_TYPE: &'static str = "reservation";

    fn validate_persisted(&self) -> Result<(), OrsError> {
        self.token.writer_epoch.validate()?;
        self.token.state_fence.validate()?;
        if self.token.reservation_order == 0
            || self.token.scopes.is_empty()
            || self.token.writer_epoch.current.epoch
                != self.token.state_fence.observed_authority_epoch
        {
            return Err(OrsError::IntegrityProblem {
                record_type: Self::RECORD_TYPE,
                reason: "invalid token order, scope set, or epoch fence".to_owned(),
            });
        }
        crate::model::validate_digest(
            &self.token.prepared_transition_sha256,
            "prepared_transition_sha256",
        )?;
        let mut scopes = BTreeSet::new();
        for scope in &self.token.scopes {
            scope.expected_head.validate()?;
            if scope.reserved_sequence <= scope.expected_head.sequence
                || !scopes.insert(scope.scope.clone())
            {
                return Err(OrsError::IntegrityProblem {
                    record_type: Self::RECORD_TYPE,
                    reason: "invalid or duplicate reserved scope".to_owned(),
                });
            }
        }
        if self.state == ReservationState::Reconciling && self.unknown_reason.is_none() {
            return Err(OrsError::IntegrityProblem {
                record_type: Self::RECORD_TYPE,
                reason: "reconciling record has no recovery reason".to_owned(),
            });
        }
        if self.state != ReservationState::Reconciling && self.unknown_reason.is_some() {
            return Err(OrsError::IntegrityProblem {
                record_type: Self::RECORD_TYPE,
                reason: "terminal and unknown markers conflict".to_owned(),
            });
        }
        Ok(())
    }
}

impl PersistedValue for DurableOperationalRecord {
    const RECORD_TYPE: &'static str = "operational_record";

    fn validate_persisted(&self) -> Result<(), OrsError> {
        self.input.validate()?;
        if self.operation_order == 0
            || self.terminal_receipt_id.is_some() != self.terminal_receipt_sha256.is_some()
        {
            return Err(OrsError::IntegrityProblem {
                record_type: Self::RECORD_TYPE,
                reason: "invalid order or partial terminal receipt binding".to_owned(),
            });
        }
        if let Some(digest) = &self.terminal_receipt_sha256 {
            crate::model::validate_digest(digest, "terminal_receipt_sha256")?;
        }
        if let Some(record) = &self.generation_cutover {
            record
                .validate()
                .map_err(|error| OrsError::IntegrityProblem {
                    record_type: Self::RECORD_TYPE,
                    reason: error.to_string(),
                })?;
            let expected_record_id =
                OpaqueLabel::new(format!("generation-cutover:{}", record.cutover_id))?;
            let expected_subject = OpaqueLabel::new(record.route_scope.clone())?;
            if !matches!(
                self.kind,
                OperationalKind::GenerationTransition | OperationalKind::GenerationCutover
            ) || self.input.record_id != expected_record_id
                || self.input.subject_id != expected_subject
                || self.input.authority_epoch.current.epoch != record.old_epoch.value()
            {
                return Err(OrsError::IntegrityProblem {
                    record_type: Self::RECORD_TYPE,
                    reason: "generation input identity does not match typed cutover".to_owned(),
                });
            }
            if !matches!(
                &self.input.payload,
                RecoveryPayload::ImmutableLocator { locator }
                    if locator.as_str() == format!("ors:generation-cutover:{}", record.cutover_id)
            ) {
                return Err(OrsError::IntegrityProblem {
                    record_type: Self::RECORD_TYPE,
                    reason: "generation input locator does not match typed cutover".to_owned(),
                });
            }
            let valid_phase = matches!(
                (self.kind, self.phase, record.state),
                (
                    OperationalKind::GenerationTransition,
                    OperationalPhase::Applying,
                    GenerationCutoverState::Armed,
                ) | (
                    OperationalKind::GenerationTransition,
                    OperationalPhase::Reconciling,
                    GenerationCutoverState::Reconciling,
                ) | (
                    OperationalKind::GenerationTransition,
                    OperationalPhase::Fenced,
                    GenerationCutoverState::FailedRequiresForwardCutover,
                ) | (
                    OperationalKind::GenerationCutover,
                    OperationalPhase::Active,
                    GenerationCutoverState::Committed,
                )
            );
            if !valid_phase {
                return Err(OrsError::IntegrityProblem {
                    record_type: Self::RECORD_TYPE,
                    reason: "generation state and operational phase disagree".to_owned(),
                });
            }
        }
        Ok(())
    }
}

impl PersistedValue for DurableInboxRecord {
    const RECORD_TYPE: &'static str = "recovery_inbox";

    fn validate_persisted(&self) -> Result<(), OrsError> {
        self.item.validate()?;
        if self.operation_order == 0
            || self.terminal_receipt_id.is_some() != self.terminal_receipt_sha256.is_some()
            || (self.disposition == RecoveryInboxDisposition::Imported
                && self.terminal_receipt_id.is_some())
            || (self.disposition != RecoveryInboxDisposition::Imported
                && self.terminal_receipt_id.is_none())
        {
            return Err(OrsError::IntegrityProblem {
                record_type: Self::RECORD_TYPE,
                reason: "invalid inbox phase or terminal binding".to_owned(),
            });
        }
        if let Some(digest) = &self.terminal_receipt_sha256 {
            crate::model::validate_digest(digest, "inbox_terminal_receipt_sha256")?;
        }
        Ok(())
    }
}

impl PersistedValue for ScopeTerminalReceipt {
    const RECORD_TYPE: &'static str = "scope_terminal";

    fn validate_persisted(&self) -> Result<(), OrsError> {
        crate::model::validate_digest(&self.receipt_sha256, "scope_terminal_receipt_sha256")?;
        if self.reserved_sequence == 0
            || self.gap != (self.disposition == CanonicalDisposition::Rejected)
        {
            return Err(OrsError::IntegrityProblem {
                record_type: Self::RECORD_TYPE,
                reason: "invalid terminal sequence or gap disposition".to_owned(),
            });
        }
        Ok(())
    }
}

impl PersistedValue for SupervisionLeaseStageReceipt {
    const RECORD_TYPE: &'static str = "supervision_lease_staged";

    fn validate_persisted(&self) -> Result<(), OrsError> {
        self.validate()
    }
}

impl PersistedValue for SupervisionLeaseSnapshot {
    const RECORD_TYPE: &'static str = "supervision_lease_snapshot";

    fn validate_persisted(&self) -> Result<(), OrsError> {
        self.validate()
    }
}

impl PersistedValue for SupervisionLeaseStageResolution {
    const RECORD_TYPE: &'static str = "supervision_lease_stage_resolution";

    fn validate_persisted(&self) -> Result<(), OrsError> {
        self.validate()
    }
}

impl PersistedValue for DurableSupervisionLeaseResult {
    const RECORD_TYPE: &'static str = "supervision_lease_result";

    fn validate_persisted(&self) -> Result<(), OrsError> {
        self.ticket.validate()?;
        self.snapshot.validate()?;
        if self.snapshot.record.artifact != self.artifact {
            return Err(OrsError::SupervisionLeaseBindingMismatch);
        }
        Ok(())
    }
}

impl PersistedValue for crate::StoreRebindReplayRecord {
    const RECORD_TYPE: &'static str = "store_rebind_replay";

    fn validate_persisted(&self) -> Result<(), OrsError> {
        self.validate()
    }
}

impl PersistedValue for StoredCutoverOwnership {
    const RECORD_TYPE: &'static str = "cutover_ownership";

    fn validate_persisted(&self) -> Result<(), OrsError> {
        self.validate_persisted()
    }
}

impl PersistedValue for UnknownCommitRecord {
    const RECORD_TYPE: &'static str = "unknown_commit_recovery";

    fn validate_persisted(&self) -> Result<(), OrsError> {
        self.validate()
    }
}

pub(super) fn decode<T: PersistedValue>(value: &str) -> Result<T, OrsError> {
    decode_named(value, T::RECORD_TYPE)
}

pub(super) fn decode_named<T: PersistedValue>(
    value: &str,
    record_type: &'static str,
) -> Result<T, OrsError> {
    let decoded: T = serde_json::from_str(value).map_err(|error| OrsError::IntegrityProblem {
        record_type,
        reason: error.to_string(),
    })?;
    decoded
        .validate_persisted()
        .map_err(|error| OrsError::IntegrityProblem {
            record_type,
            reason: error.to_string(),
        })?;
    Ok(decoded)
}
