//! Field-complete record-family evidence for observation admission.
//!
//! Exact ordinary families reuse the existing foundation record owners.  A
//! generic v1 event can therefore remain useful as a cold compatibility hint
//! without becoming an exact family merely because its caller supplied a
//! label, event kind, or prose description.

use crate::{
    AuditRecord, ChangeRecord, CoverageGap, MaintenanceRecord, ObservationError,
    ObservationEventCore, ObservationRecordEnvelope, ObservationRecordKind, TelemetryRecord,
};
use eliot_contracts::{
    ContractError, ContractIdentity, ContractVersion, canonical_json_bytes,
    contract_identity as foundation_contract_identity, sha256_hex,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Stable identity of the field-complete record-family contract.
pub const RECORD_FAMILY_CONTRACT_NAME: &str = "eliot.foundation.observation-record-family";
/// Breaking v2 revision that preserves family-specific evidence.
pub const RECORD_FAMILY_CONTRACT_VERSION: ContractVersion = ContractVersion::new(2, 0, 0);
/// Exact v1 contract identity used by the explicit importer.
pub const LEGACY_OBSERVATION_CONTRACT_REF: &str = "eliot.foundation.observation-contracts@1.0.0";

/// Validation and migration failures at the v2 record-family boundary.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum RecordFamilyContractError {
    /// A shared foundation primitive rejected its value.
    #[error("foundation contract: {0}")]
    Foundation(ContractError),
    /// The v1 observation contract rejected a nested value.
    #[error("observation contract: {0}")]
    Observation(ObservationError),
    /// A required field is blank or contains control characters.
    #[error("invalid field {field}: {reason}")]
    InvalidField {
        /// Stable field path.
        field: &'static str,
        /// Stable validation reason.
        reason: &'static str,
    },
    /// The payload and envelope markers cannot describe one record.
    #[error("record-family shape conflict: {reason}")]
    ShapeConflict {
        /// Stable public reason.
        reason: &'static str,
    },
    /// A caller hint contradicts exact family evidence.
    #[error("record-family hint conflict: expected {expected:?}, got {hinted:?}")]
    FamilyHintConflict {
        /// Family established by the payload.
        expected: ObservationRecordKind,
        /// Contradictory caller hint.
        hinted: ObservationRecordKind,
    },
    /// A digest is not canonical lowercase SHA-256 text.
    #[error("invalid digest field {field}")]
    InvalidDigest {
        /// Stable field path.
        field: &'static str,
    },
    /// Canonical serialization or raw-content parsing failed.
    #[error("record-family canonicalization failed: {0}")]
    Canonicalization(String),
    /// The retained legacy digest no longer matches the retained bytes.
    #[error("legacy content digest mismatch")]
    LegacyContentDigestMismatch,
    /// The retained legacy bytes no longer parse to the retained record.
    #[error("legacy content does not match the retained v1 record")]
    LegacyContentMismatch,
    /// The deterministic v2 projection was changed after import.
    #[error("legacy v2 projection mismatch")]
    LegacyProjectionMismatch,
    /// The stored import ceiling was changed after import.
    #[error("legacy import disposition does not match the imported record")]
    LegacyDispositionMismatch,
    /// The canonical parsed v1 shape was changed after import.
    #[error("legacy canonical digest mismatch")]
    LegacyDigestMismatch,
}

impl From<ContractError> for RecordFamilyContractError {
    fn from(error: ContractError) -> Self {
        Self::Foundation(error)
    }
}

impl From<ObservationError> for RecordFamilyContractError {
    fn from(error: ObservationError) -> Self {
        Self::Observation(error)
    }
}

fn text(value: &str, field: &'static str) -> Result<(), RecordFamilyContractError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(RecordFamilyContractError::InvalidField {
            field,
            reason: "must be non-blank and contain no control characters",
        });
    }
    Ok(())
}

fn digest(value: &str, field: &'static str) -> Result<(), RecordFamilyContractError> {
    if value.len() != 64
        || value
            .bytes()
            .any(|byte| !matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(RecordFamilyContractError::InvalidDigest { field });
    }
    Ok(())
}

/// Dedicated v2 wrapper for an explicit coverage gap.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CoverageGapRecordV2 {
    /// Stable journal identity.
    pub record_id: String,
    /// Field-complete gap payload owned by the v1 foundation contract.
    pub gap: CoverageGap,
}

impl CoverageGapRecordV2 {
    fn validate(&self) -> Result<(), RecordFamilyContractError> {
        text(&self.record_id, "payload.record_id")?;
        self.gap.validate()?;
        Ok(())
    }
}

/// Dedicated v2 journal-control audit record.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JournalControlAuditRecordV2 {
    /// Stable journal identity.
    pub record_id: String,
    /// Normalized event describing the control condition.
    pub event: ObservationEventCore,
}

impl JournalControlAuditRecordV2 {
    fn validate(&self) -> Result<(), RecordFamilyContractError> {
        text(&self.record_id, "payload.record_id")?;
        self.event.validate()?;
        Ok(())
    }
}

/// Generic ordinary material whose family-specific fields are unavailable.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AmbiguousOrdinaryRecordV2 {
    /// Stable journal identity.
    pub record_id: String,
    /// Common event retained without family promotion.
    pub event: ObservationEventCore,
    /// Source contract that supplied the generic event.
    pub source_contract_ref: String,
    /// Stable reason exact family evidence is unavailable.
    pub ambiguity_reason_ref: String,
}

impl AmbiguousOrdinaryRecordV2 {
    fn validate(&self) -> Result<(), RecordFamilyContractError> {
        text(&self.record_id, "payload.record_id")?;
        self.event.validate()?;
        text(&self.source_contract_ref, "payload.source_contract_ref")?;
        text(&self.ambiguity_reason_ref, "payload.ambiguity_reason_ref")
    }
}

/// Closed v2 family payload. Exact ordinary variants reuse existing owners.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "payload", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RecordFamilyPayloadV2 {
    /// Field-complete audit record.
    Audit(AuditRecord),
    /// Field-complete bounded telemetry record.
    Telemetry(TelemetryRecord),
    /// Field-complete change record.
    Change(ChangeRecord),
    /// Field-complete maintenance record.
    Maintenance(MaintenanceRecord),
    /// Explicit coverage-gap record.
    CoverageGap(CoverageGapRecordV2),
    /// Explicit journal-control audit record.
    JournalControlAudit(JournalControlAuditRecordV2),
    /// Generic ordinary record retained as non-exact material.
    AmbiguousOrdinary(AmbiguousOrdinaryRecordV2),
}

impl RecordFamilyPayloadV2 {
    fn validate(&self) -> Result<(), RecordFamilyContractError> {
        match self {
            Self::Audit(value) => value.validate().map_err(Into::into),
            Self::Telemetry(value) => value.validate().map_err(Into::into),
            Self::Change(value) => value.validate().map_err(Into::into),
            Self::Maintenance(value) => value.validate().map_err(Into::into),
            Self::CoverageGap(value) => value.validate(),
            Self::JournalControlAudit(value) => value.validate(),
            Self::AmbiguousOrdinary(value) => value.validate(),
        }
    }

    /// Returns the identity carried by the payload.
    pub fn record_id(&self) -> &str {
        match self {
            Self::Audit(value) => &value.record_id,
            Self::Telemetry(value) => &value.record_id,
            Self::Change(value) => &value.record_id,
            Self::Maintenance(value) => &value.record_id,
            Self::CoverageGap(value) => &value.record_id,
            Self::JournalControlAudit(value) => &value.record_id,
            Self::AmbiguousOrdinary(value) => &value.record_id,
        }
    }

    pub const fn exact_family(&self) -> Option<ObservationRecordKind> {
        match self {
            Self::Audit(_) | Self::JournalControlAudit(_) => Some(ObservationRecordKind::Audit),
            Self::Telemetry(_) => Some(ObservationRecordKind::Telemetry),
            Self::Change(_) => Some(ObservationRecordKind::Change),
            Self::Maintenance(_) => Some(ObservationRecordKind::Maintenance),
            Self::CoverageGap(_) => Some(ObservationRecordKind::CoverageGap),
            Self::AmbiguousOrdinary(_) => None,
        }
    }

    pub const fn is_journal_control(&self) -> bool {
        matches!(self, Self::JournalControlAudit(_))
    }
}

/// Deterministic first-pass classification of one v2 envelope.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(tag = "disposition", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RecordFamilyClassification {
    /// Exact field-complete family evidence is present.
    Exact {
        /// Mechanically established family.
        family: ObservationRecordKind,
    },
    /// A caller hint is retained but remains non-exact and cold.
    CompatibleHint {
        /// Caller-selected family retained as a hint.
        hinted_family: ObservationRecordKind,
    },
    /// No exact evidence or caller hint is available.
    AmbiguousCandidate,
}

/// Versioned family-sensitive observation envelope.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservationRecordEnvelopeV2 {
    /// Exact family payload or explicit ordinary ambiguity.
    pub payload: RecordFamilyPayloadV2,
    /// Caller-selected family retained only as a consistency hint.
    pub caller_family_hint: Option<ObservationRecordKind>,
    /// Optional parent record; journal-control records cannot recurse.
    pub parent_record_id: Option<String>,
}

impl ObservationRecordEnvelopeV2 {
    fn validate_structure(&self) -> Result<(), RecordFamilyContractError> {
        self.payload.validate()?;
        if let Some(parent) = &self.parent_record_id {
            text(parent, "parent_record_id")?;
            if parent == self.payload.record_id() {
                return Err(RecordFamilyContractError::ShapeConflict {
                    reason: "a record cannot be its own parent",
                });
            }
        }
        if self.payload.is_journal_control() && self.parent_record_id.is_some() {
            return Err(RecordFamilyContractError::ShapeConflict {
                reason: "journal-control events cannot have a parent record",
            });
        }
        Ok(())
    }

    /// Returns the stable record identity without duplicating it in the envelope.
    pub fn record_id(&self) -> &str {
        self.payload.record_id()
    }

    /// Derives exact, compatible-hint, or ambiguous status mechanically.
    pub fn classification(&self) -> Result<RecordFamilyClassification, RecordFamilyContractError> {
        self.validate_structure()?;
        if let Some(expected) = self.payload.exact_family() {
            if let Some(hinted) = self.caller_family_hint
                && hinted != expected
            {
                return Err(RecordFamilyContractError::FamilyHintConflict { expected, hinted });
            }
            return Ok(RecordFamilyClassification::Exact { family: expected });
        }
        match self.caller_family_hint {
            Some(ObservationRecordKind::CoverageGap) => {
                Err(RecordFamilyContractError::ShapeConflict {
                    reason: "an ordinary event cannot use a coverage-gap hint",
                })
            }
            Some(hinted_family) => Ok(RecordFamilyClassification::CompatibleHint { hinted_family }),
            None => Ok(RecordFamilyClassification::AmbiguousCandidate),
        }
    }

    /// Validates the envelope and its derived classification.
    pub fn validate(&self) -> Result<(), RecordFamilyContractError> {
        self.classification().map(|_| ())
    }

    /// Returns a digest of the complete validated v2 envelope.
    pub fn canonical_sha256(&self) -> Result<String, RecordFamilyContractError> {
        self.validate()?;
        let bytes = canonical_json_bytes(self)
            .map_err(|error| RecordFamilyContractError::Canonicalization(error.to_string()))?;
        Ok(sha256_hex(&bytes))
    }
}

/// Fail-closed coherence binding between v1 envelope markers and v2 exact family.
///
/// Binds v1 `kind`, `journal_control_event`, `coverage_gap` presence and
/// `parent_record_id` / `record_id` to v2 `exact_family()`, `is_journal_control()`,
/// payload identity and envelope parent.  `JournalControlAudit` maps to `Audit`
/// where the contract requires it.  Used at both submission and receipt/
/// persisted-replay validation; any contradiction fails closed before admission
/// or rebuild.
pub fn check_v1_v2_coherence(
    v1: &ObservationRecordEnvelope,
    v2: &ObservationRecordEnvelopeV2,
) -> Result<(), RecordFamilyContractError> {
    v2.validate()?;
    if v1.record_id != v2.record_id() {
        return Err(RecordFamilyContractError::ShapeConflict {
            reason: "v1/v2 record_id mismatch",
        });
    }
    if v1.parent_record_id != v2.parent_record_id {
        return Err(RecordFamilyContractError::ShapeConflict {
            reason: "v1/v2 parent_record_id mismatch",
        });
    }
    let v2_is_control = v2.payload.is_journal_control();
    if v1.journal_control_event != v2_is_control {
        return Err(RecordFamilyContractError::ShapeConflict {
            reason: "v1/v2 journal-control mismatch",
        });
    }
    match v2.payload.exact_family() {
        Some(family) => {
            if v1.kind != family {
                return Err(RecordFamilyContractError::ShapeConflict {
                    reason: "v1/v2 family mismatch",
                });
            }
            let v1_is_gap = v1.coverage_gap.is_some();
            let v2_is_gap = matches!(v2.payload, RecordFamilyPayloadV2::CoverageGap(_));
            if v1_is_gap != v2_is_gap {
                return Err(RecordFamilyContractError::ShapeConflict {
                    reason: "v1/v2 coverage mismatch",
                });
            }
        }
        None => {
            if v1.kind == ObservationRecordKind::CoverageGap {
                return Err(RecordFamilyContractError::ShapeConflict {
                    reason: "v1 coverage gap cannot be ambiguous",
                });
            }
        }
    }
    Ok(())
}

/// Explicit exactness ceiling for one v1 import.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum LegacyV1ImportDisposition {
    /// Dedicated v1 coverage-gap shape.
    ExactCoverageGap,
    /// Dedicated v1 journal-control shape.
    ExactJournalControlAudit,
    /// Generic ordinary v1 material remains a non-exact hint.
    CompatibleHintOnly,
}

/// Exact persisted v1 content supplied by the owning persistence adapter.
///
/// The importer derives the digest from these bytes. A caller cannot select a
/// digest independently of the content it is asking the contract to import.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LegacyV1PersistedContent {
    /// Immutable artifact/blob handle for the bytes.
    pub artifact_ref: String,
    /// Exact serialized v1 bytes returned by that handle.
    pub bytes: Vec<u8>,
}

impl LegacyV1PersistedContent {
    fn validate(&self) -> Result<(), RecordFamilyContractError> {
        text(&self.artifact_ref, "persisted_content.artifact_ref")?;
        if self.bytes.is_empty() {
            return Err(RecordFamilyContractError::InvalidField {
                field: "persisted_content.bytes",
                reason: "must not be empty",
            });
        }
        Ok(())
    }
}

/// Input for a loss-aware v1 compatibility import.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LegacyV1ImportRequest {
    /// Parsed v1 value retained for compatibility and replay.
    pub legacy_record: ObservationRecordEnvelope,
    /// Exact persisted bytes and immutable handle selected by the owner.
    pub persisted_content: LegacyV1PersistedContent,
}

impl LegacyV1ImportRequest {
    /// Validates the v1 record and binds it to the actual returned content.
    pub fn validate(&self) -> Result<(), RecordFamilyContractError> {
        self.legacy_record.validate()?;
        self.persisted_content.validate()?;
        let parsed: ObservationRecordEnvelope =
            serde_json::from_slice(&self.persisted_content.bytes)
                .map_err(|error| RecordFamilyContractError::Canonicalization(error.to_string()))?;
        if parsed != self.legacy_record {
            return Err(RecordFamilyContractError::LegacyContentMismatch);
        }
        Ok(())
    }
}

/// Immutable result of importing one persisted v1 envelope.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LegacyV1Import {
    /// Original parsed v1 value retained as compatibility evidence.
    pub legacy_record: ObservationRecordEnvelope,
    /// Immutable handle for the retained original bytes.
    pub original_artifact_ref: String,
    /// Exact bytes returned by the immutable handle.
    pub original_bytes: Vec<u8>,
    /// Digest derived from the retained bytes, never caller-selected.
    pub original_bytes_sha256: String,
    /// Digest binding the immutable handle to the retained content digest.
    pub original_content_binding_sha256: String,
    /// Digest of the canonical parsed v1 shape.
    pub legacy_canonical_sha256: String,
    /// Deterministic field-complete v2 projection.
    pub record_v2: ObservationRecordEnvelopeV2,
    /// Exactness ceiling assigned by the import.
    pub disposition: LegacyV1ImportDisposition,
}

impl LegacyV1Import {
    /// Validates immutable content lineage, projection and disposition.
    pub fn validate(&self) -> Result<(), RecordFamilyContractError> {
        self.legacy_record.validate()?;
        text(&self.original_artifact_ref, "original_artifact_ref")?;
        if self.original_bytes.is_empty() {
            return Err(RecordFamilyContractError::InvalidField {
                field: "original_bytes",
                reason: "must not be empty",
            });
        }
        let actual_bytes_digest = sha256_hex(&self.original_bytes);
        if actual_bytes_digest != self.original_bytes_sha256 {
            return Err(RecordFamilyContractError::LegacyContentDigestMismatch);
        }
        digest(&self.original_bytes_sha256, "original_bytes_sha256")?;
        let binding = canonical_json_bytes(&serde_json::json!({
            "artifact_ref": self.original_artifact_ref,
            "content_sha256": self.original_bytes_sha256,
        }))
        .map_err(|error| RecordFamilyContractError::Canonicalization(error.to_string()))?;
        if sha256_hex(&binding) != self.original_content_binding_sha256 {
            return Err(RecordFamilyContractError::LegacyContentDigestMismatch);
        }
        digest(
            &self.original_content_binding_sha256,
            "original_content_binding_sha256",
        )?;
        let parsed: ObservationRecordEnvelope = serde_json::from_slice(&self.original_bytes)
            .map_err(|error| RecordFamilyContractError::Canonicalization(error.to_string()))?;
        if parsed != self.legacy_record {
            return Err(RecordFamilyContractError::LegacyContentMismatch);
        }
        let canonical = canonical_json_bytes(&self.legacy_record)
            .map_err(|error| RecordFamilyContractError::Canonicalization(error.to_string()))?;
        if sha256_hex(&canonical) != self.legacy_canonical_sha256 {
            return Err(RecordFamilyContractError::LegacyDigestMismatch);
        }
        let (expected_record, expected_disposition) = project_legacy_record(&self.legacy_record)?;
        if self.record_v2 != expected_record {
            return Err(RecordFamilyContractError::LegacyProjectionMismatch);
        }
        if self.disposition != expected_disposition {
            return Err(RecordFamilyContractError::LegacyDispositionMismatch);
        }
        self.record_v2.validate()?;
        Ok(())
    }
}

fn project_legacy_record(
    legacy_record: &ObservationRecordEnvelope,
) -> Result<(ObservationRecordEnvelopeV2, LegacyV1ImportDisposition), RecordFamilyContractError> {
    legacy_record.validate()?;
    if let Some(gap) = legacy_record.coverage_gap.clone() {
        return Ok((
            ObservationRecordEnvelopeV2 {
                payload: RecordFamilyPayloadV2::CoverageGap(CoverageGapRecordV2 {
                    record_id: legacy_record.record_id.clone(),
                    gap,
                }),
                caller_family_hint: Some(ObservationRecordKind::CoverageGap),
                parent_record_id: legacy_record.parent_record_id.clone(),
            },
            LegacyV1ImportDisposition::ExactCoverageGap,
        ));
    }
    if legacy_record.journal_control_event {
        let event =
            legacy_record
                .event
                .clone()
                .ok_or(RecordFamilyContractError::ShapeConflict {
                    reason: "validated journal-control v1 record has no event",
                })?;
        return Ok((
            ObservationRecordEnvelopeV2 {
                payload: RecordFamilyPayloadV2::JournalControlAudit(JournalControlAuditRecordV2 {
                    record_id: legacy_record.record_id.clone(),
                    event,
                }),
                caller_family_hint: Some(ObservationRecordKind::Audit),
                parent_record_id: None,
            },
            LegacyV1ImportDisposition::ExactJournalControlAudit,
        ));
    }
    let event = legacy_record
        .event
        .clone()
        .ok_or(RecordFamilyContractError::ShapeConflict {
            reason: "validated ordinary v1 record has no event",
        })?;
    Ok((
        ObservationRecordEnvelopeV2 {
            payload: RecordFamilyPayloadV2::AmbiguousOrdinary(AmbiguousOrdinaryRecordV2 {
                record_id: legacy_record.record_id.clone(),
                event,
                source_contract_ref: LEGACY_OBSERVATION_CONTRACT_REF.to_owned(),
                ambiguity_reason_ref: "legacy-v1-generic-family-evidence-unavailable".to_owned(),
            }),
            caller_family_hint: Some(legacy_record.kind),
            parent_record_id: legacy_record.parent_record_id.clone(),
        },
        LegacyV1ImportDisposition::CompatibleHintOnly,
    ))
}

/// Imports one exact persisted v1 payload without overstating its evidence.
pub fn import_legacy_v1(
    request: LegacyV1ImportRequest,
) -> Result<LegacyV1Import, RecordFamilyContractError> {
    request.validate()?;
    let legacy_canonical_sha256 = sha256_hex(
        &canonical_json_bytes(&request.legacy_record)
            .map_err(|error| RecordFamilyContractError::Canonicalization(error.to_string()))?,
    );
    let (record_v2, disposition) = project_legacy_record(&request.legacy_record)?;
    let imported = LegacyV1Import {
        legacy_record: request.legacy_record,
        original_artifact_ref: request.persisted_content.artifact_ref,
        original_bytes: request.persisted_content.bytes,
        original_bytes_sha256: String::new(),
        original_content_binding_sha256: String::new(),
        legacy_canonical_sha256,
        record_v2,
        disposition,
    };
    let mut imported = imported;
    imported.original_bytes_sha256 = sha256_hex(&imported.original_bytes);
    let binding = canonical_json_bytes(&serde_json::json!({
        "artifact_ref": imported.original_artifact_ref,
        "content_sha256": imported.original_bytes_sha256,
    }))
    .map_err(|error| RecordFamilyContractError::Canonicalization(error.to_string()))?;
    imported.original_content_binding_sha256 = sha256_hex(&binding);
    imported.validate()?;
    Ok(imported)
}

/// Returns the content-addressed identity of the v2 family contract.
pub fn record_family_contract_identity() -> Result<ContractIdentity, RecordFamilyContractError> {
    foundation_contract_identity(
        RECORD_FAMILY_CONTRACT_NAME,
        RECORD_FAMILY_CONTRACT_VERSION,
        &serde_json::json!({
            "record": schemars::schema_for!(ObservationRecordEnvelopeV2),
            "classification": schemars::schema_for!(RecordFamilyClassification),
            "legacy_import_request": schemars::schema_for!(LegacyV1ImportRequest),
            "legacy_import": schemars::schema_for!(LegacyV1Import),
        }),
    )
    .map_err(RecordFamilyContractError::Foundation)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        CaptureMode, CoverageDisposition, CoverageEvidence, CoverageInterval, GapDisposition,
        ObservationEventIdentity, ObservationKind, ObservationScope, PrivacyRetentionDisclosure,
        ProducerTrace,
    };
    use eliot_contracts::{AuthorityEpoch, ClockReading, ResourceGeneration, StateFence};

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn fence() -> StateFence {
        StateFence::new(AuthorityEpoch::genesis(), ResourceGeneration::genesis())
    }

    fn event(kind: ObservationKind) -> Result<ObservationEventCore, ObservationError> {
        Ok(ObservationEventCore {
            event_id_and_time: ObservationEventIdentity {
                event_id: format!("event-{kind:?}"),
                clock: ClockReading::default(),
            },
            producer_generation_and_trace: ProducerTrace {
                producer: "producer:test".to_owned(),
                generation: "generation:1".to_owned(),
                trace_ref: Some("trace:1".to_owned()),
            },
            kind,
            affected_scope: ObservationScope {
                work_scope: "scope:test".parse()?,
                task_ref: None,
                attempt_ref: None,
                module_or_route_ref: None,
            },
            observed_delta: "observed delta".to_owned(),
            expected_baseline: Some("expected baseline".to_owned()),
            evidence_and_raw_handles: vec!["evidence:1".to_owned()],
            coverage_and_blind_intervals: CoverageEvidence {
                disposition: CoverageDisposition::Complete,
                denominator_source_ref: "denominator:test".to_owned(),
                interval: Some(CoverageInterval::new(1, 1)?),
                blind_intervals: Vec::new(),
                observed_count: 1,
            },
            privacy_retention_and_disclosure: PrivacyRetentionDisclosure {
                privacy_domain_ref: "privacy:test".to_owned(),
                retention_policy_ref: "retention:test".to_owned(),
                disclosure_class: "internal".to_owned(),
            },
            candidate_importance: 1,
            dedup_key: format!("dedup-{kind:?}"),
        })
    }

    fn gap() -> CoverageGap {
        CoverageGap {
            gap_id: "gap:1".to_owned(),
            obligation_profile_ref: "obligation:1".to_owned(),
            reason_ref: "reason:gap".to_owned(),
            affected_interval: None,
            disposition: GapDisposition::DegradeDependentGuarantees,
            protected: false,
            evidence_refs: vec!["evidence:gap".to_owned()],
        }
    }

    fn ambiguous(
        record_id: &str,
        kind: ObservationKind,
        hint: Option<ObservationRecordKind>,
    ) -> Result<ObservationRecordEnvelopeV2, ObservationError> {
        Ok(ObservationRecordEnvelopeV2 {
            payload: RecordFamilyPayloadV2::AmbiguousOrdinary(AmbiguousOrdinaryRecordV2 {
                record_id: record_id.to_owned(),
                event: event(kind)?,
                source_contract_ref: "source:generic".to_owned(),
                ambiguity_reason_ref: "family-fields-unavailable".to_owned(),
            }),
            caller_family_hint: hint,
            parent_record_id: None,
        })
    }

    #[test]
    fn exact_payloads_round_trip_and_reuse_family_owners() -> TestResult {
        let records = [
            ObservationRecordEnvelopeV2 {
                payload: RecordFamilyPayloadV2::Audit(AuditRecord {
                    record_id: "record:audit".to_owned(),
                    core: event(ObservationKind::Security)?,
                    audit_action: "permission checked".to_owned(),
                    state_fence: fence(),
                }),
                caller_family_hint: Some(ObservationRecordKind::Audit),
                parent_record_id: None,
            },
            ObservationRecordEnvelopeV2 {
                payload: RecordFamilyPayloadV2::Telemetry(TelemetryRecord {
                    record_id: "record:telemetry".to_owned(),
                    core: event(ObservationKind::QueueResource)?,
                    capture_mode: CaptureMode::Sampled,
                    sample_count: 4,
                    raw_evidence_handle: Some("blob:telemetry".to_owned()),
                }),
                caller_family_hint: Some(ObservationRecordKind::Telemetry),
                parent_record_id: None,
            },
            ObservationRecordEnvelopeV2 {
                payload: RecordFamilyPayloadV2::Change(ChangeRecord {
                    record_id: "record:change".to_owned(),
                    core: event(ObservationKind::Configuration)?,
                    change_operation: "configuration updated".to_owned(),
                    origin_confidence: "host-observed".to_owned(),
                    state_fence: fence(),
                }),
                caller_family_hint: Some(ObservationRecordKind::Change),
                parent_record_id: None,
            },
            ObservationRecordEnvelopeV2 {
                payload: RecordFamilyPayloadV2::Maintenance(MaintenanceRecord {
                    record_id: "record:maintenance".to_owned(),
                    core: event(ObservationKind::Maintenance)?,
                    maintenance_action: "rebuild projection".to_owned(),
                    trigger_ref: "problem:1".to_owned(),
                }),
                caller_family_hint: Some(ObservationRecordKind::Maintenance),
                parent_record_id: None,
            },
            ObservationRecordEnvelopeV2 {
                payload: RecordFamilyPayloadV2::CoverageGap(CoverageGapRecordV2 {
                    record_id: "record:gap".to_owned(),
                    gap: gap(),
                }),
                caller_family_hint: Some(ObservationRecordKind::CoverageGap),
                parent_record_id: None,
            },
        ];

        for record in records {
            assert!(matches!(
                record.classification()?,
                RecordFamilyClassification::Exact { .. }
            ));
            let encoded = serde_json::to_string(&record)?;
            assert_eq!(
                serde_json::from_str::<ObservationRecordEnvelopeV2>(&encoded)?,
                record
            );
        }
        Ok(())
    }

    #[test]
    fn generic_kind_and_compatible_hint_stay_cold() -> TestResult {
        let compatible = ambiguous(
            "record:compatible",
            ObservationKind::QueueResource,
            Some(ObservationRecordKind::Telemetry),
        )?;
        assert_eq!(
            compatible.classification()?,
            RecordFamilyClassification::CompatibleHint {
                hinted_family: ObservationRecordKind::Telemetry
            }
        );
        let ambiguous = ambiguous("record:ambiguous", ObservationKind::Security, None)?;
        assert_eq!(
            ambiguous.classification()?,
            RecordFamilyClassification::AmbiguousCandidate
        );
        Ok(())
    }

    #[test]
    fn wrong_hint_and_control_parent_fail_closed() -> TestResult {
        let mut exact = ObservationRecordEnvelopeV2 {
            payload: RecordFamilyPayloadV2::Audit(AuditRecord {
                record_id: "record:exact".to_owned(),
                core: event(ObservationKind::Security)?,
                audit_action: "checked".to_owned(),
                state_fence: fence(),
            }),
            caller_family_hint: Some(ObservationRecordKind::Telemetry),
            parent_record_id: None,
        };
        assert!(matches!(
            exact.classification(),
            Err(RecordFamilyContractError::FamilyHintConflict { .. })
        ));

        exact.payload = RecordFamilyPayloadV2::JournalControlAudit(JournalControlAuditRecordV2 {
            record_id: "record:control".to_owned(),
            event: event(ObservationKind::QueueResource)?,
        });
        exact.caller_family_hint = Some(ObservationRecordKind::Audit);
        exact.parent_record_id = Some("record:parent".to_owned());
        assert!(matches!(
            exact.classification(),
            Err(RecordFamilyContractError::ShapeConflict { .. })
        ));
        Ok(())
    }

    #[test]
    fn legacy_import_binds_actual_bytes_and_keeps_ordinary_cold() -> TestResult {
        let legacy_record = ObservationRecordEnvelope {
            record_id: "legacy:ordinary".to_owned(),
            kind: ObservationRecordKind::Telemetry,
            event: Some(event(ObservationKind::QueueResource)?),
            coverage_gap: None,
            journal_control_event: false,
            parent_record_id: None,
        };
        let original_bytes = serde_json::to_vec(&legacy_record)?;
        let imported = import_legacy_v1(LegacyV1ImportRequest {
            legacy_record: legacy_record.clone(),
            persisted_content: LegacyV1PersistedContent {
                artifact_ref: "artifact:legacy".to_owned(),
                bytes: original_bytes.clone(),
            },
        })?;
        assert_eq!(imported.original_bytes, original_bytes);
        assert_eq!(
            imported.disposition,
            LegacyV1ImportDisposition::CompatibleHintOnly
        );
        assert_eq!(
            imported.record_v2.classification()?,
            RecordFamilyClassification::CompatibleHint {
                hinted_family: ObservationRecordKind::Telemetry
            }
        );
        imported.validate()?;
        Ok(())
    }

    #[test]
    fn legacy_exact_shapes_and_tampering_are_discriminated() -> TestResult {
        let legacy_record = ObservationRecordEnvelope {
            record_id: "legacy:gap".to_owned(),
            kind: ObservationRecordKind::CoverageGap,
            event: None,
            coverage_gap: Some(gap()),
            journal_control_event: false,
            parent_record_id: None,
        };
        let bytes = serde_json::to_vec(&legacy_record)?;
        let mut imported = import_legacy_v1(LegacyV1ImportRequest {
            legacy_record,
            persisted_content: LegacyV1PersistedContent {
                artifact_ref: "artifact:gap".to_owned(),
                bytes,
            },
        })?;
        assert_eq!(
            imported.disposition,
            LegacyV1ImportDisposition::ExactCoverageGap
        );
        imported.original_bytes.push(b' ');
        assert_eq!(
            imported.validate(),
            Err(RecordFamilyContractError::LegacyContentDigestMismatch)
        );
        let mut imported = import_legacy_v1(LegacyV1ImportRequest {
            legacy_record: ObservationRecordEnvelope {
                record_id: "legacy:handle".to_owned(),
                kind: ObservationRecordKind::CoverageGap,
                event: None,
                coverage_gap: Some(gap()),
                journal_control_event: false,
                parent_record_id: None,
            },
            persisted_content: LegacyV1PersistedContent {
                artifact_ref: "artifact:handle".to_owned(),
                bytes: serde_json::to_vec(&ObservationRecordEnvelope {
                    record_id: "legacy:handle".to_owned(),
                    kind: ObservationRecordKind::CoverageGap,
                    event: None,
                    coverage_gap: Some(gap()),
                    journal_control_event: false,
                    parent_record_id: None,
                })?,
            },
        })?;
        imported.original_artifact_ref = "artifact:other".to_owned();
        assert_eq!(
            imported.validate(),
            Err(RecordFamilyContractError::LegacyContentDigestMismatch)
        );
        Ok(())
    }

    #[test]
    fn legacy_request_rejects_caller_selected_digest_field() {
        let value = serde_json::json!({
            "legacy_record": {},
            "original_artifact_ref": "artifact:legacy",
            "original_bytes_sha256": "a".repeat(64)
        });
        assert!(serde_json::from_value::<LegacyV1ImportRequest>(value).is_err());
    }

    #[test]
    fn v2_identity_is_content_addressed() -> TestResult {
        let identity = record_family_contract_identity()?;
        identity.validate()?;
        assert_eq!(identity.version, RECORD_FAMILY_CONTRACT_VERSION);
        Ok(())
    }
}
