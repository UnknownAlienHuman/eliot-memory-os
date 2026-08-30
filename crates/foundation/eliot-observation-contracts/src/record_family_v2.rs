//! Versioned record-family evidence for observation admission.
//!
//! The legacy v1 envelope stores one generic ordinary event plus a caller-selected
//! family label. This module adds a field-complete v2 contract by reusing the
//! existing family-specific records as the only exact ordinary payloads. Generic
//! legacy material remains compatible or ambiguous rather than being promoted by
//! `ObservationKind`, prose, or model judgement.

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
/// Breaking v2 revision that preserves exact family-specific evidence.
pub const RECORD_FAMILY_CONTRACT_VERSION: ContractVersion = ContractVersion::new(2, 0, 0);
/// Exact legacy contract identity used by the explicit importer.
pub const LEGACY_OBSERVATION_CONTRACT_REF: &str =
    "eliot.foundation.observation-contracts@1.0.0";

/// Validation and migration failures for the v2 record-family contract.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum RecordFamilyContractError {
    /// A shared foundation primitive rejected its value.
    #[error("foundation contract: {0}")]
    Foundation(ContractError),
    /// The legacy/common observation contract rejected a nested value.
    #[error("observation contract: {0}")]
    Observation(ObservationError),
    /// A required field is blank or contains control characters.
    #[error("invalid field {field}: {reason}")]
    InvalidField {
        /// Stable field path.
        field: &'static str,
        /// Stable public reason.
        reason: &'static str,
    },
    /// Event, family evidence, or control marker shapes are incompatible.
    #[error("record-family shape conflict: {reason}")]
    ShapeConflict {
        /// Stable public reason.
        reason: &'static str,
    },
    /// A caller hint contradicts mechanically exact family evidence.
    #[error("record-family hint conflict: expected {expected:?}, got {hinted:?}")]
    FamilyHintConflict {
        /// Family established by exact evidence.
        expected: ObservationRecordKind,
        /// Contradictory caller hint.
        hinted: ObservationRecordKind,
    },
    /// A digest is not canonical lowercase SHA-256 hexadecimal text.
    #[error("invalid digest field {field}")]
    InvalidDigest {
        /// Stable field path.
        field: &'static str,
    },
    /// Canonical serialization failed.
    #[error("record-family canonicalization failed: {0}")]
    Canonicalization(String),
    /// A legacy import disposition does not match the imported record.
    #[error("legacy import disposition does not match the imported record")]
    LegacyDispositionMismatch,
    /// A retained legacy canonical digest was changed.
    #[error("legacy canonical digest mismatch")]
    LegacyDigestMismatch,
    /// The v2 projection no longer matches the deterministic v1 migration.
    #[error("legacy v2 projection mismatch")]
    LegacyProjectionMismatch,
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

/// Dedicated record wrapper for an explicit coverage gap.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CoverageGapRecordV2 {
    /// Stable journal record identity, distinct from the gap identity when needed.
    pub record_id: String,
    /// Field-complete explicit gap payload.
    pub gap: CoverageGap,
}

impl CoverageGapRecordV2 {
    fn validate(&self) -> Result<(), RecordFamilyContractError> {
        text(&self.record_id, "payload.record_id")?;
        self.gap.validate()?;
        Ok(())
    }
}

/// Dedicated journal-health/control record.
///
/// The marker itself mechanically establishes the audit family. The nested event
/// remains the original normalized observation and is not reinterpreted as an
/// ordinary family discriminator.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JournalControlAuditRecordV2 {
    /// Stable journal record identity.
    pub record_id: String,
    /// Normalized control/health observation.
    pub event: ObservationEventCore,
}

impl JournalControlAuditRecordV2 {
    fn validate(&self) -> Result<(), RecordFamilyContractError> {
        text(&self.record_id, "payload.record_id")?;
        self.event.validate()?;
        Ok(())
    }
}

/// Generic ordinary material for which the producer has no exact family payload.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AmbiguousOrdinaryRecordV2 {
    /// Stable journal record identity.
    pub record_id: String,
    /// Common normalized event retained without family promotion.
    pub event: ObservationEventCore,
    /// Contract/source that supplied the generic ordinary event.
    pub source_contract_ref: String,
    /// Stable reason why exact family evidence is unavailable.
    pub ambiguity_reason_ref: String,
}

impl AmbiguousOrdinaryRecordV2 {
    fn validate(&self) -> Result<(), RecordFamilyContractError> {
        text(&self.record_id, "payload.record_id")?;
        self.event.validate()?;
        text(&self.source_contract_ref, "payload.source_contract_ref")?;
        text(
            &self.ambiguity_reason_ref,
            "payload.ambiguity_reason_ref",
        )
    }
}

/// Closed field-complete v2 payload.
///
/// Exact ordinary variants carry the already-owned `AuditRecord`,
/// `TelemetryRecord`, `ChangeRecord`, and `MaintenanceRecord` shapes directly;
/// this module does not define parallel copies of their fields.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "payload", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RecordFamilyPayloadV2 {
    /// Field-complete ordinary audit record.
    Audit(AuditRecord),
    /// Field-complete bounded telemetry record.
    Telemetry(TelemetryRecord),
    /// Field-complete resource/configuration change record.
    Change(ChangeRecord),
    /// Field-complete maintenance record.
    Maintenance(MaintenanceRecord),
    /// Dedicated explicit coverage-gap shape.
    CoverageGap(CoverageGapRecordV2),
    /// Dedicated journal-control marker and event.
    JournalControlAudit(JournalControlAuditRecordV2),
    /// Generic ordinary material with no exact family discriminator.
    AmbiguousOrdinary(AmbiguousOrdinaryRecordV2),
}

impl RecordFamilyPayloadV2 {
    fn validate(&self) -> Result<(), RecordFamilyContractError> {
        match self {
            Self::Audit(value) => {
                value.validate()?;
                Ok(())
            }
            Self::Telemetry(value) => {
                value.validate()?;
                Ok(())
            }
            Self::Change(value) => {
                value.validate()?;
                Ok(())
            }
            Self::Maintenance(value) => {
                value.validate()?;
                Ok(())
            }
            Self::CoverageGap(value) => value.validate(),
            Self::JournalControlAudit(value) => value.validate(),
            Self::AmbiguousOrdinary(value) => value.validate(),
        }
    }

    /// Returns the stable journal record identity carried by the payload.
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

    const fn exact_family(&self) -> Option<ObservationRecordKind> {
        match self {
            Self::Audit(_) | Self::JournalControlAudit(_) => Some(ObservationRecordKind::Audit),
            Self::Telemetry(_) => Some(ObservationRecordKind::Telemetry),
            Self::Change(_) => Some(ObservationRecordKind::Change),
            Self::Maintenance(_) => Some(ObservationRecordKind::Maintenance),
            Self::CoverageGap(_) => Some(ObservationRecordKind::CoverageGap),
            Self::AmbiguousOrdinary(_) => None,
        }
    }

    const fn is_journal_control(&self) -> bool {
        matches!(self, Self::JournalControlAudit(_))
    }
}

/// Derived first-pass family disposition.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(tag = "disposition", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RecordFamilyClassification {
    /// Exact family-specific evidence is present.
    Exact {
        /// Mechanically established family.
        family: ObservationRecordKind,
    },
    /// Only a non-conflicting caller hint is present; it remains non-exact.
    CompatibleHint {
        /// Caller-selected family retained as a hint.
        hinted_family: ObservationRecordKind,
    },
    /// Neither exact evidence nor a family hint is available.
    AmbiguousCandidate,
}

/// Versioned field-complete observation envelope.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservationRecordEnvelopeV2 {
    /// Exact family payload or explicit ordinary ambiguity.
    pub payload: RecordFamilyPayloadV2,
    /// Caller-selected family retained only as a consistency hint.
    pub caller_family_hint: Option<ObservationRecordKind>,
    /// Optional parent record; journal-control events cannot recurse.
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

    /// Derives exact, compatible-hint, or ambiguous status without interpreting prose.
    pub fn classification(
        &self,
    ) -> Result<RecordFamilyClassification, RecordFamilyContractError> {
        self.validate_structure()?;
        if let Some(expected) = self.payload.exact_family() {
            if let Some(hinted) = self.caller_family_hint
                && hinted != expected
            {
                return Err(RecordFamilyContractError::FamilyHintConflict {
                    expected,
                    hinted,
                });
            }
            return Ok(RecordFamilyClassification::Exact { family: expected });
        }

        match self.caller_family_hint {
            Some(ObservationRecordKind::CoverageGap) => {
                Err(RecordFamilyContractError::ShapeConflict {
                    reason: "an ordinary event cannot use a coverage-gap hint",
                })
            }
            Some(hinted_family) => Ok(RecordFamilyClassification::CompatibleHint {
                hinted_family,
            }),
            None => Ok(RecordFamilyClassification::AmbiguousCandidate),
        }
    }

    /// Validates the v2 envelope and its derived family disposition.
    pub fn validate(&self) -> Result<(), RecordFamilyContractError> {
        self.classification().map(|_| ())
    }

    /// Returns a deterministic digest of the complete v2 record.
    pub fn canonical_sha256(&self) -> Result<String, RecordFamilyContractError> {
        self.validate()?;
        let bytes = canonical_json_bytes(self)
            .map_err(|error| RecordFamilyContractError::Canonicalization(error.to_string()))?;
        Ok(sha256_hex(&bytes))
    }
}

/// Explicit compatibility ceiling assigned to one v1 import.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum LegacyV1ImportDisposition {
    /// The dedicated v1 coverage-gap shape is mechanically exact.
    ExactCoverageGap,
    /// The dedicated v1 journal-control marker is mechanically exact audit.
    ExactJournalControlAudit,
    /// An ordinary v1 family label remains a compatible, non-exact hint.
    CompatibleHintOnly,
}

/// Input for a loss-aware v1 compatibility import.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LegacyV1ImportRequest {
    /// Exact parsed v1 record retained for replay and compatibility fixtures.
    pub legacy_record: ObservationRecordEnvelope,
    /// Immutable artifact/blob handle containing the original serialized bytes.
    pub original_artifact_ref: String,
    /// SHA-256 of the exact original bytes, independent of canonical re-encoding.
    pub original_bytes_sha256: String,
}

impl LegacyV1ImportRequest {
    /// Validates the legacy record and its exact-byte lineage.
    pub fn validate(&self) -> Result<(), RecordFamilyContractError> {
        self.legacy_record.validate()?;
        text(&self.original_artifact_ref, "original_artifact_ref")?;
        digest(&self.original_bytes_sha256, "original_bytes_sha256")
    }
}

/// Immutable result of importing one v1 envelope without overstating its evidence.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LegacyV1Import {
    /// Original parsed v1 value retained exactly as a compatibility record.
    pub legacy_record: ObservationRecordEnvelope,
    /// Raw serialized bytes remain reachable through this immutable handle.
    pub original_artifact_ref: String,
    /// Digest of the raw serialized bytes at the handle.
    pub original_bytes_sha256: String,
    /// Digest of the canonical parsed v1 shape, used for deterministic comparison.
    pub legacy_canonical_sha256: String,
    /// Field-complete v2 projection with an explicit evidence ceiling.
    pub record_v2: ObservationRecordEnvelopeV2,
    /// Import disposition proving whether family exactness survived.
    pub disposition: LegacyV1ImportDisposition,
}

impl LegacyV1Import {
    /// Validates legacy lineage, deterministic v2 projection, and compatibility ceiling.
    pub fn validate(&self) -> Result<(), RecordFamilyContractError> {
        self.legacy_record.validate()?;
        text(&self.original_artifact_ref, "original_artifact_ref")?;
        digest(&self.original_bytes_sha256, "original_bytes_sha256")?;
        digest(&self.legacy_canonical_sha256, "legacy_canonical_sha256")?;
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

    let projected = if let Some(gap) = legacy_record.coverage_gap.clone() {
        (
            ObservationRecordEnvelopeV2 {
                payload: RecordFamilyPayloadV2::CoverageGap(CoverageGapRecordV2 {
                    record_id: legacy_record.record_id.clone(),
                    gap,
                }),
                caller_family_hint: Some(ObservationRecordKind::CoverageGap),
                parent_record_id: legacy_record.parent_record_id.clone(),
            },
            LegacyV1ImportDisposition::ExactCoverageGap,
        )
    } else if legacy_record.journal_control_event {
        let event = legacy_record.event.clone().ok_or(
            RecordFamilyContractError::ShapeConflict {
                reason: "validated journal-control v1 record has no event",
            },
        )?;
        (
            ObservationRecordEnvelopeV2 {
                payload: RecordFamilyPayloadV2::JournalControlAudit(
                    JournalControlAuditRecordV2 {
                        record_id: legacy_record.record_id.clone(),
                        event,
                    },
                ),
                caller_family_hint: Some(ObservationRecordKind::Audit),
                parent_record_id: None,
            },
            LegacyV1ImportDisposition::ExactJournalControlAudit,
        )
    } else {
        let event = legacy_record.event.clone().ok_or(
            RecordFamilyContractError::ShapeConflict {
                reason: "validated ordinary v1 record has no event",
            },
        )?;
        (
            ObservationRecordEnvelopeV2 {
                payload: RecordFamilyPayloadV2::AmbiguousOrdinary(
                    AmbiguousOrdinaryRecordV2 {
                        record_id: legacy_record.record_id.clone(),
                        event,
                        source_contract_ref: LEGACY_OBSERVATION_CONTRACT_REF.to_owned(),
                        ambiguity_reason_ref:
                            "legacy-v1-generic-family-evidence-unavailable".to_owned(),
                    },
                ),
                caller_family_hint: Some(legacy_record.kind),
                parent_record_id: legacy_record.parent_record_id.clone(),
            },
            LegacyV1ImportDisposition::CompatibleHintOnly,
        )
    };

    projected.0.validate()?;
    Ok(projected)
}

/// Imports a v1 generic envelope without treating its ordinary label as exact evidence.
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
        original_artifact_ref: request.original_artifact_ref,
        original_bytes_sha256: request.original_bytes_sha256,
        legacy_canonical_sha256,
        record_v2,
        disposition,
    };
    imported.validate()?;
    Ok(imported)
}

/// Returns the content-addressed identity of the v2 record-family contract.
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
        ObservationEventIdentity, ObservationKind, ObservationScope,
        PrivacyRetentionDisclosure, ProducerTrace,
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

    fn exact_records() -> Result<Vec<ObservationRecordEnvelopeV2>, ObservationError> {
        Ok(vec![
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
                    origin_confidence: "host_observed".to_owned(),
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
        ])
    }

    fn ambiguous_record(
        record_id: &str,
        kind: ObservationKind,
        hint: Option<ObservationRecordKind>,
    ) -> Result<ObservationRecordEnvelopeV2, ObservationError> {
        Ok(ObservationRecordEnvelopeV2 {
            payload: RecordFamilyPayloadV2::AmbiguousOrdinary(AmbiguousOrdinaryRecordV2 {
                record_id: record_id.to_owned(),
                event: event(kind)?,
                source_contract_ref: "source:generic".to_owned(),
                ambiguity_reason_ref: "family-specific-fields-unavailable".to_owned(),
            }),
            caller_family_hint: hint,
            parent_record_id: None,
        })
    }

    #[test]
    fn every_field_complete_family_roundtrips_as_exact() -> TestResult {
        for record in exact_records()? {
            let classification = record.classification()?;
            assert!(matches!(
                classification,
                RecordFamilyClassification::Exact { .. }
            ));
            let encoded = serde_json::to_string(&record)?;
            let decoded: ObservationRecordEnvelopeV2 = serde_json::from_str(&encoded)?;
            assert_eq!(decoded, record);
            assert_eq!(decoded.canonical_sha256()?, record.canonical_sha256()?);
        }
        Ok(())
    }

    #[test]
    fn exact_payload_reuses_the_existing_family_record_shape() -> TestResult {
        let record = exact_records()?.remove(0);
        let RecordFamilyPayloadV2::Audit(audit) = record.payload else {
            panic!("expected audit payload");
        };
        assert_eq!(audit.audit_action, "permission checked");
        assert_eq!(audit.core.kind, ObservationKind::Security);
        Ok(())
    }

    #[test]
    fn generic_event_hint_remains_compatible_not_exact() -> TestResult {
        let record = ambiguous_record(
            "record:legacy-like",
            ObservationKind::QueueResource,
            Some(ObservationRecordKind::Telemetry),
        )?;
        assert_eq!(
            record.classification()?,
            RecordFamilyClassification::CompatibleHint {
                hinted_family: ObservationRecordKind::Telemetry
            }
        );
        Ok(())
    }

    #[test]
    fn generic_event_without_hint_is_explicitly_ambiguous() -> TestResult {
        let record = ambiguous_record(
            "record:ambiguous",
            ObservationKind::ContextPacket,
            None,
        )?;
        assert_eq!(
            record.classification()?,
            RecordFamilyClassification::AmbiguousCandidate
        );
        Ok(())
    }

    #[test]
    fn observation_kind_does_not_mint_an_exact_family() -> TestResult {
        let record = ambiguous_record(
            "record:no-kind-promotion",
            ObservationKind::Security,
            None,
        )?;
        assert_eq!(
            record.classification()?,
            RecordFamilyClassification::AmbiguousCandidate
        );
        Ok(())
    }

    #[test]
    fn exact_family_rejects_a_conflicting_hint() -> TestResult {
        let mut record = exact_records()?.remove(0);
        record.caller_family_hint = Some(ObservationRecordKind::Telemetry);
        assert_eq!(
            record.classification(),
            Err(RecordFamilyContractError::FamilyHintConflict {
                expected: ObservationRecordKind::Audit,
                hinted: ObservationRecordKind::Telemetry,
            })
        );
        Ok(())
    }

    #[test]
    fn coverage_gap_and_ordinary_shapes_cannot_be_relabelled() -> TestResult {
        let mut gap_record = exact_records()?.remove(4);
        gap_record.caller_family_hint = Some(ObservationRecordKind::Audit);
        assert!(matches!(
            gap_record.classification(),
            Err(RecordFamilyContractError::FamilyHintConflict { .. })
        ));

        let ordinary_record = ambiguous_record(
            "record:ordinary-conflict",
            ObservationKind::TaskProgress,
            Some(ObservationRecordKind::CoverageGap),
        )?;
        assert!(matches!(
            ordinary_record.classification(),
            Err(RecordFamilyContractError::ShapeConflict { .. })
        ));
        Ok(())
    }

    #[test]
    fn journal_control_is_exact_audit_and_cannot_be_relabelled() -> TestResult {
        let mut record = ObservationRecordEnvelopeV2 {
            payload: RecordFamilyPayloadV2::JournalControlAudit(
                JournalControlAuditRecordV2 {
                    record_id: "record:control".to_owned(),
                    event: event(ObservationKind::QueueResource)?,
                },
            ),
            caller_family_hint: Some(ObservationRecordKind::Audit),
            parent_record_id: None,
        };
        assert_eq!(
            record.classification()?,
            RecordFamilyClassification::Exact {
                family: ObservationRecordKind::Audit
            }
        );
        record.caller_family_hint = Some(ObservationRecordKind::Maintenance);
        assert!(matches!(
            record.classification(),
            Err(RecordFamilyContractError::FamilyHintConflict { .. })
        ));
        Ok(())
    }

    #[test]
    fn journal_control_cannot_form_a_recursive_parent_chain() -> TestResult {
        let record = ObservationRecordEnvelopeV2 {
            payload: RecordFamilyPayloadV2::JournalControlAudit(
                JournalControlAuditRecordV2 {
                    record_id: "record:control-parent".to_owned(),
                    event: event(ObservationKind::QueueResource)?,
                },
            ),
            caller_family_hint: Some(ObservationRecordKind::Audit),
            parent_record_id: Some("record:parent".to_owned()),
        };
        assert!(matches!(
            record.classification(),
            Err(RecordFamilyContractError::ShapeConflict { .. })
        ));
        Ok(())
    }

    #[test]
    fn legacy_generic_record_imports_with_a_non_exact_ceiling() -> TestResult {
        let legacy_record = ObservationRecordEnvelope {
            record_id: "legacy:ordinary".to_owned(),
            kind: ObservationRecordKind::Telemetry,
            event: Some(event(ObservationKind::QueueResource)?),
            coverage_gap: None,
            journal_control_event: false,
            parent_record_id: Some("legacy:parent".to_owned()),
        };
        let imported = import_legacy_v1(LegacyV1ImportRequest {
            legacy_record: legacy_record.clone(),
            original_artifact_ref: "artifact:legacy-json".to_owned(),
            original_bytes_sha256: "a".repeat(64),
        })?;
        assert_eq!(
            imported.disposition,
            LegacyV1ImportDisposition::CompatibleHintOnly
        );
        assert_eq!(imported.legacy_record, legacy_record);
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
    fn dedicated_legacy_shapes_keep_only_the_exactness_they_prove() -> TestResult {
        let gap_record = ObservationRecordEnvelope {
            record_id: "legacy:gap".to_owned(),
            kind: ObservationRecordKind::CoverageGap,
            event: None,
            coverage_gap: Some(gap()),
            journal_control_event: false,
            parent_record_id: None,
        };
        let gap_import = import_legacy_v1(LegacyV1ImportRequest {
            legacy_record: gap_record,
            original_artifact_ref: "artifact:gap".to_owned(),
            original_bytes_sha256: "b".repeat(64),
        })?;
        assert_eq!(
            gap_import.disposition,
            LegacyV1ImportDisposition::ExactCoverageGap
        );

        let control_record = ObservationRecordEnvelope {
            record_id: "legacy:control".to_owned(),
            kind: ObservationRecordKind::Audit,
            event: Some(event(ObservationKind::QueueResource)?),
            coverage_gap: None,
            journal_control_event: true,
            parent_record_id: None,
        };
        let control_import = import_legacy_v1(LegacyV1ImportRequest {
            legacy_record: control_record,
            original_artifact_ref: "artifact:control".to_owned(),
            original_bytes_sha256: "c".repeat(64),
        })?;
        assert_eq!(
            control_import.disposition,
            LegacyV1ImportDisposition::ExactJournalControlAudit
        );
        Ok(())
    }

    #[test]
    fn legacy_projection_tampering_is_rejected() -> TestResult {
        let legacy_record = ObservationRecordEnvelope {
            record_id: "legacy:tamper".to_owned(),
            kind: ObservationRecordKind::Change,
            event: Some(event(ObservationKind::Configuration)?),
            coverage_gap: None,
            journal_control_event: false,
            parent_record_id: None,
        };
        let mut imported = import_legacy_v1(LegacyV1ImportRequest {
            legacy_record,
            original_artifact_ref: "artifact:tamper".to_owned(),
            original_bytes_sha256: "d".repeat(64),
        })?;
        imported.record_v2.caller_family_hint = Some(ObservationRecordKind::Audit);
        assert_eq!(
            imported.validate(),
            Err(RecordFamilyContractError::LegacyProjectionMismatch)
        );
        Ok(())
    }

    #[test]
    fn unknown_fields_fail_closed() -> TestResult {
        let record = ambiguous_record(
            "record:unknown-field",
            ObservationKind::ContextPacket,
            None,
        )?;
        let mut value = serde_json::to_value(record)?;
        value
            .as_object_mut()
            .expect("record serializes as an object")
            .insert("unexpected".to_owned(), serde_json::json!(true));
        assert!(serde_json::from_value::<ObservationRecordEnvelopeV2>(value).is_err());
        Ok(())
    }

    #[test]
    fn contract_identity_is_stable_and_v2() -> TestResult {
        let identity = record_family_contract_identity()?;
        identity.validate()?;
        assert_eq!(identity.version, RECORD_FAMILY_CONTRACT_VERSION);
        Ok(())
    }
}
