//! Admitted canonical experience-bank and agent-feedback records (B223).
//!
//! This module closes the record side of the #223 experience freeze that
//! `experience_projection.rs` leaves explicitly open: "no bank record type
//! exists upstream" and "no feedback receipt type exists upstream". It adds
//! the missing admitted record schemas **without** touching the frozen r5
//! wire shapes (`JournalProjection`, `BankProjection`, `FeedbackProjection`,
//! `ExperienceRecordRef`, `ProjectionCoverage`, `ProjectionOmissionClass` and
//! their bounds/digests are unchanged):
//!
//! - [`ExperienceBankRecord`]: one Canonical-Memory-owned self-scope memory
//!   entry derived from material or recurring journal events (I04-08: the
//!   bank "is the only semantic self-memory"; Canonical Memory "owns only
//!   the admitted `eliot_system` experience records"). Carries source journal
//!   refs with provenance, never an aggregate score, verdict, or truth
//!   promotion.
//! - [`AgentFeedbackRecord`]: one bounded admitted feedback entry preserving
//!   input origin ([`ProducerTrace`]), consent/provenance refs, and a closed
//!   [`FeedbackClass`]. Candidate-only by construction: the shape carries no
//!   findings, verdict, score, or completeness posture (I16-23: no global
//!   score; feedback identifies failing contours for the governed loop).
//! - Owner-issued revision cursors: [`ExperienceBankRecord::revision_cursor`]
//!   and [`AgentFeedbackRecord::revision_cursor`] mint the
//!   [`SourceRevisionHandle`] that backs an [`ExperienceRecordRef`]. The
//!   `content_sha256` is the record's own owner-computed digest over its
//!   canonical bytes and `byte_length` is the measured preimage length, so a
//!   projection lane can never forge admitted-source bytes: cursors only
//!   exist for records this owner admitted.
//! - Retention reads: [`resolve_retention_read`] implements the root B223
//!   decision for unknown/stale `retention_policy_ref`s. There is no
//!   invented default and no fabricated expiry/permission/erasure schedule:
//!   an unknown ref yields [`ExperienceRetentionReadPosture::UnknownPolicy`]
//!   (explicit gap; the caller emits a coverage gap and treats the material
//!   as unavailable), a known ref under hold yields `RetentionBlocked` with
//!   only caller-supplied hold refs. This maps to the existing erasure
//!   `TargetDisposition::RetentionBlocked` vocabulary and the I05-14
//!   `RETENTION_BLOCKED` availability axis without importing the security
//!   lane: no second retention owner is created here.
//! - Store manifest declarations: [`BANK_COMMIT_OPERATION`] and
//!   [`FEEDBACK_COMMIT_OPERATION`] name the closed named operations the
//!   store bridge (#19 lane) registers; both bind
//!   [`COMMIT_TRANSITION_CLASS`] (`capture_candidate`) and
//!   [`COMMIT_MAX_EFFECT`] (candidate-only: no support, influence,
//!   lifecycle, or assertability change). This module performs no I/O and
//!   owns no table: durable execution stays with the bridge.
//!
//! Versioning: these shapes carry their own
//! [`EXPERIENCE_RECORD_CONTRACT_VERSION`] (`0.1.0`). They do not alter the
//! frozen `CONTRACT_VERSION` (`1.0.0`) pinning the r5 projection envelopes.

use eliot_contracts::{ArtifactId, ContractVersion, StateFence, canonical_json_bytes, sha256_hex};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{
    ExperienceRecordRef, ObservationError, ObservationScope, PrivacyRetentionDisclosure,
    ProducerTrace, ProjectionCoverage, SourceRevisionHandle,
};

/// Contract version of the admitted bank/feedback record shapes owned here.
///
/// Prototype owner contract: `0.1.0`. Equality only; a different triple
/// fails closed. Independent of the frozen r5 projection `CONTRACT_VERSION`.
pub const EXPERIENCE_RECORD_CONTRACT_VERSION: ContractVersion = ContractVersion::new(0, 1, 0);

/// Maximum source journal refs carried by one bank record.
pub const MAX_BANK_SOURCE_REFS: usize = 64;
/// Maximum Unicode scalar values accepted for one bank summary.
pub const MAX_BANK_SUMMARY_CHARS: usize = 1024;
/// Maximum Unicode scalar values accepted for one feedback note.
pub const MAX_FEEDBACK_NOTE_CHARS: usize = 1024;
/// Maximum Unicode scalar values accepted for one consent/provenance ref.
pub const MAX_CONSENT_REF_CHARS: usize = 256;
/// Maximum Unicode scalar values accepted for one owner source identity.
pub const MAX_RECORD_SOURCE_ID_CHARS: usize = 256;

/// Closed named store operation for bank-record commit (declaration only).
///
/// The store bridge (#19 lane) registers this name; the manifest binds
/// [`COMMIT_TRANSITION_CLASS`] with [`COMMIT_MAX_EFFECT`].
pub const BANK_COMMIT_OPERATION: &str = "ExperienceBankCommit";
/// Closed named store operation for feedback-record commit (declaration only).
pub const FEEDBACK_COMMIT_OPERATION: &str = "AgentFeedbackCommit";
/// Transition class both commit operations are declared under.
pub const COMMIT_TRANSITION_CLASS: &str = "capture_candidate";
/// Maximum epistemic/control effect of either commit operation.
pub const COMMIT_MAX_EFFECT: &str =
    "candidate-only: no support, influence, lifecycle, or assertability change";

fn text(value: &str, field: &'static str) -> Result<(), ObservationError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(ObservationError::InvalidField {
            field,
            reason: "must be non-blank and free of control characters",
        });
    }
    Ok(())
}

fn bounded_text(
    value: &str,
    field: &'static str,
    max_chars: usize,
) -> Result<(), ObservationError> {
    text(value, field)?;
    if value.chars().count() > max_chars {
        return Err(ObservationError::InvalidField {
            field,
            reason: "exceeds bounded length",
        });
    }
    Ok(())
}

fn fence_shape(value: &StateFence, field: &'static str) -> Result<(), ObservationError> {
    value
        .validate()
        .map_err(|_| ObservationError::InvalidField {
            field,
            reason: "fence interval is invalid",
        })
}

fn digest_shape(value: &str, field: &'static str) -> Result<(), ObservationError> {
    if value.len() != 64
        || value
            .bytes()
            .any(|byte| !matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(ObservationError::InvalidField {
            field,
            reason: "must be lowercase SHA-256 hex",
        });
    }
    Ok(())
}

/// Closed feedback class for one admitted feedback record.
///
/// The classes mirror the normative feedback vocabulary: `UserCorrection`
/// and `OutcomeDelta` carry the I04-08 `user_correction` / `product_outcome`
/// event kinds; `UsefulnessSignal` and `CoverageComplaint` carry the I16-23
/// counter-metric subjects (acknowledged usefulness/decision delta and
/// wrong-scope/context complaints with resolution latency). The class names
/// the subject; it never scores it.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FeedbackClass {
    /// Operator/agent correction of prior material.
    UserCorrection,
    /// Reported product/runtime outcome delta.
    OutcomeDelta,
    /// Acknowledged usefulness / decision-delta signal.
    UsefulnessSignal,
    /// Wrong-scope, wrong-context, or coverage complaint.
    CoverageComplaint,
}

/// One admitted Canonical-Memory-owned experience-bank record.
///
/// A bounded self-scope memory entry derived from material or recurring
/// journal events: source journal refs plus a bounded summary, with scope,
/// fence, owner coverage, retention refs, and immutable predecessor
/// lineage. Carries no score, verdict, support delta, influence, or
/// lifecycle transition (A14.4: retrieval/use never reinforces; gravity
/// marks candidates, never deletion).
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ExperienceBankRecord {
    /// Contract version this record was written against.
    pub contract_version: ContractVersion,
    /// Exact canonical handle of the record.
    pub handle: ArtifactId,
    /// Owner revision counter assigned at admission; strictly increasing
    /// per handle under one owner.
    pub bank_revision: u64,
    /// Journal records this entry derives from; non-empty, unique.
    pub source_journal_refs: Vec<ArtifactId>,
    /// Read scope governing this record.
    pub scope: ObservationScope,
    /// Fence this record was admitted under, carried for edge gating.
    pub fence: StateFence,
    /// Owner coverage binding for the derivation.
    pub coverage: ProjectionCoverage,
    /// Privacy/retention/disclosure refs; policy is interpreted by the
    /// retention owner, never here.
    pub retention: PrivacyRetentionDisclosure,
    /// Prior bank record this entry supersedes, when retained lineage
    /// applies. Must differ from `handle`.
    pub predecessor: Option<ArtifactId>,
    /// Bounded human/machine-readable summary of the derived memory.
    pub summary: String,
    /// Measured canonical preimage byte length at admission.
    pub byte_length: u64,
    /// Frozen digest over the record shape, excluding this field and
    /// `byte_length`.
    pub digest: String,
}

impl ExperienceBankRecord {
    /// Admit a bank record: validate every binding, measure the canonical
    /// preimage, and freeze the owner digest. The digest and byte length
    /// are computed here, never caller-supplied, so downstream
    /// [`SourceRevisionHandle`] cursors are owner-issued.
    #[allow(clippy::too_many_arguments)]
    pub fn admit(
        handle: ArtifactId,
        bank_revision: u64,
        source_journal_refs: Vec<ArtifactId>,
        scope: ObservationScope,
        fence: StateFence,
        coverage: ProjectionCoverage,
        retention: PrivacyRetentionDisclosure,
        predecessor: Option<ArtifactId>,
        summary: String,
    ) -> Result<Self, ObservationError> {
        if source_journal_refs.is_empty() {
            return Err(ObservationError::InvalidField {
                field: "bank_record.source_journal_refs",
                reason: "at least one source journal ref is required",
            });
        }
        if source_journal_refs.len() > MAX_BANK_SOURCE_REFS {
            return Err(ObservationError::InvalidField {
                field: "bank_record.source_journal_refs",
                reason: "exceeds bounded length",
            });
        }
        let mut seen: Vec<&str> = Vec::with_capacity(source_journal_refs.len());
        for reference in &source_journal_refs {
            let id = reference.as_str();
            if seen.contains(&id) {
                return Err(ObservationError::Duplicate {
                    field: "bank_record.source_journal_refs",
                    value: id.to_owned(),
                });
            }
            seen.push(id);
        }
        if let Some(prior) = &predecessor {
            if prior == &handle {
                return Err(ObservationError::InvalidField {
                    field: "bank_record.predecessor",
                    reason: "predecessor must differ from the record handle",
                });
            }
        }
        scope.validate()?;
        fence_shape(&fence, "bank_record.fence")?;
        coverage.validate()?;
        retention.validate()?;
        bounded_text(&summary, "bank_record.summary", MAX_BANK_SUMMARY_CHARS)?;
        let mut record = Self {
            contract_version: EXPERIENCE_RECORD_CONTRACT_VERSION,
            handle,
            bank_revision,
            source_journal_refs,
            scope,
            fence,
            coverage,
            retention,
            predecessor,
            summary,
            byte_length: 0,
            digest: String::new(),
        };
        let preimage = record.preimage_bytes()?;
        record.byte_length = u64::try_from(preimage.len()).unwrap_or(u64::MAX);
        if record.byte_length == 0 {
            return Err(ObservationError::InvalidField {
                field: "bank_record.byte_length",
                reason: "admitted preimage must be non-empty",
            });
        }
        record.digest = sha256_hex(&preimage);
        record.validate()?;
        Ok(record)
    }

    /// Canonical preimage bytes (digest and measured length excluded).
    fn preimage_bytes(&self) -> Result<Vec<u8>, ObservationError> {
        canonical_json_bytes(&(
            &self.contract_version,
            &self.handle,
            self.bank_revision,
            &self.source_journal_refs,
            &self.scope,
            &self.fence,
            &self.coverage,
            &self.retention,
            &self.predecessor,
            &self.summary,
        ))
        .map_err(|_| ObservationError::InvalidField {
            field: "bank_record.digest",
            reason: "record is not canonically encodable",
        })
    }

    /// Compute the frozen digest over the record shape.
    pub fn compute_digest(&self) -> Result<String, ObservationError> {
        Ok(sha256_hex(&self.preimage_bytes()?))
    }

    /// Validate header, bindings, measured length, and the frozen digest.
    pub fn validate(&self) -> Result<(), ObservationError> {
        if self.contract_version != EXPERIENCE_RECORD_CONTRACT_VERSION {
            return Err(ObservationError::InvalidField {
                field: "bank_record.contract_version",
                reason: "unsupported contract version",
            });
        }
        if self.source_journal_refs.is_empty() {
            return Err(ObservationError::InvalidField {
                field: "bank_record.source_journal_refs",
                reason: "at least one source journal ref is required",
            });
        }
        if self.source_journal_refs.len() > MAX_BANK_SOURCE_REFS {
            return Err(ObservationError::InvalidField {
                field: "bank_record.source_journal_refs",
                reason: "exceeds bounded length",
            });
        }
        if let Some(prior) = &self.predecessor {
            if prior == &self.handle {
                return Err(ObservationError::InvalidField {
                    field: "bank_record.predecessor",
                    reason: "predecessor must differ from the record handle",
                });
            }
        }
        self.scope.validate()?;
        fence_shape(&self.fence, "bank_record.fence")?;
        self.coverage.validate()?;
        self.retention.validate()?;
        bounded_text(&self.summary, "bank_record.summary", MAX_BANK_SUMMARY_CHARS)?;
        let preimage = self.preimage_bytes()?;
        let measured = u64::try_from(preimage.len()).unwrap_or(u64::MAX);
        if self.byte_length != measured {
            return Err(ObservationError::InvalidField {
                field: "bank_record.byte_length",
                reason: "does not match the canonical preimage length",
            });
        }
        digest_shape(&self.digest, "bank_record.digest")?;
        if self.digest != sha256_hex(&preimage) {
            return Err(ObservationError::InvalidField {
                field: "bank_record.digest",
                reason: "does not match record preimage",
            });
        }
        Ok(())
    }

    /// Mint the owner-issued [`SourceRevisionHandle`] cursor for this
    /// admitted record: identity, owner revision, content digest over the
    /// complete admitted bytes, and measured length. Only the admitting
    /// owner calls this; projection lanes receive the cursor, never mint
    /// it.
    pub fn revision_cursor(
        &self,
        source_id: &str,
    ) -> Result<SourceRevisionHandle, ObservationError> {
        bounded_text(
            source_id,
            "bank_record.source_id",
            MAX_RECORD_SOURCE_ID_CHARS,
        )?;
        let cursor = SourceRevisionHandle {
            source_id: source_id.to_owned(),
            revision: self.bank_revision.to_string(),
            content_sha256: self.digest.clone(),
            byte_length: self.byte_length,
        };
        cursor.validate()?;
        Ok(cursor)
    }
}

/// One admitted agent-feedback record.
///
/// Preserves input origin ([`ProducerTrace`]), a consent/provenance ref,
/// the reacted-to event handle when known, and a closed [`FeedbackClass`].
/// Candidate-only by construction: no finding, verdict, score, or
/// completeness field exists on this shape (I16-23 loop: feedback feeds
/// the governed diagnosis loop; it never self-promotes).
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AgentFeedbackRecord {
    /// Contract version this record was written against.
    pub contract_version: ContractVersion,
    /// Exact canonical handle of the record.
    pub handle: ArtifactId,
    /// Owner revision counter assigned at admission.
    pub feedback_revision: u64,
    /// Input origin: producer, generation, and trace ref.
    pub origin: ProducerTrace,
    /// Consent/provenance ref for this feedback (surface consent marker or
    /// originating channel ref). Required; absence is not consent.
    pub consent_ref: String,
    /// Closed feedback class naming the subject, never scoring it.
    pub class: FeedbackClass,
    /// Reacted-to journal/event handle, when the feedback names one.
    pub subject_event_ref: Option<ArtifactId>,
    /// Read scope governing this record.
    pub scope: ObservationScope,
    /// Fence this record was admitted under, carried for edge gating.
    pub fence: StateFence,
    /// Privacy/retention/disclosure refs; policy is interpreted by the
    /// retention owner, never here.
    pub retention: PrivacyRetentionDisclosure,
    /// Bounded note carrying the feedback content.
    pub note: String,
    /// Measured canonical preimage byte length at admission.
    pub byte_length: u64,
    /// Frozen digest over the record shape, excluding this field and
    /// `byte_length`.
    pub digest: String,
}

impl AgentFeedbackRecord {
    /// Admit a feedback record: validate origin/consent/bindings, measure
    /// the canonical preimage, and freeze the owner digest. Consent is
    /// required and explicit: an empty `consent_ref` fails closed.
    #[allow(clippy::too_many_arguments)]
    pub fn admit(
        handle: ArtifactId,
        feedback_revision: u64,
        origin: ProducerTrace,
        consent_ref: String,
        class: FeedbackClass,
        subject_event_ref: Option<ArtifactId>,
        scope: ObservationScope,
        fence: StateFence,
        retention: PrivacyRetentionDisclosure,
        note: String,
    ) -> Result<Self, ObservationError> {
        origin.validate()?;
        bounded_text(
            &consent_ref,
            "feedback_record.consent_ref",
            MAX_CONSENT_REF_CHARS,
        )?;
        scope.validate()?;
        fence_shape(&fence, "feedback_record.fence")?;
        retention.validate()?;
        bounded_text(&note, "feedback_record.note", MAX_FEEDBACK_NOTE_CHARS)?;
        let mut record = Self {
            contract_version: EXPERIENCE_RECORD_CONTRACT_VERSION,
            handle,
            feedback_revision,
            origin,
            consent_ref,
            class,
            subject_event_ref,
            scope,
            fence,
            retention,
            note,
            byte_length: 0,
            digest: String::new(),
        };
        let preimage = record.preimage_bytes()?;
        record.byte_length = u64::try_from(preimage.len()).unwrap_or(u64::MAX);
        if record.byte_length == 0 {
            return Err(ObservationError::InvalidField {
                field: "feedback_record.byte_length",
                reason: "admitted preimage must be non-empty",
            });
        }
        record.digest = sha256_hex(&preimage);
        record.validate()?;
        Ok(record)
    }

    /// Canonical preimage bytes (digest and measured length excluded).
    fn preimage_bytes(&self) -> Result<Vec<u8>, ObservationError> {
        canonical_json_bytes(&(
            &self.contract_version,
            &self.handle,
            self.feedback_revision,
            &self.origin,
            &self.consent_ref,
            &self.class,
            &self.subject_event_ref,
            &self.scope,
            &self.fence,
            &self.retention,
            &self.note,
        ))
        .map_err(|_| ObservationError::InvalidField {
            field: "feedback_record.digest",
            reason: "record is not canonically encodable",
        })
    }

    /// Compute the frozen digest over the record shape.
    pub fn compute_digest(&self) -> Result<String, ObservationError> {
        Ok(sha256_hex(&self.preimage_bytes()?))
    }

    /// Validate origin, consent, bindings, measured length, and digest.
    pub fn validate(&self) -> Result<(), ObservationError> {
        if self.contract_version != EXPERIENCE_RECORD_CONTRACT_VERSION {
            return Err(ObservationError::InvalidField {
                field: "feedback_record.contract_version",
                reason: "unsupported contract version",
            });
        }
        self.origin.validate()?;
        bounded_text(
            &self.consent_ref,
            "feedback_record.consent_ref",
            MAX_CONSENT_REF_CHARS,
        )?;
        self.scope.validate()?;
        fence_shape(&self.fence, "feedback_record.fence")?;
        self.retention.validate()?;
        bounded_text(&self.note, "feedback_record.note", MAX_FEEDBACK_NOTE_CHARS)?;
        let preimage = self.preimage_bytes()?;
        let measured = u64::try_from(preimage.len()).unwrap_or(u64::MAX);
        if self.byte_length != measured {
            return Err(ObservationError::InvalidField {
                field: "feedback_record.byte_length",
                reason: "does not match the canonical preimage length",
            });
        }
        digest_shape(&self.digest, "feedback_record.digest")?;
        if self.digest != sha256_hex(&preimage) {
            return Err(ObservationError::InvalidField {
                field: "feedback_record.digest",
                reason: "does not match record preimage",
            });
        }
        Ok(())
    }

    /// Mint the owner-issued [`SourceRevisionHandle`] cursor for this
    /// admitted record. Only the admitting owner calls this.
    pub fn revision_cursor(
        &self,
        source_id: &str,
    ) -> Result<SourceRevisionHandle, ObservationError> {
        bounded_text(
            source_id,
            "feedback_record.source_id",
            MAX_RECORD_SOURCE_ID_CHARS,
        )?;
        let cursor = SourceRevisionHandle {
            source_id: source_id.to_owned(),
            revision: self.feedback_revision.to_string(),
            content_sha256: self.digest.clone(),
            byte_length: self.byte_length,
        };
        cursor.validate()?;
        Ok(cursor)
    }
}

/// Caller-supplied hold terms for a retention-blocked read.
///
/// All refs are carried, never invented: the hold owner, policy, and
/// review/expiry refs arrive from the governing schedule or stay absent
/// (see [`resolve_retention_read`]).
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RetentionHold {
    /// Hold owner ref from the governing schedule.
    pub hold_owner_ref: String,
    /// Governing retention policy ref.
    pub policy_ref: String,
    /// Next review or expiry record ref from the governing schedule.
    pub review_or_expiry_ref: String,
}

impl RetentionHold {
    /// Validate carried hold refs.
    pub fn validate(&self) -> Result<(), ObservationError> {
        bounded_text(
            &self.hold_owner_ref,
            "retention_hold.hold_owner_ref",
            MAX_CONSENT_REF_CHARS,
        )?;
        bounded_text(
            &self.policy_ref,
            "retention_hold.policy_ref",
            MAX_CONSENT_REF_CHARS,
        )?;
        bounded_text(
            &self.review_or_expiry_ref,
            "retention_hold.review_or_expiry_ref",
            MAX_CONSENT_REF_CHARS,
        )
    }
}

/// Closed read posture for one retention-gated experience record.
///
/// `UnknownPolicy` is the honest posture for an unknown or stale
/// `retention_policy_ref`: an explicit gap, never a fabricated default.
/// The caller emits a coverage gap for the withheld material and treats it
/// as unavailable (I05-14 `RETENTION_BLOCKED` axis / coverage-gap
/// posture), preserving the erasure `TargetDisposition::RetentionBlocked`
/// semantics without importing the security lane.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[serde(deny_unknown_fields)]
pub enum ExperienceRetentionReadPosture {
    /// Policy known and no hold applies: readable under the carried ref.
    Readable {
        /// Resolved governing policy ref.
        policy_ref: String,
    },
    /// Policy known and a hold applies: withheld with carried hold refs.
    RetentionBlocked {
        /// Governing policy ref.
        policy_ref: String,
        /// Hold owner ref from the governing schedule.
        hold_owner_ref: String,
        /// Next review or expiry record ref from the schedule.
        review_or_expiry_ref: String,
    },
    /// Policy ref unknown or stale: explicit gap, no default invented.
    UnknownPolicy {
        /// The unresolvable ref, echoed for gap reporting.
        retention_policy_ref: String,
    },
}

/// Resolve the read posture for one retention-gated record.
///
/// `policy_known` is attested by the retention-schedule owner (the
/// Governor-published schedule in force at the governing fence), not
/// inferred here. Unknown or stale refs resolve to `UnknownPolicy`; known
/// refs under a caller-supplied hold resolve to `RetentionBlocked` with
/// only carried refs; known refs with no hold resolve to `Readable`. No
/// expiry, permission, or erasure schedule is fabricated on any path.
pub fn resolve_retention_read(
    retention: &PrivacyRetentionDisclosure,
    policy_known: bool,
    hold: Option<&RetentionHold>,
) -> Result<ExperienceRetentionReadPosture, ObservationError> {
    retention.validate()?;
    if !policy_known {
        return Ok(ExperienceRetentionReadPosture::UnknownPolicy {
            retention_policy_ref: retention.retention_policy_ref.clone(),
        });
    }
    match hold {
        Some(terms) => {
            terms.validate()?;
            Ok(ExperienceRetentionReadPosture::RetentionBlocked {
                policy_ref: terms.policy_ref.clone(),
                hold_owner_ref: terms.hold_owner_ref.clone(),
                review_or_expiry_ref: terms.review_or_expiry_ref.clone(),
            })
        }
        None => Ok(ExperienceRetentionReadPosture::Readable {
            policy_ref: retention.retention_policy_ref.clone(),
        }),
    }
}

/// Build the opaque [`ExperienceRecordRef`] for one admitted bank record.
///
/// The ref carries the owner-issued revision cursor with scope/fence
/// echoes checked against the envelope scope/fence by
/// [`BankProjection::validate`](crate::BankProjection). This is the exact
/// shared constructor the Governor projection supplier and the Smart
/// consumer edge both resolve: refs only exist for admitted records.
///
/// [`BankProjection`]: crate::BankProjection
pub fn bank_record_ref(
    record: &ExperienceBankRecord,
    source_id: &str,
) -> Result<ExperienceRecordRef, ObservationError> {
    record.validate()?;
    let reference = ExperienceRecordRef {
        handle: record.handle.clone(),
        revision: record.revision_cursor(source_id)?,
        scope: record.scope.clone(),
        fence: record.fence.clone(),
    };
    reference.validate()?;
    Ok(reference)
}

/// Build the opaque [`ExperienceRecordRef`] for one admitted feedback
/// record. Same owner-issued cursor rule as [`bank_record_ref`].
///
/// [`ExperienceRecordRef`]: crate::ExperienceRecordRef
pub fn feedback_record_ref(
    record: &AgentFeedbackRecord,
    source_id: &str,
) -> Result<ExperienceRecordRef, ObservationError> {
    record.validate()?;
    let reference = ExperienceRecordRef {
        handle: record.handle.clone(),
        revision: record.revision_cursor(source_id)?,
        scope: record.scope.clone(),
        fence: record.fence.clone(),
    };
    reference.validate()?;
    Ok(reference)
}
