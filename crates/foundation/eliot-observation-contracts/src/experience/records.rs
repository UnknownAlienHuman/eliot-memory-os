//! Admitted canonical experience-bank and agent-feedback records (B223).
//!
//! This module closes the record side of the #223 experience freeze that
//! `experience::projection` leaves explicitly open: "no bank record type
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
//! - [`SessionEpisodeRecord`]: the I12.37 model-free, privacy-scoped
//!   `SessionEpisode` — the durable public conversation record reconstructed
//!   after UI/route restart. Capture is closed to `ModelFree` and
//!   `DialogueProse`, the ingestion owner's source cursor is carried and
//!   validated but never minted or advanced here, portability is local-private
//!   unless an explicit policy ref promotes it, and a pruned or privacy-purged
//!   source stays visibly unavailable instead of becoming a false, stale or
//!   deleted record.
//! - Store manifest declarations: [`BANK_COMMIT_OPERATION`],
//!   [`FEEDBACK_COMMIT_OPERATION`] and [`SESSION_EPISODE_COMMIT_OPERATION`]
//!   name the closed named operations the
//!   store bridge (#19 lane) registers; all bind
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
    CoverageDisposition, CoverageInterval, ExperienceRecordRef, ObservationError, ObservationScope,
    PrivacyRetentionDisclosure, ProducerTrace, ProjectionCoverage, SourceRevisionHandle,
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
/// Maximum session/attempt refs carried by one episode record.
pub const MAX_EPISODE_SESSION_REFS: usize = 64;
/// Maximum entity refs carried by one episode record.
pub const MAX_EPISODE_ENTITY_REFS: usize = 64;
/// Maximum public messages carried by one episode record.
///
/// `MAX_SESSION_EPISODE_MESSAGES * MAX_SESSION_EPISODE_MESSAGE_CHARS` keeps
/// the verbatim admitted document inside the store wire's bounded record
/// document, so an admitted episode can never be rejected for size by its own
/// commit leg.
pub const MAX_SESSION_EPISODE_MESSAGES: usize = 64;
/// Maximum Unicode scalar values accepted for one public episode message.
pub const MAX_SESSION_EPISODE_MESSAGE_CHARS: usize = 1024;

/// Closed named store operation for bank-record commit (declaration only).
///
/// The store bridge (#19 lane) registers this name; the manifest binds
/// [`COMMIT_TRANSITION_CLASS`] with [`COMMIT_MAX_EFFECT`]. Spelling follows
/// the verb-first store taxonomy (`CaptureObservation`, `AppendAuditEvent`).
pub const BANK_COMMIT_OPERATION: &str = "CommitExperienceBank";
/// Closed named store operation for feedback-record commit (declaration only).
pub const FEEDBACK_COMMIT_OPERATION: &str = "CommitAgentFeedback";
/// Closed named store operation for session-episode commit (declaration only).
///
/// I12.37: the `SessionEpisode` is a typed `ExperienceRecord` in canonical
/// memory, so its durable write travels the same `capture_candidate` ceiling
/// as the other two admitted experience records.
pub const SESSION_EPISODE_COMMIT_OPERATION: &str = "CommitSessionEpisode";
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
    ///
    /// Shape-vs-durable split (review F1): this admits the record *shape*.
    /// Durable existence is NOT established here; it is gated on the #19
    /// commit path and re-checked on every read by [`resolve_bank_ref`]
    /// against owner-issued snapshots. A shape-valid record with zero
    /// durable rows behind it resolves to nothing.
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
        if let Some(prior) = &predecessor
            && prior == &handle
        {
            return Err(ObservationError::InvalidField {
                field: "bank_record.predecessor",
                reason: "predecessor must differ from the record handle",
            });
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
        if let Some(prior) = &self.predecessor
            && prior == &self.handle
        {
            return Err(ObservationError::InvalidField {
                field: "bank_record.predecessor",
                reason: "predecessor must differ from the record handle",
            });
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
    /// it. The cursor is shape-bound (see the shape-vs-durable split on
    /// [`ExperienceBankRecord::admit`]): it proves the bytes the owner
    /// admitted, not that rows are durable — durability is re-proved by
    /// [`resolve_bank_ref`] on read-back.
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
    ///
    /// Shape-vs-durable split: as on [`ExperienceBankRecord::admit`], this
    /// admits the shape only; durable existence is gated on the #19 commit
    /// path and re-checked by [`resolve_feedback_ref`] on read-back.
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
    /// admitted record. Only the admitting owner calls this. Shape-bound
    /// (see [`ExperienceBankRecord::admit`]): durability is re-proved by
    /// [`resolve_feedback_ref`] on read-back.
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

/// Closed source-availability marker for one session episode.
///
/// `source unavailable` is not "record false", not "record current" and not
/// "delete": a privacy-purged or provider-pruned source leaves the retained
/// episode visibly unavailable here (I12.37).
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SessionEpisodeSourceAvailability {
    /// The source is present and its bytes were read.
    Present,
    /// The source was pruned by the provider; the episode is retained.
    Pruned,
    /// The source is unavailable to this owner.
    Unavailable,
    /// Availability is not established.
    Unknown,
}

/// Closed portability marker for one session episode.
///
/// Local-private is the only default: a selected scope is not evidence of
/// project sharing, so `Default` resolves to `LocalPrivate` and promotion
/// requires the explicit policy reference the promoted variants carry
/// (I12.37).
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", tag = "portability", deny_unknown_fields)]
pub enum SessionEpisodePortability {
    /// Local-private episode; no sharing was inferred.
    LocalPrivate,
    /// Project-shareable under the named explicit policy.
    ProjectShareable {
        /// Explicit promotion policy reference; a scope never supplies it.
        policy_ref: String,
    },
    /// Exportable after redaction under the named explicit policy.
    ExportableRedacted {
        /// Explicit promotion policy reference; a scope never supplies it.
        policy_ref: String,
    },
}

impl Default for SessionEpisodePortability {
    /// Private by default: a selected scope is not sharing evidence.
    fn default() -> Self {
        Self::LocalPrivate
    }
}

impl SessionEpisodePortability {
    /// Validate a promotion's explicit policy reference.
    fn validate(&self) -> Result<(), ObservationError> {
        match self {
            Self::LocalPrivate => Ok(()),
            Self::ProjectShareable { policy_ref }
            | Self::ExportableRedacted { policy_ref } => bounded_text(
                policy_ref,
                "session_episode.portability.policy_ref",
                MAX_CONSENT_REF_CHARS,
            ),
        }
    }
}

/// Closed capture-mode marker for one session episode.
///
/// The episode body is model-free normalized dialogue: no model output is
/// admitted as episode content (I12.37 `capture_mode: model_free`).
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SessionEpisodeCaptureMode {
    /// Model-free capture of normalized public messages.
    ModelFree,
}

/// Closed body-kind marker for one session episode.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SessionEpisodeBodyKind {
    /// Rendered dialogue prose plus handle-based artifact references.
    DialogueProse,
}

/// One public message admitted into a session episode.
///
/// Ordering is the explicit `sequence`; `supersedes` records an edit or
/// supersession against the stable `message_ref` it replaces. Material that
/// stays out of the episode body — a raw tool dump, provider-forbidden hidden
/// reasoning, a secret — is named only through `referenced_artifact_refs` and
/// never duplicated into `text`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SessionEpisodeMessage {
    /// Stable source identity of this message within the episode.
    pub message_ref: ArtifactId,
    /// Zero-based position in the admitted public message order.
    pub sequence: u64,
    /// Bounded normalized public text for this message.
    pub text: String,
    /// Exact artifact refs this message points at instead of inlining them.
    pub referenced_artifact_refs: Vec<ArtifactId>,
    /// Message this one edits or supersedes, when the source declared one.
    pub supersedes: Option<ArtifactId>,
}

impl SessionEpisodeMessage {
    /// Validate the message's own bindings.
    fn validate(&self, field: &'static str) -> Result<(), ObservationError> {
        bounded_text(&self.text, field, MAX_SESSION_EPISODE_MESSAGE_CHARS)?;
        let mut seen: Vec<&str> = Vec::with_capacity(self.referenced_artifact_refs.len());
        for reference in &self.referenced_artifact_refs {
            let id = reference.as_str();
            if seen.contains(&id) {
                return Err(ObservationError::Duplicate {
                    field,
                    value: id.to_owned(),
                });
            }
            seen.push(id);
        }
        if self
            .supersedes
            .as_ref()
            .is_some_and(|prior| prior == &self.message_ref)
        {
            return Err(ObservationError::InvalidField {
                field,
                reason: "a message cannot supersede itself",
            });
        }
        Ok(())
    }
}

/// One admitted `SessionEpisode`: the model-free, privacy-scoped durable
/// record a public conversation is reconstructed from (I12.37).
///
/// Guarantees this record states, and does not approximate:
///
/// - `capture_mode` is closed to `ModelFree` and `body_kind` to
///   `DialogueProse`, so no model-authored body and no tool-dump body can be
///   admitted as an episode.
/// - `source_ref` is the ingestion owner's cursor, carried verbatim and
///   validated through its own `validate()`. This record never mints, advances
///   or recomputes a source cursor: a projected index over episodes is
///   rebuildable and cannot own it.
/// - `portability` defaults to local-private and a promotion carries its own
///   explicit policy ref, so a selected scope never infers project sharing.
/// - `source_availability` keeps a pruned or privacy-purged source visibly
///   unavailable instead of turning it into a false, stale, or deleted record.
/// - `truncated` is an explicit observation: a partial window is never
///   presented as a complete conversation.
/// - Ordering is the explicit `sequence`, and every `supersedes` target must be
///   an earlier message in this same episode, so an edit cannot silently
///   reorder or vanish from history.
///
/// Shape-vs-durable split, identical to the bank and feedback records: this
/// admits the record *shape* only. Durability is established by the
/// [`SESSION_EPISODE_COMMIT_OPERATION`] commit leg, never by the existence of
/// this value.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SessionEpisodeRecord {
    /// Contract version this record was written against.
    pub contract_version: ContractVersion,
    /// Exact canonical handle of the episode.
    pub handle: ArtifactId,
    /// Owner revision counter assigned at admission; strictly increasing per
    /// handle under one owner.
    pub episode_revision: u64,
    /// Session and attempt references this episode covers; non-empty, unique.
    pub session_and_attempt_refs: Vec<ArtifactId>,
    /// Closed capture mode; only `ModelFree` exists.
    pub capture_mode: SessionEpisodeCaptureMode,
    /// Closed body kind; only `DialogueProse` exists.
    pub body_kind: SessionEpisodeBodyKind,
    /// The ingestion owner's source cursor, carried verbatim. This record
    /// validates it and never mints or advances it.
    pub source_ref: SourceRevisionHandle,
    /// Availability of the source behind `source_ref`.
    pub source_availability: SessionEpisodeSourceAvailability,
    /// Whether the episode body stands on its own without the source.
    pub content_self_contained: bool,
    /// Portability of this episode; local-private by default.
    pub portability: SessionEpisodePortability,
    /// Entity references the episode touched.
    pub touched_entity_refs: Vec<ArtifactId>,
    /// Observed cursor window of the admitted messages.
    pub observed_window: CoverageInterval,
    /// Explicit truncation observation; `true` is a partial window.
    ///
    /// Reconciled against the ingestion owner's independent coverage evidence
    /// in [`SessionEpisodeRecord::validate`], never against a copy of this
    /// record's own message list.
    pub truncated: bool,
    /// Owner coverage binding for the admitted message window.
    ///
    /// The ingestion owner, not this record, reports the observed volume and
    /// the complete/partial posture; the record only reconciles its own
    /// carried messages against that independent evidence.
    pub coverage: ProjectionCoverage,
    /// Public messages in admitted order.
    pub messages: Vec<SessionEpisodeMessage>,
    /// Read scope governing this record.
    pub scope: ObservationScope,
    /// Fence this record was admitted under, carried for edge gating.
    pub fence: StateFence,
    /// Producer origin of the admitted public messages.
    pub provenance: ProducerTrace,
    /// Privacy/retention/disclosure refs; policy is interpreted by the
    /// retention owner, never here.
    pub retention: PrivacyRetentionDisclosure,
    /// Prior episode record this one supersedes, when retained lineage
    /// applies. Must differ from `handle`.
    pub predecessor: Option<ArtifactId>,
    /// Measured canonical preimage byte length at admission.
    pub byte_length: u64,
    /// Frozen digest over the record shape, excluding this field and
    /// `byte_length`.
    pub digest: String,
}

impl SessionEpisodeRecord {
    /// Admit an episode record: validate every binding, measure the canonical
    /// preimage, and freeze the owner digest. The digest and byte length are
    /// computed here, never caller-supplied, so the commit leg can only carry
    /// bytes this owner admitted.
    ///
    /// The caller supplies `source_ref`; this owner validates it through its own
    /// `validate()` and never recomputes, replaces, or advances it.
    #[allow(clippy::too_many_arguments)]
    pub fn admit(
        handle: ArtifactId,
        episode_revision: u64,
        session_and_attempt_refs: Vec<ArtifactId>,
        source_ref: SourceRevisionHandle,
        source_availability: SessionEpisodeSourceAvailability,
        content_self_contained: bool,
        portability: SessionEpisodePortability,
        touched_entity_refs: Vec<ArtifactId>,
        observed_window: CoverageInterval,
        truncated: bool,
        coverage: ProjectionCoverage,
        messages: Vec<SessionEpisodeMessage>,
        scope: ObservationScope,
        fence: StateFence,
        provenance: ProducerTrace,
        retention: PrivacyRetentionDisclosure,
        predecessor: Option<ArtifactId>,
    ) -> Result<Self, ObservationError> {
        let mut record = Self {
            contract_version: EXPERIENCE_RECORD_CONTRACT_VERSION,
            handle,
            episode_revision,
            session_and_attempt_refs,
            capture_mode: SessionEpisodeCaptureMode::ModelFree,
            body_kind: SessionEpisodeBodyKind::DialogueProse,
            source_ref,
            source_availability,
            content_self_contained,
            portability,
            touched_entity_refs,
            observed_window,
            truncated,
            coverage,
            messages,
            scope,
            fence,
            provenance,
            retention,
            predecessor,
            byte_length: 0,
            digest: String::new(),
        };
        let preimage = record.preimage_bytes()?;
        record.byte_length = u64::try_from(preimage.len()).unwrap_or(u64::MAX);
        if record.byte_length == 0 {
            return Err(ObservationError::InvalidField {
                field: "session_episode.byte_length",
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
            self.episode_revision,
            &self.session_and_attempt_refs,
            &self.capture_mode,
            &self.body_kind,
            &self.source_ref,
            &self.source_availability,
            self.content_self_contained,
            &self.portability,
            &self.touched_entity_refs,
            &self.observed_window,
            self.truncated,
            &self.coverage,
            &self.messages,
            &self.scope,
            &self.fence,
            &self.provenance,
            &self.retention,
            &self.predecessor,
        ))
        .map_err(|_| ObservationError::InvalidField {
            field: "session_episode.digest",
            reason: "record is not canonically encodable",
        })
    }

    /// Validate bindings, message order, completeness, measured length, and
    /// the frozen digest.
    pub fn validate(&self) -> Result<(), ObservationError> {
        if self.contract_version != EXPERIENCE_RECORD_CONTRACT_VERSION {
            return Err(ObservationError::InvalidField {
                field: "session_episode.contract_version",
                reason: "unsupported contract version",
            });
        }
        self.validate_shared_bindings()?;
        self.validate_messages()?;
        self.validate_completeness_against_owner_coverage()?;
        let preimage = self.preimage_bytes()?;
        let measured = u64::try_from(preimage.len()).unwrap_or(u64::MAX);
        if self.byte_length != measured {
            return Err(ObservationError::InvalidField {
                field: "session_episode.byte_length",
                reason: "does not match the canonical preimage length",
            });
        }
        digest_shape(&self.digest, "session_episode.digest")?;
        if self.digest != sha256_hex(&preimage) {
            return Err(ObservationError::InvalidField {
                field: "session_episode.digest",
                reason: "does not match record preimage",
            });
        }
        Ok(())
    }

    /// Reconcile the carried window against the ingestion owner's independent
    /// coverage evidence.
    ///
    /// The expected set is `coverage.evidence`, which the owner reports from
    /// its own source read; it is never reconstructed from this record's own
    /// message list. Carrying more messages than the owner observed is always
    /// inconsistent, and the owner's `Complete` disposition additionally
    /// requires the exact count, no blind intervals, and no truncation — so a
    /// partial window can never be presented as a complete conversation.
    fn validate_completeness_against_owner_coverage(&self) -> Result<(), ObservationError> {
        self.coverage
            .validate()
            .map_err(|_| ObservationError::InvalidField {
                field: "session_episode.coverage",
                reason: "owner coverage binding is invalid",
            })?;
        let carried = u64::try_from(self.messages.len()).unwrap_or(u64::MAX);
        if carried > self.coverage.evidence.observed_count {
            return Err(ObservationError::CoverageIncomplete {
                reason: "admitted messages exceed the owner-observed volume",
            });
        }
        if self.coverage.evidence.disposition == CoverageDisposition::Complete
            && (carried != self.coverage.evidence.observed_count
                || !self.coverage.evidence.blind_intervals.is_empty()
                || self.truncated)
        {
            return Err(ObservationError::CoverageIncomplete {
                reason: "complete owner coverage requires the exact count, no blind intervals and no truncation",
            });
        }
        Ok(())
    }

    /// Validate the bindings shared with the other admitted experience records.
    fn validate_shared_bindings(&self) -> Result<(), ObservationError> {
        if self.session_and_attempt_refs.is_empty() {
            return Err(ObservationError::InvalidField {
                field: "session_episode.session_and_attempt_refs",
                reason: "at least one session or attempt ref is required",
            });
        }
        if self.session_and_attempt_refs.len() > MAX_EPISODE_SESSION_REFS {
            return Err(ObservationError::InvalidField {
                field: "session_episode.session_and_attempt_refs",
                reason: "exceeds bounded length",
            });
        }
        let mut seen: Vec<&str> = Vec::with_capacity(self.session_and_attempt_refs.len());
        for reference in &self.session_and_attempt_refs {
            let id = reference.as_str();
            if seen.contains(&id) {
                return Err(ObservationError::Duplicate {
                    field: "session_episode.session_and_attempt_refs",
                    value: id.to_owned(),
                });
            }
            seen.push(id);
        }
        if self.touched_entity_refs.len() > MAX_EPISODE_ENTITY_REFS {
            return Err(ObservationError::InvalidField {
                field: "session_episode.touched_entity_refs",
                reason: "exceeds bounded length",
            });
        }
        let mut seen: Vec<&str> = Vec::with_capacity(self.touched_entity_refs.len());
        for reference in &self.touched_entity_refs {
            let id = reference.as_str();
            if seen.contains(&id) {
                return Err(ObservationError::Duplicate {
                    field: "session_episode.touched_entity_refs",
                    value: id.to_owned(),
                });
            }
            seen.push(id);
        }
        if let Some(prior) = &self.predecessor
            && prior == &self.handle
        {
            return Err(ObservationError::InvalidField {
                field: "session_episode.predecessor",
                reason: "predecessor must differ from the record handle",
            });
        }
        self.source_ref
            .validate()
            .map_err(|_| ObservationError::InvalidField {
                field: "session_episode.source_ref",
                reason: "owner-issued source cursor is invalid",
            })?;
        self.portability.validate()?;
        CoverageInterval::new(self.observed_window.start, self.observed_window.end)?;
        self.scope.validate()?;
        fence_shape(&self.fence, "session_episode.fence")?;
        self.provenance.validate()?;
        self.retention.validate()
    }

    /// Validate message order, uniqueness, and supersession linkage.
    fn validate_messages(&self) -> Result<(), ObservationError> {
        if self.messages.is_empty() {
            return Err(ObservationError::InvalidField {
                field: "session_episode.messages",
                reason: "at least one public message is required",
            });
        }
        if self.messages.len() > MAX_SESSION_EPISODE_MESSAGES {
            return Err(ObservationError::InvalidField {
                field: "session_episode.messages",
                reason: "exceeds bounded length",
            });
        }
        let mut refs: Vec<&str> = Vec::with_capacity(self.messages.len());
        for (index, message) in self.messages.iter().enumerate() {
            message.validate("session_episode.messages")?;
            if message.sequence != u64::try_from(index).unwrap_or(u64::MAX) {
                return Err(ObservationError::InvalidField {
                    field: "session_episode.messages.sequence",
                    reason: "message sequence must equal its admitted order position",
                });
            }
            let id = message.message_ref.as_str();
            if refs.contains(&id) {
                return Err(ObservationError::Duplicate {
                    field: "session_episode.messages.message_ref",
                    value: id.to_owned(),
                });
            }
            refs.push(id);
        }
        // A supersession target must already be admitted earlier in this same
        // episode, so an edit can never point outside the recorded history.
        for message in &self.messages {
            if let Some(prior) = &message.supersedes {
                let target = prior.as_str();
                let earlier = self
                    .messages
                    .iter()
                    .any(|candidate| candidate.message_ref.as_str() == target);
                if !earlier {
                    return Err(ObservationError::InvalidField {
                        field: "session_episode.messages.supersedes",
                        reason: "superseded message is not admitted in this episode",
                    });
                }
            }
        }
        Ok(())
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

/// Owner-issued retention schedule binding policy refs to a fence (B223 join).
///
/// The schedule is versioned Governor configuration: `schedule_revision`
/// strictly increases per `schedule_id`, and `known_policy_refs` is the
/// exact closed set the schedule attests at `fence`. Replacing the former
/// caller-asserted `policy_known: bool` (review F4), knowledge is now an
/// owner attestation carrying schedule/revision/fence identity, so
/// [`resolve_retention_read`] can distinguish owner-attested from
/// caller-asserted knowledge and can verify the schedule was in force at
/// the record's fence.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RetentionSchedule {
    /// Contract version this schedule was written against.
    pub contract_version: ContractVersion,
    /// Stable schedule identity (one Governor configuration stream).
    pub schedule_id: String,
    /// Owner schedule revision; strictly increasing per schedule.
    pub schedule_revision: u64,
    /// Fence this schedule is in force at, carried for edge gating.
    pub fence: StateFence,
    /// Exact closed policy refs attested by this schedule revision.
    pub known_policy_refs: Vec<String>,
    /// Frozen digest over the schedule shape, excluding this field.
    pub digest: String,
}

impl RetentionSchedule {
    /// Issue a schedule revision: validate bindings and freeze the owner
    /// digest. Only the schedule owner (Governor configuration) calls this.
    pub fn issue(
        schedule_id: String,
        schedule_revision: u64,
        fence: StateFence,
        known_policy_refs: Vec<String>,
    ) -> Result<Self, ObservationError> {
        bounded_text(
            &schedule_id,
            "retention_schedule.schedule_id",
            MAX_CONSENT_REF_CHARS,
        )?;
        fence_shape(&fence, "retention_schedule.fence")?;
        if known_policy_refs.len() > MAX_BANK_SOURCE_REFS {
            return Err(ObservationError::InvalidField {
                field: "retention_schedule.known_policy_refs",
                reason: "exceeds bounded length",
            });
        }
        let mut seen: Vec<&str> = Vec::with_capacity(known_policy_refs.len());
        for policy in &known_policy_refs {
            bounded_text(
                policy,
                "retention_schedule.known_policy_refs",
                MAX_CONSENT_REF_CHARS,
            )?;
            if seen.contains(&policy.as_str()) {
                return Err(ObservationError::Duplicate {
                    field: "retention_schedule.known_policy_refs",
                    value: policy.clone(),
                });
            }
            seen.push(policy);
        }
        let mut schedule = Self {
            contract_version: EXPERIENCE_RECORD_CONTRACT_VERSION,
            schedule_id,
            schedule_revision,
            fence,
            known_policy_refs,
            digest: String::new(),
        };
        let preimage = canonical_json_bytes(&(
            &schedule.contract_version,
            &schedule.schedule_id,
            schedule.schedule_revision,
            &schedule.fence,
            &schedule.known_policy_refs,
        ))
        .map_err(|_| ObservationError::InvalidField {
            field: "retention_schedule.digest",
            reason: "schedule is not canonically encodable",
        })?;
        if preimage.is_empty() {
            return Err(ObservationError::InvalidField {
                field: "retention_schedule.digest",
                reason: "schedule preimage must be non-empty",
            });
        }
        schedule.digest = sha256_hex(&preimage);
        schedule.validate()?;
        Ok(schedule)
    }

    /// Validate bindings and the frozen digest.
    pub fn validate(&self) -> Result<(), ObservationError> {
        if self.contract_version != EXPERIENCE_RECORD_CONTRACT_VERSION {
            return Err(ObservationError::InvalidField {
                field: "retention_schedule.contract_version",
                reason: "unsupported contract version",
            });
        }
        bounded_text(
            &self.schedule_id,
            "retention_schedule.schedule_id",
            MAX_CONSENT_REF_CHARS,
        )?;
        fence_shape(&self.fence, "retention_schedule.fence")?;
        if self.known_policy_refs.len() > MAX_BANK_SOURCE_REFS {
            return Err(ObservationError::InvalidField {
                field: "retention_schedule.known_policy_refs",
                reason: "exceeds bounded length",
            });
        }
        for policy in &self.known_policy_refs {
            bounded_text(
                policy,
                "retention_schedule.known_policy_refs",
                MAX_CONSENT_REF_CHARS,
            )?;
        }
        digest_shape(&self.digest, "retention_schedule.digest")?;
        let preimage = canonical_json_bytes(&(
            &self.contract_version,
            &self.schedule_id,
            self.schedule_revision,
            &self.fence,
            &self.known_policy_refs,
        ))
        .map_err(|_| ObservationError::InvalidField {
            field: "retention_schedule.digest",
            reason: "schedule is not canonically encodable",
        })?;
        if self.digest != sha256_hex(&preimage) {
            return Err(ObservationError::InvalidField {
                field: "retention_schedule.digest",
                reason: "does not match schedule preimage",
            });
        }
        Ok(())
    }

    /// Whether this schedule attests the given policy ref.
    pub fn knows(&self, policy_ref: &str) -> bool {
        self.known_policy_refs
            .iter()
            .any(|known| known == policy_ref)
    }
}
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

/// Resolve the read posture for one retention-gated record against an
/// owner-issued schedule.
///
/// Owner checks (review F4 join): the schedule validates (identity,
/// revision, frozen digest); the schedule fence must be compatible with
/// the record fence or the schedule was not in force at the record —
/// explicit `UnknownPolicy` gap; the record's policy ref must be attested
/// by `schedule.knows`, else `UnknownPolicy`. Known refs under a
/// caller-supplied hold resolve to `RetentionBlocked` with only carried
/// refs; known refs with no hold resolve to `Readable`. No expiry,
/// permission, or erasure schedule is fabricated on any path.
pub fn resolve_retention_read(
    retention: &PrivacyRetentionDisclosure,
    schedule: &RetentionSchedule,
    record_fence: &StateFence,
    hold: Option<&RetentionHold>,
) -> Result<ExperienceRetentionReadPosture, ObservationError> {
    retention.validate()?;
    schedule.validate()?;
    fence_shape(record_fence, "retention_read.record_fence")?;
    if !schedule.fence.is_compatible_with(record_fence) {
        return Ok(ExperienceRetentionReadPosture::UnknownPolicy {
            retention_policy_ref: retention.retention_policy_ref.clone(),
        });
    }
    if !schedule.knows(&retention.retention_policy_ref) {
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

/// Resolve one opaque bank ref against an owner-issued record snapshot.
///
/// Canonical-ref join (reviews F1/F5): the handle must exist in the
/// snapshot; the cursor revision must equal the record's owner revision;
/// the cursor digest and length must equal the record's admitted digest
/// and measured preimage length; the scope echo must match. Any drift —
/// unknown handle, stale revision, rewritten digest, or scope mismatch —
/// fails closed. Durable existence behind the snapshot is the #19 read
/// path's gate: this resolver proves the ref resolves within the snapshot
/// the owner issued, never that rows are durable.
pub fn resolve_bank_ref<'a>(
    snapshot: &'a [ExperienceBankRecord],
    reference: &ExperienceRecordRef,
) -> Result<&'a ExperienceBankRecord, ObservationError> {
    reference.validate()?;
    let Some(record) = snapshot
        .iter()
        .find(|record| record.handle == reference.handle)
    else {
        return Err(ObservationError::InvalidField {
            field: "experience_ref.handle",
            reason: "ref handle is not in the owner snapshot",
        });
    };
    record.validate()?;
    if reference.revision.revision != record.bank_revision.to_string() {
        return Err(ObservationError::InvalidField {
            field: "experience_ref.revision",
            reason: "ref revision does not match the admitted record revision",
        });
    }
    if reference.revision.content_sha256 != record.digest {
        return Err(ObservationError::InvalidField {
            field: "experience_ref.revision",
            reason: "ref digest does not match the admitted record digest",
        });
    }
    if reference.revision.byte_length != record.byte_length {
        return Err(ObservationError::InvalidField {
            field: "experience_ref.revision",
            reason: "ref length does not match the admitted record length",
        });
    }
    if reference.scope != record.scope {
        return Err(ObservationError::InvalidField {
            field: "experience_ref.scope",
            reason: "ref scope does not match the admitted record scope",
        });
    }
    Ok(record)
}

/// Resolve one opaque feedback ref against an owner-issued record
/// snapshot. Same canonical-ref rule as [`resolve_bank_ref`].
pub fn resolve_feedback_ref<'a>(
    snapshot: &'a [AgentFeedbackRecord],
    reference: &ExperienceRecordRef,
) -> Result<&'a AgentFeedbackRecord, ObservationError> {
    reference.validate()?;
    let Some(record) = snapshot
        .iter()
        .find(|record| record.handle == reference.handle)
    else {
        return Err(ObservationError::InvalidField {
            field: "experience_ref.handle",
            reason: "ref handle is not in the owner snapshot",
        });
    };
    record.validate()?;
    if reference.revision.revision != record.feedback_revision.to_string() {
        return Err(ObservationError::InvalidField {
            field: "experience_ref.revision",
            reason: "ref revision does not match the admitted record revision",
        });
    }
    if reference.revision.content_sha256 != record.digest {
        return Err(ObservationError::InvalidField {
            field: "experience_ref.revision",
            reason: "ref digest does not match the admitted record digest",
        });
    }
    if reference.revision.byte_length != record.byte_length {
        return Err(ObservationError::InvalidField {
            field: "experience_ref.revision",
            reason: "ref length does not match the admitted record length",
        });
    }
    if reference.scope != record.scope {
        return Err(ObservationError::InvalidField {
            field: "experience_ref.scope",
            reason: "ref scope does not match the admitted record scope",
        });
    }
    Ok(record)
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

/// Canonical commit parameters for one admitted experience record.
///
/// Closed parameter schema for the [`BANK_COMMIT_OPERATION`] /
/// [`FEEDBACK_COMMIT_OPERATION`] named operations (transition class
/// [`COMMIT_TRANSITION_CLASS`], ceiling [`COMMIT_MAX_EFFECT`]). Every
/// field binds admitted content: the record digest and owner revision,
/// canonical digests of the exact scope and fence the record was admitted
/// under, and a deterministic idempotency key (`bank:{handle}:{revision}`
/// or `feedback:{handle}:{revision}`). The store bridge (#19 lane)
/// registers these names and executes the transition; this shape only
/// declares what the Governor commit producer must supply, byte for byte.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ExperienceCommitParameters {
    /// Closed operation name: exactly [`BANK_COMMIT_OPERATION`] or
    /// [`FEEDBACK_COMMIT_OPERATION`].
    pub operation: String,
    /// Digest of the complete admitted record bytes (the record digest).
    pub record_digest: String,
    /// Owner revision of the admitted record.
    pub record_revision: u64,
    /// Digest over the canonical bytes of the admission scope.
    pub scope_digest: String,
    /// Digest over the canonical bytes of the admission fence.
    pub fence_digest: String,
    /// Deterministic idempotency key for the commit.
    pub idempotency_key: String,
}

impl ExperienceCommitParameters {
    /// Build commit parameters for one admitted bank record. All digests
    /// are recomputed from the record here, never caller-supplied.
    pub fn for_bank(record: &ExperienceBankRecord) -> Result<Self, ObservationError> {
        record.validate()?;
        Ok(Self {
            operation: BANK_COMMIT_OPERATION.to_owned(),
            record_digest: record.digest.clone(),
            record_revision: record.bank_revision,
            scope_digest: canonical_shape_digest(&record.scope, "commit.scope")?,
            fence_digest: canonical_shape_digest(&record.fence, "commit.fence")?,
            idempotency_key: format!("bank:{}:{}", record.handle.as_str(), record.bank_revision),
        })
    }

    /// Build commit parameters for one admitted feedback record. Same
    /// recompute rule as [`for_bank`](Self::for_bank).
    pub fn for_feedback(record: &AgentFeedbackRecord) -> Result<Self, ObservationError> {
        record.validate()?;
        Ok(Self {
            operation: FEEDBACK_COMMIT_OPERATION.to_owned(),
            record_digest: record.digest.clone(),
            record_revision: record.feedback_revision,
            scope_digest: canonical_shape_digest(&record.scope, "commit.scope")?,
            fence_digest: canonical_shape_digest(&record.fence, "commit.fence")?,
            idempotency_key: format!(
                "feedback:{}:{}",
                record.handle.as_str(),
                record.feedback_revision
            ),
        })
    }

    /// Build commit parameters for one admitted session-episode record. Same
    /// recompute rule as [`for_bank`](Self::for_bank).
    pub fn for_session_episode(
        record: &SessionEpisodeRecord,
    ) -> Result<Self, ObservationError> {
        record.validate()?;
        Ok(Self {
            operation: SESSION_EPISODE_COMMIT_OPERATION.to_owned(),
            record_digest: record.digest.clone(),
            record_revision: record.episode_revision,
            scope_digest: canonical_shape_digest(&record.scope, "commit.scope")?,
            fence_digest: canonical_shape_digest(&record.fence, "commit.fence")?,
            idempotency_key: format!(
                "episode:{}:{}",
                record.handle.as_str(),
                record.episode_revision
            ),
        })
    }

    /// Validate the closed parameter shape: known operation, digest
    /// shapes, and a non-blank idempotency key.
    pub fn validate(&self) -> Result<(), ObservationError> {
        if self.operation != BANK_COMMIT_OPERATION
            && self.operation != FEEDBACK_COMMIT_OPERATION
            && self.operation != SESSION_EPISODE_COMMIT_OPERATION
        {
            return Err(ObservationError::InvalidField {
                field: "commit.operation",
                reason: "unknown experience commit operation",
            });
        }
        digest_shape(&self.record_digest, "commit.record_digest")?;
        digest_shape(&self.scope_digest, "commit.scope_digest")?;
        digest_shape(&self.fence_digest, "commit.fence_digest")?;
        text(&self.idempotency_key, "commit.idempotency_key")
    }
}

/// Digest over the canonical bytes of one scope or fence shape.
fn canonical_shape_digest<T: Serialize>(
    shape: &T,
    field: &'static str,
) -> Result<String, ObservationError> {
    canonical_json_bytes(shape)
        .map(|bytes| sha256_hex(&bytes))
        .map_err(|_| ObservationError::InvalidField {
            field,
            reason: "shape is not canonically encodable",
        })
}
