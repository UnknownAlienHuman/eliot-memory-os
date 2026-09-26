//! P-06 ORS process-stream recovery projection (issue #269).
//!
//! Architecture: A13.6 / ARCH-MOD-02 and I14.26. ORS keeps recovery durable,
//! bounded, non-semantic and non-authoritative. This module retains only what
//! is needed to *reconcile* an accepted or unknown process-stream operation
//! after Kernel restart: the immutable locator identity, the exact durable
//! coverage, the typed transport/persistence state, the exact gap set, and the
//! reconciliation owner/state.
//!
//! Structural no-bytes guarantee: no type in this module holds a
//! `Vec<u8>`. Stream payloads are reachable only through
//! [`DurableProcessStreamSource`], which carries an immutable locator plus a
//! ready-receipt reference and a digest. The bounded inline preview is
//! deliberately *not* embedded; only its identity, byte counts and omission
//! ranges are retained as [`StreamRecoveryPreview`].
//!
//! Structural no-synthetic-locator guarantee: a locator is only ever obtained
//! from [`DurableProcessStreamSource`], whose own deserializer rejects the
//! `raw`/`memory`/`process-memory` schemes, and [`ProcessStreamRecoveryProjection::validate`]
//! re-asserts the same rule at the ORS boundary. See
//! [`ProcessStreamRecoveryProjection::reject_synthetic_locator`].
//!
//! Implementation: I5.16 durable fields, I14.6 execution axes, I14.26 recovery
//! view. This module owns no `BlobStore`, no process, no parser, no evaluator,
//! no canonical state and no finish. Bytes remain under the one `BlobStore`
//! owner; [`ProcessStreamSourceResolver`] is only a read-only identity port.
//!
//! Ownership: this cell is a **data-contract boundary**, not a second durable
//! owner. Rows are written and read by the existing ORS owner
//! (`RedbRecoveryStore`) through the existing ORS codec
//! (`PersistedValue for ProcessStreamRecoveryProjection`).

use eliot_contracts::EpochId;
use eliot_process::{
    DurableProcessStreamSource, PROCESS_STREAM_EVIDENCE_SCHEMA_VERSION, ProcessStreamEvidence,
    ProcessStreamKind, ProcessStreamPolicyBinding, ProcessStreamPrefixPreview,
    ProcessStreamTransportPrefixIdentity, StreamByteRange, StreamEvidenceGap,
    StreamPersistenceStatus, StreamPreviewRepresentation, StreamTransportStatus,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::model::{sha256_hex, validate_digest, validate_text};
use crate::{
    CONTRACT_VERSION, EpochLineage, OpaqueLabel, OperationIdentity, OrsError, RecoveryOwner,
};

/// Hard ceiling for retained omitted-preview ranges on one projection.
///
/// The accepted evidence contract admits only the exact omitted suffix of a
/// retained prefix; this bound keeps the retained omission metadata
/// independently bounded so a projection cannot widen it.
pub const MAX_STREAM_RECOVERY_OMITTED_RANGES: usize = 16;
/// Hard ceiling for retained coverage gaps on one projection.
pub const MAX_STREAM_RECOVERY_GAPS: usize = 16;

/// What this projection is allowed to assert.
///
/// A single variant is deliberate: the value makes "bytes and exact coverage
/// only, never parser/evaluator/task/finish evidence" part of the stored and
/// projected wire rather than a prose promise that a caller could widen.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum StreamRecoveryEvidenceScope {
    /// Immutable process-stream bytes and exact durable coverage, and nothing else.
    ProcessStreamBytesAndCoverage,
}

/// Durable activation state of one recovery projection.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum StreamRecoveryActivation {
    /// The owning live operation may depend on this projection.
    Active,
    /// Imported or fenced recovery evidence. Never revives the operation.
    Suspended,
    /// Terminal for this projection. Absorbing: it never becomes active again.
    Retired,
}

impl StreamRecoveryActivation {
    /// Whether dependent reconciliation may consume this projection.
    pub const fn admits_dependent_reconciliation(self) -> bool {
        matches!(self, Self::Active)
    }

    /// Whether `next` is a legal successor. `Retired` is absorbing and
    /// `Suspended` can never return to `Active`, so a restore cannot revive
    /// process, session or authority state through this projection.
    pub const fn permits_transition_to(self, next: Self) -> bool {
        matches!(
            (self, next),
            (Self::Active, Self::Suspended | Self::Retired)
                | (Self::Suspended, Self::Suspended | Self::Retired)
        )
    }
}

/// Reconciliation state of the owning operation, as seen from ORS.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum StreamRecoveryReconciliationState {
    /// No reconciliation has started.
    Unreconciled,
    /// Reconciliation is in progress under the named owner.
    Reconciling,
    /// Reconciliation completed under the named owner.
    Reconciled,
    /// Reconciliation is blocked; the owner must resolve the blocker first.
    Blocked,
}

/// Reconciliation owner and the proven handoff/readback it carries.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StreamRecoveryReconciliation {
    /// Identity of the owner that may reconcile this projection. It grants no
    /// authority; it only names the accountable party.
    pub owner: RecoveryOwner,
    /// Current reconciliation state.
    pub state: StreamRecoveryReconciliationState,
    /// Digest of the proven evidence handoff/readback.
    ///
    /// `None` until the handoff is actually proven, so retirement cannot be
    /// claimed from an unproven handoff.
    pub handoff_sha256: Option<String>,
}

impl StreamRecoveryReconciliation {
    /// Creates an unreconciled projection owner with no proven handoff.
    pub fn unreconciled(owner: RecoveryOwner) -> Self {
        Self {
            owner,
            state: StreamRecoveryReconciliationState::Unreconciled,
            handoff_sha256: None,
        }
    }

    fn validate(&self) -> Result<(), OrsError> {
        validate_text(self.owner.as_str(), "stream_recovery_reconciliation_owner")?;
        match &self.handoff_sha256 {
            Some(digest) => {
                validate_digest(digest, "stream_recovery_handoff_sha256")?;
                if self.state != StreamRecoveryReconciliationState::Reconciled {
                    return Err(OrsError::InvalidField {
                        field: "stream_recovery_reconciliation_state",
                        reason: "only a reconciled projection carries a proven handoff digest",
                    });
                }
            }
            None => {
                if self.state == StreamRecoveryReconciliationState::Reconciled {
                    return Err(OrsError::InvalidField {
                        field: "stream_recovery_handoff_sha256",
                        reason: "a reconciled projection requires a proven handoff digest",
                    });
                }
            }
        }
        Ok(())
    }
}

/// Half-open durable coverage interval `[start, end_exclusive)`.
///
/// Unlike the accepted evidence contract's omitted-range type, the empty
/// interval is representable here so a zero-byte complete source round-trips
/// with exact coverage instead of degrading to "unknown".
#[derive(Clone, Copy, Debug, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StreamRecoveryRange {
    start: u64,
    end_exclusive: u64,
}

impl StreamRecoveryRange {
    /// Creates a possibly empty half-open interval.
    pub const fn new(start: u64, end_exclusive: u64) -> Result<Self, OrsError> {
        if start > end_exclusive {
            return Err(OrsError::InvalidField {
                field: "stream_recovery_range",
                reason: "range start must not exceed its exclusive end",
            });
        }
        Ok(Self {
            start,
            end_exclusive,
        })
    }

    /// First covered offset.
    pub const fn start(&self) -> u64 {
        self.start
    }

    /// Exclusive end offset.
    pub const fn end_exclusive(&self) -> u64 {
        self.end_exclusive
    }

    /// Whether the interval covers no bytes.
    pub const fn is_empty(&self) -> bool {
        self.start == self.end_exclusive
    }
}

/// Exact durable coverage of the immutable locator: digest, count and range.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StreamRecoveryCoverage {
    /// SHA-256 over the exact durable source bytes at the locator.
    pub sha256: String,
    /// Exact durable source byte count.
    pub byte_length: u64,
    /// Covered interval; always `[0, byte_length)` for a whole-object source.
    pub range: StreamRecoveryRange,
}

/// Identity, counts and omission metadata of the bounded inline preview.
///
/// The preview's bytes are deliberately absent. This is the recovery-relevant
/// remainder: which coordinate system the preview used, what it hashed to, how
/// much it retained out of what it represented, and exactly which bytes it
/// omitted.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StreamRecoveryPreview {
    /// Coordinate system the retained preview bytes were expressed in.
    pub representation: StreamPreviewRepresentation,
    /// SHA-256 over the retained preview bytes only.
    pub sha256: String,
    /// Number of preview bytes that were retained.
    pub retained_bytes: u64,
    /// Total bytes in the selected representation.
    pub represented_bytes: u64,
    /// Exact half-open ranges omitted from the retained prefix.
    pub omitted_ranges: Vec<StreamByteRange>,
}

/// Why the durable source is not usable after revalidation.
///
/// Missing, corrupt, revoked and purged sources stay distinguishable; none of
/// them can be represented as complete evidence.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum StreamRecoverySourceFault {
    /// The immutable object is absent, for example deleted or purged.
    SourceMissing,
    /// The object's content identity disagrees with the recorded digest/count.
    SourceCorrupt,
    /// Authorization to read the immutable object was revoked.
    SourceRevoked,
    /// The ready receipt does not match the recorded locator binding.
    ReceiptMismatch,
    /// The recorded coverage range disagrees with the readback.
    CoverageMismatch,
    /// The resolver returned a binding for a different locator.
    ResolverBindingMismatch,
    /// The resolver could not establish presence, absence or revocation.
    ResolverUnavailable,
}

/// Availability of the durable source as last observed by revalidation.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum StreamRecoveryAvailability {
    /// Not re-read since the observation that produced this projection.
    Unrevalidated,
    /// Revalidated against readback: locator, receipt, digest, count and
    /// coverage all agree. This is an observation about the immutable source;
    /// it never upgrades the typed transport/persistence state.
    Revalidated,
    /// The durable source is unusable. The exact fault is retained and the
    /// prior typed transport/persistence state is preserved unchanged.
    Unavailable {
        /// Why the source is unusable.
        fault: StreamRecoverySourceFault,
    },
}

/// Input for [`ProcessStreamRecoveryProjection::from_stream_evidence`].
///
/// Grouped so the projection identity, the governing policy revision and the
/// reconciliation owner are always supplied together; none of them can be
/// omitted by a caller that only has an evidence value.
#[derive(Clone, Debug)]
pub struct ProcessStreamRecoveryBinding {
    /// Exact digest of the provider fence that admitted this observation.
    pub state_fence_digest: String,
    /// Writer epoch that owned the observation, for exact-tuple staleness checks.
    pub writer_epoch: EpochLineage,
    /// Identity of the governing policy revision at observation time.
    pub policy_revision: String,
    /// Owner accountable for reconciling this projection.
    pub reconciliation_owner: RecoveryOwner,
    /// Observation time in Unix milliseconds.
    pub observed_at_ms: i64,
}

/// Versioned, per-stream recovery projection retained by ORS.
///
/// Stdout and stderr are independent records with independent identities: the
/// durable key is `(operation_id, stream)`, so one stream can never satisfy,
/// overwrite or be read back as the other.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessStreamRecoveryProjection {
    /// ORS wire/storage contract version of this projection.
    pub contract_version: u16,
    /// Accepted process-stream evidence contract revision this projection is
    /// bound to. A move of this string fails closed for dependent
    /// reconciliation instead of being reinterpreted.
    pub stream_contract_revision: String,
    /// What this projection may assert; see [`StreamRecoveryEvidenceScope`].
    pub scope: StreamRecoveryEvidenceScope,
    /// Operation that owns both stream projections.
    pub operation_id: OperationIdentity,
    /// Exact request digest of the admitted operation.
    pub request_digest: String,
    /// Process tree identity of the observation.
    pub process_tree_id: OpaqueLabel,
    /// Job Object identity of the observation.
    pub job_id: OpaqueLabel,
    /// Executable image identity of the observation.
    pub image_id: OpaqueLabel,
    /// Session identity of the observation.
    pub session_id: OpaqueLabel,
    /// Which physical stream this record describes.
    pub stream: ProcessStreamKind,
    /// Lineage-aware authority epoch exact tuple.
    pub authority_epoch: EpochId,
    /// Runtime generation of the observation.
    pub generation: u64,
    /// Writer epoch that owned the observation.
    pub writer_epoch: EpochLineage,
    /// SHA-256 over the provider fence that admitted the observation.
    pub state_fence_digest: String,
    /// Identity of the governing policy revision at observation time.
    pub policy_revision: String,
    /// Typed physical transport completion, preserved exactly.
    pub transport: StreamTransportStatus,
    /// SHA-256 over every physical transport byte observed.
    pub observed_sha256: String,
    /// Number of physical transport bytes observed.
    pub observed_bytes: u64,
    /// Typed source durability, preserved exactly and never promoted.
    pub persistence: StreamPersistenceStatus,
    /// Immutable locator plus ready receipt, when a durable source exists.
    pub source: Option<DurableProcessStreamSource>,
    /// Exact durable coverage of `source`, when a durable source exists.
    pub durable_coverage: Option<StreamRecoveryCoverage>,
    /// Exact physical transport-prefix identity when a shorter exact source
    /// is the durable one.
    pub transport_prefix_identity: Option<ProcessStreamTransportPrefixIdentity>,
    /// Preview identity, counts and omission metadata; never preview bytes.
    pub preview: StreamRecoveryPreview,
    /// Policy, privacy, visibility, retention and redaction identities fixed
    /// before persistence.
    pub policy: ProcessStreamPolicyBinding,
    /// Exact coverage gap set, canonically sorted and unique.
    pub gaps: Vec<StreamEvidenceGap>,
    /// Durable-source availability as last observed by revalidation.
    pub availability: StreamRecoveryAvailability,
    /// Reconciliation owner, state and proven handoff.
    pub reconciliation: StreamRecoveryReconciliation,
    /// Durable activation state of this projection.
    pub activation: StreamRecoveryActivation,
    /// Observation time in Unix milliseconds.
    pub observed_at_ms: i64,
}

impl ProcessStreamRecoveryProjection {
    /// Derives the recovery projection from one accepted stream observation.
    ///
    /// `evidence` is read, never copied: its bounded inline preview bytes are
    /// not retained here. Every typed axis (transport, persistence, gaps,
    /// observed digest/count) is carried through verbatim, so this constructor
    /// cannot promote or reinterpret evidence.
    pub fn from_stream_evidence(
        evidence: &ProcessStreamEvidence,
        binding: ProcessStreamRecoveryBinding,
    ) -> Result<Self, OrsError> {
        evidence
            .validate()
            .map_err(|error| OrsError::Contract(error.to_string()))?;
        let process = evidence.binding();
        let source = evidence.source().cloned();
        let durable_coverage = match &source {
            Some(source) => Some(StreamRecoveryCoverage {
                sha256: source.sha256().to_owned(),
                byte_length: source.byte_length(),
                range: StreamRecoveryRange::new(0, source.byte_length())?,
            }),
            None => None,
        };
        let projection = Self {
            contract_version: CONTRACT_VERSION,
            stream_contract_revision: evidence.schema_version().to_owned(),
            scope: StreamRecoveryEvidenceScope::ProcessStreamBytesAndCoverage,
            operation_id: OpaqueLabel::new(process.operation_id().as_str())?,
            request_digest: process.request_digest().to_owned(),
            process_tree_id: OpaqueLabel::new(process.process_tree_id().as_str())?,
            job_id: OpaqueLabel::new(process.job_id().as_str())?,
            image_id: OpaqueLabel::new(process.image_id().as_str())?,
            session_id: OpaqueLabel::new(process.session_id().as_str())?,
            stream: evidence.stream(),
            authority_epoch: process.authority_epoch().clone(),
            generation: process.state_fence().generation().get(),
            writer_epoch: binding.writer_epoch,
            state_fence_digest: binding.state_fence_digest,
            policy_revision: binding.policy_revision,
            transport: evidence.transport(),
            observed_sha256: evidence.observed_sha256().to_owned(),
            observed_bytes: evidence.observed_bytes(),
            persistence: evidence.persistence(),
            source,
            durable_coverage,
            transport_prefix_identity: evidence.transport_prefix_identity().cloned(),
            preview: preview_summary(evidence.preview()),
            policy: evidence.policy().clone(),
            gaps: evidence.gaps().to_vec(),
            availability: StreamRecoveryAvailability::Unrevalidated,
            reconciliation: StreamRecoveryReconciliation::unreconciled(
                binding.reconciliation_owner,
            ),
            activation: StreamRecoveryActivation::Active,
            observed_at_ms: binding.observed_at_ms,
        };
        projection.validate()?;
        Ok(projection)
    }

    /// Stable physical-stream key. Stdout and stderr never share a key.
    pub const fn stream_key(kind: ProcessStreamKind) -> &'static str {
        match kind {
            ProcessStreamKind::Stdout => "stdout",
            ProcessStreamKind::Stderr => "stderr",
        }
    }

    /// Canonical durable key for exactly one `(operation, stream)` record.
    pub fn record_key(&self) -> Result<String, OrsError> {
        self.validate()?;
        Ok(format!(
            "{}:{}",
            self.operation_id.as_str(),
            Self::stream_key(self.stream)
        ))
    }

    /// Digest over the immutable evidence axes and projection identity.
    ///
    /// Availability, reconciliation and activation are deliberately excluded:
    /// they are the only fields a revalidation or a retirement may advance, so
    /// an equal digest proves that no evidence axis was rewritten.
    pub fn evidence_axes_sha256(&self) -> Result<String, OrsError> {
        self.validate()?;
        let identity = StreamRecoveryEvidenceAxes {
            operation_id: self.operation_id.as_str(),
            request_digest: &self.request_digest,
            process_tree_id: self.process_tree_id.as_str(),
            job_id: self.job_id.as_str(),
            image_id: self.image_id.as_str(),
            session_id: self.session_id.as_str(),
            stream: self.stream,
            authority_epoch: &self.authority_epoch,
            generation: self.generation,
            state_fence_digest: &self.state_fence_digest,
            policy_revision: &self.policy_revision,
            stream_contract_revision: &self.stream_contract_revision,
            transport: self.transport,
            observed_sha256: &self.observed_sha256,
            observed_bytes: self.observed_bytes,
            persistence: self.persistence,
            locator: self.source.as_ref().map(DurableProcessStreamSource::locator),
            ready_receipt_ref: self
                .source
                .as_ref()
                .map(DurableProcessStreamSource::ready_receipt_ref),
            source_sha256: self.source.as_ref().map(DurableProcessStreamSource::sha256),
            source_byte_length: self.source.as_ref().map(DurableProcessStreamSource::byte_length),
            coverage_sha256: self
                .durable_coverage
                .as_ref()
                .map(|coverage| coverage.sha256.as_str()),
            coverage_byte_length: self
                .durable_coverage
                .as_ref()
                .map(|coverage| coverage.byte_length),
            coverage_start: self
                .durable_coverage
                .as_ref()
                .map(|coverage| coverage.range.start()),
            coverage_end: self
                .durable_coverage
                .as_ref()
                .map(|coverage| coverage.range.end_exclusive()),
            preview_sha256: &self.preview.sha256,
            preview_retained_bytes: self.preview.retained_bytes,
            preview_represented_bytes: self.preview.represented_bytes,
            gaps: self.gaps.clone(),
        };
        let bytes = serde_json::to_vec(&identity)
            .map_err(|error| OrsError::Encoding(error.to_string()))?;
        Ok(sha256_hex(&bytes))
    }

    /// Returns a copy carrying a new availability observation.
    ///
    /// Every typed evidence axis is copied verbatim, so this cannot promote
    /// `PARTIAL_SOURCE` or `SOURCE_UNAVAILABLE` and cannot manufacture
    /// `COMPLETE_SOURCE`.
    pub fn with_availability(
        &self,
        availability: StreamRecoveryAvailability,
    ) -> Result<Self, OrsError> {
        let mut next = self.clone();
        next.availability = availability;
        next.validate()?;
        Ok(next)
    }

    /// Returns a copy carrying a new durable activation state.
    ///
    /// Fails closed on an illegal successor, so an imported or retired
    /// projection can never be revived.
    pub fn with_activation(&self, next: StreamRecoveryActivation) -> Result<Self, OrsError> {
        if !self.activation.permits_transition_to(next) {
            return Err(OrsError::InvalidField {
                field: "stream_recovery_activation",
                reason: "activation state transition is not permitted",
            });
        }
        let mut moved = self.clone();
        moved.activation = next;
        moved.validate()?;
        Ok(moved)
    }

    /// Fail-closed validation of every cross-field recovery invariant.
    pub fn validate(&self) -> Result<(), OrsError> {
        self.validate_identity()?;
        self.validate_observed_axes()?;
        self.validate_source_axes()?;
        self.validate_preview()?;
        self.reconciliation.validate()?;
        Ok(())
    }

    fn validate_identity(&self) -> Result<(), OrsError> {
        if self.contract_version != CONTRACT_VERSION {
            return Err(OrsError::UnsupportedContractVersion(self.contract_version));
        }
        if self.stream_contract_revision != PROCESS_STREAM_EVIDENCE_SCHEMA_VERSION {
            return Err(OrsError::Contract(format!(
                "process-stream recovery is bound to stream contract revision {}, \
                 not the accepted revision {}",
                self.stream_contract_revision, PROCESS_STREAM_EVIDENCE_SCHEMA_VERSION
            )));
        }
        if self.scope != StreamRecoveryEvidenceScope::ProcessStreamBytesAndCoverage {
            return Err(OrsError::InvalidField {
                field: "stream_recovery_scope",
                reason: "a recovery projection may only assert bytes and exact coverage",
            });
        }
        validate_text(self.operation_id.as_str(), "stream_recovery_operation_id")?;
        validate_digest(&self.request_digest, "stream_recovery_request_digest")?;
        for (value, field) in [
            (&self.process_tree_id, "stream_recovery_process_tree_id"),
            (&self.job_id, "stream_recovery_job_id"),
            (&self.image_id, "stream_recovery_image_id"),
            (&self.session_id, "stream_recovery_session_id"),
        ] {
            validate_text(value.as_str(), field)?;
        }
        validate_digest(&self.state_fence_digest, "stream_recovery_state_fence_digest")?;
        validate_digest(&self.policy_revision, "stream_recovery_policy_revision")?;
        if self.generation == 0 {
            return Err(OrsError::InvalidField {
                field: "stream_recovery_generation",
                reason: "runtime generation must be greater than zero",
            });
        }
        if self.observed_at_ms <= 0 {
            return Err(OrsError::InvalidField {
                field: "stream_recovery_observed_at_ms",
                reason: "observation time must be positive",
            });
        }
        self.writer_epoch.validate()?;
        // Exact-tuple lineage check spelled across the ORS contour boundary:
        // `EpochLineage` keeps an `OpaqueLabel` lineage while the canonical
        // `EpochId` keeps an `EpochLineageId`, so the canonical
        // `is_same_authority` spelling is the dual-half comparison below. Both
        // halves must agree; an equal sequence from a different lineage is
        // unrelated and never authorizes this projection.
        if self.authority_epoch.sequence.get() != self.writer_epoch.current.epoch
            || self.authority_epoch.lineage_id.as_str()
                != self.writer_epoch.current.lineage_id.as_str()
        {
            return Err(OrsError::FenceMismatch);
        }
        Ok(())
    }

    fn validate_observed_axes(&self) -> Result<(), OrsError> {
        validate_digest(&self.observed_sha256, "stream_recovery_observed_sha256")?;
        if self.observed_bytes == 0 && self.observed_sha256 != sha256_hex(&[]) {
            return Err(OrsError::InvalidField {
                field: "stream_recovery_observed_sha256",
                reason: "a zero-byte observed stream must use the empty SHA-256 identity",
            });
        }
        if self.gaps.len() > MAX_STREAM_RECOVERY_GAPS {
            return Err(OrsError::ProjectionLimitExceeded);
        }
        if !self.gaps.windows(2).all(|pair| pair[0] < pair[1]) {
            return Err(OrsError::InvalidField {
                field: "stream_recovery_gaps",
                reason: "gap reasons must be unique and canonically sorted",
            });
        }
        Ok(())
    }

    fn validate_source_axes(&self) -> Result<(), OrsError> {
        if let Some(source) = &self.source {
            Self::reject_synthetic_locator(source.locator())?;
        }
        if let Some(prefix) = &self.transport_prefix_identity {
            if self.source.is_none() {
                return Err(OrsError::InvalidField {
                    field: "stream_recovery_transport_prefix_identity",
                    reason: "a durable-prefix identity requires a durable source",
                });
            }
            if prefix.byte_length() > self.observed_bytes {
                return Err(OrsError::InvalidField {
                    field: "stream_recovery_transport_prefix_identity",
                    reason: "a durable-prefix identity cannot exceed the observed transport bytes",
                });
            }
        }
        if self.durable_coverage.is_some() != self.source.is_some() {
            return Err(OrsError::InvalidField {
                field: "stream_recovery_durable_coverage",
                reason: "durable coverage must be present exactly when a durable source is",
            });
        }
        if let (Some(coverage), Some(source)) = (&self.durable_coverage, &self.source) {
            Self::validate_durable_coverage(coverage, source)?;
        }
        self.validate_persistence_matrix()
    }

    fn validate_durable_coverage(
        coverage: &StreamRecoveryCoverage,
        source: &DurableProcessStreamSource,
    ) -> Result<(), OrsError> {
        validate_digest(&coverage.sha256, "stream_recovery_coverage_sha256")?;
        if coverage.sha256 != source.sha256()
            || coverage.byte_length != source.byte_length()
            || coverage.range.start() != 0
            || coverage.range.end_exclusive() != coverage.byte_length
        {
            return Err(OrsError::IntegrityProblem {
                record_type: "process_stream_recovery",
                reason: "durable coverage does not bind the immutable locator identity".to_owned(),
            });
        }
        // A zero-byte complete source round-trips with exact coverage: the
        // covered interval is empty and the digest is the empty SHA-256.
        if coverage.byte_length == 0
            && (!coverage.range.is_empty() || coverage.sha256 != sha256_hex(&[]))
        {
            return Err(OrsError::InvalidField {
                field: "stream_recovery_coverage_sha256",
                reason: "a zero-byte durable source must carry empty coverage and the empty digest",
            });
        }
        Ok(())
    }

    /// Mirrors the accepted evidence contract's closed locator rule at the ORS
    /// boundary. A synthetic `raw:` (or process-memory) locator can never
    /// become durable recovery state, and a missing or mismatched receipt can
    /// never be represented as complete evidence.
    fn reject_synthetic_locator(locator: &str) -> Result<(), OrsError> {
        let scheme = locator
            .split_once(':')
            .map(|(scheme, _)| scheme.to_ascii_lowercase())
            .unwrap_or_default();
        if matches!(
            scheme.as_str(),
            "raw" | "memory" | "process-memory" | "process_memory"
        ) {
            return Err(OrsError::InvalidField {
                field: "stream_recovery_locator",
                reason: "synthetic and process-memory stream locators are forbidden in ORS",
            });
        }
        Ok(())
    }

    fn validate_persistence_matrix(&self) -> Result<(), OrsError> {
        match self.persistence {
            StreamPersistenceStatus::CompleteSource => {
                if self.source.is_none() {
                    return Err(OrsError::InvalidField {
                        field: "stream_recovery_persistence",
                        reason: "a complete source requires an immutable locator and ready receipt",
                    });
                }
                if self.transport != StreamTransportStatus::Complete || !self.gaps.is_empty() {
                    return Err(OrsError::InvalidField {
                        field: "stream_recovery_persistence",
                        reason: "a complete source requires EOF and no coverage gaps",
                    });
                }
            }
            StreamPersistenceStatus::PartialSource => {
                if self.source.is_none() {
                    return Err(OrsError::InvalidField {
                        field: "stream_recovery_persistence",
                        reason: "a partial source requires an immutable locator and ready receipt",
                    });
                }
                if self.gaps.is_empty() {
                    return Err(OrsError::InvalidField {
                        field: "stream_recovery_gaps",
                        reason: "a partial source requires an explicit coverage gap",
                    });
                }
            }
            StreamPersistenceStatus::SourceUnavailable => {
                if self.source.is_some() || self.transport_prefix_identity.is_some() {
                    return Err(OrsError::InvalidField {
                        field: "stream_recovery_source",
                        reason: "source-unavailable evidence cannot carry a durable locator",
                    });
                }
            }
        }
        Ok(())
    }

    fn validate_preview(&self) -> Result<(), OrsError> {
        validate_digest(&self.preview.sha256, "stream_recovery_preview_sha256")?;
        if self.preview.retained_bytes > self.preview.represented_bytes {
            return Err(OrsError::InvalidField {
                field: "stream_recovery_preview_retained_bytes",
                reason: "retained preview bytes cannot exceed represented bytes",
            });
        }
        if self.preview.omitted_ranges.len() > MAX_STREAM_RECOVERY_OMITTED_RANGES {
            return Err(OrsError::ProjectionLimitExceeded);
        }
        if self.preview.representation == StreamPreviewRepresentation::WithheldByPolicy {
            if self.preview.retained_bytes != 0
                || self.preview.sha256 != sha256_hex(&[])
                || !self.preview.omitted_ranges.is_empty()
            {
                return Err(OrsError::InvalidField {
                    field: "stream_recovery_preview",
                    reason: "a policy-withheld preview cannot retain byte material",
                });
            }
            return Ok(());
        }
        if self.preview.omitted_ranges != omitted_suffix(
            self.preview.retained_bytes,
            self.preview.represented_bytes,
        )? {
            return Err(OrsError::InvalidField {
                field: "stream_recovery_preview_omitted_ranges",
                reason: "a retained prefix must expose exactly the omitted suffix",
            });
        }
        Ok(())
    }
}

fn preview_summary(preview: &ProcessStreamPrefixPreview) -> StreamRecoveryPreview {
    StreamRecoveryPreview {
        representation: preview.representation(),
        sha256: preview.sha256().to_owned(),
        retained_bytes: preview.retained_bytes(),
        represented_bytes: preview.represented_bytes(),
        omitted_ranges: preview.omitted_ranges().to_vec(),
    }
}

fn omitted_suffix(
    retained_bytes: u64,
    represented_bytes: u64,
) -> Result<Vec<StreamByteRange>, OrsError> {
    if retained_bytes == represented_bytes {
        return Ok(Vec::new());
    }
    StreamByteRange::new(retained_bytes, represented_bytes)
        .map(|range| vec![range])
        .map_err(|error| OrsError::Contract(error.to_string()))
}

#[derive(Serialize)]
struct StreamRecoveryEvidenceAxes<'a> {
    operation_id: &'a str,
    request_digest: &'a str,
    process_tree_id: &'a str,
    job_id: &'a str,
    image_id: &'a str,
    session_id: &'a str,
    stream: ProcessStreamKind,
    authority_epoch: &'a EpochId,
    generation: u64,
    state_fence_digest: &'a str,
    policy_revision: &'a str,
    stream_contract_revision: &'a str,
    transport: StreamTransportStatus,
    observed_sha256: &'a str,
    observed_bytes: u64,
    persistence: StreamPersistenceStatus,
    locator: Option<&'a str>,
    ready_receipt_ref: Option<&'a str>,
    source_sha256: Option<&'a str>,
    source_byte_length: Option<u64>,
    coverage_sha256: Option<&'a str>,
    coverage_byte_length: Option<u64>,
    coverage_start: Option<u64>,
    coverage_end: Option<u64>,
    preview_sha256: &'a str,
    preview_retained_bytes: u64,
    preview_represented_bytes: u64,
    gaps: Vec<StreamEvidenceGap>,
}

/// Exact content identity of one immutable source, as read back by the
/// resolver. It is digests and counts only; the projection never asks for or
/// stores stream bytes.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessStreamSourceReadback {
    /// Locator the resolver actually resolved.
    pub locator: String,
    /// Ready receipt the resolver actually holds for that locator.
    pub ready_receipt_ref: String,
    /// SHA-256 over the exact durable source bytes.
    pub sha256: String,
    /// Exact durable source byte count.
    pub byte_length: u64,
}

/// Result of resolving one immutable source.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", tag = "kind")]
pub enum ProcessStreamSourceResolution {
    /// The immutable object exists and is readable.
    Resolved {
        /// Exact content identity of the object.
        readback: ProcessStreamSourceReadback,
    },
    /// The immutable object is absent, for example deleted or purged.
    Absent,
    /// The object exists but its content identity is not trustworthy.
    Corrupt,
    /// Authorization to read the immutable object was revoked.
    Revoked,
    /// The resolver could not establish presence, absence or revocation.
    Unavailable,
}

/// Read-only identity port for the one owner that holds the stream bytes.
///
/// The projection resolves content identity only. Absence, corruption,
/// revocation and unavailability are typed outcomes, so a missing source can
/// never be mistaken for complete evidence.
pub trait ProcessStreamSourceResolver: Send + Sync {
    /// Resolves the exact content identity of one immutable source.
    fn resolve(&self, source: &DurableProcessStreamSource) -> ProcessStreamSourceResolution;
}

/// Current fence a dependent reconciliation must be performed under.
///
/// Every dimension here fails closed: a stale generation, authority epoch,
/// policy revision, accepted stream-contract revision or immutable locator
/// identity blocks dependent reconciliation instead of being reinterpreted.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq)]
pub struct ProcessStreamRecoveryFence {
    /// Runtime generation the reconciliation is being performed for.
    pub generation: u64,
    /// Lineage-aware authority epoch exact tuple.
    pub authority_epoch: EpochId,
    /// Governing policy revision identity.
    pub policy_revision: String,
    /// Accepted process-stream evidence contract revision.
    pub stream_contract_revision: String,
    /// Immutable locator identity the reconciliation is bound to.
    pub locator: String,
}

/// Typed reason dependent reconciliation is refused.
///
/// The variant names the exact stale dimension, so a refusal can never be
/// flattened into a generic code across the layer boundary.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", tag = "reason")]
pub enum ProcessStreamRecoveryRefusal {
    /// The projection's runtime generation is stale.
    StaleGeneration {
        /// Generation the reconciliation requires.
        expected: u64,
        /// Generation the projection was written under.
        found: u64,
    },
    /// The projection's authority epoch is not the current exact tuple.
    StaleAuthorityEpoch,
    /// The governing policy revision moved.
    StalePolicyRevision,
    /// The accepted process-stream contract revision moved.
    StaleStreamContractRevision,
    /// The immutable locator identity moved.
    LocatorIdentityMismatch,
    /// The projection is not active, so it cannot back a dependent action.
    NotActive {
        /// Current durable activation state.
        activation: StreamRecoveryActivation,
    },
    /// The retained evidence is typed incomplete.
    ///
    /// `UNKNOWN_OUTCOME`, `PARTIAL_SOURCE` and `SOURCE_UNAVAILABLE` are
    /// carried verbatim; none of them can satisfy complete evidence.
    IncompleteEvidence {
        /// Preserved physical transport status.
        transport: StreamTransportStatus,
        /// Preserved source durability status.
        persistence: StreamPersistenceStatus,
    },
}

impl ProcessStreamRecoveryProjection {
    /// Gate for any action that would depend on this projection.
    ///
    /// Both halves fail closed: the staleness dimensions (generation, authority
    /// epoch, policy revision, contract revision, locator identity) and the
    /// completeness dimensions (activation, typed transport/persistence).
    pub fn admit_dependent_reconciliation(
        &self,
        fence: &ProcessStreamRecoveryFence,
    ) -> Result<(), ProcessStreamRecoveryRefusal> {
        self.check_staleness(fence)?;
        if !self.activation.admits_dependent_reconciliation() {
            return Err(ProcessStreamRecoveryRefusal::NotActive {
                activation: self.activation,
            });
        }
        if self.persistence != StreamPersistenceStatus::CompleteSource
            || self.transport != StreamTransportStatus::Complete
        {
            return Err(ProcessStreamRecoveryRefusal::IncompleteEvidence {
                transport: self.transport,
                persistence: self.persistence,
            });
        }
        Ok(())
    }

    /// Staleness-only gate. Revalidation observes the durable source even for
    /// incomplete evidence, so it must not be blocked by completeness.
    pub fn check_staleness(
        &self,
        fence: &ProcessStreamRecoveryFence,
    ) -> Result<(), ProcessStreamRecoveryRefusal> {
        if self.generation != fence.generation {
            return Err(ProcessStreamRecoveryRefusal::StaleGeneration {
                expected: fence.generation,
                found: self.generation,
            });
        }
        if !self
            .authority_epoch
            .is_same_authority(&fence.authority_epoch)
        {
            return Err(ProcessStreamRecoveryRefusal::StaleAuthorityEpoch);
        }
        if self.policy_revision != fence.policy_revision {
            return Err(ProcessStreamRecoveryRefusal::StalePolicyRevision);
        }
        if self.stream_contract_revision != fence.stream_contract_revision {
            return Err(ProcessStreamRecoveryRefusal::StaleStreamContractRevision);
        }
        let locator = self.source.as_ref().map(DurableProcessStreamSource::locator);
        if locator != Some(fence.locator.as_str()) {
            return Err(ProcessStreamRecoveryRefusal::LocatorIdentityMismatch);
        }
        Ok(())
    }

    /// Revalidates the durable locator, receipt, digest, count and coverage.
    ///
    /// The typed transport/persistence/gap state is never touched: a failed
    /// revalidation only records an availability fault, and a successful one
    /// only records `Revalidated`. Neither path can promote `PARTIAL_SOURCE`
    /// or `SOURCE_UNAVAILABLE` to `COMPLETE_SOURCE`.
    pub fn revalidate(
        &self,
        fence: &ProcessStreamRecoveryFence,
        resolver: &dyn ProcessStreamSourceResolver,
    ) -> ProcessStreamRecoveryRevalidation {
        if let Err(refusal) = self.check_staleness(fence) {
            return ProcessStreamRecoveryRevalidation::Refused(refusal);
        }
        let Some(source) = &self.source else {
            return ProcessStreamRecoveryRevalidation::NoDurableSource;
        };
        match resolver.resolve(source) {
            ProcessStreamSourceResolution::Absent => {
                ProcessStreamRecoveryRevalidation::unavailable(
                    StreamRecoverySourceFault::SourceMissing,
                )
            }
            ProcessStreamSourceResolution::Corrupt => {
                ProcessStreamRecoveryRevalidation::unavailable(
                    StreamRecoverySourceFault::SourceCorrupt,
                )
            }
            ProcessStreamSourceResolution::Revoked => {
                ProcessStreamRecoveryRevalidation::unavailable(
                    StreamRecoverySourceFault::SourceRevoked,
                )
            }
            ProcessStreamSourceResolution::Unavailable => {
                ProcessStreamRecoveryRevalidation::unavailable(
                    StreamRecoverySourceFault::ResolverUnavailable,
                )
            }
            ProcessStreamSourceResolution::Resolved { readback } => {
                Self::classify_readback(self, source, readback)
            }
        }
    }

    fn classify_readback(
        projection: &ProcessStreamRecoveryProjection,
        source: &DurableProcessStreamSource,
        readback: ProcessStreamSourceReadback,
    ) -> ProcessStreamRecoveryRevalidation {
        if readback.locator != source.locator() {
            return ProcessStreamRecoveryRevalidation::unavailable(
                StreamRecoverySourceFault::ResolverBindingMismatch,
            );
        }
        if readback.ready_receipt_ref != source.ready_receipt_ref() {
            return ProcessStreamRecoveryRevalidation::unavailable(
                StreamRecoverySourceFault::ReceiptMismatch,
            );
        }
        if readback.sha256 != source.sha256() || readback.byte_length != source.byte_length() {
            return ProcessStreamRecoveryRevalidation::unavailable(
                StreamRecoverySourceFault::SourceCorrupt,
            );
        }
        if let Some(coverage) = &projection.durable_coverage
            && (coverage.sha256 != readback.sha256
                || coverage.byte_length != readback.byte_length
                || coverage.range.start() != 0
                || coverage.range.end_exclusive() != readback.byte_length)
        {
            return ProcessStreamRecoveryRevalidation::unavailable(
                StreamRecoverySourceFault::CoverageMismatch,
            );
        }
        ProcessStreamRecoveryRevalidation::Revalidated {
            availability: StreamRecoveryAvailability::Revalidated,
            readback,
        }
    }
}

/// Outcome of revalidating one projection against the immutable source.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", tag = "outcome")]
pub enum ProcessStreamRecoveryRevalidation {
    /// The durable source was re-read and matches the recorded identity.
    Revalidated {
        /// Availability observation to persist.
        availability: StreamRecoveryAvailability,
        /// Exact content identity that was read back.
        readback: ProcessStreamSourceReadback,
    },
    /// The durable source is unusable; the prior typed state is preserved.
    SourceUnavailable {
        /// Availability observation to persist.
        availability: StreamRecoveryAvailability,
    },
    /// A stale dimension fails closed for dependent reconciliation.
    Refused(ProcessStreamRecoveryRefusal),
    /// The projection retains no durable source, so there is nothing to
    /// revalidate. Its typed `SOURCE_UNAVAILABLE` state stands unchanged.
    NoDurableSource,
}

impl ProcessStreamRecoveryRevalidation {
    fn unavailable(fault: StreamRecoverySourceFault) -> Self {
        Self::SourceUnavailable {
            availability: StreamRecoveryAvailability::Unavailable { fault },
        }
    }

    /// The availability observation to persist, when the revalidation produced
    /// one. A refusal or a source-free projection produces no observation, so
    /// there is nothing to write and nothing to promote.
    pub fn availability(&self) -> Option<StreamRecoveryAvailability> {
        match self {
            Self::Revalidated { availability, .. } | Self::SourceUnavailable { availability } => {
                Some(*availability)
            }
            Self::Refused(_) | Self::NoDurableSource => None,
        }
    }
}

/// Proof that an operation reached terminal disposition and that its evidence
/// handoff was proven by readback.
///
/// Retirement requires all of it; none of it can be inferred from the
/// projection alone.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessStreamRetirementProof {
    /// Reservation that owns the operation in the owning operation contract.
    pub reservation_id: OperationIdentity,
    /// Terminal receipt the operation contract durably recorded.
    pub terminal_receipt_id: OpaqueLabel,
    /// Digest of the proven evidence handoff/readback.
    pub handoff_sha256: String,
    /// Recovery owner the operation contract named.
    pub recovery_owner: RecoveryOwner,
}

impl ProcessStreamRetirementProof {
    pub(crate) fn validate(&self) -> Result<(), OrsError> {
        validate_text(
            self.reservation_id.as_str(),
            "stream_recovery_proof_reservation_id",
        )?;
        validate_text(
            self.terminal_receipt_id.as_str(),
            "stream_recovery_proof_terminal_receipt_id",
        )?;
        validate_text(
            self.recovery_owner.as_str(),
            "stream_recovery_proof_recovery_owner",
        )?;
        validate_digest(&self.handoff_sha256, "stream_recovery_proof_handoff_sha256")
    }
}

/// Outcome of one durable write of a recovery projection.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ProcessStreamRecoveryWriteOutcome {
    /// First durable row for this `(operation, stream)` identity.
    Inserted,
    /// The identical row was re-presented; no durable write happened.
    Unchanged,
    /// Only availability, reconciliation or activation advanced. The evidence
    /// axes were proven byte-identical, so no evidence was rewritten.
    Advanced,
}

/// Explicit recovery disposition for an unreadable or version-mismatched row.
///
/// The variant is the disposition: an interrupted read and a codec-version
/// mismatch stay distinguishable, and neither is silently repaired, upgraded or
/// deleted.
#[derive(Debug, Error)]
pub enum ProcessStreamRecoveryLoadError {
    /// The row was written by a different ORS codec contract.
    #[error(
        "process-stream recovery codec version {found} is not the current ORS contract {current}"
    )]
    CodecVersionMismatch {
        /// Contract version found in the durable row.
        found: u16,
        /// Contract version this ORS build accepts.
        current: u16,
    },
    /// The row could not be decoded or failed fail-closed validation.
    #[error("process-stream recovery row could not be read: {reason}")]
    InterruptedRead {
        /// Diagnostic detail. It is not a state; the variant is.
        reason: String,
    },
}

impl From<ProcessStreamRecoveryLoadError> for OrsError {
    fn from(error: ProcessStreamRecoveryLoadError) -> Self {
        OrsError::IntegrityProblem {
            record_type: "process_stream_recovery",
            reason: error.to_string(),
        }
    }
}
