//! Closed wire shape for an owner-observed task stop boundary.
//!
//! These values carry claims and references across the protocol boundary. Shape
//! validation does not authenticate a producer, session, occurrence, current
//! admission revision, or page owner. A deserialized or shape-valid record is
//! never a trusted stop receipt and cannot authorize a state transition or
//! produce a Finish decision or proof. Existing Kernel/ORS and canonical owners
//! must authenticate and durably publish the boundary before relying on it.
//!
//! Source bytes are represented only by [`OpaqueContentRef`]. The referenced
//! artifact must be stored and read through its existing restricted owner; this
//! contract cannot validate that restriction. That ownership requirement is
//! therefore not established by this module.

use std::collections::BTreeSet;

use eliot_contracts::{ClockReading, OperationId, StateFence, TaskId, canonical_json_bytes};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{MAX_FRAME_BYTES, OpaqueContentRef, ProtocolError};

pub use eliot_contracts::StopBoundaryAdmissionBinding;

/// Stable identity for one stop-boundary wire record.
pub const STOP_BOUNDARY_RECORD_WIRE_ID: &str = "eliot.protocol.stop-boundary-record";
/// Current stop-boundary record wire version.
pub const STOP_BOUNDARY_RECORD_WIRE_VERSION: u16 = 1;

fn text(value: &str, field: &'static str) -> Result<(), ProtocolError> {
    if value.is_empty() || value.trim() != value {
        return Err(ProtocolError::InvalidField {
            field,
            reason: "must be non-blank without surrounding whitespace",
        });
    }
    if value.chars().any(char::is_control) {
        return Err(ProtocolError::InvalidField {
            field,
            reason: "must not contain control characters",
        });
    }
    Ok(())
}

fn content_ref(value: &OpaqueContentRef, field: &'static str) -> Result<(), ProtocolError> {
    value
        .validate(field)
        .map_err(|_| ProtocolError::InvalidField {
            field,
            reason: "existing opaque artifact reference failed shape validation",
        })
}

/// Claimed source identity attached by the observing owner.
///
/// These fields preserve the claimed channel, producer and authenticated
/// session/generation binding. They remain untrusted protocol data until the
/// existing ingress owner checks them against the live authenticated session.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct StopBoundarySourceBinding {
    /// Source channel identifier supplied by its owner.
    pub channel_id: String,
    /// Producer identity supplied by its owner.
    pub producer_id: String,
    /// Session identity supplied by its owner.
    pub session_id: String,
    /// Session generation supplied by its owner, or its explicit unknown state.
    pub generation: StopBoundaryGeneration,
}

impl StopBoundarySourceBinding {
    fn validate_shape(&self) -> Result<(), ProtocolError> {
        text(&self.channel_id, "stop_boundary.source.channel_id")?;
        text(&self.producer_id, "stop_boundary.source.producer_id")?;
        text(&self.session_id, "stop_boundary.source.session_id")?;
        Ok(())
    }
}

/// Session generation can be unknown without being rewritten as a sentinel.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(
    tag = "state",
    rename_all = "SCREAMING_SNAKE_CASE",
    deny_unknown_fields
)]
pub enum StopBoundaryGeneration {
    /// Exact generation reported by the session owner.
    Observed { generation: u64 },
    /// The generation could not be established.
    Unknown {
        reason: StopBoundaryGenerationUnknownReason,
    },
}

/// Why the session generation could not be established.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum StopBoundaryGenerationUnknownReason {
    SessionOwnerUnavailable,
    OwnerDidNotReport,
}

/// Cursor at the source observation cut, with absence and unknown kept distinct.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(
    tag = "state",
    rename_all = "SCREAMING_SNAKE_CASE",
    deny_unknown_fields
)]
pub enum StopBoundaryCursorState {
    Observed {
        cursor: StopBoundarySourceCursor,
    },
    NoCursorObserved,
    Unknown {
        reason: StopBoundaryCursorUnknownReason,
    },
}

/// Why the source cursor could not be established.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum StopBoundaryCursorUnknownReason {
    SourceUnavailable,
    OwnerDidNotReport,
    CursorCoverageGap,
}

impl StopBoundaryCursorState {
    fn validate_shape(&self) -> Result<(), ProtocolError> {
        if let Self::Observed { cursor } = self {
            cursor.validate_shape()?;
        }
        Ok(())
    }
}

/// Owner-supplied cursor at the source observation cut.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct StopBoundarySourceCursor {
    /// Source stream identity.
    pub stream_id: String,
    /// Opaque cursor value in the source's own cursor domain.
    pub position: String,
}

impl StopBoundarySourceCursor {
    fn validate_shape(&self) -> Result<(), ProtocolError> {
        text(&self.stream_id, "stop_boundary.source_cursor.stream_id")?;
        text(&self.position, "stop_boundary.source_cursor.position")
    }
}

/// Position of one event in a source stream.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct StopBoundaryEventPosition {
    /// Source stream identity.
    pub stream_id: String,
    /// One-based source sequence, following the existing host-event contract.
    pub sequence: u64,
}

impl StopBoundaryEventPosition {
    fn validate_shape(&self, field: &'static str) -> Result<(), ProtocolError> {
        text(&self.stream_id, field)?;
        if self.sequence == 0 {
            return Err(ProtocolError::InvalidField {
                field,
                reason: "known event positions use a nonzero source sequence",
            });
        }
        Ok(())
    }
}

/// Whether a last event position was observed, absent, or remains unknown.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(
    tag = "state",
    rename_all = "SCREAMING_SNAKE_CASE",
    deny_unknown_fields
)]
pub enum StopBoundaryPositionState {
    /// An exact event position was observed.
    Observed {
        /// Exact position in the relevant source stream.
        position: StopBoundaryEventPosition,
    },
    /// The owner observed that no event had reached this stage.
    NoPositionObserved,
    /// The position could not be established; this does not mean zero.
    Unknown {
        /// Closed reason for the unresolved position.
        reason: StopBoundaryPositionUnknownReason,
    },
}

impl StopBoundaryPositionState {
    fn validate_shape(&self, field: &'static str) -> Result<(), ProtocolError> {
        if let Self::Observed { position } = self {
            position.validate_shape(field)?;
        }
        Ok(())
    }
}

/// Why a last event position is unknown.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum StopBoundaryPositionUnknownReason {
    SourceUnavailable,
    NormalizationFailed,
    CoverageGap,
    OwnerDidNotReport,
}

/// Last positions at the durable, normalized, and applied stages.
///
/// Each field is independent. In particular, normalization failure has no
/// normalized event position; a prior applied position is preserved as-is.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct StopBoundaryEventPositions {
    /// Latest durably retained source event position.
    pub last_durable: StopBoundaryPositionState,
    /// Latest event position successfully normalized.
    pub last_normalized: StopBoundaryPositionState,
    /// Latest event position applied to canonical state.
    pub last_applied: StopBoundaryPositionState,
}

impl StopBoundaryEventPositions {
    fn validate_shape(&self) -> Result<(), ProtocolError> {
        self.last_durable
            .validate_shape("stop_boundary.event_positions.last_durable")?;
        self.last_normalized
            .validate_shape("stop_boundary.event_positions.last_normalized")?;
        self.last_applied
            .validate_shape("stop_boundary.event_positions.last_applied")
    }
}

/// Effect disposition reported for one exact operation or admitted descendant.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum StopBoundaryEffectDisposition {
    ObservedCompleted,
    ObservedNoEffect,
    PossibleExternalEffect,
    CleanupFailed,
    Unknown,
}

/// One operation in the boundary's observed or unknown in-flight set.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct StopBoundaryOperation {
    /// Stable operation identity supplied by its owner.
    pub operation_id: OperationId,
    /// Owner-observed or unknown effect disposition.
    pub effect: StopBoundaryEffectDisposition,
}

/// One admitted descendant attempt in the boundary's observed or unknown set.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct StopBoundaryDescendant {
    /// Stable admitted attempt identity supplied by its owner.
    pub attempt_id: String,
    /// Exact parent operation when the owner has identified one.
    pub parent_operation_id: Option<OperationId>,
    /// Owner-observed or unknown effect disposition.
    pub effect: StopBoundaryEffectDisposition,
}

/// Why an operation or descendant enumeration is incomplete.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum StopBoundaryCoverageGap {
    OwnerEnumerationIncomplete,
    RetainedPageUnavailable,
    SourceCoverageGap,
    UnknownDescendants,
}

/// Why restricted source content is absent from the boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum StopBoundarySourceContentAbsence {
    NoSensitiveContentProduced,
}

/// Why restricted source content is unavailable or its retention is unknown.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum StopBoundarySourceContentUnknownReason {
    SourceUnavailable,
    RetentionUnavailable,
}

/// Restricted source content is referenced opaquely or explicitly absent.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(
    tag = "state",
    rename_all = "SCREAMING_SNAKE_CASE",
    deny_unknown_fields
)]
pub enum StopBoundarySourceContent {
    Retained {
        reference: OpaqueContentRef,
    },
    Absent {
        reason: StopBoundarySourceContentAbsence,
    },
    Unknown {
        reason: StopBoundarySourceContentUnknownReason,
    },
}

impl StopBoundarySourceContent {
    fn validate_shape(&self) -> Result<(), ProtocolError> {
        if let Self::Retained { reference } = self {
            content_ref(reference, "stop_boundary.source_content.reference")?;
        }
        Ok(())
    }
}

/// Completeness claim for a bounded operation or descendant list.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(
    tag = "state",
    rename_all = "SCREAMING_SNAKE_CASE",
    deny_unknown_fields
)]
pub enum StopBoundaryEnumeration {
    /// The inline items are the complete enumeration.
    CompleteInline,
    /// Immutable retained pages hold the complete enumeration.
    CompletePaged,
    /// The enumeration is incomplete; the gap remains explicit.
    Incomplete {
        /// Known reason for the missing coverage.
        gap: StopBoundaryCoverageGap,
    },
}

/// One immutable page reference and owner-reported item count.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct StopBoundaryPageRef {
    /// Opaque immutable artifact reference to the retained page.
    pub content: OpaqueContentRef,
    /// Number of page members reported by the page owner.
    pub item_count: u64,
}

impl StopBoundaryPageRef {
    fn validate_shape(&self) -> Result<(), ProtocolError> {
        content_ref(&self.content, "stop_boundary.coverage_page.content")?;
        if self.item_count == 0 {
            return Err(ProtocolError::InvalidField {
                field: "stop_boundary.coverage_page.item_count",
                reason: "a retained page must report at least one member",
            });
        }
        Ok(())
    }
}

/// Bounded enumeration of exact owner identities and optional retained pages.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct StopBoundaryCoverage<T> {
    /// Exact entries carried inline.
    pub items: Vec<T>,
    /// Immutable pages retained by the existing artifact owner.
    pub pages: Vec<StopBoundaryPageRef>,
    /// Explicitly states whether inline/page coverage is complete.
    pub enumeration: StopBoundaryEnumeration,
}

impl<T> StopBoundaryCoverage<T> {
    fn validate_pages(&self) -> Result<(), ProtocolError> {
        let mut seen = BTreeSet::new();
        for page in &self.pages {
            page.validate_shape()?;
            if !seen.insert(page.content.sha256.as_str()) {
                return Err(ProtocolError::InvalidField {
                    field: "stop_boundary.coverage.pages",
                    reason: "must not repeat an immutable page digest",
                });
            }
        }
        match &self.enumeration {
            StopBoundaryEnumeration::CompleteInline if !self.pages.is_empty() => {
                Err(ProtocolError::InvalidField {
                    field: "stop_boundary.coverage.pages",
                    reason: "complete inline coverage cannot also claim retained pages",
                })
            }
            StopBoundaryEnumeration::CompletePaged
                if !self.items.is_empty() || self.pages.is_empty() =>
            {
                Err(ProtocolError::InvalidField {
                    field: "stop_boundary.coverage",
                    reason: "complete paged coverage requires page references and no inline items",
                })
            }
            _ => Ok(()),
        }
    }
}

/// Required follow-up action; this is not a task outcome.
#[derive(
    Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum StopBoundaryRequiredAction {
    Checkpoint,
    Reconcile,
    SubmitTypedFinishRequest,
}

/// Whether the required follow-up action enumeration is complete.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum StopBoundaryActionCoverage {
    Complete,
    Unknown,
}

/// Required follow-up actions, separately from terminal task outcomes.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct StopBoundaryActionPlan {
    /// Actions required by the observing owner; empty means none when complete.
    pub required_actions: Vec<StopBoundaryRequiredAction>,
    /// Unknown coverage is not equivalent to an empty action set.
    pub coverage: StopBoundaryActionCoverage,
}

/// Closed stop-boundary envelope carried by the shared protocol.
///
/// `validate_shape` checks only field shape and internal coherence. A valid
/// JSON object can still be forged, stale, foreign, unobserved, or backed by
/// an unavailable artifact; only the existing authenticated owners can prove
/// occurrence, binding currency, page retention, admission fencing, and
/// durable publication.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct StopBoundaryRecord {
    /// Must equal [`STOP_BOUNDARY_RECORD_WIRE_ID`].
    pub wire_id: String,
    /// Must equal [`STOP_BOUNDARY_RECORD_WIRE_VERSION`].
    pub wire_version: u16,
    /// Stable identity allocated by the existing observing owner.
    pub stop_id: String,
    /// Owner-observed time and available clock readings.
    pub observed_at: ClockReading,
    /// Owner-supplied identity of the clock domain used for this observation.
    pub clock_domain: String,
    /// Claimed source channel, producer, authenticated session, and generation.
    pub source: StopBoundarySourceBinding,
    /// Exact task, attempt, admission revision, and State Fence being stopped.
    pub task_id: TaskId,
    /// Attempt identity supplied by the admission owner.
    pub attempt_id: String,
    /// Expected admission revision supplied by its owner; never inferred from `TaskRevision`.
    pub expected_admission_revision: String,
    /// Exact State Fence supplied by the admission owner.
    pub state_fence: StateFence,
    /// Independently owner-issued semantic admission/attempt association.
    pub admission_binding: StopBoundaryAdmissionBinding,
    /// Owner-supplied cursor at the source observation cut.
    pub source_cursor: StopBoundaryCursorState,
    /// All known in-flight operations plus explicit enumeration coverage.
    pub operations: StopBoundaryCoverage<StopBoundaryOperation>,
    /// All known admitted descendants plus explicit enumeration coverage.
    pub descendants: StopBoundaryCoverage<StopBoundaryDescendant>,
    /// Independent event positions at each processing stage.
    pub event_positions: StopBoundaryEventPositions,
    /// Required follow-up actions with explicit enumeration coverage.
    pub action_plan: StopBoundaryActionPlan,
    /// Opaque reference to restricted source content or its explicit absence.
    pub source_content: StopBoundarySourceContent,
}

impl StopBoundaryRecord {
    /// Validates the closed wire shape and local field relationships only.
    ///
    /// This method does not authenticate the source claims, establish that an
    /// event occurred, check whether the admission revision is current, prove
    /// coverage/page availability, persist a stop, fence admission, or decide
    /// task completion.
    pub fn validate_shape(&self) -> Result<(), ProtocolError> {
        if self.wire_id != STOP_BOUNDARY_RECORD_WIRE_ID
            || self.wire_version != STOP_BOUNDARY_RECORD_WIRE_VERSION
        {
            return Err(ProtocolError::InvalidField {
                field: "stop_boundary.wire",
                reason: "unsupported stop-boundary record",
            });
        }
        text(&self.stop_id, "stop_boundary.stop_id")?;
        self.observed_at.validate()?;
        text(&self.clock_domain, "stop_boundary.clock_domain")?;
        self.source.validate_shape()?;
        text(&self.attempt_id, "stop_boundary.attempt_id")?;
        text(
            &self.expected_admission_revision,
            "stop_boundary.expected_admission_revision",
        )?;
        self.state_fence.validate()?;
        self.admission_binding
            .validate()
            .map_err(|_| ProtocolError::InvalidField {
                field: "stop_boundary.admission_binding",
                reason: "owner-issued admission association failed shape validation",
            })?;
        if self.admission_binding.task_id != self.task_id
            || self.admission_binding.attempt_id != self.attempt_id
            || self.admission_binding.state_fence != self.state_fence
            || self.expected_admission_revision
                != self.admission_binding.admission_owner_revision.to_string()
        {
            return Err(ProtocolError::InvalidField {
                field: "stop_boundary.admission_binding",
                reason: "must match the record task, attempt, exact fence, and admission revision",
            });
        }
        self.source_cursor.validate_shape()?;
        self.operations.validate_pages()?;
        self.descendants.validate_pages()?;
        self.event_positions.validate_shape()?;
        self.source_content.validate_shape()?;
        let action_set: BTreeSet<_> = self.action_plan.required_actions.iter().collect();
        if action_set.len() != self.action_plan.required_actions.len() {
            return Err(ProtocolError::InvalidField {
                field: "stop_boundary.action_plan.required_actions",
                reason: "must not repeat a required action",
            });
        }
        self.validate_operation_ids()?;
        self.validate_descendant_ids()?;
        self.validate_frame_size()
    }

    fn validate_operation_ids(&self) -> Result<(), ProtocolError> {
        let mut operation_ids = BTreeSet::new();
        for operation in &self.operations.items {
            if !operation_ids.insert(operation.operation_id.as_str()) {
                return Err(ProtocolError::InvalidField {
                    field: "stop_boundary.operations.items.operation_id",
                    reason: "must not repeat an operation",
                });
            }
        }
        Ok(())
    }

    fn validate_descendant_ids(&self) -> Result<(), ProtocolError> {
        let mut attempt_ids = BTreeSet::new();
        for descendant in &self.descendants.items {
            text(
                &descendant.attempt_id,
                "stop_boundary.descendants.items.attempt_id",
            )?;
            if !attempt_ids.insert(descendant.attempt_id.as_str()) {
                return Err(ProtocolError::InvalidField {
                    field: "stop_boundary.descendants.items.attempt_id",
                    reason: "must not repeat a descendant attempt",
                });
            }
        }
        Ok(())
    }

    fn validate_frame_size(&self) -> Result<(), ProtocolError> {
        let value =
            serde_json::to_value(self).map_err(|error| ProtocolError::Json(error.to_string()))?;
        let encoded =
            canonical_json_bytes(&value).map_err(|error| ProtocolError::Json(error.to_string()))?;
        if encoded.len() > MAX_FRAME_BYTES {
            return Err(ProtocolError::OversizeFrame {
                actual: encoded.len(),
                maximum: MAX_FRAME_BYTES,
            });
        }
        Ok(())
    }
}
