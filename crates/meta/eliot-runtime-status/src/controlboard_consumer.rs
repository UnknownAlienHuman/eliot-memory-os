//! Operator-adjacent live read path over the `read_controlboard_contour` projection.
//!
//! Issue #1213 follow-through: this module binds the
//! [`read_controlboard_contour`](super::read_controlboard_contour) projection to
//! real consumption. It performs exactly one board effect — the authenticated
//! [`ControlBoard::view`](eliot_controlboard::ControlBoard::view) read owned by
//! the projection — then reconciles the resulting contour against a
//! caller-frozen expected-row denominator.
//!
//! Read-only enforcement (structural, not prose):
//!
//! * [`render_controlboard_status`] takes `&ControlBoardContour` only; it cannot
//!   touch a board handle, a port, or a command path.
//! * [`read_controlboard_status`] takes `&mut ControlBoard` but calls exactly
//!   one function — `read_controlboard_contour` — which itself performs only
//!   `ControlBoard::view`. No command construction, port access, or submit path
//!   is in scope.
//!
//! Denominator: [`ControlBoardExpectedSet`] is frozen at construction (sorted,
//! deduplicated, immutable). [`render_controlboard_status`] emits exactly one
//! [`RenderedControlBoardRow`] per expected entry, in frozen order. An expected
//! entry absent from the contour renders
//! [`ControlBoardRowDisposition::Missing`]; it can never disappear. Observed
//! view entries outside the denominator are preserved verbatim in
//! [`RenderedControlBoard::unexpected_observed`] instead of being dropped.
//!
//! Dispositions: every row carries exactly one
//! [`ControlBoardRowDisposition`]. Observed rows default to `Unknown` — a
//! projected view proves nothing about liveness, readiness, support, or product
//! state — unless the operator supplies an explicit typed override selected
//! from independent evidence. Overrides never apply to unobserved rows: an
//! absent entry is always `Missing`, never resurrected by an override. There is
//! intentionally no health predicate: no method here reports green, ready, or
//! healthy, and disposition labels never collapse to a color or scalar.
//! Dispositions are observation states only; they are never copied into
//! implementation support, maturity, or evidence-execution claims
//! (Implementation I0.5).
//!
//! Independent axes: the rendered board carries the observation disposition per
//! row and the owner's I0.5 evidence records at board level —
//! [`SupportObservationState`] for transport reachability,
//! [`EvidenceExecutionStatus`] for evidence execution, the five
//! [`DomainCoverage`] rows, and the [`CapabilitySupportRow`] set — reproduced
//! verbatim from the contour. A disposition is never derived from them and they
//! are never derived from a disposition, so transport reachability can never
//! become semantic readiness and an observation can never become support.
//!
//! Typed fields: every rendered row stamps the four observer-supplied typed
//! bindings ([`ControlBoardInstallation`], [`ControlBoardObservationTime`],
//! [`ControlBoardSourceDigest`], [`ControlBoardRecoveryOwner`]) plus the
//! projection-owned typed identities (`view_revision: u64`,
//! `view_fence: StateFence`, `contour_digest`). Every observed row additionally
//! carries the projected row's capability, canonical owner, generation, and
//! evidence handle as typed bindings reproduced verbatim
//! ([`ControlBoardCapability`], [`ControlBoardOwner`],
//! [`ControlBoardGeneration`], [`ControlBoardEvidenceHandle`]). The expiry and
//! invalidation bindings are rendered once at [`RenderedControlBoard`],
//! because the contour states one expiry and one invalidation for the whole
//! board rather than one per row. No caller-opaque string stands in
//! for a value the projection owns.
//!
//! The per-row projection bindings are never reduced to a summary: the
//! layer crossing carries the whole projected [`ControlBoardStatusRow`], so an
//! observed row keeps every identity the projection bound. An unobserved row
//! binds no capability, owner, generation, or evidence handle, so those
//! bindings are `None` — the row was not observed, which is never reported as
//! an unknown or empty value. No capability, owner, generation, or evidence
//! handle is ever inferred or filled in.
//!
//! Secret handling: rendered rows carry no session, credential, challenge,
//! access-digest, token, or nonce fields by construction. The inert
//! `ReadRequest` fields are never copied into the rendered board.
//!
//! Bounds (consumer-side allocation guards, fail-closed): at most
//! [`MAX_CONSUMER_ROWS`] expected entries; typed text fields at most
//! [`MAX_TYPED_CHARS`] characters.

use std::collections::BTreeMap;

use eliot_conformance_contracts::{
    CapabilitySupportRow, DomainCoverage, EvidenceExecutionStatus, SupportObservationState,
};
use eliot_contracts::StateFence;
use eliot_controlboard::{
    AnchorResolution, AnchorTargetKind, Attribution, ControlBoard, NotificationInbox, ReadRequest,
    ReviewLifecycle,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::controlboard_projection::{
    ControlBoardContour, ControlBoardProjectionBindings, ControlBoardReviewDetail,
    ControlBoardStatusRow, ReviewCorrectionAction, ReviewProvenanceDirection, accepted_disposition,
    read_code_provenance, read_controlboard_contour, read_review_batch_status, read_review_detail,
};

/// Stable contract identity for this read-only consumer rendering.
pub const CONTROLBOARD_CONSUMER_CONTRACT: &str = "eliot.runtime-status.controlboard-consumer/v2";

/// Maximum expected entries in one frozen denominator (allocation guard,
/// fail-closed; matches the projection-side row bound).
const MAX_CONSUMER_ROWS: usize = 2048;
/// Maximum characters per observer-supplied typed text field.
const MAX_TYPED_CHARS: usize = 1024;
/// Exact characters of a lowercase/uppercase hex SHA-256 source digest.
const SOURCE_DIGEST_CHARS: usize = 64;

fn bound_text(value: &str, field: &'static str) -> Result<(), ControlBoardConsumerError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(ControlBoardConsumerError::InvalidBinding { field });
    }
    if value.chars().count() > MAX_TYPED_CHARS {
        return Err(ControlBoardConsumerError::Oversized { field });
    }
    Ok(())
}

/// Typed installation identity the read was performed against.
///
/// Shape-validated at construction and re-validated at render, so a
/// deserialized instance cannot bypass the guard.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ControlBoardInstallation(String);

impl ControlBoardInstallation {
    /// Binds one installation identity (non-empty, no control characters,
    /// bounded length).
    pub fn new(value: impl Into<String>) -> Result<Self, ControlBoardConsumerError> {
        let inner = value.into();
        bound_text(&inner, "installation")?;
        Ok(Self(inner))
    }

    /// Returns the bound installation identity text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn validate(&self) -> Result<(), ControlBoardConsumerError> {
        bound_text(&self.0, "installation")
    }
}

/// Typed observation time of the read, as Unix milliseconds.
///
/// A zero timestamp is rejected fail-closed: it is an uninitialized sentinel,
/// never a real observation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ControlBoardObservationTime(u64);

impl ControlBoardObservationTime {
    /// Binds one non-zero Unix-millisecond observation time.
    pub fn new(value: u64) -> Result<Self, ControlBoardConsumerError> {
        if value == 0 {
            return Err(ControlBoardConsumerError::InvalidObservationTime);
        }
        Ok(Self(value))
    }

    /// Returns the bound Unix-millisecond timestamp.
    #[must_use]
    pub fn get(self) -> u64 {
        self.0
    }

    fn validate(self) -> Result<(), ControlBoardConsumerError> {
        if self.0 == 0 {
            return Err(ControlBoardConsumerError::InvalidObservationTime);
        }
        Ok(())
    }
}

/// Typed SHA-256 source digest the read was projected from.
///
/// Exactly 64 ASCII hex characters; anything else is rejected fail-closed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ControlBoardSourceDigest(String);

impl ControlBoardSourceDigest {
    /// Binds one 64-character hex source digest.
    pub fn new(value: impl Into<String>) -> Result<Self, ControlBoardConsumerError> {
        let inner = value.into();
        if inner.len() != SOURCE_DIGEST_CHARS || !inner.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(ControlBoardConsumerError::InvalidSourceDigest);
        }
        Ok(Self(inner))
    }

    /// Returns the bound digest text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn validate(&self) -> Result<(), ControlBoardConsumerError> {
        if self.0.len() != SOURCE_DIGEST_CHARS
            || !self.0.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(ControlBoardConsumerError::InvalidSourceDigest);
        }
        Ok(())
    }
}

/// Typed recovery-owner handle responsible for the observed components.
///
/// Shape-validated at construction and re-validated at render, so a
/// deserialized instance cannot bypass the guard.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ControlBoardRecoveryOwner(String);

impl ControlBoardRecoveryOwner {
    /// Binds one recovery-owner handle (non-empty, no control characters,
    /// bounded length).
    pub fn new(value: impl Into<String>) -> Result<Self, ControlBoardConsumerError> {
        let inner = value.into();
        bound_text(&inner, "recovery_owner")?;
        Ok(Self(inner))
    }

    /// Returns the bound recovery-owner handle text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn validate(&self) -> Result<(), ControlBoardConsumerError> {
        bound_text(&self.0, "recovery_owner")
    }
}

/// Typed admitted read capability a projected row was read under.
///
/// Carried verbatim from the observed projection row; an unobserved row has
/// no capability and binds none.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ControlBoardCapability(String);

impl ControlBoardCapability {
    /// Binds one admitted read capability name (non-empty, no control
    /// characters, bounded length).
    pub fn new(value: impl Into<String>) -> Result<Self, ControlBoardConsumerError> {
        let inner = value.into();
        bound_text(&inner, "capability")?;
        Ok(Self(inner))
    }

    /// Returns the bound capability name text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Typed owner-issued generation a projected row was read at.
///
/// Carried verbatim from the observed projection row; an unobserved row was
/// read at no generation and binds none.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ControlBoardGeneration(String);

impl ControlBoardGeneration {
    /// Binds one owner-issued generation (non-empty, no control characters,
    /// bounded length).
    pub fn new(value: impl Into<String>) -> Result<Self, ControlBoardConsumerError> {
        let inner = value.into();
        bound_text(&inner, "generation")?;
        Ok(Self(inner))
    }

    /// Returns the bound generation text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Typed evidence handle a projected row was read against.
///
/// Carried verbatim from the observed projection row; an unobserved row was
/// read against no evidence handle and binds none.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ControlBoardEvidenceHandle(String);

impl ControlBoardEvidenceHandle {
    /// Binds one evidence handle (non-empty, no control characters, bounded
    /// length).
    pub fn new(value: impl Into<String>) -> Result<Self, ControlBoardConsumerError> {
        let inner = value.into();
        bound_text(&inner, "evidence")?;
        Ok(Self(inner))
    }

    /// Returns the bound evidence handle text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Typed canonical owner a projected row was read under.
///
/// Carried verbatim from the observed projection row; an unobserved row has no
/// canonical owner and binds none.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ControlBoardOwner(String);

impl ControlBoardOwner {
    /// Binds one canonical owner (non-empty, no control characters, bounded
    /// length).
    pub fn new(value: impl Into<String>) -> Result<Self, ControlBoardConsumerError> {
        let inner = value.into();
        bound_text(&inner, "owner")?;
        Ok(Self(inner))
    }

    /// Returns the bound canonical owner text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Observer-supplied typed context stamped on every rendered row.
///
/// All four bindings are required. They describe the exact read the rendering
/// was reconciled from; this module validates their shape and stamps them
/// verbatim. It never infers them from files, PIDs, ports, or manifests.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlBoardObservationContext {
    /// Installation the board was read against.
    pub installation: ControlBoardInstallation,
    /// When the underlying read was observed.
    pub observed_at: ControlBoardObservationTime,
    /// Source digest the contour was projected from.
    pub source_digest: ControlBoardSourceDigest,
    /// Owner responsible for recovery of the observed components.
    pub recovery_owner: ControlBoardRecoveryOwner,
}

impl ControlBoardObservationContext {
    /// Re-validates all four bindings; called on every render so deserialized
    /// contexts cannot bypass construction guards.
    pub fn validate(&self) -> Result<(), ControlBoardConsumerError> {
        self.installation.validate()?;
        self.observed_at.validate()?;
        self.source_digest.validate()?;
        self.recovery_owner.validate()?;
        Ok(())
    }
}

/// Frozen caller-supplied expected-row denominator.
///
/// Entries are validated for shape, deduplicated, sorted, and then immutable:
/// the denominator cannot drift between construction and render. An empty
/// denominator is rejected — composition must name at least one expected row.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ControlBoardExpectedSet {
    entries: Vec<String>,
}

impl ControlBoardExpectedSet {
    /// Freezes one denominator from caller-supplied entry identities.
    pub fn new(mut ids: Vec<String>) -> Result<Self, ControlBoardConsumerError> {
        if ids.is_empty() {
            return Err(ControlBoardConsumerError::EmptyExpectedSet);
        }
        if ids.len() > MAX_CONSUMER_ROWS {
            return Err(ControlBoardConsumerError::Oversized {
                field: "expected_set",
            });
        }
        for id in &ids {
            bound_text(id, "expected_set.entry_id")?;
        }
        ids.sort();
        if let Some(duplicate) = ids.windows(2).find_map(|pair| {
            if pair[0] == pair[1] {
                Some(pair[0].clone())
            } else {
                None
            }
        }) {
            return Err(ControlBoardConsumerError::DuplicateExpectedId {
                entry_id: duplicate,
            });
        }
        Ok(Self { entries: ids })
    }

    /// Returns the frozen entries in render order.
    #[must_use]
    pub fn entries(&self) -> &[String] {
        &self.entries
    }

    /// Returns the frozen denominator size.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Reports whether the frozen denominator is empty (always false:
    /// construction rejects empty denominators; provided for API symmetry).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Returns whether the identity belongs to the frozen denominator.
    #[must_use]
    pub fn contains(&self, entry_id: &str) -> bool {
        self.entries.binary_search(&entry_id.to_owned()).is_ok()
    }
}

/// Typed per-row observation disposition.
///
/// The seven #1213 observation states plus `Missing` for expected-but-
/// unobserved rows. Every variant renders to a distinct non-green label; no
/// variant implies health, readiness, support, or product state. These are
/// observation states only and are never copied into `ImplementationSupport`,
/// maturity, or evidence-execution claims.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ControlBoardRowDisposition {
    /// Observed entry flagged stale by independent evidence.
    Stale,
    /// Observed entry reported unavailable by independent evidence.
    Unavailable,
    /// Observed entry reported not-running by independent evidence.
    NotRunning,
    /// Observed entry with contradictory independent observations.
    Conflicted,
    /// Observed entry with only partial independent evidence.
    Partial,
    /// Observed entry with no independent state evidence (default for rows
    /// this read actually observed; a view proves nothing further).
    Unknown,
    /// Observed entry reported unsupported by independent evidence.
    Unsupported,
    /// Expected entry absent from the contour (denominator gap). Always set
    /// by reconciliation, never by override.
    Missing,
}

impl ControlBoardRowDisposition {
    /// Renders the distinct non-green marker for this disposition.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Stale => "STALE",
            Self::Unavailable => "UNAVAILABLE",
            Self::NotRunning => "NOT_RUNNING",
            Self::Conflicted => "CONFLICTED",
            Self::Partial => "PARTIAL",
            Self::Unknown => "UNKNOWN",
            Self::Unsupported => "UNSUPPORTED",
            Self::Missing => "MISSING",
        }
    }

    /// Reports denominator presence only: false for `Missing`, true otherwise.
    /// This reports whether the row was observed, never whether it is healthy.
    #[must_use]
    pub fn was_observed(self) -> bool {
        !matches!(self, Self::Missing)
    }
}

/// One reconciled row: exactly one expected entry with exactly one typed
/// disposition and the four observer-supplied typed bindings plus the
/// projection-owned typed identities.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RenderedControlBoardRow {
    /// Expected entry identity (board `item_id` or review `review_item_id`).
    pub entry_id: String,
    /// The single typed disposition for this row.
    pub disposition: ControlBoardRowDisposition,
    /// Entry summary/content reproduced 1:1 from the contour when observed;
    /// `None` for `Missing` rows (nothing was observed to reproduce).
    pub summary: Option<String>,
    /// Admitted read capability the observed row was projected under, carried
    /// verbatim from the projection row; `None` for `Missing` rows.
    pub capability: Option<ControlBoardCapability>,
    /// Canonical owner the observed row was projected under, carried verbatim
    /// from the projection row; `None` for `Missing` rows.
    pub owner: Option<ControlBoardOwner>,
    /// Owner-issued generation the observed row was projected at, carried
    /// verbatim from the projection row; `None` for `Missing` rows.
    pub generation: Option<ControlBoardGeneration>,
    /// Evidence handle the observed row was projected against, carried
    /// verbatim from the projection row; `None` for `Missing` rows.
    pub evidence_handle: Option<ControlBoardEvidenceHandle>,
    /// Stamped from the observer context installation.
    pub installation: ControlBoardInstallation,
    /// Stamped from the observer context observation time.
    pub observed_at: ControlBoardObservationTime,
    /// Stamped from the observer context source digest.
    pub source_digest: ControlBoardSourceDigest,
    /// Stamped from the observer context recovery owner.
    pub recovery_owner: ControlBoardRecoveryOwner,
    /// Exact board revision the contour was pinned to (projection-owned).
    pub view_revision: u64,
    /// Freshness binding over the exact projected bytes (projection-owned).
    pub contour_digest: String,
}

/// Read-only reconciled board: one row per frozen denominator entry, in
/// frozen order, with projection-owned identities bound verbatim.
///
/// `Eq` is intentionally absent: the owner records carried here
/// ([`DomainCoverage`], [`CapabilitySupportRow`]) are `PartialEq` only, and the
/// rendered board refuses to narrow them to a weaker equality contract.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RenderedControlBoard {
    /// Always [`CONTROLBOARD_CONSUMER_CONTRACT`].
    pub contract: String,
    /// Exact board revision the contour was pinned to (typed, never Debug text).
    pub view_revision: u64,
    /// Exact shared fence the contour was pinned to (typed, never Debug text).
    pub view_fence: StateFence,
    /// Freshness binding over the exact projected bytes (projection-owned).
    pub contour_digest: String,
    /// One row per frozen denominator entry, in frozen order.
    pub rows: Vec<RenderedControlBoardRow>,
    /// Canonical notification inbox section, preserved from the board view.
    pub notifications: NotificationInbox,
    /// Count of rows actually observed in the contour.
    pub observed_count: usize,
    /// Count of expected-but-unobserved rows.
    pub missing_count: usize,
    /// Observed contour entry identities outside the frozen denominator, in
    /// view order. Preserved verbatim so denominator drift cannot silently
    /// drop observations.
    pub unexpected_observed: Vec<String>,
    /// Transport reachability of the read edge, reproduced verbatim from the
    /// contour. Never inferred from a row or a disposition.
    pub transport: SupportObservationState,
    /// Evidence execution of the cited evidence, reproduced verbatim from the
    /// contour. Never recomputed from the support rows.
    pub evidence_execution: EvidenceExecutionStatus,
    /// The one evaluation boundary the owner declared for this validation unit.
    pub evaluated_at_ms: u64,
    /// Exactly one owner coverage record per declared evidence domain.
    pub domain_coverage: Vec<DomainCoverage>,
    /// Owner capability support rows, each keeping its own independent
    /// maturity, implementation-support and evidence-execution values.
    pub support_rows: Vec<CapabilitySupportRow>,
    /// Stamped from the contour expiry binding.
    pub expiry: String,
    /// Stamped from the contour invalidation binding.
    pub invalidation: String,
}

/// Fail-closed consumer failure. Any variant refuses the rendering instead of
/// reconciling partial or inferred evidence.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum ControlBoardConsumerError {
    /// A required binding field is empty or carries control characters.
    #[error("invalid controlboard consumer binding: {field}")]
    InvalidBinding {
        /// Binding field that failed shape validation.
        field: &'static str,
    },
    /// A value exceeds its consumer-side allocation bound.
    #[error("controlboard consumer value exceeds bound: {field}")]
    Oversized {
        /// Field that exceeded its bound.
        field: &'static str,
    },
    /// The frozen denominator names no expected row.
    #[error("controlboard consumer requires a non-empty expected set")]
    EmptyExpectedSet,
    /// Two expected entries share one identity.
    #[error("duplicate controlboard expected entry identity: {entry_id}")]
    DuplicateExpectedId {
        /// Colliding entry identity.
        entry_id: String,
    },
    /// An override names an entry outside the frozen denominator.
    #[error("controlboard disposition override outside denominator: {entry_id}")]
    OverrideOutsideDenominator {
        /// Override entry identity not present in the denominator.
        entry_id: String,
    },
    /// A review rendering was bound to a row for a different entry. The bind
    /// fails instead of displaying one review's detail on another row.
    #[error("review detail does not belong to this row: {entry_id} != {review_id}")]
    ReviewRowMismatch {
        /// Reconciled row entry identity.
        entry_id: String,
        /// Rendered review identity.
        review_id: String,
    },
    /// The observation time is the zero sentinel, never a real observation.
    #[error("controlboard consumer requires a non-zero observation time")]
    InvalidObservationTime,
    /// The source digest is not 64 ASCII hex characters.
    #[error("controlboard consumer requires a 64-character hex source digest")]
    InvalidSourceDigest,
    /// The underlying authenticated projection read failed; no board exists.
    #[error("controlboard projection failed: {detail}")]
    ProjectionFailed {
        /// Underlying projection failure detail (diagnostic only).
        detail: String,
    },
}

/// One reconciled row: exactly one entry identity, exactly one typed
/// disposition, and the four observer bindings plus the projection identities.
///
/// An unobserved row was never projected under a capability, at a generation,
/// or against an evidence handle, so those bindings are `None` — because
/// nothing was observed, never because the value is unknown or empty. Nothing
/// here is inferred, defaulted, or filled in.
fn rendered_row(
    entry_id: &str,
    observed: Option<&ControlBoardStatusRow>,
    disposition: ControlBoardRowDisposition,
    context: &ControlBoardObservationContext,
    contour: &ControlBoardContour,
) -> Result<RenderedControlBoardRow, ControlBoardConsumerError> {
    let (summary, capability, owner, generation, evidence_handle) = match observed {
        Some(row) => (
            Some(row.summary.clone()),
            Some(ControlBoardCapability::new(row.capability.clone())?),
            Some(ControlBoardOwner::new(row.owner.clone())?),
            Some(ControlBoardGeneration::new(row.generation.clone())?),
            Some(ControlBoardEvidenceHandle::new(row.evidence.clone())?),
        ),
        None => (None, None, None, None, None),
    };
    Ok(RenderedControlBoardRow {
        entry_id: entry_id.to_owned(),
        disposition,
        summary,
        capability,
        owner,
        generation,
        evidence_handle,
        installation: context.installation.clone(),
        observed_at: context.observed_at,
        source_digest: context.source_digest.clone(),
        recovery_owner: context.recovery_owner.clone(),
        view_revision: contour.view_revision,
        contour_digest: contour.contour_digest.clone(),
    })
}

/// Reconciles one contour against the frozen denominator.
///
/// Every expected entry receives exactly one row in frozen order: observed
/// entries render the operator-supplied override disposition (or `Unknown`
/// when none was supplied); unobserved entries render `Missing` with no
/// summary. Observed contour entries outside the denominator are preserved in
/// `unexpected_observed`. Dispositions are never inferred from entry kinds or
/// summaries, and the board-level I0.5 axes are never derived from them.
pub fn render_controlboard_status(
    contour: &ControlBoardContour,
    context: &ControlBoardObservationContext,
    expected: &ControlBoardExpectedSet,
    overrides: &BTreeMap<String, ControlBoardRowDisposition>,
) -> Result<RenderedControlBoard, ControlBoardConsumerError> {
    context.validate()?;
    for key in overrides.keys() {
        if !expected.contains(key) {
            return Err(ControlBoardConsumerError::OverrideOutsideDenominator {
                entry_id: key.clone(),
            });
        }
    }
    let observed_by_id: BTreeMap<&str, &ControlBoardStatusRow> = contour
        .rows
        .iter()
        .map(|row| (row.entry_id.as_str(), row))
        .collect();
    let mut rows = Vec::with_capacity(expected.len());
    let mut observed_count = 0_usize;
    for entry_id in expected.entries() {
        let Some(observed) = observed_by_id.get(entry_id.as_str()).copied() else {
            let missing = rendered_row(
                entry_id,
                None,
                ControlBoardRowDisposition::Missing,
                context,
                contour,
            )?;
            rows.push(missing);
            continue;
        };
        observed_count = observed_count.saturating_add(1);
        let disposition = overrides
            .get(entry_id.as_str())
            .copied()
            .unwrap_or(ControlBoardRowDisposition::Unknown);
        rows.push(rendered_row(
            entry_id,
            Some(observed),
            disposition,
            context,
            contour,
        )?);
    }
    let mut unexpected_observed = Vec::new();
    for row in &contour.rows {
        if !expected.contains(&row.entry_id) {
            unexpected_observed.push(row.entry_id.clone());
        }
    }
    let missing_count = rows.len().saturating_sub(observed_count);
    Ok(RenderedControlBoard {
        contract: CONTROLBOARD_CONSUMER_CONTRACT.to_owned(),
        view_revision: contour.view_revision,
        view_fence: contour.view_fence.clone(),
        contour_digest: contour.contour_digest.clone(),
        rows,
        notifications: contour.notifications.clone(),
        observed_count,
        missing_count,
        unexpected_observed,
        transport: contour.transport,
        evidence_execution: contour.evidence_execution,
        evaluated_at_ms: contour.evaluated_at_ms,
        domain_coverage: contour.domain_coverage.clone(),
        support_rows: contour.support_rows.clone(),
        expiry: contour.expiry.clone(),
        invalidation: contour.invalidation.clone(),
    })
}

/// Reads one reconciled board through the real authenticated board read edge.
///
/// This is the single live consumer of
/// [`read_controlboard_contour`](super::read_controlboard_contour): it
/// performs exactly the projection-owned `ControlBoard::view` read, then
/// reconciles the contour against the frozen denominator. There is no command
/// construction, no port access, and no submit path in scope. Session, role,
/// and fence authority stay owned by the board's own resolver.
pub fn read_controlboard_status(
    board: &mut ControlBoard,
    request: &ReadRequest,
    bindings: &ControlBoardProjectionBindings,
    context: &ControlBoardObservationContext,
    expected: &ControlBoardExpectedSet,
    overrides: &BTreeMap<String, ControlBoardRowDisposition>,
) -> Result<RenderedControlBoard, ControlBoardConsumerError> {
    let contour = read_controlboard_contour(board, request, bindings).map_err(|error| {
        ControlBoardConsumerError::ProjectionFailed {
            detail: error.to_string(),
        }
    })?;
    render_controlboard_status(&contour, context, expected, overrides)
}

/// Stable contract identity for the native review-detail rendering.
///
/// The reconciled [`RenderedControlBoard`] keeps its contour-bound rows: the
/// historical target, current mapping, correction actions, and retained
/// history below travel only through this separately versioned rendering, so
/// status refreshes never grow graph bodies.
pub const CONTROLBOARD_REVIEW_RENDER_CONTRACT: &str =
    "eliot.runtime-status.controlboard-review-render/v1";

/// Authority scope stamped on every displayed correction action.
const CORRECTION_AUTHORITY_NOTE: &str = "lifecycle-permitted only; change authority is checked by the board submit path and is never granted by this rendering";

/// One lifecycle-permitted correction/disposition action, as displayed.
///
/// The action names the operator-action kind the board would accept from the
/// current lifecycle; it carries no session, capability, or authority, and
/// submitting it is outside this read-only renderer.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RenderedCorrectionAction {
    /// Operator-action kind (`AcknowledgeReview`, `AnswerReview`,
    /// `ResolveReview`, or `RejectReview`).
    pub action: String,
    /// Always [`CORRECTION_AUTHORITY_NOTE`].
    pub authority_note: String,
}

/// How the historical target maps to current code, as displayed.
///
/// A `Mapped` rendering names retained candidates; a `Failed` rendering keeps
/// the historical anchor visible and states the exact limitation. The
/// renderer never invents continuity, never attaches an ambiguous note to
/// one current fragment, and never redirects a deleted handle to current
/// code.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum RenderedReviewMapping {
    /// Retained candidate refs name at least one current target.
    Mapped {
        /// Current-target candidates, reproduced verbatim in retained order.
        candidates: Vec<String>,
    },
    /// No current target is established, or the original is gone.
    Failed {
        /// Claimed resolution label.
        resolution: String,
        /// Exact limitation; never fabricated target bytes.
        limitation: String,
    },
}

/// Native rendering of one review: historical target beside current mapping.
///
/// Retention lives with the coordination owner; this rendering holds no
/// cache and performs a fresh authenticated read per call, so unresolved
/// obligations re-render identically after restart, code movement, or source
/// unavailability from the retained records. Replay is `retained_history`:
/// the lifecycle plus candidate refs in retained order, never synthesized
/// text. No elapsed-time, speed, or quality scalar is carried anywhere here:
/// faster rendering or a lower note count cannot establish review quality
/// (I11.10).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RenderedReviewDetail {
    /// Always [`CONTROLBOARD_REVIEW_RENDER_CONTRACT`].
    pub contract: String,
    /// Rendered review identity.
    pub review_id: String,
    /// This item's own lifecycle, reproduced verbatim.
    pub lifecycle: ReviewLifecycle,
    /// True for an explicit terminal disposition, via the one shared rule.
    pub disposed: bool,
    /// Original anchor target-kind label.
    pub anchor_target_kind: String,
    /// Original anchor selector, exactly as submitted.
    pub anchor_selector: String,
    /// Original anchor revision; never rewritten by a later head.
    pub anchor_original_revision: u64,
    /// Current mapping or exact failure.
    pub current_mapping: RenderedReviewMapping,
    /// Lifecycle-permitted correction actions; permission only.
    pub correction_actions: Vec<RenderedCorrectionAction>,
    /// Retained history replay: lifecycle line plus candidate refs in
    /// retained order.
    pub retained_history: Vec<String>,
    /// Stamped from the observer context installation.
    pub installation: ControlBoardInstallation,
    /// Stamped from the observer context observation time.
    pub observed_at: ControlBoardObservationTime,
    /// Stamped from the observer context source digest.
    pub source_digest: ControlBoardSourceDigest,
    /// Stamped from the observer context recovery owner.
    pub recovery_owner: ControlBoardRecoveryOwner,
    /// Exact board revision the detail was read at (projection-owned).
    pub view_revision: u64,
    /// Exact shared fence the detail was read at (typed, never Debug text).
    pub view_fence: StateFence,
    /// Freshness binding over the exact detailed bytes (projection-owned).
    pub detail_digest: String,
}

/// Native rendering of the visible review batch summary.
///
/// Carries per-item delivery/disposition completeness (`total`,
/// `disposed_count`, `outstanding_ids`) for evaluation evidence; it carries
/// no timing or quality claim (I11.10). The denominator is the role-filtered
/// view stated in `coverage_note`, never the owner's separately recorded
/// expectation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RenderedReviewBatchSummary {
    /// Always [`CONTROLBOARD_REVIEW_RENDER_CONTRACT`].
    pub contract: String,
    /// Visible review count at this revision and fence.
    pub total: usize,
    /// Visible reviews carrying an accepted disposition.
    pub disposed_count: usize,
    /// Visible review identities still lacking an accepted disposition, in
    /// view order.
    pub outstanding_ids: Vec<String>,
    /// True only when every visible review carries an accepted disposition.
    pub complete: bool,
    /// Authorized coverage semantics, reproduced verbatim from the status.
    pub coverage_note: String,
    /// Stamped from the observer context installation.
    pub installation: ControlBoardInstallation,
    /// Stamped from the observer context observation time.
    pub observed_at: ControlBoardObservationTime,
    /// Stamped from the observer context source digest.
    pub source_digest: ControlBoardSourceDigest,
    /// Stamped from the observer context recovery owner.
    pub recovery_owner: ControlBoardRecoveryOwner,
    /// Exact board revision the status was read at (projection-owned).
    pub view_revision: u64,
    /// Exact shared fence the status was read at (typed, never Debug text).
    pub view_fence: StateFence,
    /// Freshness binding over the exact status bytes (projection-owned).
    pub status_digest: String,
}

/// One displayed provenance reference behind a code identity.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RenderedProvenanceRef {
    /// Retained edge identity.
    pub edge_id: String,
    /// The endpoint that is not the queried code identity.
    pub counterparty: String,
    /// Which side the queried identity stands on (`FROM_SUBJECT` or
    /// `TO_SUBJECT`).
    pub direction: String,
    /// Owner-recorded attribution label, reproduced verbatim.
    pub attribution: String,
    /// Recorded evidence handle, when the owner retained one.
    pub receipt_ref: Option<String>,
}

/// Native rendering of the reverse lookup from current code to its recorded
/// origins.
///
/// Every retained edge that names the code identity is displayed with its
/// attribution intact, so multiple origins stay multiple; gaps are displayed
/// verbatim when nothing names the identity.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RenderedCodeProvenance {
    /// Always [`CONTROLBOARD_REVIEW_RENDER_CONTRACT`].
    pub contract: String,
    /// Requested code identity, reproduced verbatim.
    pub code_id: String,
    /// Retained edges naming the identity, in view order.
    pub refs: Vec<RenderedProvenanceRef>,
    /// Missing coverage with reasons, reproduced verbatim.
    pub gaps: Vec<String>,
    /// Stamped from the observer context installation.
    pub installation: ControlBoardInstallation,
    /// Stamped from the observer context observation time.
    pub observed_at: ControlBoardObservationTime,
    /// Stamped from the observer context source digest.
    pub source_digest: ControlBoardSourceDigest,
    /// Stamped from the observer context recovery owner.
    pub recovery_owner: ControlBoardRecoveryOwner,
    /// Exact board revision the lookup was read at (projection-owned).
    pub view_revision: u64,
    /// Exact shared fence the lookup was read at (typed, never Debug text).
    pub view_fence: StateFence,
    /// Freshness binding over the exact lookup bytes (projection-owned).
    pub provenance_digest: String,
}

/// Renders the distinct non-green resolution label for one anchor resolution.
fn resolution_label(resolution: AnchorResolution) -> &'static str {
    match resolution {
        AnchorResolution::Exact => "EXACT",
        AnchorResolution::Moved => "MOVED",
        AnchorResolution::Modified => "MODIFIED",
        AnchorResolution::Ambiguous => "AMBIGUOUS",
        AnchorResolution::Stale => "STALE",
        AnchorResolution::Deleted => "DELETED",
        AnchorResolution::Unavailable => "UNAVAILABLE",
    }
}

/// Renders the owner-recorded anchor target-kind label.
fn target_kind_label(kind: AnchorTargetKind) -> &'static str {
    match kind {
        AnchorTargetKind::PublicMessage => "PUBLIC_MESSAGE",
        AnchorTargetKind::PublicPlan => "PUBLIC_PLAN",
        AnchorTargetKind::PublicRationale => "PUBLIC_RATIONALE",
        AnchorTargetKind::ToolResult => "TOOL_RESULT",
        AnchorTargetKind::Diff => "DIFF",
        AnchorTargetKind::Source => "SOURCE",
        AnchorTargetKind::VerifierResult => "VERIFIER_RESULT",
    }
}

/// Renders the owner-recorded attribution label, reproduced verbatim in
/// meaning: `CORRELATED` and `AMBIGUOUS` never become causation.
fn attribution_label(attribution: Attribution) -> &'static str {
    match attribution {
        Attribution::Exact => "EXACT",
        Attribution::ReceiptLinked => "RECEIPT_LINKED",
        Attribution::Correlated => "CORRELATED",
        Attribution::Ambiguous => "AMBIGUOUS",
        Attribution::Unknown => "UNKNOWN",
    }
}

/// Renders the distinct non-green lifecycle label for one review lifecycle.
fn lifecycle_label(lifecycle: ReviewLifecycle) -> &'static str {
    match lifecycle {
        ReviewLifecycle::Draft => "DRAFT",
        ReviewLifecycle::PendingDelivery => "PENDING_DELIVERY",
        ReviewLifecycle::Delivered => "DELIVERED",
        ReviewLifecycle::Answered => "ANSWERED",
        ReviewLifecycle::Resolved => "RESOLVED",
        ReviewLifecycle::RejectedWithReason => "REJECTED_WITH_REASON",
        ReviewLifecycle::Stale => "STALE",
        ReviewLifecycle::Superseded => "SUPERSEDED",
    }
}

/// Renders the operator-action kind name for one correction action.
fn correction_action_label(action: ReviewCorrectionAction) -> &'static str {
    match action {
        ReviewCorrectionAction::Acknowledge => "AcknowledgeReview",
        ReviewCorrectionAction::Answer => "AnswerReview",
        ReviewCorrectionAction::Resolve => "ResolveReview",
        ReviewCorrectionAction::Reject => "RejectReview",
    }
}

/// States the exact limitation for one unmapped resolution.
///
/// Pruned or purged originals (`DELETED`/`UNAVAILABLE`) report the limitation
/// with the retained handle; no historical text is reproduced and the handle
/// is never redirected to current code.
fn mapping_limitation(detail: &ControlBoardReviewDetail, resolution: AnchorResolution) -> String {
    match resolution {
        AnchorResolution::Exact | AnchorResolution::Moved | AnchorResolution::Modified => {
            format!(
                "resolution claims {} but the view carries no current-target candidate; continuity is not established",
                resolution_label(resolution)
            )
        }
        AnchorResolution::Ambiguous => {
            "duplicate or ambiguous candidates: the note is attached to no current fragment; explicit correction required"
                .to_owned()
        }
        AnchorResolution::Stale => {
            "stale target: the original anchor below is preserved; correction required before use"
                .to_owned()
        }
        AnchorResolution::Deleted | AnchorResolution::Unavailable => {
            format!(
                "original {} at revision {} is {}; retained bytes are unavailable, so no historical text is reproduced and the handle is not redirected to current code",
                detail.anchor_selector,
                detail.anchor_original_revision,
                resolution_label(resolution)
            )
        }
    }
}

/// Renders the current mapping or exact failure for one detail.
fn render_mapping(detail: &ControlBoardReviewDetail) -> RenderedReviewMapping {
    match detail.anchor_resolution {
        AnchorResolution::Exact | AnchorResolution::Moved | AnchorResolution::Modified
            if !detail.candidate_refs.is_empty() =>
        {
            RenderedReviewMapping::Mapped {
                candidates: detail.candidate_refs.clone(),
            }
        }
        resolution => RenderedReviewMapping::Failed {
            resolution: resolution_label(resolution).to_owned(),
            limitation: mapping_limitation(detail, resolution),
        },
    }
}

/// Renders the lifecycle-permitted correction actions for one detail.
fn render_correction_actions(detail: &ControlBoardReviewDetail) -> Vec<RenderedCorrectionAction> {
    detail
        .correction_actions
        .iter()
        .map(|action| RenderedCorrectionAction {
            action: correction_action_label(*action).to_owned(),
            authority_note: CORRECTION_AUTHORITY_NOTE.to_owned(),
        })
        .collect()
}

/// Replays the retained history for one detail: the lifecycle line plus the
/// candidate refs in retained order. Nothing is synthesized.
fn replay_history(detail: &ControlBoardReviewDetail) -> Vec<String> {
    let mut history = Vec::with_capacity(detail.candidate_refs.len().saturating_add(1));
    history.push(format!("lifecycle: {}", lifecycle_label(detail.lifecycle)));
    for (index, candidate) in detail.candidate_refs.iter().enumerate() {
        history.push(format!("candidate[{index}]: {candidate}"));
    }
    history
}

/// Renders one retained provenance ref for display.
fn render_provenance_ref(
    edge_id: &str,
    counterparty: &str,
    direction: &str,
    attribution: Attribution,
    receipt_ref: &Option<String>,
) -> RenderedProvenanceRef {
    RenderedProvenanceRef {
        edge_id: edge_id.to_owned(),
        counterparty: counterparty.to_owned(),
        direction: direction.to_owned(),
        attribution: attribution_label(attribution).to_owned(),
        receipt_ref: receipt_ref.clone(),
    }
}

impl RenderedReviewDetail {
    /// Reads one review through a fresh authenticated board read and renders
    /// its historical target beside the current mapping or exact failure,
    /// with the authorized correction actions.
    ///
    /// This performs exactly the projection-owned `ControlBoard::view` read
    /// via the detail contract, then stamps the observer context. There is
    /// no command construction, no port access, and no submit path in scope;
    /// a correction action displayed here is lifecycle permission only and
    /// must still pass the board submit path.
    pub fn read(
        board: &mut ControlBoard,
        request: &ReadRequest,
        review_id: &str,
        context: &ControlBoardObservationContext,
    ) -> Result<Self, ControlBoardConsumerError> {
        context.validate()?;
        let detail = read_review_detail(board, request, review_id).map_err(|error| {
            ControlBoardConsumerError::ProjectionFailed {
                detail: error.to_string(),
            }
        })?;
        Ok(Self {
            contract: CONTROLBOARD_REVIEW_RENDER_CONTRACT.to_owned(),
            review_id: detail.review_id.clone(),
            lifecycle: detail.lifecycle,
            disposed: accepted_disposition(detail.lifecycle),
            anchor_target_kind: target_kind_label(detail.anchor_target_kind).to_owned(),
            anchor_selector: detail.anchor_selector.clone(),
            anchor_original_revision: detail.anchor_original_revision,
            current_mapping: render_mapping(&detail),
            correction_actions: render_correction_actions(&detail),
            retained_history: replay_history(&detail),
            installation: context.installation.clone(),
            observed_at: context.observed_at,
            source_digest: context.source_digest.clone(),
            recovery_owner: context.recovery_owner.clone(),
            view_revision: detail.view_revision,
            view_fence: detail.view_fence.clone(),
            detail_digest: detail.detail_digest.clone(),
        })
    }

    /// Binds this rendering to one reconciled row, refusing a wrong-fragment
    /// attachment: the row entry must equal the rendered review identity, or
    /// the bind fails instead of displaying one review's detail on another
    /// row.
    pub fn bind_row(&self, row: &RenderedControlBoardRow) -> Result<(), ControlBoardConsumerError> {
        if row.entry_id == self.review_id {
            Ok(())
        } else {
            Err(ControlBoardConsumerError::ReviewRowMismatch {
                entry_id: row.entry_id.clone(),
                review_id: self.review_id.clone(),
            })
        }
    }
}

impl RenderedReviewBatchSummary {
    /// Reads the visible batch status through a fresh authenticated board
    /// read and renders per-item completeness for evaluation evidence.
    ///
    /// This performs exactly the projection-owned `ControlBoard::view` read
    /// via the batch-status contract. The rendering carries counts and the
    /// outstanding identities only; it carries no elapsed-time, speed, or
    /// quality scalar (I11.10).
    pub fn read(
        board: &mut ControlBoard,
        request: &ReadRequest,
        context: &ControlBoardObservationContext,
    ) -> Result<Self, ControlBoardConsumerError> {
        context.validate()?;
        let status = read_review_batch_status(board, request).map_err(|error| {
            ControlBoardConsumerError::ProjectionFailed {
                detail: error.to_string(),
            }
        })?;
        Ok(Self {
            contract: CONTROLBOARD_REVIEW_RENDER_CONTRACT.to_owned(),
            disposed_count: status
                .items
                .len()
                .saturating_sub(status.outstanding_ids.len()),
            total: status.items.len(),
            outstanding_ids: status.outstanding_ids.clone(),
            complete: status.complete,
            coverage_note: status.coverage_note.clone(),
            installation: context.installation.clone(),
            observed_at: context.observed_at,
            source_digest: context.source_digest.clone(),
            recovery_owner: context.recovery_owner.clone(),
            view_revision: status.view_revision,
            view_fence: status.view_fence.clone(),
            status_digest: status.status_digest.clone(),
        })
    }
}

impl RenderedCodeProvenance {
    /// Reads the reverse lookup for one code identity through a fresh
    /// authenticated board read and renders every retained origin with its
    /// attribution, plus any gaps.
    ///
    /// This performs exactly the projection-owned `ControlBoard::view` read
    /// via the code-provenance contract. Multiple origins stay multiple; an
    /// identity with no retained edge renders its gaps, never an invented
    /// link.
    pub fn read(
        board: &mut ControlBoard,
        request: &ReadRequest,
        code_id: &str,
        context: &ControlBoardObservationContext,
    ) -> Result<Self, ControlBoardConsumerError> {
        context.validate()?;
        let lookup = read_code_provenance(board, request, code_id).map_err(|error| {
            ControlBoardConsumerError::ProjectionFailed {
                detail: error.to_string(),
            }
        })?;
        Ok(Self {
            contract: CONTROLBOARD_REVIEW_RENDER_CONTRACT.to_owned(),
            code_id: lookup.code_id.clone(),
            refs: lookup
                .refs
                .iter()
                .map(|edge| {
                    let direction = match edge.direction {
                        ReviewProvenanceDirection::FromSubject => "FROM_SUBJECT",
                        ReviewProvenanceDirection::ToSubject => "TO_SUBJECT",
                    };
                    render_provenance_ref(
                        &edge.edge_id,
                        &edge.counterparty,
                        direction,
                        edge.attribution,
                        &edge.receipt_ref,
                    )
                })
                .collect(),
            gaps: lookup.gaps.clone(),
            installation: context.installation.clone(),
            observed_at: context.observed_at,
            source_digest: context.source_digest.clone(),
            recovery_owner: context.recovery_owner.clone(),
            view_revision: lookup.view_revision,
            view_fence: lookup.view_fence.clone(),
            provenance_digest: lookup.provenance_digest.clone(),
        })
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use std::num::NonZeroU64;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use eliot_contracts::{EpochId, EpochLineageId, ResourceGeneration};
    use eliot_controlboard::{
        AccessBinding, AccessResolverPort, AnchorResolution, AnchorTargetKind, BoardItem,
        BoardItemKind, CanonicalState, CanonicalStatePort, ControlBoard, PortError,
        ProjectionBinding, ProjectionProvider, ProviderCompleteness, ReadRequest, ReviewAnchor,
        ReviewItem, ReviewLifecycle, Role, ViewRevision, Visibility,
    };
    use eliot_evaluation_contracts::ObjectiveStatus;
    use eliot_evidence::{EpistemicStatus, EvidenceFreshness};
    use eliot_observation_contracts::ObservationKind;
    use eliot_security_contracts::PrivacyClass;

    use super::super::controlboard_projection::ControlBoardProjectionBindings;
    use super::*;

    const TEST_LINEAGE: &str = "550e8400-e29b-41d4-a716-446655440000";

    fn test_epoch(sequence: u64) -> EpochId {
        EpochId::new(
            EpochLineageId::new(TEST_LINEAGE).expect("test lineage"),
            NonZeroU64::new(sequence).expect("nonzero sequence"),
        )
        .expect("test epoch")
    }

    fn fence() -> StateFence {
        StateFence::new(
            test_epoch(1),
            ResourceGeneration::new(7).expect("test generation"),
        )
    }

    fn revision() -> ViewRevision {
        ViewRevision::new(7).expect("test revision")
    }

    fn item(id: &str, kind: BoardItemKind) -> BoardItem {
        BoardItem {
            item_id: id.to_owned(),
            kind,
            visibility: Visibility::Public,
            privacy: PrivacyClass::Public,
            summary: format!("summary for {id}"),
            observation_kind: ObservationKind::TaskProgress,
            epistemic_status: EpistemicStatus::Observed,
            evidence_freshness: EvidenceFreshness::ExactCandidate,
            objective_status: ObjectiveStatus::Active,
        }
    }

    fn review(id: &str) -> ReviewItem {
        ReviewItem {
            review_item_id: id.to_owned(),
            visibility: Visibility::Public,
            privacy: PrivacyClass::Public,
            anchor: ReviewAnchor {
                target_kind: AnchorTargetKind::Diff,
                original_revision: revision(),
                selector: "src/lib.rs:1".to_owned(),
                resolution: AnchorResolution::Ambiguous,
            },
            lifecycle: ReviewLifecycle::Delivered,
            content: format!("content for {id}"),
            response_change_refs: Vec::new(),
        }
    }

    fn bindings() -> ControlBoardProjectionBindings {
        ControlBoardProjectionBindings {
            capability: "controlboard.read".to_owned(),
            owner: "runtime-status".to_owned(),
            generation: "generation-7".to_owned(),
            evidence: "evidence-1213".to_owned(),
            expiry: "re-read required after fence or generation change".to_owned(),
            invalidation: "revision/fence change, generation rotation, owner rebind".to_owned(),
            product_pulse: None,
            product_not_applicable: Some(
                "read-only status contour carries no product claim".to_owned(),
            ),
            evaluated_at_ms: super::super::controlboard_projection::owner_records::EVALUATED_AT_MS,
            domain_coverage:
                super::super::controlboard_projection::owner_records::unobserved_coverage(),
            support_rows: vec![
                super::super::controlboard_projection::owner_records::target_source_support_row(),
            ],
            transport: SupportObservationState::Unknown,
            evidence_execution: EvidenceExecutionStatus::NotExecuted,
        }
    }

    fn context() -> ControlBoardObservationContext {
        ControlBoardObservationContext {
            installation: ControlBoardInstallation::new("installation-portable-dev")
                .expect("installation"),
            observed_at: ControlBoardObservationTime::new(1_786_000_000_000).expect("observed_at"),
            source_digest: ControlBoardSourceDigest::new("ab".repeat(32)).expect("digest"),
            recovery_owner: ControlBoardRecoveryOwner::new("recovery-owner-ops")
                .expect("recovery owner"),
        }
    }

    fn expected() -> ControlBoardExpectedSet {
        ControlBoardExpectedSet::new(vec![
            "review-1".to_owned(),
            "item-1".to_owned(),
            "item-2".to_owned(),
            "ghost-component".to_owned(),
        ])
        .expect("expected set")
    }

    struct FakeAccess {
        binding: AccessBinding,
    }

    impl AccessResolverPort for FakeAccess {
        fn resolve(&mut self, _request: &ReadRequest) -> Result<AccessBinding, PortError> {
            Ok(self.binding.clone())
        }
    }

    struct DenyingAccess;

    impl AccessResolverPort for DenyingAccess {
        fn resolve(&mut self, _request: &ReadRequest) -> Result<AccessBinding, PortError> {
            Err(PortError::Denied)
        }
    }

    struct FakeState {
        state: CanonicalState,
        reads: Arc<AtomicUsize>,
    }

    impl CanonicalStatePort for FakeState {
        fn read(
            &mut self,
            _request: &ReadRequest,
            _access: &AccessBinding,
        ) -> Result<CanonicalState, PortError> {
            self.reads.fetch_add(1, Ordering::SeqCst);
            Ok(self.state.clone())
        }
    }

    fn projection_binding(
        provider: ProjectionProvider,
        work_id: &str,
        binding_id: &str,
    ) -> ProjectionBinding {
        ProjectionBinding {
            provider,
            work_id: work_id.to_owned(),
            binding_id: binding_id.to_owned(),
            binding_revision: revision(),
            binding_fence: fence(),
            binding_digest: format!("{binding_id}-digest"),
            receipt_ref: format!("{binding_id}-receipt"),
        }
    }

    fn canonical_state() -> CanonicalState {
        CanonicalState {
            revision: revision(),
            fence: fence(),
            completeness: ProviderCompleteness {
                g11_coordination: projection_binding(
                    ProjectionProvider::G11,
                    "G-11",
                    "g11-binding",
                ),
                i12_report_projection: projection_binding(
                    ProjectionProvider::I12,
                    "I-12",
                    "i12-binding",
                ),
            },
            items: vec![
                item("item-1", BoardItemKind::Task),
                item("item-2", BoardItemKind::Attention),
            ],
            reviews: vec![review("review-1")],
            provenance: Vec::new(),
            notifications: Vec::new(),
        }
    }

    fn access_binding() -> AccessBinding {
        AccessBinding {
            principal_id: "principal".to_owned(),
            work_scope: "scope".to_owned(),
            role: Role::HumanRequester,
            admitted_privacy: vec![PrivacyClass::Public],
            capabilities: Vec::new(),
            session_id: "session".to_owned(),
            connection_id: "connection".to_owned(),
            credential_binding: "credential".to_owned(),
            challenge: "challenge".to_owned(),
            request_id: "request".to_owned(),
            generation: 4,
            issued_at_unix_ms: 1_000,
            observed_at_unix_ms: 1_100,
            expires_at_unix_ms: 2_000,
            access_revision: revision(),
            access_fence: fence(),
        }
    }

    fn board(reads: &Arc<AtomicUsize>) -> ControlBoard {
        ControlBoard::new(
            Some(Box::new(FakeAccess {
                binding: access_binding(),
            })),
            Some(Box::new(FakeState {
                state: canonical_state(),
                reads: Arc::clone(reads),
            })),
            None,
        )
    }

    fn read_request() -> ReadRequest {
        ReadRequest::new(
            "session",
            "connection",
            "credential",
            "challenge",
            "request",
            4,
        )
        .expect("test request")
    }

    #[test]
    fn live_read_path_reconciles_one_row_per_expected_entry() {
        let reads = Arc::new(AtomicUsize::new(0));
        let mut board_handle = board(&reads);
        let rendered = read_controlboard_status(
            &mut board_handle,
            &read_request(),
            &bindings(),
            &context(),
            &expected(),
            &BTreeMap::new(),
        )
        .expect("rendered board");
        assert_eq!(rendered.contract, CONTROLBOARD_CONSUMER_CONTRACT);
        assert_eq!(rendered.view_revision, 7);
        assert_eq!(rendered.view_fence, fence());
        assert!(!rendered.contour_digest.trim().is_empty());
        // Frozen denominator order: sorted entry identities.
        let rendered_ids: Vec<&str> = rendered
            .rows
            .iter()
            .map(|row| row.entry_id.as_str())
            .collect();
        assert_eq!(
            rendered_ids,
            vec!["ghost-component", "item-1", "item-2", "review-1"]
        );
        assert_eq!(rendered.observed_count, 3);
        assert_eq!(rendered.missing_count, 1);
        assert!(rendered.unexpected_observed.is_empty());
        // Exactly one canonical read; no command port exists, so any submit
        // path would have failed closed instead of producing this board.
        assert_eq!(reads.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn denominator_detects_missing_and_stamps_typed_fields() {
        let reads = Arc::new(AtomicUsize::new(0));
        let mut board_handle = board(&reads);
        let rendered = read_controlboard_status(
            &mut board_handle,
            &read_request(),
            &bindings(),
            &context(),
            &expected(),
            &BTreeMap::new(),
        )
        .expect("rendered board");
        let ghost = rendered
            .rows
            .iter()
            .find(|row| row.entry_id == "ghost-component")
            .expect("ghost row");
        assert_eq!(ghost.disposition, ControlBoardRowDisposition::Missing);
        assert!(!ghost.disposition.was_observed());
        assert_eq!(ghost.summary, None);
        let observed = rendered
            .rows
            .iter()
            .find(|row| row.entry_id == "item-1")
            .expect("observed row");
        assert_eq!(observed.disposition, ControlBoardRowDisposition::Unknown);
        assert!(observed.disposition.was_observed());
        assert_eq!(observed.summary, Some("summary for item-1".to_owned()));
        for row in &rendered.rows {
            assert_eq!(row.installation.as_str(), "installation-portable-dev");
            assert_eq!(row.observed_at.get(), 1_786_000_000_000);
            assert_eq!(row.source_digest.as_str(), &"ab".repeat(32));
            assert_eq!(row.recovery_owner.as_str(), "recovery-owner-ops");
            assert_eq!(row.view_revision, 7);
            assert_eq!(row.contour_digest, rendered.contour_digest);
        }
    }

    #[test]
    fn overrides_select_dispositions_but_never_resurrect_missing() {
        let reads = Arc::new(AtomicUsize::new(0));
        let mut board_handle = board(&reads);
        let overrides = BTreeMap::from([
            ("item-1".to_owned(), ControlBoardRowDisposition::Stale),
            (
                "ghost-component".to_owned(),
                ControlBoardRowDisposition::NotRunning,
            ),
        ]);
        let rendered = read_controlboard_status(
            &mut board_handle,
            &read_request(),
            &bindings(),
            &context(),
            &expected(),
            &overrides,
        )
        .expect("rendered board");
        let stale = rendered
            .rows
            .iter()
            .find(|row| row.entry_id == "item-1")
            .expect("stale row");
        assert_eq!(stale.disposition, ControlBoardRowDisposition::Stale);
        // Overrides cannot resurrect unobserved rows: the denominator gap wins.
        let ghost = rendered
            .rows
            .iter()
            .find(|row| row.entry_id == "ghost-component")
            .expect("ghost row");
        assert_eq!(ghost.disposition, ControlBoardRowDisposition::Missing);
    }

    #[test]
    fn all_eight_dispositions_render_distinct_and_non_green() {
        let all = [
            ControlBoardRowDisposition::Stale,
            ControlBoardRowDisposition::Unavailable,
            ControlBoardRowDisposition::NotRunning,
            ControlBoardRowDisposition::Conflicted,
            ControlBoardRowDisposition::Partial,
            ControlBoardRowDisposition::Unknown,
            ControlBoardRowDisposition::Unsupported,
            ControlBoardRowDisposition::Missing,
        ];
        let mut labels = BTreeMap::new();
        for disposition in all {
            let label = disposition.label();
            assert!(
                !matches!(label, "HEALTHY" | "GREEN" | "OK" | "READY" | "CURRENT"),
                "disposition must never render green: {label}"
            );
            assert!(
                labels.insert(label, disposition).is_none(),
                "disposition labels must be distinct: {label}"
            );
            let encoded = serde_json::to_string(&disposition).expect("json");
            let decoded: ControlBoardRowDisposition =
                serde_json::from_str(&encoded).expect("round-trip");
            assert_eq!(decoded, disposition);
        }
        assert_eq!(labels.len(), 8);
        assert!(!ControlBoardRowDisposition::Missing.was_observed());
        for disposition in all {
            if disposition != ControlBoardRowDisposition::Missing {
                assert!(disposition.was_observed());
            }
        }
    }

    #[test]
    fn override_outside_denominator_fails_closed() {
        let reads = Arc::new(AtomicUsize::new(0));
        let mut board_handle = board(&reads);
        let overrides = BTreeMap::from([(
            "outside-denominator".to_owned(),
            ControlBoardRowDisposition::Stale,
        )]);
        let error = read_controlboard_status(
            &mut board_handle,
            &read_request(),
            &bindings(),
            &context(),
            &expected(),
            &overrides,
        )
        .expect_err("outside-denominator override must fail");
        assert_eq!(
            error,
            ControlBoardConsumerError::OverrideOutsideDenominator {
                entry_id: "outside-denominator".to_owned()
            }
        );
        assert_eq!(reads.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn unexpected_observed_entries_are_preserved_not_dropped() {
        let reads = Arc::new(AtomicUsize::new(0));
        let mut board_handle = board(&reads);
        let narrow = ControlBoardExpectedSet::new(vec!["item-1".to_owned()]).expect("narrow set");
        let rendered = read_controlboard_status(
            &mut board_handle,
            &read_request(),
            &bindings(),
            &context(),
            &narrow,
            &BTreeMap::new(),
        )
        .expect("rendered board");
        assert_eq!(rendered.rows.len(), 1);
        assert_eq!(rendered.observed_count, 1);
        assert_eq!(rendered.missing_count, 0);
        assert_eq!(
            rendered.unexpected_observed,
            vec!["item-2".to_owned(), "review-1".to_owned()]
        );
    }

    #[test]
    fn denominator_rejects_empty_duplicate_and_bad_shape() {
        assert_eq!(
            ControlBoardExpectedSet::new(Vec::new()),
            Err(ControlBoardConsumerError::EmptyExpectedSet)
        );
        assert_eq!(
            ControlBoardExpectedSet::new(vec!["item-1".to_owned(), "item-1".to_owned()]),
            Err(ControlBoardConsumerError::DuplicateExpectedId {
                entry_id: "item-1".to_owned()
            })
        );
        assert_eq!(
            ControlBoardExpectedSet::new(vec![String::new()]),
            Err(ControlBoardConsumerError::InvalidBinding {
                field: "expected_set.entry_id"
            })
        );
        assert_eq!(
            ControlBoardExpectedSet::new(vec!["bad\nid".to_owned()]),
            Err(ControlBoardConsumerError::InvalidBinding {
                field: "expected_set.entry_id"
            })
        );
        // Frozen order: construction input order does not leak into render order.
        let frozen =
            ControlBoardExpectedSet::new(vec!["b".to_owned(), "a".to_owned()]).expect("frozen");
        assert_eq!(frozen.entries(), &["a".to_owned(), "b".to_owned()]);
        assert!(frozen.contains("a"));
        assert!(!frozen.contains("c"));
        assert_eq!(frozen.len(), 2);
    }

    #[test]
    fn typed_fields_reject_bad_shape() {
        assert_eq!(
            ControlBoardInstallation::new(""),
            Err(ControlBoardConsumerError::InvalidBinding {
                field: "installation"
            })
        );
        assert_eq!(
            ControlBoardInstallation::new("install\nname"),
            Err(ControlBoardConsumerError::InvalidBinding {
                field: "installation"
            })
        );
        assert_eq!(
            ControlBoardObservationTime::new(0),
            Err(ControlBoardConsumerError::InvalidObservationTime)
        );
        assert_eq!(
            ControlBoardSourceDigest::new("short"),
            Err(ControlBoardConsumerError::InvalidSourceDigest)
        );
        assert_eq!(
            ControlBoardSourceDigest::new("zz".repeat(32)),
            Err(ControlBoardConsumerError::InvalidSourceDigest)
        );
        assert_eq!(
            ControlBoardRecoveryOwner::new(""),
            Err(ControlBoardConsumerError::InvalidBinding {
                field: "recovery_owner"
            })
        );
        let digest = ControlBoardSourceDigest::new("AB".repeat(32)).expect("uppercase hex");
        assert_eq!(digest.as_str(), &"AB".repeat(32));
    }

    #[test]
    fn denied_read_yields_no_board() {
        let mut denied = ControlBoard::new(Some(Box::new(DenyingAccess)), None, None);
        let error = read_controlboard_status(
            &mut denied,
            &read_request(),
            &bindings(),
            &context(),
            &expected(),
            &BTreeMap::new(),
        )
        .expect_err("denied read must fail");
        assert!(matches!(
            error,
            ControlBoardConsumerError::ProjectionFailed { .. }
        ));
    }

    #[test]
    fn no_secret_material_in_rendered_board() {
        let reads = Arc::new(AtomicUsize::new(0));
        let mut board_handle = board(&reads);
        let rendered = read_controlboard_status(
            &mut board_handle,
            &read_request(),
            &bindings(),
            &context(),
            &expected(),
            &BTreeMap::new(),
        )
        .expect("rendered board");
        let json = serde_json::to_string(&rendered).expect("json");
        for needle in [
            "session_id",
            "credential",
            "challenge",
            "access_digest",
            "secret",
            "token",
            "nonce",
            "password",
            "private_key",
            "authorization",
        ] {
            assert!(
                !json.contains(needle),
                "secret-like text in rendered board: {needle}"
            );
        }
    }
}
