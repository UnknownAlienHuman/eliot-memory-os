//! Operator-adjacent live read path over the `read_controlboard_contour` projection.
//!
//! Issue #1213 follow-through: this module is the one live read-only consumer
//! that binds the merged [`read_controlboard_contour`](super::read_controlboard_contour)
//! projection to real consumption. It performs exactly one board effect — the
//! authenticated [`ControlBoard::view`](eliot_controlboard::ControlBoard::view)
//! read owned by the projection — then reconciles the resulting contour against
//! a caller-frozen expected-row denominator.
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
//! `ImplementationSupport`, maturity, or evidence-execution claims
//! (Implementation I0.5).
//!
//! Typed fields: every rendered row stamps the four observer-supplied typed
//! bindings ([`ControlBoardInstallation`], [`ControlBoardObservationTime`],
//! [`ControlBoardSourceDigest`], [`ControlBoardRecoveryOwner`]) plus the
//! projection-owned typed identities (`view_revision: u64`,
//! `view_fence: StateFence`, `contour_digest`). No caller-opaque string stands
//! in for a value the projection owns.
//!
//! Secret handling: rendered rows carry no session, credential, challenge,
//! access-digest, token, or nonce fields by construction. The inert
//! `ReadRequest` fields are never copied into the rendered board.
//!
//! Bounds (consumer-side allocation guards, fail-closed): at most
//! [`MAX_CONSUMER_ROWS`] expected entries; typed text fields at most
//! [`MAX_TYPED_CHARS`] characters.

use std::collections::BTreeMap;

use eliot_contracts::StateFence;
use eliot_controlboard::{ControlBoard, ReadRequest};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::controlboard_projection::{
    ControlBoardContour, ControlBoardProjectionBindings, read_controlboard_contour,
};

/// Stable contract identity for this read-only consumer rendering.
pub const CONTROLBOARD_CONSUMER_CONTRACT: &str = "eliot.runtime-status.controlboard-consumer/v1";

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
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
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
    /// Count of rows actually observed in the contour.
    pub observed_count: usize,
    /// Count of expected-but-unobserved rows.
    pub missing_count: usize,
    /// Observed contour entry identities outside the frozen denominator, in
    /// view order. Preserved verbatim so denominator drift cannot silently
    /// drop observations.
    pub unexpected_observed: Vec<String>,
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

/// Reconciles one contour against the frozen denominator.
///
/// Every expected entry receives exactly one row in frozen order: observed
/// entries render the operator-supplied override disposition (or `Unknown`
/// when none was supplied); unobserved entries render `Missing` with no
/// summary. Observed contour entries outside the denominator are preserved in
/// `unexpected_observed`. Dispositions are never inferred from entry kinds or
/// summaries.
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
    let mut observed_by_id: BTreeMap<&str, &str> = BTreeMap::new();
    for row in &contour.rows {
        observed_by_id.insert(row.entry_id.as_str(), row.summary.as_str());
    }
    let mut rows = Vec::with_capacity(expected.len());
    let mut observed_count = 0_usize;
    for entry_id in expected.entries() {
        let rendered = match observed_by_id.get(entry_id.as_str()) {
            Some(summary) => {
                observed_count = observed_count.saturating_add(1);
                RenderedControlBoardRow {
                    entry_id: entry_id.clone(),
                    disposition: overrides
                        .get(entry_id.as_str())
                        .copied()
                        .unwrap_or(ControlBoardRowDisposition::Unknown),
                    summary: Some((*summary).to_owned()),
                    installation: context.installation.clone(),
                    observed_at: context.observed_at,
                    source_digest: context.source_digest.clone(),
                    recovery_owner: context.recovery_owner.clone(),
                    view_revision: contour.view_revision,
                    contour_digest: contour.contour_digest.clone(),
                }
            }
            None => RenderedControlBoardRow {
                entry_id: entry_id.clone(),
                disposition: ControlBoardRowDisposition::Missing,
                summary: None,
                installation: context.installation.clone(),
                observed_at: context.observed_at,
                source_digest: context.source_digest.clone(),
                recovery_owner: context.recovery_owner.clone(),
                view_revision: contour.view_revision,
                contour_digest: contour.contour_digest.clone(),
            },
        };
        rows.push(rendered);
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
        observed_count,
        missing_count,
        unexpected_observed,
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
