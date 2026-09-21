//! Read-only `ControlBoard` status projection owned by `eliot-runtime-status`.
//!
//! Issue #1213 second half: this module is the one real read-only consumer
//! that wires `eliot-controlboard` under the current runtime-status owner.
//! It consumes only the immutable [`ControlBoardView`](eliot_controlboard::ControlBoardView)
//! produced by the authenticated [`ControlBoard::view`](eliot_controlboard::ControlBoard::view)
//! read edge. It never submits commands, never touches operator ports, and
//! cannot mint authority, sessions, fences, or operation identities.
//!
//! Read-only enforcement (structural, not prose):
//!
//! * [`project_controlboard_contour`] takes `&ControlBoardView` only. With no
//!   board handle and no port handle in scope, no code path in this module can
//!   effect, dispatch, or persist anything.
//! * [`read_controlboard_contour`] takes `&mut ControlBoard` but calls exactly
//!   one method: `ControlBoard::view`. The crate under test is constructed
//!   without an operator-command port in the read-only proof, so any submit
//!   path would fail closed as `PLAN_GAP` instead of producing a contour.
//!
//! Row bindings: every [`ControlBoardStatusRow`] stamps the six
//! composition-supplied bindings (`capability`, `owner`, `generation`,
//! `evidence`, `expiry`, `invalidation`). These values are caller-supplied
//! evidence, validated for shape only (non-empty, no control characters,
//! bounded length); this projection never infers them from files, PIDs, ports,
//! or manifests, and never widens them.
//!
//! Independence: `liveness`, `readiness`, `support`, `evidence_refs`, and the
//! `product_*` fields are separate contour fields with no synthesis function.
//! A projected view proves neither liveness nor readiness, so both stay
//! `Unknown` with explicit gaps; live evidence remains owned by issue #11.
//! There is intentionally no `status()`, `is_healthy()`, or `is_ready()`
//! constructor: collapsing the dimensions would manufacture a claim no single
//! read can justify (Implementation I0.5).
//!
//! Secret handling: the contour carries no session, credential, challenge,
//! access-digest, token, or nonce fields by construction. Summaries are
//! reproduced 1:1 from the already role-filtered view; role/privacy filtering
//! itself stays owned by `ControlBoard::view` and is never re-decided here.
//!
//! Bounds (projection-side allocation guards, fail-closed): at most
//! [`MAX_CONTROLBOARD_ROWS`] rows; binding fields at most
//! [`MAX_BINDING_CHARS`] characters; entry summaries at most
//! [`MAX_SUMMARY_CHARS`] characters.

use eliot_contracts::{StateFence, sha256_hex};
use eliot_controlboard::{
    BoardItemKind, ControlBoard, ControlBoardView, ReadRequest, ReviewLifecycle,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::ComponentState;

/// Stable contract identity for this read-only contour.
pub const CONTROLBOARD_CONTOUR_CONTRACT: &str = "eliot.runtime-status.controlboard-contour/v1";

/// Maximum rows projected from one view (allocation guard, fail-closed).
const MAX_CONTROLBOARD_ROWS: usize = 2048;
/// Maximum characters per caller-supplied binding field.
const MAX_BINDING_CHARS: usize = 1024;
/// Maximum characters per projected entry summary.
const MAX_SUMMARY_CHARS: usize = 4096;

fn liveness_gap() -> String {
    "no typed read-only ControlBoard liveness adapter exists; a projected view does not prove liveness; live process evidence remains owned by issue #11".to_owned()
}

fn readiness_gap() -> String {
    "a projected ControlBoard view does not prove readiness; readiness requires the Kernel readiness lease path, never view presence".to_owned()
}

/// Composition-supplied evidence stamped on every projected row.
///
/// All six bindings are required. They describe the exact read the contour was
/// projected from; this module validates their shape and stamps them verbatim.
/// Exactly one of `product_pulse` / `product_not_applicable` must be `Some`,
/// mirroring the registry readback convention: a contour either names its
/// Product Pulse or states explicitly why none applies.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlBoardProjectionBindings {
    /// Admitted read capability the operator read was performed under
    /// (for example the broker-owned `"controlboard.read"` capability name).
    /// Per-action mutation capabilities are deliberately not bound here: this
    /// projection never submits, so no action capability is exercised.
    pub capability: String,
    /// Canonical owner of the projected state named by composition.
    pub owner: String,
    /// Owner-issued generation the view was read at.
    pub generation: String,
    /// Evidence identifier for this projection.
    pub evidence: String,
    /// Freshness bound supplied by composition (re-read required after).
    pub expiry: String,
    /// What discards this contour (revision/fence change, generation
    /// rotation, owner rebind).
    pub invalidation: String,
    /// Product Pulse reference, when the owning composition declares one.
    pub product_pulse: Option<String>,
    /// Explicit reason no Product Pulse applies, when none is declared.
    pub product_not_applicable: Option<String>,
}

/// Which board entry a status row was projected from.
///
/// The variants reuse the `eliot-controlboard` enums directly, so the
/// consumer binding is type-level: a serde or variant change upstream fails
/// compilation here instead of silently reinterpreting entries.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ControlBoardEntryKind {
    Item(BoardItemKind),
    Review(ReviewLifecycle),
}

/// One projected board entry with all six owner bindings attached.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlBoardStatusRow {
    /// Board `item_id` or review `review_item_id` from the exact view.
    pub entry_id: String,
    /// Entry class, bound to the controlboard enums.
    pub entry: ControlBoardEntryKind,
    /// Entry summary/content reproduced 1:1 from the role-filtered view.
    pub summary: String,
    /// Stamped from [`ControlBoardProjectionBindings::capability`].
    pub capability: String,
    /// Stamped from [`ControlBoardProjectionBindings::owner`].
    pub owner: String,
    /// Stamped from [`ControlBoardProjectionBindings::generation`].
    pub generation: String,
    /// Stamped from [`ControlBoardProjectionBindings::evidence`].
    pub evidence: String,
    /// Stamped from [`ControlBoardProjectionBindings::expiry`].
    pub expiry: String,
    /// Stamped from [`ControlBoardProjectionBindings::invalidation`].
    pub invalidation: String,
}

/// Implementation-support position this projection may claim.
///
/// The only justifiable position for a freshly read view is
/// `CURRENT_UNVERIFIED`: source exists in-process, product behavior is not
/// proven. The vocabulary is a closed single-variant enum so no other support
/// claim can be constructed or deserialized through this contour.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ControlBoardSupport {
    CurrentUnverified,
}

/// Read-only `ControlBoard` contour.
///
/// Liveness, readiness, support, evidence, and Product are independent fields.
/// No method combines them; adding one would manufacture a claim no single
/// read can justify.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlBoardContour {
    /// Always [`CONTROLBOARD_CONTOUR_CONTRACT`].
    pub contract: String,
    /// Exact board revision the view was pinned to.
    pub view_revision: u64,
    /// Exact shared fence the view was pinned to (typed, never Debug text).
    pub view_fence: StateFence,
    /// One row per visible board item and review, in view order.
    pub rows: Vec<ControlBoardStatusRow>,
    /// Count of board items in the exact view.
    pub item_count: usize,
    /// Count of reviews in the exact view.
    pub review_count: usize,
    /// Count of provenance edges in the exact view (count only; edge bodies
    /// are out of scope for this bounded contour).
    pub provenance_edge_count: usize,
    /// Always `Unknown`: a view does not prove liveness.
    pub liveness: ComponentState,
    /// Always `Unknown`: a view does not prove readiness.
    pub readiness: ComponentState,
    /// Always `CURRENT_UNVERIFIED`: source read, behavior unproven.
    pub support: ControlBoardSupport,
    /// Caller evidence plus the exact view-revision reference.
    pub evidence_refs: Vec<String>,
    /// Product Pulse reference, when the owning composition declares one.
    pub product_pulse: Option<String>,
    /// Explicit reason no Product Pulse applies, when none is declared.
    pub product_not_applicable: Option<String>,
    /// Stamped from [`ControlBoardProjectionBindings::expiry`].
    pub expiry: String,
    /// Stamped from [`ControlBoardProjectionBindings::invalidation`].
    pub invalidation: String,
    /// SHA-256 freshness binding over the exact projected bytes.
    pub contour_digest: String,
}

/// Fail-closed projection failure. Any variant refuses the contour instead of
/// projecting partial or inferred evidence.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum ControlBoardProjectionError {
    /// A required binding field is empty or carries control characters.
    #[error("invalid controlboard projection binding: {field}")]
    InvalidBinding {
        /// Binding field that failed shape validation.
        field: &'static str,
    },
    /// A value exceeds its projection-side allocation bound.
    #[error("controlboard projection value exceeds bound: {field}")]
    Oversized {
        /// Field that exceeded its bound.
        field: &'static str,
    },
    /// Two visible entries share one identity.
    #[error("duplicate controlboard entry identity: {entry_id}")]
    DuplicateEntryId {
        /// Colliding entry identity.
        entry_id: String,
    },
    /// Neither or both Product bindings are present; exactly one is required.
    #[error("controlboard contour requires exactly one product binding")]
    MissingPulseBinding,
    /// The authenticated board read itself failed; no contour exists.
    #[error("controlboard read failed: {detail}")]
    ReadFailed {
        /// Diagnostic board error text (diagnostic only, never persisted).
        detail: String,
    },
    /// Canonical encoding for the freshness digest failed.
    #[error("controlboard contour encoding failed: {detail}")]
    EncodingFailed {
        /// Underlying encoding failure detail.
        detail: String,
    },
}

fn bound_text(
    value: &str,
    field: &'static str,
    max_chars: usize,
) -> Result<(), ControlBoardProjectionError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(ControlBoardProjectionError::InvalidBinding { field });
    }
    if value.chars().count() > max_chars {
        return Err(ControlBoardProjectionError::Oversized { field });
    }
    Ok(())
}

fn validate_bindings(
    bindings: &ControlBoardProjectionBindings,
) -> Result<(), ControlBoardProjectionError> {
    bound_text(
        &bindings.capability,
        "bindings.capability",
        MAX_BINDING_CHARS,
    )?;
    bound_text(&bindings.owner, "bindings.owner", MAX_BINDING_CHARS)?;
    bound_text(
        &bindings.generation,
        "bindings.generation",
        MAX_BINDING_CHARS,
    )?;
    bound_text(&bindings.evidence, "bindings.evidence", MAX_BINDING_CHARS)?;
    bound_text(&bindings.expiry, "bindings.expiry", MAX_BINDING_CHARS)?;
    bound_text(
        &bindings.invalidation,
        "bindings.invalidation",
        MAX_BINDING_CHARS,
    )?;
    match (&bindings.product_pulse, &bindings.product_not_applicable) {
        (Some(pulse), None) => bound_text(pulse, "bindings.product_pulse", MAX_BINDING_CHARS)?,
        (None, Some(reason)) => {
            bound_text(reason, "bindings.product_not_applicable", MAX_BINDING_CHARS)?;
        }
        _ => return Err(ControlBoardProjectionError::MissingPulseBinding),
    }
    Ok(())
}

/// Projects one read-only contour over an already-obtained board view.
///
/// The view is consumed by shared reference; role/privacy filtering is the
/// view's own property and is preserved 1:1. Every row is stamped with the
/// validated caller bindings. Liveness and readiness stay `Unknown`,
/// support stays `CURRENT_UNVERIFIED`, and Product stays exactly the
/// caller-declared pulse binding: the dimensions are never merged.
pub fn project_controlboard_contour(
    view: &ControlBoardView,
    bindings: &ControlBoardProjectionBindings,
) -> Result<ControlBoardContour, ControlBoardProjectionError> {
    validate_bindings(bindings)?;
    let entry_total = view.items.len().saturating_add(view.reviews.len());
    if entry_total > MAX_CONTROLBOARD_ROWS {
        return Err(ControlBoardProjectionError::Oversized { field: "rows" });
    }
    let mut rows = Vec::with_capacity(entry_total);
    let mut seen_ids = std::collections::BTreeSet::new();
    for item in &view.items {
        bound_text(&item.item_id, "row.entry_id", MAX_BINDING_CHARS)?;
        bound_text(&item.summary, "row.summary", MAX_SUMMARY_CHARS)?;
        if !seen_ids.insert(item.item_id.clone()) {
            return Err(ControlBoardProjectionError::DuplicateEntryId {
                entry_id: item.item_id.clone(),
            });
        }
        rows.push(ControlBoardStatusRow {
            entry_id: item.item_id.clone(),
            entry: ControlBoardEntryKind::Item(item.kind),
            summary: item.summary.clone(),
            capability: bindings.capability.clone(),
            owner: bindings.owner.clone(),
            generation: bindings.generation.clone(),
            evidence: bindings.evidence.clone(),
            expiry: bindings.expiry.clone(),
            invalidation: bindings.invalidation.clone(),
        });
    }
    for review in &view.reviews {
        bound_text(&review.review_item_id, "row.entry_id", MAX_BINDING_CHARS)?;
        bound_text(&review.content, "row.summary", MAX_SUMMARY_CHARS)?;
        if !seen_ids.insert(review.review_item_id.clone()) {
            return Err(ControlBoardProjectionError::DuplicateEntryId {
                entry_id: review.review_item_id.clone(),
            });
        }
        rows.push(ControlBoardStatusRow {
            entry_id: review.review_item_id.clone(),
            entry: ControlBoardEntryKind::Review(review.lifecycle),
            summary: review.content.clone(),
            capability: bindings.capability.clone(),
            owner: bindings.owner.clone(),
            generation: bindings.generation.clone(),
            evidence: bindings.evidence.clone(),
            expiry: bindings.expiry.clone(),
            invalidation: bindings.invalidation.clone(),
        });
    }
    let revision = view.revision.get();
    let evidence_refs = vec![
        bindings.evidence.clone(),
        format!("controlboard-view-revision={revision}"),
    ];
    let digest_bytes = serde_json::to_vec(&(
        CONTROLBOARD_CONTOUR_CONTRACT,
        revision,
        &view.fence,
        &rows,
        &evidence_refs,
    ))
    .map_err(|error| ControlBoardProjectionError::EncodingFailed {
        detail: error.to_string(),
    })?;
    Ok(ControlBoardContour {
        contract: CONTROLBOARD_CONTOUR_CONTRACT.to_owned(),
        view_revision: revision,
        view_fence: view.fence.clone(),
        rows,
        item_count: view.items.len(),
        review_count: view.reviews.len(),
        provenance_edge_count: view.provenance.len(),
        liveness: ComponentState::Unknown {
            reason: "controlboard view presence does not prove liveness".to_owned(),
            gap: liveness_gap(),
        },
        readiness: ComponentState::Unknown {
            reason: "controlboard view presence does not prove readiness".to_owned(),
            gap: readiness_gap(),
        },
        support: ControlBoardSupport::CurrentUnverified,
        evidence_refs,
        product_pulse: bindings.product_pulse.clone(),
        product_not_applicable: bindings.product_not_applicable.clone(),
        expiry: bindings.expiry.clone(),
        invalidation: bindings.invalidation.clone(),
        contour_digest: sha256_hex(&digest_bytes),
    })
}

/// Reads one contour through the real authenticated board read edge.
///
/// This is the single effect-adjacent call in this module and it performs a
/// read only: exactly `ControlBoard::view`. There is no command construction,
/// no port access, and no submit path in scope. Callers supply the inert
/// [`ReadRequest`] and the composition-owned bindings; session, role, and
/// fence authority stay owned by the board's own resolver.
pub fn read_controlboard_contour(
    board: &mut ControlBoard,
    request: &ReadRequest,
    bindings: &ControlBoardProjectionBindings,
) -> Result<ControlBoardContour, ControlBoardProjectionError> {
    let view = board
        .view(request)
        .map_err(|error| ControlBoardProjectionError::ReadFailed {
            detail: error.to_string(),
        })?;
    project_controlboard_contour(&view, bindings)
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

    fn view() -> ControlBoardView {
        ControlBoardView {
            revision: revision(),
            fence: fence(),
            items: vec![
                item("item-1", BoardItemKind::Task),
                item("item-2", BoardItemKind::Attention),
            ],
            reviews: vec![review("review-1")],
            provenance: Vec::new(),
        }
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
    fn rows_bind_all_six_owner_bindings() {
        let contour = project_controlboard_contour(&view(), &bindings()).expect("contour");
        assert_eq!(contour.contract, CONTROLBOARD_CONTOUR_CONTRACT);
        assert_eq!(contour.view_revision, 7);
        assert_eq!(contour.view_fence, fence());
        assert_eq!(contour.rows.len(), 3);
        assert_eq!(contour.item_count, 2);
        assert_eq!(contour.review_count, 1);
        assert_eq!(contour.provenance_edge_count, 0);
        let expected_ids = ["item-1", "item-2", "review-1"];
        for (row, expected_id) in contour.rows.iter().zip(expected_ids) {
            assert_eq!(row.entry_id, expected_id);
            assert_eq!(row.capability, "controlboard.read");
            assert_eq!(row.owner, "runtime-status");
            assert_eq!(row.generation, "generation-7");
            assert_eq!(row.evidence, "evidence-1213");
            assert_eq!(
                row.expiry,
                "re-read required after fence or generation change"
            );
            assert_eq!(
                row.invalidation,
                "revision/fence change, generation rotation, owner rebind"
            );
        }
        assert_eq!(
            contour.rows[0].entry,
            ControlBoardEntryKind::Item(BoardItemKind::Task)
        );
        assert_eq!(
            contour.rows[2].entry,
            ControlBoardEntryKind::Review(ReviewLifecycle::Delivered)
        );
        assert_eq!(contour.rows[0].summary, "summary for item-1");
        assert_eq!(contour.rows[2].summary, "content for review-1");
    }

    #[test]
    fn dimensions_stay_independent() {
        let first = project_controlboard_contour(&view(), &bindings()).expect("first");
        let mut other_bindings = bindings();
        other_bindings.evidence = "evidence-other".to_owned();
        other_bindings.product_pulse = Some("pulse-b".to_owned());
        other_bindings.product_not_applicable = None;
        let second = project_controlboard_contour(&view(), &other_bindings).expect("second");
        // Liveness, readiness, and support do not move with evidence/Product.
        assert_eq!(first.liveness, second.liveness);
        assert_eq!(first.readiness, second.readiness);
        assert_eq!(first.support, second.support);
        // Evidence and Product move exactly as supplied, nowhere else.
        assert_ne!(first.evidence_refs, second.evidence_refs);
        assert_ne!(first.contour_digest, second.contour_digest);
        assert_eq!(first.product_pulse, None);
        assert_eq!(second.product_pulse, Some("pulse-b".to_owned()));
        assert_ne!(first.product_not_applicable, second.product_not_applicable);
        for (first_row, second_row) in first.rows.iter().zip(&second.rows) {
            assert_eq!(first_row.entry_id, second_row.entry_id);
            assert_eq!(first_row.entry, second_row.entry);
            assert_eq!(first_row.summary, second_row.summary);
            assert_eq!(first_row.capability, second_row.capability);
            assert_eq!(first_row.owner, second_row.owner);
            assert_ne!(first_row.evidence, second_row.evidence);
        }
    }

    #[test]
    fn support_is_pinned_to_current_unverified() {
        let contour = project_controlboard_contour(&view(), &bindings()).expect("contour");
        assert_eq!(contour.support, ControlBoardSupport::CurrentUnverified);
        let json = serde_json::to_value(&contour).expect("json");
        assert_eq!(json["support"], serde_json::json!("CURRENT_UNVERIFIED"));
    }

    #[test]
    fn no_secret_material_in_projection() {
        let contour = project_controlboard_contour(&view(), &bindings()).expect("contour");
        let json = serde_json::to_string(&contour).expect("json");
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
                "secret-like text in contour: {needle}"
            );
        }
    }

    #[test]
    fn real_read_only_consumer_uses_view_without_command_port() {
        let reads = Arc::new(AtomicUsize::new(0));
        let mut board = ControlBoard::new(
            Some(Box::new(FakeAccess {
                binding: access_binding(),
            })),
            Some(Box::new(FakeState {
                state: canonical_state(),
                reads: Arc::clone(&reads),
            })),
            None,
        );
        let contour =
            read_controlboard_contour(&mut board, &read_request(), &bindings()).expect("contour");
        assert_eq!(contour.rows.len(), 3);
        assert_eq!(contour.view_revision, 7);
        // Exactly one canonical read; no command port exists, so any submit
        // path would have failed closed instead of producing this contour.
        assert_eq!(reads.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn denied_read_yields_no_contour() {
        let mut board = ControlBoard::new(Some(Box::new(DenyingAccess)), None, None);
        let error = read_controlboard_contour(&mut board, &read_request(), &bindings())
            .expect_err("denied read must fail");
        assert!(matches!(
            error,
            ControlBoardProjectionError::ReadFailed { .. }
        ));
    }

    #[test]
    fn fail_closed_bindings_and_pulse() {
        let view = view();
        let mut empty_capability = bindings();
        empty_capability.capability.clear();
        assert_eq!(
            project_controlboard_contour(&view, &empty_capability),
            Err(ControlBoardProjectionError::InvalidBinding {
                field: "bindings.capability"
            })
        );
        let mut control_chars = bindings();
        control_chars.owner = "owner\nwith-newline".to_owned();
        assert_eq!(
            project_controlboard_contour(&view, &control_chars),
            Err(ControlBoardProjectionError::InvalidBinding {
                field: "bindings.owner"
            })
        );
        let mut no_pulse = bindings();
        no_pulse.product_not_applicable = None;
        assert_eq!(
            project_controlboard_contour(&view, &no_pulse),
            Err(ControlBoardProjectionError::MissingPulseBinding)
        );
        let mut both_pulse = bindings();
        both_pulse.product_pulse = Some("pulse".to_owned());
        assert_eq!(
            project_controlboard_contour(&view, &both_pulse),
            Err(ControlBoardProjectionError::MissingPulseBinding)
        );
    }

    #[test]
    fn duplicate_and_oversized_entries_fail_closed() {
        let mut duplicated = view();
        duplicated.items.push(item("item-1", BoardItemKind::Rule));
        let error = project_controlboard_contour(&duplicated, &bindings())
            .expect_err("duplicate entry must fail");
        assert_eq!(
            error,
            ControlBoardProjectionError::DuplicateEntryId {
                entry_id: "item-1".to_owned()
            }
        );
        let mut cross_duplicate = view();
        cross_duplicate.reviews.push(review("item-1"));
        assert_eq!(
            project_controlboard_contour(&cross_duplicate, &bindings()),
            Err(ControlBoardProjectionError::DuplicateEntryId {
                entry_id: "item-1".to_owned()
            })
        );
        let mut oversized = view();
        oversized.items[0].summary = "s".repeat(MAX_SUMMARY_CHARS.saturating_add(1));
        assert_eq!(
            project_controlboard_contour(&oversized, &bindings()),
            Err(ControlBoardProjectionError::Oversized {
                field: "row.summary"
            })
        );
    }
}
