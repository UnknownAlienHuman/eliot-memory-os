//! Read-only `ControlBoard` status projection owned by `eliot-runtime-status`.
//!
//! Issue #1213: this module is the read-only projection that binds
//! `eliot-controlboard` under the current runtime-status owner. It consumes
//! only the immutable [`ControlBoardView`](eliot_controlboard::ControlBoardView)
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
//! Support and evidence vocabulary: the implementation-support and
//! evidence-execution axes are **not** `ControlBoard` types. The contour carries
//! the #216 owner records verbatim — [`DomainCoverage`] for all five
//! `EvidenceDomain` axes, [`CapabilitySupportRow`] for capability ownership, and
//! the owner's own [`EvidenceExecutionStatus`] / [`SupportObservationState`] —
//! and validates them with the owner's own validators at one frozen evaluation
//! boundary. There is deliberately no ControlBoard-local support alias, so a
//! second support or proof vocabulary cannot be constructed here (I0.5, I2.23).
//!
//! Completeness: the declared coverage denominator is
//! `EvidenceDomain::ALL`, taken from the owner crate, never from a
//! caller-supplied list. A missing, duplicated, or out-of-order domain refuses
//! the contour, so a domain cannot disappear from the board.
//!
//! Independence: `liveness`, `readiness`, `transport`, `evidence_execution`,
//! `domain_coverage`, `support_rows`, and the `product_*` fields are separate
//! contour fields with no synthesis function. A projected view proves neither
//! liveness nor readiness, so both stay `Unknown` with explicit gaps; live
//! process evidence remains owned by issue #11. `transport` and
//! `evidence_execution` are the composition's own observation, reproduced
//! verbatim: transport reachability is never derived from a row, and evidence
//! execution is never read off the support rows. There is intentionally no
//! `status()`, `is_healthy()`, or `is_ready()` constructor: collapsing the
//! dimensions would manufacture a claim no single read can justify.
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

use eliot_conformance_contracts::{
    CONTRACT_VERSION as CONFORMANCE_CONTRACT_VERSION, CapabilitySupportRow,
    ConformanceContractError, ConformanceContractSet, DomainCoverage, EvidenceExecutionStatus,
    SupportObservationState, canonicalize_domain_coverage, canonicalize_support_claim_set,
    validate_conformance_contract_set,
};
use eliot_contracts::{StateFence, sha256_hex};
use eliot_controlboard::{
    BoardItemKind, ControlBoard, ControlBoardView, NotificationInbox, ReadRequest, ReviewLifecycle,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::ComponentState;

/// Stable contract identity for this read-only contour.
pub const CONTROLBOARD_CONTOUR_CONTRACT: &str = "eliot.runtime-status.controlboard-contour/v2";

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
///
/// The last five fields are the #216 owner records. They are reproduced
/// verbatim and validated by the owner's own contract-set validator at the one
/// `evaluated_at_ms` boundary; this module never rewrites, averages, or
/// re-labels them, and never derives one from another.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
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
    /// The one evaluation boundary this owner declares for this validation
    /// unit. Coverage and support rows are checked together at exactly this
    /// instant; a row evaluated at any other boundary refuses the contour.
    pub evaluated_at_ms: u64,
    /// Owner-declared five-domain coverage. Completeness is checked against
    /// the owner's `EvidenceDomain::ALL`, never against this list.
    pub domain_coverage: Vec<DomainCoverage>,
    /// Owner-declared capability support rows, checked against the coverage
    /// above. An empty set is accepted and mints no support claim.
    pub support_rows: Vec<CapabilitySupportRow>,
    /// Transport reachability of the read edge, as the composition observed it.
    /// Never inferred from a row, a pipe, a port, or a process.
    pub transport: SupportObservationState,
    /// Evidence execution of the cited evidence, as the composition observed
    /// it. Never recomputed from the support rows.
    pub evidence_execution: EvidenceExecutionStatus,
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

/// Read-only `ControlBoard` contour.
///
/// Liveness, readiness, transport, evidence execution, five-domain coverage,
/// capability support and Product are independent fields. No method combines
/// them; adding one would manufacture a claim no single read can justify.
/// `Eq` is intentionally absent: the owner records carried here
/// ([`DomainCoverage`], [`CapabilitySupportRow`]) are `PartialEq` only, and the
/// contour refuses to narrow them to a weaker equality contract.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
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
    /// Canonical notification inbox section from the exact board view.
    pub notifications: NotificationInbox,
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
    /// Transport reachability of the read edge, reproduced verbatim from the
    /// composition. Never inferred from a port, a pipe, or a process, and
    /// never promoted into liveness or readiness.
    pub transport: SupportObservationState,
    /// Evidence execution of the cited evidence, reproduced verbatim from the
    /// composition. Never recomputed from the support rows and never promoted
    /// into implementation support.
    pub evidence_execution: EvidenceExecutionStatus,
    /// The one evaluation boundary the owner declared for this validation unit.
    pub evaluated_at_ms: u64,
    /// Exactly one coverage record per `EvidenceDomain`, canonicalized and
    /// validated by the owner crate. An omitted domain cannot reach this board.
    pub domain_coverage: Vec<DomainCoverage>,
    /// Owner capability support rows, canonicalized and validated against
    /// `domain_coverage`. Each row keeps its own independent maturity,
    /// implementation-support and evidence-execution values.
    pub support_rows: Vec<CapabilitySupportRow>,
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
    /// The owner-declared five-domain coverage or capability support rows were
    /// refused by the owner's own `eliot-conformance-contracts` validator. The
    /// error is the owner's, reproduced verbatim: this module never repairs,
    /// relaxes, or re-labels a support or evidence claim.
    #[error("controlboard I0.5 evidence axis refused: {0}")]
    EvidenceAxis(#[from] ConformanceContractError),
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

/// Canonical owner evidence records for one contour, validated at the single
/// declared evaluation boundary.
///
/// The coverage denominator is the owner's `EvidenceDomain::ALL`, so a missing,
/// duplicated, or out-of-order domain refuses the contour. The support rows are
/// checked against that exact coverage at the same boundary, and a mixed
/// boundary is rejected rather than normalized. Nothing here recomputes a
/// support or evidence-execution value from another field.
fn validated_evidence_axes(
    bindings: &ControlBoardProjectionBindings,
) -> Result<(Vec<DomainCoverage>, Vec<CapabilitySupportRow>), ControlBoardProjectionError> {
    let domain_coverage = canonicalize_domain_coverage(bindings.domain_coverage.clone())?;
    let support_rows =
        canonicalize_support_claim_set(bindings.support_rows.clone(), &domain_coverage)?;
    validate_conformance_contract_set(&ConformanceContractSet {
        contract_version: CONFORMANCE_CONTRACT_VERSION,
        evaluated_at_ms: bindings.evaluated_at_ms,
        domain_coverage: domain_coverage.clone(),
        support_rows: support_rows.clone(),
    })?;
    Ok((domain_coverage, support_rows))
}

/// One shape-validated, owner-stamped projection row.
///
/// The row text is validated here rather than in the caller so the item and
/// review paths cannot drift apart, and so every projected row is stamped from
/// the same validated bindings in the same order.
fn stamped_row(
    entry_id: &str,
    entry: ControlBoardEntryKind,
    summary: &str,
    bindings: &ControlBoardProjectionBindings,
) -> Result<ControlBoardStatusRow, ControlBoardProjectionError> {
    bound_text(entry_id, "row.entry_id", MAX_BINDING_CHARS)?;
    bound_text(summary, "row.summary", MAX_SUMMARY_CHARS)?;
    Ok(ControlBoardStatusRow {
        entry_id: entry_id.to_owned(),
        entry,
        summary: summary.to_owned(),
        capability: bindings.capability.clone(),
        owner: bindings.owner.clone(),
        generation: bindings.generation.clone(),
        evidence: bindings.evidence.clone(),
        expiry: bindings.expiry.clone(),
        invalidation: bindings.invalidation.clone(),
    })
}

/// Projects one read-only contour over an already-obtained board view.
///
/// The view is consumed by shared reference; role/privacy filtering is the
/// view's own property and is preserved 1:1. Every row is stamped with the
/// validated caller bindings. Liveness and readiness stay `Unknown`, the owner
/// evidence records are carried verbatim after the owner's own validation, and
/// Product stays exactly the caller-declared pulse binding: the dimensions are
/// never merged.
pub fn project_controlboard_contour(
    view: &ControlBoardView,
    bindings: &ControlBoardProjectionBindings,
) -> Result<ControlBoardContour, ControlBoardProjectionError> {
    validate_bindings(bindings)?;
    let (domain_coverage, support_rows) = validated_evidence_axes(bindings)?;
    let entry_total = view.items.len().saturating_add(view.reviews.len());
    if entry_total > MAX_CONTROLBOARD_ROWS {
        return Err(ControlBoardProjectionError::Oversized { field: "rows" });
    }
    let mut rows = Vec::with_capacity(entry_total);
    let mut seen_ids = std::collections::BTreeSet::new();
    for item in &view.items {
        let row = stamped_row(
            &item.item_id,
            ControlBoardEntryKind::Item(item.kind),
            &item.summary,
            bindings,
        )?;
        if !seen_ids.insert(item.item_id.clone()) {
            return Err(ControlBoardProjectionError::DuplicateEntryId {
                entry_id: item.item_id.clone(),
            });
        }
        rows.push(row);
    }
    for review in &view.reviews {
        let row = stamped_row(
            &review.review_item_id,
            ControlBoardEntryKind::Review(review.lifecycle),
            &review.content,
            bindings,
        )?;
        if !seen_ids.insert(review.review_item_id.clone()) {
            return Err(ControlBoardProjectionError::DuplicateEntryId {
                entry_id: review.review_item_id.clone(),
            });
        }
        rows.push(row);
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
        &view.notifications,
        &evidence_refs,
        &domain_coverage,
        &support_rows,
        bindings.evaluated_at_ms,
        bindings.transport,
        bindings.evidence_execution,
    ))
    .map_err(|error| ControlBoardProjectionError::EncodingFailed {
        detail: error.to_string(),
    })?;
    Ok(ControlBoardContour {
        contract: CONTROLBOARD_CONTOUR_CONTRACT.to_owned(),
        view_revision: revision,
        view_fence: view.fence.clone(),
        rows,
        notifications: view.notifications.clone(),
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
        transport: bindings.transport,
        evidence_execution: bindings.evidence_execution,
        evaluated_at_ms: bindings.evaluated_at_ms,
        domain_coverage,
        support_rows,
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

/// Owner-record fixtures shared by this crate's controlboard test modules.
///
/// The records are built from the owner's own vocabulary and claim nothing:
/// every domain is `Unknown` and the single support row is `TARGET` /
/// `NOT_EXECUTED`, which is the strongest position a fixture without executed
/// evidence may carry. Nothing here invents an observation.
#[cfg(test)]
pub(crate) mod owner_records {
    use eliot_conformance_contracts::{
        CONTRACT_VERSION, CapabilitySupportRow, ContractMaturity, DomainCoverage, EvidenceDomain,
        EvidenceExecutionStatus, ImplementationSupport, SupportObservationState,
    };

    /// One declared evaluation boundary shared by coverage and support rows.
    pub const EVALUATED_AT_MS: u64 = 1_786_000_000_000;

    /// Exactly one `Unknown` coverage record per `EvidenceDomain`, in the
    /// owner's canonical order.
    #[must_use]
    pub fn unobserved_coverage() -> Vec<DomainCoverage> {
        EvidenceDomain::ALL
            .iter()
            .map(|domain| DomainCoverage {
                contract_version: CONTRACT_VERSION,
                domain: *domain,
                state: SupportObservationState::Unknown,
                source_handles: Vec::new(),
                evidence_refs: vec![format!("owner-record:{domain:?}")],
                blind_boundaries: Vec::new(),
                observed_at_ms: None,
                expires_at_ms: None,
                invalidation_set: Vec::new(),
            })
            .collect()
    }

    /// One `TARGET` / `NOT_EXECUTED` capability support row for the `Source`
    /// domain at [`EVALUATED_AT_MS`].
    #[must_use]
    pub fn target_source_support_row() -> CapabilitySupportRow {
        CapabilitySupportRow {
            contract_version: CONTRACT_VERSION,
            contract_ref: "eliot.surfaces.controlboard/v1".to_owned(),
            support_claim_ref: "controlboard.status#projected-rows".to_owned(),
            scope_ref: "eliot-runtime-status#controlboard".to_owned(),
            claim_domain: Some(EvidenceDomain::Source),
            required_dependency_domains: vec![EvidenceDomain::Source],
            support_observation_state: SupportObservationState::Unknown,
            contract_maturity: ContractMaturity::Compatible,
            implementation_support: ImplementationSupport::Target,
            evidence_execution_status: EvidenceExecutionStatus::NotExecuted,
            proof_profile_ref: None,
            source_handles: vec![
                "crates/meta/eliot-runtime-status/src/controlboard_projection.rs".to_owned(),
            ],
            evidence_refs: vec!["owner-record:Source".to_owned()],
            blind_boundaries: Vec::new(),
            invalidation_set: vec!["source-head-change".to_owned()],
            compatibility_rule_ref: None,
            not_applicable_reason_ref: None,
            evaluated_at_ms: EVALUATED_AT_MS,
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use std::num::NonZeroU64;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use eliot_conformance_contracts::{EvidenceDomain, ImplementationSupport};
    use eliot_contracts::{EpochId, EpochLineageId, ResourceGeneration};
    use eliot_controlboard::{
        AccessBinding, AccessResolverPort, AnchorResolution, AnchorTargetKind, BoardItem,
        BoardItemKind, CanonicalState, CanonicalStatePort, ControlBoard, NotificationInbox,
        NotificationMetrics, PortError, ProjectionBinding, ProjectionProvider,
        ProviderCompleteness, ReadRequest, ReviewAnchor, ReviewItem, ReviewLifecycle, Role,
        ViewRevision, Visibility,
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
            evaluated_at_ms: super::owner_records::EVALUATED_AT_MS,
            domain_coverage: super::owner_records::unobserved_coverage(),
            support_rows: vec![super::owner_records::target_source_support_row()],
            transport: SupportObservationState::Unknown,
            evidence_execution: EvidenceExecutionStatus::NotExecuted,
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
            notifications: NotificationInbox {
                rows: Vec::new(),
                unresolved_critical: Vec::new(),
                failed_delivery: Vec::new(),
                metrics: NotificationMetrics::default(),
            },
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
        other_bindings.transport = SupportObservationState::Unavailable;
        other_bindings.evidence_execution = EvidenceExecutionStatus::UnknownOutcome;
        let second = project_controlboard_contour(&view(), &other_bindings).expect("second");
        // Liveness and readiness never move with evidence, transport, evidence
        // execution, or Product.
        assert_eq!(first.liveness, second.liveness);
        assert_eq!(first.readiness, second.readiness);
        // Transport and evidence execution are their own axes: they move only
        // where the composition observed them, and they never become liveness,
        // readiness, or support.
        assert_eq!(first.transport, SupportObservationState::Unknown);
        assert_eq!(second.transport, SupportObservationState::Unavailable);
        assert_eq!(
            first.evidence_execution,
            EvidenceExecutionStatus::NotExecuted
        );
        assert_eq!(
            second.evidence_execution,
            EvidenceExecutionStatus::UnknownOutcome
        );
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
    fn support_axis_is_the_owner_record_not_a_controlboard_alias() {
        let contour = project_controlboard_contour(&view(), &bindings()).expect("contour");
        // The implementation-support axis is the owner's record, not a
        // ControlBoard alias: exactly one coverage record per declared domain,
        // and the owner support row keeps its own independent values.
        assert_eq!(
            contour.evaluated_at_ms,
            super::owner_records::EVALUATED_AT_MS
        );
        assert_eq!(contour.domain_coverage.len(), 5);
        assert_eq!(
            contour
                .domain_coverage
                .iter()
                .map(|row| row.domain)
                .collect::<Vec<_>>(),
            EvidenceDomain::ALL.to_vec()
        );
        assert_eq!(contour.support_rows.len(), 1);
        assert_eq!(
            contour.support_rows[0].implementation_support,
            ImplementationSupport::Target
        );
        assert_eq!(
            contour.support_rows[0].evidence_execution_status,
            EvidenceExecutionStatus::NotExecuted
        );
        // No ControlBoard-specific support alias reaches the wire.
        let json = serde_json::to_value(&contour).expect("json");
        assert!(json.get("support").is_none());
        assert!(json.get("domain_coverage").is_some());
        assert!(json.get("support_rows").is_some());
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
