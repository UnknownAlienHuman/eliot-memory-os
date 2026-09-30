//! Private semantic assembly of the `ControlBoard` read projection.
//!
//! This module compiles one refresh-consistent [`ControlBoardGovernorSnapshot`]
//! over the existing Governor owners (coordination, problem, observation,
//! task, read scope) plus the Kernel-issued named-read digests retained in
//! recovery. It creates no owner, registry, Store client, authority, or
//! second canonical path: every byte digested here is already owned and
//! fenced by the composition, and the snapshot is only published through
//! [`GovernorComposition::controlboard_snapshot`](crate::composition::GovernorComposition::controlboard_snapshot)
//! after the readiness gate.
//!
//! G-11/I-12 grounding: the composition owns no dedicated report owner (see
//! [`RecoveryOwner::ALL`](crate::composition::RecoveryOwner); there is no
//! report entry among the sixteen owners). The G-11 binding is served by the
//! coordination owner and the I-12 binding by the observation evidence
//! journal, which is the provenance substrate for reports. Both binding
//! digests cover the full joint owner assembly under domain separation, and
//! both receipt references are the exact Kernel-issued named-read value
//! digests for the payload bytes assembled here. Nothing is fabricated: an
//! owner that cannot be read fails the assembly instead of producing a
//! placeholder.
//!
//! The snapshot carries no board items or provenance edges. Owner records
//! (tasks, coordination events, journal entries) carry no `ControlBoard`
//! visibility, privacy, or epistemic facts, and inventing them would be a
//! privacy expansion. An empty-items view over real bindings is the honest
//! projection; it is distinct from a missing provider, which stays a typed
//! `PLAN_GAP` at the surface. Command families that need item projections
//! remain deferred until their owners expose the required contract.
//!
//! Anchored-review obligations are the one exception, and only in owner-issued
//! form: [`ControlBoardReviewBatch`] reproduces the coordination owner's own
//! retained records verbatim and adds no visibility, privacy, or role fact, so
//! no `ControlBoard` DTO can be filled from it yet. Those records are
//! nevertheless load-bearing here — the G-11 review-projection binding digest
//! covers them — so a review that moves, is answered, or is disposed changes
//! the served binding instead of being reported as an unchanged board. The
//! batch denominator is the coordination owner's separately recorded
//! expectation, so an unrecorded expectation reads as unknown rather than as
//! a complete review section.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use eliot_contracts::{StateFence, canonical_json_bytes, sha256_hex};
use eliot_coordination::{
    AnchorResolution, CoordinationOwner, PeerReviewLifecycle, PeerReviewStanding,
};
use eliot_evaluation_contracts::{
    ComparisonBasis, EvaluatorRole, HumanAttentionClaim, HumanAttentionEvaluation,
    HumanAttentionMetric, HumanAttentionMetricGroupKind, HumanAttentionMetricObservation,
    ObservationWindowStatus,
};
use eliot_observation::ObservationJournal;
use eliot_store_api::ScopeRevisionView;
use eliot_task::TaskLifecycleOwner;
use serde::Serialize;
use thiserror::Error;

/// Fail-closed errors for `ControlBoard` projection assembly.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ControlBoardProjectionError {
    /// The assembly fence is not a valid shared fence.
    #[error("controlboard projection fence is invalid: {0}")]
    Fence(String),
    /// The board revision must be non-zero.
    #[error("controlboard projection read revision must be non-zero")]
    ZeroRevision,
    /// A Kernel-issued receipt digest is not a lowercase SHA-256 value.
    #[error("controlboard projection receipt reference is invalid: {0}")]
    Receipt(String),
    /// Owner state could not be serialized for the binding digest.
    #[error("controlboard projection owner state is invalid: {0}")]
    Owner(String),
    /// An attention-evaluation row could not be assembled honestly.
    #[error("controlboard attention evaluation is invalid: {0}")]
    Evaluation(String),
}

/// One provider-issued identity binding assembled from a real owner read.
///
/// `binding_id` names the actual Governor owner, `binding_digest` binds the
/// full joint owner assembly at the snapshot fence and revision under domain
/// separation, and `receipt_ref` is the exact Kernel-issued named-read value
/// digest for that owner's payload bytes.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ControlBoardOwnerBinding {
    /// Stable identity of the Governor owner serving this binding.
    pub binding_id: String,
    /// Digest over the joint owner assembly for this binding domain.
    pub binding_digest: String,
    /// Kernel-issued named-read value digest for the owner's payload bytes.
    pub receipt_ref: String,
}

/// One artifact's anchored-review obligations, reproduced from the
/// coordination owner.
///
/// This is the owner-issued detail record the G-11 review projection serves,
/// not a board row: it carries no `Visibility`, no privacy class, and no
/// capability decision, so no role filter can be evaluated from it and none is
/// claimed. Every obligation keeps its own historical anchor, reviewed
/// revision and digest, and its own outcome, so one answered review never
/// presents a multi-item batch as complete. `outstanding` is derived from the
/// coordination owner's separately recorded expectation, never from the
/// obligations this struct also carries; when no expectation was recorded the
/// denominator is `None` and no completeness may be inferred.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ControlBoardReviewBatch {
    /// Artifact identity this batch is anchored to.
    pub artifact_id: String,
    /// Currently admitted artifact head revision, absent when none was
    /// admitted. This is the current target and is deliberately separate from
    /// each obligation's own `artifact_revision`, so a review of an older
    /// revision cannot be read as approving the head.
    pub current_artifact_revision: Option<u64>,
    /// Owner-recorded expected-review count, absent when unrecorded.
    pub expected: Option<u64>,
    /// Retained obligation count.
    pub submitted: u64,
    /// Retained obligations that reached a recorded disposition.
    pub disposed: u64,
    /// Expected reviews still lacking a recorded disposition, absent when the
    /// owner recorded no expectation.
    pub outstanding: Option<u64>,
    /// Every retained obligation for this artifact, in `review_id` order.
    pub obligations: Vec<ControlBoardReviewBatchObligation>,
}

/// One retained anchored-review obligation as the owner holds it.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ControlBoardReviewBatchObligation {
    /// Stable review identity.
    pub review_id: String,
    /// Exact reviewed artifact revision; never rewritten by a later head.
    pub artifact_revision: u64,
    /// Exact reviewed artifact digest at that revision.
    pub artifact_digest: String,
    /// Author of this obligation.
    pub reviewer_session_id: String,
    /// Historical anchor selector exactly as submitted.
    pub anchor_field: String,
    /// Anchor resolution claimed at submit.
    pub anchor_resolution: AnchorResolution,
    /// This obligation's own lifecycle.
    pub lifecycle: PeerReviewLifecycle,
    /// This obligation's own standing.
    pub standing: PeerReviewStanding,
    /// Reason retained when this obligation was rejected.
    pub rejection_reason: Option<String>,
    /// Evidence references the obligation itself carries.
    pub evidence_refs: Vec<String>,
}

/// Refresh-consistent `ControlBoard` snapshot assembled over Governor owners.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ControlBoardGovernorSnapshot {
    /// Exact fence every assembled owner was built at.
    pub fence: StateFence,
    /// Read-owner named-read revision this snapshot was taken at.
    pub read_revision: u64,
    /// Live coordination sequence observed during assembly.
    pub coordination_sequence: u64,
    /// G-11 review-projection binding served by the coordination owner.
    pub g11_coordination: ControlBoardOwnerBinding,
    /// I-12 report-projection binding served by the observation journal.
    pub i12_report: ControlBoardOwnerBinding,
    /// Anchored-review obligations the coordination owner retains, in artifact
    /// identity order. Empty only when the owner itself retains no review
    /// expectation, obligation, or artifact head; a missing owner would fail
    /// the assembly rather than reach this field.
    pub review_batches: Vec<ControlBoardReviewBatch>,
}

/// Borrowed assembly inputs. The caller retains every owner; this struct only
/// borrows them for one deterministic compilation.
pub struct ControlBoardProjectionParts<'a> {
    /// Fence all supplied owners were built at.
    pub fence: &'a StateFence,
    /// Read-owner named-read revision bound to this snapshot.
    pub read_revision: u64,
    /// Durable application coordination owner.
    pub coordination: &'a CoordinationOwner,
    /// Durable task lifecycle owner.
    pub task: &'a TaskLifecycleOwner,
    /// Candidate observation journal owner.
    pub observation: &'a ObservationJournal,
    /// Durable problem revision map.
    pub problem_revisions: &'a BTreeMap<String, u64>,
    /// Canonical read scope view.
    pub read_scope: &'a ScopeRevisionView,
    /// Kernel-issued value digest for the coordination payload bytes.
    pub coordination_receipt_digest: &'a str,
    /// Kernel-issued value digest for the observation payload bytes.
    pub observation_receipt_digest: &'a str,
}

/// Stable owner identity bound into the G-11 coordination binding.
pub const G11_OWNER_BINDING_ID: &str = "governor-owner:coordination";
/// Stable owner identity bound into the I-12 report binding.
pub const I12_OWNER_BINDING_ID: &str = "governor-owner:observation";

fn validates_as_lower_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

/// Compiles one deterministic snapshot over the supplied owners.
///
/// The compilation is pure: identical owner state, fence, revision, and
/// receipt digests produce identical bytes. Any unreadable owner state, zero
/// revision, invalid fence, or malformed receipt digest fails closed without
/// a placeholder.
pub fn compile_controlboard_snapshot(
    parts: &ControlBoardProjectionParts<'_>,
) -> Result<ControlBoardGovernorSnapshot, ControlBoardProjectionError> {
    parts
        .fence
        .validate()
        .map_err(|error| ControlBoardProjectionError::Fence(error.to_string()))?;
    if parts.read_revision == 0 {
        return Err(ControlBoardProjectionError::ZeroRevision);
    }
    for (digest, owner) in [
        (parts.coordination_receipt_digest, "coordination"),
        (parts.observation_receipt_digest, "observation"),
    ] {
        if !validates_as_lower_sha256(digest) {
            return Err(ControlBoardProjectionError::Receipt(owner.to_owned()));
        }
    }
    let coordination_bytes = serde_json::to_vec(&(
        parts.coordination.current_sequence(),
        parts.coordination.events(),
    ))
    .map_err(|error| ControlBoardProjectionError::Owner(error.to_string()))?;
    let task_bytes = serde_json::to_vec(&parts.task.snapshot())
        .map_err(|error| ControlBoardProjectionError::Owner(error.to_string()))?;
    let observation_bytes = serde_json::to_vec(&parts.observation.snapshot())
        .map_err(|error| ControlBoardProjectionError::Owner(error.to_string()))?;
    let problem_bytes = serde_json::to_vec(&parts.problem_revisions)
        .map_err(|error| ControlBoardProjectionError::Owner(error.to_string()))?;
    let scope_bytes = serde_json::to_vec(&parts.read_scope)
        .map_err(|error| ControlBoardProjectionError::Owner(error.to_string()))?;
    let review_batches = project_review_batches(parts.coordination);
    let review_bytes = serde_json::to_vec(&review_batches)
        .map_err(|error| ControlBoardProjectionError::Owner(error.to_string()))?;
    let owner_digests = (
        sha256_hex(&coordination_bytes),
        sha256_hex(&task_bytes),
        sha256_hex(&observation_bytes),
        sha256_hex(&problem_bytes),
        sha256_hex(&scope_bytes),
    );
    // The G-11 binding is the review projection, so it also covers the
    // coordination owner's retained review obligations. The I-12 binding is
    // the observation report projection and deliberately does not: a moved or
    // disposed review must change the review binding, not the report binding.
    let bind = |binding_id: &str, receipt_ref: &str, review_digest: Option<&str>| {
        canonical_json_bytes(&(
            binding_id,
            parts.fence,
            parts.read_revision,
            &owner_digests,
            review_digest,
        ))
        .map(|bytes| ControlBoardOwnerBinding {
            binding_id: binding_id.to_owned(),
            binding_digest: sha256_hex(&bytes),
            receipt_ref: receipt_ref.to_owned(),
        })
        .map_err(|error| ControlBoardProjectionError::Owner(error.to_string()))
    };
    let review_digest = sha256_hex(&review_bytes);
    Ok(ControlBoardGovernorSnapshot {
        fence: parts.fence.clone(),
        read_revision: parts.read_revision,
        coordination_sequence: parts.coordination.current_sequence(),
        g11_coordination: bind(
            G11_OWNER_BINDING_ID,
            parts.coordination_receipt_digest,
            Some(&review_digest),
        )?,
        i12_report: bind(I12_OWNER_BINDING_ID, parts.observation_receipt_digest, None)?,
        review_batches,
    })
}

/// Reproduces the coordination owner's retained review obligations verbatim.
///
/// This performs no completeness arithmetic of its own: every count and the
/// outstanding denominator come from
/// [`CoordinationOwner::peer_review_batches`], which reads the owner's
/// separately recorded expectation, so a batch can never be closed by this
/// projection's own list. The only thing decided here is the shape: the
/// surface-visible record repeats the owner's fields and invents no
/// visibility, privacy, or role fact.
fn project_review_batches(coordination: &CoordinationOwner) -> Vec<ControlBoardReviewBatch> {
    coordination
        .peer_review_batches()
        .into_iter()
        .map(|batch| ControlBoardReviewBatch {
            artifact_id: batch.artifact_id,
            current_artifact_revision: batch.current_artifact_revision,
            expected: batch.expected,
            submitted: batch.submitted,
            disposed: batch.disposed,
            outstanding: batch.outstanding,
            obligations: batch
                .obligations
                .into_iter()
                .map(|obligation| ControlBoardReviewBatchObligation {
                    review_id: obligation.review_id,
                    artifact_revision: obligation.artifact_revision,
                    artifact_digest: obligation.artifact_digest,
                    reviewer_session_id: obligation.reviewer_session_id,
                    anchor_field: obligation.anchor_field,
                    anchor_resolution: obligation.anchor_resolution,
                    lifecycle: obligation.lifecycle,
                    standing: obligation.standing,
                    rejection_reason: obligation.rejection_reason,
                    evidence_refs: obligation.evidence_refs,
                })
                .collect(),
        })
        .collect()
}

/// Rendered currency of one evaluation revision on the board.
///
/// The persist leg remains the authority for commit decisions; this enum is the
/// board's display of the same record facts plus the chain and window context
/// the commit leg cannot see: supersession by a newer linked revision, and
/// whether the observation window matured enough for current tuning. It grants
/// no policy authority, resolves no Problem, and offers no ranking. There is
/// deliberately no `From`/`Into` bridge to the persist leg's validity verdict:
/// the commit gate and the board rendering stay separate types on purpose.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ControlBoardAttentionValidity {
    /// Usable for current tuning and citation.
    Current,
    /// A newer linked revision exists; this revision is history only.
    Superseded {
        /// Revision that supersedes the viewed revision.
        successor_revision: u64,
    },
    /// Past its declared expiry; retained for history, unusable for current use.
    Expired,
    /// Invalidated with reason and affected scope; retained for history,
    /// unusable for current use. Notification and approval obligations bound
    /// as evidence are unchanged by this verdict.
    Invalidated {
        /// Why the revision was invalidated.
        reason: String,
        /// Scope, evidence, or policy coordinates the invalidation covers.
        affected_scope_refs: Vec<String>,
    },
    /// The observation window did not mature: still open, regressed, or
    /// censored/inconclusive. Readable as history, unusable for current tuning.
    WindowNotMatured {
        /// Window status that blocks current tuning use.
        status: ObservationWindowStatus,
        /// Why the window cannot support current tuning.
        detail: String,
    },
}

impl ControlBoardAttentionValidity {
    /// Whether this revision may inform current tuning or policy citation.
    /// Only [`Self::Current`] qualifies; every other variant names its own
    /// reason and stays visibly unusable.
    #[must_use]
    pub const fn usable_for_current_tuning(&self) -> bool {
        matches!(self, Self::Current)
    }
}

/// Evaluated profile revision cited by one evaluation row.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ControlBoardAttentionProfileRef {
    /// Profile identity bound by the record.
    pub profile_id: String,
    /// Profile revision bound by the record.
    pub revision: String,
}

/// One required I11.10 metric group reproduced verbatim from the record.
///
/// Values keep their explicit missingness: an observed zero is an observed
/// number, while missing follow-up or collection stays `Unknown` with its
/// reason and is never zero-filled here.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ControlBoardAttentionMetricGroupRow {
    /// Which I11.10 group these observations belong to.
    pub group: HumanAttentionMetricGroupKind,
    /// Every observation the record carries for the group, in record order.
    pub metrics: Vec<HumanAttentionMetricObservation>,
}

/// Alert volume displayed only alongside missed risk, harm, and task costs.
///
/// The bundle carries all six load-bearing observations together so a surface
/// cannot render lower alert volume as an automatic positive badge: fewer
/// notifications next to more missed critical harm, final harm, or false
/// blocks is not superior, and this struct offers no ranking, score, or
/// `better` predicate to claim otherwise.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ControlBoardAttentionVolumeVsHarm {
    /// Deduplicated inbox items the evaluated profile produced.
    pub deduplicated_inbox_items: HumanAttentionMetricObservation,
    /// Delivery attempts the evaluated profile produced.
    pub delivery_attempts: HumanAttentionMetricObservation,
    /// Critical risk events the evaluated profile missed.
    pub missed_critical_risk_events: HumanAttentionMetricObservation,
    /// Final harm events observed on the evaluated profile.
    pub final_harm_events: HumanAttentionMetricObservation,
    /// Benign tasks the evaluated profile falsely blocked.
    pub benign_false_block_tasks: HumanAttentionMetricObservation,
    /// Work abandoned under the evaluated profile.
    pub abandoned_work_tasks: HumanAttentionMetricObservation,
}

/// One evaluation revision rendered honestly for the board.
///
/// Identity, scope, window, observations, limitations, comparison basis, and
/// validity travel together; evidence travels as bound handles only, resolved
/// through a separate authorized expansion. A row neither resolves a Problem,
/// grants an approval, nor changes policy: a separate authorized policy change
/// may cite the evaluation identity and revision.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ControlBoardAttentionEvaluationRow {
    /// Evaluation identity this revision belongs to.
    pub evaluation_id: String,
    /// Monotonic revision within the evaluation identity.
    pub revision: u64,
    /// Immediately preceding revision, absent only on revision one.
    pub predecessor_revision: Option<u64>,
    /// Principal that assembled the record, exactly as the record names it.
    pub evaluator_principal_id: String,
    /// Evaluator role as recorded; descriptive, confers no access.
    pub evaluator_role: EvaluatorRole,
    /// Authorized scope refs the evaluator declared.
    pub authorized_scope_refs: Vec<String>,
    /// Task population refs the evaluator declared.
    pub task_population_refs: Vec<String>,
    /// Risk population refs the evaluator declared.
    pub risk_population_refs: Vec<String>,
    /// Observation window identity bound by the record.
    pub window_id: String,
    /// Window open instant in Unix milliseconds, absent when unknown.
    pub window_opened_at_ms: Option<i64>,
    /// Window close instant in Unix milliseconds, absent while open.
    pub window_closed_at_ms: Option<i64>,
    /// Observation window status bound by the record.
    pub window_status: ObservationWindowStatus,
    /// Censoring reason, present exactly on censored windows.
    pub censoring_reason: Option<String>,
    /// Evaluated policy profile revision.
    pub policy_revision: ControlBoardAttentionProfileRef,
    /// Evaluated notification profile revision.
    pub notification_revision: ControlBoardAttentionProfileRef,
    /// Evaluated approval profile revision.
    pub approval_revision: ControlBoardAttentionProfileRef,
    /// Evaluated telemetry profile revision.
    pub telemetry_revision: ControlBoardAttentionProfileRef,
    /// All ten I11.10 metric groups in I11.10 field order.
    pub metric_groups: Vec<ControlBoardAttentionMetricGroupRow>,
    /// Volume shown only beside harm and task costs, never as a badge.
    pub volume_vs_harm: ControlBoardAttentionVolumeVsHarm,
    /// Explicit limitations and gaps from the record uncertainty assessment.
    pub limitations: Vec<String>,
    /// Basis text of the uncertainty assessment.
    pub uncertainty_assessment_basis: String,
    /// Declared comparison basis; descriptive records carry none.
    pub comparison_basis: ComparisonBasis,
    /// Comparator profiles the record method declares.
    pub comparator_profile_refs: Vec<String>,
    /// Reason when comparison is unavailable or inapplicable.
    pub comparison_reason: Option<String>,
    /// Conclusions exactly as the record states them; conditional claims keep
    /// their comparator, applicability, and caveats.
    pub claims: Vec<HumanAttentionClaim>,
    /// Evidence manifest identity bound by the record.
    pub evidence_manifest_id: String,
    /// Evidence manifest revision bound by the record.
    pub evidence_manifest_revision: String,
    /// Bound evidence handles for citation and authorized expansion. Handles
    /// only: the projection resolves no evidence bytes.
    pub bound_evidence_refs: Vec<String>,
    /// Always false from the projection. Evidence expansion is the separate
    /// authorized [`expand_attention_evidence`] call, never an implicit read.
    pub evidence_expanded: bool,
    /// Rendered currency of this revision.
    pub validity: ControlBoardAttentionValidity,
    /// Digest over the canonical bytes of the exact record revision. It equals
    /// the committed revision identity: any substitution, including a zero
    /// written where the producer recorded unknown, changes it.
    pub record_digest: String,
}

/// Admitted viewer asking for the attention board.
///
/// Scope refs reuse the record's own `authorized_scope_refs` vocabulary: no
/// new role, visibility, or privacy fact is invented here. The viewer proves
/// nothing by presenting these; the owning surface authenticates the binding
/// (I11.8) and this projection only filters on exact cover.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ControlBoardAttentionViewer {
    /// Principal asking for the view, exactly as the authenticated binding names it.
    pub principal_id: String,
    /// Scope refs the viewer is admitted to.
    pub scope_refs: Vec<String>,
}

impl ControlBoardAttentionViewer {
    /// Names an admitted viewer. A blank principal fails closed: anonymous
    /// callers receive no rows, full or withheld.
    pub fn new(
        principal_id: String,
        scope_refs: Vec<String>,
    ) -> Result<Self, ControlBoardProjectionError> {
        if principal_id.trim().is_empty() || principal_id.chars().any(char::is_control) {
            return Err(ControlBoardProjectionError::Evaluation(
                "attention viewer principal must be non-blank and free of control characters"
                    .to_owned(),
            ));
        }
        Ok(Self {
            principal_id,
            scope_refs,
        })
    }
}

/// Role-filtered attention board: one entry per supplied record revision.
///
/// Governance facts (identity, scope, window, validity, limitations,
/// comparison basis) stay visible on every entry. Full observations and
/// evidence handles appear only under authorized scope cover; anything else is
/// an explicit withheld marker, never a silent omission or a synthesized row.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ControlBoardAttentionBoard {
    /// One entry per supplied record revision, in caller order.
    pub rows: Vec<ControlBoardAttentionBoardRow>,
}

/// One board entry: full observations under authorized cover, or an explicit
/// withheld marker carrying only identity and validity.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum ControlBoardAttentionBoardRow {
    /// Full row: the viewer covers the record scope or is its evaluator.
    Full(ControlBoardAttentionEvaluationRow),
    /// Observations and evidence handles withheld for lack of scope cover.
    ScopeWithheld {
        /// Evaluation identity of the withheld revision.
        evaluation_id: String,
        /// Revision of the withheld record.
        revision: u64,
        /// Currency stays visible so a withheld row can never read as usable.
        validity: ControlBoardAttentionValidity,
        /// Why observations are withheld.
        reason: String,
    },
}

/// Derives the rendered validity of one record revision.
///
/// Order is fail-visible: invalidation first, then supersession by a newer
/// linked revision, then declared expiry, then window maturity. Expiry follows
/// the persist leg exactly: when either the declared expiry or the observation
/// instant is unknown, expiry cannot be established and the record is not
/// expired by default. Only a matured window with a close reading supports
/// current tuning; open, regressed, and censored windows stay readable
/// history.
#[must_use]
pub fn attention_board_validity(
    record: &HumanAttentionEvaluation,
    successor_revision: Option<u64>,
    now_unix_ms: i64,
) -> ControlBoardAttentionValidity {
    let flags = &record.evaluator_scope_uncertainty_and_invalidation;
    if let Some(invalidation) = &flags.invalidation {
        return ControlBoardAttentionValidity::Invalidated {
            reason: invalidation.reason.clone(),
            affected_scope_refs: invalidation.affected_scope_refs.clone(),
        };
    }
    if let Some(successor) = successor_revision {
        return ControlBoardAttentionValidity::Superseded {
            successor_revision: successor,
        };
    }
    if record
        .expires_at
        .known_time_ms
        .is_some_and(|expires_ms| now_unix_ms >= expires_ms)
    {
        return ControlBoardAttentionValidity::Expired;
    }
    let window = &record.observation_window;
    if window.specification.status != ObservationWindowStatus::Matured || window.closed_at.is_none()
    {
        let detail = match window.specification.status {
            ObservationWindowStatus::Open => "observation window is still open".to_owned(),
            ObservationWindowStatus::Regressed => {
                "observation window regressed after maturing".to_owned()
            }
            ObservationWindowStatus::CensoredOrInconclusive => window
                .censoring_reason
                .clone()
                .unwrap_or_else(|| "observation window is censored or inconclusive".to_owned()),
            ObservationWindowStatus::Matured => {
                "matured observation window carries no close reading".to_owned()
            }
        };
        return ControlBoardAttentionValidity::WindowNotMatured {
            status: window.specification.status,
            detail,
        };
    }
    ControlBoardAttentionValidity::Current
}

/// Whether the viewer may see full observations and expand evidence.
///
/// The evaluator who assembled the record always may. Anyone else must cover
/// every authorized scope ref the record declares; a record declaring no
/// authorized scope is covered by nobody. Foreign expansion fails closed here,
/// and byte resolution stays with the owning surface's authorized reads.
#[must_use]
pub fn attention_evidence_expansion_permitted(
    record: &HumanAttentionEvaluation,
    viewer: &ControlBoardAttentionViewer,
) -> bool {
    let flags = &record.evaluator_scope_uncertainty_and_invalidation;
    if viewer.principal_id == flags.evaluator.principal_id {
        return true;
    }
    if flags.authorized_scope.authorized_scope_refs.is_empty() {
        return false;
    }
    flags
        .authorized_scope
        .authorized_scope_refs
        .iter()
        .all(|scope| viewer.scope_refs.iter().any(|held| held == scope))
}

/// Authorizes evidence-handle expansion for one record revision.
///
/// Returns the manifest's bound handles when
/// [`attention_evidence_expansion_permitted`] holds, and fails closed
/// otherwise. The projection resolves no bytes: the owning surface resolves
/// these handles through its own authorized reads, so a suppressed toast's
/// persistent obligation and every cited artifact stay under their owners'
/// access rules.
pub fn expand_attention_evidence(
    record: &HumanAttentionEvaluation,
    viewer: &ControlBoardAttentionViewer,
) -> Result<Vec<String>, ControlBoardProjectionError> {
    record
        .validate()
        .map_err(|error| ControlBoardProjectionError::Evaluation(error.to_string()))?;
    if !attention_evidence_expansion_permitted(record, viewer) {
        return Err(ControlBoardProjectionError::Evaluation(
            "foreign evidence expansion is denied: the viewer does not cover the record scope"
                .to_owned(),
        ));
    }
    Ok(record
        .evidence_manifest
        .evidence_refs
        .iter()
        .map(ToString::to_string)
        .collect())
}

/// Finds one metric observation across all ten record groups.
fn observation_for(
    record: &HumanAttentionEvaluation,
    metric: HumanAttentionMetric,
) -> Option<HumanAttentionMetricObservation> {
    [
        &record.policy_and_task_risk_profile,
        &record.notification_approval_and_telemetry_profile,
        &record.missed_critical_and_false_critical_counts,
        &record.pre_exposure_prevention_and_conditional_intervention,
        &record.final_harm_and_residual_risk,
        &record.benign_false_blocks_and_abandoned_work,
        &record.interruption_and_resumption_time_quality,
        &record.task_correctness_rework_and_human_attention,
        &record.overtrust_undertrust_and_recoverability_observations,
        &record.privacy_purpose_retention_and_disclosure_cost,
    ]
    .iter()
    .flat_map(|group| group.metrics.iter())
    .find(|observation| observation.metric == metric)
    .cloned()
}

/// Requires one volume-bundle observation by metric key.
///
/// The bundle is all-or-nothing: a missing load-bearing observation fails the
/// row instead of rendering volume without its harm context.
fn attention_volume_metric(
    record: &HumanAttentionEvaluation,
    metric: HumanAttentionMetric,
) -> Result<HumanAttentionMetricObservation, ControlBoardProjectionError> {
    observation_for(record, metric).ok_or_else(|| {
        ControlBoardProjectionError::Evaluation(format!(
            "attention volume bundle is missing metric {metric:?}"
        ))
    })
}

/// Renders one profile revision ref bound by the record.
fn attention_profile_ref(
    profile_id: &eliot_contracts::ContractId,
    revision: &str,
) -> ControlBoardAttentionProfileRef {
    ControlBoardAttentionProfileRef {
        profile_id: profile_id.to_string(),
        revision: revision.to_owned(),
    }
}

/// Renders all ten I11.10 metric groups in I11.10 field order.
fn attention_metric_group_rows(
    record: &HumanAttentionEvaluation,
) -> Vec<ControlBoardAttentionMetricGroupRow> {
    [
        (
            &record.policy_and_task_risk_profile,
            HumanAttentionMetricGroupKind::PolicyAndTaskRiskProfile,
        ),
        (
            &record.notification_approval_and_telemetry_profile,
            HumanAttentionMetricGroupKind::NotificationApprovalAndTelemetryProfile,
        ),
        (
            &record.missed_critical_and_false_critical_counts,
            HumanAttentionMetricGroupKind::MissedCriticalAndFalseCriticalCounts,
        ),
        (
            &record.pre_exposure_prevention_and_conditional_intervention,
            HumanAttentionMetricGroupKind::PreExposurePreventionAndConditionalIntervention,
        ),
        (
            &record.final_harm_and_residual_risk,
            HumanAttentionMetricGroupKind::FinalHarmAndResidualRisk,
        ),
        (
            &record.benign_false_blocks_and_abandoned_work,
            HumanAttentionMetricGroupKind::BenignFalseBlocksAndAbandonedWork,
        ),
        (
            &record.interruption_and_resumption_time_quality,
            HumanAttentionMetricGroupKind::InterruptionAndResumptionTimeQuality,
        ),
        (
            &record.task_correctness_rework_and_human_attention,
            HumanAttentionMetricGroupKind::TaskCorrectnessReworkAndHumanAttention,
        ),
        (
            &record.overtrust_undertrust_and_recoverability_observations,
            HumanAttentionMetricGroupKind::OvertrustUndertrustAndRecoverabilityObservations,
        ),
        (
            &record.privacy_purpose_retention_and_disclosure_cost,
            HumanAttentionMetricGroupKind::PrivacyPurposeRetentionAndDisclosureCost,
        ),
    ]
    .into_iter()
    .map(|(group, kind)| ControlBoardAttentionMetricGroupRow {
        group: kind,
        metrics: group.metrics.clone(),
    })
    .collect()
}

/// Bundles the six load-bearing volume/harm observations of one record.
///
/// All-or-nothing: a missing observation fails the bundle instead of rendering
/// volume without its harm context.
fn attention_volume_vs_harm(
    record: &HumanAttentionEvaluation,
) -> Result<ControlBoardAttentionVolumeVsHarm, ControlBoardProjectionError> {
    Ok(ControlBoardAttentionVolumeVsHarm {
        deduplicated_inbox_items: attention_volume_metric(
            record,
            HumanAttentionMetric::DeduplicatedInboxItems,
        )?,
        delivery_attempts: attention_volume_metric(
            record,
            HumanAttentionMetric::DeliveryAttempts,
        )?,
        missed_critical_risk_events: attention_volume_metric(
            record,
            HumanAttentionMetric::MissedCriticalRiskEvents,
        )?,
        final_harm_events: attention_volume_metric(record, HumanAttentionMetric::FinalHarmEvents)?,
        benign_false_block_tasks: attention_volume_metric(
            record,
            HumanAttentionMetric::BenignFalseBlockTasks,
        )?,
        abandoned_work_tasks: attention_volume_metric(
            record,
            HumanAttentionMetric::AbandonedWorkTasks,
        )?,
    })
}

/// Projects one record revision into its board row.
///
/// The record is structurally validated first: a malformed record fails the
/// row instead of rendering a partial one. Unknowns travel as unknowns; the
/// volume bundle fails the row when any of its six observations is absent.
fn project_attention_row(
    record: &HumanAttentionEvaluation,
    successor_revision: Option<u64>,
    now_unix_ms: i64,
) -> Result<ControlBoardAttentionEvaluationRow, ControlBoardProjectionError> {
    record
        .validate()
        .map_err(|error| ControlBoardProjectionError::Evaluation(error.to_string()))?;
    let flags = &record.evaluator_scope_uncertainty_and_invalidation;
    let record_bytes = canonical_json_bytes(record)
        .map_err(|error| ControlBoardProjectionError::Evaluation(error.to_string()))?;
    Ok(ControlBoardAttentionEvaluationRow {
        evaluation_id: record.evaluation_id.to_string(),
        revision: record.revision,
        predecessor_revision: record.predecessor.as_ref().map(|link| link.revision),
        evaluator_principal_id: flags.evaluator.principal_id.clone(),
        evaluator_role: flags.evaluator.role,
        authorized_scope_refs: flags.authorized_scope.authorized_scope_refs.clone(),
        task_population_refs: flags.authorized_scope.task_population_refs.clone(),
        risk_population_refs: flags.authorized_scope.risk_population_refs.clone(),
        window_id: record.observation_window.specification.window_id.to_string(),
        window_opened_at_ms: record.observation_window.opened_at.known_time_ms,
        window_closed_at_ms: record
            .observation_window
            .closed_at
            .as_ref()
            .and_then(|closed| closed.known_time_ms),
        window_status: record.observation_window.specification.status,
        censoring_reason: record.observation_window.censoring_reason.clone(),
        policy_revision: attention_profile_ref(
            &record.policy_revision.profile_id,
            &record.policy_revision.revision,
        ),
        notification_revision: attention_profile_ref(
            &record.notification_revision.profile_id,
            &record.notification_revision.revision,
        ),
        approval_revision: attention_profile_ref(
            &record.approval_revision.profile_id,
            &record.approval_revision.revision,
        ),
        telemetry_revision: attention_profile_ref(
            &record.telemetry_revision.profile_id,
            &record.telemetry_revision.revision,
        ),
        metric_groups: attention_metric_group_rows(record),
        volume_vs_harm: attention_volume_vs_harm(record)?,
        limitations: flags.uncertainty.limitations.clone(),
        uncertainty_assessment_basis: flags.uncertainty.assessment_basis.clone(),
        comparison_basis: record.method.comparison_basis,
        comparator_profile_refs: record.method.comparator_profile_refs.clone(),
        comparison_reason: record.method.comparison_reason.clone(),
        claims: record.claims.clone(),
        evidence_manifest_id: record.evidence_manifest.manifest_id.to_string(),
        evidence_manifest_revision: record.evidence_manifest.revision.clone(),
        bound_evidence_refs: record
            .evidence_manifest
            .evidence_refs
            .iter()
            .map(ToString::to_string)
            .collect(),
        evidence_expanded: false,
        validity: attention_board_validity(record, successor_revision, now_unix_ms),
        record_digest: sha256_hex(&record_bytes),
    })
}

/// Projects the role-filtered attention board over supplied record revisions.
///
/// Every full row is validated; any malformed record fails the whole board
/// instead of rendering a partial one. `successors` maps
/// `(evaluation_id, revision)` to its newer linked revision when the viewed
/// set knows one; records absent from the map render without supersession.
/// `now_unix_ms` is caller-observed wall time: the projection owns no clock.
///
/// The composition snapshot join and the Store readback path supply the
/// revisions once the persist leg lands (STITCH): this function is pure over
/// already-read revisions and performs no Store, Kernel, or owner reads
/// itself.
pub fn project_attention_board(
    records: &[HumanAttentionEvaluation],
    viewer: &ControlBoardAttentionViewer,
    successors: &BTreeMap<(String, u64), u64>,
    now_unix_ms: i64,
) -> Result<ControlBoardAttentionBoard, ControlBoardProjectionError> {
    let mut rows = Vec::with_capacity(records.len());
    for record in records {
        let successor = successors
            .get(&(record.evaluation_id.to_string(), record.revision))
            .copied();
        if attention_evidence_expansion_permitted(record, viewer) {
            rows.push(ControlBoardAttentionBoardRow::Full(project_attention_row(
                record, successor, now_unix_ms,
            )?));
        } else {
            rows.push(ControlBoardAttentionBoardRow::ScopeWithheld {
                evaluation_id: record.evaluation_id.to_string(),
                revision: record.revision,
                validity: attention_board_validity(record, successor, now_unix_ms),
                reason: "the viewer does not cover the record authorized scope".to_owned(),
            });
        }
    }
    Ok(ControlBoardAttentionBoard { rows })
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use eliot_contracts::{EpochId, EpochLineageId, ResourceGeneration};
    use eliot_store_api::ScopeId;
    use std::num::NonZeroU64;

    const TEST_LINEAGE_A: &str = "550e8400-e29b-41d4-a716-446655440000";

    fn test_epoch(lineage: &str, sequence: u64) -> EpochId {
        EpochId::new(
            EpochLineageId::new(lineage).expect("valid test lineage"),
            NonZeroU64::new(sequence).expect("nonzero test sequence"),
        )
        .expect("valid test epoch")
    }

    fn fence() -> StateFence {
        StateFence::new(
            test_epoch(TEST_LINEAGE_A, 1),
            ResourceGeneration::new(1).expect("generation"),
        )
    }

    fn scope(fence: &StateFence) -> ScopeRevisionView {
        ScopeRevisionView {
            scope_id: ScopeId::new("scope").expect("scope id"),
            revision_heads: Vec::new(),
            ordering_heads: Vec::new(),
            state_fence: fence.clone(),
        }
    }

    fn parts<'a>(
        fence: &'a StateFence,
        coordination: &'a CoordinationOwner,
        task: &'a TaskLifecycleOwner,
        observation: &'a ObservationJournal,
        problems: &'a BTreeMap<String, u64>,
        read_scope: &'a ScopeRevisionView,
        digests: &'a (String, String),
    ) -> ControlBoardProjectionParts<'a> {
        ControlBoardProjectionParts {
            fence,
            read_revision: 7,
            coordination,
            task,
            observation,
            problem_revisions: problems,
            read_scope,
            coordination_receipt_digest: &digests.0,
            observation_receipt_digest: &digests.1,
        }
    }

    fn digests() -> (String, String) {
        ("a".repeat(64), "b".repeat(64))
    }

    #[test]
    fn empty_owners_assemble_a_deterministic_empty_projection() {
        let fence = fence();
        let coordination = CoordinationOwner::new();
        let task = TaskLifecycleOwner::new(test_epoch(TEST_LINEAGE_A, 1), fence.clone())
            .expect("task owner");
        let observation = ObservationJournal::default();
        let problems = BTreeMap::new();
        let read_scope = scope(&fence);
        let digests = digests();
        let input = parts(
            &fence,
            &coordination,
            &task,
            &observation,
            &problems,
            &read_scope,
            &digests,
        );
        let first = compile_controlboard_snapshot(&input).expect("snapshot");
        let second = compile_controlboard_snapshot(&input).expect("snapshot");
        assert_eq!(first, second);
        assert_eq!(first.fence, fence);
        assert_eq!(first.read_revision, 7);
        assert_eq!(first.g11_coordination.binding_id, G11_OWNER_BINDING_ID);
        assert_eq!(first.i12_report.binding_id, I12_OWNER_BINDING_ID);
        assert_ne!(
            first.g11_coordination.binding_digest,
            first.i12_report.binding_digest
        );
        assert_eq!(first.g11_coordination.receipt_ref, "a".repeat(64));
        assert_eq!(first.i12_report.receipt_ref, "b".repeat(64));
    }

    #[test]
    fn owner_bytes_are_load_bearing_not_canned() {
        let fence = fence();
        let coordination = CoordinationOwner::new();
        let task = TaskLifecycleOwner::new(test_epoch(TEST_LINEAGE_A, 1), fence.clone())
            .expect("task owner");
        let observation = ObservationJournal::default();
        let read_scope = scope(&fence);
        let empty_problems = BTreeMap::new();
        let digests = digests();
        let idle = compile_controlboard_snapshot(&parts(
            &fence,
            &coordination,
            &task,
            &observation,
            &empty_problems,
            &read_scope,
            &digests,
        ))
        .expect("snapshot");
        let mut one_problem = BTreeMap::new();
        one_problem.insert("problem-1".to_owned(), 2);
        let changed = compile_controlboard_snapshot(&parts(
            &fence,
            &coordination,
            &task,
            &observation,
            &one_problem,
            &read_scope,
            &digests,
        ))
        .expect("snapshot");
        assert_ne!(
            idle.g11_coordination.binding_digest,
            changed.g11_coordination.binding_digest
        );
        assert_ne!(
            idle.i12_report.binding_digest,
            changed.i12_report.binding_digest
        );
    }

    #[test]
    fn zero_revision_and_malformed_receipts_fail_closed() {
        let fence = fence();
        let coordination = CoordinationOwner::new();
        let task = TaskLifecycleOwner::new(test_epoch(TEST_LINEAGE_A, 1), fence.clone())
            .expect("task owner");
        let observation = ObservationJournal::default();
        let problems = BTreeMap::new();
        let read_scope = scope(&fence);
        let digests = digests();
        let mut input = parts(
            &fence,
            &coordination,
            &task,
            &observation,
            &problems,
            &read_scope,
            &digests,
        );
        input.read_revision = 0;
        assert_eq!(
            compile_controlboard_snapshot(&input),
            Err(ControlBoardProjectionError::ZeroRevision)
        );
        let mut input = parts(
            &fence,
            &coordination,
            &task,
            &observation,
            &problems,
            &read_scope,
            &digests,
        );
        input.coordination_receipt_digest = "not-a-digest";
        assert!(matches!(
            compile_controlboard_snapshot(&input),
            Err(ControlBoardProjectionError::Receipt(_))
        ));
    }
}
